package aggregate

import (
	"errors"
	"math"

	"github.com/balyakin/crawlledger/internal/domain"
)

const tokenScale int64 = 60000000

type Profile struct {
	Name  string
	Rate  int64
	Burst int64
}

var Profiles = []Profile{
	{Name: "gentle", Rate: 60, Burst: 20},
	{Name: "standard", Rate: 30, Burst: 10},
	{Name: "strict", Rate: 10, Burst: 5},
}

type bucket struct {
	lastTimestampUS int64
	tokens          int64
	initialized     bool
	unordered       bool
}

func (b *bucket) allow(timestampUS int64, profile Profile) (bool, error) {
	capacity := (profile.Burst + 1) * tokenScale
	if !b.initialized {
		b.lastTimestampUS, b.tokens, b.initialized = timestampUS, capacity, true
	} else {
		if timestampUS < b.lastTimestampUS {
			b.unordered = true
			return false, nil
		}
		delta := timestampUS - b.lastTimestampUS
		if delta > 0 {
			if delta > math.MaxInt64/profile.Rate {
				b.tokens = capacity
			} else {
				refill := delta * profile.Rate
				if refill > capacity-b.tokens {
					b.tokens = capacity
				} else {
					b.tokens += refill
				}
			}
		}
		b.lastTimestampUS = timestampUS
	}
	if b.unordered {
		return false, nil
	}
	if b.tokens >= tokenScale {
		b.tokens -= tokenScale
		return true, nil
	}
	return false, nil
}

type rateSubject struct{ buckets [3]bucket }

type rateImpactKey struct {
	uaID    int64
	class   domain.TrafficClass
	profile string
}

func addRateImpact(target *RateImpactRow, event domain.Event, allowed bool) error {
	var err error
	target.ModeledRequests, err = checkedAdd(target.ModeledRequests, 1)
	if err != nil {
		return err
	}
	if allowed {
		if target.AllowedRequests, err = checkedAdd(target.AllowedRequests, 1); err != nil {
			return err
		}
		target.AllowedBytes, err = checkedAdd(target.AllowedBytes, event.BytesSent)
	} else {
		if target.LimitedRequests, err = checkedAdd(target.LimitedRequests, 1); err != nil {
			return err
		}
		target.LimitedBytes, err = checkedAdd(target.LimitedBytes, event.BytesSent)
		if event.UpstreamDurationUS != nil {
			target.LimitedUpstreamUS, err = addNullable(target.LimitedUpstreamUS, *event.UpstreamDurationUS)
			if err == nil {
				target.LimitedUpstreamSamples, err = checkedAdd(target.LimitedUpstreamSamples, 1)
			}
		}
	}
	if err != nil {
		return errors.New("rate impact overflow")
	}
	return nil
}
