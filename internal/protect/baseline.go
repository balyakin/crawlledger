package protect

import (
	"errors"
	"fmt"
	"math"
	"sort"

	"github.com/balyakin/crawlledger/internal/domain"
)

const minuteUS int64 = 60_000_000
const minimumLiveMinutes int64 = 1440

type Baseline struct {
	ManifestSHA256       string
	CompleteStartUS      int64
	CompleteEndUS        int64
	CompleteMinutes      int64
	Eligible             bool
	IneligibilityReasons []string
	prefixRequests       map[seriesKey]int64
	routeRequests        map[seriesKey]int64
	routeUpstream        map[seriesKey]int64
}

type seriesKey struct {
	Method string
	Path   string
}

type sparseSeries map[seriesKey]map[int64]int64

func BuildBaseline(history domain.ProtectionHistory, manifestSHA256 string) (Baseline, error) {
	if !lowerDigest(manifestSHA256) {
		return Baseline{}, errors.New("invalid baseline manifest digest")
	}
	start, end, minutes, err := completeMinuteRange(history.FirstEventUS, history.LastEventUS)
	if err != nil {
		return Baseline{}, err
	}
	prefixRequests := make(sparseSeries)
	routeRequests := make(sparseSeries)
	routeUpstream := make(sparseSeries)
	routeOverflow := history.RouteOverflowRequests > 0
	for index, cell := range history.Cells {
		if err := validateProtectionCell(cell); err != nil {
			return Baseline{}, fmt.Errorf("protection cell %d: %w", index, err)
		}
		if cell.RouteOverflow {
			routeOverflow = true
		}
		routeKey := seriesKey{Method: cell.Method, Path: cell.Route}
		ensureSeries(routeRequests, routeKey)
		ensureSeries(routeUpstream, routeKey)
		if cell.ActionablePrefix != nil {
			prefixKey := seriesKey{Method: cell.Method, Path: *cell.ActionablePrefix}
			ensureSeries(prefixRequests, prefixKey)
		}
		if cell.BucketMinuteUS < start || cell.BucketMinuteUS >= end {
			continue
		}
		if err := addSeriesValue(routeRequests, routeKey, cell.BucketMinuteUS, cell.Requests); err != nil {
			return Baseline{}, err
		}
		if err := addSeriesValue(routeUpstream, routeKey, cell.BucketMinuteUS, cell.UpstreamDurationUS); err != nil {
			return Baseline{}, err
		}
		if cell.ActionablePrefix != nil {
			prefixKey := seriesKey{Method: cell.Method, Path: *cell.ActionablePrefix}
			if err := addSeriesValue(prefixRequests, prefixKey, cell.BucketMinuteUS, cell.Requests); err != nil {
				return Baseline{}, err
			}
		}
	}
	reasons := baselineIneligibility(history.InputFormat, minutes, routeOverflow)
	return Baseline{
		ManifestSHA256:       manifestSHA256,
		CompleteStartUS:      start,
		CompleteEndUS:        end,
		CompleteMinutes:      minutes,
		Eligible:             len(reasons) == 0,
		IneligibilityReasons: reasons,
		prefixRequests:       calculateP99(prefixRequests, minutes),
		routeRequests:        calculateP99(routeRequests, minutes),
		routeUpstream:        calculateP99(routeUpstream, minutes),
	}, nil
}

func (baseline Baseline) PrefixRequestP99(method, prefix string) int64 {
	return baseline.prefixRequests[seriesKey{Method: method, Path: prefix}]
}

func (baseline Baseline) RouteRequestP99(method, route string) int64 {
	return baseline.routeRequests[seriesKey{Method: method, Path: route}]
}

func (baseline Baseline) RouteUpstreamP99(method, route string) int64 {
	return baseline.routeUpstream[seriesKey{Method: method, Path: route}]
}

func (baseline Baseline) PrefixRequestThreshold(config Config, method, prefix string) (int64, error) {
	return effectiveThreshold(
		baseline.PrefixRequestP99(method, prefix),
		config.Detection.VolumeMinRequests,
		config.Detection.BaselineMultiplier,
		config.Detection.WindowSeconds,
	)
}

func (baseline Baseline) RouteRequestThreshold(config Config, method, route string) (int64, error) {
	return effectiveThreshold(
		baseline.RouteRequestP99(method, route),
		config.Detection.DistributedMinRequests,
		config.Detection.BaselineMultiplier,
		config.Detection.WindowSeconds,
	)
}

func (baseline Baseline) RouteUpstreamThreshold(config Config, method, route string) (int64, error) {
	return effectiveThreshold(
		baseline.RouteUpstreamP99(method, route),
		config.Detection.DistributedMinUpstreamUS,
		config.Detection.BaselineMultiplier,
		config.Detection.WindowSeconds,
	)
}

func completeMinuteRange(firstEventUS, lastEventUS int64) (int64, int64, int64, error) {
	if firstEventUS <= 0 || lastEventUS < firstEventUS {
		return 0, 0, 0, errors.New("invalid baseline event range")
	}
	start := firstEventUS / minuteUS * minuteUS
	if firstEventUS%minuteUS != 0 {
		if start > math.MaxInt64-minuteUS {
			return 0, 0, 0, errors.New("baseline event range overflows")
		}
		start += minuteUS
	}
	end := lastEventUS / minuteUS * minuteUS
	if end <= start {
		return start, end, 0, nil
	}
	return start, end, (end - start) / minuteUS, nil
}

func validateProtectionCell(cell domain.ProtectionCell) error {
	if cell.BucketMinuteUS < 0 || cell.BucketMinuteUS%minuteUS != 0 ||
		!domain.ValidMethod(cell.Method) || cell.Route == "" || cell.Requests <= 0 ||
		cell.UpstreamDurationUS < 0 || cell.UpstreamSamples < 0 ||
		cell.UpstreamSamples == 0 && cell.UpstreamDurationUS != 0 {
		return errors.New("invalid historical aggregate")
	}
	if cell.ActionablePrefix != nil && !domain.ValidActionable(*cell.ActionablePrefix) {
		return errors.New("invalid actionable prefix")
	}
	return nil
}

func ensureSeries(series sparseSeries, key seriesKey) {
	if _, exists := series[key]; !exists {
		series[key] = make(map[int64]int64)
	}
}

func addSeriesValue(series sparseSeries, key seriesKey, bucket, value int64) error {
	current := series[key][bucket]
	if value > math.MaxInt64-current {
		return errors.New("historical aggregate overflows")
	}
	series[key][bucket] = current + value
	return nil
}

func calculateP99(series sparseSeries, minutes int64) map[seriesKey]int64 {
	result := make(map[seriesKey]int64, len(series))
	for key, buckets := range series {
		values := make([]int64, 0, len(buckets))
		for _, value := range buckets {
			if value > 0 {
				values = append(values, value)
			}
		}
		sort.Slice(values, func(left, right int) bool { return values[left] < values[right] })
		result[key] = nearestRankP99(values, minutes)
	}
	return result
}

func nearestRankP99(nonzeroValues []int64, totalValues int64) int64 {
	if totalValues <= 0 {
		return 0
	}
	rank := (99*totalValues + 99) / 100
	zeroValues := totalValues - int64(len(nonzeroValues))
	if rank <= zeroValues {
		return 0
	}
	return nonzeroValues[rank-zeroValues-1]
}

func baselineIneligibility(inputFormat string, minutes int64, routeOverflow bool) []string {
	var reasons []string
	if inputFormat != "nginx-json" {
		reasons = append(reasons, "input-format-is-not-nginx-json")
	}
	if minutes < minimumLiveMinutes {
		reasons = append(reasons, "fewer-than-1440-complete-minutes")
	}
	if routeOverflow {
		reasons = append(reasons, "route-overflow")
	}
	return reasons
}

func effectiveThreshold(p99, floor, multiplier int64, windowSeconds int) (int64, error) {
	if p99 < 0 || floor <= 0 || multiplier <= 0 || windowSeconds <= 0 {
		return 0, errors.New("invalid threshold inputs")
	}
	if p99 > math.MaxInt64/int64(windowSeconds) {
		return 0, errors.New("threshold scaling overflows")
	}
	product := p99 * int64(windowSeconds)
	scaled := product / 60
	if product%60 != 0 {
		scaled++
	}
	if scaled > math.MaxInt64/multiplier {
		return 0, errors.New("threshold multiplication overflows")
	}
	threshold := scaled * multiplier
	if threshold < floor {
		threshold = floor
	}
	return threshold, nil
}
