package cost

import (
	"errors"
	"math/big"

	"github.com/balyakin/crawlledger/internal/domain"
)

const (
	monthSeconds = int64(2629746)
	gibBytes     = int64(1 << 30)
)

type Inputs struct {
	FirstEventUS          int64
	LastEventUS           int64
	BytesSent             int64
	UpstreamUS            *int64
	UpstreamCoveragePPM   int64
	MonthlyHostingKopecks int64
	EgressKopecksPerGiB   int64
}

type AvoidedInputs struct {
	FirstEventUS          int64
	LastEventUS           int64
	BytesAvoided          int64
	UpstreamUSAvoided     *int64
	TotalUpstreamUS       *int64
	UpstreamCoveragePPM   int64
	MonthlyHostingKopecks int64
	EgressKopecksPerGiB   int64
}

func Calculate(input Inputs) (domain.CostAllocation, error) {
	result := domain.CostAllocation{Currency: "RUB", Model: "allocation-v1"}
	if input.BytesSent < 0 || input.MonthlyHostingKopecks < 0 || input.EgressKopecksPerGiB < 0 ||
		input.UpstreamCoveragePPM < 0 || input.UpstreamCoveragePPM > 1000000 ||
		input.LastEventUS < input.FirstEventUS || input.UpstreamUS != nil && *input.UpstreamUS < 0 {
		return result, errors.New("invalid cost input")
	}
	if input.EgressKopecksPerGiB > 0 {
		value, err := roundedFraction(
			new(big.Int).Mul(big.NewInt(input.BytesSent), big.NewInt(input.EgressKopecksPerGiB)),
			big.NewInt(gibBytes),
		)
		if err != nil {
			return result, err
		}
		result.EgressKopecks = &value
	}
	if input.MonthlyHostingKopecks > 0 && input.UpstreamUS != nil && input.UpstreamCoveragePPM == 1000000 {
		window := windowSeconds(input.FirstEventUS, input.LastEventUS)
		value, err := AllocateHosting(input.MonthlyHostingKopecks, window, *input.UpstreamUS, *input.UpstreamUS)
		if err != nil {
			return result, err
		}
		result.AllocatedHostingKopecks = &value
	}
	if result.EgressKopecks != nil || result.AllocatedHostingKopecks != nil {
		total := int64(0)
		if result.EgressKopecks != nil {
			total += *result.EgressKopecks
		}
		if result.AllocatedHostingKopecks != nil {
			if total > int64(^uint64(0)>>1)-*result.AllocatedHostingKopecks {
				return result, errors.New("cost overflow")
			}
			total += *result.AllocatedHostingKopecks
		}
		result.TotalAllocatedKopecks = &total
	}
	return result, nil
}

func AllocateHosting(monthlyKopecks, windowSeconds, groupUpstreamUS, totalUpstreamUS int64) (int64, error) {
	if monthlyKopecks < 0 || windowSeconds < 0 || groupUpstreamUS < 0 || totalUpstreamUS <= 0 {
		return 0, errors.New("invalid hosting allocation")
	}
	numerator := new(big.Int).Mul(big.NewInt(monthlyKopecks), big.NewInt(windowSeconds))
	numerator.Mul(numerator, big.NewInt(groupUpstreamUS))
	denominator := new(big.Int).Mul(big.NewInt(monthSeconds), big.NewInt(totalUpstreamUS))
	return roundedFraction(numerator, denominator)
}

func CalculateAvoided(input AvoidedInputs) (*int64, error) {
	if input.BytesAvoided < 0 || input.UpstreamCoveragePPM < 0 ||
		input.UpstreamCoveragePPM > 1000000 || input.LastEventUS < input.FirstEventUS ||
		input.MonthlyHostingKopecks < 0 || input.EgressKopecksPerGiB < 0 ||
		input.UpstreamUSAvoided != nil && *input.UpstreamUSAvoided < 0 ||
		input.TotalUpstreamUS != nil && *input.TotalUpstreamUS < 0 {
		return nil, errors.New("invalid avoided cost input")
	}
	var total int64
	configured := false
	if input.EgressKopecksPerGiB > 0 {
		value, err := roundedFraction(
			new(big.Int).Mul(big.NewInt(input.BytesAvoided), big.NewInt(input.EgressKopecksPerGiB)),
			big.NewInt(gibBytes),
		)
		if err != nil {
			return nil, err
		}
		total, configured = value, true
	}
	if input.MonthlyHostingKopecks > 0 && input.UpstreamCoveragePPM == 1000000 &&
		input.UpstreamUSAvoided != nil && input.TotalUpstreamUS != nil && *input.TotalUpstreamUS > 0 {
		window := windowSeconds(input.FirstEventUS, input.LastEventUS)
		value, err := AllocateHosting(
			input.MonthlyHostingKopecks, window, *input.UpstreamUSAvoided, *input.TotalUpstreamUS,
		)
		if err != nil {
			return nil, err
		}
		if total > int64(^uint64(0)>>1)-value {
			return nil, errors.New("cost overflow")
		}
		total, configured = total+value, true
	}
	if !configured {
		return nil, nil
	}
	return &total, nil
}

func windowSeconds(first, last int64) int64 {
	delta := last - first
	seconds := delta / 1000000
	if delta%1000000 != 0 {
		seconds++
	}
	if seconds < 1 {
		return 1
	}
	return seconds
}

func roundedFraction(numerator, denominator *big.Int) (int64, error) {
	if denominator.Sign() <= 0 || numerator.Sign() < 0 {
		return 0, errors.New("invalid fraction")
	}
	quotient, remainder := new(big.Int), new(big.Int)
	quotient.QuoRem(numerator, denominator, remainder)
	if new(big.Int).Lsh(remainder, 1).Cmp(denominator) >= 0 {
		quotient.Add(quotient, big.NewInt(1))
	}
	if !quotient.IsInt64() {
		return 0, errors.New("cost result overflow")
	}
	return quotient.Int64(), nil
}
