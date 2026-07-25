package domain

import "math/bits"

func RatioPPM(numerator, denominator int64) int64 {
	if numerator <= 0 || denominator <= 0 {
		return 0
	}
	if numerator >= denominator {
		return 1_000_000
	}
	high, low := bits.Mul64(uint64(numerator), 1_000_000)
	quotient, _ := bits.Div64(high, low, uint64(denominator))
	return int64(quotient)
}
