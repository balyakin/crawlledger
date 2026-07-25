package parser

import (
	"errors"
	"math"
	"strconv"
	"strings"
)

func decimalSecondsToMicroseconds(value string) (int64, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "eE+-") {
		return 0, errors.New("invalid decimal")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" {
		return 0, errors.New("invalid decimal")
	}
	whole, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || whole > math.MaxInt64/1000000 {
		return 0, errors.New("decimal overflow")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
		if fraction == "" {
			return 0, errors.New("invalid decimal")
		}
		for _, r := range fraction {
			if r < '0' || r > '9' {
				return 0, errors.New("invalid decimal")
			}
		}
	}
	roundUp := len(fraction) > 6 && fraction[6] >= '5'
	if len(fraction) > 6 {
		fraction = fraction[:6]
	}
	fraction += strings.Repeat("0", 6-len(fraction))
	micros, err := strconv.ParseInt(fraction, 10, 64)
	if err != nil {
		return 0, errors.New("invalid decimal")
	}
	result := whole * 1000000
	if result > math.MaxInt64-micros {
		return 0, errors.New("decimal overflow")
	}
	result += micros
	if roundUp {
		if result == math.MaxInt64 {
			return 0, errors.New("decimal overflow")
		}
		result++
	}
	return result, nil
}
