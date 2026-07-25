package domain

import (
	"math"
	"testing"
)

func TestRatioPPMDoesNotOverflow(t *testing.T) {
	if got := RatioPPM(math.MaxInt64-1, math.MaxInt64); got != 999_999 {
		t.Fatalf("RatioPPM() = %d, want 999999", got)
	}
}
