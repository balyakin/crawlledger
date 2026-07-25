package apperr

import (
	"context"
	"errors"
	"testing"
)

func TestExitCode(t *testing.T) {
	tests := []struct {
		err  error
		want int
	}{
		{nil, 0},
		{context.Canceled, 130},
		{New(CodeUsage, "cli", "bad input", nil), 2},
		{New(CodeConfig, "config", "bad config", nil), 2},
		{New(CodeInput, "input", "cannot read input", nil), 3},
		{New(CodeParseThreshold, "parse", "too many invalid records", nil), 3},
		{New(CodeStorage, "store", "cannot store analysis", nil), 4},
		{New(CodeOutput, "output", "cannot publish output", nil), 4},
		{New(CodeUnsafePolicy, "policy", "acknowledgement required", nil), 5},
		{New(CodeUnsupportedPolicy, "policy", "unsupported action", nil), 5},
		{errors.New("driver detail"), 1},
	}
	for _, test := range tests {
		if got := ExitCode(test.err); got != test.want {
			t.Errorf("ExitCode(%v) = %d, want %d", test.err, got, test.want)
		}
	}

	wrapped := New(CodeInput, "read", "cannot read input", context.Canceled)
	if ExitCode(wrapped) != 130 || UserMessage(wrapped) != "operation canceled" {
		t.Fatal("cancellation must take precedence")
	}
	if UserMessage(errors.New("secret driver detail")) != "internal error" {
		t.Fatal("unexpected errors must be hidden")
	}
}
