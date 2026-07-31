package protect

import (
	"errors"
	"runtime"
	"testing"
)

func TestMutationPlatformBoundary(t *testing.T) {
	err := RequireMutationPlatform()
	if runtime.GOOS == "linux" {
		if err != nil {
			t.Fatalf("Linux rejected: %v", err)
		}
		return
	}
	if !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("non-Linux mutation returned %v", err)
	}
}
