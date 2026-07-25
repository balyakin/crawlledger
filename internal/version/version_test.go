package version

import (
	"runtime"
	"testing"
)

func TestCurrent(t *testing.T) {
	got := Current()
	if got.Version != "dev" || got.Commit != "unknown" || got.BuiltAt != "unknown" || got.Go != runtime.Version() {
		t.Fatalf("unexpected version info: %#v", got)
	}
}
