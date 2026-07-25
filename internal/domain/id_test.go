package domain

import (
	"errors"
	"strings"
	"testing"
)

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("random failure") }

func TestIDs(t *testing.T) {
	id, err := NewAnalysisID()
	if err != nil || !strings.HasPrefix(id, "an_") || len(id) != 35 {
		t.Fatalf("invalid analysis id %q: %v", id, err)
	}
	if FindingID(FindingProbe, "/x", "p") != FindingID(FindingProbe, "/x", "p") {
		t.Fatal("finding ID is not stable")
	}
	hash := strings.Repeat("a", 64)
	run, err := SimulationRunID(id, hash)
	if err != nil || len(run) != 19 {
		t.Fatalf("invalid run ID %q: %v", run, err)
	}

	original := randomReader
	randomReader = failingReader{}
	t.Cleanup(func() { randomReader = original })
	if _, err := NewAnalysisID(); err == nil {
		t.Fatal("random failure ignored")
	}
}
