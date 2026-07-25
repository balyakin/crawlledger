package aggregate

import (
	"context"
	"testing"

	"github.com/balyakin/crawlledger/internal/config"
)

func BenchmarkAggregate(b *testing.B) {
	for b.Loop() {
		aggregator := New(config.Default(), &memorySink{})
		for range 1000 {
			if err := aggregator.Add(context.Background(), validEvent()); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := aggregator.Finish(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}
