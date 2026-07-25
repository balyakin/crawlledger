package policy

import (
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
)

func BenchmarkSimulateOneMillionCells(b *testing.B) {
	value := testPolicy()
	_, hash, _ := Canonical(value)
	prefix := "/public"
	cell := domain.TrafficCell{
		Route: "/public", ActionablePrefix: &prefix, Method: "GET",
		PrimaryClass: domain.ClassUnclassified, Requests: 1, BytesSent: 1,
	}
	for b.Loop() {
		simulator := NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
		for range 1000000 {
			if err := simulator.Add(cell); err != nil {
				b.Fatal(err)
			}
		}
		if _, err := simulator.Finish(nil); err != nil {
			b.Fatal(err)
		}
	}
}
