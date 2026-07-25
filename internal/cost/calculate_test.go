package cost

import "testing"

func TestCalculate(t *testing.T) {
	upstream := int64(1000000)
	result, err := Calculate(Inputs{
		FirstEventUS: 1, LastEventUS: 1000001, BytesSent: 1 << 30, UpstreamUS: &upstream,
		UpstreamCoveragePPM: 1000000, MonthlyHostingKopecks: 2629746, EgressKopecksPerGiB: 123,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.EgressKopecks == nil || *result.EgressKopecks != 123 {
		t.Fatalf("unexpected egress: %#v", result)
	}
	if result.AllocatedHostingKopecks == nil || *result.AllocatedHostingKopecks != 1 {
		t.Fatalf("unexpected hosting allocation: %#v", result)
	}
}

func TestCalculateAvoided(t *testing.T) {
	upstreamAvoided, upstreamTotal := int64(500000), int64(1000000)
	value, err := CalculateAvoided(AvoidedInputs{
		FirstEventUS: 1, LastEventUS: 1000001, BytesAvoided: 1 << 30,
		UpstreamUSAvoided: &upstreamAvoided, TotalUpstreamUS: &upstreamTotal,
		UpstreamCoveragePPM: 1000000, MonthlyHostingKopecks: monthSeconds * 2,
		EgressKopecksPerGiB: 100,
	})
	if err != nil || value == nil || *value != 101 {
		t.Fatalf("unexpected avoided allocation: %v, %v", value, err)
	}
}
