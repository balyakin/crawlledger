package protect

import (
	"math"
	"reflect"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
)

const testManifestDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestBuildBaselineUsesCompleteMinutesAndZeroFill(t *testing.T) {
	prefix := "/api/search"
	history := domain.ProtectionHistory{
		InputFormat:  "nginx-json",
		FirstEventUS: minuteUS,
		LastEventUS:  101 * minuteUS,
		Cells: []domain.ProtectionCell{
			{BucketMinuteUS: minuteUS, Route: "/api/search/{int}", ActionablePrefix: &prefix,
				Method: "GET", Requests: 99, UpstreamDurationUS: 990, UpstreamSamples: 99},
			{BucketMinuteUS: minuteUS, Route: "/api/search/{uuid}", ActionablePrefix: &prefix,
				Method: "GET", Requests: 1, UpstreamDurationUS: 10, UpstreamSamples: 1},
			{BucketMinuteUS: 2 * minuteUS, Route: "/api/search/{int}", ActionablePrefix: &prefix,
				Method: "GET", Requests: 100, UpstreamDurationUS: 1000, UpstreamSamples: 100},
		},
	}

	baseline, err := BuildBaseline(history, testManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.CompleteStartUS != minuteUS || baseline.CompleteEndUS != 101*minuteUS ||
		baseline.CompleteMinutes != 100 {
		t.Fatalf("unexpected complete range: %#v", baseline)
	}
	if baseline.PrefixRequestP99("GET", prefix) != 100 {
		t.Fatalf("prefix p99 = %d", baseline.PrefixRequestP99("GET", prefix))
	}
	if baseline.RouteRequestP99("GET", "/api/search/{int}") != 99 {
		t.Fatalf("route request p99 = %d", baseline.RouteRequestP99("GET", "/api/search/{int}"))
	}
	if baseline.RouteUpstreamP99("GET", "/api/search/{int}") != 990 {
		t.Fatalf("route upstream p99 = %d", baseline.RouteUpstreamP99("GET", "/api/search/{int}"))
	}
	if baseline.RouteRequestP99("GET", "/api/search/{uuid}") != 0 {
		t.Fatal("zero-filled route did not produce zero p99")
	}
	if baseline.Eligible || !reflect.DeepEqual(baseline.IneligibilityReasons, []string{"fewer-than-1440-complete-minutes"}) {
		t.Fatalf("unexpected eligibility: %#v", baseline.IneligibilityReasons)
	}
}

func TestBuildBaselineExcludesPartialBoundaryMinutes(t *testing.T) {
	prefix := "/api"
	history := domain.ProtectionHistory{
		InputFormat:  "nginx-json",
		FirstEventUS: minuteUS + 1,
		LastEventUS:  5*minuteUS + 1,
		Cells: []domain.ProtectionCell{
			{BucketMinuteUS: minuteUS, Route: "/api", ActionablePrefix: &prefix,
				Method: "POST", Requests: 1000},
			{BucketMinuteUS: 2 * minuteUS, Route: "/api", ActionablePrefix: &prefix,
				Method: "POST", Requests: 7},
			{BucketMinuteUS: 5 * minuteUS, Route: "/api", ActionablePrefix: &prefix,
				Method: "POST", Requests: 2000},
		},
	}

	baseline, err := BuildBaseline(history, testManifestDigest)
	if err != nil {
		t.Fatal(err)
	}
	if baseline.CompleteStartUS != 2*minuteUS || baseline.CompleteEndUS != 5*minuteUS ||
		baseline.CompleteMinutes != 3 || baseline.PrefixRequestP99("POST", prefix) != 7 {
		t.Fatalf("partial boundary cells leaked into baseline: %#v", baseline)
	}
}

func TestBuildBaselineEligibility(t *testing.T) {
	tests := []struct {
		name    string
		history domain.ProtectionHistory
		want    []string
	}{
		{
			name: "eligible",
			history: domain.ProtectionHistory{
				InputFormat: "nginx-json", FirstEventUS: minuteUS, LastEventUS: 1441 * minuteUS,
				Cells: []domain.ProtectionCell{},
			},
		},
		{
			name: "wrong format",
			history: domain.ProtectionHistory{
				InputFormat: "nginx-combined", FirstEventUS: minuteUS, LastEventUS: 1441 * minuteUS,
				Cells: []domain.ProtectionCell{},
			},
			want: []string{"input-format-is-not-nginx-json"},
		},
		{
			name: "overflow",
			history: domain.ProtectionHistory{
				InputFormat: "nginx-json", FirstEventUS: minuteUS, LastEventUS: 1441 * minuteUS,
				RouteOverflowRequests: 1,
				Cells: []domain.ProtectionCell{{BucketMinuteUS: minuteUS, Route: "/overflow",
					RouteOverflow: true, Method: "GET", Requests: 1}},
			},
			want: []string{"route-overflow"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline, err := BuildBaseline(test.history, testManifestDigest)
			if err != nil {
				t.Fatal(err)
			}
			if baseline.Eligible != (len(test.want) == 0) ||
				!reflect.DeepEqual(baseline.IneligibilityReasons, test.want) {
				t.Fatalf("unexpected eligibility: %#v", baseline.IneligibilityReasons)
			}
		})
	}
}

func TestBaselineEffectiveThresholds(t *testing.T) {
	config := Config{Detection: Detection{
		WindowSeconds:            10,
		BaselineMultiplier:       10,
		VolumeMinRequests:        5,
		DistributedMinRequests:   7,
		DistributedMinUpstreamUS: 11,
	}}
	baseline := Baseline{
		prefixRequests: map[seriesKey]int64{{Method: "GET", Path: "/api"}: 61},
		routeRequests:  map[seriesKey]int64{{Method: "GET", Path: "/api/{int}"}: 119},
		routeUpstream:  map[seriesKey]int64{{Method: "GET", Path: "/api/{int}"}: 121},
	}

	prefixThreshold, err := baseline.PrefixRequestThreshold(config, "GET", "/api")
	if err != nil {
		t.Fatal(err)
	}
	routeThreshold, err := baseline.RouteRequestThreshold(config, "GET", "/api/{int}")
	if err != nil {
		t.Fatal(err)
	}
	upstreamThreshold, err := baseline.RouteUpstreamThreshold(config, "GET", "/api/{int}")
	if err != nil {
		t.Fatal(err)
	}
	absentThreshold, err := baseline.RouteRequestThreshold(config, "POST", "/absent")
	if err != nil {
		t.Fatal(err)
	}
	if prefixThreshold != 110 || routeThreshold != 200 || upstreamThreshold != 210 || absentThreshold != 7 {
		t.Fatalf("unexpected thresholds: prefix=%d route=%d upstream=%d absent=%d",
			prefixThreshold, routeThreshold, upstreamThreshold, absentThreshold)
	}
	baseline.routeRequests[seriesKey{Method: "GET", Path: "/overflow"}] = math.MaxInt64
	if _, err := baseline.RouteRequestThreshold(config, "GET", "/overflow"); err == nil {
		t.Fatal("threshold overflow accepted")
	}
}

func TestBuildBaselineRejectsInvalidInput(t *testing.T) {
	history := domain.ProtectionHistory{
		InputFormat: "nginx-json", FirstEventUS: 2 * minuteUS, LastEventUS: minuteUS,
		Cells: []domain.ProtectionCell{},
	}
	if _, err := BuildBaseline(history, testManifestDigest); err == nil {
		t.Fatal("inverted event range accepted")
	}
	history.FirstEventUS = minuteUS
	history.LastEventUS = 2 * minuteUS
	if _, err := BuildBaseline(history, "bad-digest"); err == nil {
		t.Fatal("invalid manifest digest accepted")
	}
}
