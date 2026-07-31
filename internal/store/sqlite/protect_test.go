package sqlite

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/domain"
)

func TestLoadProtectionHistoryAggregatesEligibleCells(t *testing.T) {
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "analysis.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store := New(database)
	analysis := domain.Analysis{
		ID:             "an_0123456789abcdef0123456789abcdef",
		SchemaVersion:  1,
		ToolVersion:    "test",
		Status:         "running",
		StartedAtUS:    1,
		InputFormat:    "nginx-json",
		CatalogVersion: "test",
		KeyID:          "0123456789abcdef",
		ConfigJSON:     "{}",
	}
	if err := store.CreateAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	prefix := "/api/search"
	upstream300 := int64(300)
	upstream400 := int64(400)
	upstream700 := int64(700)
	upstream1100 := int64(1100)
	batch := aggregate.Batch{
		UserAgents: []aggregate.UARow{
			{ID: 1, Hash: "1111111111111111111111111111111111111111111111111111111111111111"},
			{ID: 2, Hash: "2222222222222222222222222222222222222222222222222222222222222222"},
		},
		Routes: []aggregate.RouteRow{
			{ID: 1, Route: "/api/search/{int}", ActionablePrefix: &prefix},
			{ID: 2, Route: "/__overflow__", Overflow: true},
		},
		Cells: []aggregate.CellRow{
			{BucketMinuteUS: 60_000_000, RouteID: 1, UAID: 1, PrimaryClass: domain.ClassUnclassified,
				Method: "GET", Status: 200, CacheState: domain.CacheMiss, Requests: 3,
				UpstreamDurationUS: &upstream300, UpstreamSamples: 3},
			{BucketMinuteUS: 60_000_000, RouteID: 1, UAID: 2, PrimaryClass: domain.ClassSecurityProbe,
				Method: "GET", Status: 404, CacheState: domain.CacheHit, Requests: 2,
				UpstreamDurationUS: &upstream400, UpstreamSamples: 2},
			{BucketMinuteUS: 60_000_000, RouteID: 1, UAID: 1, PrimaryClass: domain.ClassUnclassified,
				Method: "GET", Status: 403, CacheState: domain.CacheUnknown, Requests: 7,
				UpstreamDurationUS: &upstream700, UpstreamSamples: 7},
			{BucketMinuteUS: 60_000_000, RouteID: 1, UAID: 1, PrimaryClass: domain.ClassUnclassified,
				Method: "GET", Status: 429, CacheState: domain.CacheUnknown, Requests: 11,
				UpstreamDurationUS: &upstream1100, UpstreamSamples: 11},
			{BucketMinuteUS: 120_000_000, RouteID: 2, UAID: 1, PrimaryClass: domain.ClassUnclassified,
				Method: "GET", Status: 200, CacheState: domain.CacheUnknown, Requests: 1},
		},
	}
	if err := store.Flush(ctx, batch); err != nil {
		t.Fatal(err)
	}
	firstEventUS := int64(60_000_000)
	lastEventUS := int64(180_000_000)
	summary := aggregate.Summary{
		TotalLines:    24,
		Accepted:      24,
		FirstEventUS:  &firstEventUS,
		LastEventUS:   &lastEventUS,
		RouteOverflow: 1,
	}
	if err := store.CompleteAnalysis(ctx, summary); err != nil {
		t.Fatal(err)
	}

	history, err := store.LoadProtectionHistory(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expected := ProtectionHistory{
		InputFormat:           "nginx-json",
		FirstEventUS:          firstEventUS,
		LastEventUS:           lastEventUS,
		RouteOverflowRequests: 1,
		Cells: []ProtectionCell{
			{BucketMinuteUS: 60_000_000, Route: "/api/search/{int}", ActionablePrefix: &prefix,
				Method: "GET", Requests: 5, UpstreamDurationUS: 700, UpstreamSamples: 5},
			{BucketMinuteUS: 120_000_000, Route: "/__overflow__", RouteOverflow: true,
				Method: "GET", Requests: 1},
		},
	}
	if !reflect.DeepEqual(history, expected) {
		t.Fatalf("unexpected protection history:\n got: %#v\nwant: %#v", history, expected)
	}
}
