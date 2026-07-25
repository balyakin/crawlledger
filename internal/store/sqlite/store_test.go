package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/domain"
)

func TestMigrationAndLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "analysis.sqlite")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, database); err != nil {
		t.Fatal(err)
	}
	store := New(database)
	analysis := domain.Analysis{
		ID: "an_0123456789abcdef0123456789abcdef", SchemaVersion: 1, ToolVersion: "test",
		Status: "running", StartedAtUS: 1, InputFormat: "nginx-combined",
		CatalogVersion: "test", KeyID: "0123456789abcdef", ConfigJSON: "{}",
	}
	if err := store.CreateAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSource(ctx, 0, "plain", nil); err != nil {
		t.Fatal(err)
	}
	batch := aggregate.Batch{
		UserAgents: []aggregate.UARow{{ID: 1, Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		Routes:     []aggregate.RouteRow{{ID: 1, Route: "/"}},
		Cells: []aggregate.CellRow{{
			RouteID: 1, UAID: 1, PrimaryClass: domain.ClassUnclassified, Method: "GET",
			Status: 200, CacheState: domain.CacheUnknown, Requests: 1,
		}},
	}
	if err := store.Flush(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteSource(ctx, 0, 1, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1, 1, 0, 0); err != nil {
		t.Fatal(err)
	}
	summary := aggregate.Summary{TotalLines: 1, Accepted: 1}
	if err := store.CompleteAnalysis(ctx, summary); err != nil {
		t.Fatal(err)
	}
}

func TestReportCombinesRouteSafetyVariants(t *testing.T) {
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
		ID: "an_0123456789abcdef0123456789abcdef", SchemaVersion: 1, ToolVersion: "test",
		Status: "running", StartedAtUS: 1, InputFormat: "nginx-combined",
		CatalogVersion: "test", KeyID: "0123456789abcdef", ConfigJSON: "{}",
	}
	if err := store.CreateAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	prefix := "/api"
	batch := aggregate.Batch{
		UserAgents: []aggregate.UARow{{ID: 1, Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		Routes: []aggregate.RouteRow{
			{ID: 1, Route: "/api", ActionablePrefix: &prefix},
			{ID: 2, Route: "/api"},
		},
		Cells: []aggregate.CellRow{
			{RouteID: 1, UAID: 1, PrimaryClass: domain.ClassUnclassified, Method: "GET", Status: 200, CacheState: domain.CacheUnknown, Requests: 1},
			{RouteID: 2, UAID: 1, PrimaryClass: domain.ClassUnclassified, Method: "GET", Status: 200, CacheState: domain.CacheUnknown, Requests: 1},
		},
		RouteStats: []aggregate.RouteStatsRow{
			{RouteID: 1, Requests: 1, DistinctClientsKMV: sketchBytes(t, "client-a"), DistinctURLsKMV: sketchBytes(t, "url-a"), DistinctQueriesKMV: sketchBytes(t)},
			{RouteID: 2, Requests: 1, DistinctClientsKMV: sketchBytes(t, "client-b"), DistinctURLsKMV: sketchBytes(t, "url-b"), DistinctQueriesKMV: sketchBytes(t)},
		},
		QueryKeys: []aggregate.QueryKeyRow{
			{RouteID: 1, Key: "page", Requests: 1},
			{RouteID: 2, Key: "page", Requests: 1},
		},
	}
	if err := store.Flush(ctx, batch); err != nil {
		t.Fatal(err)
	}
	data, err := store.LoadReportData(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(data.Routes) != 1 || data.Routes[0].Requests != 2 ||
		data.Routes[0].ActionablePrefix != nil || data.Routes[0].DistinctURLs != 2 ||
		!reflect.DeepEqual(data.Routes[0].TopQueryKeys, []string{"page"}) {
		t.Fatalf("route variants were not combined safely: %#v", data.Routes)
	}
}

func TestFlushMergesIncrementalAggregates(t *testing.T) {
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
		ID: "an_0123456789abcdef0123456789abcdef", SchemaVersion: 1, ToolVersion: "test",
		Status: "running", StartedAtUS: 1, InputFormat: "nginx-combined",
		CatalogVersion: "test", KeyID: "0123456789abcdef", ConfigJSON: "{}",
	}
	if err := store.CreateAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	base := aggregate.Batch{
		UserAgents: []aggregate.UARow{{ID: 1, Hash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},
		Routes:     []aggregate.RouteRow{{ID: 1, Route: "/"}},
		RouteStats: []aggregate.RouteStatsRow{{
			RouteID: 1, Requests: 1, DistinctClientsKMV: sketchBytes(t, "client-a"),
			DistinctURLsKMV: sketchBytes(t, "url-a"), DistinctQueriesKMV: sketchBytes(t, "query-a"),
		}},
		Subjects: []aggregate.SubjectRow{{
			ClientKey: "0123456789abcdef0123456789abcdef", UAID: 1, Requests: 1,
			DistinctRoutesKMV: sketchBytes(t, "/a"), FirstSeenUS: 2, LastSeenUS: 2,
		}},
		RobotsViolations: []aggregate.RobotsRow{{UAID: 1, RouteID: 1, Requests: 1}},
		QueryKeys:        []aggregate.QueryKeyRow{{RouteID: 1, Key: "page", Requests: 1}},
		ProbeHits:        []aggregate.ProbeRow{{ProbeID: "probe", RouteID: 1, Requests: 1}},
	}
	if err := store.Flush(ctx, base); err != nil {
		t.Fatal(err)
	}
	delta := aggregate.Batch{
		RouteStats: []aggregate.RouteStatsRow{{
			RouteID: 1, Requests: 2, DistinctClientsKMV: sketchBytes(t, "client-b"),
			DistinctURLsKMV: sketchBytes(t, "url-b"), DistinctQueriesKMV: sketchBytes(t, "query-b"),
		}},
		Subjects: []aggregate.SubjectRow{{
			ClientKey: "0123456789abcdef0123456789abcdef", UAID: 1, Requests: 2,
			DistinctRoutesKMV: sketchBytes(t, "/b"), FirstSeenUS: 1, LastSeenUS: 3,
		}},
		RobotsViolations: []aggregate.RobotsRow{{UAID: 1, RouteID: 1, Requests: 2}},
		QueryKeys:        []aggregate.QueryKeyRow{{RouteID: 1, Key: "page", Requests: 2}},
		ProbeHits:        []aggregate.ProbeRow{{ProbeID: "probe", RouteID: 1, Requests: 2}},
	}
	if err := store.Flush(ctx, delta); err != nil {
		t.Fatal(err)
	}
	var routeRequests, subjectRequests, firstSeen, lastSeen, robots, query, probes int64
	var clients []byte
	if err := database.QueryRowContext(ctx, `
		SELECT requests, distinct_clients_kmv FROM route_stats WHERE analysis_id=? AND route_id=1`,
		analysis.ID).Scan(&routeRequests, &clients); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRowContext(ctx, `
		SELECT requests, first_seen_us, last_seen_us FROM subject_stats
		WHERE analysis_id=? AND client_key=? AND user_agent_id=1`,
		analysis.ID, "0123456789abcdef0123456789abcdef",
	).Scan(&subjectRequests, &firstSeen, &lastSeen); err != nil {
		t.Fatal(err)
	}
	for queryText, target := range map[string]*int64{
		"SELECT requests FROM robots_violations WHERE analysis_id=?": &robots,
		"SELECT requests FROM route_query_keys WHERE analysis_id=?":  &query,
		"SELECT requests FROM probe_hits WHERE analysis_id=?":        &probes,
	} {
		if err := database.QueryRowContext(ctx, queryText, analysis.ID).Scan(target); err != nil {
			t.Fatal(err)
		}
	}
	var sketch aggregate.Sketch
	if err := sketch.UnmarshalBinary(clients); err != nil {
		t.Fatal(err)
	}
	if routeRequests != 3 || sketch.Estimate(3) != 2 || subjectRequests != 3 ||
		firstSeen != 1 || lastSeen != 3 || robots != 3 || query != 3 || probes != 3 {
		t.Fatalf("incremental aggregates not merged: route=%d clients=%d subject=%d range=%d..%d robot=%d query=%d probes=%d",
			routeRequests, sketch.Estimate(3), subjectRequests, firstSeen, lastSeen, robots, query, probes)
	}
}

func TestOpenReadOnlyFileUsesOpenedInode(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "analysis.sqlite")
	replacement := filepath.Join(dir, "replacement.sqlite")
	for databasePath, marker := range map[string]string{path: "verified", replacement: "replacement"} {
		database, err := Open(ctx, databasePath)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, "CREATE TABLE marker (value TEXT NOT NULL) STRICT"); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(ctx, "INSERT INTO marker VALUES (?)", marker); err != nil {
			t.Fatal(err)
		}
		if err := database.Close(); err != nil {
			t.Fatal(err)
		}
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err := os.Rename(path, filepath.Join(dir, "verified.sqlite")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	database, cleanup, err := OpenReadOnlyFile(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	defer database.Close()
	var marker string
	if err := database.QueryRowContext(ctx, "SELECT value FROM marker").Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "verified" {
		t.Fatalf("opened replacement database: %q", marker)
	}
}

func sketchBytes(t *testing.T, values ...string) []byte {
	t.Helper()
	var sketch aggregate.Sketch
	for _, value := range values {
		sketch.Add(value)
	}
	encoded, err := sketch.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
