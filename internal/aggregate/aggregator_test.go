package aggregate

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/domain"
)

type memorySink struct {
	batches []Batch
	err     error
}

func (s *memorySink) Flush(_ context.Context, batch Batch) error {
	if s.err != nil {
		return s.err
	}
	s.batches = append(s.batches, batch)
	return nil
}

func TestAggregateConservation(t *testing.T) {
	sink := &memorySink{}
	aggregator := New(config.Default(), sink)
	for index := range 3 {
		event := validEvent()
		event.TimestampUS += int64(index)
		event.BytesSent = int64(index + 1)
		if err := aggregator.Add(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := aggregator.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Accepted != 3 || summary.BytesSent != 6 || len(sink.batches) != 1 {
		t.Fatalf("conservation failed: %#v, batches=%d", summary, len(sink.batches))
	}
	if _, err := aggregator.Finish(context.Background()); err == nil {
		t.Fatal("second Finish succeeded")
	}
}

func TestAllAggregateMapsFlushAtBatchLimit(t *testing.T) {
	cfg := config.Default()
	cfg.Limits.MaxBatchCells = 5
	sink := &memorySink{}
	aggregator := New(cfg, sink)
	for range 2 {
		event := validEvent()
		event.QueryKeys = []string{"page"}
		query := "0123456789abcdef0123456789abcdef"
		event.QueryFingerprint = &query
		event.SecurityProbeIDs = []string{"log4shell-probe"}
		event.PrimaryClass = domain.ClassSecurityProbe
		event.Claim = &domain.CrawlerClaim{
			Name: "SyntheticBot", Category: domain.ClassClaimedOtherCrawler,
		}
		denied := false
		event.RobotsAllowed = &denied
		if err := aggregator.Add(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := aggregator.Finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sink.batches) != 2 {
		t.Fatalf("aggregate maps were retained until Finish: %d batches", len(sink.batches))
	}
	for _, batch := range sink.batches {
		if len(batch.RouteStats) != 1 || len(batch.Subjects) != 1 ||
			len(batch.RobotsViolations) != 1 || len(batch.QueryKeys) != 1 || len(batch.ProbeHits) != 1 {
			t.Fatalf("incomplete incremental batch: %#v", batch)
		}
	}
}

func TestSinkFailureRetainsBatch(t *testing.T) {
	sink := &memorySink{err: errors.New("disk full")}
	aggregator := New(config.Default(), sink)
	if err := aggregator.Add(context.Background(), validEvent()); err != nil {
		t.Fatal(err)
	}
	if _, err := aggregator.Finish(context.Background()); err == nil {
		t.Fatal("sink failure ignored")
	}
}

func TestAggregateOverflowIsNotOverwritten(t *testing.T) {
	duration := int64(1)
	event := validEvent()
	event.UpstreamDurationUS = &duration
	aggregator := &Aggregator{
		routeStats: map[int64]*routeAccumulator{
			1: {row: RouteStatsRow{RouteID: 1, BytesSent: math.MaxInt64}},
		},
	}
	if err := aggregator.addRoute(1, event); err == nil {
		t.Fatal("route bytes overflow was ignored")
	}
	aggregator.summary.BytesSent = math.MaxInt64
	if err := aggregator.addSummary(event); err == nil {
		t.Fatal("summary bytes overflow was ignored")
	}
	referer := "example.test"
	event.RefererHost = &referer
	if err := addCell(&CellRow{RefererPresent: math.MaxInt64}, event); err == nil {
		t.Fatal("cell sample overflow was ignored")
	}
}

func validEvent() domain.Event {
	return domain.Event{
		TimestampUS: 1, ClientKey: "0123456789abcdef0123456789abcdef", Method: "GET",
		Route: "/", URLFingerprint: "0123456789abcdef0123456789abcdef",
		QueryKeys: []string{}, Status: 200, BytesSent: 1, CacheState: domain.CacheUnknown,
		UAHash:           "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		SecurityProbeIDs: []string{}, PrimaryClass: domain.ClassUnclassified,
	}
}

func FuzzKMVDecode(f *testing.F) {
	f.Add([]byte{1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		var sketch Sketch
		if err := sketch.UnmarshalBinary(data); err == nil {
			encoded, err := sketch.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var decoded Sketch
			if err := decoded.UnmarshalBinary(encoded); err != nil {
				t.Fatal(err)
			}
		}
	})
}
