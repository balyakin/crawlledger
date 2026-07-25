package findings

import (
	"testing"

	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/domain"
)

func TestThresholdsAndMissingMetrics(t *testing.T) {
	cfg := config.Default()
	prefix := "/archive/"
	findings, err := Detect(cfg, Input{
		Analysis: domain.AnalysisSummary{Accepted: 1000},
		Routes: []domain.RouteStats{{
			Route: "/archive/{int}", ActionablePrefix: &prefix, Requests: 1000,
			QueryRequests: 500, DistinctURLs: 500, DistinctQueries: 300,
		}},
		Robots: []domain.RobotsViolationStats{{Crawler: "SyntheticBot", Route: "/private", Requests: 100}},
		Probes: []domain.ProbeHitStats{{ProbeID: "wp-admin", Route: "/wp-admin", Requests: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	foundCrawlTrap, foundMetrics, foundRobots, foundProbe := false, false, false, false
	for _, finding := range findings {
		foundCrawlTrap = foundCrawlTrap || finding.Kind == domain.FindingCrawlTrap
		foundMetrics = foundMetrics || finding.Kind == domain.FindingMetrics
		foundRobots = foundRobots || finding.Kind == domain.FindingRobots
		foundProbe = foundProbe || finding.Kind == domain.FindingProbe
	}
	if !foundCrawlTrap || !foundMetrics || !foundRobots || !foundProbe {
		t.Fatalf("expected findings missing: %#v", findings)
	}
}
