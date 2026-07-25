package findings

import (
	"errors"
	"fmt"
	"sort"

	"github.com/balyakin/crawlledger/internal/config"
	"github.com/balyakin/crawlledger/internal/domain"
)

type Input struct {
	Analysis domain.AnalysisSummary
	Routes   []domain.RouteStats
	Subjects []domain.SubjectStats
	Crawlers []domain.CrawlerStats
	Robots   []domain.RobotsViolationStats
	Probes   []domain.ProbeHitStats
}

func Detect(cfg config.Config, input Input) ([]domain.Finding, error) {
	result := make([]domain.Finding, 0)
	for _, route := range input.Routes {
		if route.Overflow || route.Requests == 0 {
			continue
		}
		result = append(result, routeFindings(cfg, route, input.Analysis.UpstreamDurationUS)...)
	}
	result = append(result, automationFindings(cfg, input.Subjects)...)
	result = append(result, robotsFindings(input.Robots)...)
	result = append(result, probeFindings(input.Probes)...)
	result = append(result, coverageFindings(input.Analysis)...)
	seen := make(map[string]struct{}, len(result))
	for _, finding := range result {
		if _, exists := seen[finding.ID]; exists {
			return nil, errors.New("duplicate finding ID")
		}
		seen[finding.ID] = struct{}{}
		sort.Slice(finding.Evidence, func(i, j int) bool {
			return finding.Evidence[i].Metric < finding.Evidence[j].Metric
		})
	}
	sort.SliceStable(result, func(i, j int) bool {
		left, right := severityRank(result[i].Severity), severityRank(result[j].Severity)
		if left != right {
			return left > right
		}
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		leftRoute, rightRoute := pointer(result[i].Route), pointer(result[j].Route)
		if leftRoute != rightRoute {
			return leftRoute < rightRoute
		}
		return pointer(result[i].Subject) < pointer(result[j].Subject)
	})
	if len(result) > 10000 {
		result = result[:10000]
	}
	return result, nil
}

func robotsFindings(rows []domain.RobotsViolationStats) []domain.Finding {
	result := make([]domain.Finding, 0, len(rows))
	for _, row := range rows {
		severity := volumeSeverity(row.Requests)
		route, crawler := row.Route, row.Crawler
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingRobots, route, crawler),
			Kind: domain.FindingRobots, Severity: severity,
			Title:   "Claimed crawler robots.txt violation: " + crawler,
			Summary: fmt.Sprintf("Observed %d requests by a claimed crawler to a disallowed route.", row.Requests),
			Route:   &route, Subject: &crawler,
			Evidence: []domain.Evidence{
				{Metric: "requests", Value: row.Requests, Threshold: 1, Unit: "count"},
			},
			RecommendedAction: "review_robots_policy_and_crawler_claim", Confidence: "high",
		})
	}
	return result
}

func probeFindings(rows []domain.ProbeHitStats) []domain.Finding {
	result := make([]domain.Finding, 0, len(rows))
	for _, row := range rows {
		route, probe := row.Route, row.ProbeID
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingProbe, route, probe),
			Kind: domain.FindingProbe, Severity: volumeSeverity(row.Requests),
			Title:   "Security probe traffic under " + route,
			Summary: fmt.Sprintf("Observed %d requests matching the %s aggregate signature.", row.Requests, probe),
			Route:   &route, Subject: &probe,
			Evidence: []domain.Evidence{
				{Metric: "requests", Value: row.Requests, Threshold: 1, Unit: "count"},
			},
			RecommendedAction: "review_and_deny_literal_path_after_validation", Confidence: "high",
		})
	}
	return result
}

func volumeSeverity(requests int64) domain.Severity {
	if requests >= 1000 {
		return domain.SeverityHigh
	}
	if requests >= 100 {
		return domain.SeverityMedium
	}
	return domain.SeverityLow
}

func routeFindings(cfg config.Config, route domain.RouteStats, totalUpstream *int64) []domain.Finding {
	var result []domain.Finding
	t := cfg.Thresholds
	if route.Requests >= t.CrawltrapMinRequests && route.DistinctURLs >= t.CrawltrapMinURLVariants &&
		ratio(route.DistinctURLs, route.Requests) >= t.CrawltrapVariantRatioPPM &&
		(route.QueryRequests > 0 || containsPlaceholder(route.Route)) {
		severity := domain.SeverityMedium
		if route.Requests/t.CrawltrapMinRequests >= 10 && route.UpstreamDurationUS != nil &&
			totalUpstream != nil && ratio(*route.UpstreamDurationUS, *totalUpstream) >= 10000 {
			severity = domain.SeverityHigh
		}
		result = append(result, makeRouteFinding(
			domain.FindingCrawlTrap, severity, route.Route,
			"High URL cardinality under "+route.Route,
			fmt.Sprintf("Observed %d requests and at least %d distinct URL variants.", route.Requests, route.DistinctURLs),
			"review_navigation_and_deny_or_canonicalize",
			[]domain.Evidence{
				{Metric: "requests", Value: route.Requests, Threshold: t.CrawltrapMinRequests, Unit: "count"},
				{Metric: "distinct_approximate", Value: boolInt(route.DistinctApproximate), Threshold: 0, Unit: "boolean"},
				{Metric: "url_variants", Value: route.DistinctURLs, Threshold: t.CrawltrapMinURLVariants, Unit: "count"},
			},
		))
	}
	if route.ActionablePrefix != nil && route.QueryRequests >= t.QueryMinRequests &&
		route.DistinctQueries >= t.QueryMinVariants &&
		ratio(route.DistinctQueries, route.QueryRequests) >= t.QueryVariantRatioPPM &&
		route.DistinctURLs >= t.QueryMinVariants {
		result = append(result, makeRouteFinding(
			domain.FindingQuerySpace, domain.SeverityMedium, route.Route,
			"Query-space expansion under "+route.Route,
			fmt.Sprintf("Observed %d query requests and at least %d distinct query shapes.", route.QueryRequests, route.DistinctQueries),
			"review_navigation_and_deny_or_canonicalize",
			[]domain.Evidence{
				{Metric: "query_requests", Value: route.QueryRequests, Threshold: t.QueryMinRequests, Unit: "count"},
				{Metric: "query_variants", Value: route.DistinctQueries, Threshold: t.QueryMinVariants, Unit: "count"},
			},
		))
	}
	if route.Requests >= t.Expensive404MinRequests && ratio(route.Status404, route.Requests) >= t.Expensive404RatioPPM &&
		route.UpstreamDurationUS != nil && *route.UpstreamDurationUS >= t.Expensive404MinUpstreamUS {
		confidence := "high"
		if ratio(route.UpstreamSamples, route.Requests) < 900000 {
			confidence = "medium"
		}
		finding := makeRouteFinding(
			domain.FindingExpensive404, domain.SeverityHigh, route.Route,
			"High-cost 404 traffic under "+route.Route,
			fmt.Sprintf("Observed %d requests; %d returned 404.", route.Requests, route.Status404),
			"deny_path_after_review",
			[]domain.Evidence{
				{Metric: "requests", Value: route.Requests, Threshold: t.Expensive404MinRequests, Unit: "count"},
				{Metric: "status_404_ppm", Value: ratio(route.Status404, route.Requests), Threshold: t.Expensive404RatioPPM, Unit: "ppm"},
				{Metric: "upstream_us", Value: *route.UpstreamDurationUS, Threshold: t.Expensive404MinUpstreamUS, Unit: "microseconds"},
			},
		)
		finding.Confidence = confidence
		result = append(result, finding)
	}
	if route.CacheEligible >= t.CacheBustMinRequests && route.DistinctQueries >= t.QueryMinVariants &&
		ratio(route.CacheSamples, route.CacheEligible) >= 900000 &&
		ratio(route.CacheMisses, route.CacheSamples) >= t.CacheBustMissRatioPPM {
		evidence := []domain.Evidence{
			{Metric: "cache_miss_ppm", Value: ratio(route.CacheMisses, route.CacheSamples), Threshold: t.CacheBustMissRatioPPM, Unit: "ppm"},
			{Metric: "cache_samples", Value: route.CacheSamples, Threshold: t.CacheBustMinRequests, Unit: "count"},
		}
		if route.UpstreamDurationUS != nil {
			evidence = append(evidence, domain.Evidence{
				Metric: "upstream_us", Value: *route.UpstreamDurationUS, Threshold: 0, Unit: "microseconds",
			})
		}
		result = append(result, makeRouteFinding(
			domain.FindingCacheBusting, domain.SeverityMedium, route.Route,
			"Cache-busting query traffic under "+route.Route,
			fmt.Sprintf("Observed %d cache misses, bypasses or expired responses.", route.CacheMisses),
			"review_cache_key_and_response_headers",
			evidence,
		))
	}
	return result
}

func automationFindings(cfg config.Config, subjects []domain.SubjectStats) []domain.Finding {
	var result []domain.Finding
	t := cfg.Thresholds
	for _, subject := range subjects {
		if subject.Claimed || subject.Requests < t.AutomationMinRequests {
			continue
		}
		score := int64(0)
		if subject.DistinctRoutes >= t.AutomationMinRoutes {
			score += 2
		}
		if ratio(subject.Status4xx, subject.Requests) >= t.Automation4xxRatioPPM {
			score += 2
		}
		if ratio(subject.NoReferer, subject.Requests) >= t.AutomationNoRefererRatioPPM {
			score++
		}
		probe := subject.ProbeRequests >= t.AutomationMinProbes
		if probe {
			score += 2
		}
		span := subject.LastSeenUS - subject.FirstSeenUS
		if span >= 10*60*1000000 && subject.Requests >= (span-1)/1000000+1 {
			score++
		}
		if score < int64(t.AutomationScoreThreshold) {
			continue
		}
		display := subject.ClientKey
		if len(display) > 12 {
			display = display[:12] + "…"
		}
		confidence := "low"
		if score >= int64(t.AutomationScoreThreshold+2) {
			confidence = "medium"
			if probe {
				confidence = "high"
			}
		}
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingAutomation, "", subject.ClientKey),
			Kind: domain.FindingAutomation, Severity: domain.SeverityMedium,
			Title:   "Unclaimed automation candidate " + display,
			Summary: fmt.Sprintf("Aggregate behavior reached the automation-candidate score %d.", score),
			Subject: &display, Evidence: []domain.Evidence{
				{Metric: "score", Value: score, Threshold: int64(t.AutomationScoreThreshold), Unit: "points"},
				{Metric: "requests", Value: subject.Requests, Threshold: t.AutomationMinRequests, Unit: "count"},
			},
			RecommendedAction: "investigate_automation_candidate", Confidence: confidence,
		})
	}
	return result
}

func coverageFindings(summary domain.AnalysisSummary) []domain.Finding {
	var result []domain.Finding
	for _, metric := range []struct {
		name    string
		samples int64
	}{
		{"request_duration", summary.RequestDurationSamples},
		{"upstream_duration", summary.UpstreamDurationSamples},
		{"cache_state", summary.CacheSamples},
	} {
		if summary.Accepted == 0 || metric.samples != 0 {
			continue
		}
		subject := metric.name
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingMetrics, "", subject),
			Kind: domain.FindingMetrics, Severity: domain.SeverityInfo,
			Title:   "Metric unavailable: " + metric.name,
			Summary: "This input format did not provide " + metric.name + " values.",
			Subject: &subject, Evidence: []domain.Evidence{},
			RecommendedAction: "use_structured_logs_for_full_metrics", Confidence: "high",
		})
	}
	if summary.RouteOverflow+summary.UAOverflow+summary.SubjectOverflow > 0 {
		subject := "bounded_dimensions"
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingCardinality, "", subject),
			Kind: domain.FindingCardinality, Severity: domain.SeverityMedium,
			Title:   "Cardinality limit reached",
			Summary: "One or more bounded aggregate dimensions overflowed; affected policy dimensions are not actionable.",
			Subject: &subject, Evidence: []domain.Evidence{},
			RecommendedAction: "review_cardinality_limits", Confidence: "high",
		})
	}
	if summary.OrderDegraded {
		subject := "rate_model"
		result = append(result, domain.Finding{
			ID:   domain.FindingID(domain.FindingOrder, "", subject),
			Kind: domain.FindingOrder, Severity: domain.SeverityMedium,
			Title:   "Out-of-order input reduced rate-model coverage",
			Summary: "Rate-limit estimates exclude affected out-of-order subject streams.",
			Subject: &subject, Evidence: []domain.Evidence{},
			RecommendedAction: "sort_logs_by_timestamp_before_analysis", Confidence: "high",
		})
	}
	return result
}

func makeRouteFinding(kind domain.FindingKind, severity domain.Severity, route, title, summary, action string, evidence []domain.Evidence) domain.Finding {
	return domain.Finding{
		ID: domain.FindingID(kind, route, ""), Kind: kind, Severity: severity,
		Title: title, Summary: summary, Route: &route, Evidence: evidence,
		RecommendedAction: action, Confidence: "high",
	}
}

func ratio(numerator, denominator int64) int64 {
	return domain.RatioPPM(numerator, denominator)
}

func containsPlaceholder(route string) bool {
	for index := 0; index < len(route); index++ {
		if route[index] == '{' {
			return true
		}
	}
	return false
}

func severityRank(value domain.Severity) int {
	switch value {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	default:
		return 1
	}
}

func pointer(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func boolInt(value bool) int64 {
	if value {
		return 1
	}
	return 0
}
