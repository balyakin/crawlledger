package domain

type FindingKind string

const (
	FindingCrawlTrap    FindingKind = "crawl_trap_path_cardinality"
	FindingQuerySpace   FindingKind = "query_space_explosion"
	FindingExpensive404 FindingKind = "expensive_404"
	FindingCacheBusting FindingKind = "cache_busting"
	FindingRobots       FindingKind = "robots_violation"
	FindingProbe        FindingKind = "security_probe"
	FindingAutomation   FindingKind = "automation_candidate"
	FindingMetrics      FindingKind = "metrics_missing"
	FindingOrder        FindingKind = "input_order_degraded"
	FindingCardinality  FindingKind = "cardinality_overflow"
)

func (k FindingKind) Valid() bool {
	switch k {
	case FindingCrawlTrap, FindingQuerySpace, FindingExpensive404, FindingCacheBusting,
		FindingRobots, FindingProbe, FindingAutomation, FindingMetrics, FindingOrder, FindingCardinality:
		return true
	default:
		return false
	}
}

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	return s == SeverityInfo || s == SeverityLow || s == SeverityMedium || s == SeverityHigh || s == SeverityCritical
}

type Evidence struct {
	Metric    string `json:"metric"`
	Value     int64  `json:"value"`
	Threshold int64  `json:"threshold"`
	Unit      string `json:"unit"`
}

type Finding struct {
	ID                string      `json:"id"`
	Kind              FindingKind `json:"kind"`
	Severity          Severity    `json:"severity"`
	Title             string      `json:"title"`
	Summary           string      `json:"summary"`
	Route             *string     `json:"route"`
	Subject           *string     `json:"subject"`
	Evidence          []Evidence  `json:"evidence"`
	RecommendedAction string      `json:"recommended_action"`
	Confidence        string      `json:"confidence"`
}
