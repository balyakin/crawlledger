package domain

type ActionKind string

const (
	ActionAllow     ActionKind = "allow"
	ActionDeny      ActionKind = "deny"
	ActionRateLimit ActionKind = "rate_limit"
	ActionCache     ActionKind = "cache"
)

func (a ActionKind) Valid() bool {
	return a == ActionAllow || a == ActionDeny || a == ActionRateLimit || a == ActionCache
}

type Policy struct {
	SchemaVersion int          `json:"schema_version"`
	Name          string       `json:"name"`
	Description   string       `json:"description"`
	Rules         []PolicyRule `json:"rules"`
}

type PolicyRule struct {
	ID     string       `json:"id"`
	Match  PolicyMatch  `json:"match"`
	Action PolicyAction `json:"action"`
}

type PolicyMatch struct {
	CrawlerNames []string       `json:"crawler_names"`
	Categories   []TrafficClass `json:"categories"`
	PathPrefixes []string       `json:"path_prefixes"`
	Methods      []string       `json:"methods"`
}

type PolicyAction struct {
	Kind            ActionKind `json:"kind"`
	RateProfile     *string    `json:"rate_profile"`
	CacheTTLSeconds *int       `json:"cache_ttl_seconds"`
}

type PolicyCell struct {
	Route            string
	ActionablePrefix *string
	Method           string
	ClaimName        *string
	ClaimCategory    *TrafficClass
	ProtectedDefault bool
	PrimaryClass     TrafficClass
	Requests         int64
	BytesSent        int64
	UpstreamUS       *int64
}

type SimulationStatus string

const (
	SimulationSafe        SimulationStatus = "safe"
	SimulationRequiresAck SimulationStatus = "requires_ack"
	SimulationBlocked     SimulationStatus = "blocked"
	SimulationAnalysis    SimulationStatus = "analysis_only"
)

type SimulationCoverage struct {
	RateModelPPM       int64  `json:"rate_model_ppm"`
	PathPolicyCoverage *int64 `json:"path_policy_coverage_ppm"`
}

type SimulationTotals struct {
	ObservedRequests            int64  `json:"observed_requests"`
	AllowedRequests             int64  `json:"allowed_requests"`
	DeniedRequests              int64  `json:"denied_requests"`
	RateLimitedRequests         int64  `json:"rate_limited_requests"`
	CacheCandidateRequests      int64  `json:"cache_candidate_requests"`
	BytesAvoided                int64  `json:"bytes_avoided"`
	UpstreamUSAvoided           *int64 `json:"upstream_us_avoided"`
	AllocatedCostAvoidedKopecks *int64 `json:"allocated_cost_avoided_kopecks"`
}

type RuleImpact struct {
	RuleID                      string     `json:"rule_id"`
	Action                      ActionKind `json:"action"`
	MatchedRequests             int64      `json:"matched_requests"`
	Allowed                     int64      `json:"allowed"`
	Denied                      int64      `json:"denied"`
	RateLimited                 int64      `json:"rate_limited"`
	BytesAvoided                int64      `json:"bytes_avoided"`
	UpstreamUSAvoided           *int64     `json:"upstream_us_avoided"`
	AllocatedCostAvoidedKopecks *int64     `json:"allocated_cost_avoided_kopecks"`
	ClaimedCrawlersAffected     []string   `json:"claimed_crawlers_affected"`
	TopRoutesAffected           []string   `json:"top_routes_affected"`
	MetricCoveragePPM           int64      `json:"metric_coverage_ppm"`
	PathPolicyCoveragePPM       *int64     `json:"path_policy_coverage_ppm"`
	EligibleObserved            int64      `json:"eligible_observed"`
	CacheMissesObserved         int64      `json:"cache_misses_observed"`
	Warnings                    []string   `json:"warnings"`
}

type Risk struct {
	ID              string   `json:"id"`
	Severity        Severity `json:"severity"`
	Acknowledgeable bool     `json:"acknowledgeable"`
	Message         string   `json:"message"`
}

type Simulation struct {
	SchemaVersion int                `json:"schema_version"`
	RunID         string             `json:"run_id"`
	AnalysisID    string             `json:"analysis_id"`
	PolicyHash    string             `json:"policy_hash"`
	Status        SimulationStatus   `json:"status"`
	Coverage      SimulationCoverage `json:"coverage"`
	Totals        SimulationTotals   `json:"totals"`
	RuleImpacts   []RuleImpact       `json:"rule_impacts"`
	Risks         []Risk             `json:"risks"`
	Assumptions   []string           `json:"assumptions"`
}
