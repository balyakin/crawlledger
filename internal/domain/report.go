package domain

type Analysis struct {
	ID             string
	SchemaVersion  int
	ToolVersion    string
	Status         string
	StartedAtUS    int64
	FinishedAtUS   *int64
	FirstEventUS   *int64
	LastEventUS    *int64
	InputFormat    string
	CatalogVersion string
	KeyID          string
	ConfigJSON     string
}

type AnalysisSummary struct {
	AnalysisID              string
	TotalLines              int64
	Accepted                int64
	Rejected                int64
	Skipped                 int64
	BytesSent               int64
	RequestDurationUS       *int64
	RequestDurationSamples  int64
	UpstreamDurationUS      *int64
	UpstreamDurationSamples int64
	CacheSamples            int64
	RefererSamples          int64
	RobotsChecked           int64
	RateModeled             int64
	FirstEventUS            *int64
	LastEventUS             *int64
	RouteOverflow           int64
	UAOverflow              int64
	SubjectOverflow         int64
	OrderDegraded           bool
}

type ClassStats struct {
	Class              TrafficClass `json:"class"`
	Requests           int64        `json:"requests"`
	BytesSent          int64        `json:"bytes_sent"`
	UpstreamDurationUS *int64       `json:"upstream_duration_us"`
}

type CrawlerStats struct {
	Name               string       `json:"name"`
	Category           TrafficClass `json:"category"`
	ProtectedDefault   bool         `json:"protected_default"`
	Requests           int64        `json:"requests"`
	BytesSent          int64        `json:"bytes_sent"`
	UpstreamDurationUS *int64       `json:"upstream_duration_us"`
}

type RouteStats struct {
	ID                  int64    `json:"-"`
	Route               string   `json:"route"`
	ActionablePrefix    *string  `json:"actionable_prefix"`
	Overflow            bool     `json:"-"`
	Requests            int64    `json:"requests"`
	QueryRequests       int64    `json:"query_requests"`
	Status404           int64    `json:"status_404"`
	CacheMisses         int64    `json:"cache_misses"`
	CacheSamples        int64    `json:"-"`
	CacheEligible       int64    `json:"-"`
	BytesSent           int64    `json:"bytes_sent"`
	UpstreamDurationUS  *int64   `json:"upstream_duration_us"`
	UpstreamSamples     int64    `json:"-"`
	DistinctClients     int64    `json:"distinct_clients"`
	DistinctURLs        int64    `json:"distinct_urls"`
	DistinctQueries     int64    `json:"distinct_queries"`
	DistinctApproximate bool     `json:"distinct_approximate"`
	TopQueryKeys        []string `json:"top_query_keys"`
	ProbeRequests       int64    `json:"-"`
}

type SubjectStats struct {
	ClientKey        string
	Claimed          bool
	Requests         int64
	Status4xx        int64
	NoReferer        int64
	ProbeRequests    int64
	RobotsViolations int64
	DistinctRoutes   int64
	FirstSeenUS      int64
	LastSeenUS       int64
}

type RobotsViolationStats struct {
	Crawler  string
	Route    string
	Requests int64
}

type ProbeHitStats struct {
	ProbeID  string
	Route    string
	Requests int64
}

type TrafficCell struct {
	Route            string
	ActionablePrefix *string
	Method           string
	ClaimName        *string
	ClaimCategory    *TrafficClass
	ProtectedDefault bool
	PrimaryClass     TrafficClass
	Status           int
	CacheState       CacheState
	Requests         int64
	BytesSent        int64
	UpstreamUS       *int64
	UpstreamSamples  int64
}

type RateProfileImpact struct {
	ClaimName              *string
	ClaimCategory          *TrafficClass
	ProtectedDefault       bool
	PrimaryClass           TrafficClass
	Profile                string
	ModeledRequests        int64
	AllowedRequests        int64
	LimitedRequests        int64
	AllowedBytes           int64
	LimitedBytes           int64
	LimitedUpstreamUS      *int64
	LimitedUpstreamSamples int64
}

type ReportData struct {
	Analysis Analysis
	Summary  AnalysisSummary
	Classes  []ClassStats
	Crawlers []CrawlerStats
	Routes   []RouteStats
	Subjects []SubjectStats
	Robots   []RobotsViolationStats
	Probes   []ProbeHitStats
	Findings []Finding
	Cost     CostAllocation
	Warnings []string
}

type CostMetadata struct {
	FirstEventUS            *int64
	LastEventUS             *int64
	Accepted                int64
	BytesSent               int64
	UpstreamUS              *int64
	UpstreamDurationSamples int64
	ConfigJSON              string
}

type CostAllocation struct {
	Currency                string `json:"currency"`
	EgressKopecks           *int64 `json:"egress_kopecks"`
	AllocatedHostingKopecks *int64 `json:"allocated_hosting_kopecks"`
	TotalAllocatedKopecks   *int64 `json:"total_allocated_kopecks"`
	Model                   string `json:"model"`
}
