package config

import "fmt"

type Config struct {
	SchemaVersion int        `json:"schema_version"`
	Limits        Limits     `json:"limits"`
	Thresholds    Thresholds `json:"thresholds"`
	Costs         Costs      `json:"costs"`
}

type Limits struct {
	MaxLineBytes         int   `json:"max_line_bytes"`
	MaxUncompressedBytes int64 `json:"max_uncompressed_bytes"`
	MaxGzipRatio         int64 `json:"max_gzip_ratio"`
	MaxRoutes            int   `json:"max_routes"`
	MaxUserAgents        int   `json:"max_user_agents"`
	MaxRateSubjects      int   `json:"max_rate_subjects"`
	MaxBatchCells        int   `json:"max_batch_cells"`
	MaxSavedParseErrors  int   `json:"max_saved_parse_errors"`
}

type Thresholds struct {
	CrawltrapMinRequests        int64 `json:"crawltrap_min_requests"`
	CrawltrapMinURLVariants     int64 `json:"crawltrap_min_url_variants"`
	CrawltrapVariantRatioPPM    int64 `json:"crawltrap_variant_ratio_ppm"`
	QueryMinRequests            int64 `json:"query_min_requests"`
	QueryMinVariants            int64 `json:"query_min_variants"`
	QueryVariantRatioPPM        int64 `json:"query_variant_ratio_ppm"`
	Expensive404MinRequests     int64 `json:"expensive_404_min_requests"`
	Expensive404RatioPPM        int64 `json:"expensive_404_ratio_ppm"`
	Expensive404MinUpstreamUS   int64 `json:"expensive_404_min_upstream_us"`
	CacheBustMinRequests        int64 `json:"cache_bust_min_requests"`
	CacheBustMissRatioPPM       int64 `json:"cache_bust_miss_ratio_ppm"`
	AutomationMinRequests       int64 `json:"automation_min_requests"`
	AutomationMinRoutes         int64 `json:"automation_min_routes"`
	Automation4xxRatioPPM       int64 `json:"automation_4xx_ratio_ppm"`
	AutomationNoRefererRatioPPM int64 `json:"automation_no_referer_ratio_ppm"`
	AutomationMinProbes         int64 `json:"automation_min_probes"`
	AutomationScoreThreshold    int   `json:"automation_score_threshold"`
}

type Costs struct {
	MonthlyHostingKopecks int64 `json:"monthly_hosting_kopecks"`
	EgressKopecksPerGiB   int64 `json:"egress_kopecks_per_gib"`
}

func Default() Config {
	return Config{
		SchemaVersion: 1,
		Limits: Limits{
			MaxLineBytes: 1048576, MaxUncompressedBytes: 21474836480, MaxGzipRatio: 200,
			MaxRoutes: 50000, MaxUserAgents: 100000, MaxRateSubjects: 100000,
			MaxBatchCells: 50000, MaxSavedParseErrors: 1000,
		},
		Thresholds: Thresholds{
			CrawltrapMinRequests: 1000, CrawltrapMinURLVariants: 200, CrawltrapVariantRatioPPM: 500000,
			QueryMinRequests: 500, QueryMinVariants: 200, QueryVariantRatioPPM: 300000,
			Expensive404MinRequests: 100, Expensive404RatioPPM: 700000, Expensive404MinUpstreamUS: 5000000,
			CacheBustMinRequests: 500, CacheBustMissRatioPPM: 800000,
			AutomationMinRequests: 1000, AutomationMinRoutes: 300, Automation4xxRatioPPM: 800000,
			AutomationNoRefererRatioPPM: 990000, AutomationMinProbes: 10, AutomationScoreThreshold: 4,
		},
		Costs: Costs{},
	}
}

func (c Config) Validate() error {
	if c.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1")
	}
	l := c.Limits
	checks := []struct {
		path       string
		value, min int64
		max        int64
	}{
		{"limits.max_line_bytes", int64(l.MaxLineBytes), 4096, 16 << 20},
		{"limits.max_uncompressed_bytes", l.MaxUncompressedBytes, 1 << 20, 1 << 40},
		{"limits.max_gzip_ratio", l.MaxGzipRatio, 1, 1000},
		{"limits.max_routes", int64(l.MaxRoutes), 100, 200000},
		{"limits.max_user_agents", int64(l.MaxUserAgents), 100, 500000},
		{"limits.max_rate_subjects", int64(l.MaxRateSubjects), 1000, 1000000},
		{"limits.max_batch_cells", int64(l.MaxBatchCells), 100, 100000},
		{"limits.max_saved_parse_errors", int64(l.MaxSavedParseErrors), 0, 10000},
	}
	for _, check := range checks {
		if check.value < check.min || check.value > check.max {
			return fmt.Errorf("%s must be between %d and %d", check.path, check.min, check.max)
		}
	}
	t := c.Thresholds
	positive := []struct {
		path  string
		value int64
	}{
		{"thresholds.crawltrap_min_requests", t.CrawltrapMinRequests},
		{"thresholds.crawltrap_min_url_variants", t.CrawltrapMinURLVariants},
		{"thresholds.query_min_requests", t.QueryMinRequests},
		{"thresholds.query_min_variants", t.QueryMinVariants},
		{"thresholds.expensive_404_min_requests", t.Expensive404MinRequests},
		{"thresholds.expensive_404_min_upstream_us", t.Expensive404MinUpstreamUS},
		{"thresholds.cache_bust_min_requests", t.CacheBustMinRequests},
		{"thresholds.automation_min_requests", t.AutomationMinRequests},
		{"thresholds.automation_min_routes", t.AutomationMinRoutes},
		{"thresholds.automation_min_probes", t.AutomationMinProbes},
	}
	for _, check := range positive {
		if check.value <= 0 {
			return fmt.Errorf("%s must be positive", check.path)
		}
	}
	for path, value := range map[string]int64{
		"thresholds.crawltrap_variant_ratio_ppm":     t.CrawltrapVariantRatioPPM,
		"thresholds.query_variant_ratio_ppm":         t.QueryVariantRatioPPM,
		"thresholds.expensive_404_ratio_ppm":         t.Expensive404RatioPPM,
		"thresholds.cache_bust_miss_ratio_ppm":       t.CacheBustMissRatioPPM,
		"thresholds.automation_4xx_ratio_ppm":        t.Automation4xxRatioPPM,
		"thresholds.automation_no_referer_ratio_ppm": t.AutomationNoRefererRatioPPM,
	} {
		if value < 0 || value > 1000000 {
			return fmt.Errorf("%s must be between 0 and 1000000", path)
		}
	}
	if t.CrawltrapMinURLVariants > t.CrawltrapMinRequests || t.QueryMinVariants > t.QueryMinRequests {
		return fmt.Errorf("minimum variants cannot exceed minimum requests")
	}
	if t.AutomationScoreThreshold < 1 || t.AutomationScoreThreshold > 10 {
		return fmt.Errorf("thresholds.automation_score_threshold must be between 1 and 10")
	}
	const maxMoney = int64(10000000000)
	if c.Costs.MonthlyHostingKopecks < 0 || c.Costs.MonthlyHostingKopecks > maxMoney ||
		c.Costs.EgressKopecksPerGiB < 0 || c.Costs.EgressKopecksPerGiB > maxMoney {
		return fmt.Errorf("costs must be between 0 and %d kopecks", maxMoney)
	}
	return nil
}
