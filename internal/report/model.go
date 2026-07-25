package report

import (
	"errors"
	"sort"
	"time"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/version"
)

type Model struct {
	SchemaVersion   int                   `json:"schema_version"`
	Tool            Tool                  `json:"tool"`
	Analysis        Analysis              `json:"analysis"`
	Coverage        Coverage              `json:"coverage"`
	Totals          Totals                `json:"totals"`
	Classes         []domain.ClassStats   `json:"classes"`
	Crawlers        []domain.CrawlerStats `json:"crawlers"`
	Routes          []domain.RouteStats   `json:"routes"`
	Findings        []domain.Finding      `json:"findings"`
	Cost            domain.CostAllocation `json:"cost"`
	Methodology     Methodology           `json:"methodology"`
	Assumptions     []string              `json:"assumptions"`
	DegradedReasons []string              `json:"degraded_reasons"`
	Warnings        []string              `json:"warnings"`
}

type Tool struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	CatalogVersion string `json:"catalog_version"`
}

type Analysis struct {
	ID           string  `json:"id"`
	StartedAt    string  `json:"started_at"`
	FinishedAt   string  `json:"finished_at"`
	FirstEventAt *string `json:"first_event_at"`
	LastEventAt  *string `json:"last_event_at"`
	Status       string  `json:"status"`
	InputFormat  string  `json:"input_format"`
}

type Coverage struct {
	RequestDurationPPM  int64 `json:"request_duration_ppm"`
	UpstreamDurationPPM int64 `json:"upstream_duration_ppm"`
	CacheStatePPM       int64 `json:"cache_state_ppm"`
	RefererPPM          int64 `json:"referer_ppm"`
	RobotsCheckedPPM    int64 `json:"robots_checked_ppm"`
	RateModelPPM        int64 `json:"rate_model_ppm"`
}

type Totals struct {
	Lines              int64  `json:"lines"`
	Accepted           int64  `json:"accepted"`
	Rejected           int64  `json:"rejected"`
	Skipped            int64  `json:"skipped"`
	Requests           int64  `json:"requests"`
	BytesSent          int64  `json:"bytes_sent"`
	RequestDurationUS  *int64 `json:"request_duration_us"`
	UpstreamDurationUS *int64 `json:"upstream_duration_us"`
}

type Methodology struct {
	Classification     string `json:"classification"`
	RouteNormalization string `json:"route_normalization"`
	CostAllocation     string `json:"cost_allocation"`
}

type Builder struct{ build version.Info }

func NewBuilder(build version.Info) *Builder { return &Builder{build: build} }

func (b *Builder) Build(data domain.ReportData) (Model, error) {
	if data.Analysis.ID == "" || data.Summary.Accepted+data.Summary.Rejected+data.Summary.Skipped != data.Summary.TotalLines {
		return Model{}, errors.New("invalid report data")
	}
	finished := data.Analysis.FinishedAtUS
	if finished == nil {
		value := time.Now().UTC().UnixMicro()
		finished = &value
	}
	model := Model{
		SchemaVersion: 1,
		Tool:          Tool{Name: "crawlledger", Version: b.build.Version, CatalogVersion: data.Analysis.CatalogVersion},
		Analysis: Analysis{
			ID: data.Analysis.ID, StartedAt: formatTime(data.Analysis.StartedAtUS),
			FinishedAt: formatTime(*finished), FirstEventAt: formatOptionalTime(data.Summary.FirstEventUS),
			LastEventAt: formatOptionalTime(data.Summary.LastEventUS), Status: "completed",
			InputFormat: data.Analysis.InputFormat,
		},
		Coverage: Coverage{
			RequestDurationPPM:  domain.RatioPPM(data.Summary.RequestDurationSamples, data.Summary.Accepted),
			UpstreamDurationPPM: domain.RatioPPM(data.Summary.UpstreamDurationSamples, data.Summary.Accepted),
			CacheStatePPM:       domain.RatioPPM(data.Summary.CacheSamples, data.Summary.Accepted),
			RefererPPM:          domain.RatioPPM(data.Summary.RefererSamples, data.Summary.Accepted),
			RobotsCheckedPPM:    domain.RatioPPM(data.Summary.RobotsChecked, data.Summary.Accepted),
			RateModelPPM:        domain.RatioPPM(data.Summary.RateModeled, data.Summary.Accepted),
		},
		Totals: Totals{
			Lines: data.Summary.TotalLines, Accepted: data.Summary.Accepted,
			Rejected: data.Summary.Rejected, Skipped: data.Summary.Skipped,
			Requests: data.Summary.Accepted, BytesSent: data.Summary.BytesSent,
			RequestDurationUS:  data.Summary.RequestDurationUS,
			UpstreamDurationUS: data.Summary.UpstreamDurationUS,
		},
		Classes:  append([]domain.ClassStats{}, data.Classes...),
		Crawlers: append([]domain.CrawlerStats{}, data.Crawlers...),
		Routes:   append([]domain.RouteStats{}, data.Routes...),
		Findings: append([]domain.Finding{}, data.Findings...),
		Cost:     data.Cost,
		Methodology: Methodology{
			Classification: "claimed-user-agent-v1", RouteNormalization: "route-v1",
			CostAllocation: "allocation-v1",
		},
		Assumptions: []string{
			"Crawler identity is claimed from User-Agent and is not DNS-verified.",
			"Sanitized identifiers remain linkable within one HMAC key scope.",
			"Allocated cost is proportional attribution, not an invoice or guaranteed saving.",
		},
		DegradedReasons: []string{},
		Warnings:        append([]string{}, data.Warnings...),
	}
	if data.Summary.RouteOverflow > 0 {
		model.DegradedReasons = append(model.DegradedReasons, "route_cardinality_overflow")
	}
	if data.Summary.UAOverflow > 0 {
		model.DegradedReasons = append(model.DegradedReasons, "user_agent_cardinality_overflow")
	}
	if data.Summary.SubjectOverflow > 0 {
		model.DegradedReasons = append(model.DegradedReasons, "rate_subject_cardinality_overflow")
	}
	if data.Summary.OrderDegraded {
		model.DegradedReasons = append(model.DegradedReasons, "input_order_degraded")
	}
	sort.SliceStable(model.Classes, func(i, j int) bool {
		if model.Classes[i].Requests != model.Classes[j].Requests {
			return model.Classes[i].Requests > model.Classes[j].Requests
		}
		return model.Classes[i].Class < model.Classes[j].Class
	})
	sort.SliceStable(model.Crawlers, func(i, j int) bool {
		left, right := model.Crawlers[i].UpstreamDurationUS, model.Crawlers[j].UpstreamDurationUS
		if left != nil && right == nil {
			return true
		}
		if left == nil && right != nil {
			return false
		}
		if left != nil && *left != *right {
			return *left > *right
		}
		if model.Crawlers[i].Requests != model.Crawlers[j].Requests {
			return model.Crawlers[i].Requests > model.Crawlers[j].Requests
		}
		return model.Crawlers[i].Name < model.Crawlers[j].Name
	})
	sort.SliceStable(model.Routes, func(i, j int) bool {
		left, right := model.Routes[i].UpstreamDurationUS, model.Routes[j].UpstreamDurationUS
		if left != nil && right == nil {
			return true
		}
		if left == nil && right != nil {
			return false
		}
		if left != nil && *left != *right {
			return *left > *right
		}
		if model.Routes[i].Requests != model.Routes[j].Requests {
			return model.Routes[i].Requests > model.Routes[j].Requests
		}
		return model.Routes[i].Route < model.Routes[j].Route
	})
	if len(model.Crawlers) > 100 {
		model.Crawlers = model.Crawlers[:100]
	}
	if len(model.Routes) > 500 {
		model.Routes = model.Routes[:500]
	}
	if len(model.Findings) > 10000 {
		model.Findings = model.Findings[:10000]
	}
	sort.Strings(model.DegradedReasons)
	sort.Strings(model.Warnings)
	return model, nil
}

func formatTime(value int64) string {
	return time.UnixMicro(value).UTC().Format(time.RFC3339Nano)
}

func formatOptionalTime(value *int64) *string {
	if value == nil {
		return nil
	}
	formatted := formatTime(*value)
	return &formatted
}
