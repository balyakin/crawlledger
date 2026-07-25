package policy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/jsonstrict"
)

const maxSimulationBytes int64 = 8 << 20

func LoadSimulation(path string) (domain.Simulation, []byte, error) {
	data, err := readAnchored(path, maxSimulationBytes)
	if err != nil {
		return domain.Simulation{}, nil, fmt.Errorf("read simulation: %w", err)
	}
	if err := requireSimulationKeys(data); err != nil {
		return domain.Simulation{}, nil, err
	}
	var value domain.Simulation
	if err := jsonstrict.Decode(data, &value); err != nil {
		return domain.Simulation{}, nil, fmt.Errorf("decode simulation: %w", err)
	}
	if err := validateSimulation(value); err != nil {
		return domain.Simulation{}, nil, err
	}
	return value, data, nil
}

func requireSimulationKeys(data []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil || top == nil {
		return errors.New("simulation must be an object")
	}
	if err := require(top, "simulation",
		"schema_version", "run_id", "analysis_id", "policy_hash", "status", "coverage",
		"totals", "rule_impacts", "risks", "assumptions"); err != nil {
		return err
	}
	if err := rejectNull(top, "simulation",
		"schema_version", "run_id", "analysis_id", "policy_hash", "status", "coverage",
		"totals", "rule_impacts", "risks", "assumptions"); err != nil {
		return err
	}
	var coverage, totals map[string]json.RawMessage
	if json.Unmarshal(top["coverage"], &coverage) != nil || json.Unmarshal(top["totals"], &totals) != nil {
		return errors.New("simulation coverage and totals must be objects")
	}
	if err := require(coverage, "simulation.coverage", "rate_model_ppm", "path_policy_coverage_ppm"); err != nil {
		return err
	}
	if err := rejectNull(coverage, "simulation.coverage", "rate_model_ppm"); err != nil {
		return err
	}
	if err := require(totals, "simulation.totals",
		"observed_requests", "allowed_requests", "denied_requests", "rate_limited_requests",
		"cache_candidate_requests", "bytes_avoided", "upstream_us_avoided",
		"allocated_cost_avoided_kopecks"); err != nil {
		return err
	}
	if err := rejectNull(totals, "simulation.totals",
		"observed_requests", "allowed_requests", "denied_requests", "rate_limited_requests",
		"cache_candidate_requests", "bytes_avoided"); err != nil {
		return err
	}
	var impacts []map[string]json.RawMessage
	var risks []map[string]json.RawMessage
	if json.Unmarshal(top["rule_impacts"], &impacts) != nil || impacts == nil ||
		json.Unmarshal(top["risks"], &risks) != nil || risks == nil {
		return errors.New("simulation impacts and risks must be arrays")
	}
	for index, impact := range impacts {
		if err := require(impact, fmt.Sprintf("simulation.rule_impacts[%d]", index),
			"rule_id", "action", "matched_requests", "allowed", "denied", "rate_limited",
			"bytes_avoided", "upstream_us_avoided", "allocated_cost_avoided_kopecks",
			"claimed_crawlers_affected", "top_routes_affected", "metric_coverage_ppm",
			"path_policy_coverage_ppm", "eligible_observed", "cache_misses_observed",
			"warnings"); err != nil {
			return err
		}
		if err := rejectNull(impact, fmt.Sprintf("simulation.rule_impacts[%d]", index),
			"rule_id", "action", "matched_requests", "allowed", "denied", "rate_limited",
			"bytes_avoided", "claimed_crawlers_affected", "top_routes_affected",
			"metric_coverage_ppm", "eligible_observed", "cache_misses_observed", "warnings"); err != nil {
			return err
		}
	}
	for index, risk := range risks {
		if err := require(risk, fmt.Sprintf("simulation.risks[%d]", index),
			"id", "severity", "acknowledgeable", "message"); err != nil {
			return err
		}
		if err := rejectNull(risk, fmt.Sprintf("simulation.risks[%d]", index),
			"id", "severity", "acknowledgeable", "message"); err != nil {
			return err
		}
	}
	return nil
}

func rejectNull(object map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if bytes.Equal(bytes.TrimSpace(object[key]), []byte("null")) {
			return fmt.Errorf("%s.%s must not be null", path, key)
		}
	}
	return nil
}

func require(object map[string]json.RawMessage, path string, keys ...string) error {
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return fmt.Errorf("%s.%s is required", path, key)
		}
	}
	return nil
}

func validateSimulation(value domain.Simulation) error {
	if value.SchemaVersion != 1 || !strings.HasPrefix(value.RunID, "pr_") ||
		!lowerHex(value.RunID[3:], 16) || !strings.HasPrefix(value.AnalysisID, "an_") ||
		!lowerHex(value.AnalysisID[3:], 32) || !lowerHex(value.PolicyHash, 64) ||
		value.RuleImpacts == nil || len(value.RuleImpacts) > 100 ||
		value.Risks == nil || len(value.Risks) > 1000 || value.Assumptions == nil {
		return errors.New("invalid simulation contract")
	}
	switch value.Status {
	case domain.SimulationSafe, domain.SimulationRequiresAck, domain.SimulationBlocked, domain.SimulationAnalysis:
	default:
		return errors.New("invalid simulation status")
	}
	if value.Coverage.RateModelPPM < 0 || value.Coverage.RateModelPPM > 1000000 ||
		value.Coverage.PathPolicyCoverage != nil &&
			(*value.Coverage.PathPolicyCoverage < 0 || *value.Coverage.PathPolicyCoverage > 1000000) {
		return errors.New("invalid simulation coverage")
	}
	totals := value.Totals
	if totals.ObservedRequests < 0 || totals.AllowedRequests < 0 || totals.DeniedRequests < 0 ||
		totals.RateLimitedRequests < 0 || totals.CacheCandidateRequests < 0 ||
		totals.BytesAvoided < 0 || !Conserves(value) {
		return errors.New("invalid simulation totals")
	}
	for _, impact := range value.RuleImpacts {
		if impact.ClaimedCrawlersAffected == nil || impact.TopRoutesAffected == nil ||
			len(impact.TopRoutesAffected) > 20 || impact.Warnings == nil ||
			!identifier.MatchString(impact.RuleID) || !impact.Action.Valid() ||
			impact.MatchedRequests < 0 || impact.Allowed < 0 || impact.Denied < 0 ||
			impact.RateLimited < 0 || impact.BytesAvoided < 0 ||
			impact.MetricCoveragePPM < 0 || impact.MetricCoveragePPM > 1000000 ||
			impact.PathPolicyCoveragePPM != nil &&
				(*impact.PathPolicyCoveragePPM < 0 || *impact.PathPolicyCoveragePPM > 1000000) ||
			impact.EligibleObserved < 0 || impact.CacheMissesObserved < 0 ||
			impact.UpstreamUSAvoided != nil && *impact.UpstreamUSAvoided < 0 ||
			impact.AllocatedCostAvoidedKopecks != nil && *impact.AllocatedCostAvoidedKopecks < 0 {
			return errors.New("simulation arrays must not be null")
		}
	}
	for _, risk := range value.Risks {
		if risk.ID == "" || len(risk.ID) > 512 || !risk.Severity.Valid() || risk.Message == "" {
			return errors.New("invalid simulation risk")
		}
	}
	if totals.UpstreamUSAvoided != nil && *totals.UpstreamUSAvoided < 0 ||
		totals.AllocatedCostAvoidedKopecks != nil && *totals.AllocatedCostAvoidedKopecks < 0 {
		return errors.New("invalid simulation totals")
	}
	return nil
}

func lowerHex(value string, size int) bool {
	if len(value) != size || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func Conserves(value domain.Simulation) bool {
	total := value.Totals
	if total.AllowedRequests > math.MaxInt64-total.DeniedRequests {
		return false
	}
	classified := total.AllowedRequests + total.DeniedRequests
	if classified > math.MaxInt64-total.RateLimitedRequests {
		return false
	}
	classified += total.RateLimitedRequests
	if classified == total.ObservedRequests {
		return true
	}
	if value.Status != domain.SimulationBlocked || classified > total.ObservedRequests {
		return false
	}
	for _, risk := range value.Risks {
		if !risk.Acknowledgeable && strings.HasPrefix(risk.ID, "rate-coverage-incomplete:") {
			return true
		}
	}
	return false
}
