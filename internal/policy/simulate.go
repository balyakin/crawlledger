package policy

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
)

type Simulator struct {
	policy           domain.Policy
	analysisID       string
	policyHash       string
	impacts          []domain.RuleImpact
	rateMatched      []int64
	pathPolicy       bool
	pathActionable   int64
	totals           domain.SimulationTotals
	protected        map[string]struct{}
	pathUnclassified map[string]bool
	pathAmbiguous    map[string]bool
	crawlerSets      []map[string]struct{}
	observedStates   map[string]int64
	avoidedRequests  []int64
	avoidedSamples   []int64
	totalAvoided     int64
	totalSamples     int64
	currentRoute     string
	haveRoute        bool
	currentRouteRows []int64
	topRoutes        [][]routeImpact
	routeOverflow    int64
}

func (s *Simulator) SetRouteOverflow(requests int64) {
	if requests > 0 {
		s.routeOverflow = requests
	}
}

type routeImpact struct {
	route    string
	requests int64
}

func NewSimulator(value domain.Policy, analysisID, policyHash string) *Simulator {
	impacts := make([]domain.RuleImpact, len(value.Rules))
	for index, rule := range value.Rules {
		impacts[index] = domain.RuleImpact{
			RuleID: rule.ID, Action: rule.Action.Kind,
			ClaimedCrawlersAffected: []string{}, TopRoutesAffected: []string{}, Warnings: []string{},
		}
	}
	simulator := &Simulator{
		policy: value, analysisID: analysisID, policyHash: policyHash, impacts: impacts,
		rateMatched: make([]int64, len(value.Rules)), protected: make(map[string]struct{}),
		pathUnclassified: make(map[string]bool), crawlerSets: make([]map[string]struct{}, len(value.Rules)),
		pathAmbiguous:    make(map[string]bool),
		observedStates:   make(map[string]int64),
		avoidedRequests:  make([]int64, len(value.Rules)),
		avoidedSamples:   make([]int64, len(value.Rules)),
		currentRouteRows: make([]int64, len(value.Rules)),
		topRoutes:        make([][]routeImpact, len(value.Rules)),
	}
	for _, rule := range value.Rules {
		if len(rule.Match.PathPrefixes) > 0 {
			simulator.pathPolicy = true
		}
	}
	return simulator
}

func (s *Simulator) AddSubjectState(claimName *string, claimCategory *domain.TrafficClass) error {
	cell := domain.PolicyCell{ClaimName: claimName, ClaimCategory: claimCategory}
	for _, rule := range s.policy.Rules {
		if rule.Action.Kind == domain.ActionRateLimit && Matches(rule, cell) {
			profile := *rule.Action.RateProfile
			value, err := checkedAdd(s.observedStates[profile], 1)
			if err == nil {
				s.observedStates[profile] = value
			}
			return err
		}
	}
	return nil
}

func (s *Simulator) ObservedStates() map[string]int64 {
	result := make(map[string]int64, len(s.observedStates))
	for profile, states := range s.observedStates {
		result[profile] = states
	}
	return result
}

func (s *Simulator) Add(cell domain.TrafficCell) error {
	if cell.Requests < 0 || cell.BytesSent < 0 {
		return errors.New("invalid traffic cell")
	}
	if !s.haveRoute {
		s.currentRoute, s.haveRoute = cell.Route, true
	} else if cell.Route != s.currentRoute {
		s.flushRoute()
		s.currentRoute = cell.Route
	}
	if err := addInt64(&s.totals.ObservedRequests, cell.Requests); err != nil {
		return err
	}
	if s.pathPolicy && cell.ActionablePrefix != nil {
		if err := addInt64(&s.pathActionable, cell.Requests); err != nil {
			return err
		}
	}
	policyCell := domain.PolicyCell{
		Route: cell.Route, ActionablePrefix: cell.ActionablePrefix, Method: cell.Method,
		ClaimName: cell.ClaimName, ClaimCategory: cell.ClaimCategory,
		ProtectedDefault: cell.ProtectedDefault, PrimaryClass: cell.PrimaryClass,
		Requests: cell.Requests, BytesSent: cell.BytesSent, UpstreamUS: cell.UpstreamUS,
	}
	matched := -1
	for index, rule := range s.policy.Rules {
		withoutPath := rule
		withoutPath.Match.PathPrefixes = nil
		if Matches(withoutPath, policyCell) && ambiguousDynamicPath(rule, policyCell) {
			s.pathAmbiguous[rule.ID] = true
		}
		if Matches(rule, policyCell) {
			matched = index
			break
		}
	}
	if matched < 0 {
		return addInt64(&s.totals.AllowedRequests, cell.Requests)
	}
	rule := s.policy.Rules[matched]
	impact := &s.impacts[matched]
	if err := addInt64(&impact.MatchedRequests, cell.Requests); err != nil {
		return err
	}
	if cell.ClaimName != nil {
		if s.crawlerSets[matched] == nil {
			s.crawlerSets[matched] = make(map[string]struct{})
		}
		s.crawlerSets[matched][*cell.ClaimName] = struct{}{}
		if cell.ProtectedDefault && (rule.Action.Kind == domain.ActionDeny || rule.Action.Kind == domain.ActionRateLimit) {
			s.protected[*cell.ClaimName] = struct{}{}
		}
	}
	if err := addInt64(&s.currentRouteRows[matched], cell.Requests); err != nil {
		return err
	}
	switch rule.Action.Kind {
	case domain.ActionAllow:
		if err := addInt64(&impact.Allowed, cell.Requests); err != nil {
			return err
		}
		return addInt64(&s.totals.AllowedRequests, cell.Requests)
	case domain.ActionDeny:
		for _, pair := range []struct {
			target *int64
			value  int64
		}{
			{&impact.Denied, cell.Requests},
			{&impact.BytesAvoided, cell.BytesSent},
			{&s.totals.DeniedRequests, cell.Requests},
			{&s.totals.BytesAvoided, cell.BytesSent},
			{&s.avoidedRequests[matched], cell.Requests},
			{&s.avoidedSamples[matched], cell.UpstreamSamples},
			{&s.totalAvoided, cell.Requests},
			{&s.totalSamples, cell.UpstreamSamples},
		} {
			if err := addInt64(pair.target, pair.value); err != nil {
				return err
			}
		}
		if cell.UpstreamUS != nil && cell.UpstreamSamples == cell.Requests {
			if err := addNullableInt64(&impact.UpstreamUSAvoided, *cell.UpstreamUS); err != nil {
				return err
			}
			if err := addNullableInt64(&s.totals.UpstreamUSAvoided, *cell.UpstreamUS); err != nil {
				return err
			}
		}
		if len(rule.Match.PathPrefixes) > 0 && len(rule.Match.CrawlerNames)+len(rule.Match.Categories) == 0 &&
			cell.PrimaryClass == domain.ClassUnclassified {
			s.pathUnclassified[rule.ID] = true
		}
	case domain.ActionRateLimit:
		return addInt64(&s.rateMatched[matched], cell.Requests)
	case domain.ActionCache:
		if err := addInt64(&impact.Allowed, cell.Requests); err != nil {
			return err
		}
		if err := addInt64(&impact.EligibleObserved, cell.Requests); err != nil {
			return err
		}
		if cell.CacheState == domain.CacheMiss || cell.CacheState == domain.CacheBypass || cell.CacheState == domain.CacheExpired {
			if err := addInt64(&impact.CacheMissesObserved, cell.Requests); err != nil {
				return err
			}
			if err := addInt64(&s.totals.CacheCandidateRequests, cell.Requests); err != nil {
				return err
			}
		}
		return addInt64(&s.totals.AllowedRequests, cell.Requests)
	}
	return nil
}

func (s *Simulator) Finish(rate []domain.RateProfileImpact) (domain.Simulation, error) {
	s.flushRoute()
	modeled := make([]int64, len(s.policy.Rules))
	for _, row := range rate {
		for index, rule := range s.policy.Rules {
			if rule.Action.Kind != domain.ActionRateLimit || rule.Action.RateProfile == nil ||
				*rule.Action.RateProfile != row.Profile {
				continue
			}
			cell := domain.PolicyCell{
				ClaimName: row.ClaimName, ClaimCategory: row.ClaimCategory,
				ProtectedDefault: row.ProtectedDefault, PrimaryClass: row.PrimaryClass,
			}
			if !Matches(rule, cell) {
				continue
			}
			impact := &s.impacts[index]
			for _, pair := range []struct {
				target *int64
				value  int64
			}{
				{&modeled[index], row.ModeledRequests},
				{&impact.Allowed, row.AllowedRequests},
				{&impact.RateLimited, row.LimitedRequests},
				{&impact.BytesAvoided, row.LimitedBytes},
				{&s.totals.AllowedRequests, row.AllowedRequests},
				{&s.totals.RateLimitedRequests, row.LimitedRequests},
				{&s.totals.BytesAvoided, row.LimitedBytes},
				{&s.avoidedRequests[index], row.LimitedRequests},
				{&s.avoidedSamples[index], row.LimitedUpstreamSamples},
				{&s.totalAvoided, row.LimitedRequests},
				{&s.totalSamples, row.LimitedUpstreamSamples},
			} {
				if err := addInt64(pair.target, pair.value); err != nil {
					return domain.Simulation{}, err
				}
			}
			if row.LimitedUpstreamUS != nil && row.LimitedUpstreamSamples == row.LimitedRequests {
				if err := addNullableInt64(&impact.UpstreamUSAvoided, *row.LimitedUpstreamUS); err != nil {
					return domain.Simulation{}, err
				}
				if err := addNullableInt64(&s.totals.UpstreamUSAvoided, *row.LimitedUpstreamUS); err != nil {
					return domain.Simulation{}, err
				}
			}
			break
		}
	}
	for index := range s.impacts {
		names := make([]string, 0, len(s.crawlerSets[index]))
		for name := range s.crawlerSets[index] {
			names = append(names, name)
		}
		sort.Strings(names)
		s.impacts[index].ClaimedCrawlersAffected = names
		for _, route := range s.topRoutes[index] {
			s.impacts[index].TopRoutesAffected = append(s.impacts[index].TopRoutesAffected, route.route)
		}
		if s.policy.Rules[index].Action.Kind == domain.ActionRateLimit {
			s.impacts[index].MetricCoveragePPM = 1000000
			if s.rateMatched[index] > 0 {
				s.impacts[index].MetricCoveragePPM = domain.RatioPPM(modeled[index], s.rateMatched[index])
			}
		} else if s.impacts[index].MatchedRequests > 0 {
			s.impacts[index].MetricCoveragePPM = 1000000
		}
		if s.avoidedSamples[index] != s.avoidedRequests[index] {
			s.impacts[index].UpstreamUSAvoided = nil
		}
	}
	if s.totalSamples != s.totalAvoided {
		s.totals.UpstreamUSAvoided = nil
	}
	risks := s.risks(modeled)
	status := statusFor(risks)
	runID, err := domain.SimulationRunID(s.analysisID, s.policyHash)
	if err != nil {
		return domain.Simulation{}, err
	}
	rateTotal, rateModeled := int64(0), int64(0)
	for index, rule := range s.policy.Rules {
		if rule.Action.Kind == domain.ActionRateLimit {
			if err := addInt64(&rateTotal, s.rateMatched[index]); err != nil {
				return domain.Simulation{}, err
			}
			if err := addInt64(&rateModeled, modeled[index]); err != nil {
				return domain.Simulation{}, err
			}
		}
	}
	rateCoverage := int64(1000000)
	if rateTotal > 0 {
		rateCoverage = domain.RatioPPM(rateModeled, rateTotal)
	}
	var pathCoverage *int64
	if s.pathPolicy {
		value := int64(1000000)
		if s.totals.ObservedRequests > 0 {
			value = domain.RatioPPM(s.pathActionable, s.totals.ObservedRequests)
		}
		pathCoverage = &value
		for index := range s.impacts {
			if len(s.policy.Rules[index].Match.PathPrefixes) > 0 {
				s.impacts[index].PathPolicyCoveragePPM = pathCoverage
			}
		}
	}
	return domain.Simulation{
		SchemaVersion: 1, RunID: runID, AnalysisID: s.analysisID, PolicyHash: s.policyHash,
		Status: status, Coverage: domain.SimulationCoverage{
			RateModelPPM: rateCoverage, PathPolicyCoverage: pathCoverage,
		},
		Totals: s.totals, RuleImpacts: s.impacts, Risks: risks,
		Assumptions: []string{
			"Historical requests are evaluated independently of crawler adaptation.",
			"Cache impact ignores response Cache-Control, Set-Cookie, authorization and Vary.",
			"Crawler identity is claimed from User-Agent and is not DNS-verified.",
		},
	}, nil
}

func (s *Simulator) risks(modeled []int64) []domain.Risk {
	byID := make(map[string]domain.Risk)
	if s.routeOverflow > 0 {
		for _, rule := range s.policy.Rules {
			if len(rule.Match.PathPrefixes) > 0 {
				id := "cardinality-overflow:route"
				byID[id] = domain.Risk{
					ID: id, Severity: domain.SeverityHigh, Acknowledgeable: false,
					Message: "Route cardinality overflow affects a policy matcher dimension.",
				}
				break
			}
		}
	}
	for name := range s.protected {
		id := "protected-crawler:" + name
		byID[id] = domain.Risk{
			ID: id, Severity: domain.SeverityHigh, Acknowledgeable: true,
			Message: "Policy affects a protected claimed crawler.",
		}
	}
	for index, rule := range s.policy.Rules {
		impact := s.impacts[index]
		for _, prefix := range rule.Match.PathPrefixes {
			if prefix == "/" {
				id := "broad-root-match:" + rule.ID
				byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: true, Message: "Rule matches the root path."}
			}
		}
		if s.pathUnclassified[rule.ID] {
			id := "path-deny-unclassified:" + rule.ID
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: true, Message: "Path-only deny affects unclassified traffic."}
		}
		if impact.MatchedRequests > s.totals.ObservedRequests/2 && (rule.Action.Kind == domain.ActionDeny || rule.Action.Kind == domain.ActionRateLimit) {
			id := "high-impact:" + rule.ID
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: true, Message: "Rule affects more than half of observed requests."}
		}
		if rule.Action.Kind == domain.ActionAllow && len(rule.Match.CrawlerNames)+len(rule.Match.Categories) > 0 {
			for _, later := range s.policy.Rules[index+1:] {
				if later.Action.Kind == domain.ActionDeny || later.Action.Kind == domain.ActionRateLimit {
					id := "claimed-allow-bypass:" + rule.ID
					byID[id] = domain.Risk{ID: id, Severity: domain.SeverityMedium, Acknowledgeable: true, Message: "A spoofable claimed User-Agent may bypass a later restrictive rule."}
					break
				}
			}
		}
		if len(rule.Match.PathPrefixes) > 0 &&
			(s.pathActionable < s.totals.ObservedRequests || s.pathAmbiguous[rule.ID]) {
			id := "path-normalization-drift:" + rule.ID
			risk := domain.Risk{
				ID: id, Severity: domain.SeverityMedium, Acknowledgeable: true,
				Message: "Some observed paths are not safely translatable to server matchers.",
			}
			if s.pathAmbiguous[rule.ID] {
				risk.Severity = domain.SeverityHigh
				risk.Acknowledgeable = false
				risk.Message = "A policy prefix enters a normalized dynamic segment and cannot be simulated safely."
			}
			byID[id] = risk
		}
		if rule.Action.Kind == domain.ActionRateLimit && modeled[index] != s.rateMatched[index] {
			id := "rate-coverage-incomplete:" + rule.ID
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: false, Message: "Rate model coverage is incomplete for this rule."}
		}
		if rule.Action.Kind == domain.ActionCache {
			id := "analysis-only-cache:" + rule.ID
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityInfo, Acknowledgeable: false, Message: "Cache impact is an upper bound and cannot be rendered."}
		}
	}
	for profile, states := range s.observedStates {
		zone := zoneMiB(states)
		if zone > 256 {
			id := "nginx-zone-too-large:" + profile
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: false, Message: "Calculated Nginx rate zone exceeds 256 MiB."}
		} else if zone > 32 {
			id := "nginx-zone-memory:" + profile + ":" + strconv.FormatInt(zone, 10)
			byID[id] = domain.Risk{ID: id, Severity: domain.SeverityHigh, Acknowledgeable: true, Message: "Calculated Nginx rate zone exceeds 32 MiB."}
		}
	}
	result := make([]domain.Risk, 0, len(byID))
	for _, risk := range byID {
		result = append(result, risk)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func ambiguousDynamicPath(rule domain.PolicyRule, cell domain.PolicyCell) bool {
	if cell.ActionablePrefix == nil || !strings.Contains(cell.Route, "{") {
		return false
	}
	for _, prefix := range rule.Match.PathPrefixes {
		if segmentPrefix(prefix, *cell.ActionablePrefix) &&
			!segmentPrefix(*cell.ActionablePrefix, prefix) {
			return true
		}
	}
	return false
}

func statusFor(risks []domain.Risk) domain.SimulationStatus {
	status := domain.SimulationSafe
	analysisOnly := false
	for _, risk := range risks {
		if strings.HasPrefix(risk.ID, "analysis-only-cache:") {
			analysisOnly = true
			continue
		}
		if !risk.Acknowledgeable {
			return domain.SimulationBlocked
		} else if status == domain.SimulationSafe {
			status = domain.SimulationRequiresAck
		}
	}
	if analysisOnly {
		return domain.SimulationAnalysis
	}
	return status
}

func (s *Simulator) flushRoute() {
	if !s.haveRoute {
		return
	}
	for index, requests := range s.currentRouteRows {
		if requests == 0 {
			continue
		}
		s.topRoutes[index] = append(s.topRoutes[index], routeImpact{route: s.currentRoute, requests: requests})
		sort.Slice(s.topRoutes[index], func(left, right int) bool {
			if s.topRoutes[index][left].requests != s.topRoutes[index][right].requests {
				return s.topRoutes[index][left].requests > s.topRoutes[index][right].requests
			}
			return s.topRoutes[index][left].route < s.topRoutes[index][right].route
		})
		if len(s.topRoutes[index]) > 20 {
			s.topRoutes[index] = s.topRoutes[index][:20]
		}
		s.currentRouteRows[index] = 0
	}
}

func checkedAdd(left, right int64) (int64, error) {
	if right < 0 || left < 0 || left > math.MaxInt64-right {
		return 0, errors.New("simulation integer overflow")
	}
	return left + right, nil
}

func addInt64(target *int64, value int64) error {
	result, err := checkedAdd(*target, value)
	if err == nil {
		*target = result
	}
	return err
}

func addNullableInt64(target **int64, value int64) error {
	if value < 0 {
		return errors.New("simulation integer overflow")
	}
	if *target == nil {
		copy := value
		*target = &copy
		return nil
	}
	return addInt64(*target, value)
}

func zoneMiB(states int64) int64 {
	value := (states*512 + (1 << 20) - 1) / (1 << 20)
	if value < 1 {
		return 1
	}
	return value
}
