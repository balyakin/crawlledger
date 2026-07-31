package protect

import (
	"errors"
	"math"
	"math/bits"
	"sort"
	"strings"

	"github.com/balyakin/crawlledger/internal/aggregate"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
)

const ratioScale uint64 = 1_000_000

type Accounting struct {
	Denominator bool
	Candidate   bool
	Refresh     bool
}

type ProtectionRecord struct {
	Event          domain.Event
	CanonicalPath  *string
	NginxURI       string
	LimitReqStatus string
}

type ObserveResult struct {
	Fresh     bool
	Candidate bool
	Reason    string
}

type DetectorEvent struct {
	Kind               string
	Detector           string
	Method             string
	PathPrefix         string
	Requests           int64
	SiteRequests       int64
	DistinctClients    int64
	UpstreamSamples    int64
	UpstreamDurationUS int64
	BaselineRequests   int64
	BaselineUpstreamUS int64
	RequestThreshold   int64
	UpstreamThreshold  int64
	ExpiresAtUS        int64
}

type RejectedRecordCounts struct {
	RecordContent   int64
	SensorStructure int64
	Stale           int64
	Future          int64
	InvalidStatus   int64
	CounterOverflow int64
}

type Decision struct {
	State           State
	Events          []DetectorEvent
	StateChanged    bool
	MapChanged      bool
	ApplyRequired   bool
	ApplyNow        bool
	Suspended       bool
	GroupOverflowed bool
	MaxEventLagUS   int64
	RejectedRecords RejectedRecordCounts
}

type Detector struct {
	config                  Config
	baseline                Baseline
	state                   State
	groups                  map[string]*trackedGroup
	siteBuckets             map[int64]int64
	attemptBuckets          map[string]map[int64]int64
	health                  [100]bool
	healthCount             int
	healthIndex             int
	structureErrors         int
	dataSinceEvaluation     bool
	freshSinceEvaluation    bool
	capacitySinceEvaluation bool
	maxEventLagUS           int64
	rejectedRecords         RejectedRecordCounts
	lastEvaluationUS        int64
	lastAppliedUS           int64
	appliedRules            []ApplyRule
}

type trackedGroup struct {
	kind        string
	method      string
	path        string
	pathPrefix  string
	unsafe      bool
	consecutive int
	buckets     map[int64]*detectorMetrics
}

type detectorMetrics struct {
	requests           int64
	upstreamSamples    int64
	upstreamDurationUS int64
	clients            aggregate.Sketch
}

type qualification struct {
	reason           string
	method           string
	pathPrefix       string
	requestThreshold int64
}

type groupThresholds struct {
	request          int64
	upstream         int64
	baselineRequests int64
	baselineUpstream int64
}

type actionProposal struct {
	method           string
	pathPrefix       string
	reasons          []string
	requestThreshold int64
}

func NewDetector(config Config, configSHA256 string, baseline Baseline, state State) (*Detector, error) {
	if !sitePattern.MatchString(config.Site) || !lowerDigest(configSHA256) {
		return nil, errors.New("invalid detector identity")
	}
	if err := config.validateDetection(); err != nil {
		return nil, err
	}
	if err := config.validateAction(); err != nil {
		return nil, err
	}
	if err := validateUnique(config.Exclusions.Methods, domain.ValidMethod, "excluded method"); err != nil {
		return nil, err
	}
	if err := validateUnique(config.Exclusions.PathPrefixes, domain.ValidActionable, "excluded path prefix"); err != nil {
		return nil, err
	}
	if !lowerDigest(baseline.ManifestSHA256) {
		return nil, errors.New("invalid detector baseline")
	}
	if err := state.Validate(); err != nil {
		return nil, err
	}
	if state.Site != config.Site || state.ConfigSHA256 != configSHA256 ||
		state.BaselineManifestSHA256 == nil || *state.BaselineManifestSHA256 != baseline.ManifestSHA256 {
		return nil, errors.New("detector state digest mismatch")
	}
	if len(state.Rules) > config.Action.MaxActiveRules {
		return nil, errors.New("detector state exceeds active rule capacity")
	}
	for _, rule := range state.Rules {
		if config.actionExcluded(rule.Method, rule.PathPrefix) {
			return nil, errors.New("detector state contains an excluded rule")
		}
	}
	return &Detector{
		config:         config,
		baseline:       baseline,
		state:          cloneState(state),
		groups:         make(map[string]*trackedGroup),
		siteBuckets:    make(map[int64]int64),
		attemptBuckets: make(map[string]map[int64]int64),
		appliedRules:   projectRules(state.Rules),
	}, nil
}

func ClassifyAccounting(status int, limiterStatus string) Accounting {
	if limiterStatus == "REJECTED" {
		return Accounting{Refresh: status == 429}
	}
	if limiterStatus == "DELAYED_DRY_RUN" || limiterStatus == "REJECTED_DRY_RUN" {
		return Accounting{Denominator: true, Candidate: status != 403 && status != 429}
	}
	eligible := status != 403 && status != 429
	return Accounting{Denominator: true, Candidate: eligible, Refresh: eligible}
}

func (detector *Detector) ObserveError(receiptUS int64, class parser.RecordErrorClass, nonEmpty bool) {
	detector.dataSinceEvaluation = true
	if class == parser.SensorStructureError {
		incrementRejected(&detector.rejectedRecords.SensorStructure)
	} else {
		incrementRejected(&detector.rejectedRecords.RecordContent)
	}
	if !nonEmpty {
		return
	}
	detector.recordHealth(class == parser.SensorStructureError)
}

func (detector *Detector) SensorSuspended() bool {
	return detector.healthCount == len(detector.health) && detector.structureErrors > 10
}

func (detector *Detector) Observe(record ProtectionRecord, receiptUS int64) ObserveResult {
	detector.dataSinceEvaluation = true
	detector.recordHealth(false)
	if receiptUS <= 0 || record.Event.TimestampUS <= 0 {
		incrementRejected(&detector.rejectedRecords.RecordContent)
		return ObserveResult{Reason: "invalid-time"}
	}
	if record.Event.TimestampUS > receiptUS {
		incrementRejected(&detector.rejectedRecords.Future)
		return ObserveResult{Reason: "future"}
	}
	lagUS := receiptUS - record.Event.TimestampUS
	detector.maxEventLagUS = max(detector.maxEventLagUS, lagUS)
	maxLagUS := int64(detector.config.Detection.MaxEventLagSeconds) * 1_000_000
	windowUS := int64(detector.config.Detection.WindowSeconds) * 1_000_000
	if lagUS > maxLagUS || lagUS >= windowUS {
		incrementRejected(&detector.rejectedRecords.Stale)
		return ObserveResult{Reason: "stale"}
	}
	if !validObservedStatus(record.Event.Status, record.LimitReqStatus) {
		incrementRejected(&detector.rejectedRecords.InvalidStatus)
		return ObserveResult{Reason: "invalid-status"}
	}
	detector.freshSinceEvaluation = true
	accounting := ClassifyAccounting(record.Event.Status, record.LimitReqStatus)
	bucket := detector.bucketEnd(record.Event.TimestampUS)
	if accounting.Denominator {
		if err := addBucketCount(detector.siteBuckets, bucket, 1); err != nil {
			incrementRejected(&detector.rejectedRecords.CounterOverflow)
			return ObserveResult{Fresh: true, Reason: "counter-overflow"}
		}
	}
	if accounting.Refresh {
		detector.observeRefresh(record, bucket)
	}
	candidate := accounting.Candidate && detector.candidateSafe(record)
	if !candidate {
		return ObserveResult{Fresh: true}
	}
	if err := detector.observeCandidate(record, bucket); err != nil {
		incrementRejected(&detector.rejectedRecords.CounterOverflow)
		return ObserveResult{Fresh: true, Reason: "counter-overflow"}
	}
	return ObserveResult{Fresh: true, Candidate: true}
}

func (detector *Detector) Evaluate(evaluationUS int64) (Decision, error) {
	if evaluationUS <= detector.lastEvaluationUS || evaluationUS <= 0 {
		return Decision{}, errors.New("evaluation time must increase")
	}
	intervalUS := int64(detector.config.Detection.EvaluationIntervalSeconds) * 1_000_000
	if evaluationUS%intervalUS != 0 {
		return Decision{}, errors.New("evaluation time must be epoch-aligned")
	}
	detector.prune(evaluationUS)
	before := cloneState(detector.state)
	activationAllowed := detector.freshSinceEvaluation && !detector.SensorSuspended()
	decision := Decision{
		Suspended:       detector.SensorSuspended() || detector.dataSinceEvaluation && !detector.freshSinceEvaluation,
		GroupOverflowed: detector.capacitySinceEvaluation,
		MaxEventLagUS:   detector.maxEventLagUS,
		RejectedRecords: detector.rejectedRecords,
	}
	if decision.Suspended {
		decision.Events = append(decision.Events, DetectorEvent{Kind: "protect_detection_suspended"})
	}
	if detector.capacitySinceEvaluation {
		decision.Events = append(decision.Events, DetectorEvent{Kind: "protect_capacity_reached"})
	}
	qualifications, err := detector.evaluateGroups(evaluationUS, activationAllowed, &decision)
	if err != nil {
		return Decision{}, err
	}
	proposals := makeProposals(qualifications)
	if err := detector.updateRules(evaluationUS, activationAllowed, proposals, &decision); err != nil {
		return Decision{}, err
	}
	detector.lastEvaluationUS = evaluationUS
	detector.dataSinceEvaluation = false
	detector.freshSinceEvaluation = false
	detector.capacitySinceEvaluation = false
	detector.maxEventLagUS = 0
	detector.rejectedRecords = RejectedRecordCounts{}
	decision.State = cloneState(detector.state)
	decision.StateChanged = !rulesEqual(before.Rules, detector.state.Rules)
	decision.MapChanged = !applyRulesEqual(projectRules(before.Rules), projectRules(detector.state.Rules))
	desiredRules := projectRules(detector.state.Rules)
	decision.ApplyRequired = !applyRulesEqual(detector.appliedRules, desiredRules)
	if decision.ApplyRequired {
		firstActivation := len(detector.appliedRules) == 0 && len(desiredRules) > 0
		ruleRemoved := applyRuleRemoved(detector.appliedRules, desiredRules)
		minimumUS := int64(detector.config.Action.MinReloadIntervalSeconds) * 1_000_000
		decision.ApplyNow = ruleRemoved || firstActivation || detector.lastAppliedUS == 0 ||
			evaluationUS-detector.lastAppliedUS >= minimumUS
	}
	return decision, nil
}

func (detector *Detector) MarkApplied(appliedUS int64) {
	detector.appliedRules = projectRules(detector.state.Rules)
	detector.lastAppliedUS = appliedUS
}

func (detector *Detector) CurrentState() State {
	return cloneState(detector.state)
}

func (detector *Detector) recordHealth(structureError bool) {
	if detector.healthCount == len(detector.health) {
		if detector.health[detector.healthIndex] {
			detector.structureErrors--
		}
	} else {
		detector.healthCount++
	}
	detector.health[detector.healthIndex] = structureError
	if structureError {
		detector.structureErrors++
	}
	detector.healthIndex = (detector.healthIndex + 1) % len(detector.health)
}

func validObservedStatus(status int, limiterStatus string) bool {
	if status < 100 || status > 599 {
		return false
	}
	switch limiterStatus {
	case "", "-", "PASSED", "DELAYED", "DELAYED_DRY_RUN", "REJECTED_DRY_RUN":
		return true
	case "REJECTED":
		return status == 429
	default:
		return false
	}
}

func (detector *Detector) candidateSafe(record ProtectionRecord) bool {
	if record.CanonicalPath == nil || *record.CanonicalPath != record.NginxURI ||
		record.Event.ActionablePrefix == nil || record.Event.ClientKey == "" ||
		!domain.ValidMethod(record.Event.Method) || !domain.ValidActionable(*record.Event.ActionablePrefix) {
		return false
	}
	return !detector.config.actionExcluded(record.Event.Method, *record.Event.ActionablePrefix)
}

func (config Config) actionExcluded(method, pathPrefix string) bool {
	if method == "OPTIONS" || pathPrefix == "/" {
		return true
	}
	for _, excludedMethod := range config.Exclusions.Methods {
		if method == excludedMethod {
			return true
		}
	}
	builtInPaths := []string{
		"/.well-known/acme-challenge/", "/health", "/healthz", "/live", "/livez", "/ready", "/readyz",
	}
	for _, excludedPath := range append(builtInPaths, config.Exclusions.PathPrefixes...) {
		if RulePathMatches(excludedPath, pathPrefix) || RulePathMatches(pathPrefix, excludedPath) {
			return true
		}
	}
	return false
}

func (detector *Detector) observeCandidate(record ProtectionRecord, bucket int64) error {
	prefix := *record.Event.ActionablePrefix
	volume := detector.registerGroup("volume", record.Event.Method, prefix, prefix)
	if volume != nil {
		if err := addGroupObservation(volume, bucket, record.Event); err != nil {
			volume.unsafe = true
			return err
		}
	}
	shape := detector.registerGroup("shape", record.Event.Method, record.Event.Route, prefix)
	if shape != nil {
		if shape.pathPrefix != prefix {
			shape.unsafe = true
		}
		if err := addGroupObservation(shape, bucket, record.Event); err != nil {
			shape.unsafe = true
			return err
		}
	}
	return nil
}

func (detector *Detector) registerGroup(kind, method, path, pathPrefix string) *trackedGroup {
	key := kind + "\x00" + method + "\x00" + path
	if group, exists := detector.groups[key]; exists {
		return group
	}
	if len(detector.groups) >= detector.config.Detection.MaxTrackedGroups {
		detector.capacitySinceEvaluation = true
		return nil
	}
	group := &trackedGroup{
		kind: kind, method: method, path: path, pathPrefix: pathPrefix,
		buckets: make(map[int64]*detectorMetrics),
	}
	detector.groups[key] = group
	return group
}

func addGroupObservation(group *trackedGroup, bucket int64, event domain.Event) error {
	metrics := group.buckets[bucket]
	if metrics == nil {
		metrics = &detectorMetrics{}
		group.buckets[bucket] = metrics
	}
	if metrics.requests == math.MaxInt64 {
		return errors.New("group request counter overflows")
	}
	metrics.requests++
	metrics.clients.Add(event.ClientKey)
	if event.UpstreamDurationUS != nil {
		if metrics.upstreamSamples == math.MaxInt64 ||
			*event.UpstreamDurationUS > math.MaxInt64-metrics.upstreamDurationUS {
			return errors.New("group upstream counter overflows")
		}
		metrics.upstreamSamples++
		metrics.upstreamDurationUS += *event.UpstreamDurationUS
	}
	return nil
}

func (detector *Detector) observeRefresh(record ProtectionRecord, bucket int64) {
	for _, rule := range detector.appliedRules {
		if rule.Method != record.Event.Method || !RulePathMatches(rule.PathPrefix, record.NginxURI) {
			continue
		}
		key := actionKey(rule.Method, rule.PathPrefix)
		if detector.attemptBuckets[key] == nil {
			detector.attemptBuckets[key] = make(map[int64]int64)
		}
		_ = addBucketCount(detector.attemptBuckets[key], bucket, 1)
	}
}

func addBucketCount(buckets map[int64]int64, bucket, value int64) error {
	if value < 0 || buckets[bucket] > math.MaxInt64-value {
		return errors.New("bucket counter overflows")
	}
	buckets[bucket] += value
	return nil
}

func incrementRejected(counter *int64) {
	if *counter < math.MaxInt64 {
		*counter++
	}
}

func (detector *Detector) bucketEnd(timestampUS int64) int64 {
	intervalUS := int64(detector.config.Detection.EvaluationIntervalSeconds) * 1_000_000
	return ((timestampUS-1)/intervalUS + 1) * intervalUS
}

func (detector *Detector) prune(evaluationUS int64) {
	cutoff := evaluationUS - int64(detector.config.Detection.WindowSeconds)*1_000_000
	pruneCounts(detector.siteBuckets, cutoff, evaluationUS)
	for key, group := range detector.groups {
		for bucket := range group.buckets {
			if bucket <= cutoff || bucket > evaluationUS {
				delete(group.buckets, bucket)
			}
		}
		if len(group.buckets) == 0 {
			delete(detector.groups, key)
		}
	}
	for key, buckets := range detector.attemptBuckets {
		pruneCounts(buckets, cutoff, evaluationUS)
		if len(buckets) == 0 {
			delete(detector.attemptBuckets, key)
		}
	}
}

func pruneCounts(buckets map[int64]int64, cutoff, maximumBucket int64) {
	for bucket := range buckets {
		if bucket <= cutoff || bucket > maximumBucket {
			delete(buckets, bucket)
		}
	}
}

func (detector *Detector) evaluateGroups(
	evaluationUS int64,
	allowed bool,
	decision *Decision,
) ([]qualification, error) {
	keys := make([]string, 0, len(detector.groups))
	for key := range detector.groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	siteRequests, err := sumCounts(detector.siteBuckets)
	if err != nil {
		return nil, err
	}
	qualifications := []qualification{}
	for _, key := range keys {
		group := detector.groups[key]
		metrics, err := sumGroup(group)
		if err != nil {
			return nil, err
		}
		qualified, thresholds, err := detector.groupQualified(group, metrics, siteRequests)
		if err != nil {
			return nil, err
		}
		if !allowed || !qualified || group.unsafe {
			group.consecutive = 0
			continue
		}
		decision.Events = append(decision.Events, DetectorEvent{
			Kind: "protect_candidate", Detector: detectorReason(group.kind),
			Method: group.method, PathPrefix: group.pathPrefix,
			Requests: metrics.requests, SiteRequests: siteRequests,
			DistinctClients: metrics.clients.Conservative(metrics.requests),
			UpstreamSamples: metrics.upstreamSamples, UpstreamDurationUS: metrics.upstreamDurationUS,
			BaselineRequests: thresholds.baselineRequests, BaselineUpstreamUS: thresholds.baselineUpstream,
			RequestThreshold: thresholds.request, UpstreamThreshold: thresholds.upstream,
		})
		group.consecutive++
		if group.consecutive < detector.config.Detection.RequiredConsecutiveEvaluations {
			continue
		}
		qualifications = append(qualifications, qualification{
			reason: detectorReason(group.kind), method: group.method, pathPrefix: group.pathPrefix,
			requestThreshold: thresholds.request,
		})
	}
	return qualifications, nil
}

func (detector *Detector) groupQualified(
	group *trackedGroup,
	metrics detectorMetrics,
	siteRequests int64,
) (bool, groupThresholds, error) {
	if group.kind == "volume" {
		threshold, err := detector.baseline.PrefixRequestThreshold(detector.config, group.method, group.path)
		if err != nil {
			return false, groupThresholds{}, err
		}
		qualified := metrics.requests >= threshold && ratioAtLeast(
			metrics.requests,
			siteRequests,
			detector.config.Detection.VolumeMinSiteSharePPM,
		)
		return qualified, groupThresholds{
			request:          threshold,
			baselineRequests: detector.baseline.PrefixRequestP99(group.method, group.path),
		}, nil
	}
	requestThreshold, err := detector.baseline.RouteRequestThreshold(detector.config, group.method, group.path)
	if err != nil {
		return false, groupThresholds{}, err
	}
	upstreamThreshold, err := detector.baseline.RouteUpstreamThreshold(detector.config, group.method, group.path)
	if err != nil {
		return false, groupThresholds{}, err
	}
	clients := metrics.clients.Conservative(metrics.requests)
	qualified := metrics.requests >= requestThreshold &&
		clients >= detector.config.Detection.DistributedMinClients &&
		ratioAtLeast(clients, metrics.requests, detector.config.Detection.DistributedMinClientRatioPPM) &&
		ratioAtLeast(
			metrics.upstreamSamples,
			metrics.requests,
			detector.config.Detection.DistributedMinUpstreamCoveragePPM,
		) &&
		metrics.upstreamDurationUS >= upstreamThreshold &&
		productAtLeast(
			metrics.upstreamDurationUS,
			1,
			metrics.upstreamSamples,
			detector.config.Detection.DistributedMinAverageUpstreamUS,
		)
	return qualified, groupThresholds{
		request:          requestThreshold,
		upstream:         upstreamThreshold,
		baselineRequests: detector.baseline.RouteRequestP99(group.method, group.path),
		baselineUpstream: detector.baseline.RouteUpstreamP99(group.method, group.path),
	}, nil
}

func sumCounts(buckets map[int64]int64) (int64, error) {
	var total int64
	for _, value := range buckets {
		if value > math.MaxInt64-total {
			return 0, errors.New("rolling counter overflows")
		}
		total += value
	}
	return total, nil
}

func sumGroup(group *trackedGroup) (detectorMetrics, error) {
	var total detectorMetrics
	for _, metrics := range group.buckets {
		if metrics.requests > math.MaxInt64-total.requests ||
			metrics.upstreamSamples > math.MaxInt64-total.upstreamSamples ||
			metrics.upstreamDurationUS > math.MaxInt64-total.upstreamDurationUS {
			return detectorMetrics{}, errors.New("rolling group counter overflows")
		}
		total.requests += metrics.requests
		total.upstreamSamples += metrics.upstreamSamples
		total.upstreamDurationUS += metrics.upstreamDurationUS
		total.clients.Merge(metrics.clients)
	}
	return total, nil
}

func ratioAtLeast(numerator, denominator, minimumPPM int64) bool {
	if numerator < 0 || denominator <= 0 || minimumPPM < 0 {
		return false
	}
	return productAtLeast(numerator, int64(ratioScale), denominator, minimumPPM)
}

func productAtLeast(leftA, leftB, rightA, rightB int64) bool {
	if leftA < 0 || leftB < 0 || rightA < 0 || rightB < 0 {
		return false
	}
	leftHigh, leftLow := bits.Mul64(uint64(leftA), uint64(leftB))
	rightHigh, rightLow := bits.Mul64(uint64(rightA), uint64(rightB))
	return leftHigh > rightHigh || leftHigh == rightHigh && leftLow >= rightLow
}

func detectorReason(kind string) string {
	if kind == "volume" {
		return "extreme-volume"
	}
	return "distributed-expense"
}

func makeProposals(qualifications []qualification) map[string]actionProposal {
	proposals := make(map[string]actionProposal)
	for _, qualified := range qualifications {
		key := actionKey(qualified.method, qualified.pathPrefix)
		proposal, exists := proposals[key]
		if !exists {
			proposal = actionProposal{
				method: qualified.method, pathPrefix: qualified.pathPrefix,
				requestThreshold: qualified.requestThreshold,
			}
		}
		if qualified.requestThreshold < proposal.requestThreshold {
			proposal.requestThreshold = qualified.requestThreshold
		}
		proposal.reasons = append(proposal.reasons, qualified.reason)
		proposals[key] = proposal
	}
	for key, proposal := range proposals {
		sort.Strings(proposal.reasons)
		proposal.reasons = compactStrings(proposal.reasons)
		proposals[key] = proposal
	}
	return proposals
}

func (detector *Detector) updateRules(
	evaluationUS int64,
	activationAllowed bool,
	proposals map[string]actionProposal,
	decision *Decision,
) error {
	expiresAtUS, err := addSeconds(evaluationUS, detector.config.Action.TTLSeconds)
	if err != nil {
		return err
	}
	rules := make(map[string]Rule, len(detector.state.Rules))
	for _, rule := range detector.state.Rules {
		rules[actionKey(rule.Method, rule.PathPrefix)] = rule
	}
	proposalKeys := make([]string, 0, len(proposals))
	for key := range proposals {
		proposalKeys = append(proposalKeys, key)
	}
	sort.Strings(proposalKeys)
	refreshed := make(map[string]bool)
	for _, key := range proposalKeys {
		proposal := proposals[key]
		rule, exists := rules[key]
		if !exists {
			if len(rules) >= detector.config.Action.MaxActiveRules {
				decision.Events = append(decision.Events, DetectorEvent{
					Kind: "protect_capacity_reached", Method: proposal.method, PathPrefix: proposal.pathPrefix,
				})
				continue
			}
			rule = Rule{
				Method: proposal.method, PathPrefix: proposal.pathPrefix,
				Reasons: append([]string(nil), proposal.reasons...), RequestThreshold: proposal.requestThreshold,
				FirstQualifiedAtUS: evaluationUS,
			}
			decision.Events = append(decision.Events, DetectorEvent{
				Kind: "protect_activated", Method: rule.Method, PathPrefix: rule.PathPrefix,
				RequestThreshold: rule.RequestThreshold, ExpiresAtUS: expiresAtUS,
			})
		} else {
			rule.Reasons = mergeStrings(rule.Reasons, proposal.reasons)
			decision.Events = append(decision.Events, DetectorEvent{
				Kind: "protect_refreshed", Method: rule.Method, PathPrefix: rule.PathPrefix,
				RequestThreshold: rule.RequestThreshold, ExpiresAtUS: expiresAtUS,
			})
		}
		rule.LastQualifiedAtUS = evaluationUS
		rule.ExpiresAtUS = expiresAtUS
		rules[key] = rule
		refreshed[key] = true
	}
	if activationAllowed {
		for key, rule := range rules {
			if refreshed[key] {
				continue
			}
			attempts, err := sumCounts(detector.attemptBuckets[key])
			if err != nil {
				return err
			}
			if attempts < rule.RequestThreshold {
				continue
			}
			rule.LastQualifiedAtUS = evaluationUS
			rule.ExpiresAtUS = expiresAtUS
			rules[key] = rule
			refreshed[key] = true
			decision.Events = append(decision.Events, DetectorEvent{
				Kind: "protect_refreshed", Detector: "active-attempts", Method: rule.Method,
				PathPrefix: rule.PathPrefix, Requests: attempts, RequestThreshold: rule.RequestThreshold,
				ExpiresAtUS: expiresAtUS,
			})
		}
	}
	result := make([]Rule, 0, len(rules))
	for key, rule := range rules {
		if rule.ExpiresAtUS <= evaluationUS && !refreshed[key] {
			decision.Events = append(decision.Events, DetectorEvent{
				Kind: "protect_expired", Method: rule.Method, PathPrefix: rule.PathPrefix,
			})
			continue
		}
		result = append(result, rule)
	}
	sort.Slice(result, func(left, right int) bool { return ruleLess(result[left], result[right]) })
	detector.state.Rules = result
	return detector.state.Validate()
}

func addSeconds(timestampUS int64, seconds int) (int64, error) {
	delta := int64(seconds) * 1_000_000
	if timestampUS > math.MaxInt64-delta {
		return 0, errors.New("rule expiry overflows")
	}
	return timestampUS + delta, nil
}

func RulePathMatches(prefix, path string) bool {
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(path, prefix)
	}
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func actionKey(method, pathPrefix string) string {
	return method + "\x00" + pathPrefix
}

func projectRules(rules []Rule) []ApplyRule {
	result := make([]ApplyRule, len(rules))
	for index, rule := range rules {
		result[index] = ApplyRule{Method: rule.Method, PathPrefix: rule.PathPrefix}
	}
	return result
}

func cloneState(state State) State {
	result := state
	if state.BaselineManifestSHA256 != nil {
		digest := *state.BaselineManifestSHA256
		result.BaselineManifestSHA256 = &digest
	}
	result.Rules = make([]Rule, len(state.Rules))
	for index, rule := range state.Rules {
		result.Rules[index] = rule
		result.Rules[index].Reasons = append([]string(nil), rule.Reasons...)
	}
	return result
}

func rulesEqual(left, right []Rule) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].Method != right[index].Method || left[index].PathPrefix != right[index].PathPrefix ||
			left[index].RequestThreshold != right[index].RequestThreshold ||
			left[index].FirstQualifiedAtUS != right[index].FirstQualifiedAtUS ||
			left[index].LastQualifiedAtUS != right[index].LastQualifiedAtUS ||
			left[index].ExpiresAtUS != right[index].ExpiresAtUS ||
			!stringSlicesEqual(left[index].Reasons, right[index].Reasons) {
			return false
		}
	}
	return true
}

func applyRulesEqual(left, right []ApplyRule) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func applyRuleRemoved(applied, desired []ApplyRule) bool {
	for _, appliedRule := range applied {
		found := false
		for _, desiredRule := range desired {
			if appliedRule == desiredRule {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func mergeStrings(left, right []string) []string {
	result := append(append([]string(nil), left...), right...)
	sort.Strings(result)
	return compactStrings(result)
}

func compactStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
