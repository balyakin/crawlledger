package protect

import (
	"fmt"
	"net/netip"
	"strconv"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/normalize"
	"github.com/balyakin/crawlledger/internal/parser"
)

func TestDetectorStatusAccounting(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		limiter string
		want    Accounting
	}{
		{name: "normal", status: 200, limiter: "", want: Accounting{Denominator: true, Candidate: true, Refresh: true}},
		{name: "passed", status: 404, limiter: "PASSED", want: Accounting{Denominator: true, Candidate: true, Refresh: true}},
		{name: "static 403", status: 403, limiter: "", want: Accounting{Denominator: true}},
		{name: "application 429", status: 429, limiter: "", want: Accounting{Denominator: true}},
		{name: "rejected", status: 429, limiter: "REJECTED", want: Accounting{Refresh: true}},
		{name: "dry run", status: 200, limiter: "REJECTED_DRY_RUN", want: Accounting{Denominator: true, Candidate: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ClassifyAccounting(test.status, test.limiter); got != test.want {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestDetectorHealthUsesLastHundredNonEmptyLines(t *testing.T) {
	detector := newTestDetector(t, testDetectorConfig(), Baseline{Eligible: true})
	for index := 0; index < 11; index++ {
		detector.ObserveError(1, parser.SensorStructureError, true)
	}
	for index := 0; index < 89; index++ {
		detector.ObserveError(1, parser.RecordContentError, true)
	}
	if !detector.SensorSuspended() {
		t.Fatal("eleven structure errors in the last hundred did not suspend detection")
	}
	for index := 0; index < 11; index++ {
		detector.ObserveError(1, parser.RecordContentError, true)
	}
	if detector.SensorSuspended() {
		t.Fatal("detector did not recover after structure errors left the window")
	}
	for index := 0; index < 20; index++ {
		detector.ObserveError(1, parser.SensorStructureError, false)
	}
	if detector.SensorSuspended() {
		t.Fatal("empty lines affected structure health")
	}
}

func TestDetectorLagBoundaries(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.WindowSeconds = 60
	config.Detection.MaxEventLagSeconds = 30
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	receiptUS := int64(100 * 1_000_000)
	record := testProtectionRecord(receiptUS-30*1_000_000, "GET", "/api", "/api", "client-a")
	if result := detector.Observe(record, receiptUS); !result.Fresh {
		t.Fatalf("exact lag boundary rejected: %#v", result)
	}
	record.Event.TimestampUS--
	if result := detector.Observe(record, receiptUS); result.Fresh || result.Reason != "stale" {
		t.Fatalf("past lag accepted: %#v", result)
	}
	record.Event.TimestampUS = receiptUS + 1
	if result := detector.Observe(record, receiptUS); result.Fresh || result.Reason != "future" {
		t.Fatalf("future timestamp accepted: %#v", result)
	}
}

func TestDetectorRollingWindowExcludesExactCutoff(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Detection.VolumeMinRequests = 1
	evaluationUS := int64(100 * 1_000_000)
	cutoffUS := evaluationUS - int64(config.Detection.WindowSeconds)*1_000_000

	atCutoff := newTestDetector(t, config, Baseline{Eligible: true})
	atCutoff.Observe(testProtectionRecord(cutoffUS, "GET", "/api", "/api", "client-a"), cutoffUS)
	decision, err := atCutoff.Evaluate(evaluationUS)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 0 {
		t.Fatalf("exact cutoff contributed to the rolling window: %#v", decision.State.Rules)
	}

	afterCutoff := newTestDetector(t, config, Baseline{Eligible: true})
	afterCutoff.Observe(testProtectionRecord(cutoffUS+1, "GET", "/api", "/api", "client-a"), cutoffUS+1)
	decision, err = afterCutoff.Evaluate(evaluationUS)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 1 {
		t.Fatalf("event after cutoff was excluded: %#v", decision.State.Rules)
	}
}

func TestDetectorMixedStaleAndFreshStreamUsesOnlyFreshRecords(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(150 * 1_000_000)
	for index := 0; index < 4; index++ {
		freshUS := baseUS + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(freshUS, "GET", "/api", "/api", fmt.Sprintf("%032x", index+1)), freshUS)
		stale := testProtectionRecord(baseUS-20*1_000_000, "GET", "/stale", "/stale", fmt.Sprintf("%032x", index+10))
		if result := detector.Observe(stale, freshUS); result.Fresh || result.Reason != "stale" {
			t.Fatalf("stale record accepted: %#v", result)
		}
	}
	decision, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 1 || decision.State.Rules[0].PathPrefix != "/api" {
		t.Fatalf("fresh neighbor did not detect safely: %#v", decision.State.Rules)
	}
}

func TestDetectorActivatesExtremeVolumeAfterConsecutiveEvaluations(t *testing.T) {
	config := testDetectorConfig()
	baseline := Baseline{
		Eligible:       true,
		prefixRequests: map[seriesKey]int64{{Method: "POST", Path: "/api"}: 1},
		routeRequests:  map[seriesKey]int64{},
		routeUpstream:  map[seriesKey]int64{},
	}
	detector := newTestDetector(t, config, baseline)
	baseUS := int64(100 * 1_000_000)
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "POST", "/api/{int}", "/api", fmt.Sprintf("%032x", index+1)), timestampUS)
	}
	first, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.State.Rules) != 0 {
		t.Fatal("rule activated before the required consecutive evaluation")
	}
	if len(first.Events) != 1 || first.Events[0].Kind != "protect_candidate" ||
		first.Events[0].Requests != 4 || first.Events[0].SiteRequests != 4 {
		t.Fatalf("first qualifying evaluation did not emit candidate evidence: %#v", first.Events)
	}
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + 5*1_000_000 + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "POST", "/api/{int}", "/api", fmt.Sprintf("%032x", index+5)), timestampUS)
	}
	second, err := detector.Evaluate(baseUS + 10*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.State.Rules) != 1 {
		t.Fatalf("rule did not activate: %#v", second)
	}
	rule := second.State.Rules[0]
	if rule.Method != "POST" || rule.PathPrefix != "/api" || rule.RequestThreshold != 4 ||
		len(rule.Reasons) != 1 || rule.Reasons[0] != "extreme-volume" || !second.ApplyNow {
		t.Fatalf("unexpected activated rule: %#v", rule)
	}
}

func TestDetectorReportsBaselineLagAndRejectedRecordEvidence(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Detection.VolumeMinRequests = 1
	baseline := Baseline{
		Eligible:       true,
		prefixRequests: map[seriesKey]int64{{Method: "GET", Path: "/api"}: 3},
	}
	detector := newTestDetector(t, config, baseline)
	detector.ObserveError(1, parser.RecordContentError, true)
	detector.ObserveError(1, parser.SensorStructureError, true)
	timestampUS := int64(100 * 1_000_000)
	receiptUS := timestampUS + 7_000
	detector.Observe(testProtectionRecord(timestampUS, "GET", "/api", "/api", "client-a"), receiptUS)
	detector.Observe(testProtectionRecord(timestampUS+1_000, "GET", "/api", "/api", "client-b"), timestampUS+1_000)
	future := testProtectionRecord(receiptUS+1, "GET", "/future", "/future", "client-b")
	detector.Observe(future, receiptUS)
	decision, err := detector.Evaluate(105 * 1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if decision.MaxEventLagUS != 7_000 || decision.RejectedRecords.RecordContent != 1 ||
		decision.RejectedRecords.SensorStructure != 1 || decision.RejectedRecords.Future != 1 {
		t.Fatalf("missing interval evidence: %#v", decision)
	}
	found := false
	for _, event := range decision.Events {
		if event.Kind == "protect_candidate" {
			found = true
			if event.BaselineRequests != 3 || event.RequestThreshold != 2 {
				t.Fatalf("missing baseline evidence: %#v", event)
			}
		}
	}
	if !found {
		t.Fatalf("candidate event is missing: %#v", decision.Events)
	}
}

func TestDetectorEnforcesActiveRuleCapacity(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Action.MaxActiveRules = 1
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(350 * 1_000_000)
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "GET", "/a", "/a", fmt.Sprintf("%032x", index+1)), timestampUS)
		detector.Observe(testProtectionRecord(timestampUS+10, "GET", "/b", "/b", fmt.Sprintf("%032x", index+10)), timestampUS+10)
	}
	decision, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 1 {
		t.Fatalf("active rule cap was exceeded: %#v", decision.State.Rules)
	}
	foundCapacity := false
	for _, event := range decision.Events {
		foundCapacity = foundCapacity || event.Kind == "protect_capacity_reached"
	}
	if !foundCapacity {
		t.Fatalf("capacity event is missing: %#v", decision.Events)
	}
}

func TestDetectorCoalescesLaterMapChanges(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Action.MinReloadIntervalSeconds = 60
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(500 * 1_000_000)
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "GET", "/a", "/a", fmt.Sprintf("%032x", index+1)), timestampUS)
	}
	first, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil || !first.ApplyNow {
		t.Fatalf("first activation was not immediate: decision=%#v err=%v", first, err)
	}
	detector.MarkApplied(baseUS + 5*1_000_000)
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + 5*1_000_000 + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "GET", "/b", "/b", fmt.Sprintf("%032x", index+10)), timestampUS)
	}
	second, err := detector.Evaluate(baseUS + 10*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !second.ApplyRequired || second.ApplyNow {
		t.Fatalf("later addition bypassed reload coalescing: %#v", second)
	}
	third, err := detector.Evaluate(baseUS + 65*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !third.ApplyRequired || !third.ApplyNow {
		t.Fatalf("coalesced map did not become applicable: %#v", third)
	}
}

func TestDetectorAppliesRuleRemovalImmediately(t *testing.T) {
	config := testDetectorConfig()
	config.Action.MinReloadIntervalSeconds = 60
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(600 * 1_000_000)
	detector.state.Rules = []Rule{{
		Method: "GET", PathPrefix: "/api", Reasons: []string{"extreme-volume"}, RequestThreshold: 4,
		FirstQualifiedAtUS: baseUS - 20*1_000_000, LastQualifiedAtUS: baseUS - 10*1_000_000,
		ExpiresAtUS: baseUS + 5*1_000_000,
	}}
	detector.MarkApplied(baseUS)
	decision, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if !decision.ApplyRequired || !decision.ApplyNow || len(decision.State.Rules) != 0 {
		t.Fatalf("expired applied rule was not removed immediately: %#v", decision)
	}
}

func TestDetectorReusesTrackedGroupCapacityAfterWindow(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Detection.VolumeMinRequests = 4
	config.Detection.MaxTrackedGroups = 100
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(700 * 1_000_000)
	for index := 0; index < 50; index++ {
		path := fmt.Sprintf("/cold/%d", index)
		timestampUS := baseUS + int64(index+1)*1_000
		detector.Observe(testProtectionRecord(timestampUS, "GET", path, path, "client-cold"), timestampUS)
	}
	if _, err := detector.Evaluate(baseUS + 5*1_000_000); err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Evaluate(baseUS + 15*1_000_000); err != nil {
		t.Fatal(err)
	}
	if len(detector.groups) != 0 {
		t.Fatalf("cold tracked groups were not pruned: %d", len(detector.groups))
	}
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + 15*1_000_000 + int64(index+1)*100_000
		detector.Observe(
			testProtectionRecord(timestampUS, "GET", "/hot", "/hot", fmt.Sprintf("%032x", index+1)),
			timestampUS,
		)
	}
	decision, err := detector.Evaluate(baseUS + 20*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 1 || decision.State.Rules[0].PathPrefix != "/hot" {
		t.Fatalf("new hot group was not tracked after pruning: %#v", decision)
	}
}

func TestDetectorRequiresSafeUnexcludedPath(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Exclusions.PathPrefixes = []string{"/private"}
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(200 * 1_000_000)
	records := []ProtectionRecord{
		testProtectionRecord(baseUS+100_000, "OPTIONS", "/api", "/api", "client-a"),
		testProtectionRecord(baseUS+200_000, "GET", "/health", "/health", "client-b"),
		testProtectionRecord(baseUS+300_000, "GET", "/private", "/private", "client-c"),
		testProtectionRecord(baseUS+400_000, "GET", "/api", "/api", "client-d"),
	}
	changed := "/rewritten"
	records[3].CanonicalPath = &changed
	for _, record := range records {
		detector.Observe(record, record.Event.TimestampUS)
	}
	decision, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 0 {
		t.Fatalf("unsafe path activated a rule: %#v", decision.State.Rules)
	}
}

func TestDetectorActivatesDistributedExpense(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	config.Detection.VolumeMinRequests = 10_000_000
	config.Detection.DistributedMinRequests = 10_000
	config.Detection.DistributedMinClients = 5_000
	config.Detection.DistributedMinClientRatioPPM = 500_000
	config.Detection.DistributedMinUpstreamCoveragePPM = 800_000
	config.Detection.DistributedMinUpstreamUS = 2_500_000_000
	config.Detection.DistributedMinAverageUpstreamUS = 250_000
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(300 * 1_000_000)
	upstreamUS := int64(300_000)
	var key normalize.Key
	for index := range key {
		key[index] = byte(index + 1)
	}
	normalizer := normalize.New(key)
	for index := 0; index < 10_000; index++ {
		timestampUS := baseUS + int64(index+1)*100
		address := netip.MustParseAddr("2001:db8::" + strconv.FormatInt(int64(index+1), 16))
		requestURI := "/api/search/" + strconv.Itoa(index+100_000)
		event, canonical, err := normalizer.NormalizeProtection(parser.RawRecord{
			TimestampUS: timestampUS, ClientIP: address, Method: "POST", RequestURI: requestURI,
			Status: 200, BytesSent: 1, UpstreamDurationUS: &upstreamUS, CacheState: domain.CacheUnknown,
		}, normalize.Facts{})
		if err != nil {
			t.Fatal(err)
		}
		record := ProtectionRecord{Event: event, CanonicalPath: canonical, NginxURI: requestURI}
		detector.Observe(record, timestampUS)
	}
	decision, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if len(decision.State.Rules) != 1 || decision.State.Rules[0].Reasons[0] != "distributed-expense" {
		t.Fatalf("distributed attack did not activate: rules=%#v events=%#v", decision.State.Rules, decision.Events)
	}
}

func TestDetectorRefreshAndExpiry(t *testing.T) {
	config := testDetectorConfig()
	config.Detection.RequiredConsecutiveEvaluations = 1
	detector := newTestDetector(t, config, Baseline{Eligible: true})
	baseUS := int64(400 * 1_000_000)
	for index := 0; index < 4; index++ {
		timestampUS := baseUS + int64(index+1)*100_000
		detector.Observe(testProtectionRecord(timestampUS, "POST", "/api", "/api", fmt.Sprintf("%032x", index+1)), timestampUS)
	}
	activated, err := detector.Evaluate(baseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	detector.MarkApplied(baseUS + 5*1_000_000)
	initialExpiry := activated.State.Rules[0].ExpiresAtUS
	refreshBaseUS := baseUS + 20*1_000_000
	for index := 0; index < 4; index++ {
		timestampUS := refreshBaseUS + int64(index+1)*100_000
		record := testProtectionRecord(timestampUS, "POST", "/ignored", "/api/item", fmt.Sprintf("%032x", index+20))
		record.Event.Status = 429
		detector.Observe(record, timestampUS)
		adjacent := testProtectionRecord(timestampUS+10, "POST", "/ignored", "/apix", fmt.Sprintf("%032x", index+30))
		adjacent.LimitReqStatus = "REJECTED"
		adjacent.Event.Status = 429
		detector.Observe(adjacent, timestampUS+10)
	}
	notRefreshed, err := detector.Evaluate(refreshBaseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if notRefreshed.State.Rules[0].ExpiresAtUS != initialExpiry {
		t.Fatal("application 429 or adjacent limiter rejects refreshed the rule")
	}
	refreshBaseUS += 10 * 1_000_000
	for index := 0; index < 4; index++ {
		timestampUS := refreshBaseUS + int64(index+1)*100_000
		record := testProtectionRecord(timestampUS, "POST", "/ignored", "/api/item", fmt.Sprintf("%032x", index+40))
		record.LimitReqStatus = "REJECTED"
		record.Event.Status = 429
		record.CanonicalPath = nil
		detector.Observe(record, timestampUS)
	}
	refreshed, err := detector.Evaluate(refreshBaseUS + 5*1_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.State.Rules[0].ExpiresAtUS <= initialExpiry {
		t.Fatal("matching limiter rejects did not refresh the rule")
	}
	expired, err := detector.Evaluate(refreshed.State.Rules[0].ExpiresAtUS)
	if err != nil {
		t.Fatal(err)
	}
	if len(expired.State.Rules) != 0 {
		t.Fatalf("quiet rule did not expire: %#v", expired.State.Rules)
	}
	if len(detector.attemptBuckets) != 0 {
		t.Fatalf("expired attempt buckets were not pruned: %d", len(detector.attemptBuckets))
	}
}

func TestRulePathMatchBoundaries(t *testing.T) {
	tests := map[string]bool{
		"/api":        true,
		"/api/item":   true,
		"/api/":       true,
		"/apipayment": false,
		"/api%2fitem": false,
		"/other":      false,
	}
	for path, expected := range tests {
		if got := RulePathMatches("/api", path); got != expected {
			t.Fatalf("RulePathMatches(%q) = %t, want %t", path, got, expected)
		}
	}
	if !RulePathMatches("/api/", "/api/item") || RulePathMatches("/api/", "/api") {
		t.Fatal("slash-terminated prefix semantics are wrong")
	}
}

func testDetectorConfig() Config {
	config := Config{
		SchemaVersion: 1,
		Site:          "example",
		Runtime:       RuntimeConfig{MaxLogLineBytes: 4096},
		Detection: Detection{
			WindowSeconds:                     10,
			EvaluationIntervalSeconds:         5,
			RequiredConsecutiveEvaluations:    2,
			MaxEventLagSeconds:                30,
			BaselineMultiplier:                2,
			VolumeMinRequests:                 4,
			VolumeMinSiteSharePPM:             500_000,
			DistributedMinRequests:            1_000,
			DistributedMinClients:             500,
			DistributedMinClientRatioPPM:      500_000,
			DistributedMinUpstreamCoveragePPM: 800_000,
			DistributedMinUpstreamUS:          120_000_000,
			DistributedMinAverageUpstreamUS:   250_000,
			MaxTrackedGroups:                  100,
		},
		Action: Action{
			TTLSeconds:               60,
			RateRequestsPerSecond:    10,
			Burst:                    20,
			MaxActiveRules:           16,
			MinReloadIntervalSeconds: 5,
		},
		Exclusions: Exclusions{Methods: []string{}, PathPrefixes: []string{}},
		StaticDeny: StaticDeny{Enabled: []string{}},
	}
	return config
}

func newTestDetector(t *testing.T, config Config, baseline Baseline) *Detector {
	t.Helper()
	baseline.ManifestSHA256 = testManifestDigest
	if baseline.prefixRequests == nil {
		baseline.prefixRequests = map[seriesKey]int64{}
	}
	if baseline.routeRequests == nil {
		baseline.routeRequests = map[seriesKey]int64{}
	}
	if baseline.routeUpstream == nil {
		baseline.routeUpstream = map[seriesKey]int64{}
	}
	baselineDigest := baseline.ManifestSHA256
	state := State{
		SchemaVersion:          1,
		Site:                   config.Site,
		ConfigSHA256:           testManifestDigest,
		BaselineManifestSHA256: &baselineDigest,
		Rules:                  []Rule{},
	}
	detector, err := NewDetector(config, testManifestDigest, baseline, state)
	if err != nil {
		t.Fatal(err)
	}
	return detector
}

func testProtectionRecord(timestampUS int64, method, route, prefix, client string) ProtectionRecord {
	canonical := prefix
	actionable := prefix
	return ProtectionRecord{
		Event: domain.Event{
			TimestampUS:      timestampUS,
			ClientKey:        client,
			Method:           method,
			Route:            route,
			ActionablePrefix: &actionable,
			Status:           200,
		},
		CanonicalPath: &canonical,
		NginxURI:      prefix,
	}
}
