package policy

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
)

func testPolicy() domain.Policy {
	return domain.Policy{
		SchemaVersion: 1, Name: "safe", Description: "synthetic",
		Rules: []domain.PolicyRule{{
			ID: "deny-admin",
			Match: domain.PolicyMatch{
				CrawlerNames: []string{}, Categories: []domain.TrafficClass{},
				PathPrefixes: []string{"/admin/"}, Methods: []string{"GET"},
			},
			Action: domain.PolicyAction{Kind: domain.ActionDeny},
		}},
	}
}

func TestLoadValidateCanonicalAndMatch(t *testing.T) {
	value := testPolicy()
	data := `{"schema_version":1,"name":"safe","description":"synthetic","rules":[{"id":"deny-admin","match":{"crawler_names":[],"categories":[],"path_prefixes":["/admin/"],"methods":["GET"]},"action":{"kind":"deny","rate_profile":null,"cache_ttl_seconds":null}}]}`
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	catalogValue, _ := catalog.LoadEmbedded()
	if err := Validate(loaded, catalogValue); err != nil {
		t.Fatal(err)
	}
	_, hash, err := Canonical(loaded)
	if err != nil || len(hash) != 64 {
		t.Fatalf("canonical hash: %q %v", hash, err)
	}
	prefix := "/admin/users"
	if !Matches(value.Rules[0], domain.PolicyCell{ActionablePrefix: &prefix, Method: "GET"}) {
		t.Fatal("segment matcher failed")
	}
	prefix = "/administrator"
	if Matches(value.Rules[0], domain.PolicyCell{ActionablePrefix: &prefix, Method: "GET"}) {
		t.Fatal("segment matcher overmatched")
	}
	if _, err := decode([]byte(strings.Replace(data, `"description":"synthetic"`, `"description":null`, 1))); err == nil {
		t.Fatal("null policy description accepted")
	}
}

func TestSimulationFirstMatch(t *testing.T) {
	value := testPolicy()
	_, hash, _ := Canonical(value)
	simulator := NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
	prefix := "/admin/"
	if err := simulator.Add(domain.TrafficCell{
		Route: "/admin/", ActionablePrefix: &prefix, Method: "GET",
		PrimaryClass: domain.ClassUnclassified, Requests: 3, BytesSent: 30,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := simulator.Finish(nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Totals.DeniedRequests != 3 || result.Totals.AllowedRequests != 0 ||
		result.Status != domain.SimulationRequiresAck {
		t.Fatalf("unexpected simulation: %#v", result)
	}
}

func TestSimulationWarnsForPrefixInsideDynamicRoute(t *testing.T) {
	value := testPolicy()
	value.Rules[0].Match.PathPrefixes = []string{"/archive/123"}
	_, hash, _ := Canonical(value)
	simulator := NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
	prefix := "/archive/"
	if err := simulator.Add(domain.TrafficCell{
		Route: "/archive/{int}", ActionablePrefix: &prefix, Method: "GET",
		PrimaryClass: domain.ClassUnclassified, Requests: 1,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := simulator.Finish(nil)
	if err != nil {
		t.Fatal(err)
	}
	risk, found := findRisk(result, "path-normalization-drift:deny-admin")
	if result.Totals.AllowedRequests != 1 ||
		!found || risk.Acknowledgeable ||
		result.Status != domain.SimulationBlocked {
		t.Fatalf("dynamic path mismatch was deployable: %#v", result)
	}
}

func TestCacheStatusDoesNotMaskBlocker(t *testing.T) {
	risks := []domain.Risk{
		{ID: "analysis-only-cache:cache", Acknowledgeable: false},
		{ID: "rate-coverage-incomplete:rate", Acknowledgeable: false},
	}
	if got := statusFor(risks); got != domain.SimulationBlocked {
		t.Fatalf("statusFor(cache + blocker) = %q", got)
	}
}

func TestRateCoverageAndZoneRisks(t *testing.T) {
	profile := "standard"
	value := domain.Policy{
		SchemaVersion: 1, Name: "rate", Description: "synthetic",
		Rules: []domain.PolicyRule{{
			ID: "rate-ai",
			Match: domain.PolicyMatch{
				CrawlerNames: []string{"GPTBot"}, Categories: []domain.TrafficClass{},
				PathPrefixes: []string{}, Methods: []string{},
			},
			Action: domain.PolicyAction{Kind: domain.ActionRateLimit, RateProfile: &profile},
		}},
	}
	_, hash, _ := Canonical(value)
	name, category := "GPTBot", domain.ClassClaimedAICrawler
	simulator := NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
	if err := simulator.Add(domain.TrafficCell{
		Route: "/archive", Method: "GET", ClaimName: &name, ClaimCategory: &category,
		PrimaryClass: category, Requests: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if err := simulator.AddSubjectState(&name, &category); err != nil {
		t.Fatal(err)
	}
	result, err := simulator.Finish([]domain.RateProfileImpact{{
		ClaimName: &name, ClaimCategory: &category, PrimaryClass: category,
		Profile: profile, ModeledRequests: 1, AllowedRequests: 1,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != domain.SimulationBlocked ||
		result.RuleImpacts[0].MetricCoveragePPM != 500000 ||
		!hasRisk(result, "rate-coverage-incomplete:rate-ai") || !Conserves(result) {
		t.Fatalf("incomplete rate coverage was not blocked: %#v", result)
	}

	simulator = NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
	simulator.observedStates[profile] = 65537
	result, err = simulator.Finish(nil)
	if err != nil || result.Status != domain.SimulationRequiresAck ||
		result.Risks[0].ID != "nginx-zone-memory:standard:33" {
		t.Fatalf("zone acknowledgement boundary failed: %#v, %v", result, err)
	}
	simulator = NewSimulator(value, "an_0123456789abcdef0123456789abcdef", hash)
	simulator.observedStates[profile] = 524289
	result, err = simulator.Finish(nil)
	if err != nil || result.Status != domain.SimulationBlocked ||
		result.Risks[0].ID != "nginx-zone-too-large:standard" {
		t.Fatalf("zone blocker boundary failed: %#v, %v", result, err)
	}
}

func TestSimulationRejectsCounterOverflow(t *testing.T) {
	value := testPolicy()
	simulator := NewSimulator(value, "an_0123456789abcdef0123456789abcdef", strings.Repeat("a", 64))
	simulator.totals.ObservedRequests = math.MaxInt64
	if err := simulator.Add(domain.TrafficCell{Route: "/", Requests: 1}); err == nil {
		t.Fatal("simulation counter overflow was accepted")
	}
}

func TestSimulationRejectsNullRiskBoolean(t *testing.T) {
	value := domain.Simulation{
		SchemaVersion: 1, RunID: "pr_0123456789abcdef",
		AnalysisID: "an_0123456789abcdef0123456789abcdef",
		PolicyHash: strings.Repeat("a", 64), Status: domain.SimulationRequiresAck,
		Coverage:    domain.SimulationCoverage{RateModelPPM: 1_000_000},
		RuleImpacts: []domain.RuleImpact{},
		Risks: []domain.Risk{{
			ID: "synthetic", Severity: domain.SeverityMedium,
			Acknowledgeable: true, Message: "synthetic",
		}},
		Assumptions: []string{},
	}
	data, err := CanonicalSimulation(value)
	if err != nil {
		t.Fatal(err)
	}
	data = []byte(strings.Replace(string(data), `"acknowledgeable":true`, `"acknowledgeable":null`, 1))
	if err := requireSimulationKeys(data); err == nil {
		t.Fatal("null risk acknowledgement flag accepted")
	}
}

func hasRisk(value domain.Simulation, id string) bool {
	_, found := findRisk(value, id)
	return found
}

func findRisk(value domain.Simulation, id string) (domain.Risk, bool) {
	for _, risk := range value.Risks {
		if risk.ID == id {
			return risk, true
		}
	}
	return domain.Risk{}, false
}

func FuzzPolicyLoad(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		value, err := decode(data)
		if err == nil {
			if value.Rules == nil {
				t.Fatal("nil rules accepted")
			}
			encoded, _, err := Canonical(value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "\n") {
				t.Fatal("canonical policy contains newline")
			}
		}
	})
}
