package render

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/catalog"
	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/policy"
)

var updateGoldens = flag.Bool("update", false, "update golden render outputs")

func TestRenderers(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	value := domain.Policy{
		SchemaVersion: 1, Name: "safe", Description: "synthetic",
		Rules: []domain.PolicyRule{{
			ID: "deny-gptbot",
			Match: domain.PolicyMatch{
				CrawlerNames: []string{"GPTBot"}, Categories: []domain.TrafficClass{},
				PathPrefixes: []string{}, Methods: []string{},
			},
			Action: domain.PolicyAction{Kind: domain.ActionDeny},
		}},
	}
	_, hash, err := policy.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	simulation := domain.Simulation{
		SchemaVersion: 1, AnalysisID: "an_0123456789abcdef0123456789abcdef",
		PolicyHash: hash, Status: domain.SimulationSafe,
		Risks: []domain.Risk{},
	}
	input := Input{AnalysisID: simulation.AnalysisID, Simulation: simulation, Policy: value, Catalog: catalogValue}
	for _, target := range []string{"nginx", "caddy"} {
		renderer, err := New(target)
		if err != nil {
			t.Fatal(err)
		}
		artifacts, err := renderer.Render(input)
		if err != nil || len(artifacts) == 0 {
			t.Fatalf("%s render failed: %v", target, err)
		}
	}
}

func TestGoldenOutputs(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join("..", "..", "testdata", "policies", "safe.json")
	value, err := policy.Load(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Validate(value, catalogValue); err != nil {
		t.Fatal(err)
	}
	_, hash, err := policy.Canonical(value)
	if err != nil {
		t.Fatal(err)
	}
	risk := domain.Risk{
		ID: "claimed-allow-bypass:allow-googlebot", Severity: domain.SeverityMedium,
		Acknowledgeable: true, Message: "synthetic",
	}
	simulation := domain.Simulation{
		SchemaVersion: 1, AnalysisID: "an_0123456789abcdef0123456789abcdef",
		PolicyHash: hash, Status: domain.SimulationRequiresAck, Risks: []domain.Risk{risk},
	}
	input := Input{
		AnalysisID: simulation.AnalysisID, Simulation: simulation, Policy: value,
		Catalog: catalogValue, Acks: []string{risk.ID}, ObservedStates: map[string]int64{},
	}
	for target, names := range map[string][]string{
		"nginx": {"crawlledger-http.conf", "crawlledger-server.conf"},
		"caddy": {"Caddyfile.crawlledger"},
	} {
		renderer, _ := New(target)
		artifacts, err := renderer.Render(input)
		if err != nil {
			t.Fatal(err)
		}
		second, err := renderer.Render(input)
		if err != nil {
			t.Fatal(err)
		}
		for index, name := range names {
			if !bytes.Equal(artifacts[index].Content, second[index].Content) {
				t.Fatalf("%s output is not deterministic", name)
			}
			goldenName := name
			if target == "nginx" {
				goldenName = strings.TrimPrefix(name, "crawlledger-")
				goldenName = "nginx-" + goldenName
			}
			path := filepath.Join("..", "..", "testdata", "golden", goldenName)
			if *updateGoldens {
				if err := os.WriteFile(path, artifacts[index].Content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(artifacts[index].Content, want) {
				t.Fatalf("%s differs from golden; run go test ./internal/render -update", name)
			}
		}
	}
}

func TestRenderSafetyBoundaries(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	risk := domain.Risk{ID: "risk", Acknowledgeable: true}
	simulation := domain.Simulation{
		AnalysisID: "an_0123456789abcdef0123456789abcdef",
		Status:     domain.SimulationRequiresAck,
		Risks:      []domain.Risk{risk},
	}
	input := Input{
		AnalysisID: simulation.AnalysisID, Simulation: simulation, Catalog: catalogValue,
		Policy: policyWithAction(domain.ActionDeny, nil),
	}
	setPolicyHash(t, &input)
	nginx, _ := New("nginx")
	if err := nginx.Validate(input); err == nil {
		t.Fatal("missing acknowledgement accepted")
	}
	input.Acks = []string{"risk"}
	input.Simulation.PolicyHash = strings.Repeat("a", 64)
	if err := nginx.Validate(input); err == nil {
		t.Fatal("policy hash mismatch accepted")
	}
	setPolicyHash(t, &input)
	input.Policy = policyWithAction(domain.ActionCache, nil)
	setPolicyHash(t, &input)
	if err := nginx.Validate(input); err == nil {
		t.Fatal("cache action rendered")
	}
	profile := "standard"
	input.Policy = policyWithAction(domain.ActionRateLimit, &profile)
	setPolicyHash(t, &input)
	caddy, _ := New("caddy")
	if err := caddy.Validate(input); err == nil {
		t.Fatal("Caddy rate action rendered")
	}

	input.Policy = domain.Policy{Rules: make([]domain.PolicyRule, 67)}
	for index := range input.Policy.Rules {
		input.Policy.Rules[index] = domain.PolicyRule{
			ID: "deny",
			Match: domain.PolicyMatch{
				CrawlerNames: []string{}, Categories: []domain.TrafficClass{},
				PathPrefixes: []string{"/a", "/b", "/c"}, Methods: []string{},
			},
			Action: domain.PolicyAction{Kind: domain.ActionDeny},
		}
	}
	setPolicyHash(t, &input)
	if err := nginx.Validate(input); err == nil {
		t.Fatal("201 Nginx matcher clauses accepted")
	}
}

func TestCaddyEscapesPolicyRegex(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	value := domain.Policy{Rules: []domain.PolicyRule{{
		ID: "quoted-path",
		Match: domain.PolicyMatch{
			CrawlerNames: []string{}, Categories: []domain.TrafficClass{},
			PathPrefixes: []string{`/say"hi`}, Methods: []string{},
		},
		Action: domain.PolicyAction{Kind: domain.ActionDeny},
	}}}
	input := Input{
		AnalysisID: "an_0123456789abcdef0123456789abcdef",
		Catalog:    catalogValue,
		Simulation: domain.Simulation{
			AnalysisID: "an_0123456789abcdef0123456789abcdef",
			Status:     domain.SimulationSafe, Risks: []domain.Risk{},
		},
		Policy: value,
	}
	setPolicyHash(t, &input)
	artifacts, err := (caddyRenderer{}).Render(input)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(artifacts[0].Content, []byte(`say\"hi`)) {
		t.Fatalf("quoted path was not escaped:\n%s", artifacts[0].Content)
	}
}

func TestRenderersPreserveLongestCatalogMatch(t *testing.T) {
	catalogValue, err := catalog.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	simulation := domain.Simulation{
		AnalysisID: "an_0123456789abcdef0123456789abcdef",
		Status:     domain.SimulationSafe, Risks: []domain.Risk{},
	}
	input := Input{
		AnalysisID: simulation.AnalysisID, Simulation: simulation, Catalog: catalogValue,
		Policy: policyWithAction(domain.ActionDeny, nil),
	}
	setPolicyHash(t, &input)
	nginxArtifacts, err := (nginxRenderer{}).Render(input)
	if err != nil {
		t.Fatal(err)
	}
	nginxConfig := string(nginxArtifacts[0].Content)
	if google, gpt := strings.Index(nginxConfig, `"Googlebot"`), strings.Index(nginxConfig, `"GPTBot"`); google < 0 || gpt < 0 || google > gpt {
		t.Fatal("Nginx catalog map does not preserve longest-token ordering")
	}
	caddyArtifacts, err := (caddyRenderer{}).Render(input)
	if err != nil {
		t.Fatal(err)
	}
	caddyConfig := string(caddyArtifacts[0].Content)
	if !strings.Contains(caddyConfig, "map {http.request.header.User-Agent} {crawlledger_crawler}") ||
		!strings.Contains(caddyConfig, `vars {crawlledger_crawler} "GPTBot"`) ||
		strings.Contains(caddyConfig, "header_regexp User-Agent") {
		t.Fatalf("Caddy renderer bypasses catalog classification:\n%s", caddyConfig)
	}
}

func policyWithAction(action domain.ActionKind, profile *string) domain.Policy {
	return domain.Policy{Rules: []domain.PolicyRule{{
		ID: "synthetic", Match: domain.PolicyMatch{
			CrawlerNames: []string{"GPTBot"}, Categories: []domain.TrafficClass{},
			PathPrefixes: []string{}, Methods: []string{},
		},
		Action: domain.PolicyAction{Kind: action, RateProfile: profile},
	}}}
}

func setPolicyHash(t *testing.T, input *Input) {
	t.Helper()
	_, hash, err := policy.Canonical(input.Policy)
	if err != nil {
		t.Fatal(err)
	}
	input.Simulation.PolicyHash = hash
}
