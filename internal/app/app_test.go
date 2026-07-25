package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/apperr"
	"github.com/balyakin/crawlledger/internal/logging"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/policy"
	"github.com/balyakin/crawlledger/internal/version"
)

func TestAnalyzeAndSanitize(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	line := `192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /archive?page=SECRET_TOKEN HTTP/1.1" 200 1234 "-" "Googlebot GPTBot"` + "\n"
	if err := os.WriteFile(logPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	service := New(bytes.NewReader(nil), logging.NewJSON(&logs, slog.LevelInfo), version.Info{Version: "test"})
	workspace := filepath.Join(dir, "audit")
	result, err := service.Analyze(context.Background(), AnalyzeRequest{
		Inputs: []string{logPath}, Format: parser.FormatNginxCombined, OutputDir: workspace,
	})
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	if result.Accepted != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	for _, name := range []string{"analysis.sqlite", "report.json", "report.html", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(workspace, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}
	reportData, err := os.ReadFile(result.ReportJSON)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(reportData), "SECRET_TOKEN") || strings.Contains(string(reportData), "192.0.2.10") {
		t.Fatal("raw data leaked into report")
	}
	var decoded map[string]any
	if err := json.Unmarshal(reportData, &decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(reportData, []byte(`"ambiguous_user_agent_observed"`)) {
		t.Fatal("multi-token User-Agent warning missing from report")
	}

	evidence := filepath.Join(dir, "evidence")
	sanitized, err := service.Sanitize(context.Background(), SanitizeRequest{
		Inputs: []string{logPath}, Format: parser.FormatNginxCombined, OutputDir: evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if sanitized.Accepted != 1 {
		t.Fatalf("unexpected sanitized result: %#v", sanitized)
	}
	manifestData, err := os.ReadFile(sanitized.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifestData, []byte(`"ambiguous_user_agent_observed"`)) {
		t.Fatal("multi-token User-Agent warning missing from sanitized manifest")
	}
	tamperedManifest := filepath.Join(dir, "tampered.manifest.json")
	manifestData = bytes.Replace(manifestData,
		[]byte(`"raw_lines_retained":false`), []byte(`"raw_lines_retained":true`), 1)
	if err := os.WriteFile(tamperedManifest, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSanitizedManifest(tamperedManifest); err == nil {
		t.Fatal("manifest claiming retained raw lines was accepted")
	}
	assertNoCanaries(t, []string{workspace, evidence}, "SECRET_TOKEN", "192.0.2.10")
}

func assertNoCanaries(t *testing.T, roots []string, canaries ...string) {
	t.Helper()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, canary := range canaries {
				if bytes.Contains(data, []byte(canary)) {
					t.Fatalf("privacy canary survived in %s", path)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestParseThreshold(t *testing.T) {
	if parseLimitExceeded(100, 100, false) || !parseLimitExceeded(101, 101, false) {
		t.Fatal("early absolute threshold boundary failed")
	}
	if parseLimitExceeded(100000, 100, true) || !parseLimitExceeded(100000, 101, true) {
		t.Fatal("final threshold boundary failed")
	}
	if parseLimitExceeded(1000001, 50001, false) || !parseLimitExceeded(1000001, 50002, false) {
		t.Fatal("ppm threshold rounding boundary failed")
	}
	finalLimit := int64(math.MaxInt64 / 1000)
	if parseLimitExceeded(math.MaxInt64, finalLimit, true) ||
		!parseLimitExceeded(math.MaxInt64, finalLimit+1, true) {
		t.Fatal("large final threshold overflowed")
	}
}

func TestSanitizeRejectsRemoteRobots(t *testing.T) {
	service := New(bytes.NewReader(nil), nil, version.Info{Version: "test"})
	_, err := service.Sanitize(context.Background(), SanitizeRequest{
		Inputs: []string{"unused.log"}, Format: parser.FormatNginxCombined,
		OutputDir: "unused-output", RobotsPath: "https://example.test/robots.txt",
	})
	if got := apperr.UserMessage(err); got != "sanitize: robots must be a local file" {
		t.Fatalf("unexpected error: %q", got)
	}
}

func TestManifestKeysRejectNullScalars(t *testing.T) {
	data := []byte(`{"schema_version":1,"analysis_id":"an_0123456789abcdef0123456789abcdef","tool_version":"test","catalog_version":"2026-07-24","status":"completed","artifacts":[],"privacy":{"raw_lines_retained":null,"hmac_key_retained":false,"anonymous":false,"residual_risks":[]}}`)
	if err := requireWorkspaceManifestKeys(data); err == nil {
		t.Fatal("null workspace privacy field accepted")
	}
}

func TestEnsureOutsideWorkspaceResolvesSymlinksWithMixedPaths(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "workspace-alias")
	if err := os.Symlink(workspace, alias); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Chdir(root)
	relativeWorkspace := filepath.Base(workspace)
	if err := ensureOutsideWorkspace(filepath.Join(alias, "simulation.json"), relativeWorkspace); err == nil {
		t.Fatal("absolute output through a symlink bypassed a relative workspace")
	}
}

func TestSimulateAndRender(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "access.log")
	if err := os.WriteFile(logPath, []byte(
		`192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /archive HTTP/1.1" 200 1234 "-" "GPTBot/1.0"`+"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	service := New(bytes.NewReader(nil), nil, version.Info{Version: "test"})
	workspace := filepath.Join(dir, "audit")
	if _, err := service.Analyze(context.Background(), AnalyzeRequest{
		Inputs: []string{logPath}, Format: parser.FormatNginxCombined, OutputDir: workspace,
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshotWorkspace(t, workspace)
	policyPath := filepath.Join(dir, "policy.json")
	policyJSON := `{"schema_version":1,"name":"deny-gptbot","description":"synthetic","rules":[{"id":"deny-gptbot","match":{"crawler_names":["GPTBot"],"categories":[],"path_prefixes":[],"methods":[]},"action":{"kind":"deny","rate_profile":null,"cache_ttl_seconds":null}}]}`
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	simulationPath := filepath.Join(dir, "simulation.json")
	simulated, err := service.Simulate(context.Background(), SimulateRequest{
		Workspace: workspace, Policy: policyPath, Output: simulationPath,
	})
	if err != nil {
		t.Fatalf("%v: %v", err, errors.Unwrap(err))
	}
	if after := snapshotWorkspace(t, workspace); !reflect.DeepEqual(before, after) {
		t.Fatal("simulation mutated workspace")
	}
	simulation, _, err := policy.LoadSimulation(simulationPath)
	if err != nil {
		t.Fatal(err)
	}
	if after := snapshotWorkspace(t, workspace); !reflect.DeepEqual(before, after) {
		t.Fatal("render mutated workspace")
	}
	acks := make([]string, 0)
	for _, risk := range simulation.Risks {
		if risk.Acknowledgeable {
			acks = append(acks, risk.ID)
		}
	}
	rendered, err := service.Render(context.Background(), RenderRequest{
		Workspace: workspace, Policy: policyPath, Simulation: simulationPath,
		Target: "caddy", OutputDir: filepath.Join(dir, "rendered"), Acks: acks,
	})
	if err != nil {
		t.Fatal(err)
	}
	if simulated.RunID == "" || rendered.Files != 1 {
		t.Fatalf("unexpected results: %#v %#v", simulated, rendered)
	}
	for _, name := range []string{"Caddyfile.crawlledger", "MANIFEST.json"} {
		if _, err := os.Stat(filepath.Join(rendered.Output, name)); err != nil {
			t.Fatalf("%s missing: %v", name, err)
		}
	}

	sidecarData, err := os.ReadFile(simulationPath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSimulation := filepath.Join(dir, "tampered-simulation.json")
	if err := os.WriteFile(tamperedSimulation, append(sidecarData, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedOutput := filepath.Join(dir, "tampered-render")
	_, err = service.Render(context.Background(), RenderRequest{
		Workspace: workspace, Policy: policyPath, Simulation: tamperedSimulation,
		Target: "caddy", OutputDir: tamperedOutput, Acks: acks,
	})
	if apperr.ExitCode(err) != 5 {
		t.Fatalf("tampered simulation exit code = %d: %v", apperr.ExitCode(err), err)
	}
	if _, statErr := os.Stat(filepath.Join(tamperedOutput, "MANIFEST.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("tampered simulation published a manifest")
	}

	changedPolicy := filepath.Join(dir, "changed-policy.json")
	if err := os.WriteFile(changedPolicy, []byte(strings.Replace(policyJSON, "GPTBot", "Googlebot", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	changedPolicyOutput := filepath.Join(dir, "changed-policy-render")
	_, err = service.Render(context.Background(), RenderRequest{
		Workspace: workspace, Policy: changedPolicy, Simulation: simulationPath,
		Target: "caddy", OutputDir: changedPolicyOutput, Acks: acks,
	})
	if apperr.ExitCode(err) != 5 {
		t.Fatalf("changed policy exit code = %d: %v", apperr.ExitCode(err), err)
	}
	if _, statErr := os.Stat(filepath.Join(changedPolicyOutput, "MANIFEST.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("changed policy published a manifest")
	}

	reportPath := filepath.Join(workspace, "report.json")
	reportBytes, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, append(reportBytes, ' '), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedWorkspaceOutput := filepath.Join(dir, "tampered-workspace-simulation.json")
	_, err = service.Simulate(context.Background(), SimulateRequest{
		Workspace: workspace, Policy: policyPath, Output: tamperedWorkspaceOutput,
	})
	if apperr.ExitCode(err) != 5 {
		t.Fatalf("tampered workspace exit code = %d: %v", apperr.ExitCode(err), err)
	}
	if _, statErr := os.Stat(tamperedWorkspaceOutput); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("tampered workspace published a simulation")
	}
}

func snapshotWorkspace(t *testing.T, root string) map[string]string {
	t.Helper()
	result := make(map[string]string)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = string(data)
	}
	return result
}
