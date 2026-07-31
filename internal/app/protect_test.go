package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/balyakin/crawlledger/internal/logging"
	"github.com/balyakin/crawlledger/internal/parser"
	"github.com/balyakin/crawlledger/internal/protect"
	"github.com/balyakin/crawlledger/internal/version"
)

func TestProtectRunDryRunNeverTouchesMutationPaths(t *testing.T) {
	directory := t.TempDir()
	workspace := filepath.Join(directory, "baseline")
	service := New(bytes.NewReader(nil), slog.New(slog.DiscardHandler), version.Current())
	_, err := service.Analyze(context.Background(), AnalyzeRequest{
		Inputs: []string{filepath.Join("..", "..", "testdata", "logs", "nginx-json", "valid.jsonl")},
		Format: parser.FormatNginxJSON, OutputDir: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(directory, "live.jsonl")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(directory, "missing-state-directory", "state.json")
	configPath := writeProtectionConfig(t, protect.Config{
		SchemaVersion:     1,
		Site:              "example",
		LogPath:           logPath,
		BaselineWorkspace: workspace,
		Nginx: protect.NginxConfig{
			Binary:     filepath.Join(directory, "missing-nginx"),
			ConfigPath: filepath.Join(directory, "missing-nginx.conf"),
			ManagedDir: filepath.Join(directory, "missing-managed"),
		},
		Runtime: protect.RuntimeConfig{StateFile: statePath, MaxLogLineBytes: 4096},
		Detection: protect.Detection{
			WindowSeconds: 10, EvaluationIntervalSeconds: 1, RequiredConsecutiveEvaluations: 1,
			MaxEventLagSeconds: 30, BaselineMultiplier: 2, VolumeMinRequests: 1,
			VolumeMinSiteSharePPM: 1, DistributedMinRequests: 1, DistributedMinClients: 1,
			DistributedMinClientRatioPPM: 1, DistributedMinUpstreamCoveragePPM: 1,
			DistributedMinUpstreamUS: 1, DistributedMinAverageUpstreamUS: 1, MaxTrackedGroups: 100,
		},
		Action: protect.Action{
			TTLSeconds: 60, RateRequestsPerSecond: 1, Burst: 0, MaxActiveRules: 1,
			MinReloadIntervalSeconds: 1,
		},
		Exclusions: protect.Exclusions{Methods: []string{}, PathPrefixes: []string{}},
		StaticDeny: protect.StaticDeny{Enabled: []string{}},
	})
	var logs bytes.Buffer
	service = New(bytes.NewReader(nil), logging.NewJSON(&logs, slog.LevelInfo), version.Current())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, runErr := service.ProtectRun(ctx, ProtectRunRequest{ConfigPath: configPath})
		done <- runErr
	}()
	time.Sleep(50 * time.Millisecond)
	line, err := json.Marshal(map[string]string{
		"timestamp":              time.Now().UTC().Format(time.RFC3339Nano),
		"remote_addr":            "192.0.2.99",
		"method":                 "GET",
		"uri":                    "/api?token=SYNTHETIC_QUERY_SECRET",
		"nginx_uri":              "/api",
		"status":                 "200",
		"limit_req_status":       "PASSED",
		"bytes_sent":             "1",
		"request_time":           "0.100",
		"upstream_response_time": "0.090",
		"upstream_cache_status":  "MISS",
		"user_agent":             "SYNTHETIC_UA_SECRET",
		"referer":                "https://secret.example/private/path",
	})
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')
	if err := os.WriteFile(logPath, line, 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful dry-run stop returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dry run did not stop")
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("dry run created persistent state")
	}
	logText := logs.String()
	if !bytes.Contains(logs.Bytes(), []byte(`"event":"protect_candidate"`)) {
		t.Fatalf("dry run did not emit a candidate: %s", logText)
	}
	for _, field := range []string{`"apply_status":"dry-run"`, `"baseline_requests":`, `"max_event_lag_us":`,
		`"rejected_record_content":`} {
		if !bytes.Contains(logs.Bytes(), []byte(field)) {
			t.Fatalf("structured protection evidence is missing %s: %s", field, logText)
		}
	}
	for _, secret := range []string{
		"192.0.2.99", "SYNTHETIC_QUERY_SECRET", "SYNTHETIC_UA_SECRET", "secret.example", string(line),
	} {
		if bytes.Contains(logs.Bytes(), []byte(secret)) {
			t.Fatalf("structured protection event leaked %q: %s", secret, logText)
		}
	}
}

func writeProtectionConfig(t *testing.T, config protect.Config) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "protect.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReconcileLiveStateClearsChangedDigestBeforeApply(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "state.json")
	oldConfigDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	currentConfigDigest := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	baselineDigest := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	nowUS := time.Now().UTC().UnixMicro()
	oldBaseline := baselineDigest
	oldState := protect.State{
		SchemaVersion: 1, Site: "example", ConfigSHA256: oldConfigDigest,
		BaselineManifestSHA256: &oldBaseline,
		Rules: []protect.Rule{{
			Method: "POST", PathPrefix: "/api", Reasons: []string{"extreme-volume"},
			RequestThreshold: 10, FirstQualifiedAtUS: nowUS - 2, LastQualifiedAtUS: nowUS - 1,
			ExpiresAtUS: nowUS + 60_000_000,
		}},
	}
	if err := protect.WriteState(context.Background(), statePath, oldState); err != nil {
		t.Fatal(err)
	}
	loaded := protect.LoadedConfig{
		Config: protect.Config{Site: "example", Runtime: protect.RuntimeConfig{StateFile: statePath}},
		Path:   "/etc/crawlledger/protect.json", SHA256: currentConfigDigest,
	}
	baseline := protect.Baseline{ManifestSHA256: baselineDigest}
	var applied protect.State
	state, err := reconcileLiveStateWith(
		context.Background(),
		loaded,
		baseline,
		"/usr/local/sbin/crawlledger",
		func(_ context.Context, _, _ string, desired protect.State) error {
			applied = desired
			persisted, exists, readErr := protect.ReadState(statePath)
			if readErr != nil || !exists || len(persisted.Rules) != 0 {
				return errors.New("desired clear was not persisted before apply")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Rules) != 0 || len(applied.Rules) != 0 || state.ConfigSHA256 != currentConfigDigest {
		t.Fatalf("changed digest was not cleared: state=%#v applied=%#v", state, applied)
	}
	if err := protect.WriteState(context.Background(), statePath, oldState); err != nil {
		t.Fatal(err)
	}
	_, err = reconcileLiveStateWith(
		context.Background(),
		loaded,
		baseline,
		"/usr/local/sbin/crawlledger",
		func(context.Context, string, string, protect.State) error {
			return errors.New("synthetic clear failure")
		},
	)
	if err == nil {
		t.Fatal("failed digest clear did not block startup")
	}
}
