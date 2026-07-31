package protect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func TestStateProjectionIsCanonical(t *testing.T) {
	baseline := digestB
	state := State{
		SchemaVersion:          1,
		Site:                   "example",
		ConfigSHA256:           digestA,
		BaselineManifestSHA256: &baseline,
		Rules: []Rule{{
			Method: "POST", PathPrefix: "/api/search", Reasons: []string{"distributed-expense"},
			RequestThreshold: 1000, FirstQualifiedAtUS: 1785430800000000,
			LastQualifiedAtUS: 1785430860000000, ExpiresAtUS: 1785431460000000,
		}},
	}

	encoded, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeState(encoded)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ProjectState(decoded)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"schema_version\":1,\"site\":\"example\",\"rules\":[{\"method\":\"POST\",\"path_prefix\":\"/api/search\"}]}\n"
	if string(payload) != want {
		t.Fatalf("payload = %q", payload)
	}
	canonical, err := DecodeApplyPayload(append([]byte(" \n"), payload...))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canonical, payload) {
		t.Fatalf("canonical payload = %q", canonical)
	}
}

func TestStateRejectsBrokenInvariants(t *testing.T) {
	valid := `{"schema_version":1,"site":"example","config_sha256":"` + digestA + `","baseline_manifest_sha256":"` + digestB + `","rules":[{"method":"POST","path_prefix":"/api/search","reasons":["distributed-expense"],"request_threshold":1000,"first_qualified_at_us":1785430800000000,"last_qualified_at_us":1785430860000000,"expires_at_us":1785431460000000}]}`
	tests := map[string]string{
		"unknown":                  strings.Replace(valid, `"site":"example"`, `"site":"example","extra":1`, 1),
		"duplicate":                strings.Replace(valid, `"site":"example"`, `"site":"example","site":"again"`, 1),
		"null baseline with rules": strings.Replace(valid, `"`+digestB+`"`, `null`, 1),
		"bad timestamp":            strings.Replace(valid, `1785431460000000`, `1785430860000000`, 1),
		"bad reason":               strings.Replace(valid, `distributed-expense`, `other`, 1),
		"duplicate reason":         strings.Replace(valid, `"distributed-expense"`, `"distributed-expense","distributed-expense"`, 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeState([]byte(data)); err == nil {
				t.Fatal("invalid state accepted")
			}
		})
	}
}

func TestEmptyStateAllowsNullBaseline(t *testing.T) {
	data := []byte(`{"schema_version":1,"site":"example","config_sha256":"` + digestA + `","baseline_manifest_sha256":null,"rules":[]}`)
	state, err := DecodeState(data)
	if err != nil {
		t.Fatal(err)
	}
	if state.BaselineManifestSHA256 != nil || len(state.Rules) != 0 {
		t.Fatalf("unexpected empty state: %#v", state)
	}
}

func TestStateAndApplyPayloadRejectRuleCountAboveGlobalCap(t *testing.T) {
	baseline := digestB
	rules := make([]Rule, 129)
	applyRules := make([]ApplyRule, 129)
	for index := range rules {
		pathPrefix := fmt.Sprintf("/route-%03d", index)
		rules[index] = Rule{
			Method: "GET", PathPrefix: pathPrefix, Reasons: []string{"extreme-volume"},
			RequestThreshold: 1, FirstQualifiedAtUS: 1, LastQualifiedAtUS: 2, ExpiresAtUS: 3,
		}
		applyRules[index] = ApplyRule{Method: "GET", PathPrefix: pathPrefix}
	}
	state := State{
		SchemaVersion: 1, Site: "example", ConfigSHA256: digestA,
		BaselineManifestSHA256: &baseline, Rules: rules,
	}
	if err := state.Validate(); err == nil {
		t.Fatal("state above the global rule cap was accepted")
	}
	payload := ApplyPayload{SchemaVersion: 1, Site: "example", Rules: applyRules}
	if err := payload.Validate(); err == nil {
		t.Fatal("apply payload above the global rule cap was accepted")
	}
}

func TestStateAndApplyPayloadRejectOversizedDocuments(t *testing.T) {
	if _, err := DecodeState(make([]byte, maxStateBytes+1)); err == nil {
		t.Fatal("oversized state was accepted")
	}
	if _, err := DecodeApplyPayload(make([]byte, maxApplyBytes+1)); err == nil {
		t.Fatal("oversized apply payload was accepted")
	}
}

func TestReadWriteStateUsesBoundedAtomicPrivateFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	if _, exists, err := ReadState(path); err != nil || exists {
		t.Fatalf("missing state: exists=%t err=%v", exists, err)
	}
	baseline := digestB
	state := State{
		SchemaVersion: 1, Site: "example", ConfigSHA256: digestA,
		BaselineManifestSHA256: &baseline, Rules: []Rule{},
	}
	if err := WriteState(context.Background(), path, state); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := ReadState(path)
	if err != nil || !exists {
		t.Fatalf("read state: exists=%t err=%v", exists, err)
	}
	encoded, err := EncodeState(loaded)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, want) {
		t.Fatalf("state changed: %q, want %q", encoded, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}
}

func TestReadStateRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is not generally available")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	path := filepath.Join(directory, "state.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadState(path); err == nil {
		t.Fatal("state symlink accepted")
	}
}

func TestWriteStateCancellationPreservesOldState(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state.json")
	old := []byte(`{"old":true}`)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	state := State{
		SchemaVersion: 1, Site: "example", ConfigSHA256: digestA,
		BaselineManifestSHA256: nil, Rules: []Rule{},
	}
	if err := WriteState(ctx, path, state); !errors.Is(err, context.Canceled) {
		t.Fatalf("write returned %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(data, old) {
		t.Fatalf("canceled write changed state: %q %v", data, err)
	}
}
