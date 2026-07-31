package protect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCommandExecutorRejectsTruncatedOutputAndTimeout(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executor := CommandExecutor{Timeout: time.Second, OutputLimit: 8}
	output, err := executor.Run(
		context.Background(),
		executable,
		"-test.run=TestCommandHelperProcess",
		"--",
		"output",
	)
	if err == nil || string(output) != "12345678" {
		t.Fatalf("truncated output was accepted: output=%q err=%v", output, err)
	}
	executor.Timeout = 10 * time.Millisecond
	_, err = executor.Run(
		context.Background(),
		executable,
		"-test.run=TestCommandHelperProcess",
		"--",
		"sleep",
	)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout returned %v", err)
	}
}

func TestApplyActiveMapValidatesAndReloadsAnUnchangedMap(t *testing.T) {
	config, directory := mutationTestConfig(t)
	desired, err := RenderActiveMap(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, activeMapName), desired, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := [][]string{}
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), arguments...))
		if arguments[0] == "-T" {
			return validPreflight(config), nil
		}
		return nil, nil
	}
	if err := ApplyActiveMap(context.Background(), config, nil, execute); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-T", "-c", config.Nginx.ConfigPath},
		{"-t", "-c", config.Nginx.ConfigPath},
		{"-s", "reload", "-c", config.Nginx.ConfigPath},
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("unchanged startup calls = %#v, want %#v", calls, want)
	}
}

func TestCommandHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	switch os.Args[separator+1] {
	case "output":
		_, _ = fmt.Fprint(os.Stdout, "1234567890")
	case "sleep":
		time.Sleep(time.Second)
	}
}

func TestApplyActiveMapSuccess(t *testing.T) {
	config, directory := mutationTestConfig(t)
	oldMap := []byte("# CrawlLedger active map v1 site=example\n")
	if err := os.WriteFile(filepath.Join(directory, activeMapName), oldMap, 0o644); err != nil {
		t.Fatal(err)
	}
	calls := [][]string{}
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), arguments...))
		if len(arguments) > 0 && arguments[0] == "-T" {
			return validPreflight(config), nil
		}
		return nil, nil
	}
	rules := []ApplyRule{{Method: "POST", PathPrefix: "/api/search"}}
	if err := ApplyActiveMap(context.Background(), config, rules, execute); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, activeMapName))
	if err != nil {
		t.Fatal(err)
	}
	expected, err := RenderActiveMap(config, rules)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, expected) {
		t.Fatalf("active map = %q, want %q", data, expected)
	}
	wantCalls := [][]string{
		{"-T", "-c", config.Nginx.ConfigPath},
		{"-t", "-c", config.Nginx.ConfigPath},
		{"-s", "reload", "-c", config.Nginx.ConfigPath},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("commands = %#v, want %#v", calls, wantCalls)
	}
}

func TestApplyActiveMapRollsBackValidationFailure(t *testing.T) {
	config, directory := mutationTestConfig(t)
	oldMap := []byte("# CrawlLedger active map v1 site=example\n")
	path := filepath.Join(directory, activeMapName)
	if err := os.WriteFile(path, oldMap, 0o644); err != nil {
		t.Fatal(err)
	}
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if arguments[0] == "-T" {
			return validPreflight(config), nil
		}
		if arguments[0] == "-t" {
			return nil, errors.New("synthetic validation failure")
		}
		return nil, errors.New("reload must not run")
	}
	err := ApplyActiveMap(
		context.Background(),
		config,
		[]ApplyRule{{Method: "POST", PathPrefix: "/api/search"}},
		execute,
	)
	if err == nil || IsRollbackFailure(err) {
		t.Fatalf("unexpected apply error: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !reflect.DeepEqual(data, oldMap) {
		t.Fatalf("validation rollback failed: %q %v", data, readErr)
	}
}

func TestApplyActiveMapRollsBackReloadFailure(t *testing.T) {
	config, directory := mutationTestConfig(t)
	oldMap := []byte("# CrawlLedger active map v1 site=example\n")
	path := filepath.Join(directory, activeMapName)
	if err := os.WriteFile(path, oldMap, 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		switch arguments[0] {
		case "-T":
			return validPreflight(config), nil
		case "-t":
			return nil, nil
		case "-s":
			reloads++
			if reloads == 1 {
				return nil, errors.New("synthetic reload failure")
			}
			return nil, nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	err := ApplyActiveMap(
		context.Background(),
		config,
		[]ApplyRule{{Method: "POST", PathPrefix: "/api/search"}},
		execute,
	)
	if err == nil || IsRollbackFailure(err) {
		t.Fatalf("unexpected reload error: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !reflect.DeepEqual(data, oldMap) || reloads != 2 {
		t.Fatalf("reload rollback failed: map=%q reloads=%d err=%v", data, reloads, readErr)
	}
}

func TestApplyActiveMapReportsRollbackFailure(t *testing.T) {
	config, directory := mutationTestConfig(t)
	path := filepath.Join(directory, activeMapName)
	if err := os.WriteFile(path, []byte("previous\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tests := 0
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		if arguments[0] == "-T" {
			return validPreflight(config), nil
		}
		if arguments[0] == "-t" {
			tests++
			if tests > 1 {
				return nil, errors.New("rollback validation failure")
			}
			return nil, nil
		}
		return nil, errors.New("reload failure")
	}
	err := ApplyActiveMap(
		context.Background(),
		config,
		[]ApplyRule{{Method: "POST", PathPrefix: "/api/search"}},
		execute,
	)
	if !IsRollbackFailure(err) {
		t.Fatalf("rollback failure not classified: %v", err)
	}
}

func TestApplyActiveMapRollsBackAfterCallerCancellation(t *testing.T) {
	config, directory := mutationTestConfig(t)
	oldMap := []byte("# CrawlLedger active map v1 site=example\n")
	path := filepath.Join(directory, activeMapName)
	if err := os.WriteFile(path, oldMap, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reloads := 0
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		switch arguments[0] {
		case "-T":
			return validPreflight(config), nil
		case "-t":
			return nil, nil
		case "-s":
			reloads++
			if reloads == 1 {
				cancel()
				return nil, context.Canceled
			}
			return nil, nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	err := ApplyActiveMap(
		ctx,
		config,
		[]ApplyRule{{Method: "POST", PathPrefix: "/api/search"}},
		execute,
	)
	if err == nil || IsRollbackFailure(err) {
		t.Fatalf("canceled apply was not safely rolled back: %v", err)
	}
	data, readErr := os.ReadFile(path)
	if readErr != nil || !reflect.DeepEqual(data, oldMap) || reloads != 2 {
		t.Fatalf("canceled rollback failed: map=%q reloads=%d err=%v", data, reloads, readErr)
	}
}

func TestValidateNginxPreflightRequiresEachMarkerExactlyOnce(t *testing.T) {
	config := nginxTestConfig()
	if err := ValidateNginxPreflight(validPreflight(config), config); err != nil {
		t.Fatal(err)
	}
	duplicated := append(validPreflight(config), []byte(HTTPMarker(config.Site))...)
	if err := ValidateNginxPreflight(duplicated, config); err == nil {
		t.Fatal("duplicate marker accepted")
	}
	missing := strings.Replace(string(validPreflight(config)), ServerMarker(config.Site), "", 1)
	if err := ValidateNginxPreflight([]byte(missing), config); err == nil {
		t.Fatal("missing marker accepted")
	}
}

func TestValidateApplyRequestBindsPayloadToPersistedState(t *testing.T) {
	config := nginxTestConfig()
	baseline := digestB
	state := State{
		SchemaVersion:          1,
		Site:                   config.Site,
		ConfigSHA256:           digestA,
		BaselineManifestSHA256: &baseline,
		Rules: []Rule{{
			Method: "POST", PathPrefix: "/api/search", Reasons: []string{"extreme-volume"},
			RequestThreshold: 1000, FirstQualifiedAtUS: 1, LastQualifiedAtUS: 2, ExpiresAtUS: 3,
		}},
	}
	payload, err := ProjectState(state)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := ValidateApplyRequest(config, digestA, state, append([]byte(" \n"), payload...))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules, []ApplyRule{{Method: "POST", PathPrefix: "/api/search"}}) {
		t.Fatalf("rules = %#v", rules)
	}
	wrongPayload := []byte(`{"schema_version":1,"site":"example","rules":[]}`)
	if _, err := ValidateApplyRequest(config, digestA, state, wrongPayload); err == nil {
		t.Fatal("state/payload mismatch accepted")
	}
	if _, err := ValidateApplyRequest(config, digestB, state, payload); err == nil {
		t.Fatal("config digest mismatch accepted")
	}
	state.Rules[0].PathPrefix = "/health"
	if _, err := ValidateApplyRequest(config, digestA, state, payload); err == nil {
		t.Fatal("excluded persisted action accepted")
	}
}

func TestSetupManagedFilesRendersAndReportsMissingIncludes(t *testing.T) {
	config, directory := mutationTestConfig(t)
	calls := [][]string{}
	execute := func(_ context.Context, _ string, arguments ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), arguments...))
		return nil, nil
	}
	result, err := SetupManagedFiles(context.Background(), config, execute)
	if err != nil {
		t.Fatal(err)
	}
	if result.HTTPIncluded || result.ServerIncluded || result.ActiveIncluded {
		t.Fatalf("missing includes reported present: %#v", result)
	}
	for _, name := range []string{httpIncludeName, serverIncludeName, activeMapName} {
		if _, err := os.Stat(filepath.Join(directory, name)); err != nil {
			t.Fatalf("managed file %s is missing: %v", name, err)
		}
	}
	wantCalls := [][]string{
		{"-T", "-c", config.Nginx.ConfigPath},
		{"-t", "-c", config.Nginx.ConfigPath},
		{"-s", "reload", "-c", config.Nginx.ConfigPath},
	}
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("setup commands = %#v, want %#v", calls, wantCalls)
	}
}

func TestSetupManagedFilesRejectsNonemptyMapBeforeWriting(t *testing.T) {
	config, directory := mutationTestConfig(t)
	path := filepath.Join(directory, activeMapName)
	if err := os.WriteFile(path, []byte("nonempty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	called := false
	_, err := SetupManagedFiles(context.Background(), config, func(
		context.Context,
		string,
		...string,
	) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err == nil || called {
		t.Fatalf("nonempty setup state was mutated: called=%t err=%v", called, err)
	}
	if _, err := os.Stat(filepath.Join(directory, httpIncludeName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("setup wrote HTTP include before rejecting active map")
	}
}

func TestInvokePrivilegedApplyUsesExactArgumentsAndProjection(t *testing.T) {
	directory := t.TempDir()
	executable := filepath.Join(directory, "crawlledger")
	configPath := filepath.Join(directory, "protect.json")
	baseline := digestB
	state := State{
		SchemaVersion: 1, Site: "example", ConfigSHA256: digestA,
		BaselineManifestSHA256: &baseline,
		Rules: []Rule{{
			Method: "POST", PathPrefix: "/api/search", Reasons: []string{"distributed-expense"},
			RequestThreshold: 1000, FirstQualifiedAtUS: 1, LastQualifiedAtUS: 2, ExpiresAtUS: 3,
		}},
	}
	var gotArguments []string
	var gotStdin []byte
	err := invokePrivilegedApply(
		context.Background(),
		executable,
		configPath,
		state,
		func(_ context.Context, arguments []string, stdin []byte) error {
			gotArguments = append([]string(nil), arguments...)
			gotStdin = append([]byte(nil), stdin...)
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	wantArguments := []string{
		"-n", executable, "protect", "apply", "--config", configPath,
	}
	wantStdin, err := ProjectState(state)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotArguments, wantArguments) || !reflect.DeepEqual(gotStdin, wantStdin) {
		t.Fatalf("privileged invocation: args=%#v stdin=%q", gotArguments, gotStdin)
	}
}

func mutationTestConfig(t *testing.T) (Config, string) {
	t.Helper()
	directory := t.TempDir()
	config := nginxTestConfig()
	config.Nginx.Binary = filepath.Join(directory, "nginx")
	config.Nginx.ConfigPath = filepath.Join(directory, "nginx.conf")
	config.Nginx.ManagedDir = directory
	return config, directory
}

func validPreflight(config Config) []byte {
	return []byte(strings.Join([]string{
		HTTPMarker(config.Site), ServerMarker(config.Site), ActiveMarker(config.Site), "",
	}, "\n"))
}
