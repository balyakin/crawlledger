package protect

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const validConfigJSONTemplate = `{
  "schema_version": 1,
  "site": "example",
  "log_path": "/var/log/nginx/access.crawlledger.json",
  "baseline_workspace": "/var/lib/crawlledger/example-baseline",
  "nginx": {
    "binary": "/usr/sbin/nginx",
    "config_path": "/etc/nginx/nginx.conf",
    "managed_dir": "/etc/nginx/crawlledger/example"
  },
  "runtime": {
    "state_file": "/var/lib/crawlledger/example/state.json",
    "max_log_line_bytes": 1048576
  },
  "detection": {
    "window_seconds": 60,
    "evaluation_interval_seconds": 10,
    "required_consecutive_evaluations": 2,
    "max_event_lag_seconds": 120,
    "baseline_multiplier": 10,
    "volume_min_requests": 1200,
    "volume_min_site_share_ppm": 500000,
    "distributed_min_requests": 1000,
    "distributed_min_clients": 500,
    "distributed_min_client_ratio_ppm": 500000,
    "distributed_min_upstream_coverage_ppm": 800000,
    "distributed_min_upstream_us": 120000000,
    "distributed_min_average_upstream_us": 250000,
    "max_tracked_groups": 10000
  },
  "action": {
    "ttl_seconds": 600,
    "rate_requests_per_second": 10,
    "burst": 20,
    "max_active_rules": 16,
    "min_reload_interval_seconds": 10
  },
  "exclusions": {
    "methods": [],
    "path_prefixes": []
  },
  "static_deny": {
    "enabled": [
      "env-file-scan",
      "git-metadata-scan",
      "path-traversal-scan",
      "log4shell-probe"
    ]
  }
}`

var validConfigJSON = makeValidConfigJSON(validConfigJSONTemplate)

func TestLoadConfigPreservesExactDigest(t *testing.T) {
	path := writeConfig(t, validConfigJSON)

	loaded, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(validConfigJSON))
	if loaded.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest = %q", loaded.SHA256)
	}
	if loaded.Config.Action.TTLSeconds != 600 || loaded.Config.Site != "example" {
		t.Fatalf("unexpected config: %#v", loaded.Config)
	}
}

func TestDocumentedProtectionConfigIsValid(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "crawlledger-protect.json"))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(writeConfig(t, makeValidConfigJSON(string(data))))
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Config.Site != "example" || len(loaded.Config.StaticDeny.Enabled) != 4 {
		t.Fatalf("unexpected documented config: %#v", loaded.Config)
	}
}

func TestLoadConfigRejectsUnsafeDocuments(t *testing.T) {
	tests := map[string]string{
		"unknown":   strings.Replace(validConfigJSON, `"site": "example",`, `"site": "example", "extra": 1,`, 1),
		"duplicate": strings.Replace(validConfigJSON, `"site": "example",`, `"site": "example", "site": "again",`, 1),
		"relative path": strings.Replace(
			validConfigJSON,
			strconv.Quote(testAbsolutePath("var", "log", "nginx", "access.crawlledger.json")),
			`"access.log"`,
			1,
		),
		"bad ttl":          strings.Replace(validConfigJSON, `"ttl_seconds": 600`, `"ttl_seconds": 59`, 1),
		"bucket capacity":  strings.Replace(validConfigJSON, `"max_tracked_groups": 10000`, `"max_tracked_groups": 20000`, 1),
		"duplicate method": strings.Replace(validConfigJSON, `"methods": []`, `"methods": ["POST", "POST"]`, 1),
	}
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadConfig(writeConfig(t, data)); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}

func TestLoadConfigRejectsOversizedDocument(t *testing.T) {
	path := filepath.Join(t.TempDir(), "protect.json")
	if err := os.WriteFile(path, make([]byte, maxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("oversized config was accepted")
	}
}

func writeConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "protect.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeValidConfigJSON(data string) string {
	replacements := map[string][]string{
		"/var/log/nginx/access.crawlledger.json":  {"var", "log", "nginx", "access.crawlledger.json"},
		"/var/lib/crawlledger/example-baseline":   {"var", "lib", "crawlledger", "example-baseline"},
		"/usr/sbin/nginx":                         {"usr", "sbin", "nginx"},
		"/etc/nginx/nginx.conf":                   {"etc", "nginx", "nginx.conf"},
		"/etc/nginx/crawlledger/example":          {"etc", "nginx", "crawlledger", "example"},
		"/var/lib/crawlledger/example/state.json": {"var", "lib", "crawlledger", "example", "state.json"},
	}
	for source, elements := range replacements {
		data = strings.Replace(data, strconv.Quote(source), strconv.Quote(testAbsolutePath(elements...)), 1)
	}
	return data
}

func testAbsolutePath(elements ...string) string {
	root := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	return filepath.Join(append([]string{root}, elements...)...)
}
