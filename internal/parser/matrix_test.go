package parser

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/balyakin/crawlledger/internal/domain"
)

type parserCase struct {
	name  string
	line  string
	valid bool
}

func TestParserCaseMatrices(t *testing.T) {
	for _, format := range []Format{
		FormatNginxCombined, FormatNginxJSON, FormatCaddyJSON, FormatCrawlLedgerJSON,
	} {
		cases := parserCases(format)
		if len(cases) < 20 {
			t.Fatalf("%s has only %d cases", format, len(cases))
		}
		value, _ := New(format)
		for _, test := range cases {
			t.Run(string(format)+"/"+test.name, func(t *testing.T) {
				parsed, err := value.Parse([]byte(test.line))
				if test.valid && err != nil {
					t.Fatal(err)
				}
				if !test.valid && err == nil {
					t.Fatalf("invalid record accepted: %#v", parsed)
				}
			})
		}
	}
}

func parserCases(format Format) []parserCase {
	switch format {
	case FormatNginxCombined:
		base := `192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /archive?page=42 HTTP/1.1" 200 1234 "-" "ExampleBot/1.0"`
		return []parserCase{
			{"base", base, true},
			{"ipv6", strings.Replace(base, "192.0.2.10", "2001:db8::10", 1), true},
			{"http09", strings.Replace(base, "HTTP/1.1", "HTTP/0.9", 1), true},
			{"http10", strings.Replace(base, "HTTP/1.1", "HTTP/1.0", 1), true},
			{"http20", strings.Replace(base, "HTTP/1.1", "HTTP/2.0", 1), true},
			{"http30", strings.Replace(base, "HTTP/1.1", "HTTP/3.0", 1), true},
			{"head", strings.Replace(base, "GET ", "HEAD ", 1), true},
			{"status599", strings.Replace(base, " 200 1234 ", " 599 1234 ", 1), true},
			{"zero-bytes", strings.Replace(base, " 200 1234 ", " 200 0 ", 1), true},
			{"escaped-ua", strings.Replace(base, `ExampleBot/1.0`, `ExampleBot/\"1.0\"`, 1), true},
			{"empty", "", false},
			{"bad-ip", strings.Replace(base, "192.0.2.10", "999.0.0.1", 1), false},
			{"ip-port", strings.Replace(base, "192.0.2.10", "192.0.2.10:80", 1), false},
			{"missing-bracket", strings.Replace(base, "[24/Jul", "24/Jul", 1), false},
			{"nested-bracket", strings.Replace(base, "[24/Jul", "[[24/Jul", 1), false},
			{"missing-request", strings.Replace(base, `"GET /archive?page=42 HTTP/1.1"`, `"-"`, 1), false},
			{"bad-protocol", strings.Replace(base, "HTTP/1.1", "HTTP/9", 1), false},
			{"bad-status", strings.Replace(base, " 200 1234 ", " 99 1234 ", 1), false},
			{"negative-bytes", strings.Replace(base, " 200 1234 ", " 200 -1 ", 1), false},
			{"trailing", base + " extra", false},
			{"literal-space-uri", strings.Replace(base, "/archive?page=42", "/archive bad", 1), false},
			{"control-ua", strings.Replace(base, "ExampleBot/1.0", "Example\x00Bot", 1), false},
		}
	case FormatNginxJSON:
		base := `{"timestamp":"2026-07-24T07:11:12Z","remote_addr":"192.0.2.10","method":"GET","uri":"/archive?page=42","status":"200","bytes_sent":"1234","request_time":"0.120000","upstream_response_time":"0.100, -, 0.020","upstream_cache_status":"MISS","user_agent":"ExampleBot/1.0","referer":"-"}`
		cases := []parserCase{
			{"base", base, true},
			{"unknown", strings.Replace(base, `}`, `,"synthetic":true}`, 1), true},
			{"ipv6", strings.Replace(base, "192.0.2.10", "2001:db8::10", 1), true},
			{"unavailable", strings.Replace(base, `"0.120000"`, `"-"`, 1), true},
			{"cache-lower", strings.Replace(base, `"MISS"`, `"miss"`, 1), true},
			{"unknown-cache", strings.Replace(base, `"MISS"`, `"SYNTHETIC"`, 1), true},
			{"lower-method", strings.Replace(base, `"GET"`, `"get"`, 1), true},
			{"zero-bytes", strings.Replace(base, `"1234"`, `"0"`, 1), true},
			{"status599", strings.Replace(base, `"200"`, `"599"`, 1), true},
			{"empty-ua", strings.Replace(base, `"ExampleBot/1.0"`, `"-"`, 1), true},
			{"empty", "", false},
			{"duplicate", strings.Replace(base, `"timestamp":`, `"timestamp":"2026-07-24T07:11:12Z","timestamp":`, 1), false},
			{"trailing", base + `{}`, false},
			{"bad-ip", strings.Replace(base, "192.0.2.10", "192.0.2.10:80", 1), false},
			{"negative-bytes", strings.Replace(base, `"1234"`, `"-1"`, 1), false},
			{"bad-status-type", strings.Replace(base, `"status":"200"`, `"status":200`, 1), false},
			{"exponent-duration", strings.Replace(base, `"0.120000"`, `"1e2"`, 1), false},
			{"control-ua", strings.Replace(base, "ExampleBot/1.0", `Example\u0000Bot`, 1), false},
		}
		for _, key := range []string{"timestamp", "remote_addr", "method", "uri", "status", "bytes_sent"} {
			cases = append(cases, parserCase{"missing-" + key, deleteJSONKey(base, key), false})
		}
		return cases
	case FormatCaddyJSON:
		base := `{"ts":1784877072.12,"request":{"remote_ip":"192.0.2.10","method":"GET","uri":"/archive?page=42","headers":{"User-Agent":["ExampleBot/1.0"],"Referer":[]}},"status":200,"size":1234,"duration":0.12}`
		cases := []parserCase{
			{"base", base, true},
			{"unknown", strings.Replace(base, `}`, `,"synthetic":true}`, 1), true},
			{"ipv6", strings.Replace(base, "192.0.2.10", "2001:db8::10", 1), true},
			{"lower-method", strings.Replace(base, `"GET"`, `"get"`, 1), true},
			{"zero-size", strings.Replace(base, `"size":1234`, `"size":0`, 1), true},
			{"status599", strings.Replace(base, `"status":200`, `"status":599`, 1), true},
			{"absolute-uri", strings.Replace(base, `"/archive?page=42"`, `"https://site.example/archive?page=42"`, 1), true},
			{"multiple-headers", strings.Replace(base, `["ExampleBot/1.0"]`, `["ExampleBot/1.0","Synthetic/2"]`, 1), true},
			{"no-headers", strings.Replace(base, `,"headers":{"User-Agent":["ExampleBot/1.0"],"Referer":[]}`, ``, 1), true},
			{"rounding", strings.Replace(base, `"duration":0.12`, `"duration":0.0000015`, 1), true},
			{"empty", "", false},
			{"duplicate", strings.Replace(base, `"status":200`, `"status":200,"status":200`, 1), false},
			{"trailing", base + `{}`, false},
			{"ip-port", strings.Replace(base, "192.0.2.10", "192.0.2.10:443", 1), false},
			{"negative-size", strings.Replace(base, `"size":1234`, `"size":-1`, 1), false},
			{"null-size", strings.Replace(base, `"size":1234`, `"size":null`, 1), false},
			{"negative-duration", strings.Replace(base, `"duration":0.12`, `"duration":-1`, 1), false},
			{"exponent", strings.Replace(base, `"duration":0.12`, `"duration":1e2`, 1), false},
			{"bad-status", strings.Replace(base, `"status":200`, `"status":99`, 1), false},
		}
		for _, key := range []string{"ts", "request", "status", "size", "duration"} {
			cases = append(cases, parserCase{"missing-" + key, deleteJSONKey(base, key), false})
		}
		for _, key := range []string{"remote_ip", "method", "uri"} {
			cases = append(cases, parserCase{"missing-request-" + key, deleteNestedJSONKey(base, "request", key), false})
		}
		return cases
	default:
		event := domain.Event{
			TimestampUS: 1784877072120000, ClientKey: strings.Repeat("1", 32), Method: "GET",
			Route: "/", ActionablePrefix: stringPointer("/"), URLFingerprint: strings.Repeat("2", 32),
			QueryKeys: []string{}, Status: 200, BytesSent: 1, CacheState: domain.CacheUnknown,
			UAHash: strings.Repeat("3", 64), SecurityProbeIDs: []string{}, PrimaryClass: domain.ClassUnclassified,
		}
		encoded, _ := MarshalCanonical(event)
		base := string(encoded)
		cases := []parserCase{
			{"base", base, true},
			{"nanoseconds", strings.Replace(base, "2026-07-24T07:11:12.12Z", "2026-07-24T07:11:12.120000001Z", 1), true},
			{"non-utc", strings.Replace(base, "2026-07-24T07:11:12.12Z", "2026-07-24T10:11:12.12+03:00", 1), false},
			{"unknown", strings.Replace(base, `}`, `,"synthetic":true}`, 1), false},
			{"duplicate", strings.Replace(base, `"status":200`, `"status":200,"status":200`, 1), false},
			{"null-query-keys", strings.Replace(base, `"query_keys":[]`, `"query_keys":null`, 1), false},
			{"null-probes", strings.Replace(base, `"security_probe_ids":[]`, `"security_probe_ids":null`, 1), false},
			{"null-bytes", strings.Replace(base, `"bytes_sent":1`, `"bytes_sent":null`, 1), false},
			{"bad-probe", strings.Replace(base, `"security_probe_ids":[]`, `"security_probe_ids":["synthetic"]`, 1), false},
			{"trailing", base + `{}`, false},
		}
		for _, key := range []string{
			"schema_version", "timestamp", "client_key", "method", "route", "actionable_prefix",
			"url_fingerprint", "query_keys", "query_fingerprint", "status", "bytes_sent",
			"request_duration_us", "upstream_duration_us", "cache_state", "ua_hash",
			"claimed_crawler", "claimed_category", "claimed_protected_default", "referer_host",
			"security_probe_ids", "robots_allowed",
		} {
			cases = append(cases, parserCase{"missing-" + key, deleteJSONKey(base, key), false})
		}
		return cases
	}
}

func deleteJSONKey(data, key string) string {
	var value map[string]any
	_ = json.Unmarshal([]byte(data), &value)
	delete(value, key)
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func deleteNestedJSONKey(data, object, key string) string {
	var value map[string]any
	_ = json.Unmarshal([]byte(data), &value)
	delete(value[object].(map[string]any), key)
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func stringPointer(value string) *string { return &value }
