package parser

import (
	"errors"
	"strings"
	"testing"
)

func TestParsers(t *testing.T) {
	tests := []struct {
		format Format
		line   string
	}{
		{FormatNginxCombined, `192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /archive?page=42 HTTP/1.1" 200 1234 "-" "ExampleBot/1.0"`},
		{FormatNginxJSON, `{"timestamp":"2026-07-24T07:11:12Z","remote_addr":"192.0.2.10","method":"GET","uri":"/archive?page=42","status":"200","bytes_sent":"1234","request_time":"0.120000","upstream_response_time":"0.100, -, 0.020","upstream_cache_status":"MISS","user_agent":"ExampleBot/1.0","referer":"-"}`},
		{FormatCaddyJSON, `{"ts":1784877072.12,"request":{"remote_ip":"192.0.2.10","method":"GET","uri":"/archive?page=42","headers":{"User-Agent":["ExampleBot/1.0"],"Referer":[]}},"status":200,"size":1234,"duration":0.12}`},
	}
	for _, test := range tests {
		parser, err := New(test.format)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse([]byte(test.line))
		if err != nil || parsed.Raw == nil || parsed.Raw.Status != 200 {
			t.Fatalf("%s parse failed: %#v %v", test.format, parsed, err)
		}
	}
}

func TestDecimal(t *testing.T) {
	for input, want := range map[string]int64{
		"0": 0, "0.000001": 1, "1.2345674": 1234567, "1.2345675": 1234568,
		"9223372036854.775807": 9223372036854775807,
	} {
		got, err := decimalSecondsToMicroseconds(input)
		if err != nil || got != want {
			t.Errorf("%q = %d, %v; want %d", input, got, err, want)
		}
	}
	if _, err := decimalSecondsToMicroseconds("9223372036854.775808"); err == nil {
		t.Fatal("duration overflow accepted")
	}
}

func TestCanonicalRequiresNullableFields(t *testing.T) {
	value, _ := New(FormatCrawlLedgerJSON)
	line := `{"schema_version":1,"timestamp":"2026-07-24T07:11:12Z","client_key":"5e8ff9bf55ba3508199d22e984129be6","method":"GET","route":"/","url_fingerprint":"8b8fe7b64e6c786122310f7a3f1b0bf5","query_keys":[],"query_fingerprint":null,"status":200,"bytes_sent":1,"request_duration_us":null,"upstream_duration_us":null,"cache_state":"unknown","ua_hash":"b97a1ad44f5f1437bcdb4d674768a10ce34c9e75f13a7624ee03df3ec26b055a","claimed_crawler":null,"claimed_category":null,"claimed_protected_default":null,"referer_host":null,"security_probe_ids":[],"robots_allowed":null}`
	if _, err := value.Parse([]byte(line)); err == nil {
		t.Fatal("missing actionable_prefix accepted")
	}
}

func TestParseErrorsDoNotEchoInput(t *testing.T) {
	const secret = "SYNTHETIC_SECRET_7XQ"
	for _, format := range []Format{
		FormatNginxCombined, FormatNginxJSON, FormatCaddyJSON, FormatCrawlLedgerJSON,
	} {
		value, _ := New(format)
		_, err := value.Parse([]byte(secret))
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("%s exposed input in error: %v", format, err)
		}
	}
}

func TestRawParserRejectsDisplayControls(t *testing.T) {
	for _, character := range []rune{'\u0085', '\u200b', '\u2028', '\u2029', '\u202e', '\ufeff'} {
		if !hasControl("/archive/" + string(character)) {
			t.Errorf("display control U+%04X accepted", character)
		}
	}
}

func FuzzNginxCombined(f *testing.F) {
	f.Add(`192.0.2.1 - - [24/Jul/2026:10:11:12 +0000] "GET / HTTP/1.1" 200 1 "-" "-"`)
	f.Fuzz(func(t *testing.T, line string) { assertSafeParse(t, FormatNginxCombined, line) })
}

func FuzzNginxJSON(f *testing.F) {
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, line string) { assertSafeParse(t, FormatNginxJSON, line) })
}

func FuzzCaddyJSON(f *testing.F) {
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, line string) { assertSafeParse(t, FormatCaddyJSON, line) })
}

func FuzzCanonicalJSON(f *testing.F) {
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, line string) { assertSafeParse(t, FormatCrawlLedgerJSON, line) })
}

func assertSafeParse(t *testing.T, format Format, line string) {
	t.Helper()
	value, _ := New(format)
	parsed, err := value.Parse([]byte(line))
	if err != nil {
		var parseErr *Error
		if !errors.As(err, &parseErr) || err.Error() != "invalid log record: "+parseErr.Code {
			t.Fatalf("unsafe parse error: %v", err)
		}
	}
	if err == nil {
		if err := parsed.Validate(); err != nil {
			t.Fatal(err)
		}
		if parsed.Canonical != nil {
			if err := parsed.Canonical.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	}
}
