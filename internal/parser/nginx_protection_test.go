package parser

import (
	"strings"
	"testing"
)

const validProtectionLine = `{"timestamp":"2026-07-31T12:00:00+00:00","remote_addr":"192.0.2.10","method":"POST","uri":"/api/search?q=x","nginx_uri":"/api/search","status":"200","limit_req_status":"PASSED","bytes_sent":"12","request_time":"0.010","upstream_response_time":"0.009","upstream_cache_status":"MISS","user_agent":"synthetic","referer":"-","extra":"accepted"}`

func TestParseNginxProtectionAcceptsRequiredFieldsAndExtras(t *testing.T) {
	record, class, err := ParseNginxProtection([]byte(validProtectionLine))
	if err != nil {
		t.Fatal(err)
	}
	if class != "" || record.NginxURI != "/api/search" || record.LimitReqStatus != "PASSED" {
		t.Fatalf("unexpected record: %#v class=%q", record, class)
	}
	if record.Raw == nil || record.Raw.Status != 200 {
		t.Fatalf("base parser was not used: %#v", record.Raw)
	}
}

func TestParseNginxProtectionClassifiesErrors(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		class RecordErrorClass
	}{
		{"malformed", `{`, SensorStructureError},
		{"duplicate", strings.Replace(validProtectionLine, `"nginx_uri":"/api/search"`, `"nginx_uri":"/api/search","nginx_uri":"/other"`, 1), SensorStructureError},
		{"missing", strings.Replace(validProtectionLine, `,"nginx_uri":"/api/search"`, ``, 1), SensorStructureError},
		{"missing metric", strings.Replace(validProtectionLine, `,"upstream_response_time":"0.009"`, ``, 1), SensorStructureError},
		{"wrong type", strings.Replace(validProtectionLine, `"nginx_uri":"/api/search"`, `"nginx_uri":1`, 1), SensorStructureError},
		{"wrong metric type", strings.Replace(validProtectionLine, `"request_time":"0.010"`, `"request_time":1`, 1), SensorStructureError},
		{"bad uri", strings.Replace(validProtectionLine, `"nginx_uri":"/api/search"`, `"nginx_uri":"relative"`, 1), RecordContentError},
		{"bad limiter", strings.Replace(validProtectionLine, `"limit_req_status":"PASSED"`, `"limit_req_status":"UNKNOWN"`, 1), RecordContentError},
		{"impossible rejected", strings.Replace(strings.Replace(validProtectionLine, `"limit_req_status":"PASSED"`, `"limit_req_status":"REJECTED"`, 1), `"status":"200"`, `"status":"200"`, 1), RecordContentError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, class, err := ParseNginxProtection([]byte(test.line))
			if err == nil || class != test.class {
				t.Fatalf("class=%q err=%v", class, err)
			}
		})
	}
	invalidUTF8 := append([]byte(validProtectionLine), 0xff)
	if _, class, err := ParseNginxProtection(invalidUTF8); err == nil || class != RecordContentError {
		t.Fatalf("invalid UTF-8 class=%q err=%v", class, err)
	}
}

func TestParseNginxProtectionAcceptsLimiterRejection(t *testing.T) {
	line := strings.Replace(validProtectionLine, `"status":"200"`, `"status":"429"`, 1)
	line = strings.Replace(line, `"limit_req_status":"PASSED"`, `"limit_req_status":"REJECTED"`, 1)
	if _, class, err := ParseNginxProtection([]byte(line)); err != nil || class != "" {
		t.Fatalf("class=%q err=%v", class, err)
	}
}

func TestParseNginxProtectionAcceptsEveryDocumentedLimiterStatusPair(t *testing.T) {
	tests := map[string]string{
		"":                 "200",
		"-":                "200",
		"PASSED":           "200",
		"DELAYED":          "200",
		"DELAYED_DRY_RUN":  "403",
		"REJECTED_DRY_RUN": "429",
		"REJECTED":         "429",
	}
	for limiterStatus, status := range tests {
		line := strings.Replace(validProtectionLine, `"status":"200"`, `"status":"`+status+`"`, 1)
		line = strings.Replace(
			line,
			`"limit_req_status":"PASSED"`,
			`"limit_req_status":"`+limiterStatus+`"`,
			1,
		)
		if _, class, err := ParseNginxProtection([]byte(line)); err != nil || class != "" {
			t.Fatalf("status=%s limiter=%q: class=%q err=%v", status, limiterStatus, class, err)
		}
	}
}
