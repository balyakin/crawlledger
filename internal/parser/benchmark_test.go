package parser

import "testing"

func BenchmarkNginxCombinedParse(b *testing.B) {
	benchmarkParse(b, FormatNginxCombined, []byte(
		`192.0.2.10 - - [24/Jul/2026:10:11:12 +0300] "GET /archive?page=42 HTTP/1.1" 200 1234 "-" "SyntheticBot/1.0"`,
	))
}

func BenchmarkNginxJSONParse(b *testing.B) {
	benchmarkParse(b, FormatNginxJSON, []byte(
		`{"timestamp":"2026-07-24T07:11:12Z","remote_addr":"192.0.2.10","method":"GET","uri":"/archive?page=42","status":"200","bytes_sent":"1234","request_time":"0.120","upstream_response_time":"0.100","upstream_cache_status":"MISS","user_agent":"SyntheticBot/1.0","referer":"-"}`,
	))
}

func BenchmarkCaddyJSONParse(b *testing.B) {
	benchmarkParse(b, FormatCaddyJSON, []byte(
		`{"ts":1784877072.125,"request":{"remote_ip":"192.0.2.10","method":"GET","uri":"/archive?page=42","headers":{"User-Agent":["SyntheticBot/1.0"],"Referer":[]}},"status":200,"size":1234,"duration":0.12}`,
	))
}

func benchmarkParse(b *testing.B, format Format, line []byte) {
	b.Helper()
	value, err := New(format)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(line)))
	for b.Loop() {
		if _, err := value.Parse(line); err != nil {
			b.Fatal(err)
		}
	}
}
