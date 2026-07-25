package parser

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strconv"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

type caddyJSON struct{}

type caddyJSONRecord struct {
	Timestamp json.Number `json:"ts"`
	Request   struct {
		RemoteIP string `json:"remote_ip"`
		Method   string `json:"method"`
		URI      string `json:"uri"`
		Headers  struct {
			UserAgent []string `json:"User-Agent"`
			Referer   []string `json:"Referer"`
		} `json:"headers"`
	} `json:"request"`
	Status   int         `json:"status"`
	Size     int64       `json:"size"`
	Duration json.Number `json:"duration"`
}

func (caddyJSON) Parse(line []byte) (Parsed, error) {
	if len(line) == 0 {
		return Parsed{}, parseError("empty_line")
	}
	if !utf8.Valid(line) {
		return Parsed{}, parseError("invalid_utf8")
	}
	if err := rejectDuplicateJSON(line); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(line, &top); err != nil || top == nil {
		return Parsed{}, parseError("invalid_json")
	}
	for _, name := range []string{"ts", "request", "status", "size", "duration"} {
		if value, ok := top[name]; !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return Parsed{}, parseError("invalid_json")
		}
	}
	var request map[string]json.RawMessage
	if err := json.Unmarshal(top["request"], &request); err != nil || request == nil {
		return Parsed{}, parseError("invalid_json")
	}
	for _, name := range []string{"remote_ip", "method", "uri"} {
		if _, ok := request[name]; !ok {
			return Parsed{}, parseError("invalid_json")
		}
	}
	var raw caddyJSONRecord
	if err := decodeOne(line, &raw, false); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	timestamp, err := decimalSecondsToMicroseconds(raw.Timestamp.String())
	if err != nil {
		return Parsed{}, parseError("invalid_timestamp")
	}
	duration, err := decimalSecondsToMicroseconds(raw.Duration.String())
	if err != nil {
		return Parsed{}, parseError("invalid_duration")
	}
	ip, err := netip.ParseAddr(raw.Request.RemoteIP)
	if err != nil {
		return Parsed{}, parseError("invalid_ip")
	}
	record := &RawRecord{
		TimestampUS: timestamp, ClientIP: ip, Method: raw.Request.Method, RequestURI: raw.Request.URI,
		Status: raw.Status, BytesSent: raw.Size, RequestDurationUS: &duration,
		CacheState: domain.CacheUnknown,
	}
	if len(raw.Request.Headers.UserAgent) > 0 {
		record.UserAgent = raw.Request.Headers.UserAgent[0]
	}
	if len(raw.Request.Headers.Referer) > 0 {
		record.Referer = raw.Request.Headers.Referer[0]
	}
	record.MultipleHeaderValues = len(raw.Request.Headers.UserAgent) > 1 ||
		len(raw.Request.Headers.Referer) > 1
	if err := validateRaw(record); err != nil {
		return Parsed{}, err
	}
	return Parsed{Raw: record, Warnings: []string{}}, nil
}

var _ = strconv.IntSize
