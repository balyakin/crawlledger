package parser

import (
	"encoding/json"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

type nginxJSON struct{}

type nginxJSONRecord struct {
	Timestamp            string `json:"timestamp"`
	RemoteAddr           string `json:"remote_addr"`
	Method               string `json:"method"`
	URI                  string `json:"uri"`
	Status               string `json:"status"`
	BytesSent            string `json:"bytes_sent"`
	RequestTime          string `json:"request_time"`
	UpstreamResponseTime string `json:"upstream_response_time"`
	UpstreamCacheStatus  string `json:"upstream_cache_status"`
	UserAgent            string `json:"user_agent"`
	Referer              string `json:"referer"`
}

func (nginxJSON) Parse(line []byte) (Parsed, error) {
	if len(line) == 0 {
		return Parsed{}, parseError("empty_line")
	}
	if !utf8.Valid(line) {
		return Parsed{}, parseError("invalid_utf8")
	}
	if err := rejectDuplicateJSON(line); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	var fields map[string]json.RawMessage
	if err := decodeOne(line, &fields, false); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	for _, required := range []string{"timestamp", "remote_addr", "method", "uri", "status", "bytes_sent"} {
		if _, ok := fields[required]; !ok {
			return Parsed{}, parseError("invalid_json")
		}
	}
	var raw nginxJSONRecord
	if err := decodeOne(line, &raw, false); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	timestamp, err := time.Parse(time.RFC3339, raw.Timestamp)
	if err != nil {
		return Parsed{}, parseError("invalid_timestamp")
	}
	ip, err := netip.ParseAddr(raw.RemoteAddr)
	if err != nil {
		return Parsed{}, parseError("invalid_ip")
	}
	status, err := strconv.Atoi(raw.Status)
	if err != nil {
		return Parsed{}, parseError("invalid_status")
	}
	bytesSent, err := strconv.ParseInt(raw.BytesSent, 10, 64)
	if err != nil {
		return Parsed{}, parseError("invalid_bytes")
	}
	requestDuration, err := optionalDuration(raw.RequestTime)
	if err != nil {
		return Parsed{}, parseError("invalid_duration")
	}
	upstreamDuration, err := upstreamDurations(raw.UpstreamResponseTime)
	if err != nil {
		return Parsed{}, parseError("invalid_duration")
	}
	cache, cacheWarning := cacheState(raw.UpstreamCacheStatus)
	record := &RawRecord{
		TimestampUS: timestamp.UTC().UnixMicro(), ClientIP: ip, Method: raw.Method, RequestURI: raw.URI,
		Status: status, BytesSent: bytesSent, RequestDurationUS: requestDuration,
		UpstreamDurationUS: upstreamDuration, CacheState: cache,
		UserAgent: unavailableString(raw.UserAgent), Referer: unavailableString(raw.Referer),
	}
	if err := validateRaw(record); err != nil {
		return Parsed{}, err
	}
	result := Parsed{Raw: record, Warnings: []string{}}
	if cacheWarning {
		result.Warnings = append(result.Warnings, "unknown_cache_state_observed")
	}
	return result, nil
}

func optionalDuration(value string) (*int64, error) {
	if value == "" || value == "-" {
		return nil, nil
	}
	parsed, err := decimalSecondsToMicroseconds(value)
	return &parsed, err
}

func upstreamDurations(value string) (*int64, error) {
	if value == "" || value == "-" {
		return nil, nil
	}
	var total int64
	found := false
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "-" {
			continue
		}
		duration, err := decimalSecondsToMicroseconds(item)
		if err != nil || total > int64(^uint64(0)>>1)-duration {
			return nil, strconv.ErrRange
		}
		total += duration
		found = true
	}
	if !found {
		return nil, nil
	}
	return &total, nil
}

func cacheState(value string) (domain.CacheState, bool) {
	switch strings.ToUpper(value) {
	case "HIT":
		return domain.CacheHit, false
	case "MISS":
		return domain.CacheMiss, false
	case "BYPASS":
		return domain.CacheBypass, false
	case "EXPIRED":
		return domain.CacheExpired, false
	case "STALE":
		return domain.CacheStale, false
	case "", "-":
		return domain.CacheUnknown, false
	default:
		return domain.CacheUnknown, true
	}
}

func unavailableString(value string) string {
	if value == "-" {
		return ""
	}
	return value
}
