package parser

import (
	"bytes"
	"encoding/json"
	"time"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

type canonicalJSON struct{}

var canonicalRequiredFields = []string{
	"schema_version", "timestamp", "client_key", "method", "route", "actionable_prefix",
	"url_fingerprint", "query_keys", "query_fingerprint", "status", "bytes_sent",
	"request_duration_us", "upstream_duration_us", "cache_state", "ua_hash",
	"claimed_crawler", "claimed_category", "claimed_protected_default", "referer_host",
	"security_probe_ids", "robots_allowed",
}

var canonicalAllowedFields = func() map[string]struct{} {
	result := make(map[string]struct{}, len(canonicalRequiredFields))
	for _, name := range canonicalRequiredFields {
		result[name] = struct{}{}
	}
	return result
}()

var canonicalNullableFields = map[string]struct{}{
	"actionable_prefix": {}, "query_fingerprint": {}, "request_duration_us": {},
	"upstream_duration_us": {}, "claimed_crawler": {}, "claimed_category": {},
	"claimed_protected_default": {}, "referer_host": {}, "robots_allowed": {},
}

type CanonicalEvent struct {
	SchemaVersion           int                  `json:"schema_version"`
	Timestamp               string               `json:"timestamp"`
	ClientKey               string               `json:"client_key"`
	Method                  string               `json:"method"`
	Route                   string               `json:"route"`
	ActionablePrefix        *string              `json:"actionable_prefix"`
	URLFingerprint          string               `json:"url_fingerprint"`
	QueryKeys               []string             `json:"query_keys"`
	QueryFingerprint        *string              `json:"query_fingerprint"`
	Status                  int                  `json:"status"`
	BytesSent               int64                `json:"bytes_sent"`
	RequestDurationUS       *int64               `json:"request_duration_us"`
	UpstreamDurationUS      *int64               `json:"upstream_duration_us"`
	CacheState              domain.CacheState    `json:"cache_state"`
	UAHash                  string               `json:"ua_hash"`
	ClaimedCrawler          *string              `json:"claimed_crawler"`
	ClaimedCategory         *domain.TrafficClass `json:"claimed_category"`
	ClaimedProtectedDefault *bool                `json:"claimed_protected_default"`
	RefererHost             *string              `json:"referer_host"`
	SecurityProbeIDs        []string             `json:"security_probe_ids"`
	RobotsAllowed           *bool                `json:"robots_allowed"`
}

func (canonicalJSON) Parse(line []byte) (Parsed, error) {
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
	if err := json.Unmarshal(line, &fields); err != nil || fields == nil {
		return Parsed{}, parseError("invalid_json")
	}
	for _, name := range canonicalRequiredFields {
		raw, ok := fields[name]
		_, nullable := canonicalNullableFields[name]
		if !ok || !nullable && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return Parsed{}, parseError("invalid_json")
		}
	}
	for name := range fields {
		if _, ok := canonicalAllowedFields[name]; !ok {
			return Parsed{}, parseError("unknown_field")
		}
	}
	var value CanonicalEvent
	if err := decodeOne(line, &value, true); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	if value.SchemaVersion != 1 {
		return Parsed{}, parseError("invalid_json")
	}
	if value.QueryKeys == nil || value.SecurityProbeIDs == nil {
		return Parsed{}, parseError("invalid_json")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, value.Timestamp)
	_, offset := timestamp.Zone()
	if err != nil || offset != 0 {
		return Parsed{}, parseError("invalid_timestamp")
	}
	claimCount := 0
	if value.ClaimedCrawler != nil {
		claimCount++
	}
	if value.ClaimedCategory != nil {
		claimCount++
	}
	if value.ClaimedProtectedDefault != nil {
		claimCount++
	}
	if claimCount != 0 && claimCount != 3 {
		return Parsed{}, parseError("invalid_json")
	}
	var claim *domain.CrawlerClaim
	if claimCount == 3 {
		claim = &domain.CrawlerClaim{
			Name: *value.ClaimedCrawler, Category: *value.ClaimedCategory,
			ProtectedDefault: *value.ClaimedProtectedDefault,
		}
	}
	primary := domain.ClassUnclassified
	if len(value.SecurityProbeIDs) > 0 {
		primary = domain.ClassSecurityProbe
	} else if claim != nil {
		primary = claim.Category
	}
	event := &domain.Event{
		TimestampUS: timestamp.UTC().UnixMicro(), ClientKey: value.ClientKey, Method: value.Method,
		Route: value.Route, ActionablePrefix: value.ActionablePrefix, URLFingerprint: value.URLFingerprint,
		QueryKeys: value.QueryKeys, QueryFingerprint: value.QueryFingerprint, Status: value.Status,
		BytesSent: value.BytesSent, RequestDurationUS: value.RequestDurationUS,
		UpstreamDurationUS: value.UpstreamDurationUS, CacheState: value.CacheState, UAHash: value.UAHash,
		Claim: claim, RefererHost: value.RefererHost, SecurityProbeIDs: value.SecurityProbeIDs,
		RobotsAllowed: value.RobotsAllowed, PrimaryClass: primary,
	}
	if err := event.Validate(); err != nil {
		return Parsed{}, parseError("invalid_json")
	}
	result := Parsed{Canonical: event, Warnings: []string{}}
	if timestamp.Nanosecond()%1000 != 0 {
		result.Warnings = append(result.Warnings, "canonical_timestamp_precision_truncated")
	}
	return result, nil
}

func CanonicalFromEvent(event domain.Event) CanonicalEvent {
	queryKeys := append([]string{}, event.QueryKeys...)
	probeIDs := append([]string{}, event.SecurityProbeIDs...)
	value := CanonicalEvent{
		SchemaVersion: 1, Timestamp: time.UnixMicro(event.TimestampUS).UTC().Format(time.RFC3339Nano),
		ClientKey: event.ClientKey, Method: event.Method, Route: event.Route,
		ActionablePrefix: event.ActionablePrefix, URLFingerprint: event.URLFingerprint,
		QueryKeys: queryKeys, QueryFingerprint: event.QueryFingerprint, Status: event.Status,
		BytesSent: event.BytesSent, RequestDurationUS: event.RequestDurationUS,
		UpstreamDurationUS: event.UpstreamDurationUS, CacheState: event.CacheState, UAHash: event.UAHash,
		RefererHost: event.RefererHost, SecurityProbeIDs: probeIDs,
		RobotsAllowed: event.RobotsAllowed,
	}
	if event.Claim != nil {
		value.ClaimedCrawler = &event.Claim.Name
		value.ClaimedCategory = &event.Claim.Category
		value.ClaimedProtectedDefault = &event.Claim.ProtectedDefault
	}
	return value
}

func MarshalCanonical(event domain.Event) ([]byte, error) {
	return json.Marshal(CanonicalFromEvent(event))
}
