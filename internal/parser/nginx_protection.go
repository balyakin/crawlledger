package parser

import (
	"encoding/json"
	"strings"
	"unicode/utf8"
)

type RecordErrorClass string

const (
	RecordContentError   RecordErrorClass = "record_content"
	SensorStructureError RecordErrorClass = "sensor_structure"
)

type NginxProtectionRecord struct {
	Raw            *RawRecord
	NginxURI       string
	LimitReqStatus string
	Warnings       []string
}

func ParseNginxProtection(line []byte) (NginxProtectionRecord, RecordErrorClass, error) {
	if len(line) == 0 {
		return NginxProtectionRecord{}, RecordContentError, parseError("empty_line")
	}
	if !utf8.Valid(line) {
		return NginxProtectionRecord{}, RecordContentError, parseError("invalid_utf8")
	}
	if err := rejectDuplicateJSON(line); err != nil {
		return NginxProtectionRecord{}, SensorStructureError, parseError("invalid_json")
	}
	var fields map[string]json.RawMessage
	if err := decodeOne(line, &fields, false); err != nil || fields == nil {
		return NginxProtectionRecord{}, SensorStructureError, parseError("invalid_json")
	}
	required := []string{
		"timestamp", "remote_addr", "method", "uri", "nginx_uri", "status",
		"limit_req_status", "bytes_sent", "request_time", "upstream_response_time",
		"upstream_cache_status", "user_agent", "referer",
	}
	values := make(map[string]string, len(required))
	for _, name := range required {
		raw, exists := fields[name]
		var value string
		if !exists || json.Unmarshal(raw, &value) != nil {
			return NginxProtectionRecord{}, SensorStructureError, parseError("invalid_json")
		}
		values[name] = value
	}
	parsed, err := (nginxJSON{}).Parse(line)
	if err != nil {
		return NginxProtectionRecord{}, RecordContentError, err
	}
	nginxURI := values["nginx_uri"]
	if len(nginxURI) < 1 || len(nginxURI) > 65536 || !strings.HasPrefix(nginxURI, "/") ||
		!utf8.ValidString(nginxURI) || hasControl(nginxURI) {
		return NginxProtectionRecord{}, RecordContentError, parseError("invalid_nginx_uri")
	}
	limitStatus := values["limit_req_status"]
	if !validLimitStatus(limitStatus) || limitStatus == "REJECTED" && parsed.Raw.Status != 429 {
		return NginxProtectionRecord{}, RecordContentError, parseError("invalid_limit_req_status")
	}
	return NginxProtectionRecord{
		Raw:            parsed.Raw,
		NginxURI:       nginxURI,
		LimitReqStatus: limitStatus,
		Warnings:       append([]string(nil), parsed.Warnings...),
	}, "", nil
}

func validLimitStatus(value string) bool {
	switch value {
	case "", "-", "PASSED", "DELAYED", "REJECTED", "DELAYED_DRY_RUN", "REJECTED_DRY_RUN":
		return true
	default:
		return false
	}
}
