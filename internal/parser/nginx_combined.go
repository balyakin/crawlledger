package parser

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

type nginxCombined struct{}

func (nginxCombined) Parse(line []byte) (Parsed, error) {
	if len(line) == 0 {
		return Parsed{}, parseError("empty_line")
	}
	if !utf8.Valid(line) {
		return Parsed{}, parseError("invalid_utf8")
	}
	scanner := combinedScanner{text: string(line)}
	ipText, ok := scanner.token()
	if !ok {
		return Parsed{}, parseError("invalid_structure")
	}
	if _, ok = scanner.token(); !ok {
		return Parsed{}, parseError("invalid_structure")
	}
	if _, ok = scanner.token(); !ok {
		return Parsed{}, parseError("invalid_structure")
	}
	timestampText, ok := scanner.bracket()
	if !ok {
		return Parsed{}, parseError("invalid_structure")
	}
	request, ok := scanner.quoted()
	if !ok {
		return Parsed{}, parseError("invalid_structure")
	}
	statusText, ok := scanner.token()
	if !ok {
		return Parsed{}, parseError("invalid_status")
	}
	bytesText, ok := scanner.token()
	if !ok {
		return Parsed{}, parseError("invalid_bytes")
	}
	referer, ok := scanner.quoted()
	if !ok {
		return Parsed{}, parseError("invalid_referer")
	}
	userAgent, ok := scanner.quoted()
	if !ok || strings.TrimSpace(scanner.text[scanner.index:]) != "" {
		return Parsed{}, parseError("trailing_data")
	}
	if request == "-" {
		return Parsed{}, parseError("missing_request")
	}
	requestParts := strings.Fields(request)
	if len(requestParts) != 3 {
		return Parsed{}, parseError("invalid_structure")
	}
	switch requestParts[2] {
	case "HTTP/0.9", "HTTP/1.0", "HTTP/1.1", "HTTP/2.0", "HTTP/3.0":
	default:
		return Parsed{}, parseError("unsupported_protocol")
	}
	timestamp, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampText)
	if err != nil {
		return Parsed{}, parseError("invalid_timestamp")
	}
	ip, err := netip.ParseAddr(ipText)
	if err != nil {
		return Parsed{}, parseError("invalid_ip")
	}
	status, err := strconv.Atoi(statusText)
	if err != nil {
		return Parsed{}, parseError("invalid_status")
	}
	bytesSent, err := strconv.ParseInt(bytesText, 10, 64)
	if err != nil {
		return Parsed{}, parseError("invalid_bytes")
	}
	record := &RawRecord{
		TimestampUS: timestamp.UTC().UnixMicro(), ClientIP: ip, Method: requestParts[0],
		RequestURI: requestParts[1], Status: status, BytesSent: bytesSent,
		CacheState: domain.CacheUnknown, UserAgent: userAgent, Referer: referer,
	}
	if err := validateRaw(record); err != nil {
		return Parsed{}, err
	}
	return Parsed{Raw: record}, nil
}

type combinedScanner struct {
	text  string
	index int
}

func (s *combinedScanner) spaces() {
	for s.index < len(s.text) && (s.text[s.index] == ' ' || s.text[s.index] == '\t') {
		s.index++
	}
}

func (s *combinedScanner) token() (string, bool) {
	s.spaces()
	start := s.index
	for s.index < len(s.text) && s.text[s.index] != ' ' && s.text[s.index] != '\t' {
		s.index++
	}
	return s.text[start:s.index], s.index > start
}

func (s *combinedScanner) bracket() (string, bool) {
	s.spaces()
	if s.index >= len(s.text) || s.text[s.index] != '[' {
		return "", false
	}
	s.index++
	start := s.index
	for s.index < len(s.text) && s.text[s.index] != ']' {
		if s.text[s.index] == '[' {
			return "", false
		}
		s.index++
	}
	if s.index >= len(s.text) {
		return "", false
	}
	value := s.text[start:s.index]
	s.index++
	return value, true
}

func (s *combinedScanner) quoted() (string, bool) {
	s.spaces()
	if s.index >= len(s.text) || s.text[s.index] != '"' {
		return "", false
	}
	s.index++
	var value strings.Builder
	for s.index < len(s.text) {
		character := s.text[s.index]
		s.index++
		if character == '"' {
			return value.String(), true
		}
		if character == '\\' && s.index < len(s.text) && (s.text[s.index] == '"' || s.text[s.index] == '\\') {
			character = s.text[s.index]
			s.index++
		}
		value.WriteByte(character)
	}
	return "", false
}
