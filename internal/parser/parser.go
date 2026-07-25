package parser

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/balyakin/crawlledger/internal/domain"
)

type Format string

const (
	FormatNginxCombined   Format = "nginx-combined"
	FormatNginxJSON       Format = "nginx-json"
	FormatCaddyJSON       Format = "caddy-json"
	FormatCrawlLedgerJSON Format = "crawlledger-json"
)

func (f Format) Valid() bool {
	return f == FormatNginxCombined || f == FormatNginxJSON || f == FormatCaddyJSON || f == FormatCrawlLedgerJSON
}

type RawRecord struct {
	TimestampUS          int64
	ClientIP             netip.Addr
	Method               string
	RequestURI           string
	Status               int
	BytesSent            int64
	RequestDurationUS    *int64
	UpstreamDurationUS   *int64
	CacheState           domain.CacheState
	UserAgent            string
	Referer              string
	MultipleHeaderValues bool
}

type Parsed struct {
	Raw       *RawRecord
	Canonical *domain.Event
	Warnings  []string
}

func (p Parsed) Validate() error {
	if (p.Raw == nil) == (p.Canonical == nil) {
		return fmt.Errorf("parsed record must contain exactly one representation")
	}
	return nil
}

type Parser interface {
	Parse(line []byte) (Parsed, error)
}

type Error struct{ Code string }

func (e *Error) Error() string { return "invalid log record: " + e.Code }

func parseError(code string) error { return &Error{Code: code} }

func New(format Format) (Parser, error) {
	switch format {
	case FormatNginxCombined:
		return nginxCombined{}, nil
	case FormatNginxJSON:
		return nginxJSON{}, nil
	case FormatCaddyJSON:
		return caddyJSON{}, nil
	case FormatCrawlLedgerJSON:
		return canonicalJSON{}, nil
	default:
		return nil, fmt.Errorf("unsupported log format")
	}
}

func validateRaw(record *RawRecord) error {
	if record.TimestampUS <= 0 {
		return parseError("invalid_timestamp")
	}
	if !record.ClientIP.IsValid() || record.ClientIP.Zone() != "" {
		return parseError("invalid_ip")
	}
	record.ClientIP = record.ClientIP.Unmap()
	record.Method = strings.ToUpper(record.Method)
	if len(record.Method) < 1 || len(record.Method) > 16 {
		return parseError("invalid_method")
	}
	for i, r := range record.Method {
		if (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') || (i > 0 && (r == '_' || r == '-')) {
			continue
		}
		return parseError("invalid_method")
	}
	if len(record.RequestURI) < 1 || len(record.RequestURI) > 65536 ||
		!utf8.ValidString(record.RequestURI) || hasControl(record.RequestURI) {
		return parseError("invalid_uri")
	}
	if record.Status < 100 || record.Status > 599 {
		return parseError("invalid_status")
	}
	if record.BytesSent < 0 {
		return parseError("invalid_bytes")
	}
	if record.RequestDurationUS != nil && *record.RequestDurationUS < 0 ||
		record.UpstreamDurationUS != nil && *record.UpstreamDurationUS < 0 {
		return parseError("invalid_duration")
	}
	if len(record.UserAgent) > 4096 || hasControl(record.UserAgent) {
		return parseError("invalid_user_agent")
	}
	if len(record.Referer) > 8192 || hasControl(record.Referer) {
		return parseError("invalid_referer")
	}
	if !record.CacheState.Valid() {
		record.CacheState = domain.CacheUnknown
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.In(r, unicode.Cc, unicode.Cf, unicode.Zl, unicode.Zp) {
			return true
		}
	}
	return false
}
