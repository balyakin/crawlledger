package domain

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

type TrafficClass string

const (
	ClassClaimedAICrawler     TrafficClass = "claimed_ai_crawler"
	ClassClaimedSearchCrawler TrafficClass = "claimed_search_crawler"
	ClassClaimedOtherCrawler  TrafficClass = "claimed_other_crawler"
	ClassSecurityProbe        TrafficClass = "security_probe"
	ClassUnclassified         TrafficClass = "unclassified"
)

func (c TrafficClass) Valid() bool {
	switch c {
	case ClassClaimedAICrawler, ClassClaimedSearchCrawler, ClassClaimedOtherCrawler,
		ClassSecurityProbe, ClassUnclassified:
		return true
	default:
		return false
	}
}

func (c TrafficClass) Claimed() bool {
	return c == ClassClaimedAICrawler || c == ClassClaimedSearchCrawler || c == ClassClaimedOtherCrawler
}

type CacheState string

const (
	CacheHit     CacheState = "hit"
	CacheMiss    CacheState = "miss"
	CacheBypass  CacheState = "bypass"
	CacheExpired CacheState = "expired"
	CacheStale   CacheState = "stale"
	CacheUnknown CacheState = "unknown"
)

func (c CacheState) Valid() bool {
	switch c {
	case CacheHit, CacheMiss, CacheBypass, CacheExpired, CacheStale, CacheUnknown:
		return true
	default:
		return false
	}
}

type CrawlerClaim struct {
	Name             string
	Category         TrafficClass
	ProtectedDefault bool
}

type Event struct {
	TimestampUS        int64
	ClientKey          string
	Method             string
	Route              string
	ActionablePrefix   *string
	URLFingerprint     string
	QueryKeys          []string
	QueryFingerprint   *string
	Status             int
	BytesSent          int64
	RequestDurationUS  *int64
	UpstreamDurationUS *int64
	CacheState         CacheState
	UAHash             string
	Claim              *CrawlerClaim
	RefererHost        *string
	SecurityProbeIDs   []string
	RobotsAllowed      *bool
	PrimaryClass       TrafficClass
}

func MinuteBucket(timestampUS int64) int64 {
	const minuteUS = int64(time.Minute / time.Microsecond)
	return timestampUS - timestampUS%minuteUS
}

func (e Event) Validate() error {
	if e.TimestampUS <= 0 {
		return errors.New("timestamp must be positive")
	}
	if !lowerHex(e.ClientKey, 32) || !lowerHex(e.URLFingerprint, 32) || !lowerHex(e.UAHash, 64) {
		return errors.New("invalid pseudonym")
	}
	if !validMethod(e.Method) {
		return errors.New("invalid method")
	}
	if !validText(e.Route, 1, 512) || !strings.HasPrefix(e.Route, "/") {
		return errors.New("invalid route")
	}
	if e.ActionablePrefix != nil && !validActionable(*e.ActionablePrefix) {
		return errors.New("invalid actionable prefix")
	}
	if e.Status < 100 || e.Status > 599 || e.BytesSent < 0 {
		return errors.New("invalid response metrics")
	}
	if (e.RequestDurationUS != nil && *e.RequestDurationUS < 0) ||
		(e.UpstreamDurationUS != nil && *e.UpstreamDurationUS < 0) {
		return errors.New("invalid duration")
	}
	if !e.CacheState.Valid() || !e.PrimaryClass.Valid() {
		return errors.New("invalid enum")
	}
	if e.QueryKeys == nil || e.SecurityProbeIDs == nil ||
		!sortedUnique(e.QueryKeys) || len(e.QueryKeys) > 32 || !sortedUnique(e.SecurityProbeIDs) {
		return errors.New("unordered or duplicate values")
	}
	for _, key := range e.QueryKeys {
		if !validText(key, 1, 80) {
			return errors.New("invalid query key")
		}
	}
	if (len(e.QueryKeys) == 0) != (e.QueryFingerprint == nil) {
		return errors.New("query fingerprint invariant")
	}
	if e.QueryFingerprint != nil && !lowerHex(*e.QueryFingerprint, 32) {
		return errors.New("invalid query fingerprint")
	}
	if e.Claim == nil {
		if e.RobotsAllowed != nil || e.PrimaryClass.Claimed() {
			return errors.New("claim invariant")
		}
	} else {
		if !validText(e.Claim.Name, 1, 128) || !e.Claim.Category.Claimed() {
			return errors.New("invalid claim")
		}
	}
	if e.RefererHost != nil && !validHostname(*e.RefererHost) {
		return errors.New("invalid referer host")
	}
	for _, id := range e.SecurityProbeIDs {
		if !ValidProbeID(id) {
			return errors.New("invalid security probe ID")
		}
	}
	expected := ClassUnclassified
	if len(e.SecurityProbeIDs) != 0 {
		expected = ClassSecurityProbe
	} else if e.Claim != nil {
		expected = e.Claim.Category
	}
	if e.PrimaryClass != expected {
		return fmt.Errorf("primary class must be %s", expected)
	}
	return nil
}

func ValidProbeID(value string) bool {
	switch value {
	case "env-file-scan", "git-metadata-scan", "log4shell-probe", "path-traversal-scan",
		"phpmyadmin-scan", "shell-probe", "wp-login-scan":
		return true
	default:
		return false
	}
}

func ValidMethod(value string) bool { return validMethod(value) }

func ValidActionable(value string) bool { return validActionable(value) }

func validHostname(value string) bool {
	if !validText(value, 1, 253) || value != strings.ToLower(value) {
		return false
	}
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Zone() == "" && address.Unmap().String() == value
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func lowerHex(value string, length int) bool {
	if len(value) != length || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validText(value string, min, max int) bool {
	if len(value) < min || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == 0 || r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validMethod(value string) bool {
	if len(value) < 1 || len(value) > 16 {
		return false
	}
	for i, r := range value {
		if (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9') || (i > 0 && (r == '_' || r == '-')) {
			continue
		}
		return false
	}
	return true
}

func validActionable(value string) bool {
	if !validText(value, 1, 256) || !strings.HasPrefix(value, "/") {
		return false
	}
	for _, r := range value {
		if r > 0x7e || r == '\\' || r == '%' || r == '?' || r == '#' || r == '*' || r == '{' || r == '}' || r == ' ' {
			return false
		}
	}
	return !strings.Contains(value, "//") && !strings.Contains(value, "..")
}

func sortedUnique(values []string) bool {
	for i, value := range values {
		if !validText(value, 1, 256) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}
