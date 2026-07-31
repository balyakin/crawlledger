package normalize

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"sort"

	"github.com/balyakin/crawlledger/internal/domain"
	"github.com/balyakin/crawlledger/internal/parser"
)

var errInvalidURI = errors.New("invalid request URI")

type Facts struct {
	Claim            *domain.CrawlerClaim
	SecurityProbeIDs []string
	RobotsAllowed    *bool
}

type Normalizer struct{ key Key }

func New(key Key) *Normalizer { return &Normalizer{key: key} }

func (n *Normalizer) hmac(purpose string, value []byte) [32]byte {
	hash := hmac.New(sha256.New, n.key[:])
	_, _ = hash.Write([]byte(purpose))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(value)
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}

func (n *Normalizer) Normalize(record parser.RawRecord, facts Facts) (domain.Event, error) {
	event, _, err := n.NormalizeProtection(record, facts)
	return event, err
}

func (n *Normalizer) NormalizeProtection(record parser.RawRecord, facts Facts) (domain.Event, *string, error) {
	parsed, err := url.ParseRequestURI(record.RequestURI)
	if err != nil || parsed.Fragment != "" {
		return domain.Event{}, nil, errInvalidURI
	}
	if parsed.IsAbs() {
		if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" {
			return domain.Event{}, nil, errInvalidURI
		}
	}
	route, actionable, err := n.normalizePath(parsed, record.RequestURI)
	if err != nil {
		return domain.Event{}, nil, err
	}
	canonical := canonicalPath(parsed, actionable)
	queryKeys, queryFingerprint, err := n.normalizeQuery(parsed)
	if err != nil {
		return domain.Event{}, nil, err
	}
	client := n.hmac("client", []byte(record.ClientIP.Unmap().String()))
	urlSum := n.hmac("url", []byte(record.RequestURI))
	ua := n.hmac("ua", []byte(record.UserAgent))
	probes := append([]string{}, facts.SecurityProbeIDs...)
	sort.Strings(probes)
	probes = dedupe(probes)
	primary := domain.ClassUnclassified
	if len(probes) > 0 {
		primary = domain.ClassSecurityProbe
	} else if facts.Claim != nil {
		primary = facts.Claim.Category
	}
	event := domain.Event{
		TimestampUS: record.TimestampUS, ClientKey: hex.EncodeToString(client[:16]), Method: record.Method,
		Route: route, ActionablePrefix: actionable, URLFingerprint: hex.EncodeToString(urlSum[:16]),
		QueryKeys: queryKeys, QueryFingerprint: queryFingerprint, Status: record.Status,
		BytesSent: record.BytesSent, RequestDurationUS: record.RequestDurationUS,
		UpstreamDurationUS: record.UpstreamDurationUS, CacheState: record.CacheState,
		UAHash: hex.EncodeToString(ua[:]), Claim: facts.Claim, RefererHost: refererHost(record.Referer),
		SecurityProbeIDs: probes, RobotsAllowed: facts.RobotsAllowed, PrimaryClass: primary,
	}
	if err := event.Validate(); err != nil {
		return domain.Event{}, nil, err
	}
	return event, canonical, nil
}

func canonicalPath(parsed *url.URL, actionable *string) *string {
	if actionable == nil {
		return nil
	}
	path := parsed.Path
	if path == "" {
		path = "/"
	}
	return &path
}
