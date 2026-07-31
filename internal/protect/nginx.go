package protect

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/balyakin/crawlledger/internal/domain"
)

const activeMapName = "crawlledger-active.map"
const httpIncludeName = "crawlledger-http.conf"
const serverIncludeName = "crawlledger-server.conf"

type NginxNames struct {
	Suffix             string
	EmergencyVariable  string
	EmergencyZone      string
	StaticDenyVariable string
}

type staticSignature struct {
	id      string
	pattern string
}

var staticSignatures = []staticSignature{
	{id: "env-file-scan", pattern: `~*(?:^|/)\.env(?:[./?]|\z)`},
	{id: "git-metadata-scan", pattern: `~*(?:^|/)\.git(?:/|\?|\z)`},
	{id: "path-traversal-scan", pattern: `~*(?:^|/|\\|%2f|%5c)(?:\.\.|%2e%2e)(?:/|\\|%2f|%5c|\?|\z)`},
	{id: "log4shell-probe", pattern: `~*\x24\{jndi:`},
	{id: "phpmyadmin-scan", pattern: `~*^/(?:phpmyadmin|pma)/`},
	{id: "shell-probe", pattern: `~*(?:^|/)(?:c99|r57|shell|cmd|wso)\.php(?:\?|\z)`},
	{id: "wp-login-scan", pattern: `~*^/(?:wp-login\.php(?:\?|\z)|wp-admin/)`},
}

func NginxNamesFor(config Config) NginxNames {
	sum := sha256.Sum256([]byte("crawlledger-nginx-name-v1\x00" + config.Site + "\x00" + config.Nginx.ManagedDir))
	suffix := hex.EncodeToString(sum[:4])
	site := strings.ReplaceAll(config.Site, "-", "_")
	prefix := "crawlledger_" + site + "_" + suffix
	return NginxNames{
		Suffix:             suffix,
		EmergencyVariable:  prefix + "_emergency_key",
		EmergencyZone:      prefix + "_emergency",
		StaticDenyVariable: prefix + "_static_deny",
	}
}

func OpaqueRuleKey(site, method, pathPrefix string) string {
	sum := sha256.Sum256([]byte("crawlledger-limit-key-v1\x00" + site + "\x00" + method + "\x00" + pathPrefix))
	return hex.EncodeToString(sum[:16])
}

func RenderProtectionIncludes(config Config) ([]byte, []byte, error) {
	if err := validateRenderConfig(config); err != nil {
		return nil, nil, err
	}
	names := NginxNamesFor(config)
	activePath := filepath.Join(config.Nginx.ManagedDir, activeMapName)
	var http bytes.Buffer
	fmt.Fprintf(&http, "%s\n", HTTPMarker(config.Site))
	fmt.Fprintf(&http, "map \"$request_method|$uri\" $%s {\n", names.EmergencyVariable)
	http.WriteString("    default \"\";\n")
	fmt.Fprintf(&http, "    include %s;\n", nginxQuote(activePath))
	http.WriteString("}\n\n")
	fmt.Fprintf(&http, "map $request_uri $%s {\n", names.StaticDenyVariable)
	http.WriteString("    default 0;\n")
	enabled := make(map[string]bool, len(config.StaticDeny.Enabled))
	for _, identifier := range config.StaticDeny.Enabled {
		enabled[identifier] = true
	}
	for _, signature := range staticSignatures {
		if enabled[signature.id] {
			fmt.Fprintf(&http, "    %s 1;\n", nginxQuote(signature.pattern))
		}
	}
	http.WriteString("}\n\n")
	fmt.Fprintf(
		&http,
		"limit_req_zone $%s zone=%s:1m rate=%dr/s;\n",
		names.EmergencyVariable,
		names.EmergencyZone,
		config.Action.RateRequestsPerSecond,
	)
	var server bytes.Buffer
	fmt.Fprintf(&server, "%s\n", ServerMarker(config.Site))
	fmt.Fprintf(&server, "if ($%s) {\n", names.StaticDenyVariable)
	server.WriteString("    return 403;\n")
	server.WriteString("}\n")
	server.WriteString("limit_req_status 429;\n")
	fmt.Fprintf(&server, "limit_req zone=%s", names.EmergencyZone)
	if config.Action.Burst > 0 {
		fmt.Fprintf(&server, " burst=%d nodelay", config.Action.Burst)
	}
	server.WriteString(";\n")
	return http.Bytes(), server.Bytes(), nil
}

func RenderActiveMap(config Config, rules []ApplyRule) ([]byte, error) {
	if err := validateRenderConfig(config); err != nil {
		return nil, err
	}
	ordered := append([]ApplyRule(nil), rules...)
	sort.Slice(ordered, func(left, right int) bool {
		if len(ordered[left].PathPrefix) != len(ordered[right].PathPrefix) {
			return len(ordered[left].PathPrefix) > len(ordered[right].PathPrefix)
		}
		if ordered[left].Method != ordered[right].Method {
			return ordered[left].Method < ordered[right].Method
		}
		return ordered[left].PathPrefix < ordered[right].PathPrefix
	})
	keys := make(map[string]ApplyRule, len(ordered))
	actions := make(map[string]bool, len(ordered))
	var result bytes.Buffer
	fmt.Fprintf(&result, "%s\n", ActiveMarker(config.Site))
	for _, rule := range ordered {
		if !domain.ValidMethod(rule.Method) || !domain.ValidActionable(rule.PathPrefix) ||
			config.actionExcluded(rule.Method, rule.PathPrefix) {
			return nil, errors.New("active map contains an unsafe action")
		}
		action := actionKey(rule.Method, rule.PathPrefix)
		if actions[action] {
			return nil, errors.New("active map contains a duplicate action")
		}
		actions[action] = true
		opaque := OpaqueRuleKey(config.Site, rule.Method, rule.PathPrefix)
		if previous, collision := keys[opaque]; collision && previous != rule {
			return nil, errors.New("active map opaque key collision")
		}
		keys[opaque] = rule
		quotedPrefix := strings.ReplaceAll(regexp.QuoteMeta(rule.PathPrefix), `\$`, `\x24`)
		pattern := "^" + regexp.QuoteMeta(rule.Method) + `\|` + quotedPrefix
		if !strings.HasSuffix(rule.PathPrefix, "/") {
			pattern += `(?:/|\z)`
		}
		fmt.Fprintf(&result, "    %s %s;\n", nginxQuote("~"+pattern), nginxQuote(opaque))
	}
	return result.Bytes(), nil
}

func HTTPMarker(site string) string {
	return "# CrawlLedger protect http v1 site=" + site
}

func ServerMarker(site string) string {
	return "# CrawlLedger protect server v1 site=" + site
}

func ActiveMarker(site string) string {
	return "# CrawlLedger active map v1 site=" + site
}

func validateRenderConfig(config Config) error {
	if !sitePattern.MatchString(config.Site) || !absoluteCleanPath(config.Nginx.ManagedDir) {
		return errors.New("invalid Nginx rendering identity")
	}
	if err := config.validateAction(); err != nil {
		return err
	}
	return validateUnique(config.StaticDeny.Enabled, domain.ValidProbeID, "static deny ID")
}

func nginxQuote(value string) string {
	var result strings.Builder
	result.Grow(len(value) + 2)
	result.WriteByte('"')
	for _, character := range value {
		switch character {
		case '\\':
			result.WriteString(`\\`)
		case '"':
			result.WriteString(`\"`)
		case '$':
			result.WriteString(`\$`)
		case '\n':
			result.WriteString(`\n`)
		case '\r':
			result.WriteString(`\r`)
		default:
			result.WriteRune(character)
		}
	}
	result.WriteByte('"')
	return result.String()
}
