package classify

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

func MatchProbes(method, rawRequestURI string, status int) []string {
	upperMethod := strings.ToUpper(method)
	low := strings.ToLower(rawRequestURI)
	parsed, _ := url.ParseRequestURI(rawRequestURI)
	decoded := low
	if parsed != nil {
		if value, err := url.PathUnescape(parsed.EscapedPath()); err == nil {
			decoded = strings.ToLower(value)
		}
	}
	failed := status == 400 || status == 401 || status == 403 || status == 404
	get := upperMethod == "GET" || upperMethod == "HEAD"
	var matches []string
	if get && failed && (decoded == "/wp-login.php" || strings.HasPrefix(decoded, "/wp-admin/")) {
		matches = append(matches, "wp-login-scan")
	}
	if decoded == "/.env" || strings.HasPrefix(decoded, "/.env.") {
		matches = append(matches, "env-file-scan")
	}
	if strings.HasPrefix(decoded, "/.git/") {
		matches = append(matches, "git-metadata-scan")
	}
	if get && failed && (strings.HasPrefix(decoded, "/phpmyadmin/") || strings.HasPrefix(decoded, "/pma/")) {
		matches = append(matches, "phpmyadmin-scan")
	}
	if hasPathTraversal(decoded) {
		matches = append(matches, "path-traversal-scan")
	}
	switch strings.ToLower(path.Base(decoded)) {
	case "c99.php", "r57.php", "shell.php", "cmd.php", "wso.php":
		matches = append(matches, "shell-probe")
	}
	if strings.Contains(low, "${jndi:") {
		matches = append(matches, "log4shell-probe")
	}
	sort.Strings(matches)
	return matches
}

func hasPathTraversal(value string) bool {
	for _, segment := range strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' }) {
		if segment == ".." {
			return true
		}
	}
	return false
}
