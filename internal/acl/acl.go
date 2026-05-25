package acl

import "strings"

func Allowed(host string, allow, deny []string) bool {
	host = normalize(host)
	if host == "" {
		return false
	}
	if MatchAny(deny, host) {
		return false
	}
	if len(allow) == 0 {
		return true
	}
	return MatchAny(allow, host)
}

func MatchAny(patterns []string, host string) bool {
	host = normalize(host)
	for _, p := range patterns {
		if Match(p, host) {
			return true
		}
	}
	return false
}

func Match(pattern, host string) bool {
	host = normalize(host)
	pattern = normalize(pattern)
	if pattern == "" {
		return false
	}
	if pattern == "*" || pattern == "." {
		return true
	}
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*.")
		return strings.HasSuffix(host, "."+suffix)
	}
	if strings.HasPrefix(pattern, ".") {
		suffix := strings.TrimPrefix(pattern, ".")
		return host == suffix || strings.HasSuffix(host, "."+suffix)
	}
	return false
}

func normalize(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	return strings.TrimSuffix(s, ".")
}
