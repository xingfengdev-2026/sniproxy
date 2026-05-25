package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

var (
	errHTTPHeaderTooLarge = errors.New("http header too large")
	errHTTPHostMissing    = errors.New("http host header missing")
)

func readHTTPHost(conn net.Conn, maxBytes int, timeout time.Duration) (string, []byte, error) {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return "", nil, err
		}
		defer conn.SetReadDeadline(time.Time{})
	}

	buf := make([]byte, 0, 2048)
	tmp := make([]byte, 1024)
	for len(buf) < maxBytes {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if headerEnd(buf) >= 0 {
				host, err := parseHTTPHost(buf)
				return host, buf, err
			}
		}
		if err != nil {
			return "", buf, err
		}
	}
	return "", buf, errHTTPHeaderTooLarge
}

func headerEnd(buf []byte) int {
	if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
		return i + 4
	}
	if i := bytes.Index(buf, []byte("\n\n")); i >= 0 {
		return i + 2
	}
	return -1
}

func parseHTTPHost(buf []byte) (string, error) {
	lineEnd := bytes.IndexByte(buf, '\n')
	if lineEnd <= 0 {
		return "", errHTTPHostMissing
	}

	for start := lineEnd + 1; start < len(buf); {
		endRel := bytes.IndexByte(buf[start:], '\n')
		if endRel < 0 {
			break
		}
		end := start + endRel
		line := bytes.TrimRight(buf[start:end], "\r")
		start = end + 1
		if len(line) == 0 {
			break
		}
		if len(line) < 5 || !asciiEqualFold(line[:5], []byte("host:")) {
			continue
		}
		value := strings.TrimSpace(string(line[5:]))
		host, err := cleanHTTPHost(value)
		if err != nil {
			return "", err
		}
		return host, nil
	}

	return "", errHTTPHostMissing
}

func cleanHTTPHost(value string) (string, error) {
	if value == "" {
		return "", errHTTPHostMissing
	}
	value = strings.Trim(value, " \t")
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end < 0 {
			return "", fmt.Errorf("invalid host header %q", value)
		}
		return strings.ToLower(value[1:end]), nil
	}
	if i := strings.LastIndexByte(value, ':'); i > 0 {
		if allDigits(value[i+1:]) {
			value = value[:i]
		}
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if value == "" || strings.ContainsAny(value, "/\\@") {
		return "", fmt.Errorf("invalid host header %q", value)
	}
	return value, nil
}

func asciiEqualFold(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
