package sni

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var (
	ErrNotTLSClientHello = errors.New("not a TLS client hello")
	ErrNoServerName      = errors.New("client hello has no server_name")
)

type ClientHello struct {
	ServerName string
}

func ReadClientHello(conn net.Conn, maxBytes int, timeout time.Duration) (*ClientHello, []byte, error) {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	if timeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, nil, err
		}
		defer conn.SetReadDeadline(time.Time{})
	}

	var raw []byte
	var handshake []byte
	handshakeLen := -1

	for handshakeLen < 0 || len(handshake) < 4+handshakeLen {
		if len(raw)+5 > maxBytes {
			return nil, raw, fmt.Errorf("client hello exceeds %d bytes", maxBytes)
		}
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return nil, raw, err
		}
		if header[0] != 22 {
			raw = append(raw, header...)
			return nil, raw, ErrNotTLSClientHello
		}
		recordLen := int(binary.BigEndian.Uint16(header[3:5]))
		if recordLen == 0 || recordLen > 18432 {
			return nil, raw, fmt.Errorf("invalid TLS record length %d", recordLen)
		}
		if len(raw)+5+recordLen > maxBytes {
			return nil, raw, fmt.Errorf("client hello exceeds %d bytes", maxBytes)
		}
		payload := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return nil, raw, err
		}
		raw = append(raw, header...)
		raw = append(raw, payload...)
		handshake = append(handshake, payload...)

		if len(handshake) >= 4 && handshakeLen < 0 {
			if handshake[0] != 1 {
				return nil, raw, ErrNotTLSClientHello
			}
			handshakeLen = int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
			if handshakeLen <= 0 || handshakeLen+4 > maxBytes {
				return nil, raw, fmt.Errorf("invalid client hello length %d", handshakeLen)
			}
		}
	}

	name, err := parseServerName(handshake[:4+handshakeLen])
	if err != nil {
		return nil, raw, err
	}
	return &ClientHello{ServerName: name}, raw, nil
}

func parseServerName(handshake []byte) (string, error) {
	if len(handshake) < 4 || handshake[0] != 1 {
		return "", ErrNotTLSClientHello
	}
	body := handshake[4:]
	if len(body) < 34 {
		return "", ErrNotTLSClientHello
	}
	offset := 34
	if offset >= len(body) {
		return "", ErrNotTLSClientHello
	}
	sessionLen := int(body[offset])
	offset++
	if offset+sessionLen > len(body) {
		return "", ErrNotTLSClientHello
	}
	offset += sessionLen
	if offset+2 > len(body) {
		return "", ErrNotTLSClientHello
	}
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if cipherLen == 0 || cipherLen%2 != 0 || offset+cipherLen > len(body) {
		return "", ErrNotTLSClientHello
	}
	offset += cipherLen
	if offset >= len(body) {
		return "", ErrNotTLSClientHello
	}
	compressionLen := int(body[offset])
	offset++
	if offset+compressionLen > len(body) {
		return "", ErrNotTLSClientHello
	}
	offset += compressionLen
	if offset == len(body) {
		return "", ErrNoServerName
	}
	if offset+2 > len(body) {
		return "", ErrNotTLSClientHello
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(body) {
		return "", ErrNotTLSClientHello
	}
	extensionsEnd := offset + extensionsLen
	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(body[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extensionsEnd {
			return "", ErrNotTLSClientHello
		}
		if extType == 0 {
			return parseSNIExtension(body[offset : offset+extLen])
		}
		offset += extLen
	}
	return "", ErrNoServerName
}

func parseSNIExtension(ext []byte) (string, error) {
	if len(ext) < 2 {
		return "", ErrNotTLSClientHello
	}
	listLen := int(binary.BigEndian.Uint16(ext[:2]))
	if listLen+2 > len(ext) {
		return "", ErrNotTLSClientHello
	}
	offset := 2
	end := 2 + listLen
	for offset+3 <= end {
		nameType := ext[offset]
		nameLen := int(binary.BigEndian.Uint16(ext[offset+1 : offset+3]))
		offset += 3
		if offset+nameLen > end {
			return "", ErrNotTLSClientHello
		}
		if nameType == 0 {
			name := strings.ToLower(strings.TrimSuffix(string(ext[offset:offset+nameLen]), "."))
			if !validHostName(name) {
				return "", fmt.Errorf("invalid server_name %q", name)
			}
			return name, nil
		}
		offset += nameLen
	}
	return "", ErrNoServerName
}

func validHostName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if strings.ContainsAny(name, "/\\:@[]") {
		return false
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
