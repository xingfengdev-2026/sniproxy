package dnsserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestSyntheticAResponse(t *testing.T) {
	query := dnsQuery(0x1234, "example.com", dnsTypeA)
	q, err := parseQuestion(query)
	if err != nil {
		t.Fatalf("parseQuestion: %v", err)
	}
	resp := syntheticResponse(q, []net.IP{net.ParseIP("203.0.113.10")}, nil, 60)
	if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
		t.Fatalf("id mismatch")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 1 {
		t.Fatalf("answer count mismatch")
	}
	if got := resp[len(resp)-4:]; !bytes.Equal(got, net.ParseIP("203.0.113.10").To4()) {
		t.Fatalf("answer rdata=%v", got)
	}
}

func TestDecodeCompressedName(t *testing.T) {
	query := dnsQuery(1, "www.example.com", dnsTypeA)
	msg := append(query, 0xC0, 0x0C)
	name, _, err := decodeName(msg, len(query))
	if err != nil {
		t.Fatalf("decodeName: %v", err)
	}
	if name != "www.example.com" {
		t.Fatalf("name=%q", name)
	}
}

func dnsQuery(id uint16, name string, typ uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], id)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	for _, label := range split(name, '.') {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0)
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp[0:2], typ)
	binary.BigEndian.PutUint16(tmp[2:4], dnsClassIN)
	return append(msg, tmp...)
}

func split(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}
