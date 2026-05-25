package dnsserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	dnsTypeANY  uint16 = 255
	dnsClassIN  uint16 = 1

	rcodeFormatError    = 1
	rcodeServerFail     = 2
	rcodeNotImplemented = 4
)

type Question struct {
	ID       uint16
	Flags    uint16
	Name     string
	Type     uint16
	Class    uint16
	Question []byte
}

func parseQuestion(msg []byte) (*Question, error) {
	if len(msg) < 12 {
		return nil, errors.New("short dns message")
	}
	qd := binary.BigEndian.Uint16(msg[4:6])
	if qd == 0 {
		return nil, errors.New("dns message has no question")
	}
	name, next, err := decodeName(msg, 12)
	if err != nil {
		return nil, err
	}
	if next+4 > len(msg) {
		return nil, errors.New("short dns question")
	}
	return &Question{
		ID:       binary.BigEndian.Uint16(msg[0:2]),
		Flags:    binary.BigEndian.Uint16(msg[2:4]),
		Name:     strings.ToLower(strings.TrimSuffix(name, ".")),
		Type:     binary.BigEndian.Uint16(msg[next : next+2]),
		Class:    binary.BigEndian.Uint16(msg[next+2 : next+4]),
		Question: append([]byte(nil), msg[12:next+4]...),
	}, nil
}

func decodeName(msg []byte, offset int) (string, int, error) {
	var labels []string
	original := offset
	jumped := false
	for jumps := 0; jumps < 32; jumps++ {
		if offset >= len(msg) {
			return "", 0, errors.New("dns name exceeds message")
		}
		l := int(msg[offset])
		switch l & 0xC0 {
		case 0x00:
			offset++
			if l == 0 {
				if !jumped {
					original = offset
				}
				if len(labels) == 0 {
					return ".", original, nil
				}
				return strings.Join(labels, "."), original, nil
			}
			if l > 63 || offset+l > len(msg) {
				return "", 0, errors.New("invalid dns label")
			}
			labels = append(labels, string(msg[offset:offset+l]))
			offset += l
			if !jumped {
				original = offset
			}
		case 0xC0:
			if offset+1 >= len(msg) {
				return "", 0, errors.New("short dns compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(msg[offset:offset+2]) & 0x3FFF)
			if ptr >= len(msg) {
				return "", 0, errors.New("dns compression pointer out of range")
			}
			if !jumped {
				original = offset + 2
			}
			offset = ptr
			jumped = true
		default:
			return "", 0, errors.New("invalid dns label type")
		}
	}
	return "", 0, errors.New("too many dns compression jumps")
}

func syntheticResponse(q *Question, aRecords, aaaaRecords []net.IP, ttl uint32) []byte {
	answers := make([]dnsAnswer, 0, len(aRecords)+len(aaaaRecords))
	if (q.Type == dnsTypeA || q.Type == dnsTypeANY) && q.Class == dnsClassIN {
		for _, ip := range aRecords {
			if v4 := ip.To4(); v4 != nil {
				answers = append(answers, dnsAnswer{typ: dnsTypeA, data: v4})
			}
		}
	}
	if (q.Type == dnsTypeAAAA || q.Type == dnsTypeANY) && q.Class == dnsClassIN {
		for _, ip := range aaaaRecords {
			if v6 := ip.To16(); v6 != nil && v6.To4() == nil {
				answers = append(answers, dnsAnswer{typ: dnsTypeAAAA, data: v6})
			}
		}
	}

	resp := make([]byte, 12, 12+len(q.Question)+len(answers)*32)
	binary.BigEndian.PutUint16(resp[0:2], q.ID)
	flags := uint16(0x8000) | (q.Flags & 0x0100) | 0x0080
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], uint16(len(answers)))
	resp = append(resp, q.Question...)
	for _, answer := range answers {
		resp = append(resp, 0xC0, 0x0C)
		tmp := make([]byte, 10)
		binary.BigEndian.PutUint16(tmp[0:2], answer.typ)
		binary.BigEndian.PutUint16(tmp[2:4], dnsClassIN)
		binary.BigEndian.PutUint32(tmp[4:8], ttl)
		binary.BigEndian.PutUint16(tmp[8:10], uint16(len(answer.data)))
		resp = append(resp, tmp...)
		resp = append(resp, answer.data...)
	}
	return resp
}

func errorResponseFromQuery(q *Question, rcode int) []byte {
	resp := make([]byte, 12, 12+len(q.Question))
	binary.BigEndian.PutUint16(resp[0:2], q.ID)
	flags := uint16(0x8000) | (q.Flags & 0x0100) | 0x0080 | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	resp = append(resp, q.Question...)
	return resp
}

func errorResponseFromMessage(msg []byte, rcode int) []byte {
	resp := make([]byte, 12)
	if len(msg) >= 2 {
		copy(resp[0:2], msg[0:2])
	}
	flags := uint16(0x8000) | uint16(rcode&0x0F)
	if len(msg) >= 4 {
		flags |= binary.BigEndian.Uint16(msg[2:4]) & 0x0100
	}
	binary.BigEndian.PutUint16(resp[2:4], flags)
	return resp
}

type dnsAnswer struct {
	typ  uint16
	data []byte
}

func parseIPs(values []string, want6 bool) ([]net.IP, error) {
	var out []net.IP
	for _, value := range values {
		ip := net.ParseIP(strings.TrimSpace(value))
		if ip == nil {
			return nil, fmt.Errorf("invalid ip address %q", value)
		}
		if want6 {
			ip = ip.To16()
			if ip == nil || ip.To4() != nil {
				return nil, fmt.Errorf("not an ipv6 address %q", value)
			}
		} else {
			ip = ip.To4()
			if ip == nil {
				return nil, fmt.Errorf("not an ipv4 address %q", value)
			}
		}
		out = append(out, ip)
	}
	return out, nil
}
