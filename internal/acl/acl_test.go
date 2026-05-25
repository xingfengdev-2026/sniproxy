package acl

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"*", "example.com", true},
		{".example.com", "example.com", true},
		{".example.com", "www.example.com", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "example.com", false},
		{"example.com", "www.example.com", false},
	}
	for _, tt := range tests {
		if got := Match(tt.pattern, tt.host); got != tt.want {
			t.Fatalf("Match(%q, %q)=%v want %v", tt.pattern, tt.host, got, tt.want)
		}
	}
}
