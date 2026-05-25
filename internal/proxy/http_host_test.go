package proxy

import "testing"

func TestParseHTTPHost(t *testing.T) {
	tests := []struct {
		name string
		req  string
		want string
	}{
		{
			name: "host",
			req:  "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n",
			want: "example.com",
		},
		{
			name: "case and port",
			req:  "GET / HTTP/1.1\r\nhOsT: Example.COM:80\r\n\r\n",
			want: "example.com",
		},
		{
			name: "ipv6",
			req:  "GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n",
			want: "2001:db8::1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHTTPHost([]byte(tt.req))
			if err != nil {
				t.Fatalf("parseHTTPHost: %v", err)
			}
			if got != tt.want {
				t.Fatalf("host=%q want %q", got, tt.want)
			}
		})
	}
}
