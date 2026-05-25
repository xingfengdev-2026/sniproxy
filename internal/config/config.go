package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		d.Duration = 0
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		if s == "" {
			d.Duration = 0
			return nil
		}
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		d.Duration = v
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(b, &seconds); err != nil {
		return err
	}
	d.Duration = time.Duration(seconds * float64(time.Second))
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}

type Config struct {
	PortCleanup PortCleanupConfig `json:"port_cleanup"`
	SNI         SNIConfig         `json:"sni"`
	DNS         DNSConfig         `json:"dns"`
	Metrics     MetricsConfig     `json:"metrics"`
	Logging     LoggingConfig     `json:"logging"`
}

type PortCleanupConfig struct {
	Enabled     bool     `json:"enabled"`
	Ports       []int    `json:"ports"`
	Protocols   []string `json:"protocols"`
	KillTimeout Duration `json:"kill_timeout"`
	FailOnError bool     `json:"fail_on_error"`
}

type SNIConfig struct {
	Listen             string                `json:"listen"`
	TargetPort         int                   `json:"target_port"`
	Listeners          []ProxyListenerConfig `json:"listeners"`
	AcceptWorkers      int                   `json:"accept_workers"`
	ConnectTimeout     Duration              `json:"connect_timeout"`
	HandshakeTimeout   Duration              `json:"handshake_timeout"`
	IdleTimeout        Duration              `json:"idle_timeout"`
	ResolveCacheTTL    Duration              `json:"resolve_cache_ttl"`
	MaxHelloBytes      int                   `json:"max_hello_bytes"`
	MaxConnections     int64                 `json:"max_connections"`
	AllowDomains       []string              `json:"allow_domains"`
	DenyDomains        []string              `json:"deny_domains"`
	DenyTargetIPs      []string              `json:"deny_target_ips"`
	DenyPrivateTargets bool                  `json:"deny_private_targets"`
	BufferSize         int                   `json:"buffer_size"`
}

type ProxyListenerConfig struct {
	Listen     string `json:"listen"`
	Protocol   string `json:"protocol"`
	TargetPort int    `json:"target_port"`
}

type DNSConfig struct {
	UDPListen            string   `json:"udp_listen"`
	TCPListen            string   `json:"tcp_listen"`
	DoTListen            string   `json:"dot_listen"`
	DoHListen            string   `json:"doh_listen"`
	DoHPath              string   `json:"doh_path"`
	Upstreams            []string `json:"upstreams"`
	Timeout              Duration `json:"timeout"`
	TTL                  uint32   `json:"ttl"`
	AuthoritativeDomains []string `json:"authoritative_domains"`
	ARecords             []string `json:"a_records"`
	AAAARecords          []string `json:"aaaa_records"`
	MaxConcurrentQueries int64    `json:"max_concurrent_queries"`
	TLSCertFile          string   `json:"tls_cert_file"`
	TLSKeyFile           string   `json:"tls_key_file"`
	TLSServerNames       []string `json:"tls_server_names"`
	MaxUDPSize           int      `json:"max_udp_size"`
	MaxDNSMessageSize    int      `json:"max_dns_message_size"`
}

type MetricsConfig struct {
	Listen string `json:"listen"`
}

type LoggingConfig struct {
	Access bool `json:"access"`
}

func Default() Config {
	return Config{
		PortCleanup: PortCleanupConfig{
			Enabled:     false,
			Ports:       []int{53, 853, 80, 443, 8443},
			Protocols:   []string{"tcp", "udp"},
			KillTimeout: Duration{2 * time.Second},
			FailOnError: true,
		},
		SNI: SNIConfig{
			TargetPort: 443,
			Listeners: []ProxyListenerConfig{
				{Listen: ":443", Protocol: "tls", TargetPort: 443},
				{Listen: ":80", Protocol: "http", TargetPort: 80},
			},
			ConnectTimeout:     Duration{10 * time.Second},
			HandshakeTimeout:   Duration{5 * time.Second},
			IdleTimeout:        Duration{0},
			ResolveCacheTTL:    Duration{60 * time.Second},
			MaxHelloBytes:      64 * 1024,
			MaxConnections:     200000,
			AllowDomains:       []string{"*"},
			DenyPrivateTargets: true,
			BufferSize:         8 * 1024,
		},
		DNS: DNSConfig{
			UDPListen:            ":53",
			TCPListen:            ":53",
			DoTListen:            ":853",
			DoHListen:            ":8443",
			DoHPath:              "/dns-query",
			Upstreams:            []string{"1.1.1.1:53", "8.8.8.8:53"},
			Timeout:              Duration{3 * time.Second},
			TTL:                  60,
			MaxConcurrentQueries: 200000,
			TLSServerNames:       []string{"localhost"},
			MaxUDPSize:           4096,
			MaxDNSMessageSize:    65535,
		},
		Metrics: MetricsConfig{
			Listen: "127.0.0.1:9090",
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		if err := cfg.Normalize(); err != nil {
			return nil, err
		}
		return &cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Normalize() error {
	if len(c.PortCleanup.Ports) == 0 {
		c.PortCleanup.Ports = []int{53, 853, 80, 443, 8443}
	}
	for _, port := range c.PortCleanup.Ports {
		if port < 1 || port > 65535 {
			return fmt.Errorf("invalid port_cleanup port %d", port)
		}
	}
	if len(c.PortCleanup.Protocols) == 0 {
		c.PortCleanup.Protocols = []string{"tcp", "udp"}
	}
	for i, proto := range c.PortCleanup.Protocols {
		proto = strings.ToLower(strings.TrimSpace(proto))
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("invalid port_cleanup protocol %q", c.PortCleanup.Protocols[i])
		}
		c.PortCleanup.Protocols[i] = proto
	}
	if c.PortCleanup.KillTimeout.Duration <= 0 {
		c.PortCleanup.KillTimeout = Duration{2 * time.Second}
	}
	if c.SNI.TargetPort == 0 {
		c.SNI.TargetPort = 443
	}
	if len(c.SNI.Listeners) == 0 {
		if c.SNI.Listen != "" {
			c.SNI.Listeners = []ProxyListenerConfig{
				{Listen: c.SNI.Listen, Protocol: "tls", TargetPort: c.SNI.TargetPort},
			}
		} else {
			c.SNI.Listeners = []ProxyListenerConfig{
				{Listen: ":443", Protocol: "tls", TargetPort: 443},
				{Listen: ":80", Protocol: "http", TargetPort: 80},
			}
		}
	}
	for i := range c.SNI.Listeners {
		l := &c.SNI.Listeners[i]
		l.Protocol = strings.ToLower(strings.TrimSpace(l.Protocol))
		if l.Protocol == "" || l.Protocol == "sni" {
			l.Protocol = "tls"
		}
		if l.Protocol != "tls" && l.Protocol != "http" {
			return fmt.Errorf("invalid sni.listeners[%d].protocol %q", i, l.Protocol)
		}
		if l.Listen == "" {
			return fmt.Errorf("sni.listeners[%d].listen is required", i)
		}
		if l.TargetPort == 0 {
			if l.Protocol == "http" {
				l.TargetPort = 80
			} else {
				l.TargetPort = 443
			}
		}
		if l.TargetPort < 1 || l.TargetPort > 65535 {
			return fmt.Errorf("invalid sni.listeners[%d].target_port %d", i, l.TargetPort)
		}
	}
	if c.SNI.AcceptWorkers <= 0 {
		c.SNI.AcceptWorkers = runtime.GOMAXPROCS(0)
	}
	if c.SNI.AcceptWorkers > 128 {
		c.SNI.AcceptWorkers = 128
	}
	if c.SNI.ConnectTimeout.Duration <= 0 {
		c.SNI.ConnectTimeout = Duration{10 * time.Second}
	}
	if c.SNI.HandshakeTimeout.Duration <= 0 {
		c.SNI.HandshakeTimeout = Duration{5 * time.Second}
	}
	if c.SNI.ResolveCacheTTL.Duration <= 0 {
		c.SNI.ResolveCacheTTL = Duration{60 * time.Second}
	}
	if c.SNI.MaxHelloBytes <= 0 {
		c.SNI.MaxHelloBytes = 64 * 1024
	}
	if c.SNI.BufferSize <= 0 {
		c.SNI.BufferSize = 8 * 1024
	}
	if len(c.SNI.AllowDomains) == 0 {
		c.SNI.AllowDomains = []string{"*"}
	}
	if c.DNS.DoHPath == "" {
		c.DNS.DoHPath = "/dns-query"
	}
	if len(c.DNS.Upstreams) == 0 {
		c.DNS.Upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	for i, upstream := range c.DNS.Upstreams {
		if _, _, err := net.SplitHostPort(upstream); err != nil {
			if strings.Contains(err.Error(), "missing port") {
				c.DNS.Upstreams[i] = net.JoinHostPort(upstream, "53")
				continue
			}
			return fmt.Errorf("invalid upstream %q: %w", upstream, err)
		}
	}
	if c.DNS.Timeout.Duration <= 0 {
		c.DNS.Timeout = Duration{3 * time.Second}
	}
	if c.DNS.TTL == 0 {
		c.DNS.TTL = 60
	}
	if c.DNS.MaxUDPSize <= 0 {
		c.DNS.MaxUDPSize = 4096
	}
	if c.DNS.MaxDNSMessageSize <= 0 {
		c.DNS.MaxDNSMessageSize = 65535
	}
	if c.DNS.MaxDNSMessageSize > 65535 {
		return errors.New("max_dns_message_size cannot exceed 65535")
	}
	return nil
}
