package proxy

import (
	"context"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sniproxy/internal/acl"
	"sniproxy/internal/config"
	"sniproxy/internal/sni"
)

var (
	currentConnections = expvar.NewInt("proxy_connections_current")
	totalConnections   = expvar.NewInt("proxy_connections_total")
	failedConnections  = expvar.NewInt("proxy_connections_failed")
	bytesClientToUp    = expvar.NewInt("proxy_bytes_client_to_upstream")
	bytesUpToClient    = expvar.NewInt("proxy_bytes_upstream_to_client")
)

type Server struct {
	cfg     config.SNIConfig
	log     *log.Logger
	sem     chan struct{}
	buffers sync.Pool
	cache   *ipCache
	denyIPs []netip.Prefix
	dialer  net.Dialer
	active  atomic.Int64
	started atomic.Bool
}

func New(cfg config.SNIConfig, logger *log.Logger) *Server {
	var sem chan struct{}
	if cfg.MaxConnections > 0 {
		sem = make(chan struct{}, cfg.MaxConnections)
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{
		cfg: cfg,
		log: logger,
		sem: sem,
		buffers: sync.Pool{New: func() any {
			return make([]byte, cfg.BufferSize)
		}},
		cache:   newIPCache(cfg.ResolveCacheTTL.Duration),
		denyIPs: parseDenyTargetIPs(cfg.DenyTargetIPs, logger),
		dialer: net.Dialer{
			Timeout:       cfg.ConnectTimeout.Duration,
			KeepAlive:     30 * time.Second,
			FallbackDelay: 100 * time.Millisecond,
		},
	}
}

func (s *Server) Start(ctx context.Context) error {
	if len(s.cfg.Listeners) == 0 {
		return nil
	}
	if !s.started.CompareAndSwap(false, true) {
		return nil
	}
	workers := s.cfg.AcceptWorkers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	for _, listener := range s.cfg.Listeners {
		ln, err := net.Listen("tcp", listener.Listen)
		if err != nil {
			return err
		}
		s.log.Printf("%s proxy listening on %s -> :%d", listener.Protocol, listener.Listen, listener.TargetPort)
		go func(ln net.Listener) {
			<-ctx.Done()
			_ = ln.Close()
		}(ln)
		for i := 0; i < workers; i++ {
			go s.acceptLoop(ctx, ln, listener)
		}
	}
	return nil
}

func (s *Server) acceptLoop(ctx context.Context, ln net.Listener, listener config.ProxyListenerConfig) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Printf("sni accept error: %v", err)
			continue
		}
		if s.sem != nil {
			select {
			case s.sem <- struct{}{}:
			default:
				failedConnections.Add(1)
				_ = conn.Close()
				continue
			}
		}
		totalConnections.Add(1)
		currentConnections.Add(1)
		s.active.Add(1)
		go func() {
			defer func() {
				if s.sem != nil {
					<-s.sem
				}
				currentConnections.Add(-1)
				s.active.Add(-1)
			}()
			s.handleConn(ctx, conn, listener)
		}()
	}
}

func (s *Server) handleConn(parent context.Context, client net.Conn, listener config.ProxyListenerConfig) {
	defer client.Close()
	tuneTCP(client)

	host, firstBytes, err := s.readHost(client, listener)
	if err != nil || !acl.Allowed(host, s.cfg.AllowDomains, s.cfg.DenyDomains) {
		failedConnections.Add(1)
		return
	}

	ctx, cancel := context.WithTimeout(parent, s.cfg.ConnectTimeout.Duration)
	defer cancel()
	upstream, err := s.dialTarget(ctx, host, listener.TargetPort)
	if err != nil {
		failedConnections.Add(1)
		s.log.Printf("%s dial %s:%d: %v", listener.Protocol, host, listener.TargetPort, err)
		return
	}
	defer upstream.Close()
	tuneTCP(upstream)

	if _, err := upstream.Write(firstBytes); err != nil {
		failedConnections.Add(1)
		return
	}
	bytesClientToUp.Add(int64(len(firstBytes)))

	errc := make(chan error, 2)
	go func() {
		n, err := s.copy(upstream, client)
		bytesClientToUp.Add(n)
		closeWrite(upstream)
		errc <- err
	}()
	go func() {
		n, err := s.copy(client, upstream)
		bytesUpToClient.Add(n)
		closeWrite(client)
		errc <- err
	}()
	<-errc
	_ = client.Close()
	_ = upstream.Close()
	<-errc
}

func (s *Server) readHost(client net.Conn, listener config.ProxyListenerConfig) (string, []byte, error) {
	switch listener.Protocol {
	case "http":
		return readHTTPHost(client, s.cfg.MaxHelloBytes, s.cfg.HandshakeTimeout.Duration)
	default:
		hello, firstBytes, err := sni.ReadClientHello(client, s.cfg.MaxHelloBytes, s.cfg.HandshakeTimeout.Duration)
		if err != nil {
			return "", firstBytes, err
		}
		return hello.ServerName, firstBytes, nil
	}
}

func (s *Server) dialTarget(ctx context.Context, host string, targetPort int) (net.Conn, error) {
	port := strconv.Itoa(targetPort)
	if !s.cfg.DenyPrivateTargets {
		return s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	}
	ips, err := s.cache.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		if blockedIP(ip.IP) || s.deniedTargetIP(ip.IP) {
			last = fmt.Errorf("target %s resolved to blocked address %s", host, ip.IP)
			continue
		}
		conn, err := s.dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		last = err
	}
	if last == nil {
		last = fmt.Errorf("no usable address for %s", host)
	}
	return nil, last
}

func (s *Server) deniedTargetIP(ip net.IP) bool {
	if len(s.denyIPs) == 0 {
		return false
	}
	addr, ok := netip.AddrFromSlice(normalizeIP(ip))
	if !ok {
		return true
	}
	for _, prefix := range s.denyIPs {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Server) copy(dst, src net.Conn) (int64, error) {
	buf := s.buffers.Get().([]byte)
	defer s.buffers.Put(buf)
	var total int64
	for {
		if s.cfg.IdleTimeout.Duration > 0 {
			_ = src.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout.Duration))
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if s.cfg.IdleTimeout.Duration > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(s.cfg.IdleTimeout.Duration))
			}
			nw, ew := writeFull(dst, buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nw != nr {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if errors.Is(er, io.EOF) {
				return total, nil
			}
			return total, er
		}
	}
}

func writeFull(w io.Writer, p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		n, err := w.Write(p)
		written += n
		p = p[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func tuneTCP(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

func closeWrite(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
	}
}

func blockedIP(ip net.IP) bool {
	ip = normalizeIP(ip)
	if ip == nil {
		return true
	}
	return ip.IsUnspecified() ||
		ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsMulticast()
}

func normalizeIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip.To16()
}

func parseDenyTargetIPs(values []string, logger *log.Logger) []netip.Prefix {
	var out []netip.Prefix
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				logger.Printf("invalid deny_target_ips entry %q: %v", value, err)
				continue
			}
			out = append(out, prefix)
			continue
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			logger.Printf("invalid deny_target_ips entry %q: %v", value, err)
			continue
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		out = append(out, netip.PrefixFrom(addr, bits))
	}
	return out
}

type ipCache struct {
	ttl     time.Duration
	mu      sync.RWMutex
	entries map[string]ipCacheEntry
}

type ipCacheEntry struct {
	ips     []net.IPAddr
	expires time.Time
}

func newIPCache(ttl time.Duration) *ipCache {
	return &ipCache{
		ttl:     ttl,
		entries: make(map[string]ipCacheEntry),
	}
}

func (c *ipCache) lookup(ctx context.Context, host string) ([]net.IPAddr, error) {
	now := time.Now()
	if c.ttl > 0 {
		c.mu.RLock()
		entry, ok := c.entries[host]
		c.mu.RUnlock()
		if ok && now.Before(entry.expires) && len(entry.ips) > 0 {
			return entry.ips, nil
		}
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if c.ttl > 0 {
		c.mu.Lock()
		c.entries[host] = ipCacheEntry{ips: ips, expires: now.Add(c.ttl)}
		c.mu.Unlock()
	}
	return ips, nil
}
