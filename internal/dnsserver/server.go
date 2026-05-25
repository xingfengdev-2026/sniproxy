package dnsserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"expvar"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"sniproxy/internal/acl"
	"sniproxy/internal/config"
)

var (
	dnsQueriesTotal   = expvar.NewInt("dns_queries_total")
	dnsQueriesFailed  = expvar.NewInt("dns_queries_failed")
	dnsSyntheticTotal = expvar.NewInt("dns_synthetic_total")
)

type Server struct {
	cfg         config.DNSConfig
	log         *log.Logger
	sem         chan struct{}
	roundRobin  atomic.Uint64
	aRecords    []net.IP
	aaaaRecords []net.IP
}

func New(cfg config.DNSConfig, logger *log.Logger) *Server {
	var sem chan struct{}
	if cfg.MaxConcurrentQueries > 0 {
		sem = make(chan struct{}, cfg.MaxConcurrentQueries)
	}
	if logger == nil {
		logger = log.Default()
	}
	aRecords, err := parseIPs(cfg.ARecords, false)
	if err != nil {
		logger.Printf("dns a_records ignored: %v", err)
	}
	aaaaRecords, err := parseIPs(cfg.AAAARecords, true)
	if err != nil {
		logger.Printf("dns aaaa_records ignored: %v", err)
	}
	return &Server{
		cfg:         cfg,
		log:         logger,
		sem:         sem,
		aRecords:    aRecords,
		aaaaRecords: aaaaRecords,
	}
}

func (s *Server) Start(ctx context.Context) error {
	if s.cfg.UDPListen != "" {
		if err := s.startUDP(ctx); err != nil {
			return err
		}
	}
	if s.cfg.TCPListen != "" {
		if err := s.startTCP(ctx, s.cfg.TCPListen, false); err != nil {
			return err
		}
	}
	if s.cfg.DoTListen != "" {
		if err := s.startTCP(ctx, s.cfg.DoTListen, true); err != nil {
			return err
		}
	}
	if s.cfg.DoHListen != "" {
		if err := s.startDoH(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) startUDP(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", s.cfg.UDPListen)
	if err != nil {
		return err
	}
	s.log.Printf("dns udp listening on %s", s.cfg.UDPListen)
	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()
	go func() {
		for {
			buf := make([]byte, s.cfg.MaxUDPSize)
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				s.log.Printf("dns udp read: %v", err)
				continue
			}
			packet := append([]byte(nil), buf[:n]...)
			go func() {
				resp := s.handlePacket(ctx, packet)
				if len(resp) > s.cfg.MaxUDPSize {
					resp = setTruncated(resp)
					if len(resp) > 512 {
						resp = resp[:512]
					}
				}
				_, _ = pc.WriteTo(resp, addr)
			}()
		}
	}()
	return nil
}

func (s *Server) startTCP(ctx context.Context, addr string, tlsMode bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if tlsMode {
		cert, err := s.loadCertificate()
		if err != nil {
			_ = ln.Close()
			return err
		}
		ln = tls.NewListener(ln, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})
		s.log.Printf("dns over tls listening on %s", addr)
	} else {
		s.log.Printf("dns tcp listening on %s", addr)
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				s.log.Printf("dns tcp accept: %v", err)
				continue
			}
			go s.handleTCPConn(ctx, conn)
		}
	}()
	return nil
}

func (s *Server) handleTCPConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.Timeout.Duration))
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header))
		if size == 0 || size > s.cfg.MaxDNSMessageSize {
			return
		}
		msg := make([]byte, size)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		resp := s.handlePacket(ctx, msg)
		if len(resp) > s.cfg.MaxDNSMessageSize {
			resp = errorResponseFromMessage(msg, rcodeServerFail)
		}
		out := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(out[:2], uint16(len(resp)))
		copy(out[2:], resp)
		_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.Timeout.Duration))
		if _, err := conn.Write(out); err != nil {
			return
		}
	}
}

func (s *Server) startDoH(ctx context.Context) error {
	cert, err := s.loadCertificate()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc(s.cfg.DoHPath, s.handleDoH)
	srv := &http.Server{
		Addr:              s.cfg.DoHListen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
		},
	}
	ln, err := net.Listen("tcp", s.cfg.DoHListen)
	if err != nil {
		return err
	}
	s.log.Printf("dns over https listening on https://%s%s", s.cfg.DoHListen, s.cfg.DoHPath)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			s.log.Printf("doh server stopped: %v", err)
		}
	}()
	return nil
}

func (s *Server) handleDoH(w http.ResponseWriter, r *http.Request) {
	var msg []byte
	switch r.Method {
	case http.MethodGet:
		q := r.URL.Query().Get("dns")
		if q == "" {
			http.Error(w, "missing dns parameter", http.StatusBadRequest)
			return
		}
		decoded, err := base64.RawURLEncoding.DecodeString(q)
		if err != nil {
			http.Error(w, "invalid dns parameter", http.StatusBadRequest)
			return
		}
		msg = decoded
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/dns-message") {
			http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.cfg.MaxDNSMessageSize)+1))
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return
		}
		if len(body) > s.cfg.MaxDNSMessageSize {
			http.Error(w, "dns message too large", http.StatusRequestEntityTooLarge)
			return
		}
		msg = body
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := s.handlePacket(r.Context(), msg)
	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(resp)
}

func (s *Server) handlePacket(ctx context.Context, msg []byte) []byte {
	dnsQueriesTotal.Add(1)
	if s.sem != nil {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
		default:
			dnsQueriesFailed.Add(1)
			return errorResponseFromMessage(msg, rcodeServerFail)
		}
	}
	q, err := parseQuestion(msg)
	if err != nil {
		dnsQueriesFailed.Add(1)
		return errorResponseFromMessage(msg, rcodeFormatError)
	}
	if s.isAuthoritative(q.Name) {
		dnsSyntheticTotal.Add(1)
		return syntheticResponse(q, s.aRecords, s.aaaaRecords, s.cfg.TTL)
	}
	resp, err := s.forward(ctx, msg)
	if err != nil {
		dnsQueriesFailed.Add(1)
		return errorResponseFromQuery(q, rcodeServerFail)
	}
	return resp
}

func (s *Server) isAuthoritative(name string) bool {
	if len(s.cfg.AuthoritativeDomains) == 0 {
		return false
	}
	return acl.MatchAny(s.cfg.AuthoritativeDomains, name)
}

func (s *Server) forward(ctx context.Context, msg []byte) ([]byte, error) {
	if len(s.cfg.Upstreams) == 0 {
		return nil, errors.New("no upstream dns servers")
	}
	start := int(s.roundRobin.Add(1) % uint64(len(s.cfg.Upstreams)))
	var last error
	for i := 0; i < len(s.cfg.Upstreams); i++ {
		upstream := s.cfg.Upstreams[(start+i)%len(s.cfg.Upstreams)]
		resp, err := s.forwardUDP(ctx, upstream, msg)
		if err == nil {
			return resp, nil
		}
		last = err
	}
	return nil, last
}

func (s *Server) forwardUDP(ctx context.Context, upstream string, msg []byte) ([]byte, error) {
	dialer := &net.Dialer{Timeout: s.cfg.Timeout.Duration}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout.Duration)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout.Duration))
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, s.cfg.MaxDNSMessageSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

func (s *Server) loadCertificate() (tls.Certificate, error) {
	if s.cfg.TLSCertFile != "" || s.cfg.TLSKeyFile != "" {
		if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
			return tls.Certificate{}, errors.New("both tls_cert_file and tls_key_file are required")
		}
		return tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	}
	s.log.Printf("dns tls certificate not configured; using ephemeral self-signed certificate")
	return generateSelfSigned(s.cfg.TLSServerNames)
}

func generateSelfSigned(names []string) (tls.Certificate, error) {
	if len(names) == 0 {
		names = []string{"localhost"}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: names[0],
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, name := range names {
		if ip := net.ParseIP(name); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, name)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func setTruncated(resp []byte) []byte {
	out := append([]byte(nil), resp...)
	if len(out) >= 4 {
		flags := binary.BigEndian.Uint16(out[2:4])
		flags |= 0x0200
		binary.BigEndian.PutUint16(out[2:4], flags)
	}
	return out
}

func debugPacket(msg []byte) string {
	q, err := parseQuestion(msg)
	if err != nil {
		return fmt.Sprintf("invalid:%v", err)
	}
	return fmt.Sprintf("%s/%d", q.Name, q.Type)
}
