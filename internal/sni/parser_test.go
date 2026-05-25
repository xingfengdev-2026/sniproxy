package sni

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestReadClientHelloServerName(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		c := tls.Client(client, &tls.Config{
			ServerName:         "www.example.com",
			InsecureSkipVerify: true,
		})
		done <- c.Handshake()
	}()

	hello, first, err := ReadClientHello(server, 64*1024, time.Second)
	if err != nil {
		t.Fatalf("ReadClientHello: %v", err)
	}
	if hello.ServerName != "www.example.com" {
		t.Fatalf("ServerName=%q", hello.ServerName)
	}
	if len(first) == 0 {
		t.Fatalf("expected captured client hello bytes")
	}
	server.Close()
	<-done
}
