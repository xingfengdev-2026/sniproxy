package main

import (
	"testing"

	"sniproxy/internal/config"
)

func TestShouldStartProxyUsesListenerArray(t *testing.T) {
	cfg := config.SNIConfig{
		Listeners: []config.ProxyListenerConfig{
			{Listen: ":443", Protocol: "tls", TargetPort: 443},
			{Listen: ":80", Protocol: "http", TargetPort: 80},
		},
	}
	if !shouldStartProxy(cfg) {
		t.Fatal("proxy should start when sni.listeners is configured")
	}
}

func TestShouldStartProxyDisabledWhenNoListeners(t *testing.T) {
	if shouldStartProxy(config.SNIConfig{}) {
		t.Fatal("proxy should stay disabled with no listeners")
	}
}
