package main

import (
	"context"
	"expvar"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sniproxy/internal/config"
	"sniproxy/internal/dnsserver"
	"sniproxy/internal/portcleanup"
	"sniproxy/internal/proxy"
)

var buildVersion = "dev"

func main() {
	configPath := flag.String("config", "config.json", "path to JSON config")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sniproxy %s %s/%s go=%s\n", buildVersion, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if err := portcleanup.Cleanup(cfg.PortCleanup, log.Default()); err != nil {
		log.Fatalf("port cleanup: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	expvar.NewString("sniproxy_version").Set(buildVersion)

	if cfg.Metrics.Listen != "" {
		go func() {
			log.Printf("metrics listening on %s", cfg.Metrics.Listen)
			if err := http.ListenAndServe(cfg.Metrics.Listen, nil); err != nil && err != http.ErrServerClosed {
				log.Printf("metrics server stopped: %v", err)
			}
		}()
	}

	sni := proxy.New(cfg.SNI, log.Default())
	if shouldStartProxy(cfg.SNI) {
		if err := sni.Start(ctx); err != nil {
			log.Fatalf("start sni proxy: %v", err)
		}
	}

	dns := dnsserver.New(cfg.DNS, log.Default())
	if err := dns.Start(ctx); err != nil {
		log.Fatalf("start dns services: %v", err)
	}

	<-ctx.Done()
	log.Printf("shutting down")
	time.Sleep(250 * time.Millisecond)
}

func shouldStartProxy(cfg config.SNIConfig) bool {
	return len(cfg.Listeners) > 0
}
