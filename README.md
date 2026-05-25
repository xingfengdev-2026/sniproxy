# sniproxy

High-concurrency HTTP Host and TLS SNI passthrough proxy written in Go. It also includes:

- DNS over UDP and TCP
- DNS over TLS
- DNS over HTTPS
- Synthetic DNS answers for configured domains
- JSON configuration
- Local expvar metrics on `127.0.0.1:9090/debug/vars`

## How it works

The TCP proxy listens on a configurable listener array. The default listeners are `:443` for TLS SNI passthrough and `:80` for plain HTTP Host passthrough. It reads only the first TLS ClientHello or HTTP request header, extracts the target host, opens a TCP connection to the same host on the configured target port, writes the original bytes upstream, then pipes both directions. It does not decrypt TLS or parse HTTP bodies.

Do not run it as an unrestricted open relay. Use `deny_domains` and `deny_target_ips` to prevent self-loops and abuse, especially for the proxy server's own public IP and host name.

The DNS service can either forward queries to upstream resolvers or synthesize A/AAAA answers for configured domain suffixes. For SNI proxy use, the installer defaults to wildcard DNS rewrite: every A query answered by this DNS server returns the VPS public IPv4 address. For example, `nslookup 1.2.3.4.nip.io <vps-ip>` should return the VPS IP, not `1.2.3.4`.

## Build

```bash
go test ./...
go build -trimpath -ldflags "-s -w" -o sniproxy ./cmd/sniproxy
```

Cross-compile for Linux amd64:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sniproxy-linux-amd64 ./cmd/sniproxy
```

## Run

```bash
cp configs/sniproxy.example.json config.json
./sniproxy -config config.json
```

The example config enables `port_cleanup` for ports `53`, `853`, `80`, `443`, and `8443`. At startup, sniproxy will force-kill other processes listening on those ports before binding. Disable this section if the machine runs another service that must keep those ports.

DoT and DoH require TLS. If no certificate is configured, the process creates an ephemeral self-signed certificate at startup. That is enough for testing, but production clients need a trusted certificate.

## Install On Linux

After the repo is published, install directly from GitHub:

```bash
curl -fsSL https://github.com/xingfengdev-2026/sniproxy/releases/latest/download/install.sh | bash
```

Non-interactive example:

```bash
SNIPROXY_DOMAIN=dns.example.com \
SNIPROXY_AUTHORITATIVE_DOMAINS='*' \
SNIPROXY_CERT_MODE=letsencrypt \
bash install.sh
```

The installer auto-detects public and local IP addresses, writes the server domain into `deny_domains`, writes the server IPs into `deny_target_ips`, fills `tls_server_names` for DoT/DoH, defaults DNS rewrite to `*`, downloads the prebuilt binary, installs the systemd unit, and applies Linux socket tuning.

The installer downloads the prebuilt Linux package from GitHub Releases. Use `SNIPROXY_VERSION=v0.2.0` to pin a version, or leave it unset to use the latest release.

The default certificate mode is `letsencrypt`, using certbot standalone with the HTTP-01 challenge on port 80. Your `SNIPROXY_DOMAIN` must resolve to the VPS public IP, and port 80 must be reachable from the internet. Use `SNIPROXY_EMAIL=you@example.com` if you want expiry notices; otherwise the installer registers without an email address. The installer also adds a certbot deploy hook to restart sniproxy after renewal.

## Capacity notes

The proxy path uses multiple accept workers per listener, shared DNS resolution cache, shared dialer, goroutine-per-connection I/O, kernel-assisted `io.Copy` when `idle_timeout` is `0s`, pooled copy buffers when application idle deadlines are enabled, and no TLS termination. The default config keeps `idle_timeout` at `0s` for the fastest copy path and relies on TCP keepalive; set it to a non-zero duration if you need strict idle connection expiry. The default copy buffer for deadline mode is 8 KiB to keep memory bounded at very high connection counts. Handling 100,000 simultaneous clients is mainly limited by:

- `ulimit -n` / systemd `LimitNOFILE`
- kernel listen backlog and TCP memory settings
- available RAM
- network bandwidth and upstream target capacity
- DNS resolver throughput

For Linux, use a high file descriptor limit and tune the kernel before large-scale load tests:

```bash
sysctl -w net.core.somaxconn=65535
sysctl -w net.core.netdev_max_backlog=250000
sysctl -w net.ipv4.ip_local_port_range="10000 65000"
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fastopen=3
```

The included systemd unit sets `LimitNOFILE=1048576`.
