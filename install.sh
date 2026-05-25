#!/usr/bin/env bash
set -Eeuo pipefail

REPO_URL="${SNIPROXY_REPO_URL:-https://github.com/xingfengdev-2026/sniproxy.git}"
REF="${SNIPROXY_REF:-main}"
SRC_DIR="${SNIPROXY_SRC_DIR:-/usr/local/src/sniproxy}"
INSTALL_DIR="${SNIPROXY_INSTALL_DIR:-/opt/sniproxy}"
CONFIG_DIR="${SNIPROXY_CONFIG_DIR:-/etc/sniproxy}"
SERVICE_FILE="/etc/systemd/system/sniproxy.service"
GO_VERSION="${SNIPROXY_GO_VERSION:-1.25.6}"

log() {
  printf '[sniproxy-install] %s\n' "$*" >&2
}

die() {
  printf '[sniproxy-install] ERROR: %s\n' "$*" >&2
  exit 1
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "run as root"
  fi
}

have_tty() {
  [ -t 0 ] && [ -t 1 ]
}

prompt_default() {
  local var_name="$1"
  local prompt="$2"
  local default_value="$3"
  local value="${!var_name:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  if have_tty; then
    read -r -p "$prompt [$default_value]: " value
    printf '%s' "${value:-$default_value}"
    return
  fi
  printf '%s' "$default_value"
}

prompt_required() {
  local var_name="$1"
  local prompt="$2"
  local value="${!var_name:-}"
  if [ -n "$value" ]; then
    printf '%s' "$value"
    return
  fi
  if have_tty; then
    while [ -z "$value" ]; do
      read -r -p "$prompt: " value
    done
    printf '%s' "$value"
    return
  fi
  die "$var_name is required in non-interactive mode"
}

install_packages() {
  local packages=("$@")
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends "${packages[@]}"
    return
  fi
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y "${packages[@]}"
    return
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y "${packages[@]}"
    return
  fi
  die "no supported package manager found"
}

ensure_tools() {
  local missing=()
  for tool in curl git tar python3 openssl ip; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    log "installing required packages: ${missing[*]}"
    install_packages ca-certificates curl git tar python3 openssl iproute2
  fi
}

go_arch() {
  case "$(uname -m)" in
    x86_64|amd64) printf 'amd64' ;;
    aarch64|arm64) printf 'arm64' ;;
    armv7l) printf 'armv6l' ;;
    i386|i686) printf '386' ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    log "using existing $(go version)"
    return
  fi
  if [ -x /usr/local/go/bin/go ]; then
    export PATH="/usr/local/go/bin:$PATH"
    log "using existing $(go version)"
    return
  fi
  local arch
  arch="$(go_arch)"
  local url="https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"
  log "installing Go ${GO_VERSION} from ${url}"
  curl -fsSL "$url" -o /tmp/go.tgz
  rm -rf /usr/local/go
  tar -C /usr/local -xzf /tmp/go.tgz
  rm -f /tmp/go.tgz
  export PATH="/usr/local/go/bin:$PATH"
  command -v go >/dev/null 2>&1 || die "go install failed"
}

detect_public_ipv4() {
  if [ -n "${SNIPROXY_PUBLIC_IPV4:-}" ]; then
    printf '%s' "$SNIPROXY_PUBLIC_IPV4"
    return
  fi
  curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null ||
    curl -4 -fsS --max-time 5 https://ifconfig.me/ip 2>/dev/null ||
    true
}

detect_public_ipv6() {
  if [ -n "${SNIPROXY_PUBLIC_IPV6:-}" ]; then
    printf '%s' "$SNIPROXY_PUBLIC_IPV6"
    return
  fi
  curl -6 -fsS --max-time 5 https://api64.ipify.org 2>/dev/null || true
}

detect_primary_ipv4() {
  if [ -n "${SNIPROXY_PRIMARY_IPV4:-}" ]; then
    printf '%s' "$SNIPROXY_PRIMARY_IPV4"
    return
  fi
  ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}'
}

detect_local_ips_csv() {
  {
    hostname -I 2>/dev/null | tr ' ' '\n'
    ip -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1
  } | awk 'NF && !seen[$0]++' | paste -sd, -
}

csv_join_nonempty() {
  local first=1
  local item
  for item in "$@"; do
    [ -n "$item" ] || continue
    if [ "$first" -eq 1 ]; then
      printf '%s' "$item"
      first=0
    else
      printf ',%s' "$item"
    fi
  done
}

install_certificate() {
  local domain="$1"
  local public_ipv4="$2"
  local public_ipv6="$3"
  local cert_mode="$4"
  local email="$5"

  mkdir -p "$CONFIG_DIR"
  case "$cert_mode" in
    none)
      printf '|'
      ;;
    existing)
      [ -n "${SNIPROXY_TLS_CERT_FILE:-}" ] || die "SNIPROXY_TLS_CERT_FILE is required for cert mode existing"
      [ -n "${SNIPROXY_TLS_KEY_FILE:-}" ] || die "SNIPROXY_TLS_KEY_FILE is required for cert mode existing"
      printf '%s|%s' "$SNIPROXY_TLS_CERT_FILE" "$SNIPROXY_TLS_KEY_FILE"
      ;;
    letsencrypt)
      if ! command -v certbot >/dev/null 2>&1; then
        log "installing certbot"
        install_packages certbot >&2
      fi
      systemctl stop sniproxy >/dev/null 2>&1 || true
      local email_args=()
      if [ -n "$email" ]; then
        email_args=(--email "$email")
      else
        email_args=(--register-unsafely-without-email)
      fi
      certbot certonly --standalone --non-interactive --agree-tos \
        --preferred-challenges "${SNIPROXY_LE_CHALLENGE:-http}" \
        "${email_args[@]}" -d "$domain" >&2
      printf '/etc/letsencrypt/live/%s/fullchain.pem|/etc/letsencrypt/live/%s/privkey.pem' "$domain" "$domain"
      ;;
    selfsigned)
      local cert="$CONFIG_DIR/tls.crt"
      local key="$CONFIG_DIR/tls.key"
      local san="DNS:${domain}"
      [ -z "$public_ipv4" ] || san="${san},IP:${public_ipv4}"
      [ -z "$public_ipv6" ] || san="${san},IP:${public_ipv6}"
      log "creating self-signed TLS certificate for ${domain}"
      openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
        -keyout "$key" -out "$cert" \
        -subj "/CN=${domain}" \
        -addext "subjectAltName=${san}" >/dev/null 2>&1
      chmod 600 "$key"
      printf '%s|%s' "$cert" "$key"
      ;;
    *)
      die "invalid SNIPROXY_CERT_MODE: $cert_mode"
      ;;
  esac
}

write_config() {
  local domain="$1"
  local public_ipv4="$2"
  local public_ipv6="$3"
  local primary_ipv4="$4"
  local local_ips="$5"
  local cert_file="$6"
  local key_file="$7"
  local port_cleanup="$8"
  local auth_domains="$9"

  mkdir -p "$CONFIG_DIR"
  SNIPROXY_DOMAIN_VALUE="$domain" \
  SNIPROXY_PUBLIC_IPV4_VALUE="$public_ipv4" \
  SNIPROXY_PUBLIC_IPV6_VALUE="$public_ipv6" \
  SNIPROXY_PRIMARY_IPV4_VALUE="$primary_ipv4" \
  SNIPROXY_LOCAL_IPS_VALUE="$local_ips" \
  SNIPROXY_TLS_CERT_FILE_VALUE="$cert_file" \
  SNIPROXY_TLS_KEY_FILE_VALUE="$key_file" \
  SNIPROXY_PORT_CLEANUP_VALUE="$port_cleanup" \
  SNIPROXY_AUTHORITATIVE_DOMAINS_VALUE="$auth_domains" \
  SNIPROXY_EXTRA_DENY_DOMAINS_VALUE="${SNIPROXY_EXTRA_DENY_DOMAINS:-}" \
  SNIPROXY_UPSTREAMS_VALUE="${SNIPROXY_UPSTREAMS:-1.1.1.1:53,8.8.8.8:53}" \
  python3 - <<'PY' > "$CONFIG_DIR/config.json"
import ipaddress
import json
import os
import socket

def csv(name):
    return [x.strip() for x in os.environ.get(name, "").split(",") if x.strip()]

def unique(values):
    out = []
    seen = set()
    for value in values:
        if value and value not in seen:
            out.append(value)
            seen.add(value)
    return out

def prefix(ip):
    parsed = ipaddress.ip_address(ip)
    return f"{ip}/32" if parsed.version == 4 else f"{ip}/128"

domain = os.environ["SNIPROXY_DOMAIN_VALUE"].strip().rstrip(".").lower()
public_ipv4 = os.environ.get("SNIPROXY_PUBLIC_IPV4_VALUE", "").strip()
public_ipv6 = os.environ.get("SNIPROXY_PUBLIC_IPV6_VALUE", "").strip()
primary_ipv4 = os.environ.get("SNIPROXY_PRIMARY_IPV4_VALUE", "").strip()
local_ips = csv("SNIPROXY_LOCAL_IPS_VALUE")
auth_domains = csv("SNIPROXY_AUTHORITATIVE_DOMAINS_VALUE")
extra_deny_domains = csv("SNIPROXY_EXTRA_DENY_DOMAINS_VALUE")
upstreams = csv("SNIPROXY_UPSTREAMS_VALUE")
cert_file = os.environ.get("SNIPROXY_TLS_CERT_FILE_VALUE", "")
key_file = os.environ.get("SNIPROXY_TLS_KEY_FILE_VALUE", "")
port_cleanup = os.environ.get("SNIPROXY_PORT_CLEANUP_VALUE", "true").lower() in ("1", "true", "yes", "on")

try:
    hostnames = [socket.getfqdn(), socket.gethostname()]
except Exception:
    hostnames = []
deny_domains = unique([domain] + [h.strip().rstrip(".").lower() for h in hostnames if h] + extra_deny_domains)
deny_ips = []
for value in unique([public_ipv4, public_ipv6, primary_ipv4] + local_ips):
    try:
        deny_ips.append(prefix(value))
    except ValueError:
        pass
deny_ips = unique(deny_ips)

tls_names = unique([domain, public_ipv4, public_ipv6])

cfg = {
    "port_cleanup": {
        "enabled": port_cleanup,
        "ports": [53, 853, 80, 443, 8443],
        "protocols": ["tcp", "udp"],
        "kill_timeout": "2s",
        "fail_on_error": True,
    },
    "sni": {
        "listen": ":443",
        "target_port": 443,
        "connect_timeout": "10s",
        "handshake_timeout": "5s",
        "idle_timeout": "2m",
        "resolve_cache_ttl": "60s",
        "max_hello_bytes": 65536,
        "max_connections": 200000,
        "allow_domains": csv("SNIPROXY_ALLOW_DOMAINS") or ["*"],
        "deny_domains": deny_domains,
        "deny_target_ips": deny_ips,
        "deny_private_targets": True,
        "buffer_size": 8192,
    },
    "dns": {
        "udp_listen": ":53",
        "tcp_listen": ":53",
        "dot_listen": ":853",
        "doh_listen": ":8443",
        "doh_path": "/dns-query",
        "upstreams": upstreams,
        "timeout": "3s",
        "ttl": 60,
        "authoritative_domains": auth_domains,
        "a_records": [public_ipv4] if public_ipv4 and auth_domains else [],
        "aaaa_records": [public_ipv6] if public_ipv6 and auth_domains else [],
        "max_concurrent_queries": 200000,
        "tls_cert_file": cert_file,
        "tls_key_file": key_file,
        "tls_server_names": tls_names,
        "max_udp_size": 4096,
        "max_dns_message_size": 65535,
    },
    "metrics": {"listen": "127.0.0.1:9090"},
    "logging": {"access": False},
}

print(json.dumps(cfg, indent=2))
PY
  chmod 600 "$CONFIG_DIR/config.json"
}

tune_kernel() {
  cat > /etc/sysctl.d/99-sniproxy.conf <<'EOF'
fs.file-max = 2097152
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOF
  sysctl -p /etc/sysctl.d/99-sniproxy.conf >/dev/null || true
}

fetch_source() {
  if [ -d "$SRC_DIR/.git" ]; then
    log "updating source in $SRC_DIR"
    git -C "$SRC_DIR" fetch --depth 1 origin "$REF"
    git -C "$SRC_DIR" checkout -q FETCH_HEAD
  else
    log "cloning $REPO_URL to $SRC_DIR"
    rm -rf "$SRC_DIR"
    git clone --depth 1 --branch "$REF" "$REPO_URL" "$SRC_DIR"
  fi
}

build_install() {
  mkdir -p "$INSTALL_DIR"
  log "running tests"
  (cd "$SRC_DIR" && go test ./...)
  log "building sniproxy"
  (cd "$SRC_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.buildVersion=${REF}" -o /tmp/sniproxy ./cmd/sniproxy)
  systemctl stop sniproxy >/dev/null 2>&1 || true
  install -m 755 /tmp/sniproxy "$INSTALL_DIR/sniproxy"
  install -m 644 "$SRC_DIR/deploy/sniproxy.service" "$SERVICE_FILE"
  systemctl daemon-reload
}

main() {
  need_root
  ensure_tools

  local domain
  domain="$(prompt_required SNIPROXY_DOMAIN "DoT/DoH domain, for example dns.example.com")"
  domain="${domain%.}"

  local public_ipv4 public_ipv6 primary_ipv4 local_ips
  public_ipv4="$(detect_public_ipv4)"
  public_ipv6="$(detect_public_ipv6)"
  primary_ipv4="$(detect_primary_ipv4)"
  local_ips="$(detect_local_ips_csv)"

  local auth_domains
  auth_domains="$(prompt_default SNIPROXY_AUTHORITATIVE_DOMAINS "Domains that DNS should rewrite to this server IP, comma-separated" "*")"

  local cert_mode
  cert_mode="$(prompt_default SNIPROXY_CERT_MODE "TLS certificate mode: letsencrypt, existing, selfsigned, none" "letsencrypt")"
  local email=""
  if [ "$cert_mode" = "letsencrypt" ]; then
    email="$(prompt_default SNIPROXY_EMAIL "Let's Encrypt email; leave empty to register without email" "")"
  fi

  local port_cleanup
  port_cleanup="$(prompt_default SNIPROXY_PORT_CLEANUP "Enable startup port cleanup for 53/853/80/443/8443" "true")"

  log "domain: $domain"
  log "public IPv4: ${public_ipv4:-none}"
  log "public IPv6: ${public_ipv6:-none}"
  log "primary IPv4: ${primary_ipv4:-none}"
  log "local IPs: ${local_ips:-none}"
  log "DNS rewrite domains: ${auth_domains:-none}"
  log "certificate mode: $cert_mode"

  ensure_go
  fetch_source
  build_install

  local cert_pair cert_file key_file
  cert_pair="$(install_certificate "$domain" "$public_ipv4" "$public_ipv6" "$cert_mode" "$email")"
  cert_file="${cert_pair%%|*}"
  key_file="${cert_pair#*|}"
  [ "$cert_file" = "$key_file" ] && key_file=""

  write_config "$domain" "$public_ipv4" "$public_ipv6" "$primary_ipv4" "$local_ips" "$cert_file" "$key_file" "$port_cleanup" "$auth_domains"
  tune_kernel

  if [ "$port_cleanup" = "true" ] || [ "$port_cleanup" = "1" ] || [ "$port_cleanup" = "yes" ] || [ "$port_cleanup" = "on" ]; then
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
      log "stopping systemd-resolved so sniproxy can own :53"
      systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
    fi
  fi

  log "starting sniproxy"
  systemctl enable --now sniproxy
  sleep 1
  systemctl --no-pager --full status sniproxy | sed -n '1,18p'

  log "installed. config: $CONFIG_DIR/config.json"
  log "metrics: http://127.0.0.1:9090/debug/vars"
}

main "$@"
