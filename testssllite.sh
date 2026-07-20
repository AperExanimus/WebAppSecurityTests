#!/usr/bin/env bash
set -euo pipefail

# testssllite.sh
# A small, readable TLS checker for host[:port] based on testssl
# Dependencies: bash, openssl, timeout, awk, sed, grep, date, curl (optional for HTTP headers)

VERSION="0.1.0"

HOST=""
PORT="443"
SNI=""
TIMEOUT_SECS="8"
OUTPUT="text"         # text|json
CHECK_HEADERS="false" # true|false
PATH_FOR_HEADERS="/"

# Results (flat vars for readability)
R_TLS10="unknown"
R_TLS11="unknown"
R_TLS12="unknown"
R_TLS13="unknown"
R_CERT_SUBJECT=""
R_CERT_ISSUER=""
R_CERT_NOT_BEFORE=""
R_CERT_NOT_AFTER=""
R_CERT_DAYS_LEFT=""
R_CERT_HOST_MATCH="unknown"
R_NEGOTIATED_CIPHER="unknown"
R_NEGOTIATED_PROTOCOL="unknown"
R_HSTS="n/a"
R_XCTO="n/a"
R_XFO="n/a"
R_CSP="n/a"
R_SERVER="n/a"
R_ERROR=""

usage() {
  cat <<'EOF'
Usage:
  testssl-lite.sh [options] host[:port]

Options:
  -s, --sni <name>          SNI server name (default: host)
  -t, --timeout <seconds>   Connection timeout (default: 8)
  -o, --output <text|json>  Output format (default: text)
  -H, --headers             Check common HTTP security headers via curl -I
  -p, --path <path>         HTTP path for header check (default: /)
  -h, --help                Show help

Examples:
  ./testssl-lite.sh example.com
  ./testssl-lite.sh example.com:8443 --output json
  ./testssl-lite.sh example.com --headers --path /login
EOF
}

log_err() {
  R_ERROR="$1"
}

require_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || {
      echo "Missing required command: $c" >&2
      exit 1
    }
  done
}

parse_target() {
  local target="$1"

  # Very simple host:port split (IPv6 not handled in this lite script)
  if [[ "$target" == *:* ]]; then
    HOST="${target%%:*}"
    PORT="${target##*:}"
  else
    HOST="$target"
    PORT="443"
  fi

  if [[ -z "$HOST" ]]; then
    echo "Invalid target host." >&2
    exit 1
  fi

  if [[ -z "${SNI}" ]]; then
    SNI="$HOST"
  fi
}

run_s_client() {
  # Args: extra openssl flags (e.g. -tls1_2)
  # Returns openssl combined output to stdout
  local extra_flags=("$@")
  # Feed EOF immediately so s_client exits after handshake attempt.
  timeout "${TIMEOUT_SECS}" openssl s_client \
    -connect "${HOST}:${PORT}" \
    -servername "${SNI}" \
    "${extra_flags[@]}" \
    -brief < /dev/null 2>&1 || true
}

probe_one_protocol() {
  # Args: openssl protocol flag, result var name
  local flag="$1"
  local out

  out="$(run_s_client "$flag")"

  if grep -qiE 'Protocol *:|Cipher *:' <<<"$out" && ! grep -qiE 'handshake failure|wrong version number|no protocols available|unsupported protocol|alert' <<<"$out"; then
    echo "supported"
  else
    echo "not_supported"
  fi
}

probe_protocols() {
  R_TLS10="$(probe_one_protocol -tls1)"
  R_TLS11="$(probe_one_protocol -tls1_1)"
  R_TLS12="$(probe_one_protocol -tls1_2)"

  # TLS 1.3 might not exist on older OpenSSL builds
  if openssl s_client -help 2>&1 | grep -q -- '-tls1_3'; then
    R_TLS13="$(probe_one_protocol -tls1_3)"
  else
    R_TLS13="not_testable"
  fi
}

fetch_leaf_cert_pem() {
  # Print first certificate PEM from s_client output
  run_s_client -showcerts | awk '
    /-----BEGIN CERTIFICATE-----/ {in_cert=1}
    in_cert {print}
    /-----END CERTIFICATE-----/ {exit}
  '
}

analyze_certificate() {
  local cert_pem now_epoch not_after_epoch
  cert_pem="$(fetch_leaf_cert_pem)"

  if [[ -z "$cert_pem" ]]; then
    log_err "Could not retrieve certificate."
    return
  fi

  R_CERT_SUBJECT="$(openssl x509 -noout -subject <<<"$cert_pem" | sed 's/^subject= *//')"
  R_CERT_ISSUER="$(openssl x509 -noout -issuer <<<"$cert_pem" | sed 's/^issuer= *//')"
  R_CERT_NOT_BEFORE="$(openssl x509 -noout -startdate <<<"$cert_pem" | sed 's/^notBefore=//')"
  R_CERT_NOT_AFTER="$(openssl x509 -noout -enddate <<<"$cert_pem" | sed 's/^notAfter=//')"

  # Days left (GNU date; if parsing fails, set unknown)
  if now_epoch="$(date -u +%s 2>/dev/null)" && \
     not_after_epoch="$(date -u -d "$R_CERT_NOT_AFTER" +%s 2>/dev/null)"; then
    R_CERT_DAYS_LEFT="$(( (not_after_epoch - now_epoch) / 86400 ))"
  else
    R_CERT_DAYS_LEFT="unknown"
  fi

  # Hostname check via openssl verify -verify_hostname
  if openssl verify -verify_hostname "$HOST" <(printf '%s\n' "$cert_pem") >/dev/null 2>&1; then
    R_CERT_HOST_MATCH="yes"
  else
    R_CERT_HOST_MATCH="no"
  fi
}

probe_negotiated_session() {
  local out proto cipher
  out="$(run_s_client -tls1_2)"

  proto="$(awk -F': *' '/^Protocol *:/{print $2; exit}' <<<"$out" || true)"
  cipher="$(awk -F': *' '/^Cipher *:/{print $2; exit}' <<<"$out" || true)"

  [[ -n "$proto" ]] && R_NEGOTIATED_PROTOCOL="$proto"
  [[ -n "$cipher" ]] && R_NEGOTIATED_CIPHER="$cipher"

  # If TLS1.2 failed, try generic
  if [[ "$R_NEGOTIATED_PROTOCOL" == "unknown" || "$R_NEGOTIATED_CIPHER" == "unknown" ]]; then
    out="$(run_s_client)"
    proto="$(awk -F': *' '/^Protocol *:/{print $2; exit}' <<<"$out" || true)"
    cipher="$(awk -F': *' '/^Cipher *:/{print $2; exit}' <<<"$out" || true)"
    [[ -n "$proto" ]] && R_NEGOTIATED_PROTOCOL="$proto"
    [[ -n "$cipher" ]] && R_NEGOTIATED_CIPHER="$cipher"
  fi
}

header_value() {
  # Args: full headers, key regex (case-insensitive)
  local headers="$1"
  local key_regex="$2"
  awk -v IGNORECASE=1 -v k="$key_regex" '
    $0 ~ k { sub(/\r$/, "", $0); print; found=1; exit }
    END { if (!found) print "missing" }
  ' <<<"$headers"
}

check_http_headers() {
  local url headers
  url="https://${HOST}:${PORT}${PATH_FOR_HEADERS}"

  if ! command -v curl >/dev/null 2>&1; then
    R_HSTS="curl_not_installed"
    R_XCTO="curl_not_installed"
    R_XFO="curl_not_installed"
    R_CSP="curl_not_installed"
    R_SERVER="curl_not_installed"
    return
  fi

  headers="$(curl -k -sS -I --max-time "${TIMEOUT_SECS}" "$url" 2>/dev/null || true)"
  if [[ -z "$headers" ]]; then
    R_HSTS="unreachable"
    R_XCTO="unreachable"
    R_XFO="unreachable"
    R_CSP="unreachable"
    R_SERVER="unreachable"
    return
  fi

  R_HSTS="$(header_value "$headers" '^Strict-Transport-Security:')"
  R_XCTO="$(header_value "$headers" '^X-Content-Type-Options:')"
  R_XFO="$(header_value "$headers" '^X-Frame-Options:')"
  R_CSP="$(header_value "$headers" '^Content-Security-Policy:')"
  R_SERVER="$(header_value "$headers" '^Server:')"
}

risk_summary() {
  # Very lightweight summary logic
  local notes=()

  [[ "$R_TLS10" == "supported" ]] && notes+=("TLS1.0 enabled")
  [[ "$R_TLS11" == "supported" ]] && notes+=("TLS1.1 enabled")
  [[ "$R_CERT_HOST_MATCH" == "no" ]] && notes+=("Certificate hostname mismatch")

  if [[ "$R_CERT_DAYS_LEFT" != "unknown" && "$R_CERT_DAYS_LEFT" -lt 0 ]]; then
    notes+=("Certificate expired")
  elif [[ "$R_CERT_DAYS_LEFT" != "unknown" && "$R_CERT_DAYS_LEFT" -lt 14 ]]; then
    notes+=("Certificate expires soon (<14 days)")
  fi

  if ((${#notes[@]} == 0)); then
    echo "No immediate high-level issues found by lite checks."
  else
    printf '%s; ' "${notes[@]}" | sed 's/; $//'
  fi
}

print_text() {
  cat <<EOF
== testssl-lite ${VERSION} ==
Target: ${HOST}:${PORT}
SNI: ${SNI}

[Protocols]
  TLS1.0: ${R_TLS10}
  TLS1.1: ${R_TLS11}
  TLS1.2: ${R_TLS12}
  TLS1.3: ${R_TLS13}

[Negotiation]
  Protocol: ${R_NEGOTIATED_PROTOCOL}
  Cipher:   ${R_NEGOTIATED_CIPHER}

[Certificate]
  Subject:     ${R_CERT_SUBJECT}
  Issuer:      ${R_CERT_ISSUER}
  Not Before:  ${R_CERT_NOT_BEFORE}
  Not After:   ${R_CERT_NOT_AFTER}
  Days Left:   ${R_CERT_DAYS_LEFT}
  Host Match:  ${R_CERT_HOST_MATCH}
EOF

  if [[ "$CHECK_HEADERS" == "true" ]]; then
    cat <<EOF

[HTTP Security Headers]
  Strict-Transport-Security: ${R_HSTS}
  X-Content-Type-Options:    ${R_XCTO}
  X-Frame-Options:           ${R_XFO}
  Content-Security-Policy:   ${R_CSP}
  Server:                    ${R_SERVER}
EOF
  fi

  cat <<EOF

[Summary]
  $(risk_summary)
EOF

  if [[ -n "$R_ERROR" ]]; then
    echo
    echo "[Error]"
    echo "  ${R_ERROR}"
  fi
}

json_escape() {
  sed 's/\\/\\\\/g; s/"/\\"/g'
}

print_json() {
  local summary
  summary="$(risk_summary | json_escape)"

  cat <<EOF
{
  "tool": "testssl-lite",
  "version": "${VERSION}",
  "target": {
    "host": "$(printf '%s' "$HOST" | json_escape)",
    "port": "$(printf '%s' "$PORT" | json_escape)",
    "sni": "$(printf '%s' "$SNI" | json_escape)"
  },
  "protocols": {
    "tls1_0": "$(printf '%s' "$R_TLS10" | json_escape)",
    "tls1_1": "$(printf '%s' "$R_TLS11" | json_escape)",
    "tls1_2": "$(printf '%s' "$R_TLS12" | json_escape)",
    "tls1_3": "$(printf '%s' "$R_TLS13" | json_escape)"
  },
  "negotiation": {
    "protocol": "$(printf '%s' "$R_NEGOTIATED_PROTOCOL" | json_escape)",
    "cipher": "$(printf '%s' "$R_NEGOTIATED_CIPHER" | json_escape)"
  },
  "certificate": {
    "subject": "$(printf '%s' "$R_CERT_SUBJECT" | json_escape)",
    "issuer": "$(printf '%s' "$R_CERT_ISSUER" | json_escape)",
    "not_before": "$(printf '%s' "$R_CERT_NOT_BEFORE" | json_escape)",
    "not_after": "$(printf '%s' "$R_CERT_NOT_AFTER" | json_escape)",
    "days_left": "$(printf '%s' "$R_CERT_DAYS_LEFT" | json_escape)",
    "host_match": "$(printf '%s' "$R_CERT_HOST_MATCH" | json_escape)"
  },
  "http_headers": {
    "enabled": ${CHECK_HEADERS},
    "strict_transport_security": "$(printf '%s' "$R_HSTS" | json_escape)",
    "x_content_type_options": "$(printf '%s' "$R_XCTO" | json_escape)",
    "x_frame_options": "$(printf '%s' "$R_XFO" | json_escape)",
    "content_security_policy": "$(printf '%s' "$R_CSP" | json_escape)",
    "server": "$(printf '%s' "$R_SERVER" | json_escape)"
  },
  "summary": "$(printf '%s' "$summary")",
  "error": "$(printf '%s' "$R_ERROR" | json_escape)"
}
EOF
}

main() {
  require_cmd bash openssl timeout awk sed grep date

  if [[ $# -eq 0 ]]; then
    usage
    exit 1
  fi

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -s|--sni)
        SNI="${2:-}"; shift 2 ;;
      -t|--timeout)
        TIMEOUT_SECS="${2:-}"; shift 2 ;;
      -o|--output)
        OUTPUT="${2:-}"; shift 2 ;;
      -H|--headers)
        CHECK_HEADERS="true"; shift ;;
      -p|--path)
        PATH_FOR_HEADERS="${2:-/}"; shift 2 ;;
      -h|--help)
        usage; exit 0 ;;
      -*)
        echo "Unknown option: $1" >&2
        usage
        exit 1 ;;
      *)
        if [[ -n "$HOST" ]]; then
          echo "Only one target is supported in this lite script." >&2
          exit 1
        fi
        parse_target "$1"
        shift ;;
    esac
  done

  if [[ "$OUTPUT" != "text" && "$OUTPUT" != "json" ]]; then
    echo "Invalid output format: $OUTPUT (use text|json)" >&2
    exit 1
  fi

  probe_protocols
  probe_negotiated_session
  analyze_certificate
  [[ "$CHECK_HEADERS" == "true" ]] && check_http_headers

  if [[ "$OUTPUT" == "json" ]]; then
    print_json
  else
    print_text
  fi
}

main "$@"
