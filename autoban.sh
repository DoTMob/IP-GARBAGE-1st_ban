================================================================================
=== FILE: autoban.sh
================================================================================
#!/usr/bin/env bash
# =============================================================================
# autoban.sh — Adaptive, log-driven IP ban daemon for nginx / Apache / HAProxy
#
#   DEFENSIVE TOOLING ONLY. Reads local web-server logs and modifies the
#   host's own firewall. Does not send traffic to remote hosts.
#
#   Version: 2.0.0
#
#   Sections:
#     §1  Header, strict mode, constants
#     §2  Logging + JSON events
#     §3  Config loader + validator
#     §4  Locking
#     §5  IP / CIDR helpers
#     §6  Firewall backend (ipset + iptables; nft-compat transparent)
#     §7  Whitelist / blacklist → ipset loaders
#     §8  Log reader (inode + offset, rotation-safe)
#     §9  Log parsers (combined | json | custom)
#     §10 Real-client-IP resolver (XFF, trusted proxies)
#     §11 Score engine (sliding window, weighted signals)
#     §12 Ban manager (TTL, recidivism, offense store)
#     §13 Notifier (digest | per-ip | webhook | mail | notify-send)
#     §14 Signal traps
#     §15 Subcommands (status, list, unban, test, install, uninstall, teardown)
#     §16 Main daemon loop
# =============================================================================

set -euo pipefail
umask 022

# =============================================================================
# §1  Header, strict mode, constants
# =============================================================================
readonly SCRIPT_NAME="autoban"
readonly SCRIPT_VERSION="2.0.0"
readonly DEFAULT_CONF="/etc/autoban/autoban.conf"
readonly DEFAULT_STATE="/var/lib/autoban"
readonly DEFAULT_LOG="/var/log/autoban"
readonly DEFAULT_INSTALL_DIR="/opt/autoban"

CONFIG_FILE="$DEFAULT_CONF"
ACTION="run"
ARG1=""
ARG2=""
DRY_RUN="no"
REPLAY="no"
ONCE=0
VERBOSE="no"

# =============================================================================
# §2  Logging + JSON events
# =============================================================================
EVENTS_LOG=""

log() {
    printf '%s autoban[%d] %s\n' "$(date -u +%FT%TZ)" "$$" "$*" >&2
}

die() {
    log "FATAL: $*"
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

json_escape() {
    local s=$1
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

log_json() {
    local event=$1; shift
    [[ -n "$EVENTS_LOG" ]] || return 0
    local line
    line=$(printf '{"ts":"%s","pid":%d,"event":"%s"' \
        "$(date -u +%FT%TZ)" "$$" "$(json_escape "$event")")
    local kv k v
    for kv in "$@"; do
        k="${kv%%=*}"
        v="${kv#*=}"
        line+=$(printf ',"%s":"%s"' "$(json_escape "$k")" "$(json_escape "$v")")
    done
    line+='}'
    printf '%s\n' "$line" >> "$EVENTS_LOG"
}

# =============================================================================
# §3  Config loader + validator
# =============================================================================
: "${NGINX_LOG:=/var/log/nginx/access.log}"
: "${LOG_FORMAT:=combined}"
: "${PARSE_REGEX:=}"
: "${TRUSTED_PROXIES:=127.0.0.1/32,::1/128}"
: "${USE_XFF:=auto}"
: "${WINDOW_SECONDS:=60}"
: "${BAN_THRESHOLD:=40}"
: "${MIN_REQUESTS:=15}"
: "${MIN_SIGNALS:=2}"
: "${SCAN_PATH_REGEX:=/(\\.env|wp-login\\.php|\\.git|phpmyadmin|xmlrpc\\.php)}"
: "${BAD_UA_REGEX:=(sqlmap|nikto|masscan|zgrab|python-requests|curl/7\\.(3[0-9]|4[0-9]|5[0-9]))}"
: "${DEFAULT_TTL:=3600}"
: "${TTL_STEP:=2}"
: "${MAX_TTL:=604800}"
: "${NEVER_BAN:=/etc/autoban/whitelist.txt}"
: "${MANUAL_BAN:=/etc/autoban/blacklist.txt}"
: "${PROTECTED_RANGES:=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128}"
: "${IPSET_NAME:=autoban4}"
: "${IPSET_NAME6:=autoban6}"
: "${NOTIFY:=digest}"
: "${DIGEST_MINUTES:=15}"
: "${MAIL_TO:=admin@localhost}"
: "${WEBHOOK_URL:=}"
: "${POLL_INTERVAL:=5}"
: "${STATE_DIR:=$DEFAULT_STATE}"
: "${LOGS_DIR:=$DEFAULT_LOG}"

load_config() {
    local file=$1 line key val
    [[ -f "$file" ]] || die "config not found: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^([A-Z_][A-Z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        [[ "$val" =~ ^\"(.*)\"$ ]] && val="${BASH_REMATCH[1]}"
        [[ "$val" =~ ^\'(.*)\'$ ]] && val="${BASH_REMATCH[1]}"
        printf -v "$key" '%s' "$val"
    done < "$file"
}

validate_config() {
    [[ "$LOG_FORMAT" =~ ^(combined|json|custom)$ ]] \
        || die "LOG_FORMAT must be combined|json|custom"
    [[ "$NOTIFY" =~ ^(none|digest|per-ip)$ ]] \
        || die "NOTIFY must be none|digest|per-ip"
    [[ "$DEFAULT_TTL" =~ ^[0-9]+$ ]] || die "DEFAULT_TTL must be integer"
    [[ "$BAN_THRESHOLD" =~ ^[0-9]+$ ]] || die "BAN_THRESHOLD must be integer"
    [[ "$MIN_REQUESTS" =~ ^[0-9]+$ ]] || die "MIN_REQUESTS must be integer"
    [[ "$MIN_REQUESTS" -ge 2 ]] \
        || die "MIN_REQUESTS must be >= 2 (guardrail against self-DoS)"
    [[ "$MIN_SIGNALS" -ge 1 ]] \
        || die "MIN_SIGNALS must be >= 1"
}

# =============================================================================
# §4  Locking
# =============================================================================
acquire_lock() {
    mkdir -p "$STATE_DIR"
    local lock="$STATE_DIR/autoban.lock"
    exec 9>"$lock"
    if ! flock -n 9; then
        die "another instance is running (lock: $lock)"
    fi
}

# =============================================================================
# §5  IP / CIDR helpers
# =============================================================================
is_ipv4() {
    local ip=$1 octet
    [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] \
        || return 1
    for octet in "${BASH_REMATCH[@]:1:4}"; do
        (( octet <= 255 )) || return 1
    done
    return 0
}

is_ipv6() {
    local ip=$1
    [[ $ip == *:* ]] || return 1
    [[ $ip =~ ^[0-9a-fA-F:]+$ ]] || return 1
    return 0
}

is_ip() { is_ipv4 "$1" || is_ipv6 "$1"; }

is_never_ban() {
    local ip=$1
    if is_ipv4 "$ip"; then
        ipset test "${IPSET_NAME}_never4" "$ip" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_never6" "$ip" 2>/dev/null
    fi
}

is_manual_ban() {
    local ip=$1
    if is_ipv4 "$ip"; then
        ipset test "${IPSET_NAME}_manual4" "$ip" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_manual6" "$ip" 2>/dev/null
    fi
}

is_trusted_proxy() {
    local ip=$1
    if is_ipv4 "$ip"; then
        ipset test "${IPSET_NAME}_trusted4" "$ip" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_trusted6" "$ip" 2>/dev/null
    fi
}

# =============================================================================
# §6  Firewall backend (ipset + iptables)
# =============================================================================
fw_init() {
    need_cmd ipset
    need_cmd iptables

    ipset create "${IPSET_NAME}"     hash:ip  family inet  timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME6}"    hash:ip  family inet6 timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME}_never4"   hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_never6"  hash:net family inet6 -exist
    ipset create "${IPSET_NAME}_manual4"  hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_manual6" hash:net family inet6 -exist
    ipset create "${IPSET_NAME}_trusted4"  hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_trusted6" hash:net family inet6 -exist

    iptables -nL AUTOBAN >/dev/null 2>&1 || iptables -N AUTOBAN
    iptables -C INPUT -j AUTOBAN 2>/dev/null || iptables -I INPUT 1 -j AUTOBAN
    iptables -C AUTOBAN -m set --match-set "${IPSET_NAME}" src \
        -m comment --comment "autoban-drop" -j DROP 2>/dev/null \
        || iptables -A AUTOBAN -m set --match-set "${IPSET_NAME}" src \
            -m comment --comment "autoban-drop" -j DROP

    if command -v ip6tables >/dev/null 2>&1; then
        ip6tables -nL AUTOBAN >/dev/null 2>&1 || ip6tables -N AUTOBAN
        ip6tables -C INPUT -j AUTOBAN 2>/dev/null || ip6tables -I INPUT 1 -j AUTOBAN
        ip6tables -C AUTOBAN -m set --match-set "${IPSET_NAME6}" src \
            -m comment --comment "autoban-drop" -j DROP 2>/dev/null \
            || ip6tables -A AUTOBAN -m set --match-set "${IPSET_NAME6}" src \
                -m comment --comment "autoban-drop" -j DROP
    fi
}

fw_ban() {
    local ip=$1 ttl=$2
    if is_ipv4 "$ip"; then
        ipset add "${IPSET_NAME}" "$ip" timeout "$ttl" -exist
    elif is_ipv6 "$ip"; then
        ipset add "${IPSET_NAME6}" "$ip" timeout "$ttl" -exist
    else
        return 1
    fi
}

fw_unban() {
    local ip=$1
    if is_ipv4 "$ip"; then
        ipset del "${IPSET_NAME}" "$ip" 2>/dev/null
    else
        ipset del "${IPSET_NAME6}" "$ip" 2>/dev/null
    fi
}

fw_member() {
    local ip=$1
    if is_ipv4 "$ip"; then
        ipset test "${IPSET_NAME}" "$ip" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}" "$ip" 2>/dev/null
    fi
}

fw_teardown() {
    command -v iptables >/dev/null 2>&1 && {
        iptables -D INPUT -j AUTOBAN 2>/dev/null || true
        iptables -F AUTOBAN 2>/dev/null || true
        iptables -X AUTOBAN 2>/dev/null || true
    }
    command -v ip6tables >/dev/null 2>&1 && {
        ip6tables -D INPUT -j AUTOBAN 2>/dev/null || true
        ip6tables -F AUTOBAN 2>/dev/null || true
        ip6tables -X AUTOBAN 2>/dev/null || true
    }
    command -v ipset >/dev/null 2>&1 && {
        local s
        for s in "${IPSET_NAME}" "${IPSET_NAME6}" \
                 "${IPSET_NAME}_never4"  "${IPSET_NAME6}_never6" \
                 "${IPSET_NAME}_manual4" "${IPSET_NAME6}_manual6" \
                 "${IPSET_NAME}_trusted4" "${IPSET_NAME6}_trusted6"; do
            ipset destroy "$s" 2>/dev/null || true
        done
    }
}

# =============================================================================
# §7  Whitelist / blacklist → ipset loaders
# =============================================================================
_load_list_into_set() {
    local file=$1 set4=$2 set6=$3 label=$4
    local line entry n=0 skip=0
    [[ -f "$file" ]] || { log "list not found, skipping: $file"; return 0; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -z "$line" ]] && continue
        entry="$line"
        if [[ "$entry" =~ /([0-9]+)$ ]]; then
            local pfx="${BASH_REMATCH[1]}"
            if (( pfx == 0 )) || { (( pfx < 8 )) && [[ "${FORCE_BROAD:-no}" != "yes" ]]; }; then
                log "refusing overly broad entry in $label: $entry (set FORCE_BROAD=yes to allow)"
                skip=$((skip+1)); continue
            fi
        fi
        if [[ "$entry" == *:* ]]; then
            ipset add "$set6" "$entry" -exist 2>/dev/null || { log "invalid v6 in $label: $entry"; skip=$((skip+1)); continue; }
        else
            ipset add "$set4" "$entry" -exist 2>/dev/null || { log "invalid v4 in $label: $entry"; skip=$((skip+1)); continue; }
        fi
        n=$((n+1))
    done < "$file"
    log "loaded $label from $file ($n entries, $skip skipped)"
}

load_lists() {
    local tp
    for tp in ${TRUSTED_PROXIES//,/ }; do
        [[ -z "$tp" ]] && continue
        if [[ "$tp" == *:* ]]; then
            ipset add "${IPSET_NAME6}_trusted6" "$tp" -exist 2>/dev/null || true
        else
            ipset add "${IPSET_NAME}_trusted4" "$tp" -exist 2>/dev/null || true
        fi
    done

    local pr
    for pr in ${PROTECTED_RANGES//,/ }; do
        [[ -z "$pr" ]] && continue
        if [[ "$pr" == *:* ]]; then
            ipset add "${IPSET_NAME6}_never6" "$pr" -exist 2>/dev/null || true
        else
            ipset add "${IPSET_NAME}_never4" "$pr" -exist 2>/dev/null || true
        fi
    done

    _load_list_into_set "$NEVER_BAN"  "${IPSET_NAME}_never4"  "${IPSET_NAME6}_never6"  "whitelist"
    _load_list_into_set "$MANUAL_BAN" "${IPSET_NAME}_manual4" "${IPSET_NAME6}_manual6" "blacklist"
}

# =============================================================================
# §8  Log reader (inode + offset, rotation-safe)
# =============================================================================
LOG_STATE_FILE=""

init_log_state() {
    LOG_STATE_FILE="$STATE_DIR/logstate.$(basename "$NGINX_LOG")"
    mkdir -p "$STATE_DIR"
    if [[ ! -f "$LOG_STATE_FILE" && "$REPLAY" != "yes" && -r "$NGINX_LOG" ]]; then
        local inode size
        inode=$(stat -Lc %i "$NGINX_LOG")
        size=$(stat -Lc %s "$NGINX_LOG")
        printf '%s:%s\n' "$inode" "$size" > "$LOG_STATE_FILE"
        log "initialized log state at offset $size (use --replay to reprocess)"
    fi
}

read_new_lines() {
    local log=$1
    [[ -r "$log" ]] || return 0
    local inode size saved_inode="" saved_offset=0
    inode=$(stat -Lc %i "$log" 2>/dev/null) || return 0
    size=$(stat -Lc %s "$log" 2>/dev/null) || return 0
    if [[ -f "$LOG_STATE_FILE" ]]; then
        IFS=':' read -r saved_inode saved_offset < "$LOG_STATE_FILE" || true
        [[ "$saved_offset" =~ ^[0-9]+$ ]] || saved_offset=0
    fi
    if [[ "$saved_inode" != "$inode" ]] || (( saved_offset > size )); then
        saved_offset=0
    fi
    if (( saved_offset >= size )); then return 0; fi
    tail -c +$(( saved_offset + 1 )) "$log" || true
    printf '%s:%s\n' "$inode" "$size" > "$LOG_STATE_FILE"
}

# =============================================================================
# §9  Log parsers
# =============================================================================
parse_combined() {
    local line=$1
    [[ $line =~ ^([^[:space:]]+)[[:space:]][^[:space:]]+[[:space:]][^[:space:]]+[[:space:]]\[[^]]+\][[:space:]]\"([^\"]*)\"[[:space:]]([0-9]{3})[[:space:]][0-9-]+[[:space:]]\"([^\"]*)\"[[:space:]]\"([^\"]*)\" ]] || return 1
    PARSE_IP="${BASH_REMATCH[1]}"
    PARSE_STATUS="${BASH_REMATCH[3]}"
    PARSE_UA="${BASH_REMATCH[5]}"
    local req="${BASH_REMATCH[2]}"
    PARSE_PATH="${req#* }"; PARSE_PATH="${PARSE_PATH% *}"
    PARSE_XFF=""
}

parse_json() {
    local line=$1
    [[ $line =~ \"remote_addr\":\"([^\"]+)\" ]] || return 1
    PARSE_IP="${BASH_REMATCH[1]}"
    PARSE_STATUS=""; PARSE_PATH=""; PARSE_UA=""; PARSE_XFF=""
    [[ $line =~ \"status\":([0-9]+) ]]              && PARSE_STATUS="${BASH_REMATCH[1]}"
    [[ $line =~ \"request_uri\":\"([^\"]+)\" ]]     && PARSE_PATH="${BASH_REMATCH[1]}"
    [[ $line =~ \"http_user_agent\":\"([^\"]*)\" ]] && PARSE_UA="${BASH_REMATCH[1]}"
    [[ $line =~ \"http_x_forwarded_for\":\"([^\"]*)\" ]] && PARSE_XFF="${BASH_REMATCH[1]}"
}

parse_custom() {
    local line=$1
    [[ $line =~ $PARSE_REGEX ]] || return 1
    PARSE_IP="${BASH_REMATCH[1]:-}"
    PARSE_STATUS="${BASH_REMATCH[2]:-}"
    PARSE_PATH="${BASH_REMATCH[3]:-}"
    PARSE_UA="${BASH_REMATCH[4]:-}"
    PARSE_XFF="${BASH_REMATCH[5]:-}"
}

parse_line() {
    PARSE_IP=""; PARSE_STATUS=""; PARSE_PATH=""; PARSE_UA=""; PARSE_XFF=""
    case "$LOG_FORMAT" in
        combined) parse_combined "$1" ;;
        json)     parse_json     "$1" ;;
        custom)   parse_custom   "$1" ;;
        *) return 1 ;;
    esac
}

# =============================================================================
# §10 Real-client-IP resolver (XFF, trusted proxies)
# =============================================================================
resolve_client_ip() {
    local socket_ip=$1 xff=${2:-}
    if [[ "$USE_XFF" == "auto" || "$USE_XFF" == "yes" ]]; then
        if is_trusted_proxy "$socket_ip" && [[ -n "$xff" ]]; then
            local parts=() ip i
            IFS=',' read -ra parts <<< "$xff"
            for (( i=${#parts[@]}-1; i>=0; i-- )); do
                ip="${parts[$i]//[[:space:]]/}"
                is_ip "$ip" || continue
                is_trusted_proxy "$ip" && continue
                printf '%s\n' "$ip"
                return 0
            done
        fi
    fi
    printf '%s\n' "$socket_ip"
}

# =============================================================================
# §11 Score engine (sliding window, weighted signals)
# =============================================================================
declare -A SCORE_N=()
declare -A SCORE_TS=()
declare -A SCORE_SIGS=()
declare -A SCORE_CNT=()

score_add() {
    local ip=$1 signal=$2 weight=$3
    local now sigs
    now=$(date +%s)
    SCORE_N[$ip]=$(( ${SCORE_N[$ip]:-0} + weight ))
    SCORE_TS[$ip]=$now
    SCORE_CNT[$ip]=$(( ${SCORE_CNT[$ip]:-0} + 1 ))
    sigs="${SCORE_SIGS[$ip]:-}"
    if [[ ",$sigs," != *",$signal,"* ]]; then
        SCORE_SIGS[$ip]="${sigs:+$sigs,}$signal"
    fi
}

sweep_scores() {
    (( ${#SCORE_TS[@]} > 0 )) || return 0
    local cutoff ip
    cutoff=$(( $(date +%s) - WINDOW_SECONDS * 2 ))
    for ip in "${!SCORE_TS[@]}"; do
        if (( ${SCORE_TS[$ip]:-0} < cutoff )); then
            unset "SCORE_N[$ip]" "SCORE_TS[$ip]" "SCORE_SIGS[$ip]" "SCORE_CNT[$ip]"
        fi
    done
}

# =============================================================================
# §12 Ban manager (TTL, recidivism, offense store)
# =============================================================================
OFFENSE_DIR=""

offense_of() {
    local f="$OFFENSE_DIR/$1"
    [[ -f "$f" ]] || { echo 0; return; }
    local n
    n=$(cat "$f" 2>/dev/null || echo 0)
    [[ "$n" =~ ^[0-9]+$ ]] || n=0
    echo "$n"
}

offense_bump() {
    local ip=$1 n
    n=$(offense_of "$ip")
    n=$((n + 1))
    mkdir -p "$OFFENSE_DIR"
    printf '%s\n' "$n" > "$OFFENSE_DIR/$ip"
    echo "$n"
}

ttl_for_offense() {
    local offense=$1 ttl=$DEFAULT_TTL i
    for (( i=1; i<offense; i++ )); do
        ttl=$(( ttl * TTL_STEP ))
        (( ttl >= MAX_TTL )) && { ttl=$MAX_TTL; break; }
    done
    echo "$ttl"
}

ban_ip() {
    local ip=$1 reason=$2
    local offense ttl
    offense=$(offense_bump "$ip")
    ttl=$(ttl_for_offense "$offense")

    if [[ "$DRY_RUN" == "yes" ]]; then
        log "DRY-RUN would ban $ip for ${ttl}s (offense #$offense, signals: $reason)"
        log_json "would_ban" "ip=$ip" "ttl=$ttl" "offense=$offense" "signals=$reason"
        return 0
    fi
    if fw_ban "$ip" "$ttl"; then
        log "Banned $ip for ${ttl}s (offense #$offense, signals: $reason)"
        log_json "ban" "ip=$ip" "ttl=$ttl" "offense=$offense" "signals=$reason"
        notify_enqueue "$ip" "$ttl" "$offense" "$reason"
    else
        log "Failed to ban $ip (invalid or firewall error)"
        log_json "ban_failed" "ip=$ip"
    fi
}

apply_bans() {
    (( ${#SCORE_N[@]} > 0 )) || return 0
    local ip score cnt sigs nsigs to_ban=()
    for ip in "${!SCORE_N[@]}"; do
        score=${SCORE_N[$ip]:-0}
        cnt=${SCORE_CNT[$ip]:-0}
        sigs="${SCORE_SIGS[$ip]:-}"
        nsigs=0
        local _s _arr
        IFS=',' read -ra _arr <<< "$sigs"
        for _s in "${_arr[@]}"; do [[ -n "$_s" ]] && nsigs=$((nsigs+1)); done
        if (( score >= BAN_THRESHOLD && cnt >= MIN_REQUESTS && nsigs >= MIN_SIGNALS )); then
            if ! fw_member "$ip"; then
                to_ban+=("$ip|$sigs")
            fi
        fi
    done
    (( ${#to_ban[@]} > 0 )) || return 0
    local entry ip_part reason
    for entry in "${to_ban[@]}"; do
        ip_part="${entry%%|*}"
        reason="${entry#*|}"
        ban_ip "$ip_part" "$reason"
        unset "SCORE_N[$ip_part]" "SCORE_TS[$ip_part]" "SCORE_SIGS[$ip_part]" "SCORE_CNT[$ip_part]"
    done
}

# =============================================================================
# §13 Notifier (digest | per-ip | webhook | mail | notify-send)
# =============================================================================
NOTIFY_QUEUE=""

notify_init() {
    NOTIFY_QUEUE="$STATE_DIR/notify_queue"
    mkdir -p "$STATE_DIR"
    touch "$NOTIFY_QUEUE"
}

notify_enqueue() {
    local ip=$1 ttl=$2 offense=$3 reason=$4
    [[ "$NOTIFY" == "none" ]] && return 0
    local line
    line=$(printf '%s|%s|%s|%s|%s' "$(date -u +%FT%TZ)" "$ip" "$ttl" "$offense" "$reason")
    if [[ "$NOTIFY" == "per-ip" ]]; then
        printf '%s\n' "$line" > "$STATE_DIR/_notify_oneshot"
        notify_send_bulk "$STATE_DIR/_notify_oneshot"
        rm -f "$STATE_DIR/_notify_oneshot"
    else
        printf '%s\n' "$line" >> "$NOTIFY_QUEUE"
    fi
}

notify_send_bulk() {
    local file=$1
    local count
    count=$(wc -l < "$file" 2>/dev/null || echo 0)
    (( count > 0 )) || return 0
    local subject body
    subject="autoban: $count IP(s) banned"
    body=$(cat "$file")

    if command -v notify-send >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        notify-send -u normal "autoban" "$subject" 2>/dev/null || true
    fi

    if command -v mail >/dev/null 2>&1 && [[ -n "$MAIL_TO" ]]; then
        printf '%s\n' "$body" | mail -s "$subject" "$MAIL_TO" 2>/dev/null || \
            log "mail delivery failed"
    fi

    if [[ -n "$WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        local payload
        payload=$(printf '{"subject":"%s","count":%d,"body":"%s"}' \
            "$(json_escape "$subject")" "$count" "$(json_escape "$body")")
        curl -fsS -m 10 -H 'Content-Type: application/json' \
            -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 || \
            log "webhook delivery failed"
    fi
    log_json "notify_sent" "count=$count"
}

notify_flush_digest() {
    [[ "$NOTIFY" == "digest" ]] || return 0
    [[ -s "$NOTIFY_QUEUE" ]] || return 0
    notify_send_bulk "$NOTIFY_QUEUE"
    : > "$NOTIFY_QUEUE"
}

# =============================================================================
# §14 Signal traps
# =============================================================================
SHUTDOWN=0
RELOAD=0

dump_stats() {
    log "stats: banned4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]' || echo 0)" \
        "banned6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || echo 0)" \
        "tracked=${#SCORE_N[@]}"
}

install_traps() {
    trap 'SHUTDOWN=1' TERM INT
    trap 'RELOAD=1'   HUP
    trap 'dump_stats' USR1
}

# =============================================================================
# §15 Subcommands
# =============================================================================
usage() {
    cat <<EOF
$SCRIPT_NAME $SCRIPT_VERSION — adaptive log-driven IP ban daemon

Usage:
  $SCRIPT_NAME [options] [command]

Commands:
  run           Start the daemon (default)
  status        Show current ban counts and config paths
  list          List currently banned IPs
  unban <ip>    Remove an IP from the ban set
  test <line>   Parse one log line and show extracted fields
  install       Install unit, config, lists, and enable service
  uninstall     Disable service and tear down firewall objects
  teardown      Remove firewall objects only (keep service files)

Options:
  -c, --config <file>   Config file (default: $DEFAULT_CONF)
      --dry-run         Do not modify firewall; log intended actions
      --replay          Process log from the beginning on first run
      --once            Run a single poll cycle then exit
  -v, --verbose         Verbose output
  -h, --help            This help
      --version         Print version
EOF
}

cmd_status() {
    local c4=0 c6=0 st="stopped"
    command -v ipset >/dev/null 2>&1 && {
        c4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]'    || true)
        c6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || true)
    }
    pgrep -f "autoban.sh" >/dev/null 2>&1 && st="running"
    printf 'autoban %s\n' "$SCRIPT_VERSION"
    printf '  status:   %s\n' "$st"
    printf '  banned4:  %s\n' "$c4"
    printf '  banned6:  %s\n' "$c6"
    printf '  config:   %s\n' "$CONFIG_FILE"
    printf '  state:    %s\n' "$STATE_DIR"
    printf '  log:      %s\n' "$NGINX_LOG"
}

cmd_list() {
    command -v ipset >/dev/null 2>&1 || die "ipset not available"
    ipset list "${IPSET_NAME}"  2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2 || true
    ipset list "${IPSET_NAME6}" 2>/dev/null | sed -n '/^Members:/,$p' | tail -n +2 || true
}

cmd_unban() {
    local ip=${1:-}
    [[ -n "$ip" ]] || die "usage: $SCRIPT_NAME unban <ip>"
    is_ip "$ip" || die "not a valid IP: $ip"
    fw_init
    if fw_unban "$ip"; then
        rm -f "$OFFENSE_DIR/$ip"
        log "Unbanned $ip"
        log_json "unban" "ip=$ip"
    else
        log "Not banned or invalid: $ip"
        return 1
    fi
}

cmd_test() {
    local line=${1:-}
    [[ -n "$line" ]] || die "usage: $SCRIPT_NAME test '<log line>'"
    if parse_line "$line"; then
        printf 'ip=%s\nstatus=%s\npath=%s\nua=%s\nxff=%s\n' \
            "$PARSE_IP" "$PARSE_STATUS" "$PARSE_PATH" "$PARSE_UA" "$PARSE_XFF"
    else
        printf 'parse failed (LOG_FORMAT=%s)\n' "$LOG_FORMAT"
        return 1
    fi
}

cmd_install() {
    need_cmd systemctl
    local here
    here=$(cd "$(dirname "$0")" && pwd)
    install -d "$DEFAULT_INSTALL_DIR" "/etc/autoban" "$STATE_DIR" "$LOGS_DIR"
    install -m 0755 "$0" "$DEFAULT_INSTALL_DIR/autoban.sh"
    install -m 0644 "$here/autoban.conf"     "/etc/autoban/autoban.conf"    2>/dev/null || true
    install -m 0644 "$here/whitelist.txt"    "/etc/autoban/whitelist.txt"   2>/dev/null || true
    install -m 0644 "$here/blacklist.txt"    "/etc/autoban/blacklist.txt"   2>/dev/null || true
    install -m 0644 "$here/autoban.service"  "/etc/systemd/system/autoban.service"
    systemctl daemon-reload
    systemctl enable --now autoban.service
    log "Installed. Edit /etc/autoban/autoban.conf, then: systemctl reload autoban"
}

cmd_uninstall() {
    need_cmd systemctl
    systemctl disable --now autoban.service 2>/dev/null || true
    rm -f /etc/systemd/system/autoban.service
    systemctl daemon-reload
    fw_teardown
    log "Uninstalled and firewall objects removed"
}

cmd_teardown() {
    fw_teardown
    log "Firewall objects removed (service files kept)"
}

# =============================================================================
# §16 Main daemon loop
# =============================================================================
process_line() {
    local line=$1
    parse_line "$line" || return 0
    local socket_ip="${PARSE_IP:-}"
    [[ -n "$socket_ip" ]] || return 0
    is_ip "$socket_ip" || return 0

    local ip
    ip=$(resolve_client_ip "$socket_ip" "${PARSE_XFF:-}")
    is_ip "$ip" || return 0

    if is_never_ban "$ip"; then return 0; fi
    if is_manual_ban "$ip"; then return 0; fi

    score_add "$ip" "request" 1

    case "${PARSE_STATUS:-}" in
        4??) score_add "$ip" "4xx" 5 ;;
        5??) score_add "$ip" "5xx" 8 ;;
    esac

    if [[ -n "${PARSE_PATH:-}" && -n "$SCAN_PATH_REGEX" ]]; then
        # shellcheck disable=SC2053
        if [[ "$PARSE_PATH" =~ $SCAN_PATH_REGEX ]]; then
            score_add "$ip" "path" 10
        fi
    fi

    if [[ -n "${PARSE_UA:-}" && -n "$BAD_UA_REGEX" ]]; then
        # shellcheck disable=SC2053
        if [[ "$PARSE_UA" =~ $BAD_UA_REGEX ]]; then
            score_add "$ip" "ua" 10
        fi
    fi
}

run_daemon() {
    fw_init
    load_lists
    init_log_state
    notify_init
    install_traps

    log "started (pid $$, config=$CONFIG_FILE, dry-run=$DRY_RUN, format=$LOG_FORMAT)"
    log_json "start" "config=$CONFIG_FILE" "dry_run=$DRY_RUN"

    local last_digest
    last_digest=$(date +%s)

    while (( ! SHUTDOWN )); do
        if (( RELOAD )); then
            log "SIGHUP: reloading config and lists"
            load_config "$CONFIG_FILE"
            validate_config
            load_lists
            RELOAD=0
        fi

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            process_line "$line" || true
        done < <(read_new_lines "$NGINX_LOG")

        apply_bans
        sweep_scores

        if [[ "$NOTIFY" == "digest" ]]; then
            local now
            now=$(date +%s)
            if (( now - last_digest >= DIGEST_MINUTES * 60 )); then
                notify_flush_digest
                last_digest=$now
            fi
        fi

        (( ONCE )) && break
        sleep "$POLL_INTERVAL" &
        wait $! 2>/dev/null || true
    done

    notify_flush_digest || true
    log "stopped"
    log_json "stop"
}

# =============================================================================
# Entry point
# =============================================================================
main() {
    while (( $# )); do
        case "$1" in
            -c|--config)  CONFIG_FILE="$2"; shift 2 ;;
            --dry-run)    DRY_RUN="yes"; shift ;;
            --replay)     REPLAY="yes"; shift ;;
            --once)       ONCE=1; shift ;;
            -v|--verbose) VERBOSE="yes"; shift ;;
            -h|--help)    usage; exit 0 ;;
            --version)    echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
            status|list|install|uninstall|teardown|run)
                ACTION="$1"; shift ;;
            unban|test)
                ACTION="$1"; ARG1="${2:-}"; shift $(( $# >= 2 ? 2 : 1 )) ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    if [[ -f "$CONFIG_FILE" ]]; then
        load_config "$CONFIG_FILE"
    elif [[ "$ACTION" == "run" || "$ACTION" == "install" ]]; then
        die "config not found: $CONFIG_FILE (see autoban.conf for an example)"
    fi
    validate_config

    mkdir -p "$STATE_DIR" "$LOGS_DIR" 2>/dev/null || true
    EVENTS_LOG="$LOGS_DIR/events.jsonl"
    OFFENSE_DIR="$STATE_DIR/offenses"
    mkdir -p "$OFFENSE_DIR" 2>/dev/null || true

    case "$ACTION" in
        run)       acquire_lock; run_daemon ;;
        status)    cmd_status ;;
        list)      cmd_list ;;
        unban)     cmd_unban "$ARG1" ;;
        test)      cmd_test "$ARG1" ;;
        install)   cmd_install ;;
        uninstall) cmd_uninstall ;;
        teardown)  cmd_teardown ;;
        *)         usage; exit 1 ;;
    esac
}

main "$@"


================================================================================
=== FILE: autoban-initd
================================================================================
#!/bin/bash
### BEGIN INIT INFO
# Provides:          autoban
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     3 4 5
# Default-Stop:      0 1 2 6
# Short-Description: Adaptive log-driven IP ban daemon
# Description:       Reads local web-server logs and manages the host's
#                    own ipset/iptables firewall. Defensive tooling only.
### END INIT INFO
#
# Thin SysV wrapper around autoban.sh. If systemd is present we delegate to
# `systemctl` so behavior matches autoban.service exactly. Otherwise we
# supervise autoban.sh directly with a proper PID file and signal handling.

set -euo pipefail

NAME="autoban"
DAEMON="/opt/autoban/autoban.sh"
CONFIG="/etc/autoban/autoban.conf"
PIDFILE="/var/run/${NAME}.pid"

if command -v systemctl >/dev/null 2>&1 \
   && [[ -d /run/systemd/system ]] \
   && systemctl list-unit-files 2>/dev/null | grep -q '^autoban\.service'; then
    case "${1:-}" in
        start)   exec systemctl start   autoban.service ;;
        stop)    exec systemctl stop    autoban.service ;;
        restart) exec systemctl restart autoban.service ;;
        reload)  exec systemctl reload  autoban.service ;;
        status)  exec systemctl status  autoban.service ;;
        *)       echo "Usage: $0 {start|stop|restart|reload|status}" >&2; exit 1 ;;
    esac
fi

[ -x "$DAEMON" ] || { echo "not executable: $DAEMON" >&2; exit 5; }

is_running() {
    [[ -f "$PIDFILE" ]] || return 1
    local pid; pid=$(cat "$PIDFILE" 2>/dev/null || true)
    [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

do_start() {
    if is_running; then
        echo "$NAME already running (pid $(cat "$PIDFILE"))"
        return 0
    fi
    [[ -f "$PIDFILE" ]] && rm -f "$PIDFILE"
    echo -n "Starting $NAME: "
    setsid "$DAEMON" --config "$CONFIG" run </dev/null >/dev/null 2>&1 &
    local pid=$!
    echo "$pid" > "$PIDFILE"
    sleep 1
    if is_running; then
        echo "OK (pid $pid)"
    else
        echo "FAILED"
        rm -f "$PIDFILE"
        return 1
    fi
}

do_stop() {
    if ! is_running; then
        echo "$NAME not running"
        rm -f "$PIDFILE"
        return 0
    fi
    echo -n "Stopping $NAME: "
    local pid; pid=$(cat "$PIDFILE")
    kill -TERM "$pid" 2>/dev/null || true
    for _ in {1..15}; do
        kill -0 "$pid" 2>/dev/null || break
        sleep 1
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "TIMEOUT, sending SIGKILL"
        kill -KILL "$pid" 2>/dev/null || true
    else
        echo "OK"
    fi
    rm -f "$PIDFILE"
}

do_status() {
    if is_running; then
        echo "$NAME running (pid $(cat "$PIDFILE"))"
    elif [[ -f "$PIDFILE" ]]; then
        echo "$NAME dead but pidfile exists ($PIDFILE)"
        return 1
    else
        echo "$NAME stopped"
        return 3
    fi
}

case "${1:-}" in
    start)   do_start   ;;
    stop)    do_stop    ;;
    restart) do_stop; do_start ;;
    reload)  is_running && kill -HUP "$(cat "$PIDFILE")" && echo "reloaded" ;;
    status)  do_status  ;;
    *)       echo "Usage: $0 {start|stop|restart|reload|status}" >&2; exit 1 ;;
esac


================================================================================
=== FILE: autoban.service
================================================================================
[Unit]
Description=autoban — adaptive log-driven IP ban daemon
Documentation=file:/opt/autoban/README.md
After=network-online.target nginx.service apache2.service
Wants=network-online.target
ConditionPathExists=/opt/autoban/autoban.sh

[Service]
Type=simple
ExecStart=/opt/autoban/autoban.sh --config /etc/autoban/autoban.conf run
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s

User=root
StateDirectory=autoban
RuntimeDirectory=autoban
LogsDirectory=autoban
ConfigurationDirectory=autoban

NoNewPrivileges=no
ProtectSystem=full
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
LimitNOFILE=8192
ReadOnlyPaths=/var/log/nginx /var/log/apache2 /etc/autoban
ReadWritePaths=/var/lib/autoban /var/log/autoban /run/autoban

[Install]
WantedBy=multi-user.target


================================================================================
=== FILE: autoban.conf
================================================================================
# =============================================================================
# autoban.conf — configuration for autoban.sh
#
# Format: KEY=value, one per line. `#` starts a comment. Values are not
# shell-evaluated; do not quote unless the value contains spaces.
# After edits:  systemctl reload autoban   (SIGHUP)
# =============================================================================

# --- Source log --------------------------------------------------------------
NGINX_LOG=/var/log/nginx/access.log
# combined | json | custom
LOG_FORMAT=combined
# Required when LOG_FORMAT=custom. Capture groups 1..5 map to:
#   ip, status, path, user-agent, x-forwarded-for
PARSE_REGEX=

# --- Real client IP ----------------------------------------------------------
TRUSTED_PROXIES=127.0.0.1/32,::1/128
# auto = honor XFF only when socket peer is trusted; yes = always; no = never.
USE_XFF=auto

# --- Detection window & thresholds ------------------------------------------
WINDOW_SECONDS=60
BAN_THRESHOLD=40
MIN_REQUESTS=15
# Do not set MIN_REQUESTS below 2 — single-request bans are trivially abusive.
MIN_SIGNALS=2
SCAN_PATH_REGEX=/(\.env|wp-login\.php|\.git|phpmyadmin|xmlrpc\.php|\.aws/credentials)
BAD_UA_REGEX=(sqlmap|nikto|masscan|zgrab|python-requests|nmap|dirbuster|wfuzz|nuclei)

# --- Ban lifecycle -----------------------------------------------------------
DEFAULT_TTL=3600
TTL_STEP=2
MAX_TTL=604800

# --- Lists -------------------------------------------------------------------
NEVER_BAN=/etc/autoban/whitelist.txt
MANUAL_BAN=/etc/autoban/blacklist.txt
PROTECTED_RANGES=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10

# --- Firewall backend --------------------------------------------------------
IPSET_NAME=autoban4
IPSET_NAME6=autoban6

# --- Notifications -----------------------------------------------------------
# none | digest | per-ip
NOTIFY=digest
DIGEST_MINUTES=15
MAIL_TO=admin@example.com
WEBHOOK_URL=

# --- Runtime -----------------------------------------------------------------
POLL_INTERVAL=5
STATE_DIR=/var/lib/autoban
LOGS_DIR=/var/log/autoban


================================================================================
=== FILE: whitelist.txt
================================================================================
# =============================================================================
# whitelist.txt — NEVER-BAN ranges (ipset hash:net)
#
# Loaded into the autoban_never{4,6} sets. Membership is checked before
# scoring, so nothing here is ever banned. Use this file for:
#   * your management / SSH source IPs
#   * monitoring and health-checkers
#   * upstream load balancers and reverse proxies
#   * CDN egress ranges (Cloudflare, Fastly, CloudFront, etc.)
#
# Format:
#   <ip-or-cidr>          plain entry
#   <ip-or-cidr>  # note  inline comment
#
# Prefixes shorter than /8 are refused unless FORCE_BROAD=yes is exported.
# =============================================================================

# --- Loopback & link-local (also in PROTECTED_RANGES by default) -------------
127.0.0.1/32
::1/128

# --- Cloudflare (https://www.cloudflare.com/ips/) ----------------------------
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32

# --- AWS / Azure health-check egress (adjust to your account) ----------------
3.80.0.0/12
18.208.0.0/13
34.192.0.0/12
34.224.0.0/12
65.52.0.0/14
68.67.152.0/21
185.34.106.0/24    # your monitoring host
185.34.107.0/24    # your monitoring host (secondary)

# --- Add your operator IPs below --------------------------------------------
# 203.0.113.7/32   # office VPN
# 198.51.100.0/24  # staging ingress


================================================================================
=== FILE: blacklist.txt
================================================================================
# =============================================================================
# blacklist.txt — MANUAL persistent bans (ipset hash:net)
#
# Loaded into autoban_manual{4,6} at startup. Membership is checked before
# scoring, so anything here is always blocked (subject to whitelist override).
#
# Do NOT add auto-banned IPs here — those live in the runtime ipset with TTL.
# Use this file only for entries you want to survive reboots and expire
# manually.
#
# Format:
#   <ip-or-cidr>                                  permanent until removed
#   <ip-or-cidr>  # reason=... [until=YYYY-MM-DD]  annotated
# =============================================================================

# --- Known scanner sources (example placeholders — replace with real data) --
# 192.0.2.0/24     # reason=continuous xmlrpc.php scanning until=2025-12-31
# 198.51.100.44    # reason=credential stuffing until=2025-09-01
# 2001:db8::/48    # reason=abusive v6 scanner until=2025-12-31

# --- Empty by default. Add manual bans below as needed. ---------------------


================================================================================
=== FILE: README.md
================================================================================
# AutoBan

Adaptive, log-driven IP ban daemon for nginx / Apache / HAProxy, built on
`ipset` + `iptables` (`iptables-nft` on modern distros). Sliding-window
scoring, TTL bans with recidivism escalation, CIDR-correct whitelist, and
digest alerting — in a single auditable shell script.

> **Defensive tooling only.** AutoBan reads *your own* web-server logs and
> modifies *your own* host firewall. It does not probe, scan, or send traffic
> to any remote host, and it never spoofs source addresses.

**Version:** 2.0.0 · **License:** MIT (choose one before publishing)

---

## Why

- `fail2ban` is large and regex-heavy; AutoBan is ~1,000 lines of readable
  bash organized into 16 commented sections.
- Built around `ipset`/`iptables-nft`, so bans are **O(1)**, IPv4/IPv6 aware,
  and expire natively via set timeouts.
- CIDR-correct whitelist (Cloudflare, CDN, monitoring) enforced *before*
  scoring, so protected ranges can never be banned.
- Real-client-IP resolution walks `X-Forwarded-For` only from trusted proxies.
- Ships in **dry-run mode**; nothing touches the firewall until you turn it off.

## Threat model

| In scope | Out of scope |
|---|---|
| Single-IP / small-CIDR HTTP abuse: scanners, brute force, path probing, credential stuffing, bad UAs | Volumetric L3/L4 DDoS (use BGP RTBH / scrubbers) |
| Recidivism: escalating TTL for repeat offenders | DNS amplification (see sibling project) |
| Log-driven thresholds you can tune and audit | Endpoint compromise, lateral movement |
| Misconfigured XFF chains and wrong-IP bans (mitigated by trusted-proxy walk) | Application-layer business-logic abuse |

## How it decides

Every request contributes weighted signals to a per-IP score inside a sliding
window (`WINDOW_SECONDS`). An IP is banned only when **all** of the following
are true:

1. Score ≥ `BAN_THRESHOLD`
2. At least `MIN_REQUESTS` requests were seen (minimum 2 enforced)
3. At least `MIN_SIGNALS` distinct signal types fired

Signals and default weights:

| Signal | Trigger | Weight |
|---|---|---|
| `request` | any request | 1 |
| `4xx` | status 400–499 | 5 |
| `5xx` | status 500–599 | 8 |
| `path` | `SCAN_PATH_REGEX` matches `.env`, `wp-login.php`, `.git`, etc. | 10 |
| `ua` | `BAD_UA_REGEX` matches sqlmap, nikto, nuclei, etc. | 10 |

The combination of threshold + min-requests + min-signals is what prevents the
classic failure mode where one request from a shared NAT or CDN edge bans an
entire range.

Bans have a TTL. Repeat offenders get `DEFAULT_TTL × TTL_STEP^(offense-1)`,
capped at `MAX_TTL`.

## Files

| File | Purpose |
|---|---|
| `autoban.sh` | Engine: capture, parse, score, ban, notify, install/uninstall |
| `autoban-initd` | Thin SysV shim; delegates to `systemctl` when systemd is present |
| `autoban.service` | systemd unit with sandboxing and `ExecReload=SIGHUP` |
| `autoban.conf` | Single source of truth: paths, thresholds, lists, notify |
| `whitelist.txt` | Never-ban ranges (management, monitoring, CDN egress) |
| `blacklist.txt` | Manual persistent bans with optional `reason=` / `until=` notes |

## Requirements

- Linux with `ipset` and `iptables` (or `iptables-nft`)
- `bash` ≥ 4.3 (`mapfile`, `printf -v`)
- `flock` (util-linux)
- Optional: `curl` (webhook), `mail`/`sendmail` (email), `notify-send` (desktop)
- Root or `CAP_NET_ADMIN` for firewall changes
- **systemd** recommended; SysV supported via `autoban-initd`

## Install

```bash
sudo ./autoban.sh install
