#!/usr/bin/env bash
# =============================================================================
# autoban.sh — Adaptive, log-driven IP ban daemon for nginx / Apache / HAProxy
#
#   DEFENSIVE TOOLING ONLY. Reads local web-server logs and modifies the
#   host's own firewall. Does not send traffic to remote hosts.
#
#   Version: 2.0.1
#
#   Sections:
#     §1  Header, strict mode, constants
#     §2  Logging + JSON events
#     §3  Config loader + validator
#     §4  Locking
#     §5  IP / CIDR helpers
#     §6  Firewall backend (ipset + iptables; nft-compat transparent)
#     §7  List loaders (whitelist / blacklist / trusted / protected)
#     §8  Log reader (inode + offset, partial-line safe)
#     §9  Log parsers (combined | json | custom)
#     §10 Real-client-IP resolver (XFF, trusted proxies)
#     §11 Score engine (sliding window, weighted signals)
#     §12 Ban manager (TTL, recidivism, offense store)
#     §13 Notifier (digest | per-ip | webhook | mail | notify-send)
#     §14 Signal traps
#     §15 Subcommands (run status list unban test check install uninstall teardown)
#     §16 Main daemon loop
# =============================================================================

set -euo pipefail
umask 022

# =============================================================================
# §1  Constants
# =============================================================================
readonly SCRIPT_NAME="autoban"
readonly SCRIPT_VERSION="2.0.1"
readonly DEFAULT_CONF="/etc/autoban/autoban.conf"
readonly DEFAULT_STATE="/var/lib/autoban"
readonly DEFAULT_LOG="/var/log/autoban"
readonly DEFAULT_INSTALL_DIR="/opt/autoban"

# Allowlist of settable config keys (anything else in the config file is
# ignored with a warning). Prevents a hostile or typo'd config from clobbering
# internal variables like PATH, IFS, or HOME.
readonly VALID_CONFIG_KEYS="NGINX_LOG LOG_FORMAT PARSE_REGEX TRUSTED_PROXIES \
USE_XFF WINDOW_SECONDS BAN_THRESHOLD MIN_REQUESTS MIN_SIGNALS SCAN_PATH_REGEX \
BAD_UA_REGEX DEFAULT_TTL TTL_STEP MAX_TTL NEVER_BAN MANUAL_BAN PROTECTED_RANGES \
IPSET_NAME IPSET_NAME6 NOTIFY DIGEST_MINUTES MAIL_TO WEBHOOK_URL POLL_INTERVAL \
STATE_DIR LOGS_DIR"

CONFIG_FILE="$DEFAULT_CONF"
ACTION="run"
ARG1=""
DRY_RUN="no"
REPLAY="no"
ONCE=0
VERBOSE="no"
CURRENT_TIME=0

# =============================================================================
# §2  Logging + JSON events
# =============================================================================
EVENTS_LOG=""

log() {
    printf '%s autoban[%d] %s\n' "$(date -u +%FT%TZ)" "$$" "$*" >&2
}

verbose() {
    [[ "$VERBOSE" == "yes" ]] && log "$@"
    return 0
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
: "${BAD_UA_REGEX:=(sqlmap|nikto|masscan|zgrab|python-requests|nmap|dirbuster|wfuzz|nuclei)}"
: "${DEFAULT_TTL:=3600}"
: "${TTL_STEP:=2}"
: "${MAX_TTL:=604800}"
: "${NEVER_BAN:=/etc/autoban/whitelist.txt}"
: "${MANUAL_BAN:=/etc/autoban/blacklist.txt}"
: "${PROTECTED_RANGES:=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,169.254.0.0/16,::1/128,fe80::/10}"
: "${IPSET_NAME:=autoban4}"
: "${IPSET_NAME6:=autoban6}"
: "${NOTIFY:=digest}"
: "${DIGEST_MINUTES:=15}"
: "${MAIL_TO:=admin@localhost}"
: "${WEBHOOK_URL:=}"
: "${POLL_INTERVAL:=5}"
: "${STATE_DIR:=$DEFAULT_STATE}"
: "${LOGS_DIR:=$DEFAULT_LOG}"

is_valid_config_key() {
    [[ " ${VALID_CONFIG_KEYS//$'\n'/ } " == *" $1 "* ]]
}

load_config() {
    local file=$1 line key val
    [[ -f "$file" ]] || die "config not found: $file"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        val="${BASH_REMATCH[2]}"
        [[ "$val" =~ ^\"(.*)\"$ ]] && val="${BASH_REMATCH[1]}"
        [[ "$val" =~ ^\'(.*)\'$ ]] && val="${BASH_REMATCH[1]}"
        if is_valid_config_key "$key"; then
            printf -v "$key" '%s' "$val"
        else
            log "warning: unknown config key ignored: $key"
        fi
    done < "$file"
}

validate_config() {
    [[ "$LOG_FORMAT" =~ ^(combined|json|custom)$ ]] \
        || die "LOG_FORMAT must be combined|json|custom"
    [[ "$LOG_FORMAT" == "custom" && -z "$PARSE_REGEX" ]] \
        && die "LOG_FORMAT=custom requires PARSE_REGEX"
    [[ "$NOTIFY" =~ ^(none|digest|per-ip)$ ]] \
        || die "NOTIFY must be none|digest|per-ip"
    [[ "$USE_XFF" =~ ^(auto|yes|no)$ ]] \
        || die "USE_XFF must be auto|yes|no"
    [[ "$DEFAULT_TTL" =~ ^[0-9]+$ ]] || die "DEFAULT_TTL must be integer"
    [[ "$BAN_THRESHOLD" =~ ^[0-9]+$ ]] || die "BAN_THRESHOLD must be integer"
    [[ "$MIN_REQUESTS" =~ ^[0-9]+$ ]] || die "MIN_REQUESTS must be integer"
    [[ "$MIN_REQUESTS" -ge 2 ]] \
        || die "MIN_REQUESTS must be >= 2 (guardrail against self-DoS)"
    [[ "$MIN_SIGNALS" -ge 1 ]] \
        || die "MIN_SIGNALS must be >= 1"
    [[ "$POLL_INTERVAL" =~ ^[0-9]+$ ]] && (( POLL_INTERVAL >= 1 )) \
        || die "POLL_INTERVAL must be integer >= 1"
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
    [[ "$ip" == *:* ]] || return 1
    [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] || return 1
    [[ "$ip" == *":::"* ]] && return 1
    [[ "$ip" =~ [0-9a-fA-F] ]] || return 1
    return 0
}

is_ip() { is_ipv4 "$1" || is_ipv6 "$1"; }

is_never_ban() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}_never4" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_never6" "$1" 2>/dev/null
    fi
}

is_manual_ban() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}_manual4" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_manual6" "$1" 2>/dev/null
    fi
}

is_trusted_proxy() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}_trusted4" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}_trusted6" "$1" 2>/dev/null
    fi
}

# =============================================================================
# §6  Firewall backend (ipset + iptables)
# =============================================================================
fw_init() {
    need_cmd ipset
    need_cmd iptables

    ipset create "${IPSET_NAME}"      hash:ip  family inet  timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME6}"     hash:ip  family inet6 timeout "$DEFAULT_TTL" maxelem 262144 -exist
    ipset create "${IPSET_NAME}_never4"    hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_never6"   hash:net family inet6 -exist
    ipset create "${IPSET_NAME}_manual4"   hash:net family inet  -exist
    ipset create "${IPSET_NAME6}_manual6"  hash:net family inet6 -exist
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
    if is_ipv4 "$1"; then
        ipset del "${IPSET_NAME}" "$1" 2>/dev/null
    elif is_ipv6 "$1"; then
        ipset del "${IPSET_NAME6}" "$1" 2>/dev/null
    else
        return 1
    fi
}

fw_member() {
    if is_ipv4 "$1"; then
        ipset test "${IPSET_NAME}" "$1" 2>/dev/null
    else
        ipset test "${IPSET_NAME6}" "$1" 2>/dev/null
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
                 "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6" \
                 "${IPSET_NAME}_manual4"  "${IPSET_NAME6}_manual6" \
                 "${IPSET_NAME}_trusted4" "${IPSET_NAME6}_trusted6"; do
            ipset destroy "$s" 2>/dev/null || true
        done
    }
}

# =============================================================================
# §7  List loaders
# =============================================================================
_load_cidr_list() {
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
            ipset add "$set6" "$entry" -exist 2>/dev/null \
                || { log "invalid v6 in $label: $entry"; skip=$((skip+1)); continue; }
        else
            ipset add "$set4" "$entry" -exist 2>/dev/null \
                || { log "invalid v4 in $label: $entry"; skip=$((skip+1)); continue; }
        fi
        n=$((n+1))
    done < "$file"
    log "loaded $label from $file ($n entries, $skip skipped)"
}

_load_csv_ranges() {
    local csv=$1 set4=$2 set6=$3 label=$4
    local entry n=0 skip=0
    for entry in ${csv//,/ }; do
        [[ -z "$entry" ]] && continue
        if [[ "$entry" == *:* ]]; then
            ipset add "$set6" "$entry" -exist 2>/dev/null \
                || { log "invalid v6 in $label: $entry"; skip=$((skip+1)); continue; }
        else
            ipset add "$set4" "$entry" -exist 2>/dev/null \
                || { log "invalid v4 in $label: $entry"; skip=$((skip+1)); continue; }
        fi
        n=$((n+1))
    done
    log "loaded $label ($n entries, $skip skipped)"
}

load_lists() {
    _load_csv_ranges "$TRUSTED_PROXIES" \
        "${IPSET_NAME}_trusted4" "${IPSET_NAME6}_trusted6" "trusted-proxies"
    _load_csv_ranges "$PROTECTED_RANGES" \
        "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6"   "protected-ranges"
    _load_cidr_list "$NEVER_BAN" \
        "${IPSET_NAME}_never4"   "${IPSET_NAME6}_never6"   "whitelist"
    _load_cidr_list "$MANUAL_BAN" \
        "${IPSET_NAME}_manual4"  "${IPSET_NAME6}_manual6"  "blacklist"
}

# =============================================================================
# §8  Log reader (inode + offset, partial-line safe)
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

# Emits only complete lines (up to and including the last newline in the
# readable chunk). Leaves a trailing partial line unprocessed so it is read
# whole on the next poll.
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
    (( saved_offset >= size )) && return 0

    local chunk complete consumed
    chunk=$(tail -c +$(( saved_offset + 1 )) "$log") || return 0
    complete="${chunk%$'\n'*}"
    [[ "$complete" == "$chunk" ]] && return 0   # no complete line yet
    complete="${complete}"$'\n'
    consumed=$(printf '%s' "$complete" | wc -c)
    printf '%s' "$complete"
    printf '%s:%s\n' "$inode" "$(( saved_offset + consumed ))" > "$LOG_STATE_FILE"
}

# =============================================================================
# §9  Log parsers
# =============================================================================
parse_combined() {
    [[ $1 =~ ^([^[:space:]]+)[[:space:]][^[:space:]]+[[:space:]][^[:space:]]+[[:space:]]\[[^]]+\][[:space:]]\"([^\"]*)\"[[:space:]]([0-9]{3})[[:space:]][0-9-]+[[:space:]]\"([^\"]*)\"[[:space:]]\"([^\"]*)\" ]] || return 1
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
    [[ $line =~ \"status\":([0-9]+) ]]                   && PARSE_STATUS="${BASH_REMATCH[1]}"
    [[ $line =~ \"request_uri\":\"([^\"]+)\" ]]          && PARSE_PATH="${BASH_REMATCH[1]}"
    [[ $line =~ \"http_user_agent\":\"([^\"]*)\" ]]      && PARSE_UA="${BASH_REMATCH[1]}"
    [[ $line =~ \"http_x_forwarded_for\":\"([^\"]*)\" ]] && PARSE_XFF="${BASH_REMATCH[1]}"
}

parse_custom() {
    [[ $1 =~ $PARSE_REGEX ]] || return 1
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
    local ip=$1 signal=$2 weight=$3 sigs
    SCORE_N[$ip]=$(( ${SCORE_N[$ip]:-0} + weight ))
    SCORE_TS[$ip]=$CURRENT_TIME
    SCORE_CNT[$ip]=$(( ${SCORE_CNT[$ip]:-0} + 1 ))
    sigs="${SCORE_SIGS[$ip]:-}"
    if [[ ",$sigs," != *",$signal,"* ]]; then
        SCORE_SIGS[$ip]="${sigs:+$sigs,}$signal"
    fi
}

sweep_scores() {
    (( ${#SCORE_TS[@]} > 0 )) || return 0
    local cutoff ip
    cutoff=$(( CURRENT_TIME - WINDOW_SECONDS * 2 ))
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
    local f="$OFFENSE_DIR/$1" n
    [[ -f "$f" ]] || { echo 0; return; }
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
    local ip=$1 reason=$2 offense ttl
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
    local ip score cnt sigs nsigs entry ip_part reason
    local -a to_ban=()
    for ip in "${!SCORE_N[@]}"; do
        score=${SCORE_N[$ip]:-0}
        (( score >= BAN_THRESHOLD )) || continue
        cnt=${SCORE_CNT[$ip]:-0}
        (( cnt >= MIN_REQUESTS ))   || continue
        sigs="${SCORE_SIGS[$ip]:-}"
        nsigs=0
        local _s
        local -a _arr=()
        IFS=',' read -ra _arr <<< "$sigs"
        for _s in "${_arr[@]}"; do [[ -n "$_s" ]] && nsigs=$((nsigs+1)); done
        (( nsigs >= MIN_SIGNALS ))   || continue
        fw_member "$ip" && continue
        to_ban+=("$ip|$sigs")
    done
    (( ${#to_ban[@]} > 0 )) || return 0
    for entry in "${to_ban[@]}"; do
        ip_part="${entry%%|*}"
        reason="${entry#*|}"
        ban_ip "$ip_part" "$reason"
        unset "SCORE_N[$ip_part]" "SCORE_TS[$ip_part]" "SCORE_SIGS[$ip_part]" "SCORE_CNT[$ip_part]"
    done
}

# =============================================================================
# §13 Notifier
# =============================================================================
NOTIFY_QUEUE=""

notify_init() {
    NOTIFY_QUEUE="$STATE_DIR/notify_queue"
    mkdir -p "$STATE_DIR"
    touch "$NOTIFY_QUEUE"
}

notify_enqueue() {
    local ip=$1 ttl=$2 offense=$3 reason=$4 line
    [[ "$NOTIFY" == "none" ]] && return 0
    line=$(printf '%s|%s|%s|%s|%s' \
        "$(date -u +%FT%TZ)" "$ip" "$ttl" "$offense" "${reason//|/_}")
    if [[ "$NOTIFY" == "per-ip" ]]; then
        local oneshot
        oneshot=$(mktemp "$STATE_DIR/_notify_oneshot.XXXXXX")
        printf '%s\n' "$line" > "$oneshot"
        notify_send_bulk "$oneshot"
        rm -f "$oneshot"
    else
        printf '%s\n' "$line" >> "$NOTIFY_QUEUE"
    fi
}

notify_send_bulk() {
    local file=$1 count subject body
    [[ -f "$file" ]] || return 0
    count=$(wc -l < "$file" 2>/dev/null || echo 0)
    (( count > 0 )) || return 0
    subject="autoban: $count IP(s) banned"
    body=$(cat "$file")

    if command -v notify-send >/dev/null 2>&1 && [[ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
        notify-send -u normal "autoban" "$subject" 2>/dev/null || true
    fi
    if command -v mail >/dev/null 2>&1 && [[ -n "$MAIL_TO" ]]; then
        printf '%s\n' "$body" | mail -s "$subject" "$MAIL_TO" 2>/dev/null \
            || log "mail delivery failed"
    fi
    if [[ -n "$WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        local payload
        payload=$(printf '{"subject":"%s","count":%d,"body":"%s"}' \
            "$(json_escape "$subject")" "$count" "$(json_escape "$body")")
        curl -fsS -m 10 -H 'Content-Type: application/json' \
            -d "$payload" "$WEBHOOK_URL" >/dev/null 2>&1 \
            || log "webhook delivery failed"
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
    local c4=0 c6=0
    command -v ipset >/dev/null 2>&1 && {
        c4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]'    || true)
        c6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || true)
    }
    log "stats: banned4=$c4 banned6=$c6 tracked=${#SCORE_N[@]}"
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
  check         Validate config and dependencies without running
  install       Install unit, config, lists, and enable service
  uninstall     Disable service and tear down firewall objects
  teardown      Remove firewall objects only (keep service files)

Options:
  -c, --config <file>   Config file (default: $DEFAULT_CONF)
      --dry-run         Do not modify firewall; log intended actions
      --replay          Process log from the beginning on first run
      --once            Run a single poll cycle then exit
  -v, --verbose         Verbose output (per-line parse logging)
  -h, --help            This help
      --version         Print version
EOF
}

cmd_status() {
    local c4=0 c6=0 st="stopped" lock="$STATE_DIR/autoban.lock"
    command -v ipset >/dev/null 2>&1 && {
        c4=$(ipset list "${IPSET_NAME}"  2>/dev/null | grep -c '^[0-9]'    || true)
        c6=$(ipset list "${IPSET_NAME6}" 2>/dev/null | grep -c '^[0-9a-f:]' || true)
    }
    if [[ -f "$lock" ]] && ! flock -n "$lock" true 2>/dev/null; then
        st="running"
    fi
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

cmd_check() {
    local rc=0
    log "config file: $CONFIG_FILE"
    log "  log:        $NGINX_LOG"
    log "  format:     $LOG_FORMAT"
    log "  threshold:  $BAN_THRESHOLD (min_requests=$MIN_REQUESTS, min_signals=$MIN_SIGNALS)"
    log "  notify:     $NOTIFY"

    [[ -r "$NGINX_LOG" ]] && log "OK: log readable" \
        || { log "WARN: log not readable: $NGINX_LOG"; rc=1; }
    [[ -f "$NEVER_BAN" ]] && log "OK: whitelist present" \
        || { log "WARN: whitelist missing: $NEVER_BAN"; rc=1; }
    [[ -f "$MANUAL_BAN" ]] && log "OK: blacklist present" \
        || { log "WARN: blacklist missing: $MANUAL_BAN"; rc=1; }
    local c
    for c in ipset iptables flock; do
        command -v "$c" >/dev/null 2>&1 && log "OK: $c found" \
            || { log "WARN: $c missing"; rc=1; }
    done
    (( rc == 0 )) && log "config check passed" || log "config check found issues"
    return $rc
}

cmd_install() {
    need_cmd systemctl
    local here
    here=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
    install -d "$DEFAULT_INSTALL_DIR" "/etc/autoban" "$STATE_DIR" "$LOGS_DIR"
    install -m 0755 "$here/autoban.sh" "$DEFAULT_INSTALL_DIR/autoban.sh"
    install -m 0644 "$here/autoban.conf"    "/etc/autoban/autoban.conf"    2>/dev/null || true
    install -m 0644 "$here/whitelist.txt"   "/etc/autoban/whitelist.txt"   2>/dev/null || true
    install -m 0644 "$here/blacklist.txt"   "/etc/autoban/blacklist.txt"   2>/dev/null || true
    install -m 0644 "$here/autoban.service" "/etc/systemd/system/autoban.service"
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
    parse_line "$1" || return 0
    local socket_ip="${PARSE_IP:-}"
    [[ -n "$socket_ip" ]] || return 0
    is_ip "$socket_ip" || return 0

    local ip
    ip=$(resolve_client_ip "$socket_ip" "${PARSE_XFF:-}")
    is_ip "$ip" || return 0

    verbose "line: ip=$ip status=${PARSE_STATUS:-} path=${PARSE_PATH:0:60} ua=${PARSE_UA:0:40}"

    is_never_ban "$ip"  && return 0
    is_manual_ban "$ip" && return 0

    score_add "$ip" "request" 1
    case "${PARSE_STATUS:-}" in
        4??) score_add "$ip" "4xx" 5 ;;
        5??) score_add "$ip" "5xx" 8 ;;
    esac
    if [[ -n "${PARSE_PATH:-}" && -n "$SCAN_PATH_REGEX" ]]; then
        # shellcheck disable=SC2053
        [[ "$PARSE_PATH" =~ $SCAN_PATH_REGEX ]] && score_add "$ip" "path" 10
    fi
    if [[ -n "${PARSE_UA:-}" && -n "$BAD_UA_REGEX" ]]; then
        # shellcheck disable=SC2053
        [[ "$PARSE_UA" =~ $BAD_UA_REGEX ]] && score_add "$ip" "ua" 10
    fi
    return 0
}

run_daemon() {
    [[ -r "$NGINX_LOG" ]] || log "WARN: log not readable yet: $NGINX_LOG"
    fw_init
    load_lists
    init_log_state
    notify_init
    install_traps

    log "started (pid $$, config=$CONFIG_FILE, dry-run=$DRY_RUN, format=$LOG_FORMAT)"
    log_json "start" "config=$CONFIG_FILE" "dry_run=$DRY_RUN"

    local last_digest now
    last_digest=$(date +%s)

    while (( ! SHUTDOWN )); do
        if (( RELOAD )); then
            log "SIGHUP: reloading config and lists"
            load_config "$CONFIG_FILE"
            validate_config
            load_lists
            RELOAD=0
        fi

        CURRENT_TIME=$(date +%s)
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            process_line "$line" || true
        done < <(read_new_lines "$NGINX_LOG")

        apply_bans
        sweep_scores

        if [[ "$NOTIFY" == "digest" ]]; then
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
            -c|--config)   [[ -n "${2:-}" ]] || die "--config requires a path"
                           CONFIG_FILE="$2"; shift 2 ;;
            --dry-run)     DRY_RUN="yes"; shift ;;
            --replay)      REPLAY="yes"; shift ;;
            --once)        ONCE=1; shift ;;
            -v|--verbose)  VERBOSE="yes"; shift ;;
            -h|--help)     usage; exit 0 ;;
            --version)     echo "$SCRIPT_NAME $SCRIPT_VERSION"; exit 0 ;;
            status|list|check|install|uninstall|teardown|run)
                           ACTION="$1"; shift ;;
            unban|test)    [[ -n "${2:-}" ]] || die "$1 requires an argument"
                           ACTION="$1"; ARG1="$2"; shift 2 ;;
            *)             die "unknown argument: $1" ;;
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
        check)     cmd_check ;;
        install)   cmd_install ;;
        uninstall) cmd_uninstall ;;
        teardown)  cmd_teardown ;;
        *)         usage; exit 1 ;;
    esac
}

main "$@"
