#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# psf-run: manual (check needs the URL of the site)
# =============================================================================
# WordPress XSS2Shell pre-auth XSS, October 2026: read-only checker  (v1)
# CVE-2026-64638
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# WordPress Core 4.7 through 7.0.2 reflects the submitted username in the
# wp-login.php error message via sprintf() without adequate sanitization. A
# parser-differential payload (a whitespace character between '<' and a tag
# name, such as "< area") survives PHP strip_tags() because of the space,
# then WordPress's KSES sanitizer re-tokenizes it into a live DOM element. An
# attacker who can get a logged-in administrator to trigger the XSS can chain
# that into full remote code execution via OAuth app-password abuse and plugin
# upload. The attack is pre-authentication: no account is required to send the
# crafted login form. Disclosed 2026-08-07 by PWN.AI; WordPress shipped the
# fix in 7.0.3 the same day.
#
# This script is read-only: it checks the WordPress version, probes for XSS
# reflection (a non-destructive POST to wp-login.php that generates only an
# authentication failure), audits defensive posture, and searches logs and
# plugin directories for signs of exploitation. It does NOT exercise the RCE
# chain or upload anything.
#
# Usage:
#   ./wordpress-xss2shell-check.sh [command] [arguments]
#
#   check URL (default)  detect WordPress version and probe wp-login.php for
#                        XSS reflection. The probe is a URL-encoded POST to the
#                        login form: it generates one failed-authentication entry
#                        in the auth log and no other side effects. Root not
#                        needed. Exit 0 = not vulnerable or not WordPress, 1 =
#                        appears vulnerable, 2 = error or unreachable.
#   audit URL            all of check, plus: sensitive file exposure
#                        (wp-config backups, .git/config, debug.log, xmlrpc.php,
#                        .env), security headers (CSP, HSTS, X-Frame-Options,
#                        X-Content-Type-Options), and REST API user enumeration.
#                        Exit 0 = no critical findings, 1 = critical, 2 = error.
#   hunt [WEBROOT]       read-only log and filesystem analysis: web server access
#                        logs for POST bursts to wp-login.php, requests to
#                        authorize-application.php (OAuth app-password abuse),
#                        plugin upload requests, and direct PHP execution in
#                        plugin directories; WordPress debug.log for error
#                        patterns; and the plugin directories under WEBROOT (or
#                        WP_ROOTS) for recently added or unexpected PHP files.
#                        Exit 0 = nothing found, 1 = findings.
#   version              print the script version.
#
# Env overrides:
#   WP_ROOTS="/var/www /srv/www"   where hunt looks for wp-content/ (space-sep)
#   HUNT_SINCE="2026-08-07"        earliest date hunt reads from logs
#   HUNT_LOGS="/srv/app/log/*.log" extra log globs
#   CURL_OPTS="--insecure"         extra curl options (e.g. skip TLS verify)
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

CVE="CVE-2026-64638"
FIXED_VERSION="7.0.3"
# The parser-differential probe: a space between '<' and the tag name survives
# PHP strip_tags() but is re-tokenized by KSES into a live <area> element.
PROBE='< area id=ajaxurl href=/?rest_route=/>'
WP_ROOTS="${WP_ROOTS:-/var/www /srv/www /srv/www/html /opt/wordpress}"
HUNT_SINCE="${HUNT_SINCE:-2026-08-07}"
HUNT_LOGS="${HUNT_LOGS:-}"
CURL_OPTS="${CURL_OPTS:-}"
read -ra CURL_ARR <<<"$CURL_OPTS"   # split once, without globbing; used as "${CURL_ARR[@]}"
SCRIPT_NAME="wordpress-xss2shell-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
# one private temp file (mode 0600, from mktemp) for HTTP response bodies; removed on every exit path
P2S_TMP=""

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }

# ---------- structured output and read-only mode (the same block in every script) ----------
# Generated from automation/output-block.bash by automation/psf-output.py; edit it there.
# --output jsonl (or PSF_OUTPUT=jsonl) writes JSON Lines, one record per line, when the script ends:
# a start record, an event for each finding, a text record for any other line, and a verdict.
# The format is described in automation/README.md. --output text, the default, changes nothing.
# NO_COLOR (https://no-color.org): set to anything, no color codes in the text output, for screen readers and logs.
if [[ -n "${NO_COLOR:-}" ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v
fi
# PSF_READ_ONLY=1 refuses every command that changes the host, before it starts.
_PSF_FMT="${PSF_OUTPUT:-text}"; _psf_a=()
while (($#)); do
    case "$1" in
        --output) [[ $# -ge 2 ]] || { echo "--output needs a format: text or jsonl" >&2; exit 2; }; _PSF_FMT="$2"; shift 2 ;;
        --output=*) _PSF_FMT="${1#--output=}"; shift ;;
        *) _psf_a+=("$1"); shift ;;
    esac
done
set -- "${_psf_a[@]+"${_psf_a[@]}"}"; unset _psf_a
case "$_PSF_FMT" in text|jsonl) ;; *) echo "--output: unknown format '$_PSF_FMT' (text or jsonl; psf-report renders Markdown, HTML and PDF)" >&2; exit 2 ;; esac
_PSF_CMD=""; for _psf_x in "$@"; do [[ "$_psf_x" == -* ]] || { _PSF_CMD="$_psf_x"; break; }; done; unset _psf_x

# A command that changes the host is refused in read-only mode, whatever else it is asked to do.
psf_refuse_change() {
    [[ "${PSF_READ_ONLY:-0}" == 1 ]] || return 0
    local m="read-only mode (PSF_READ_ONLY=1): ${1:-this change} refused; nothing was changed"
    if [[ "$_PSF_FMT" == jsonl ]]; then PSF_KIND="" _psf_ev error "$m"; else echo "$m" >&2; fi
    exit 2
}

# A check that found nothing to examine says so; only the jsonl verdict records it.
psf_not_applicable() { [[ "$_PSF_FMT" == jsonl ]] && _psf_rec applicable "" "$*"; return 0; }

if [[ "$_PSF_FMT" == jsonl ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v   # the colors this script set
    _PSF_SELF="${BASH_SOURCE[0]}"; _PSF_TOOL="${SCRIPT_NAME:-${_PSF_SELF##*/}}"; _PSF_TOOL="${_PSF_TOOL%.sh}"
    _PSF_HOST="$(cat /proc/sys/kernel/hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"
    _PSF_MAIN_PID="$BASHPID"; _PSF_T0="${EPOCHREALTIME:-$(date +%s)}"; _PSF_EXIT_CMD=""
    _PSF_RUN="${_PSF_HOST}-${_PSF_TOOL}-$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)-$$"
    _psf_d="$(cd "$(dirname "$_PSF_SELF")" 2>/dev/null && pwd)"; _psf_c="${_psf_d%/*}"; _psf_c="${_psf_c##*/}"
    case "$_psf_c" in
        servers|system|runtimes|web-apps|developer|threats) _PSF_FIX="https://privacysafe.app/docs/security-patches/${_psf_c}/${_psf_d##*/}/" ;;
        *) _PSF_FIX="https://privacysafe.app/docs/security-patches/" ;;
    esac; unset _psf_d _psf_c

    _psf_s() {   # a JSON string: escapes, newlines kept, color codes and other control characters dropped
        local s="$1"
        while [[ "$s" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do s="${s/"${BASH_REMATCH[0]}"/}"; done
        s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; s="${s//$'\t'/\\t}"
        s="${s//[$'\001'-$'\037']/}"
        printf '"%s"' "$s"
    }
    # A record this block writes carries a secret marker, made fresh for each run and kept in this shell only.
    # At exit only marked lines are records; any other line, even one that looks like a record (a file name
    # with a newline in it, a log line the script prints), stays text, so output cannot forge a record.
    _PSF_MARK=""; read -r _PSF_MARK </proc/sys/kernel/random/uuid 2>/dev/null || _PSF_MARK="${RANDOM}${RANDOM}${RANDOM}${RANDOM}$$"
    _PSF_MARK=$'\036'"psf-${_PSF_MARK}"$'\036'
    _psf_rec() {   # type level message [more JSON fields]: one marked record on stdout
        local type="$1" level="$2" msg="$3" ts tsms ems cves="" rest extra="${4:-}" c er="${EPOCHREALTIME:-}"
        # one reading of the clock, written three ways: ts to the second (as records always had it), ts_ms to the
        # millisecond (as the joint event logging guide prefers), both RFC 3339 in UTC, and ts_epoch_ms, the same
        # instant as whole milliseconds since 1970 for tools that want a number. EPOCHREALTIME (bash 5) can use a
        # decimal comma; without it the time is whole seconds and the milliseconds are 000.
        if [[ "$er" =~ ^([0-9]+)[.,]([0-9]{3}) ]]; then
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' "${BASH_REMATCH[1]}"; tsms="${ts%Z}.${BASH_REMATCH[2]}Z"
            ems="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        else
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' -1; tsms="${ts%Z}.000Z"
            printf -v ems '%(%s)T' -1; ems="${ems}000"
        fi
        rest="$msg"
        while [[ "$rest" =~ (CVE-[0-9]{4}-[0-9]{4,}) ]]; do
            c="${BASH_REMATCH[1]}"; [[ ",$cves," == *",\"$c\","* ]] || cves="${cves:+$cves,}\"$c\""; rest="${rest#*"$c"}"
        done
        local kind="${PSF_KIND:-}"
        [[ -z "$kind" && "$_PSF_CMD" == hunt && "$level" =~ ^(crit|warn)$ ]] && kind=indicator
        [[ -n "$kind" && "$level" =~ ^(crit|warn)$ ]] && extra+=",\"kind\":$(_psf_s "$kind")"
        [[ -n "${PSF_CODE:-}" ]] && extra+=",\"code\":$(_psf_s "$PSF_CODE")"
        [[ -n "${PSF_PATH:-}" ]] && extra+=",\"path\":$(_psf_s "$PSF_PATH")"
        [[ "$level" =~ ^(crit|warn)$ ]] && extra+=",\"fix\":$(_psf_s "${PSF_FIX:-$_PSF_FIX}")"
        printf '%s{"schema":1,"type":"%s","run":%s,"tool":%s,"version":%s,"host":%s,"command":%s,"ts":"%s","ts_ms":"%s","ts_epoch_ms":%s%s,"msg":%s,"cve":[%s]%s}\n' \
            "$_PSF_MARK" "$type" "$(_psf_s "$_PSF_RUN")" "$(_psf_s "$_PSF_TOOL")" "$(_psf_s "${SCRIPT_VERSION:-}")" "$(_psf_s "$_PSF_HOST")" \
            "$(_psf_s "$_PSF_CMD")" "$ts" "$tsms" "$ems" "${level:+,\"level\":\"$level\"}" "$(_psf_s "$msg")" "$cves" "$extra"
    }
    _psf_ev() { local level="$1" m; shift; printf -v m '%b' "$*"; m="${m#"${m%%[![:space:]]*}"}"; m="${m%"${m##*[![:space:]]}"}"; _psf_rec event "$level" "$m"; }

    # the helpers this script defined above now write records
    declare -F ok      >/dev/null && ok()      { _psf_ev ok "$*"; }
    declare -F pass    >/dev/null && pass()    { _psf_ev ok "$*"; }
    declare -F info    >/dev/null && info()    { _psf_ev info "$*"; }
    declare -F inf     >/dev/null && inf()     { _psf_ev info "$*"; }
    declare -F inf_hunt >/dev/null && inf_hunt() { _psf_ev info "$*"; }
    declare -F note    >/dev/null && note()    { _psf_ev info "$*"; }
    declare -F tip     >/dev/null && tip()     { _psf_ev info "$*"; }
    declare -F warn    >/dev/null && warn()    { _psf_ev warn "$*"; }
    declare -F caution >/dev/null && caution() { _psf_ev warn "$*"; }
    declare -F bad     >/dev/null && bad()     { _psf_ev crit "$*"; }
    declare -F fail    >/dev/null && fail()    { _psf_ev crit "$*"; }
    declare -F step    >/dev/null && step()    { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    declare -F section >/dev/null && section() { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    die() { _psf_ev error "$*"; exit 2; }

    # Everything the script prints goes to a private file; at exit it becomes records, and a verdict closes the run.
    # As root it is always /tmp (root's, sticky): a TMPDIR another account can write would let it swap the file.
    _PSF_TMPD="${TMPDIR:-/tmp}"; [[ $EUID -eq 0 ]] && _PSF_TMPD=/tmp
    _PSF_TMP="$(mktemp "$_PSF_TMPD/psf-output.XXXXXXXXXX")" || { echo "--output jsonl: cannot make a temporary file" >&2; exit 2; }
    exec {_PSF_OUT}>&1 {_PSF_ERR}>&2
    exec {_PSF_RD}<"$_PSF_TMP"        # read back at exit through this handle
    exec >>"$_PSF_TMP" 2>&1
    rm -f "$_PSF_TMP"                 # nameless from here on: nothing is left in /tmp, even when the run is killed
    _psf_rec start "" "$_PSF_TOOL ${SCRIPT_VERSION:-} ${_PSF_CMD:-(no command)}" \
        ",\"script_date\":$(_psf_s "${SCRIPT_DATE:-}"),\"euid\":${EUID},\"read_only\":$([[ "${PSF_READ_ONLY:-0}" == 1 ]] && echo true || echo false)"
    _psf_finish() {
        local rc="$1" line crit=0 warn=0 ok=0 info=0 err=0 text=0 app=null result t1 dur seq=0
        exec 1>&"$_PSF_OUT" 2>&"$_PSF_ERR"
        _psf_out() { local r="${1#"$_PSF_MARK"}"; seq=$((seq + 1)); printf '{"schema":1,"seq":%d,%s\n' "$seq" "${r#\{\"schema\":1,}"; }   # numbered in output order
        local fd="$_PSF_RD"
        while IFS= read -r line <&"$fd" || [[ -n "$line" ]]; do
            if [[ "$line" == "$_PSF_MARK"'{"schema":1,'* ]]; then
                case "$line" in
                    *'"type":"applicable"'*) app=false ;;
                    *'"level":"crit"'*) crit=$((crit + 1)) ;;
                    *'"level":"warn"'*) warn=$((warn + 1)) ;;
                    *'"level":"ok"'*) ok=$((ok + 1)) ;;
                    *'"level":"info"'*) info=$((info + 1)) ;;
                    *'"level":"error"'*) err=$((err + 1)) ;;
                esac
                _psf_out "$line"
            else
                line="${line//$'\036'/}"
                while [[ "$line" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do line="${line/"${BASH_REMATCH[0]}"/}"; done
                line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
                [[ -n "$line" ]] || continue
                text=$((text + 1)); _psf_out "$(_psf_rec text "" "$line")"
            fi
        done
        exec {fd}<&-
        case "$rc" in 0) result=clean ;; 1) result=findings ;; *) result=undecided ;; esac
        [[ "$app" == null && $((crit + warn + ok)) -gt 0 ]] && app=true
        t1="${EPOCHREALTIME:-$(date +%s)}"; dur="$(awk -v a="$_PSF_T0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }' 2>/dev/null || echo 0)"
        _psf_out "$(_psf_rec verdict "" "$result" ",\"result\":\"$result\",\"exit\":$rc,\"applicable\":$app,\"duration_s\":$dur,\"counts\":{\"crit\":$crit,\"warn\":$warn,\"ok\":$ok,\"info\":$info,\"error\":$err,\"text\":$text}")"
    }
    _psf_on_exit() {
        local rc=$?
        if [[ -n "$_PSF_EXIT_CMD" ]]; then eval "$_PSF_EXIT_CMD"; fi
        [[ "$BASHPID" == "$_PSF_MAIN_PID" ]] && _psf_finish "$rc"
        exit "$rc"
    }
    # the script's own EXIT traps still run, before the verdict is written
    trap() {
        local action has_exit=0 s rest=()
        # shellcheck disable=SC2064   # the script's own trap arguments, passed on unchanged
        case "${1:-}" in ""|-p|-l) builtin trap "$@"; return ;; esac
        action="$1"; shift
        for s in "$@"; do if [[ "$s" == EXIT || "$s" == 0 ]]; then has_exit=1; else rest+=("$s"); fi; done
        if ((has_exit)); then
            if [[ "$action" == - ]]; then _PSF_EXIT_CMD=""; else _PSF_EXIT_CMD="$action"; fi
            builtin trap _psf_on_exit EXIT
        fi
        # shellcheck disable=SC2064   # the action string the script wrote, passed on as it was given
        ((${#rest[@]})) && builtin trap "$action" "${rest[@]}"
        return 0
    }
    builtin trap _psf_on_exit EXIT
fi
case "$_PSF_CMD" in
    mitigate|rollback|harden|fix|apply|restore|remove|uninstall|install|enable|disable|quarantine|purge|revert|undo)
        psf_refuse_change "$_PSF_CMD" ;;
esac
# ---------- end of structured output and read-only mode ----------

have() { command -v "$1" >/dev/null 2>&1; }

# Compare two version strings; returns true if $1 >= $2
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

normalize_url() {
    local u="$1"
    [[ "$u" =~ ^https?:// ]] || u="https://${u}"
    echo "${u%/}"
}

# ---------- version detection ------------------------------------------------
# Reads from a response body string; prints the version or nothing.
extract_version() {
    local body="$1"
    grep -oE 'content="WordPress [0-9]+\.[0-9.]*"' <<<"$body" \
        | grep -oE '[0-9]+\.[0-9.]+' | head -1
}

detect_wp_version() {   # <base_url> -> version or empty
    local url="$1"
    # Try meta generator on homepage
    # shellcheck disable=SC2086
    local resp; resp="$(curl -sSL --max-time 15 --max-redirs 3 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" "${url}/" 2>/dev/null || true)"
    local ver; ver="$(extract_version "$resp")"
    [[ -n "$ver" ]] && { echo "$ver"; return; }
    # Fallback: OPML endpoint often exposes the version
    local opml; opml="$(curl -sSL --max-time 10 --max-redirs 2 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" "${url}/wp-links-opml.php" 2>/dev/null || true)"
    grep -oE 'generator="WordPress/[0-9]+\.[0-9.]*"' <<<"$opml" \
        | grep -oE '[0-9]+\.[0-9.]+' | head -1
}

# ---------- XSS reflection probe --------------------------------------------
# POSTs the probe username to wp-login.php. On vulnerable WordPress this
# reflects as a parsed <area id="ajaxurl"> element inside the error message.
# Matches the Nuclei template's verified matcher: body must contain
# id="ajaxurl" AND <area AND Error: (the last is always in a login failure,
# so its presence confirms we reached the login-error path).
probe_reflection() {   # <base_url> -> 0 if reflected, 1 if clean, 2 if error
    local url="$1"
    local resp
    # shellcheck disable=SC2086
    resp="$(curl -sSL --max-time 15 --max-redirs 0 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        -X POST \
        --data-urlencode "log=${PROBE}" \
        -d "pwd=x&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" "${url}/wp-login.php" 2>/dev/null)" || return 2
    [[ -n "$resp" ]] || return 2
    # All three must match (same logic as the verified Nuclei template)
    if grep -qF 'id="ajaxurl"' <<<"$resp" && \
       grep -qF '<area'        <<<"$resp" && \
       grep -qF 'Error:'       <<<"$resp"; then
        return 0   # reflected
    fi
    return 1   # no reflection
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    [[ -n "${1:-}" ]] || die "check needs a URL"
    local url; url="$(normalize_url "$1")"
    have curl || die "curl is required"

    local rc=0

    step "${CVE} check: ${url}"

    # Version
    inf "detecting WordPress version..."
    local ver; ver="$(detect_wp_version "$url")"
    if [[ -z "$ver" ]]; then
        caution "WordPress version not detected (meta generator may be hidden -- run audit for more checks)"
    elif ver_ge "$ver" "$FIXED_VERSION"; then
        ok "WordPress ${ver} -- at or above ${FIXED_VERSION} (version is patched)"
    else
        bad "WordPress ${ver} -- BELOW ${FIXED_VERSION} -- vulnerable to ${CVE}"; rc=1
    fi

    # XSS reflection probe
    inf "probing wp-login.php for parser-differential XSS reflection..."
    probe_reflection "$url"
    local pr=$?
    if [[ $pr -eq 0 ]]; then
        bad "wp-login.php REFLECTS the probe -- ${CVE} active, update immediately"; rc=1
    elif [[ $pr -eq 2 ]]; then
        caution "wp-login.php was not reachable (firewall, redirect, or not WordPress)"
        [[ $rc -eq 0 ]] && rc=2
    else
        ok "no XSS reflection in wp-login.php response"
    fi

    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No ${CVE} indicators (check --url or run audit for full posture)"
    elif [[ $rc -eq 2 ]]; then
        warn "Check inconclusive -- target may not be WordPress or login is blocked"
    else
        warn "${CVE} indicators found. Update to WordPress ${FIXED_VERSION}+ now."
        inf "A logged-in administrator who visits an attacker-controlled page can be"
        inf "chained from the XSS to full RCE via app-password abuse and plugin upload."
        inf "  Disclosure: https://pwn.ai/blog/xss2shell"
        inf "  NVD: https://nvd.nist.gov/vuln/detail/${CVE}"
    fi
    return "$rc"
}

# ---------- audit ------------------------------------------------------------
SENSITIVE_PATHS=(
    "/wp-config.php.bak"
    "/wp-config.php~"
    "/wp-config.php.save"
    "/wp-config.php.swp"
    "/.git/config"
    "/.env"
    "/debug.log"
    "/wp-content/debug.log"
    "/wp-content/uploads/wp-config.php.bak"
    "/.htaccess.bak"
    "/wp-login.php.bak"
)
SECURITY_HDRS=(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Content-Security-Policy"
    "Strict-Transport-Security"
)

cmd_audit() {
    [[ -n "${1:-}" ]] || die "audit needs a URL"
    local url; url="$(normalize_url "$1")"
    have curl || die "curl is required"

    # an unreachable target cannot be audited: that is an error (exit 2), never a clean result
    local reach
    # shellcheck disable=SC2086
    reach="$(curl -sS --max-time 10 --max-redirs 5 -L "${CURL_ARR[@]+"${CURL_ARR[@]}"}" -o /dev/null -w '%{http_code}' "${url}/" 2>/dev/null || true)"
    [[ -n "$reach" && "$reach" != "000" ]] || die "${url} did not answer (no HTTP response): nothing was audited"

    local rc=0

    echo "================================================================"
    echo "${CVE} (XSS2Shell) -- WordPress security audit"
    echo "  Target: ${url}"
    echo "================================================================"

    step "1/5  Core version"
    local ver; ver="$(detect_wp_version "$url")"
    if [[ -z "$ver" ]]; then
        caution "WordPress version not detected (meta generator may be removed)"
    elif ver_ge "$ver" "$FIXED_VERSION"; then
        ok "WordPress ${ver} -- patched (${FIXED_VERSION}+ required)"
    else
        bad "WordPress ${ver} -- VULNERABLE to ${CVE} -- update immediately"; rc=1
    fi

    step "2/5  XSS reflection (${CVE} parser-differential probe)"
    probe_reflection "$url"
    local pr=$?
    if [[ $pr -eq 0 ]]; then
        bad "wp-login.php REFLECTS payload -- ${CVE} active"; rc=1
    elif [[ $pr -eq 2 ]]; then
        caution "wp-login.php not reachable -- could not probe"
    else
        ok "no XSS reflection (patched or access restricted)"
    fi

    step "3/5  Sensitive file exposure"
    local any_exposed=0
    for path in "${SENSITIVE_PATHS[@]}"; do
        # shellcheck disable=SC2086
        local scode body
        scode="$(curl -sSL --max-time 10 --max-redirs 0 \
            -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
            "${CURL_ARR[@]+"${CURL_ARR[@]}"}" -o "${P2S_TMP}" -w '%{http_code}' \
            "${url}${path}" 2>/dev/null || echo "000")"
        body="$(head -c 512 "${P2S_TMP}" 2>/dev/null || true)"
        if [[ "$scode" == "200" ]]; then
            # Distinguish a custom 404 returning 200 from a real leak
            if echo "$body" | grep -E 'DB_PASSWORD|DB_USER|DB_HOST|\[core\]|define\(.*SECRET' >/dev/null; then
                bad "EXPOSED: ${path} (HTTP 200, contains sensitive config data)"; rc=1; any_exposed=1
            elif ! echo "$body" | grep -iE '(not found|404|does not exist|error)' >/dev/null; then
                caution "POSSIBLE LEAK: ${path} (HTTP 200, not obviously a custom 404)"; any_exposed=1
            fi
        fi
    done
    [[ $any_exposed -eq 0 ]] && ok "no sensitive file leaks detected"

    # xmlrpc.php: 405 Method Not Allowed means the service is responding
    # shellcheck disable=SC2086
    local xrpc_code
    xrpc_code="$(curl -sSL --max-time 10 --max-redirs 0 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" -o "${P2S_TMP}" -w '%{http_code}' \
        "${url}/xmlrpc.php" 2>/dev/null || echo "000")"
    local xrpc_body; xrpc_body="$(head -c 256 "${P2S_TMP}" 2>/dev/null || true)"
    if [[ "$xrpc_code" == "405" ]] || \
       { [[ "$xrpc_code" == "200" ]] && echo "$xrpc_body" | grep -F "XML-RPC" >/dev/null; }; then
        caution "xmlrpc.php exposed (HTTP ${xrpc_code}) -- block or disable if not needed"
    fi

    step "4/5  Security response headers"
    # shellcheck disable=SC2086
    local raw_hdrs; raw_hdrs="$(curl -sSL --max-time 10 --max-redirs 3 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" -D - -o /dev/null "${url}/" 2>/dev/null || true)"
    for hdr in "${SECURITY_HDRS[@]}"; do
        if echo "$raw_hdrs" | grep -i "^${hdr}:" >/dev/null; then
            ok "header present: ${hdr}"
        else
            caution "header missing: ${hdr}"
        fi
    done

    step "5/5  REST API user enumeration"
    # shellcheck disable=SC2086
    local rest_code rest_body
    rest_code="$(curl -sSL --max-time 10 --max-redirs 2 \
        -A "Mozilla/5.0 XSS2Shell-Check/${SCRIPT_VERSION}" \
        "${CURL_ARR[@]+"${CURL_ARR[@]}"}" -o "${P2S_TMP}" -w '%{http_code}' \
        "${url}/wp-json/wp/v2/users" 2>/dev/null || echo "000")"
    rest_body="$(head -c 1024 "${P2S_TMP}" 2>/dev/null || true)"
    if [[ "$rest_code" == "200" ]] && echo "$rest_body" | grep -F '"slug"' >/dev/null; then
        caution "REST API /wp-json/wp/v2/users OPEN -- exposes usernames"
    else
        ok "REST API user list closed or filtered (HTTP ${rest_code:-?})"
    fi

    echo
    echo "================================================================"
    if [[ $rc -eq 0 ]]; then
        info "No critical findings. Review warnings above."
    else
        warn "Critical findings. Update WordPress to ${FIXED_VERSION}+ immediately."
        inf "  Disclosure: https://pwn.ai/blog/xss2shell"
        inf "  NVD: https://nvd.nist.gov/vuln/detail/${CVE}"
    fi
    echo "================================================================"
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local webroot="${1:-}"
    local rc=0

    step "Hunting for ${CVE} (XSS2Shell) exploitation signs since ${HUNT_SINCE}"

    # Collect log files
    local -a logfiles=()
    shopt -s nullglob
    for g in /var/log/apache2/access.log /var/log/apache2/access.log.1 \
              /var/log/nginx/access.log /var/log/nginx/access.log.1 \
              /var/log/httpd/access_log /var/log/httpd/access_log.1 \
              /var/log/apache2/*.log /var/log/nginx/*.log \
              /srv/*/logs/access.log /var/www/*/log/*.log; do
        [[ -r "$g" && -f "$g" ]] && logfiles+=("$g")
    done
    # Extra logs from env
    if [[ -n "$HUNT_LOGS" ]]; then
        # shellcheck disable=SC2086
        for g in $HUNT_LOGS; do
            for f in $g; do [[ -r "$f" && -f "$f" ]] && logfiles+=("$f"); done
        done
    fi
    shopt -u nullglob

    # Collect plugin directories to inspect for unexpected PHP files
    local -a plugin_dirs=()
    shopt -s nullglob
    for root in $WP_ROOTS ${webroot:-}; do
        [[ -d "$root" ]] || continue
        for d in "${root}"/wp-content/plugins "${root}"/*/wp-content/plugins; do
            [[ -d "$d" ]] && plugin_dirs+=("$d")
        done
    done
    shopt -u nullglob

    local any_logs=0 any_dirs=0
    [[ ${#logfiles[@]} -gt 0 ]] && any_logs=1
    [[ ${#plugin_dirs[@]} -gt 0 ]] && any_dirs=1

    if [[ $any_logs -eq 0 && $any_dirs -eq 0 ]]; then
        warn "No readable log files or plugin directories found"
        inf "Try running as root, or set WP_ROOTS and HUNT_LOGS"
        return 0
    fi
    inf "Checking ${#logfiles[@]} log file(s) and ${#plugin_dirs[@]} plugin directory(ies)"

    local n

    # 1: POST bursts to wp-login.php: the XSS stage sends crafted login forms
    n=0
    if [[ $any_logs -eq 1 ]]; then
        n="$( { grep -hcE 'POST .*wp-login\.php' "${logfiles[@]}" 2>/dev/null || true; } \
              | awk '{s+=$1} END{print s+0}')"
    fi
    if [[ "${n:-0}" -gt 100 ]]; then
        rc=1
        warn "wp-login.php POST burst: ${n} requests -- possible XSS probe or brute-force"
        { grep -hE 'POST .*wp-login\.php' "${logfiles[@]}" 2>/dev/null || true; } \
            | tail -5 | sed 's/^/      /'
    elif [[ "${n:-0}" -gt 0 ]]; then
        inf "wp-login.php POST count: ${n} (in normal range)"
    else
        ok "wp-login.php: no POST requests found in logs"
    fi

    # 2: authorize-application.php: OAuth app-password abuse (stage 4 of chain)
    n=0
    if [[ $any_logs -eq 1 ]]; then
        n="$( { grep -hcE 'authorize-application\.php' "${logfiles[@]}" 2>/dev/null || true; } \
              | awk '{s+=$1} END{print s+0}')"
    fi
    if [[ "${n:-0}" -gt 0 ]]; then
        rc=1
        warn "authorize-application.php: ${n} request(s) -- not normally accessed directly"
        { grep -hE 'authorize-application\.php' "${logfiles[@]}" 2>/dev/null || true; } \
            | tail -5 | sed 's/^/      /'
    else
        ok "authorize-application.php: no requests found"
    fi

    # 3: Plugin upload (update.php?action=upload-plugin), stage 5 of chain
    n=0
    if [[ $any_logs -eq 1 ]]; then
        n="$( { grep -hcE 'POST .*update\.php\?action=upload-plugin|POST .*update\.php.*upload-plugin' \
                "${logfiles[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
    fi
    if [[ "${n:-0}" -gt 0 ]]; then
        rc=1
        warn "Plugin upload requests: ${n} -- review each; unexpected uploads indicate compromise"
        { grep -hE 'POST .*update\.php.*upload-plugin' "${logfiles[@]}" 2>/dev/null || true; } \
            | tail -5 | sed 's/^/      /'
    else
        ok "plugin upload requests: none found"
    fi

    # 4: Direct PHP access under plugin directories returning 200, webshell calls
    n=0
    if [[ $any_logs -eq 1 ]]; then
        n="$( { grep -hcE '"GET .*wp-content/plugins/[^/]+/[^/]+\.php[^/]*" 200' \
                "${logfiles[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
    fi
    if [[ "${n:-0}" -gt 0 ]]; then
        rc=1
        warn "Direct plugin PHP access (200): ${n} -- review for webshell calls"
        { grep -hE '"GET .*wp-content/plugins/[^/]+/[^/]+\.php[^/]*" 200' \
                "${logfiles[@]}" 2>/dev/null || true; } | tail -5 | sed 's/^/      /'
    else
        ok "direct plugin PHP access: none returning 200"
    fi

    # 5: Recently modified PHP files in plugin directories
    if [[ $any_dirs -eq 1 ]]; then
        # find files modified since HUNT_SINCE; mtime comparison via stat avoids
        # the -newer FILE unreliability across different filesystem timestamps.
        local hunt_epoch; hunt_epoch="$(date -d "${HUNT_SINCE}" +%s 2>/dev/null || date -j -f "%Y-%m-%d" "${HUNT_SINCE}" +%s 2>/dev/null || echo 0)"
        local new_php; new_php="$(find "${plugin_dirs[@]}" -maxdepth 3 -name '*.php'             -type f -printf '%T@  %p\n' 2>/dev/null             | awk -v epoch="${hunt_epoch}" '$1 >= epoch {print}'             | sort -rn | head -20             | sed 's|^[0-9.]\+  ||' || true)"
        if [[ -n "$new_php" ]]; then
            local flagged="$new_php"
            if [[ -n "$flagged" ]]; then
                rc=1
                warn "PHP files modified/created in plugin directories since ${HUNT_SINCE}:"
                echo "$flagged" | sed 's/^/      /'
                inf "Review each. Webshell dropped via XSS2Shell chain has no marker, so any unexpected file is worth checking."
            else
                ok "no plugin PHP files created after ${HUNT_SINCE}"
            fi
        else
            ok "plugin directories: no recently modified PHP files found"
        fi
    fi

    # 6: WordPress debug.log
    shopt -s nullglob
    local -a debuglogs=()
    for root in $WP_ROOTS ${webroot:-}; do
        [[ -d "$root" ]] || continue
        for f in "${root}/wp-content/debug.log" "${root}"/*/wp-content/debug.log; do
            [[ -r "$f" ]] && debuglogs+=("$f")
        done
    done
    shopt -u nullglob
    if [[ ${#debuglogs[@]} -gt 0 ]]; then
        n="$( { grep -hcE '(PHP Fatal|PHP Warning.*call_user_func|system\(|passthru\(|shell_exec\()' \
                "${debuglogs[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            rc=1
            warn "Suspicious entries in WordPress debug.log: ${n}"
            { grep -hE '(PHP Fatal|PHP Warning.*call_user_func|system\(|passthru\(|shell_exec\()' \
                "${debuglogs[@]}" 2>/dev/null || true; } | tail -5 | sed 's/^/      /'
        else
            ok "debug.log: no obviously suspicious entries"
        fi
    fi

    echo
    if [[ ${rc:-0} -eq 0 ]]; then
        info "No XSS2Shell exploitation indicators found in accessible logs"
        inf "A clean result does not prove the host was not compromised: requests cleared"
        inf "from logs before this ran, or from hosts not logged here, will not appear."
    else
        warn "Exploitation indicators found. Treat the host as potentially compromised:"
        inf "  - Rotate all WordPress admin and application passwords"
        inf "  - Audit wp-content/plugins/ for unexpected or recently added PHP files"
        inf "  - Review outbound network connections from the web server account"
        inf "  Reference: https://pwn.ai/blog/xss2shell"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    [[ $# -eq 0 && "$CMD" == "hunt" ]] || [[ $# -le 1 ]] || die "Too many arguments"
    have curl || die "curl is required but not found"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}; fixed in WordPress ${FIXED_VERSION}"
    case "$CMD" in
        check|audit)
            P2S_TMP="$(mktemp)" || die "cannot create a temporary file"
            trap 'rm -f "${P2S_TMP:-}"' EXIT ;;
    esac
    case "$CMD" in
        check|audit|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|audit|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
