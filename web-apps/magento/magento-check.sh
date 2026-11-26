#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Magento, Adobe Commerce and Mage-OS: the exploited 2026 flaws: check, hunt and upload-folder guard  (v4)
# CVE-2026-48356 (PolyShell), CVE-2026-71362, CVE-2026-75650 (StyleSmuggler),
# CVE-2026-103849 (BlockStrap)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Four flaws, four fixes. Each needs its own:
#   CVE-2026-48356   PolyShell. Unauthenticated file upload through the guest-cart REST API:
#                    a polyglot image with PHP inside lands in pub/media/custom_options/quote/.
#                    Exploited since March 2026, CISA KEV 27 October 2026. Fixed in the
#                    July 2026 releases (APSB26-73, -2026-jul); Mage-OS 2.2.1 and every 3.x.
#   CVE-2026-71362   Customer account takeover without authentication (incorrect
#                    authorization, CVSS 9.1). CISA KEV 24 September 2026. Fixed in the
#                    August 2026 releases (APSB26-92, -2026-aug); Mage-OS 3.4.0.
#   CVE-2026-75650   StyleSmuggler. Unauthenticated remote code execution through template
#                    styles, CVSS 10.0, exploited before the fix, CISA KEV 8 September 2026.
#                    Fixed ONLY by Adobe's hotfix VULN-39341 (APSB26-146, 7 September 2026),
#                    which no dated release includes, the October one either; Mage-OS 3.5.0.
#   CVE-2026-103849  BlockStrap. A CVSS 10.0 bypass of the StyleSmuggler fix. Fixed in the
#                    October 2026 releases (APSB26-153, -2026-oct); Mage-OS 3.6.0.
#
# What a version can show. Adobe also ships these fixes as isolated patches and hotfixes, which
# do not change the version string. A dated release (2.4.8-2026-oct) and a Mage-OS release give
# a firm answer; for any other version the script names what to confirm. For StyleSmuggler it
# looks for evidence of the hotfix (VULN-39341 in composer.json, composer.lock,
# .magento.env.yaml, m2-hotfixes/ or patches/), because no version carries it.
#
# Usage:
#   ./magento-check.sh [command] [DIR ...]
#   check (default)  Read-only. Finds installs by bin/magento (default /var/www /srv /home
#                    /opt), reads the distribution and version from composer.lock, and judges
#                    each flaw. Reads whether the PolyShell upload folder is closed: the nginx
#                    configuration (a location for custom_options that denies, placed where a
#                    PHP location cannot win) and the Apache .htaccess in
#                    pub/media/custom_options/, and counts files already in that folder.
#                    Also reads copies of installs in running docker and podman containers
#                    (SCAN_CONTAINERS=1, the default). Exit 0 = nothing exposed, 1 = exposed or
#                    unconfirmed.
#   hunt             Read-only. Looks for what these attacks leave behind: PHP files and
#                    polyglot images in the upload folder and anywhere under pub/media, the
#                    accesson.php backdoor and its assets/images copies, webshell and beacon
#                    strings, a cookie-triggered include in vendor/magento/framework/App/View.php,
#                    stage-one PHP in var/report and var/log, exception.log signatures, the
#                    StyleSmuggler implants on the host (kernel-thread names on non-root
#                    processes, binaries running from temporary folders, cron entries, the
#                    php-fpm private /tmp drops, known SHA-256 hashes) and connections to the
#                    published command servers. Reads web server access logs of the last
#                    HUNT_DAYS days (default 30). Prints read-only SQL for the CMS loader that
#                    PolyShell and StyleSmuggler crews inject into the database; it does not
#                    connect to the database. Exit 0 = nothing found, 1 = findings or leads.
#   mitigate [--dry-run] [--no-nginx] [DIR ...]   (root) Closes the PolyShell upload folder. Writes
#                    pub/media/custom_options/.htaccess (PHP off, all access denied) in every
#                    install it finds (or under DIR) where it is missing or does not deny, and the nginx guard
#                    /etc/nginx/snippets/psf-magento-guard.conf (the upload folder, PHP under
#                    pub/media, and the StyleSmuggler query strings). File changes in a store run
#                    as the account that owns the folder, without following links; each file is
#                    copied first. The snippet is not included anywhere and nothing is reloaded:
#                    add "include snippets/psf-magento-guard.conf;" at the top of each Magento
#                    server block, above every PHP location, run nginx -t, then reload. This is
#                    a guard, not a fix: uploads still reach the disk until the patch is in.
#   rollback [--dry-run]   (root) Puts back every file mitigate changed, and removes the files
#                    it created.
#   version          Print the script version.
#
# Environment: HUNT_DAYS (30), SCAN_CONTAINERS (1), NGINX_SNIPPET_DIR (/etc/nginx/snippets),
# WEB_SERVERS (the servers to judge, "nginx", "apache" or both; default: the running ones),
# NGINX_DIRS (/etc/nginx /usr/local/nginx/conf /usr/local/etc/nginx /opt/nginx/conf),
# LOG_DIRS (/var/log/nginx /var/log/apache2 /var/log/httpd /var/log/lsws /usr/local/lsws/logs
# /var/www /home), STATE_DIR (/var/lib/psf-security-patches/magento-check), PSF_LOCK_WAIT (30).
#
# Output and automation (every command):
#   --output jsonl      JSON Lines for programs and language models: a start record,
#                       an event for each finding, a text record for any other line
#                       and a verdict, written when the command ends (format in
#                       automation/README.md; psf-report turns it into Markdown, HTML
#                       or PDF). --output text, the default, is the output above.
#   PSF_READ_ONLY=1     refuse every command that changes the host, before it starts;
#                       nothing is changed. A runner sets it for scheduled checks.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="magento-check.sh"
SCRIPT_VERSION="4.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/magento-check}"
HUNT_DAYS="${HUNT_DAYS:-30}"
NGINX_SNIPPET_DIR="${NGINX_SNIPPET_DIR:-/etc/nginx/snippets}"
SNIPPET_NAME="psf-magento-guard.conf"
MARK="PrivacySafe Security Patches: Magento guard"

# ---------- common helpers (the same block is used in every check script) ----
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
have()    { command -v "$1" >/dev/null 2>&1; }

# Version helpers: strip a leading v and any -prerelease or +build suffix, then compare with
# sort -V. A pre-release of the boundary itself (6.3.0-rc2 against 6.3.0) is below it, as in
# semantic versioning, so a pre-release of a fixed release is never reported as the release.
norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# Temporary files are registered here, in the main shell, and removed when the script ends.
PSF_TMP=()
STAGE=""
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -rf "${PSF_TMP[@]}"; [[ -z "${STAGE:-}" ]] || rm -rf "$STAGE"' EXIT
mk_tmp() { local _t; _t="$(mktemp)" || die "cannot create a temporary file"; PSF_TMP+=("$_t"); printf -v "$1" '%s' "$_t"; }

is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how=", or add --dry-run to see what it would do" msg
    if is_root; then root_note; return 0; fi
    if have sudo; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    have sudo && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
limited_view() {
    is_root && return 0
    if have sudo; then caution "not running as root: ${1:-files, processes and logs} that belong to other accounts may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files, processes and logs} that belong to other accounts may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
# a regular file that is not a link (FIFOs and devices are never read)
regular() { [[ -f "$1" && ! -L "$1" ]]; }

# ---------- reading an install -----------------------------------------------
# prints: <edition>|<version>      edition = mageos | adobe | magento | unknown
magento_identity() {
    local root="$1" lock="$1/composer.lock" pkg v
    if regular "$lock"; then
        for pkg in mage-os/product-community-edition magento/product-enterprise-edition magento/product-community-edition; do
            v="$(grep -F -A1 "\"name\": \"${pkg}\"" "$lock" 2>/dev/null | sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
            if [[ -n "$v" ]]; then
                case "$pkg" in mage-os/*) echo "mageos|${v}" ;; magento/product-enterprise-edition) echo "adobe|${v}" ;; *) echo "magento|${v}" ;; esac
                return
            fi
        done
    fi
    # a git checkout names itself in composer.json
    if regular "$root/composer.json"; then
        local name; name="$(sed -nE 's/^[[:space:]]*"name":[[:space:]]*"([^"]+)".*/\1/p' "$root/composer.json" | head -n1)"
        v="$(sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([^"]+)".*/\1/p' "$root/composer.json" | head -n1)"
        if [[ -n "$v" ]]; then case "$name" in mage-os/*) echo "mageos|${v}" ;; magento/*) echo "magento|${v}" ;; *) echo "unknown|${v}" ;; esac; return; fi
    fi
    echo "unknown|"
}

# a dated release string such as 2.4.9-2026-oct gives the patch month, as YYYYMM; else 0
dated_month() {
    local v="$1" n
    if [[ "$v" =~ -([0-9]{4})-(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$ ]]; then
        case "${BASH_REMATCH[2]}" in jan)n=01;; feb)n=02;; mar)n=03;; apr)n=04;; may)n=05;; jun)n=06;; jul)n=07;; aug)n=08;; sep)n=09;; oct)n=10;; nov)n=11;; *)n=12;; esac
        echo "${BASH_REMATCH[1]}${n}"
    elif [[ "$v" =~ -([0-9]{4})-([0-9]{2})$ ]]; then echo "${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
    else echo 0; fi
}

# Mage-OS: a fix arrives as a release. <version> <first fixed> -> affected | fixed | prerelease | unknown
mageos_at() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || { echo unknown; return; }
    ver_lt "$v" "$2" && { echo affected; return; }
    # a pre-release of the fixed release may not carry the fix, and the script does not claim it does
    [[ "$1" =~ -(alpha|beta|rc|dev|pre) && "$v" == "$2" ]] && { echo prerelease; return; }
    echo fixed
}

find_installs() {
    local -a dirs=() existing=(); local d f
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    [[ ${#existing[@]} -gt 0 ]] || return 0
    while IFS= read -r f; do echo "$(dirname "$(dirname "$f")")"; done < <(timeout 120 find "${existing[@]}" -xdev -maxdepth 8 -path '*/bin/magento' -type f -not -path '*/vendor/*' 2>/dev/null | sort -u)
}

# ---------- running containers -----------------------------------------------
# An install inside a container is not on the host. For each running container, find installs by
# their marker file, copy ONLY the files this check reads into a temporary directory (one per
# install, named after the container and the path inside it, mode 0700, removed on exit), and let
# the normal checks judge it like a host install. Paths the container reports are checked before
# they are used. The check never runs anything in a container beyond "find" and a file copy.
# It runs once, in the main shell (a subshell's exit would delete the copies early).
declare -a STAGED_DIRS=()
stage_containers() {   # <marker file, relative to the install root> <other relative files the check reads>...
    local marker="$1" rt id name roots r f s; shift
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            roots="$("$rt" exec "$id" sh -c "find /var/www /srv /opt /home /usr/share -maxdepth 8 -path '*/${marker}' -type f 2>/dev/null | head -n 20" 2>/dev/null)" || continue
            while read -r r; do
                [[ "$r" =~ ^/[A-Za-z0-9._/@+-]+$ && "$r" == */"$marker" ]] || continue
                r="${r%/"$marker"}"
                if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; fi
                s="$STAGE/${rt}_${name:-$id}_${r//\//_}"; mkdir -p "$s"
                for f in "$marker" "$@"; do
                    mkdir -p "$s/$(dirname "$f")"
                    "$rt" cp "${id}:${r}/${f}" "$s/$f" >/dev/null 2>&1 || rm -f "$s/$f"
                    [[ -L "$s/$f" ]] && rm -f "$s/$f"
                done
                STAGED_DIRS+=("$s")
            done <<<"$roots"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}
is_staged() { [[ -n "$STAGE" && "$1" == "$STAGE"/* ]]; }

# ---------- web servers ------------------------------------------------------
running_servers() {   # prints nginx and/or apache when such a process runs (WEB_SERVERS overrides)
    local c
    if [[ -n "${WEB_SERVERS:-}" ]]; then tr ' ,' '\n\n' <<<"$WEB_SERVERS" | grep -xE 'nginx|apache'; return 0; fi
    c="$(ps -eo comm= 2>/dev/null)"
    grep -qxE 'nginx' <<<"$c" && echo nginx
    grep -qxE 'apache2|httpd|httpd-prefork|httpd-worker' <<<"$c" && echo apache
    grep -qxE 'litespeed|lshttpd|openlitespeed' <<<"$c" && echo apache   # LiteSpeed reads .htaccess
    return 0
}

# nginx configuration files: everything under the usual directories, plus the absolute files
# (globs expanded) that those files include, plus the nginx.conf.sample of each install, which
# many hosts include as it is. Regular files only; a link is not followed.
NGINX_DIRS="${NGINX_DIRS:-/etc/nginx /usr/local/nginx/conf /usr/local/etc/nginx /opt/nginx/conf}"
LOG_DIRS="${LOG_DIRS:-/var/log/nginx /var/log/apache2 /var/log/httpd /var/log/lsws /usr/local/lsws/logs /var/www /home}"
nginx_files() {
    local d f inc
    local -a base=()
    for d in $NGINX_DIRS; do [[ -d "$d" && ! -L "$d" ]] && while IFS= read -r f; do base+=("$f"); done < <(find "$d" -maxdepth 4 -type f -readable 2>/dev/null)
    done
    printf '%s\n' ${base[@]+"${base[@]}"}
    for f in ${base[@]+"${base[@]}"}; do
        while IFS= read -r inc; do
            # shellcheck disable=SC2086   # the include may be a glob, as nginx allows
            for d in $inc; do regular "$d" && [[ -r "$d" ]] && echo "$d"; done
        done < <(sed -nE 's/^[[:space:]]*include[[:space:]]+(\/[^;[:space:]]+)[[:space:]]*;.*/\1/p' "$f" 2>/dev/null)
    done
}

# For each nginx file, every location that names custom_options:
#   <file>|<line>|<modifier: ^~ ~ ~* = or none>|<denies: 1/0>|<line of the first PHP regex location in that file, 0 if none>
# and, for a file that includes the guard snippet: <file>|<line>|snippet|1|0
nginx_upload_rules() {
    local f
    while IFS= read -r f; do
        # the guard snippet counts only where a server includes it, never as a file on its own
        grep -qF "$MARK" "$f" 2>/dev/null && continue
        awk -v F="$f" -v SN="$SNIPPET_NAME" '
            { line[NR] = $0 }
            /^[[:space:]]*#/ { next }
            $0 ~ "include[[:space:]]+[^;]*" SN { print F "|" NR "|snippet|1|0"; next }
            /location[[:space:]]+~\*?[[:space:]]+[^{]*\\\.php/ && !php { php = NR }
            /location[[:space:]]/ && /custom_options/ { open[++n] = NR }
            END {
                for (i = 1; i <= n; i++) {
                    s = open[i]; t = line[s]; mod = "none"
                    if (t ~ /location[[:space:]]+\^~/) mod = "^~"
                    else if (t ~ /location[[:space:]]+~\*/) mod = "~*"
                    else if (t ~ /location[[:space:]]+~/) mod = "~"
                    else if (t ~ /location[[:space:]]+=/) mod = "="
                    depth = 0; den = 0
                    for (j = s; j <= NR && j < s + 40; j++) {
                        u = line[j]; sub(/#.*/, "", u)
                        if (u ~ /deny[[:space:]]+all/ || u ~ /return[[:space:]]+(403|404|444)/) den = 1
                        depth += gsub(/\{/, "{", u); depth -= gsub(/\}/, "}", u)
                        if (j > s && depth <= 0) break
                        if (j == s && depth == 0 && u ~ /\}/) break
                    }
                    print F "|" s "|" mod "|" den "|" (php ? php : 0)
                }
            }' "$f" 2>/dev/null
    done < <(nginx_files | awk '!seen[$0]++')
}

# Judge the nginx rules once. Sets NGX_STATE (closed | weak | none) and NGX_WHERE.
NGX_STATE=""; NGX_WHERE=""
judge_nginx() {
    [[ -n "$NGX_STATE" ]] && return 0
    local f l mod den php weak="" good=""
    while IFS='|' read -r f l mod den php; do
        [[ -n "$f" ]] || continue
        if [[ "$mod" == snippet ]]; then good="${f}:${l} (includes ${SNIPPET_NAME})"; continue; fi
        [[ "$den" == 1 ]] || { weak="${f}:${l} names custom_options but does not deny"; continue; }
        case "$mod" in
            '^~') good="${f}:${l}" ;;
            '~'|'~*') if [[ "$php" == 0 || "$l" -lt "$php" ]]; then good="${f}:${l}"; else weak="${f}:${l} comes after the PHP location at line ${php}, which wins for .php requests: move it above"; fi ;;
            *) weak="${f}:${l} is a plain prefix location, which a PHP regex location overrides for .php requests: use 'location ^~'" ;;
        esac
    done < <(nginx_upload_rules)
    if [[ -n "$good" ]]; then NGX_STATE=closed; NGX_WHERE="$good"
    elif [[ -n "$weak" ]]; then NGX_STATE=weak; NGX_WHERE="$weak"
    else NGX_STATE=none; NGX_WHERE=""; fi
}

# The Apache guard in pub/media/custom_options/.htaccess: closed when it denies all access.
#   prints: closed | open | missing | link
htaccess_state() {
    local f="$1/pub/media/custom_options/.htaccess" t
    [[ -L "$f" ]] && { echo link; return; }
    regular "$f" || { echo missing; return; }
    t="$(sed 's/#.*//' "$f" 2>/dev/null)"
    if grep -qiE 'Require[[:space:]]+all[[:space:]]+denied|Deny[[:space:]]+from[[:space:]]+all' <<<"$t"; then echo closed; else echo open; fi
}

# Files already in the upload folder: <count of files> <count of executable or PHP-bearing files>
upload_files() {
    local d="$1/pub/media/custom_options" n=0 x=0 f
    [[ -d "$d" && ! -L "$d" ]] || { echo "0 0"; return; }
    while IFS= read -r -d '' f; do
        n=$((n + 1))
        if [[ "$f" =~ \.(php[0-9]?|phtml|phar|pht|phps|inc)$ ]] || head -c 65536 "$f" 2>/dev/null | grep -aqE '<\?(php|=)'; then x=$((x + 1)); fi
    done < <(timeout 60 find "$d" -xdev -type f ! -name '.htaccess' -print0 2>/dev/null)
    echo "$n $x"
}

# Evidence of the StyleSmuggler hotfix VULN-39341 in the project files. prints the evidence, or nothing.
hotfix_evidence() {
    local root="$1" f
    for f in composer.json composer.lock .magento.env.yaml; do
        regular "$root/$f" && grep -qF 'VULN-39341' "$root/$f" 2>/dev/null && { echo "VULN-39341 in ${f}"; return; }
    done
    regular "$root/composer.lock" && grep -qF '"name": "disrex/stylesmuggler-adobe-patches"' "$root/composer.lock" 2>/dev/null && { echo "disrex/stylesmuggler-adobe-patches (Adobe's patch, applied by Composer) in composer.lock"; return; }
    for f in m2-hotfixes patches; do
        [[ -d "$root/$f" && ! -L "$root/$f" ]] || continue
        f="$(timeout 30 find "$root/$f" -maxdepth 4 -type f \( -iname '*VULN-39341*' -o -iname '*.patch' \) -size -4M 2>/dev/null | while IFS= read -r p; do
                if [[ "$p" == *VULN-39341* ]] || grep -qF 'VULN-39341' "$p" 2>/dev/null; then echo "$p"; break; fi; done)"
        [[ -n "$f" ]] && { echo "${f#"$root"/}"; return; }
    done
    return 0
}
# Community mitigations that are not the fix. prints them, or nothing.
guard_evidence() {
    local root="$1" g=()
    regular "$root/composer.lock" && grep -qF '"name": "ceymox/module-style-smuggler-shield"' "$root/composer.lock" 2>/dev/null && g+=("ceymox/module-style-smuggler-shield")
    local a="$root/setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php"
    regular "$a" && grep -qF 'PHP_SAPI' "$a" 2>/dev/null && g+=("a CLI-only guard in the DI ArrayScanner")
    [[ ${#g[@]} -gt 0 ]] && { local IFS=,; echo "${g[*]}"; }
    return 0
}

# ---------- check --------------------------------------------------------------
cmd_check() {
    if [[ $# -eq 0 ]]; then
        stage_containers 'bin/magento' 'composer.lock' 'composer.json' '.magento.env.yaml' \
            'pub/media/custom_options/.htaccess' 'setup/src/Magento/Setup/Module/Di/Code/Scanner/ArrayScanner.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local rc=0 found=0 root id ed ver mo servers ev gd ht nf nx s
    step "Looking for Magento, Adobe Commerce or Mage-OS"
    local -a roots=(); while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(find_installs "$@")
    if [[ ${#roots[@]} -eq 0 ]]; then info "No install found (looked for bin/magento under ${*:-/var/www /srv /home /opt})"; psf_not_applicable "no Magento, Adobe Commerce or Mage-OS install found$([[ "${SCAN_CONTAINERS:-1}" == 1 ]] && echo " on the host or in running containers" || echo " on the host (containers not read)")"; return 0; fi
    servers="$(running_servers | sort -u | tr '\n' ' ')"
    for root in "${roots[@]}"; do
        found=$((found + 1))
        id="$(magento_identity "$root")"; ed="${id%%|*}"; ver="${id#*|}"
        step "${ed} ${ver:-unknown} at ${root}"
        if [[ -z "$ver" ]]; then PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_VERSION_UNREADABLE caution "could not read the version (looked in composer.lock and composer.json): judge it by hand against APSB26-73, APSB26-92, APSB26-146 and APSB26-153"; rc=1; continue; fi
        mo="$(dated_month "$ver")"
        local poly="" ato="" ss="" bs=""
        if [[ "$ed" == mageos ]]; then
            poly="$(mageos_at "$ver" 2.2.1)"; ato="$(mageos_at "$ver" 3.4.0)"; ss="$(mageos_at "$ver" 3.5.0)"; bs="$(mageos_at "$ver" 3.6.0)"
        elif is_semver "$ver" && ver_lt "$(norm_ver "$ver")" 2.4.4; then
            poly=old; ato=old; ss=old; bs=old
        elif [[ "$mo" != 0 ]]; then
            if (( mo >= 202607 )); then poly=fixed; else poly=affected; fi
            if (( mo >= 202608 )); then ato=fixed; else ato=affected; fi
            if (( mo >= 202610 )); then bs=fixed; else bs=affected; fi
            ss=hotfix
        else
            poly=confirm; ato=confirm; ss=hotfix; bs=confirm
        fi
        if [[ "$poly" == old ]]; then
            PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_OUT_OF_SUPPORT bad "${ver} is out of Adobe's support (below 2.4.4): Adobe published no fix for any of these four flaws on this line. Upgrade; community backports of the StyleSmuggler fix exist for 2.2.0 to 2.4.3-p3 (Scandiweb), unreviewed here"
            rc=1
        fi

        # CVE-2026-48356, PolyShell
        echo "  -- CVE-2026-48356 (PolyShell, upload through the guest cart, CISA KEV)"
        case "$poly" in
            fixed) ok "${ver} carries the PolyShell fix" ;;
            affected) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_POLYSHELL_UNFIXED bad "${ver}: built before the July 2026 fix (APSB26-73)"; rc=1 ;;
            confirm) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_POLYSHELL_UNCONFIRMED caution "${ver}: confirm the July 2026 fix (APSB26-73): an isolated patch does not change the version string. Adobe lists plain 2.4.9 as affected and 2.4.9-2026-jul as fixed"; rc=1 ;;
            prerelease) caution "Mage-OS ${ver} is a pre-release: it may not carry the fix"; rc=1 ;;
            old) : ;;
            *) caution "cannot compare version '${ver}'"; rc=1 ;;
        esac
        if is_staged "$root"; then
            inf "container copy: the web server rules of the container were not read"
        else
            if [[ "$servers" == *nginx* ]]; then
                judge_nginx
                case "$NGX_STATE" in
                    closed) ok "nginx closes the upload folder: ${NGX_WHERE}" ;;
                    weak) if [[ "$poly" == fixed ]]; then PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN caution "nginx does not close the upload folder (defense in depth): ${NGX_WHERE}"; else PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN bad "nginx does not close the upload folder: ${NGX_WHERE}"; rc=1; fi ;;
                    *) if [[ "$poly" == fixed ]]; then PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN caution "no nginx location closes /media/custom_options/ (defense in depth: run mitigate for the snippet)"; else PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN bad "no nginx location closes /media/custom_options/: an uploaded .php can run when the PHP location serves it (run mitigate for the snippet)"; rc=1; fi ;;
                esac
            fi
            ht="$(htaccess_state "$root")"
            if [[ "$servers" == *apache* || -z "$servers" ]]; then
                case "$ht" in
                    closed) ok "pub/media/custom_options/.htaccess denies all access (read by Apache and LiteSpeed when AllowOverride permits it)" ;;
                    link) PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_HTACCESS_LINK bad "pub/media/custom_options/.htaccess is a symbolic link: not read; replace it with a regular file"; rc=1 ;;
                    *) if [[ "$poly" == fixed ]]; then PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN caution "pub/media/custom_options/.htaccess is ${ht} or does not deny (defense in depth: run mitigate)"; else PSF_KIND=exposure PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_FOLDER_OPEN bad "pub/media/custom_options/.htaccess is ${ht} or does not deny, and Apache or LiteSpeed serves this host (run mitigate)"; rc=1; fi ;;
                esac
            fi
            [[ -n "$servers" ]] || inf "no nginx, Apache or LiteSpeed process seen: the folder guard was judged from the .htaccess alone"
        fi
        read -r nf nx <<<"$(upload_files "$root")"
        if [[ "${nx:-0}" -gt 0 ]]; then PSF_KIND=compromise PSF_PATH="$root" PSF_CODE=MAGENTO_UPLOAD_PHP bad "${nx} file(s) in pub/media/custom_options/ are PHP or carry PHP code: treat the store as compromised and run hunt"; rc=1
        elif [[ "${nf:-0}" -gt 0 ]]; then inf "${nf} file(s) in pub/media/custom_options/ (customer uploads look like this too); hunt reads them"; fi

        # CVE-2026-71362
        echo "  -- CVE-2026-71362 (customer account takeover, CISA KEV)"
        case "$ato" in
            fixed) ok "${ver} carries the August 2026 fix (APSB26-92)" ;;
            affected) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_CVE_2026_71362_UNFIXED bad "${ver}: built before the August 2026 fix (APSB26-92)"; rc=1 ;;
            confirm) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_CVE_2026_71362_UNCONFIRMED caution "${ver}: confirm the August 2026 fix (APSB26-92; Adobe's isolated patch 249-2026-08-001-CE on 2.4.9)"; rc=1 ;;
            prerelease) caution "Mage-OS ${ver} is a pre-release: it may not carry the fix"; rc=1 ;;
            old) : ;;
            *) caution "cannot compare version '${ver}'"; rc=1 ;;
        esac

        # CVE-2026-75650, StyleSmuggler
        echo "  -- CVE-2026-75650 (StyleSmuggler, unauthenticated RCE, CISA KEV)"
        case "$ss" in
            fixed) ok "Mage-OS ${ver} carries the StyleSmuggler fix (3.5.0 or later)" ;;
            affected) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_STYLESMUGGLER_UNFIXED bad "Mage-OS ${ver} is below 3.5.0: exposed to StyleSmuggler"; rc=1 ;;
            prerelease) caution "Mage-OS ${ver} is a pre-release: it may not carry the fix"; rc=1 ;;
            hotfix)
                ev="$(hotfix_evidence "$root")"; gd="$(guard_evidence "$root")"
                if [[ -n "$ev" ]]; then
                    ok "the hotfix is referenced: ${ev}. Confirm it applied: vendor/bin/magento-patches -n status | grep 39341"
                else
                    PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_STYLESMUGGLER_NO_HOTFIX caution "no sign of hotfix VULN-39341 (looked in composer.json, composer.lock, .magento.env.yaml, m2-hotfixes/ and patches/). No release carries it, the October 2026 one included: exposed unless it was applied another way. Confirm: vendor/bin/magento-patches -n status | grep 39341"
                    rc=1
                fi
                [[ -n "$gd" ]] && inf "community mitigation present (not the fix): ${gd}"
                ;;
            old) : ;;
            *) caution "cannot compare version '${ver}'"; rc=1 ;;
        esac

        # CVE-2026-103849, BlockStrap
        echo "  -- CVE-2026-103849 (BlockStrap, bypass of the StyleSmuggler fix)"
        case "$bs" in
            fixed) ok "${ver} carries the October 2026 fix (APSB26-153)" ;;
            affected) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_BLOCKSTRAP_UNFIXED bad "${ver}: built before the October 2026 fix (APSB26-153)"; rc=1 ;;
            confirm) PSF_KIND=vulnerability PSF_PATH="$root" PSF_CODE=MAGENTO_BLOCKSTRAP_UNCONFIRMED caution "${ver}: confirm the October 2026 fix (APSB26-153): an isolated patch does not change the version string"; rc=1 ;;
            prerelease) caution "Mage-OS ${ver} is a pre-release: it may not carry the fix"; rc=1 ;;
            old) : ;;
            *) caution "cannot compare version '${ver}'"; rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No exposed install found (${found} checked)."
    else
        warn "Exposed or unconfirmed install found."
        inf "Adobe Commerce and Magento Open Source: move to the October 2026 release (-2026-oct), which carries the PolyShell, August and BlockStrap fixes, and apply hotfix VULN-39341 (APSB26-146) separately. Mage-OS: 3.6.0 or later."
        inf "Close the upload folder now, patched or not: sudo ${SELF} mitigate (the .htaccess and an nginx snippet)."
        inf "StyleSmuggler, PolyShell and CVE-2026-71362 were exploited before many stores patched: run hunt, and rotate the encryption key and every credential it protected if hunt finds anything."
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
# Published indicators. Sources: Sansec (PolyShell, StyleSmuggler), the disrex StyleSmuggler
# incident notes. Addresses rotate: a match is a lead, a miss proves nothing.
KNOWN_HASHES="e315687a1dfe61ef4a5a5642214db6d3b2b05d81391285eebc2af664641a26a7 StyleSmuggler implant (kworker build)
b79dfdc1eed860e0b76c629d6adfce251db379b0b45a6d728d4ef483f7551420 StyleSmuggler implant
4352cabaa451e5a894535fbcc4d46628701303322a13745cb5479d7d0534ae8e StyleSmuggler implant, kworker-linux-x64
d2fbf9eb75c495bfea48790d3b228fab0c15a282419c3d3f5e49294c4e1a3e82 StyleSmuggler implant, kworker-linux-arm64
1a3374ffac5b0a62467612f264c49792d206304d4514409c982325c91231375d StyleSmuggler implant, chronyd build
8334b434fa3fe9f59cebe9609b11e0b1fd19d10212c45c705adec1902a1d06ef StyleSmuggler implant (disrex)
251fabd50d7b18a8b5e1b3ef5d64e7198c17244778f6461fb1ab07f6169bf220 StyleSmuggler implant (disrex)
d61217ca0bca83204302fa7b41935ce36f73764559c156d5c980f2fedddffb6e PHP dropper (second StyleSmuggler crew)
d94f75a70b5cabaf786ac57177ed841732e62bdcc9a29e06e5b41d9be567bcfa gs-netcat (Global Socket Toolkit)
64bcb4426783e2b4f8ec68b2f63e42cf4b404af6cd65c4c47f5ae3ac0a3d439e WraithC2 implant
8cef8dcac2bb4598fb821859deb61c9b6889b4bdad00498a38d113954334bbb3 Adminer 6.0.2 (database panel left by an attacker)"
C2_ADDRS="99.84.67.186 185.157.160.251 213.111.146.27 209.141.43.95 212.132.98.170 152.53.173.29"
SRC_ADDRS="3.12.250.83 3.88.149.41 3.150.234.247 18.220.50.153 23.22.254.35 31.134.0.53 31.134.1.34 31.134.7.117
31.134.11.173 31.134.15.89 31.134.15.251 45.136.24.213 45.136.26.181 45.136.27.218 45.147.233.211 45.147.234.73
45.155.166.228 52.24.6.119 64.49.38.96 78.129.161.63 79.130.2.23 81.169.144.135 91.132.124.183 103.216.223.206
109.107.178.102 115.79.194.68 136.244.92.114 140.235.2.103 140.235.171.72 140.248.75.31 140.248.75.114 162.159.113.66
185.3.235.111 193.151.188.86 193.233.216.217 193.233.221.124 194.180.233.186 198.186.130.10 199.96.165.186 212.87.218.43
216.38.6.137 88.216.72.181 88.216.72.182 182.182.152.48 76.31.99.207 209.73.130.148 77.239.124.107 98.224.189.28
45.10.167.153 45.135.3.216 217.181.79.178 217.181.79.189 45.135.2.183 216.40.73.46 146.19.140.158 45.145.128.160
194.26.129.230 88.218.44.215 83.142.54.144 93.177.119.38 37.72.141.145 144.31.2.154 5.181.86.133 91.238.181.19"
# strings that a stock store does not carry in its own PHP: webshell hashes and beacons, the
# second crew's token, the cookie of the View.php include, and the stage-one payload labels
WEBSHELL_RE='8194460|409723\*20|a17028468cb2a870d460676d6d6da3ad|4009d3fa8132195a2dab4dfa3affc8d2|fced27f6d57702565353ecc11722533b|gl_google_advisor_|MGPROOF::|MGKWSIM::|ss[56]_457cfa2fb7'
LOADER_DOMAINS="lanhd6549tdhse.top jslibrary.net canevaslab.com deepveindrilling.com safeprocessor.com assetsbundle.com widgetassets.com gtmtimestamp.com specterguardian.com checkout-cdn.com fb_metrics.php"

N_HIGH=0; N_MED=0
hit_high() { N_HIGH=$((N_HIGH + 1)); bad "$*"; }
hit_med()  { N_MED=$((N_MED + 1)); caution "$*"; }
known_hash() {   # <file> -> prints the label when its SHA-256 is a published one
    local f="$1" s h l
    s="$(stat -L -c %s "$f" 2>/dev/null)" || return 0
    [[ "$s" =~ ^[0-9]+$ && "$s" -le 52428800 ]] || return 0
    h="$(timeout 60 sha256sum -- "$f" 2>/dev/null | awk '{print $1}')"
    [[ -n "$h" ]] || return 0
    l="$(awk -v h="$h" '$1 == h {sub(/^[^ ]+ /, ""); print; exit}' <<<"$KNOWN_HASHES")"
    [[ -n "$l" ]] && echo "$l"
    return 0
}

hunt_install() {
    local root="$1" f n l c cnt d
    step "Store files: ${root}"
    # 1. the PolyShell upload folder
    d="$root/pub/media/custom_options"
    if [[ -L "$d" ]]; then hit_med "pub/media/custom_options is a symbolic link: read by hand"
    elif [[ -d "$d" ]]; then
        n=0
        while IFS= read -r -d '' f; do
            n=$((n + 1))
            if [[ "$f" =~ \.(php[0-9]?|phtml|phar|pht|phps|inc|html?)$ ]] || head -c 65536 "$f" 2>/dev/null | grep -aqE '<\?(php|=)'; then
                l="$(known_hash "$f")"
                hit_high "upload folder: ${f#"$root"/}$( [[ -n "$l" ]] && echo " (${l})" )$(head -c 6 "$f" 2>/dev/null | grep -aqE '^(GIF8[79]a|.PNG)' && echo ': an image header with PHP inside (polyglot)')"
            fi
        done < <(timeout 120 find "$d" -xdev -type f ! -name '.htaccess' -print0 2>/dev/null)
        [[ $n -gt 0 ]] && inf "${n} file(s) in the upload folder in all; customer uploads for products with file options look like this, PHP does not"
    fi
    # 2. PHP anywhere under pub/media (no stock file is PHP there), and the second crew's cache shells
    while IFS= read -r -d '' f; do
        [[ "$f" == "$d"/* ]] && continue
        l="$(known_hash "$f")"
        hit_high "PHP under pub/media: ${f#"$root"/}$( [[ -n "$l" ]] && echo " (${l})" )"
    done < <(timeout 180 find "$root/pub/media" -xdev -type f \( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.pht' \) -print0 2>/dev/null)
    # 3. the accesson.php backdoor and its assets/images copies, the stage-one proof file, gs-netcat
    while IFS= read -r -d '' f; do
        hit_high "${f#"$root"/}: $(case "$f" in *accesson.php) echo 'the accesson.php backdoor (PolyShell follow-up)' ;; *mgproof717.txt) echo 'written by a StyleSmuggler stage-one payload' ;; *defunct.dat) echo 'gs-netcat relay secret' ;; */defunct) echo 'gs-netcat binary' ;; *) echo 'PHP in an assets/images folder, the pattern the accesson.php crew uses' ;; esac)"
    done < <(timeout 180 find "$root" -xdev -maxdepth 6 -type f \( -name 'accesson.php' -o -name 'mgproof717.txt' -o -path "$root/defunct" -o -path "$root/defunct.dat" -o -path "$root/pub/defunct" -o \( -path '*/assets/images/*' \( -iname '*.php' -o -iname '*.phtml' \) \) \) -print0 2>/dev/null)
    # 4. webshell and beacon strings in PHP outside the packages (vendor/assets is where the crew writes)
    local -a scan=()
    for c in pub app var generated lib setup bin phpserver bamboo-specs vendor/assets dev; do [[ -d "$root/$c" && ! -L "$root/$c" ]] && scan+=("$root/$c"); done
    if [[ ${#scan[@]} -gt 0 ]]; then
        while IFS= read -r f; do
            [[ -n "$f" ]] && hit_high "webshell or payload marker in ${f#"$root"/}: $(grep -aoE "$WEBSHELL_RE" "$f" 2>/dev/null | head -n1)"
        done < <(timeout 300 grep -rlaE --include='*.php' --include='*.phtml' --include='*.phar' --include='*.php[0-9]' --include='*.inc' "$WEBSHELL_RE" "${scan[@]}" 2>/dev/null | head -n 50)
    fi
    # 5. the cookie-triggered include in the framework
    f="$root/vendor/magento/framework/App/View.php"
    if regular "$f" && grep -aqE '\$_COOKIE|gl_google_advisor_|base64_decode' "$f" 2>/dev/null; then
        hit_high "vendor/magento/framework/App/View.php reads a cookie or decodes base64, which the stock file does not: a remote file include was added (StyleSmuggler follow-up)"
    fi
    # 6. stage one of StyleSmuggler: PHP stored in Magento's own report and log files
    if [[ -d "$root/var/report" && ! -L "$root/var/report" ]]; then
        cnt="$(timeout 180 grep -rlaiE '<\?(php|=)|template_styles|x_trace_|MGPROOF::|MGKWSIM::' "$root/var/report" 2>/dev/null | wc -l)"
        [[ "$cnt" -gt 0 ]] && hit_high "${cnt} file(s) in var/report hold PHP code or StyleSmuggler markers: stage one of the chain was delivered; check whether stage two ran (processes, cron and files below)"
    fi
    for f in "$root"/var/log/system.log "$root"/var/log/exception.log "$root"/var/log/debug.log; do
        regular "$f" || continue
        cnt="$(timeout 120 grep -acE '<\?(php|=)' "$f" 2>/dev/null)"; cnt="${cnt:-0}"
        [[ "$cnt" -gt 0 ]] && hit_med "${f#"$root"/}: ${cnt} line(s) with a PHP open tag (StyleSmuggler log poisoning, or the recon probe in a Store header)"
    done
    f="$root/var/log/exception.log"
    if regular "$f"; then
        local la mf st gu
        la="$(timeout 120 grep -acF 'Laminas\Loader\Exception\InvalidArgumentException' "$f" 2>/dev/null)"
        mf="$(timeout 120 grep -acF 'Map file provided does not exist' "$f" 2>/dev/null)"
        st="$(timeout 120 grep -acF 'Requested store is not found (<?' "$f" 2>/dev/null)"
        gu="$(timeout 120 grep -acF 'Variable "$guard" of required type "Boolean!" was not provided' "$f" 2>/dev/null)"
        [[ "${la:-0}" -gt 0 ]] && hit_med "exception.log: ${la} Laminas ClassMapAutoloader error(s), one per StyleSmuggler stage-two attempt; ${mf:-0} of them failed to include (Magento_Support doubles these counts where it is enabled). Days with attempts and fewer failures than attempts are the ones to examine"
        [[ "${st:-0}" -gt 0 ]] && hit_med "exception.log: ${st} 'Requested store is not found (<?' line(s): PHP sent in the Store header, the second crew's recon probe"
        [[ "${gu:-0}" -gt 0 ]] && hit_med "exception.log: ${gu} GraphQL error(s) for a \$guard variable that no Magento schema declares: attacker tooling"
    fi
    # 7. the database, which this script does not open
    step "Database (not read by this script)"
    inf "PolyShell and StyleSmuggler crews store skimmer loaders in CMS blocks, pages and the HTML head setting, and a rogue admin account outlives any patch. Run these read-only queries yourself (add your table prefix if the store uses one):"
    local re; re="$(tr ' ' '|' <<<"$LOADER_DOMAINS" | sed 's/\./\\\\./g')"
    echo "      SELECT block_id, identifier, update_time FROM cms_block WHERE content REGEXP '${re}';"
    echo "      SELECT page_id, identifier, update_time FROM cms_page WHERE content REGEXP '${re}';"
    echo "      SELECT config_id, scope, scope_id, path FROM core_config_data WHERE path LIKE 'design/head/%' AND value REGEXP '${re}|<script';"
    echo "      SELECT user_id, username, email, created, logdate FROM admin_user ORDER BY created DESC LIMIT 20;"
    return 0
}

hunt_host() {
    step "This host: processes, cron, temporary folders and connections"
    limited_view "processes, cron spools and home folders"
    local p args uid ppid exe comm l
    for p in /proc/[0-9]*; do
        [[ -r "$p/status" ]] || continue
        args="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"; args="${args% }"
        [[ -n "$args" ]] || continue          # kernel threads have an empty cmdline
        uid="$(awk '/^Uid:/ {print $2; exit}' "$p/status" 2>/dev/null)"
        ppid="$(awk '/^PPid:/ {print $2; exit}' "$p/status" 2>/dev/null)"
        comm="$(cat "$p/comm" 2>/dev/null)"
        exe="$(readlink "$p/exe" 2>/dev/null)"
        if [[ "$args" == \[* ]]; then
            hit_high "process ${p#/proc/} (uid ${uid}) calls itself '${args}': a kernel-thread name on a real program, the StyleSmuggler implant disguise$( [[ -n "$exe" ]] && echo ", running ${exe}" )"
            l="$(known_hash "$p/exe")"; [[ -n "$l" ]] && inf "  its binary matches: ${l}"
            continue
        fi
        if [[ "$args" =~ ^sshd:\ [^\ ]+@notty && "$ppid" == 1 ]]; then
            hit_high "process ${p#/proc/} '${args}' has PID 1 as its parent, which no real sshd session process has (WraithC2 disguise)"; continue
        fi
        case "$exe" in
            /tmp/*|/var/tmp/*|/dev/shm/*|*/.local/share/.gvfsd/*|*/.cache/fontconfig/*|*/.gsusr-*/*)
                l="$(known_hash "$p/exe")"
                case "$comm" in
                    fc-cache|chronyd|gvfsd-user|defunct|kstrp|ksmd|kworker*|bash|-bash|sshd) hit_high "process ${p#/proc/} '${comm}' runs ${exe}: a system name on a binary in a temporary or hidden folder$( [[ -n "$l" ]] && echo " (${l})" )" ;;
                    *) if [[ -n "$l" ]]; then hit_high "process ${p#/proc/} runs ${exe}: ${l}"; else hit_med "process ${p#/proc/} '${comm}' (uid ${uid}) runs ${exe}, a temporary or hidden folder"; fi ;;
                esac ;;
        esac
        if [[ "$comm" == chronyd && -n "$exe" && ! "$exe" =~ ^/(usr/)?s?bin/ ]]; then hit_high "process ${p#/proc/} is called chronyd but runs ${exe}"; fi
    done
    # dropped files
    local g f
    shopt -s nullglob dotglob
    for g in /tmp/.kw_* /var/tmp/.kw_* /dev/shm/.kw_* /tmp/.fc-*/fc-cache /tmp/fc-cache /tmp/.fc_*.lock /tmp/.chrony-*/chronyd /tmp/.gvfsd-* \
             /tmp/systemd-private-*php*fpm*/tmp/.dbus-session-* /tmp/systemd-private-*php*fpm*/tmp/.dbus/dbus-session-* \
             /tmp/systemd-private-*php*fpm*/tmp/.pipewire-session-* /tmp/systemd-private-*php*fpm*/tmp/.pipewire/pipewire-session-* \
             /tmp/systemd-private-*php*fpm*/tmp/.dbus/.c2 /tmp/systemd-private-*php*fpm*/tmp/.gsusr-*/defunct \
             /tmp/systemd-private-*php*fpm*/tmp/adminer.version /tmp/.dbus_*.lock; do
        [[ -e "$g" || -L "$g" ]] || continue
        if [[ -L "$g" ]]; then hit_high "${g}: a published StyleSmuggler drop path (a symbolic link here)"; continue; fi
        l=""; regular "$g" && l="$(known_hash "$g")"
        hit_high "${g}: a published StyleSmuggler drop path$( [[ -n "$l" ]] && echo " (${l})" )"
    done
    while IFS=: read -r _ _ uid _ _ f _; do
        [[ -n "$f" && "$f" == /* && -d "$f" && ! -L "$f" ]] || continue
        for g in "$f/.local/share/.gvfsd/gvfsd-user" "$f/.cache/fontconfig/fc-cache" "$f"/.local/share/.gvfsd/.gvfsd_*.lock; do
            [[ -e "$g" || -L "$g" ]] || continue
            l=""; regular "$g" && l="$(known_hash "$g")"
            hit_high "${g}: StyleSmuggler implant persistence$( [[ -n "$l" ]] && echo " (${l})" )"
        done
    done < <(getent passwd 2>/dev/null || cat /etc/passwd 2>/dev/null)
    shopt -u nullglob dotglob
    # cron: read the spool files themselves, because the implant writes them directly
    local -a cronf=()
    while IFS= read -r -d '' f; do cronf+=("$f"); done < <(find /var/spool/cron /etc/cron.d /etc/crontab -maxdepth 2 -type f -print0 2>/dev/null)
    if [[ ${#cronf[@]} -gt 0 ]]; then
        while IFS= read -r l; do
            [[ -n "$l" ]] && hit_high "cron entry for an implant: ${l}"
        done < <(grep -HE 'gvfsd-user|fontconfig/fc-cache|/tmp/\.chrony-|/tmp/\.fc-|/tmp/\.kw_|/tmp/fc-cache' "${cronf[@]}" 2>/dev/null | head -n 20)
    fi
    # connections to the published command servers
    local hits
    hits="$(awk -v L="$C2_ADDRS" '
        function hd(h,   i, c, v) { v = 0; h = toupper(h); for (i = 1; i <= length(h); i++) { c = index("0123456789ABCDEF", substr(h, i, 1)) - 1; v = v * 16 + c }; return v }
        function hx(h, i) { return hd(substr(h, i, 2)) }
        function v4(h) { return hx(h,7) "." hx(h,5) "." hx(h,3) "." hx(h,1) }
        BEGIN { n = split(L, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
        FNR == 1 { next }
        { split($3, r, ":"); h = r[1]; ip = ""
          if (length(h) == 8) ip = v4(h)
          else if (length(h) == 32 && substr(h, 1, 24) == "0000000000000000FFFF0000") ip = v4(substr(h, 25, 8))
          if (ip in want) print ip ":" hd(r[2]) " (" FILENAME ")" }' /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 2>/dev/null | sort -u)"
    if [[ -n "$hits" ]]; then while IFS= read -r l; do hit_high "connection to a published command server: ${l}"; done <<<"$hits"
    else inf "no open connection to the published command servers (${C2_ADDRS// /, })"; fi
    return 0
}

hunt_logs() {
    step "Web server access logs, last ${HUNT_DAYS} days"
    local -a logs=(); local f
    local -a ld=(); local x
    for x in $LOG_DIRS; do [[ -d "$x" && ! -L "$x" ]] && ld+=("$x"); done
    [[ ${#ld[@]} -gt 0 ]] && while IFS= read -r -d '' f; do regular "$f" && logs+=("$f"); done < <(find "${ld[@]}" \
        -maxdepth 4 -type f \( -name '*access*log*' -o -name 'access_log*' \) -mtime "-${HUNT_DAYS}" -print0 2>/dev/null)
    if [[ ${#logs[@]} -eq 0 ]]; then caution "no access log changed in the last ${HUNT_DAYS} days was found under ${LOG_DIRS}: a clean result here means nothing"; return 0; fi
    inf "${#logs[@]} log file(s)"
    local before=$((N_HIGH + N_MED))
    local tmp ipre; mk_tmp tmp
    ipre="^($(tr -s ' \n' '\n\n' <<<"$SRC_ADDRS" | grep -v '^$' | sed 's/\./\\./g' | paste -sd '|'))[[:space:]]"
    for f in "${logs[@]}"; do
        timeout 300 zcat -f -- "$f" 2>/dev/null | grep -aE "${ipre}|"'custom_options|guest-carts/[^/ ]+/items|styles(\[|%5B)|template_styles|generatorClass|with_resolved|/paypal/transparent/response/?\?(<\?|%3C%3F)|accesson\.php|catalog/product/cache/ss_[0-9a-f]+/sync_|/graphql' >> "$tmp"
    done
    local c ips
    c="$(grep -acE '"[A-Z]+ [^"]*/media/custom_options/[^" ]*\.(php[0-9]?|phtml|phar)[^"]*" 200 ' "$tmp")"
    [[ "$c" -gt 0 ]] && hit_high "${c} request(s) for PHP in the upload folder answered 200: an uploaded shell was served; from $(grep -aE '"[A-Z]+ [^"]*/media/custom_options/[^" ]*\.(php[0-9]?|phtml|phar)[^"]*" 200 ' "$tmp" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 | awk '{printf "%s (%s) ", $2, $1}')"
    c="$(grep -acE '"[A-Z]+ [^"]*(accesson\.php|catalog/product/cache/ss_[0-9a-f]+/sync_[0-9a-f]+\.php)[^"]*" 200 ' "$tmp")"
    [[ "$c" -gt 0 ]] && hit_high "${c} request(s) for accesson.php or a sync_*.php cache shell answered 200"
    c="$(grep -acE '/media/custom_options/[^" ]*\.(php[0-9]?|phtml|phar)' "$tmp")"
    [[ "$c" -gt 0 ]] && hit_med "${c} request(s) for PHP in the upload folder (PolyShell probes or use)"
    # an address that uploads through a guest cart AND then asks for the upload folder
    ips="$(awk '/"(POST|PUT) [^"]*\/V1\/guest-carts\/[^\/" ]+\/items/ {u[$1]=1} /\/media\/custom_options\// {m[$1]=1} END {for (i in u) if (i in m) print i}' "$tmp" | head -n 10 | tr '\n' ' ')"
    [[ -n "$ips" ]] && hit_med "address(es) that posted to a guest cart and then requested the upload folder: ${ips}"
    c="$(grep -acE 'styles(\[|%5B)|template_styles|generatorClass|with_resolved|/paypal/transparent/response/?\?(<\?|%3C%3F)' "$tmp")"
    [[ "$c" -gt 0 ]] && hit_med "${c} StyleSmuggler request(s) (styles[ parameters or PHP in the PayPal response query); from $(grep -aE 'styles(\[|%5B)|template_styles|generatorClass|with_resolved|/paypal/transparent/response/?\?(<\?|%3C%3F)' "$tmp" | awk '{print $1}' | sort | uniq -c | sort -rn | head -n 5 | awk '{printf "%s (%s) ", $2, $1}')"
    ips="$(awk -v L="$SRC_ADDRS" 'BEGIN {n = split(L, a, /[ \n]+/); for (i = 1; i <= n; i++) if (a[i] != "") w[a[i]] = 1} ($1 in w) {c[$1]++} END {for (i in c) print i " (" c[i] ")"}' "$tmp" | sort | head -n 15 | tr '\n' ' ')"
    [[ -n "$ips" ]] && hit_med "published PolyShell or StyleSmuggler source address(es) in these requests: ${ips}"
    [[ $((N_HIGH + N_MED)) -eq $before ]] && inf "no PolyShell or StyleSmuggler pattern in the access logs"
    return 0
}

cmd_hunt() {
    local root
    local -a roots=(); while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(find_installs "$@")
    [[ ${#roots[@]} -gt 0 ]] || info "No install found (looked for bin/magento under ${*:-/var/www /srv /home /opt}): only the host and the logs are read"
    for root in ${roots[@]+"${roots[@]}"}; do hunt_install "$root"; done
    hunt_host
    hunt_logs
    step "Verdict"
    if [[ $N_HIGH -gt 0 ]]; then
        warn "${N_HIGH} finding(s) and ${N_MED} lead(s). Treat the store as compromised: keep the evidence (do not reboot: /proc/<pid>/exe may be the only copy of a deleted binary), remove cron entries before stopping processes, then rotate the encryption key and every credential it protected (admin, integration and payment tokens, database, SSH and deploy keys)."
        return 1
    elif [[ $N_MED -gt 0 ]]; then
        warn "${N_MED} lead(s) to look at (above). Attempts are not proof of success; the file, process and cron checks are."
        return 1
    fi
    info "Nothing found in what this account could read. The database queries above are yours to run."
    return 0
}

# ---------- mitigate and rollback --------------------------------------------
# File operations in a store folder run as the account that owns the folder, so no link the web
# account plants can turn them into a root write elsewhere. Every operation works on a directory
# opened with O_NOFOLLOW and on names relative to it: nothing follows a link, a new file is created
# with O_EXCL beside the target and renamed over it, and an existing link is reported, not replaced.
PY_FS="$(cat <<'EOS'
import base64, os, secrets, stat, sys
op, d, name = sys.argv[1], sys.argv[2], sys.argv[3]
def opendir(p):
    return os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    if op == 'mkdir':
        fd = opendir(d)
        try:
            os.mkdir(name, int(sys.argv[4], 8), dir_fd=fd)
            print('created')
        except FileExistsError:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            print('exists' if stat.S_ISDIR(st.st_mode) else 'notdir')
        sys.exit(0)
    fd = opendir(d)
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if op == 'read':
        if st is None: print('missing'); sys.exit(0)
        if stat.S_ISLNK(st.st_mode): print('link'); sys.exit(0)
        if not stat.S_ISREG(st.st_mode): print('notreg'); sys.exit(0)
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        data = b''
        while True:
            c = os.read(f, 1 << 20)
            if not c: break
            data += c
        os.close(f)
        print('ok', oct(stat.S_IMODE(st.st_mode)), st.st_uid, st.st_gid)
        print(base64.b64encode(data).decode())
    elif op == 'write':
        mode = int(sys.argv[4], 8)
        if st is not None and not stat.S_ISREG(st.st_mode):
            print('link' if stat.S_ISLNK(st.st_mode) else 'notreg'); sys.exit(0)
        data = sys.stdin.buffer.read()
        tmp = '.psf-mag-' + secrets.token_hex(8)
        f = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            os.write(f, data); os.fchmod(f, mode); os.fsync(f)
        except Exception:
            os.close(f); os.unlink(tmp, dir_fd=fd); raise
        os.close(f)
        os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        print('ok')
    elif op == 'remove':
        if st is None: print('missing'); sys.exit(0)
        if not stat.S_ISREG(st.st_mode): print('notreg'); sys.exit(0)
        os.unlink(name, dir_fd=fd)
        print('ok')
except OSError as e:
    print('error', e.errno)
EOS
)"
# as_owner <dir> <op> <dir> <name> [args...]: run the helper as the account that owns <dir>
as_owner() {
    local owner_dir="$1"; shift
    local uid gid
    uid="$(stat -c %u "$owner_dir" 2>/dev/null)" || { echo "error stat"; return 0; }
    gid="$(stat -c %g "$owner_dir" 2>/dev/null)"
    if [[ "$uid" == 0 ]]; then python3 -c "$PY_FS" "$@"; return 0; fi
    if have setpriv; then setpriv --reuid="$uid" --regid="$gid" --clear-groups -- python3 -c "$PY_FS" "$@"
    elif have runuser && getent passwd "$uid" >/dev/null 2>&1; then runuser -u "$(getent passwd "$uid" | cut -d: -f1)" -- python3 -c "$PY_FS" "$@"
    else echo "error noswitch"; fi
}

htaccess_body() {
cat <<'HT'
# PrivacySafe Security Patches: Magento guard. PolyShell (CVE-2026-48356) uploads land here;
# nothing in this folder is ever served or run. Magento serves customer uploads through its own
# controller, which this file does not affect.
<IfModule mod_php.c>
    php_flag engine 0
</IfModule>
<IfModule mod_php7.c>
    php_flag engine 0
</IfModule>
<IfModule mod_authz_core.c>
    Require all denied
</IfModule>
<IfModule !mod_authz_core.c>
    Order deny,allow
    Deny from all
</IfModule>
HT
}
snippet_body() {
cat <<'SN'
# PrivacySafe Security Patches: Magento guard (CVE-2026-48356 PolyShell, CVE-2026-75650 StyleSmuggler)
# Include inside each Magento server { } block, ABOVE every PHP location:
#     include snippets/psf-magento-guard.conf;
# then run nginx -t and reload only if it passes. A guard, not a fix: apply APSB26-73 and the
# VULN-39341 hotfix. The query-string rules stop the requests seen in the wild; the same
# parameters sent in a POST body pass them.

# PolyShell: nothing in the upload folder is served, and no PHP under media runs
location ~* ^/(pub/)?media/custom_options/ { deny all; return 403; }
location ~* ^/(pub/)?media/.*\.(php[0-9]?|phtml|phar|pht|phps)$ { deny all; return 403; }

# StyleSmuggler: the gadget parameters, raw and percent-encoded, and PHP in the query or headers
if ($query_string ~* "styles(\[|%5B)") { return 444; }
if ($query_string ~* "(template_styles|generatorClass|with_resolved)") { return 444; }
if ($query_string ~* "(<\?|%3C%3F)") { return 444; }
if ($http_user_agent ~* "<\?(php|=)") { return 444; }
if ($http_store ~* "<\?") { return 444; }
SN
}

manifest_add() { mkdir -p "$STATE_DIR" && chmod 700 "$STATE_DIR" 2>/dev/null; printf '%s\t%s\t%s\t%s\t%s\n' "$@" >> "$STATE_DIR/manifest"; }

cmd_mitigate() {
    local dry=0 do_nginx=1 a
    local -a where=()
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --no-nginx) do_nginx=0 ;; -*) die "Unknown option: $a (mitigate [--dry-run] [--no-nginx] [DIR ...])" ;; *) where+=("$a") ;; esac; done
    [[ $dry -eq 1 ]] || need_root "mitigate writes files in the stores and in the nginx configuration"
    [[ $dry -eq 1 ]] || have python3 || die "mitigate needs python3: it writes without following links"
    local root media d st stamp bk failed=0 changed=0 out mode uid gid
    stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"; bk="${STATE_DIR}/backups/${stamp}"
    local -a roots=(); while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(find_installs ${where[@]+"${where[@]}"})
    step "The PolyShell upload folder in each store"
    [[ ${#roots[@]} -gt 0 ]] || inf "no install found under ${where[*]:-/var/www /srv /home /opt}"
    for root in ${roots[@]+"${roots[@]}"}; do
        media="$root/pub/media"
        if [[ ! -d "$media" ]]; then caution "${root}: no pub/media folder, left alone"; continue; fi
        d="$media/custom_options"
        if [[ -L "$d" ]]; then bad "${d}: a symbolic link, left alone: close it by hand"; failed=$((failed + 1)); continue; fi
        st="$(htaccess_state "$root")"
        case "$st" in
            closed) ok "${root}: the .htaccess already denies all access"; continue ;;
            link) bad "${d}/.htaccess: a symbolic link, left alone: replace it with a regular file by hand"; failed=$((failed + 1)); continue ;;
        esac
        if [[ $dry -eq 1 ]]; then inf "would write ${d}/.htaccess (now ${st}), as the owner of ${media}"; continue; fi
        mkdir -p "$bk" && chmod 700 "$STATE_DIR" "$STATE_DIR/backups" "$bk" 2>/dev/null
        if [[ ! -d "$d" ]]; then
            out="$(as_owner "$media" mkdir "$media" custom_options 0755)"
            [[ "$out" == created || "$out" == exists ]] || { bad "${d}: could not be created (${out})"; failed=$((failed + 1)); continue; }
        fi
        if [[ "$st" == open ]]; then
            out="$(as_owner "$d" read "$d" .htaccess)"
            read -r a mode uid gid <<<"$(head -n1 <<<"$out")"
            if [[ "$a" != ok ]]; then bad "${d}/.htaccess: could not be read (${a}), left alone"; failed=$((failed + 1)); continue; fi
            local b; b="${bk}/$(printf '%s' "$d/.htaccess" | sed 's#/#_#g')"
            tail -n +2 <<<"$out" | base64 -d > "$b" 2>/dev/null || { bad "${d}/.htaccess: could not copy it to ${b}, left alone"; failed=$((failed + 1)); continue; }
            chmod 600 "$b"
            out="$(htaccess_body | as_owner "$d" write "$d" .htaccess "${mode#0o}")"
            if [[ "$out" == ok ]]; then manifest_add "$stamp" htaccess "$d/.htaccess" "$b" "${mode#0o}"; changed=$((changed + 1))
            else bad "${d}/.htaccess: not replaced (${out})"; failed=$((failed + 1)); continue; fi
        else
            out="$(htaccess_body | as_owner "$d" write "$d" .htaccess 644)"
            if [[ "$out" == ok ]]; then manifest_add "$stamp" htaccess "$d/.htaccess" - 644; changed=$((changed + 1))
            else bad "${d}/.htaccess: not written (${out})"; failed=$((failed + 1)); continue; fi
        fi
        if [[ "$(htaccess_state "$root")" == closed ]]; then info "${d}/.htaccess: PHP off, all access denied"
        else bad "${d}/.htaccess: written but does not read back as closed: check it by hand"; failed=$((failed + 1)); fi
    done

    if [[ $do_nginx -eq 1 ]]; then
        step "nginx guard snippet"
        local sd="$NGINX_SNIPPET_DIR" sf="$NGINX_SNIPPET_DIR/$SNIPPET_NAME" cur
        if [[ ! -d "$(dirname "$sd")" ]]; then inf "no $(dirname "$sd") folder: nginx is not installed here, no snippet written"
        elif [[ -L "$sd" || -L "$sf" ]]; then bad "${sd} or ${sf} is a symbolic link: no snippet written"; failed=$((failed + 1))
        elif regular "$sf" && [[ "$(cat "$sf")" == "$(snippet_body)" ]]; then ok "${sf} is already current"
        elif [[ $dry -eq 1 ]]; then inf "would write ${sf}"
        else
            mkdir -p "$bk" && chmod 700 "$STATE_DIR" "$STATE_DIR/backups" "$bk" 2>/dev/null
            if [[ ! -d "$sd" ]]; then
                out="$(python3 -c "$PY_FS" mkdir "$(dirname "$sd")" "$(basename "$sd")" 0755)"
                [[ "$out" == created || "$out" == exists ]] || { bad "${sd}: could not be created (${out})"; failed=$((failed + 1)); }
            fi
            if [[ -d "$sd" ]]; then
                cur=-
                if regular "$sf"; then cur="${bk}/$(printf '%s' "$sf" | sed 's#/#_#g')"; cp -p -- "$sf" "$cur" && chmod 600 "$cur"; fi
                out="$(snippet_body | python3 -c "$PY_FS" write "$sd" "$SNIPPET_NAME" 644)"
                if [[ "$out" == ok ]]; then manifest_add "$stamp" snippet "$sf" "$cur" 644; changed=$((changed + 1)); info "wrote ${sf}"
                else bad "${sf}: not written (${out})"; failed=$((failed + 1)); fi
            fi
        fi
        if regular "$sf" || [[ $dry -eq 1 ]]; then
            NGX_STATE=""; judge_nginx
            if [[ "$NGX_WHERE" == *"$SNIPPET_NAME"* ]]; then ok "the snippet is included: ${NGX_WHERE}"
            else warn "Not included yet: add 'include snippets/${SNIPPET_NAME};' at the top of each Magento server block (above every PHP location), run 'nginx -t', and reload nginx only if it passes. Nothing was reloaded."; fi
        fi
    fi
    step "Verdict"
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was written."; return 0; fi
    if [[ $failed -gt 0 ]]; then warn "${failed} item(s) could not be changed (above)."; return 1; fi
    if [[ $changed -gt 0 ]]; then warn "Upload folder closed where it was open. This is a guard, not a fix: uploads still reach the disk until APSB26-73 (or a July 2026 or later release) is in, and StyleSmuggler needs hotfix VULN-39341. Run hunt. To undo: sudo ${SELF} rollback"
    else info "Nothing needed changing."; fi
    return 0
}

cmd_rollback() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (rollback [--dry-run])" ;; esac; done
    local manifest="${STATE_DIR}/manifest"
    [[ -s "$manifest" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes files in the stores and in the nginx configuration"
    [[ $dry -eq 1 ]] || have python3 || die "rollback needs python3, to write without following links"
    step "Rolling back"
    local rc=0 stamp kind path b mode d n out
    # newest first, so where two runs saved the same file, the oldest copy, the true original, is put back last
    while IFS=$'\t' read -r stamp kind path b mode; do
        [[ -n "$path" ]] || continue
        d="$(dirname "$path")"; n="$(basename "$path")"
        if [[ "$b" == - ]]; then
            if regular "$path"; then
                local want
                if [[ "$kind" == snippet ]]; then want="$(snippet_body)"; else want="$(htaccess_body)"; fi
                [[ "$(cat "$path" 2>/dev/null)" == "$want" ]] || { caution "${path}: changed since mitigate created it, left alone: remove it by hand if you no longer want it"; rc=1; continue; }
            fi
            if [[ $dry -eq 1 ]]; then echo "  would remove ${path} (created by mitigate)"; continue; fi
            if [[ "$kind" == snippet ]]; then out="$(python3 -c "$PY_FS" remove "$d" "$n")"; else out="$(as_owner "$d" remove "$d" "$n")"; fi
            case "$out" in ok|missing) info "removed ${path}" ;; *) bad "${path}: not removed (${out})"; rc=1 ;; esac
        else
            [[ -r "$b" ]] || { bad "${path}: its copy ${b} is missing, left alone"; rc=1; continue; }
            if [[ $dry -eq 1 ]]; then echo "  would restore ${path} from ${b}"; continue; fi
            if [[ "$kind" == snippet ]]; then out="$(python3 -c "$PY_FS" write "$d" "$n" "${mode:-644}" < "$b")"; else out="$(as_owner "$d" write "$d" "$n" "${mode:-644}" < "$b")"; fi
            [[ "$out" == ok ]] && info "restored ${path}" || { bad "${path}: not restored from ${b} (${out})"; rc=1; }
        fi
    done < <(tac "$manifest")
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was written."; return "$rc"; fi
    [[ $rc -eq 0 ]] && mv "$manifest" "${manifest}.rolled-back-$(date +%s)" 2>/dev/null
    [[ $rc -eq 0 ]] && warn "Rolled back. If nginx includes the snippet, remove the include line, run nginx -t and reload."
    return "$rc"
}

# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a
# dry run, run the script again under flock(1), so two runs cannot interleave their changes. The
# second run waits PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. The lock file is
# STATE_DIR/.lock. Without flock nothing is locked. PSF_LOCK_HELD marks the re-run: leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
    done
    [[ $lk_hit -eq 1 ]] || return 0
    psf_refuse_change "lock_for_change"
    have flock || return 0
    lk_dir="$STATE_DIR"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Magento, Adobe Commerce and Mage-OS: CVE-2026-48356 (PolyShell), CVE-2026-71362, CVE-2026-75650 (StyleSmuggler), CVE-2026-103849 (BlockStrap)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
