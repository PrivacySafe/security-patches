#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache CouchDB admin-to-OS-command execution: read-only checker  (v1)
# CVE-2026-86471
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# An unvalidated runtime configuration value in Apache CouchDB lets a CouchDB
# server admin run arbitrary shell commands as the operating system user that
# runs CouchDB. CVSS 9.3 on the v4 scale. The attacker needs server-admin
# credentials, so this is a privilege escalation from a CouchDB admin (a stolen
# or weak admin password, an exposed admin interface, or a compromised
# application that holds admin credentials) to the host. It is not a flaw an
# anonymous visitor can use alone.
#
#   Affected: Apache CouchDB 3.5.2 and earlier, on all platforms
#   Fixed:    3.5.3
#
# The same release fixes other CouchDB flaws, among them a pre-authentication
# gzip decompression bomb on POST /_session. That one needs no credentials, which
# is why it matters whether the node listens beyond localhost.
#
# This script is read-only. It reads the CouchDB version from the release files
# (releases/start_erl.data), the installed package, and, if you give it URLs, from
# a single unauthenticated GET of the server's root document. It reads the ini
# files for the bind address, require_valid_user and how many admin entries
# exist. It NEVER prints a value from the [admins] section (they are password
# hashes or passwords).
#
# Usage:
#   ./couchdb-check.sh [command] [URL ...]
#
#   check (default)  Exit 0 = nothing affected, 1 = an affected version was found.
#                    With URL arguments (such as http://10.0.0.5:5984/) it also
#                    asks each server for its version. Without arguments it asks
#                    only http://127.0.0.1:5984/ and ignores a refusal.
#   version          print the script version.
#
# Environment: COUCHDB_ROOT (default /opt/couchdb) and COUCHDB_ETC (space
# separated, default "/opt/couchdb/etc /etc/couchdb /usr/local/etc/couchdb")
# point the script at unusual layouts.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="couchdb-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"

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

# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
DISTRO_PKG=""; DISTRO_HIT=""
distro_mentions() {
    local f real pkg="" cl="" c id
    f="$1"; shift
    real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if have dpkg; then
        pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] && cl+="$(zcat "$c" 2>/dev/null)"
            done
        fi
    fi
    if [[ -z "$pkg" ]] && have rpm; then
        pkg="$(rpm -qf "$real" 2>/dev/null | head -n1)"
        [[ "$pkg" == *"not owned"* ]] && pkg=""
        [[ -n "$pkg" ]] && cl="$(rpm -q --changelog "$pkg" 2>/dev/null)"
    fi
    [[ -n "$pkg" ]] || return 2
    DISTRO_PKG="$pkg"
    for id in "$@"; do
        if grep -qF "$id" <<<"$cl"; then DISTRO_HIT="$id"; return 0; fi
    done
    return 1
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- helpers ----------------------------------------------------------
couch_affected() { ver_lt "$1" "3.5.3"; }

AFFECTED=0; CHECKED=0
report() {   # label version [probe file for the distribution check]
    local label="$1" ver="$2" probe="${3:-}"
    CHECKED=$((CHECKED+1))
    if ! is_semver "$(norm_ver "$ver")"; then caution "${label}: cannot parse version '${ver}'; treating it as not confirmed fixed"; AFFECTED=$((AFFECTED+1)); return 0; fi
    if ! couch_affected "$ver"; then ok "${label}: CouchDB ${ver} has the fix (3.5.3 or newer)"; return 0; fi
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-86471; then
            ok "${label}: CouchDB ${ver}, and package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: a backported fix is likely"
            return 0
        elif [[ $? -eq 1 ]]; then
            bad "${label}: CouchDB ${ver} is affected by CVE-2026-86471 (fixed in 3.5.3); package ${DISTRO_PKG} does not mention it"
            AFFECTED=$((AFFECTED+1)); return 0
        fi
    fi
    bad "${label}: CouchDB ${ver} is affected by CVE-2026-86471 (fixed in 3.5.3)"
    AFFECTED=$((AFFECTED+1))
}

# ini parsing: the last value wins across default.ini, local.ini and local.d/*.ini
ini_value() {   # section key files...
    local sec="$1" key="$2"; shift 2
    local f v=""
    for f in "$@"; do
        [[ -r "$f" ]] || continue
        v2="$(awk -v sec="[$sec]" -v key="$key" '
            /^[[:space:]]*[;#]/ {next}
            /^[[:space:]]*\[/ {s=$0; gsub(/[[:space:]]/,"",s); cur=s; next}
            cur==sec { line=$0; sub(/^[[:space:]]+/,"",line)
                       n=index(line,"="); if(n>0){k=substr(line,1,n-1); gsub(/[[:space:]]/,"",k)
                         if(k==key){val=substr(line,n+1); sub(/^[[:space:]]+/,"",val); sub(/[[:space:]]+$/,"",val); sub(/[[:space:]]*[;#].*$/,"",val); out=val}}}
            END{print out}' "$f")"
        [[ -n "$v2" ]] && v="$v2"
    done
    printf '%s' "$v"
}
ini_count() {   # section files... -> number of key = value lines (values are never printed)
    local sec="$1"; shift
    local f t=0 n
    for f in "$@"; do
        [[ -r "$f" ]] || continue
        n="$(awk -v sec="[$sec]" '
            /^[[:space:]]*[;#]/ {next}
            /^[[:space:]]*\[/ {s=$0; gsub(/[[:space:]]/,"",s); cur=s; next}
            cur==sec && /=/ {c++}
            END{print c+0}' "$f")"
        t=$((t+n))
    done
    echo "$t"
}

# ---------- check ------------------------------------------------------------
# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
# Paths the container reports are validated before use, a symlink is never kept (docker cp copies the
# link itself, and the check would then read whatever it points to on the host), and the number of
# copied files is capped. It runs once, in the main shell (a subshell's exit would delete the copies).
STAGE=""
declare -a STAGED_DIRS=()
stage_probe() {   # <probe script, run with sh -s inside each running container>
    local probe="$1" rt id name out kind p rest s nf
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        command -v "$rt" >/dev/null 2>&1 || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            out="$(printf '%s\n' "$probe" | "$rt" exec -i "$id" sh -s 2>/dev/null | head -n 6000)" || continue
            [[ -n "$out" ]] || continue
            s=""; nf=0
            while read -r kind p rest; do
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
                if [[ -z "$s" ]]; then
                    if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; trap 'rm -rf "${STAGE:-}"' EXIT; fi
                    s="$STAGE/${rt}_${name:-$id}"; mkdir -p "$s"
                fi
                case "$kind" in
                    F) nf=$((nf + 1)); [[ $nf -le 400 ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       "$rt" cp "${id}:${p}" "$s$p" >/dev/null 2>&1 || rm -f "$s$p"
                       [[ -L "$s$p" ]] && rm -f "$s$p" ;;
                    D) mkdir -p "$s$p" ;;
                    E) mkdir -p "$s$(dirname "$p")"; : > "$s$p" ;;
                    L) [[ "$rest" =~ ^[A-Za-z0-9_=.,:/@-]{0,120}$ ]] || continue
                       mkdir -p "$s$(dirname "$p")"; printf '%s\n' "$rest" > "$s$p" ;;
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

COUCHDB_PROBE="$(cat <<'EOS'
find /opt /usr/local /home /srv -maxdepth 4 -path "*/releases/start_erl.data" -type f 2>/dev/null | head -n 5 | while read -r l; do
  r=${l%/releases/start_erl.data}
  echo "F $l"
  for e in "$r/etc" /etc/couchdb /usr/local/etc/couchdb; do
    [ -d "$e" ] && find "$e" -maxdepth 2 -type f -name "*.ini" -size -512k 2>/dev/null | head -n 20 | while read -r p; do
      echo "B $p $(awk '/^\[/ {s=$0} s=="[admins]" && /=/ {sub(/=.*/,"= REDACTED"); print; next} {print}' "$p" | base64 | tr -d '\n')"
    done
  done
done
exit 0
EOS
)"

container_run() {   # <staged directory> : CouchDB in one container, judged by this script run in isolation
    local s="$1" out rc l r bad_rc=0; local -i n=0
    while IFS= read -r l; do
        [[ -n "$l" ]] || continue
        r="${l%/releases/start_erl.data}"; n=$((n + 1))
        step "CouchDB in a container (${s##*/}), ${r#"$s"}"
        out="$(SCAN_CONTAINERS=0 COUCHDB_ISOLATED=1 COUCHDB_ROOT="$r" COUCHDB_ETC="$r/etc $s/etc/couchdb $s/usr/local/etc/couchdb" bash "$SELF" check  2>&1)"; rc=$?
        tail -n +3 <<<"$out"
        [[ $rc -eq 0 ]] || bad_rc=1
    done < <(find "$s" -path '*/releases/start_erl.data' -type f 2>/dev/null)
    return "$bad_rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$COUCHDB_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local root="${COUCHDB_ROOT:-/opt/couchdb}"
    local -a urls=() inis=() etcs=()
    local f v d u body pv etc bind rvu na
    # versions on disk
    step "CouchDB installation"
    local found=0
    f="${root}/releases/start_erl.data"
    if [[ -r "$f" ]]; then
        v="$(awk '{print $2}' "$f" | head -n1)"
        [[ -n "$v" ]] && { found=1; report "${f}" "$v" "${root}/bin/couchdb"; }
    fi
    if [[ -d "${root}/releases" ]]; then
        for d in "${root}"/releases/[0-9]*; do
            [[ -d "$d" ]] || continue
            v="$(basename "$d")"
            [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            # skip the one already reported from start_erl.data
            [[ -r "${root}/releases/start_erl.data" && "$(awk '{print $2}' "${root}/releases/start_erl.data")" == "$v" ]] && continue
            found=1; inf "also present: ${d} (an older release directory, not necessarily the running one)"
        done
    fi
    # package manager
    pv=""
    if have dpkg; then pv="$(dpkg-query -W -f='${Version}' couchdb 2>/dev/null)"; fi
    if [[ -z "$pv" ]] && have rpm; then pv="$(rpm -q --qf '%{VERSION}' couchdb 2>/dev/null | grep -v 'not installed')"; fi
    if [[ -n "$pv" ]]; then
        found=1
        v="$(norm_ver "$pv")"
        if [[ "$(norm_ver "$v")" == "$(awk '{print $2}' "${root}/releases/start_erl.data" 2>/dev/null | head -n1)" ]]; then
            inf "package version ${pv} matches the release files"
        else
            report "package couchdb ${pv}" "$v" ""
        fi
    fi
    # live server (read-only GET of the root document)
    if [[ $# -gt 0 ]]; then urls=("$@"); else urls=("http://127.0.0.1:5984/"); fi
    # a run staged from a container reads only the copied files: no package database, no live server
    if [[ -n "${COUCHDB_ISOLATED:-}" ]]; then urls=(); fi
    if [[ -n "${COUCHDB_ISOLATED:-}" ]]; then :
    elif have curl; then
        for u in "${urls[@]}"; do
            body="$(curl -fsS --max-time 4 "$u" 2>/dev/null)" || { [[ $# -gt 0 ]] && inf "${u}: no answer (down, filtered, or it requires a login)"; continue; }
            v="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' <<<"$body" | head -n1)"
            if [[ -n "$v" && "$body" == *'"couchdb"'* ]]; then found=1; report "server at ${u}" "$v" ""; fi
        done
    else
        inf "curl not found: the live server was not asked for its version"
    fi
    [[ $found -eq 0 ]] && inf "no CouchDB found at ${root}, in the package database, or at the URL(s) probed"

    step "Configuration"
    read -r -a etcs <<<"${COUCHDB_ETC:-/opt/couchdb/etc /etc/couchdb /usr/local/etc/couchdb}"
    for etc in "${etcs[@]}"; do
        [[ -d "$etc" ]] || continue
        shopt -s nullglob
        for f in "$etc/default.ini" "$etc/default.d"/*.ini "$etc/local.ini" "$etc/local.d"/*.ini; do [[ -r "$f" ]] && inis+=("$f"); done
        shopt -u nullglob
    done
    if [[ ${#inis[@]} -eq 0 ]]; then
        inf "no readable CouchDB ini files (looked in: ${etcs[*]})"
    else
        inf "read ${#inis[@]} ini file(s) under: ${etcs[*]}"
        bind="$(ini_value chttpd bind_address "${inis[@]}")"
        rvu="$(ini_value chttpd require_valid_user "${inis[@]}")"
        na="$(ini_count admins "${inis[@]}")"
        case "$bind" in
            0.0.0.0|::|"[::]") caution "chttpd bind_address is ${bind}: CouchDB listens on every interface, so the unauthenticated /_session gzip flaw fixed in the same release is reachable by anyone who can connect" ;;
            127.0.0.1|localhost|::1) ok "chttpd bind_address is ${bind}: loopback only" ;;
            "") inf "chttpd bind_address not set in these files (the compiled default applies)" ;;
            *) inf "chttpd bind_address is ${bind}: confirm that address is not reachable from untrusted networks" ;;
        esac
        [[ "$rvu" == "true" ]] && inf "require_valid_user is true: anonymous requests are refused" \
            || inf "require_valid_user is not true: some endpoints answer without a login"
        inf "${na} entr(y/ies) in [admins] across these files (values are not read out); this CVE needs one of these credentials, or admin rights granted another way"
    fi

    step "Verdict"
    if [[ $CHECKED -eq 0 ]]; then
        info "No CouchDB version could be read"
    elif [[ $AFFECTED -eq 0 ]]; then
        info "No affected CouchDB found (${CHECKED} checked)"
    else
        warn "${AFFECTED} affected CouchDB instance(s) of ${CHECKED} checked. Upgrade to 3.5.3 or later."
        inf "PrivacySafe recommendation: keep port 5984 off untrusted networks, give admins long unique passwords, and do not let applications hold admin credentials they do not need."
        inf "After upgrading, rotate any admin password that may have been exposed."
        inf "Release information: https://couchdb.apache.org/"
    fi
    [[ $AFFECTED -eq 0 ]]
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-86471; fixed in Apache CouchDB 3.5.3"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
