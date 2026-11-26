#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Next.js Server Actions denial of service, the August, October and November 2026
# security releases, and the image libraries sharp bundles: read-only checker  (v1)
# CVE-2026-94482; CVE-2026-119346, CVE-2026-119347, CVE-2026-119348, CVE-2026-119349,
# CVE-2026-119350, CVE-2026-119351, CVE-2026-119790; CVE-2026-96889, CVE-2026-75604;
# sharp: CVE-2026-114111, CVE-2026-114112, CVE-2026-114113
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Crafted requests aimed at a Next.js App Router application that has at least
# one Server Action can cause excessive CPU consumption and block the processing
# of further requests in the same Node.js process. CVSS 8.2 (v4.0), 7.5 (v3).
# No authentication is needed.
#
#   Affected: next 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1
#   Fixed:    15.5.28 and 16.4.1
#   Not affected: Pages Router applications, and App Router applications that
#   have no Server Action.
#
# Next.js 13.x and 14.x apps move to 15.5.28 or later.
#
# The November 2026 security release (3 November: 15.5.29 and 16.4.5) fixes seven
# more flaws, and an app needs it whether or not it has a Server Action:
#   CVE-2026-119790  cache disclosure across root params, use cache + unstable_cache (16.3.0+)
#   CVE-2026-119351  cache disclosure across root params, nested use cache (16.2.0+)
#   CVE-2026-119349  cross-user cache disclosure and poisoning, binary use cache arguments (16.x)
#   CVE-2026-119350  shared shell cache poisoning, Cache Components (16.4.0+)
#   CVE-2026-119348  cross-client response injection behind a pipelining HTTP/1.1 proxy,
#                    self-hosted (all lines before 15.5.29; 16.x before 16.4.5)
#   CVE-2026-119346  HttpOnly cookie values exposed on Edge routes (15.x and 16.x); on
#                    Netlify also cookies set in Middleware, fixed only in the Netlify
#                    adapter @netlify/plugin-nextjs 5.16.6, which this script also checks
#                    where a lockfile pins it
#   CVE-2026-119347  SVG rejection bypass in image optimization (15.x and 16.x)
# Most need a particular feature, but this script cannot see features at run time,
# so a version before 15.5.29 (15.x) or 16.4.5 (16.x) is reported as missing the
# release. 13.x and 14.x get no November fix: move to 15.5.29 or 16.4.5.
#
# Earlier releases, named for every version that still carries them:
#   GHSA-673q-mjm6-r5xr (no CVE; React upstream CVE-2026-126187), 14 October, critical:
#                    unauthenticated code execution when a use cache function returns
#                    multiple typed arrays (16.0.0 to 16.4.0; fixed 16.4.1; no workaround)
#   CVE-2026-96889   14 October, critical: code execution in image optimization through SVG
#                    (librsvg inside sharp) on glibc GNU/Linux (10.0.0 to 15.5.27, 16.0.0 to
#                    16.4.0; fixed 15.5.28 and 16.4.1; workaround sharp 0.35.5 or later)
#   CVE-2026-75604   25 August, critical: path traversal to code execution on servers using
#                    a Windows filesystem (13.4.0 to 15.5.23, 16.0.0 to 16.3.2; fixed 15.5.24
#                    and 16.3.3); GNU/Linux and macOS are not affected
#   GHSA-2xp9-vwfh-vxw4  25 August, critical: code execution through AVIF images (libheif
#                    inside sharp); 15.5.24 and 16.3.3 turn AVIF optimization off
#
# sharp: an upgraded Next.js still runs whatever sharp the lockfile or an override pins, and
# the bundled image libraries are the code execution path. For each Next.js project the
# script reads the sharp versions in its lockfiles and node_modules and reports:
#   before 0.35.5  CVE-2026-114111  librsvg (SVG)
#   before 0.35.4  CVE-2026-114112  libheif (AVIF and HEIF)
#   before 0.35.0  CVE-2026-114113  libvips (GIF, TIFF and VIPS decoders)
#
# This script is read-only. It reads the Next.js version from package-lock.json,
# npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml and from installed
# node_modules/next copies, then checks the project for the App Router and for
# Server Actions ("use server" directives, or a populated
# .next/server/server-reference-manifest.json for built-only deployments).
#
# Usage:
#   ./nextjs-server-actions-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home).
#                    Exit 0 = nothing exposed, 1 = an affected project with
#                    Server Actions was found, a version is missing the
#                    November 2026 release, a project carries sharp before
#                    0.35.5, a version could not be parsed, or an install is
#                    older than 13.0.0.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="nextjs-server-actions-check.sh"
SCRIPT_VERSION="1.4.0"
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

# ---------- version rule -----------------------------------------------------
# affected: 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1
next_affected() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || return 1
    ver_lt "$v" "13.0.0" && return 1
    if (( ${v%%.*} >= 16 )); then ver_lt "$v" "16.4.1"; else ver_lt "$v" "15.5.28"; fi
}

# ---------- lock file parsers (each prints every Next.js version it finds) ---
# What a project turns on, read from next.config.* and, for built-only deployments, from
# .next/required-server-files.json (the config the build used). Read-only. Prints one line per
# finding: "cacheComponents", "partialPrefetching", "use-cache N" (files with the directive),
# "cache-store" (a cacheHandler or cacheHandlers store, which keeps entries across restarts).
cache_features() {   # <project dir>
    local d="$1" c f n
    c="$(cat "$d"/next.config.js "$d"/next.config.mjs "$d"/next.config.cjs "$d"/next.config.ts "$d"/next.config.mts \
             "$d"/.next/required-server-files.json 2>/dev/null | head -c 2000000)"
    grep -qE '"?cacheComponents"?[[:space:]]*:[[:space:]]*true' <<<"$c" && echo cacheComponents
    grep -qE '"?partialPrefetching"?[[:space:]]*:[[:space:]]*true' <<<"$c" && echo partialPrefetching
    grep -qE '"?cacheHandlers?"?[[:space:]]*:[[:space:]]*["{a-zA-Z(]' <<<"$c" && ! grep -qE '"cacheHandlers?"[[:space:]]*:[[:space:]]*(null|\{\})' <<<"$c" && echo cache-store
    n="$(grep -rlE "^[[:space:]]*['\"]use cache(: *[a-z]+)?['\"]" --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
             --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git "$d" 2>/dev/null | head -n 1000 | wc -l)"
    [[ "$n" -gt 0 ]] && echo "use-cache ${n}"
    return 0
}

# The November 2026 release: 15.5.29 on 15.x and earlier lines, 16.4.5 on 16.x
nov_missing() {
    local v; v="$(norm_ver "$1")"
    if (( ${v%%.*} >= 16 )); then ver_lt "$v" "16.4.5"; else ver_lt "$v" "15.5.29"; fi
}
# The November flaws this version carries, by each advisory's own range
nov_cves() {
    local v m out=""; v="$(norm_ver "$1")"; m="${v%%.*}"
    nov_missing "$v" || return 0
    if (( m >= 16 )); then
        ! ver_lt "$v" "16.3.0" && out+="CVE-2026-119790 "
        ! ver_lt "$v" "16.2.0" && out+="CVE-2026-119351 "
        out+="CVE-2026-119349 "
        ! ver_lt "$v" "16.4.0" && out+="CVE-2026-119350 "
        out+="CVE-2026-119348 CVE-2026-119346 CVE-2026-119347"
    elif (( m == 15 )); then out+="CVE-2026-119348 CVE-2026-119346 CVE-2026-119347"
    else out+="CVE-2026-119348"
    fi
    echo "${out% }"
}

# Earlier critical flaws a version still carries; one line each: "crit|text" or "info|text"
earlier_flaws() {
    local v m; v="$(norm_ver "$1")"; m="${v%%.*}"
    if (( m >= 16 )); then
        ver_lt "$v" "16.4.1" && echo "crit|GHSA-673q-mjm6-r5xr (critical, no CVE; React upstream CVE-2026-126187): unauthenticated code execution when a use cache function returns multiple typed arrays; Cache Components apps; no workaround, fixed in 16.4.1"
        ver_lt "$v" "16.4.1" && echo "crit|CVE-2026-96889 (critical): code execution in image optimization through crafted SVG (librsvg inside sharp) on glibc GNU/Linux; fixed in 16.4.1, workaround sharp 0.35.5 or later"
        ver_lt "$v" "16.3.3" && echo "info|CVE-2026-75604 (critical): path traversal to code execution, only where the server uses a Windows filesystem (GNU/Linux and macOS are not affected); fixed in 16.3.3"
        ver_lt "$v" "16.3.3" && echo "info|before 16.3.3 Next.js still optimizes AVIF images, which reaches libheif inside sharp (GHSA-2xp9-vwfh-vxw4); the sharp check below says whether that libheif is the vulnerable one"
    else
        ! ver_lt "$v" "10.0.0" && ver_lt "$v" "15.5.28" && echo "crit|CVE-2026-96889 (critical): code execution in image optimization through crafted SVG (librsvg inside sharp) on glibc GNU/Linux; fixed in 15.5.28, workaround sharp 0.35.5 or later"
        ! ver_lt "$v" "13.4.0" && ver_lt "$v" "15.5.24" && echo "info|CVE-2026-75604 (critical): path traversal to code execution, only where the server uses a Windows filesystem (GNU/Linux and macOS are not affected); fixed in 15.5.24"
        ver_lt "$v" "15.5.24" && echo "info|before 15.5.24 Next.js still optimizes AVIF images, which reaches libheif inside sharp (GHSA-2xp9-vwfh-vxw4); the sharp check below says whether that libheif is the vulnerable one"
    fi
    return 0
}

# sharp, the image library Next.js uses for optimization, bundles libvips, librsvg and libheif.
# Versions come from the project's own lockfiles and from regular package.json files under its
# node_modules; links are not followed.
SHARP_FIXED="0.35.5"
sharp_versions() {   # <project dir>
    local d="$1" f
    for f in "$d"/package-lock.json "$d"/npm-shrinkwrap.json; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        awk '/"(node_modules\/)?([^"]*\/node_modules\/)?sharp": *\{/ {f=1; next}
             f && /"version":/ { v=$2; gsub(/[",]/,"",v); print v; f=0 }' "$f" 2>/dev/null
    done
    f="$d/yarn.lock"
    if [[ -f "$f" && ! -L "$f" ]]; then
        awk '/^"?sharp@/ {f=1; next}
             f && /^[[:space:]]+version:?[[:space:]]/ { v=$2; gsub(/"/,"",v); print v; f=0 }
             /^[^ #]/ && !/^"?sharp@/ {f=0}' "$f" 2>/dev/null
    fi
    f="$d/pnpm-lock.yaml"
    [[ -f "$f" && ! -L "$f" ]] && grep -oE "(^|[[:space:]'/])sharp@[0-9]+\.[0-9]+\.[0-9]+" "$f" 2>/dev/null | sed 's/.*sharp@//'
    find "$d" -maxdepth 6 \( -name .git -o -name .next \) -prune -o -path '*/node_modules/sharp/package.json' -type f -print 2>/dev/null \
        | while IFS= read -r f; do
              grep -q '"name": *"sharp"' "$f" 2>/dev/null || continue
              sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n1
          done
    return 0
}
sharp_cves() {   # <version> -> the sharp records it carries
    local v out=""; v="$(norm_ver "$1")"
    ver_lt "$v" "0.35.0" && out+="CVE-2026-114113 (libvips: GIF, TIFF, VIPS) "
    ver_lt "$v" "0.35.4" && out+="CVE-2026-114112 (libheif: AVIF, HEIF) "
    ver_lt "$v" "0.35.5" && out+="CVE-2026-114111 (librsvg: SVG)"
    echo "${out% }"
}
svg_allowed() {   # <project dir> -> 0 if next.config or the built config turns on dangerouslyAllowSVG
    local d="$1" c
    c="$(cat "$d"/next.config.js "$d"/next.config.mjs "$d"/next.config.cjs "$d"/next.config.ts "$d"/next.config.mts \
             "$d"/.next/required-server-files.json 2>/dev/null | head -c 2000000)"
    grep -qE '"?dangerouslyAllowSVG"?[[:space:]]*:[[:space:]]*true' <<<"$c"
}

# The Netlify adapter a lockfile pins (@netlify/plugin-nextjs): 5.16.6 carries the Middleware
# part of CVE-2026-119346 on Netlify. Netlify installs the adapter itself unless a project pins it.
NETLIFY_ADAPTER_FIXED="5.16.6"
adapter_versions() {   # <lockfile>
    case "${1##*/}" in
        package-lock.json|npm-shrinkwrap.json)
            awk '/node_modules\/@netlify\/plugin-nextjs": *\{/ {f=1; next}
                 f && /"version":/ { v=$2; gsub(/[",]/,"",v); print v; f=0 }' "$1" ;;
        yarn.lock)
            awk '/^"?@netlify\/plugin-nextjs@/ {f=1; next}
                 f && /^[[:space:]]+version:?[[:space:]]/ { v=$2; gsub(/"/,"",v); print v; f=0 }
                 /^[^ #]/ && !/^"?@netlify\/plugin-nextjs@/ {f=0}' "$1" ;;
        pnpm-lock.yaml)
            grep -oE "@netlify/plugin-nextjs@[0-9]+\.[0-9]+\.[0-9]+" "$1" | sed 's/.*@//' ;;
    esac 2>/dev/null | sort -u
}

versions_npm_lock() {
    awk '
        /node_modules\/next": *\{/ {f=1; next}
        /^    "next": *\{/ {f=1; next}
        f && /"version":/ { v=$2; gsub(/[",]/,"",v); print v; f=0 }
    ' "$1" | sort -u
}
versions_yarn_lock() {
    awk '
        /^"?next@/ {f=1; next}
        f && /^[[:space:]]+version:?[[:space:]]/ { v=$2; gsub(/"/,"",v); print v; f=0 }
        /^[^ #]/ && !/^"?next@/ {f=0}
    ' "$1" | sort -u
}
versions_pnpm_lock() {
    grep -oE "^[[:space:]]+'?/?next@[0-9]+\.[0-9]+\.[0-9]+[^:(' ]*" "$1" 2>/dev/null \
        | sed -E "s/.*next@//" | sort -u
}
version_installed() {   # node_modules/next/package.json
    grep -q '"name": *"next"' "$1" 2>/dev/null || return 0
    sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1
}

declare -A ACT_CACHE=()
ACT_EVIDENCE=""
server_actions_present() {   # project dir -> 0 if the App Router and a Server Action are present
    local dir="$1" manifest f app=0
    if [[ -n "${ACT_CACHE[$dir]:-}" ]]; then
        [[ "${ACT_CACHE[$dir]}" == yes* ]] && { ACT_EVIDENCE="${ACT_CACHE[$dir]#yes }"; return 0; }
        return 1
    fi
    [[ -d "$dir/app" || -d "$dir/src/app" ]] && app=1
    manifest="$dir/.next/server/server-reference-manifest.json"
    if [[ -r "$manifest" ]] && ! { grep -q '"node": *{}' "$manifest" && grep -q '"edge": *{}' "$manifest"; }; then
        ACT_CACHE[$dir]="yes built manifest lists server actions"
        ACT_EVIDENCE="built manifest lists server actions"; return 0
    fi
    if [[ $app -eq 1 ]]; then
        f="$(grep -rlE "^[[:space:]]*['\"]use server['\"]" \
              --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
              --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git "$dir" 2>/dev/null | head -n2 | tr '\n' ' ')"
        f="${f% }"
        if [[ -n "$f" ]]; then
            ACT_CACHE[$dir]="yes 'use server' in ${f}"
            ACT_EVIDENCE="'use server' in ${f}"; return 0
        fi
        ACT_CACHE[$dir]="no App Router without any 'use server' directive"
    else
        ACT_CACHE[$dir]="no no app/ directory (Pages Router)"
    fi
    return 1
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
#   L <path> <text>   write one short sanitized line of text (used so .env itself is never copied)
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
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != */../* && "$p" != */.. ]] || continue   # no ".." path component
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

NEXT_PROBE="$(cat <<'EOS'
R="/var/www /srv /opt /home"
find $R -maxdepth 7 \( -name node_modules -o -name .next -o -name .git \) -prune -o \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -type f -print 2>/dev/null | head -n 30 | while read -r l; do
  d=${l%/*}
  echo "F $l"
  [ -f "$d/.next/server/server-reference-manifest.json" ] && echo "F $d/.next/server/server-reference-manifest.json"
  [ -d "$d/app" ] && echo "D $d/app"
  [ -d "$d/src/app" ] && echo "D $d/src/app"
  find "$d" \( -name node_modules -o -name .next -o -name .git \) -prune -o -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" -o -name "*.mjs" \) -print 2>/dev/null | head -n 5000 | xargs -r grep -lE "^[[:space:]]*['\"]use server['\"]" 2>/dev/null | head -n 5 | while read -r f; do echo "F $f"; done
done
find $R -maxdepth 9 -path "*/node_modules/next/package.json" -type f 2>/dev/null | head -n 30 | while read -r l; do echo "F $l"; done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$NEXT_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 nov=0 sharpbad=0 d f v dir kind
    local -a pdirs=()
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Next.js"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi

    local -a hits=() adapters=()   # "project|source|version"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        dir="$(dirname "$f")"
        case "$(basename "$f")" in
            package-lock.json|npm-shrinkwrap.json) kind=npm ;;
            yarn.lock) kind=yarn ;;
            pnpm-lock.yaml) kind=pnpm ;;
            *) continue ;;
        esac
        while IFS= read -r v; do [[ -n "$v" ]] && hits+=("${dir}|${f}|${v}"); done < <("versions_${kind}_lock" "$f")
        while IFS= read -r v; do [[ -n "$v" ]] && adapters+=("${dir}|${f}|${v}"); done < <(adapter_versions "$f")
    done < <(find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name .next -o -name .git \) -prune \
                -o \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -type f -print 2>/dev/null | sort -u)
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        v="$(version_installed "$f")"
        [[ -n "$v" ]] || continue
        dir="${f%/node_modules/next/package.json}"
        hits+=("${dir}|${f}|${v}")
    done < <(find "${existing[@]}" -maxdepth 9 -name .git -prune -o -path '*/node_modules/next/package.json' -type f -print 2>/dev/null | sort -u)

    local h seen=""
    for h in "${hits[@]:-}"; do
        [[ -n "$h" ]] || continue
        IFS='|' read -r dir f v <<<"$h"
        [[ "$seen" == *"|${dir}|${v}|"* ]] && continue
        seen+="|${dir}|${v}|"
        found=$((found+1))
        step "next ${v} in ${dir}"
        inf "source: ${f}"
        if ! is_semver "$v"; then caution "cannot parse version '${v}'"; rc=1; continue; fi
        local feats; feats="$(cache_features "$dir")"
        if nov_missing "$v"; then
            bad "next ${v} is missing the November 2026 security release: $(nov_cves "$v")"
            if (( ${v%%.*} <= 14 )); then inf "${v%%.*}.x gets no November fix: move to 15.5.29 or 16.4.5"
            else
                inf "most of these need a particular feature (use cache and Cache Components, Edge routes, self-hosting behind a pipelining proxy, next/image); the release is the fix"
                if (( ${v%%.*} >= 16 )); then
                    if grep -q '^cacheComponents' <<<"$feats"; then
                        inf "this project turns on Cache Components (new projects get it by default since 16.4), so the cache flaws apply$(grep -q '^use-cache' <<<"$feats" && echo ": $(grep '^use-cache' <<<"$feats" | cut -d' ' -f2) file(s) use the 'use cache' directive")"
                        grep -q '^partialPrefetching' <<<"$feats" && inf "Partial Prefetching is on: the reported route shape for CVE-2026-119350 needs it off"
                    elif grep -q '^use-cache' <<<"$feats"; then
                        inf "$(grep '^use-cache' <<<"$feats" | cut -d' ' -f2) file(s) use the 'use cache' directive, but no cacheComponents setting was read; a built-only copy may hide it"
                    else
                        inf "no Cache Components setting and no 'use cache' directive read here: the four cache flaws are less likely to apply, the other three may"
                    fi
                fi
            fi
            nov=1; rc=1
        else ok "next ${v} has the November 2026 security release"
        fi
        local ef
        while IFS='|' read -r kind ef; do
            [[ -n "$ef" ]] || continue
            if [[ "$kind" == crit ]]; then bad "also carries ${ef}"; rc=1; else inf "$ef"; fi
        done < <(earlier_flaws "$v")
        [[ " ${pdirs[*]:-} " == *" ${dir} "* ]] || pdirs+=("$dir")
        if grep -qE '^(cache-store|use-cache)' <<<"$feats"; then
            if grep -q '^cache-store' <<<"$feats"; then
                inf "a cacheHandler or cacheHandlers store is configured: entries it holds can outlive the upgrade, so purge it after updating (the advisories note nested entries can ignore tag invalidation and lifetimes)"
            else
                inf "'use cache' entries live in memory by default with next start: restarting after the upgrade clears them"
            fi
        fi
        if ! next_affected "$v"; then
            if ver_lt "$v" "13.0.0"; then caution "next ${v} is older than 13.0.0 and outside the affected range of CVE-2026-94482, but this is not a general Next.js health check: a version this old has almost certainly accumulated other, unrelated CVEs. Update regardless."; rc=1
            else ok "next ${v} has the CVE-2026-94482 fix (15.5.28+ on 15.x, 16.4.1+ on 16.x)"; fi
            continue
        fi
        bad "next ${v} is affected by CVE-2026-94482"
        [[ "${v%%.*}" -le 14 ]] && inf "13.x and 14.x move to 15.5.29 or 16.4.5"
        if server_actions_present "$dir"; then
            bad "this project uses Server Actions (${ACT_EVIDENCE}): exposed"
            rc=1
        else
            caution "no Server Action found (${ACT_CACHE[$dir]#no }): not exposed by the advisory's definition, but source checks can miss built-only apps"
            inf "update anyway: the release that fixes CVE-2026-94482 (15.5.28 and 16.4.1) also fixes the critical code execution flaws listed above, which need no Server Action"
        fi
    done

    if [[ ${#pdirs[@]} -gt 0 ]]; then
        step "sharp in Next.js projects"
        local sv sseen
        for dir in "${pdirs[@]}"; do
            sseen=""
            while IFS= read -r sv; do
                [[ -n "$sv" ]] || continue
                [[ "$sseen" == *"|${sv}|"* ]] && continue
                sseen+="|${sv}|"
                if ! is_semver "$sv"; then caution "${dir}: cannot parse sharp version '${sv}'"; rc=1
                elif ver_lt "$(norm_ver "$sv")" "$SHARP_FIXED"; then
                    bad "${dir}: sharp ${sv} carries $(sharp_cves "$sv")"
                    sharpbad=1; rc=1
                else ok "${dir}: sharp ${sv} (${SHARP_FIXED} or later)"; fi
            done < <(sharp_versions "$dir" | sort -u)
            [[ -n "$sseen" ]] || inf "${dir}: no sharp in the lockfiles or node_modules read here (Next.js then has no image optimization through sharp, or a global install provides it)"
            if svg_allowed "$dir"; then
                inf "${dir}: dangerouslyAllowSVG is on, so attacker-supplied SVG reaches librsvg through image optimization"
            fi
        done
    fi

    if [[ ${#adapters[@]} -gt 0 ]]; then
        step "Netlify adapter pinned in lockfiles"
        for h in "${adapters[@]}"; do
            IFS='|' read -r dir f v <<<"$h"
            if ! is_semver "$v"; then caution "${f}: cannot parse @netlify/plugin-nextjs version '${v}'"; rc=1
            elif ver_lt "$v" "$NETLIFY_ADAPTER_FIXED"; then
                bad "${f} pins @netlify/plugin-nextjs ${v}: on Netlify, cookies set in Middleware stay readable by same-origin JavaScript (CVE-2026-119346) until ${NETLIFY_ADAPTER_FIXED}, whatever the Next.js version"
                inf "upgrade @netlify/plugin-nextjs to ${NETLIFY_ADAPTER_FIXED} or later and redeploy, or unpin it so Netlify installs the current one"
                rc=1
            else ok "${f} pins @netlify/plugin-nextjs ${v} (${NETLIFY_ADAPTER_FIXED} or later)"; fi
        done
    fi

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Next.js found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Next.js project found (${found} version checked)"
    else
        warn "Exposed Next.js found. Upgrade: npm install next@15.5.29  (or next@16.4.5 or later), rebuild and restart."
        inf "Reduce CVE-2026-94482 exposure meanwhile at the reverse proxy: rate limit requests that carry a Next-Action header. This slows abuse, it does not fix the bug."
        [[ $sharpbad -eq 0 ]] || inf "sharp: update to ${SHARP_FIXED} or later (npm install sharp@${SHARP_FIXED}, or an \"overrides\" entry when sharp comes in through next), reinstall and redeploy. Meanwhile sharp.block({ operation: [\"VipsForeignLoadHeif\"] }) stops AVIF and HEIF decoding, and leaving dangerouslyAllowSVG off keeps SVG out of image optimization."
        [[ $nov -eq 0 ]] || inf "CVE-2026-119348 needs a self-hosted app behind a reverse proxy that queues pipelined requests on a shared backend connection; the advisory says not every proxy configuration does. The update is the fix."
        inf "Advisories: GHSA-p3m5-59mp-jv5r; November 2026: https://nextjs.org/blog/november-2026-security-release; October 2026: https://nextjs.org/blog/nextjs-security-update-october-14-2026; August 2026: https://nextjs.org/blog/august-2026-security-release"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-94482 (fixed in 15.5.28 and 16.4.1), the August, October and November 2026 releases (current: 15.5.29 and 16.4.5), and sharp (0.35.5)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
