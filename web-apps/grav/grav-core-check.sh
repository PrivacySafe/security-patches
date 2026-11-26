#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Grav CMS core allowlist bypass through Flex form overrides: read-only checker  (v1)
# CVE-2026-116019
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Grav 2.0.15 before 2.2.13 lets a user who may edit pages run arbitrary public static
# methods. Grav marks the dynamic directives in a blueprint (the data-*@ fields that name a
# PHP method to call) as trusted only where the blueprint file itself defines them, and
# checks the ones that arrive from page frontmatter against an allowlist. The merge that
# combines the two could relocate a directive away from the path it was checked at: the
# vendor deepMerge() honors the unset-name@ merge action as well as replace-name@, and it
# renumbers an integer key the base does not have. A relocated directive was then trusted as
# if the blueprint file had defined it, so the allowlist was skipped. A page editor can embed
# crafted fields in the Flex form overrides of a page's frontmatter and call methods such as
# Folder::delete or Utils::download, which deletes directories, overwrites files, or reads
# files outside the page tree. CVSS 8.8 (v3.1), 8.7 (v4.0). No exploitation was reported at
# the time of the sources used. Found through a GitHub security advisory
# (GHSA-47gg-mh38-9rr7), published 24 October 2026.
#
#   Affected: Grav 2.0.15 up to and including 2.2.12
#   Fixed:    2.2.13 (24 October 2026)
#
# How this script reads a site. The version is the GRAV_VERSION constant in
# system/defines.php. The script also reads system/src/Grav/Common/Data/Blueprint.php for
# the two things the fix adds: the dynamicOf() helper that compares the directives before and
# after the merge, and the extension of the stripping from replace-name@ to unset-name@. Both
# present means the fix is there, whatever the version string says; neither present on a
# version in the affected range means exposed; one of the two is a partial patch.
#
# This script is read-only. "hunt" also looks in the site's pages for what an attack needs:
# a relocation merge action (unset-name@, replace-name@) or a static method call in page
# frontmatter. Those are indicators to investigate: a relocation directive together with a static
# method call in the same page is a strong lead, either one alone is only listed for review.
# A clean hunt means none of the published indicators were found.
#
# Usage:
#   ./grav-core-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for Grav sites. Exit 0 =
#                    nothing exposed, 1 = an exposed or unverifiable site.
#   hunt             check, then look in the pages for the indicators above. Exit 0 =
#                    nothing found, 1 = an exposed site or a strong lead.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="grav-core-check.sh"
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
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}

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
# ---------- reading a site ---------------------------------------------------
# the version string, exactly as defines.php holds it (2.2.12, or 2.2.13-rc.1)
grav_version() {
    local f="$1/system/defines.php"
    [[ -r "$f" ]] || return 0
    sed -nE "s/^[[:space:]]*define\([[:space:]]*['\"]GRAV_VERSION['\"][[:space:]]*,[[:space:]]*['\"]([^'\"]+)['\"].*/\1/p" "$f" | head -n1 | tr -d '\r'
}

# version status. prints: notaffected | vulnerable | fixed | prerelease | unknown
#   prerelease = a pre-release of the fixed release itself (2.2.13-rc.1): not judged as the release
grav_status() {
    local raw="$1" v; v="$(norm_ver "$raw")"
    is_semver "$v" || { echo unknown; return; }
    ver_lt "$v" 2.0.15 && { echo notaffected; return; }
    ver_lt "$v" 2.2.13 && { echo vulnerable; return; }
    [[ "$raw" =~ -(alpha|beta|rc|dev|pre) && "$v" == 2.2.13 ]] && { echo prerelease; return; }
    echo fixed
}

# the two things the fix adds to Blueprint.php. prints: both | one | none | unreadable
blueprint_signature() {
    local f="$1/system/src/Grav/Common/Data/Blueprint.php" a=0 b=0
    [[ -r "$f" ]] || { echo unreadable; return; }
    grep -qF 'function dynamicOf(' "$f" && a=1
    grep -qF "['replace', 'unset']" "$f" && b=1
    case "$((a+b))" in 2) echo both ;; 1) echo one ;; *) echo none ;; esac
}

# ---------- check ------------------------------------------------------------
# ---------- running containers -----------------------------------------------
# An install inside a container is not on the host. For each running container, find installs by
# their marker file, copy ONLY the files this check reads into a temporary directory (one per
# install, named after the container and the path inside it, mode 0700, removed on exit), and let
# the normal checks judge it like a host install. Paths the container reports are checked before
# they are used. The check never runs anything in a container beyond "find" and a file copy.
# It runs once, in the main shell (a subshell's exit would delete the copies early).
STAGE=""
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
                if [[ -z "$STAGE" ]]; then
                    STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${STAGE:-}"' EXIT
                fi
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

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'system/defines.php' 'system/src/Grav/Common/Data/Blueprint.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d df root ver st sig
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Grav sites"
    SITES=()
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r df; do
        [[ -n "$df" ]] || continue
        grep -qF 'GRAV_VERSION' "$df" 2>/dev/null || continue
        root="$(dirname "$(dirname "$df")")"
        found=$((found+1)); SITES+=("$root")
        ver="$(grav_version "$root")"
        step "Grav ${ver:-version unreadable} at ${root}"
        if [[ -z "$ver" ]]; then caution "could not read GRAV_VERSION from ${df}: affected is 2.0.15 up to 2.2.12, fixed is 2.2.13"; rc=1; continue; fi
        st="$(grav_status "$ver")"; sig="$(blueprint_signature "$root")"
        case "$sig" in
            both)
                ok "Blueprint.php carries the fix (the dynamicOf() comparison and the unset-name@ stripping)"
                [[ "$st" == vulnerable ]] && inf "the version string ${ver} is older than 2.2.13, but the files carry the fix: a backport, or files copied over an older install" ;;
            one)
                caution "Blueprint.php has only part of the fix (one of dynamicOf() and the unset-name@ stripping): a partial or mixed update. Reinstall 2.2.13 or later"; rc=1 ;;
            none)
                case "$st" in
                    vulnerable|prerelease) bad "Grav ${ver} is affected by CVE-2026-116019 (fixed in 2.2.13): a page editor can run arbitrary public static methods"
                        inf "update now (bin/gpm selfupgrade), then run: $0 hunt"; rc=1 ;;
                    fixed)       caution "version ${ver} is 2.2.13 or later, but Blueprint.php lacks the fix: the files do not match the version. Reinstall Grav"; rc=1 ;;
                    notaffected) caution "Grav ${ver} is older than 2.0.15, the start of the affected range. This is not confirmed clear, only outside this one CVE's range: it is far out of date, so update it anyway"; rc=1 ;;
                    *)           caution "cannot compare version '${ver}': check it against 2.2.13"; rc=1 ;;
                esac ;;
            unreadable)
                case "$st" in
                    fixed)       ok "Grav ${ver} is 2.2.13 or later (Blueprint.php could not be read to confirm)" ;;
                    notaffected) caution "Grav ${ver} is older than 2.0.15, the start of the affected range. This is not confirmed clear, only outside this one CVE's range: it is far out of date, so update it anyway"; rc=1 ;;
                    vulnerable)  bad "Grav ${ver} is affected by CVE-2026-116019 (fixed in 2.2.13): a page editor can run arbitrary public static methods"; inf "update now (bin/gpm selfupgrade), then run: $0 hunt"; rc=1 ;;
                    prerelease)  caution "Grav ${ver} is a pre-release of 2.2.13, not the release, and Blueprint.php could not be read to confirm the fix. Update to 2.2.13 or later"; rc=1 ;;
                    *)           caution "cannot compare version '${ver}': check it against 2.2.13"; rc=1 ;;
                esac ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -path '*/system/defines.php' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then info "No Grav site found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then info "No exposed Grav found (${found} checked)"
    else
        warn "Exposed or unverifiable Grav found. Update to 2.2.13 or later."
        inf "Exposure needs an account that can edit pages (or a form that accepts page frontmatter). PrivacySafe recommendation: restrict who can edit pages and who has Admin access until you update"
        inf "Advisory: https://github.com/getgrav/grav/security/advisories/GHSA-47gg-mh38-9rr7"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
hunt_site() {   # site root; returns 1 on a strong lead
    local root="$1" rc=0 f has_reloc has_call n_reloc=0 n_call=0 strong="" rl="" cl=""
    step "Hunting in ${root}"
    if [[ ! -d "$root/user/pages" ]]; then inf "no user/pages directory to search"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        has_reloc=0; has_call=0
        grep -qE '(unset|replace)-name@' "$f" 2>/dev/null && has_reloc=1
        grep -qE '(Folder|Utils|Filesystem)(\\\\|\\)?[A-Za-z]*::[A-Za-z_]+' "$f" 2>/dev/null && has_call=1
        [[ $has_reloc -eq 1 ]] && { n_reloc=$((n_reloc+1)); rl+="${f}"$'\n'; }
        [[ $has_call -eq 1 ]] && { n_call=$((n_call+1)); cl+="${f}"$'\n'; }
        [[ $has_reloc -eq 1 && $has_call -eq 1 ]] && strong+="${f}"$'\n'
    done < <(find "$root/user/pages" -type f \( -name '*.md' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | head -n5000)
    if [[ -n "$strong" ]]; then
        bad "page(s) with a relocation merge action (unset-name@ or replace-name@) AND a static method call in the same file: a strong lead"
        grep -v '^$' <<<"$strong" | sed 's/^/        /' | head -n10; rc=1
    fi
    if [[ $n_reloc -gt 0 && -z "$strong" ]]; then
        caution "${n_reloc} page file(s) use a relocation merge action (unset-name@ or replace-name@), which pages do not normally need:"
        grep -v '^$' <<<"$rl" | sed 's/^/        /' | head -n10
    fi
    if [[ $n_call -gt 0 && -z "$strong" ]]; then
        caution "${n_call} page file(s) mention a static method call (Folder::, Utils::); on a documentation site this can be harmless. Review who wrote them:"
        grep -v '^$' <<<"$cl" | sed 's/^/        /' | head -n10
    fi
    [[ $n_reloc -eq 0 && $n_call -eq 0 ]] && ok "no page frontmatter uses a relocation merge action or a static method call"
    return "$rc"
}

cmd_hunt() {
    local rc=0 site
    cmd_check "$@" || rc=1
    for site in "${SITES[@]:-}"; do
        [[ -n "$site" ]] || continue
        hunt_site "$site" || rc=1
    done
    step "Verdict"
    limited_view
    if [[ $rc -eq 0 ]]; then info "No exposed site and no strong lead found: none of the published indicators were found."
    else
        warn "An exposed site or a strong lead was found."
        inf "Review recent edits to pages and Flex form overrides, check for deleted directories and changed files outside the page tree, and review who can edit pages."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-116019; fixed in Grav 2.2.13"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
