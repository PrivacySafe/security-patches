#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Roundcube Webmail October and November 2026 security releases: read-only checker  (v1)
# CVE-2026-114716 (mail header injection, CVSS 8.5)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Roundcube released 1.6.20 (LTS) and 1.7.5 (mainline) on 19 October 2026. Both
# carry the same 20 security fixes, the largest batch since 1.7.0: IMAP command
# injection, four mail header injection flaws, XSS, SSRF, CSRF, an object
# injection primitive in session handling and ImageMagick limit bypasses.
# CVE-2026-114716 is one of the mail header injection fixes (the release notes
# list header injection through the From display-name in Bounce, through the
# References, In-Reply-To, Message-ID and From parameters, through the subject
# of a message forwarded as an attachment, and through the media type of an
# inline image). A header injection lets an attacker add or alter headers of an
# outgoing message, which feeds phishing and mail forgery from a trusted host.
#
# A second, separate round followed on 9 November 2026: 1.6.21 (LTS) and 1.7.6
# (mainline), 17 more fixes with no CVE numbers assigned to any of them. The
# release notes name an open redirect through IMAP error recovery on an
# attachment fetch, a fix so the Received header only ever carries a trusted
# hostname and a forwarded IP taken from a trusted proxy, a managesieve bug
# where a destructive filter action could run without the confirmation it
# requires, and further CSRF, SSRF and injection fixes credited mostly to a
# reporting group using the names Squirt1e, Atum, N0b0dy and Gh0u1L5, who have
# reported several of the preceding rounds too. The project has said the 1.6
# LTS branch, now four years old, will be retired, citing how error-prone its
# own backports have become; no end date was given as of this release.
#
#   Affected: Roundcube 1.6.x before 1.6.21, and 1.7.x before 1.7.6
#   Fixed:    1.6.21 and 1.7.6. These releases do not cover 1.5 and earlier.
#
# Roundcube is bundled by hosting panels. cPanel and Plesk ship their own copy
# and update it with the panel, so the panel's changelog decides when it is safe.
#
# This script is read-only. It finds Roundcube installs, reads the version from
# program/include/iniset.php, and can search web server logs for CRLF probing
# of the _uid and _flag parameters (the IMAP injection that the same release
# fixes), which is a sign someone has been testing your webmail.
#
# Usage:
#   ./roundcube-oct2026-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home
#                    /usr/share/roundcube /usr/share/roundcubemail
#                    /var/lib/roundcube plus the cPanel and Plesk paths).
#                    Exit 0 = nothing affected, 1 = an affected install found.
#   hunt             search readable web server logs for _uid or _flag values
#                    that contain an encoded carriage return or line feed.
#                    Exit 0 = none found, 1 = matches found.
#   version          print the script version.
#
# Distribution packages backport fixes without changing the version string. The
# script reads the owning package changelog and reports a mention of the CVE.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="roundcube-oct2026-check.sh"
SCRIPT_VERSION="1.2.0"
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
# prints fixed | vulnerable | eol | unknown
roundcube_status() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || { echo unknown; return; }
    case "${v%.*}" in
        1.6) ver_lt "$v" "1.6.21" && echo vulnerable || echo fixed ;;
        1.7) ver_lt "$v" "1.7.6"  && echo vulnerable || echo fixed ;;
        *)   if ver_lt "$v" "1.6.0"; then echo eol; else echo fixed; fi ;;
    esac
}

rc_version() {   # iniset.php -> version
    local f="$1" v dir
    v="$(sed -n "s/.*define([[:space:]]*['\"]RCMAIL_VERSION['\"],[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$f" | head -n1)"
    if [[ -z "$v" ]]; then
        dir="$(dirname "$(dirname "$(dirname "$f")")")"
        for c in "$dir/CHANGELOG.md" "$dir/CHANGELOG"; do
            [[ -r "$c" ]] || continue
            v="$(grep -m1 -oiE 'release [0-9]+\.[0-9]+\.[0-9]+' "$c" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
            [[ -n "$v" ]] && break
        done
    fi
    echo "$v"
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
        stage_containers 'program/include/iniset.php' 'CHANGELOG.md'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home /usr/share/roundcube /usr/share/roundcubemail /var/lib/roundcube /usr/local/cpanel/base/3rdparty/roundcube /usr/share/psa-roundcube /usr/share/psa-webmail; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f ver st root
    if [[ $# -gt 0 ]]; then dirs=("$@")
    else dirs=(/var/www /srv /opt /home /usr/share/roundcube /usr/share/roundcubemail /var/lib/roundcube \
               /usr/local/cpanel/base/3rdparty/roundcube /usr/share/psa-roundcube /usr/share/psa-webmail); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Roundcube Webmail"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        root="$(dirname "$(dirname "$(dirname "$f")")")"
        ver="$(rc_version "$f")"
        found=$((found+1))
        step "Roundcube ${ver:-?} at ${root}"
        if [[ -z "$ver" ]]; then caution "version not found in ${f}; treating it as not confirmed fixed"; rc=1; continue; fi
        st="$(roundcube_status "$ver")"
        case "$st" in
            fixed)   ok "Roundcube ${ver} has the 1.6.21 / 1.7.6 fixes"; continue ;;
            unknown) caution "could not parse version '${ver}'; treating it as not confirmed fixed"; rc=1; continue ;;
            eol)     bad "Roundcube ${ver} is on a branch these releases do not cover (1.5 and earlier): move to 1.6.21 or 1.7.6" ;;
            vulnerable) bad "Roundcube ${ver} is affected by CVE-2026-114716 and up to 36 other fixes across the October and November rounds (fixed in 1.6.21 / 1.7.6)" ;;
        esac
        if distro_mentions "$f" CVE-2026-114716; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this copy and its changelog does not mention the CVE yet"
        fi
        case "$root" in
            */cpanel/*|*/psa-*) inf "bundled with a hosting panel: the panel's own update delivers the fix" ;;
        esac
        rc=1
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/program/include/iniset.php' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Roundcube found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Roundcube found (${found} checked)"
    else
        warn "Affected Roundcube found. Update to 1.6.21 (LTS) or 1.7.6, and back up first as the project advises."
        inf "Release notes: https://roundcube.net/news/2026/11/09/security-updates-1.6.21-and-1.7.6"
        inf "Then run: $0 hunt   to look for probing of the IMAP injection parameters."
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local -a logs=()
    local f n total=0 rc=0
    shopt -s nullglob
    for f in /var/log/apache2/*access*.log /var/log/apache2/*access*.log.1 \
             /var/log/nginx/*access*.log /var/log/nginx/*access*.log.1 \
             /var/log/httpd/*access*log /var/log/httpd/*access*log.1 \
             /var/log/apache2/other_vhosts_access.log /usr/local/apache/logs/access_log \
             "${HUNT_LOGS:-/nonexistent}"; do
        [[ -r "$f" && -f "$f" ]] && logs+=("$f")
    done
    shopt -u nullglob
    step "Searching web logs for CRLF in the Roundcube _uid and _flag parameters"
    if [[ ${#logs[@]} -eq 0 ]]; then
        warn "No readable access logs found (run as root, or set HUNT_LOGS to a log path)"
        return 0
    fi
    inf "reading ${#logs[@]} log file(s)"
    for f in "${logs[@]}"; do
        n="$(grep -cE '[?&_]_(uid|flag)=[^ &"]*(%0[dD]|%0[aA]|\\r|\\n)' "$f" 2>/dev/null)"
        [[ "${n:-0}" -gt 0 ]] || continue
        total=$((total+n)); rc=1
        bad "${f}: ${n} request(s) with an encoded CR or LF in _uid or _flag"
        grep -E '[?&_]_(uid|flag)=[^ &"]*(%0[dD]|%0[aA]|\\r|\\n)' "$f" 2>/dev/null | head -n3 | cut -c1-200 | sed 's/^/        /'
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No CRLF probing of _uid or _flag found in the readable logs"
        inf "A clean result does not prove nothing happened: logs rotate, and POST bodies are not logged."
    else
        warn "${total} suspicious request(s). Someone has been testing IMAP command injection against your webmail."
        inf "Update first, then review the IMAP server log for commands you did not expect."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114716 and 16 later unnumbered fixes; fixed in Roundcube 1.6.21 and 1.7.6"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
