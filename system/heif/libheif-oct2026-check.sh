#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# libheif HEIF/AVIF decoder check  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# A heap buffer overflow in libheif's HEIF decoding (reached through
# ImageMagick on an attacker-supplied image) was used to get remote code
# execution on a Discourse forum and pivot further. The bug class spans many
# libheif CVEs with no single CVE for the Discourse case; the upstream commit
# shipped without one. Debian fixed a batch in DSA-6417-1 (libheif
# 1.19.8-1+deb13u1, trixie, 8 Aug 2026); other distributions backport under
# their own version strings, and some stable branches stayed vulnerable for a
# while. Upstream security releases have continued (1.21.0, 1.22.0, 1.22.1,
# 1.23.x). See https://www.hacktron.ai/blog/hacking-openai
#
# This is NOT the Ruby Regexp issue. For Ruby/GitLab, use
# runtimes/ruby/ruby-regexp-oct2026-check.sh instead.
#
# Usage:
#   ./libheif-oct2026-check.sh [command]
#
#   check (default)  read-only: every libheif and libde265 on the host, the
#                    ImageMagick and libvips that reach them, every Discourse
#                    install (whose image-upload path runs an attacker-supplied
#                    file through ImageMagick into libheif), and container
#                    images, with whether each libheif carries the fixes. For
#                    a Discourse container it says whether a rebuild is needed
#                    rather than a restart. Root optional. Exit 0 = nothing
#                    exposed, 1 = a vulnerable libheif is reachable, 2 =
#                    something couldn't be read.
#   policy           read-only: whether ImageMagick's policy.xml still lets
#                    HEIC/HEIF/AVIF through. Disabling those coders protects the system until
#                    you can patch libheif. Exit 0 =
#                    HEIF is blocked everywhere a policy was found, 1 = HEIF
#                    is still allowed, 2 = no policy found.
#   harden           write a managed block into ImageMagick's policy.xml that
#                    refuses the HEIC/HEIF/AVIF coders, so a crafted upload
#                    never reaches libheif through ImageMagick. Backs the file
#                    up first, is reversible with unharden, and is the one
#                    thing this script changes. Needs root. This is defense in
#                    depth, NOT a substitute for updating libheif.
#   unharden         remove that managed block and restore. Needs root. Only
#                    touches a block this script wrote.
#   mw-harden        block HEIF/HEIC/AVIF uploads in every MediaWiki found, by
#                    adding those MIME types to wgMimeTypeExclusions in
#                    LocalSettings.php, so a crafted upload is rejected by its
#                    detected type before the scaler runs. Backs up first,
#                    checks the result still parses as PHP, reversible with
#                    mw-unharden. Needs root. Application-level defense; the
#                    host libheif still needs updating.
#   mw-unharden      remove that MediaWiki block and restore. Needs root.
#   hunt             read-only: the journal and logs for image-processor
#                    crashes (ImageMagick/libheif/libde265 segfaults, HEIF
#                    decoder frames, repeated convert/magick aborts).
#                    Exit 0 = clean, 1 = findings, 2 = no journal or log could
#                    be read, so nothing was searched.
#   version          print the script version.
#
# The real fix is to update libheif (and libde265) and rebuild anything that
# bundles it (Discourse containers especially); this script does not run that
# for you, because a package upgrade or a container rebuild is an administrator's
# call to make and time. The only change it will make is the ImageMagick coder
# policy, and only when you ask for it with harden.
#
# Env overrides:
#   HEIF_FIXED_UPSTREAM=1.22.0        upstream floor the heap-write class is
#                                     fixed at (coarse: distro backports under
#                                     older numbers are judged by FIXED_BUILDS
#                                     and the package changelog first)
#   FIXED_BUILDS="1.19.8-1+deb13u1 1.17.6-1ubuntu4.6"
#                                     distro builds known to carry the fixes,
#                                     space-separated full versions
#   DISCOURSE_ROOT="/var/discourse"   where the Docker launcher lives
#   DISCOURSE_APP="/var/www/discourse"  where a bare-metal checkout lives
#   POLICY_PATHS="/etc/ImageMagick-6 /etc/ImageMagick-7 ..."
#                                     where policy looks for policy.xml
#   HUNT_SINCE="2026-07-01"           how far back hunt reads the journal
#   HUNT_LOGS="/var/log/nginx/*.log"  extra log globs for hunt
#   BACKUP_ROOT=/var/backups/libheif-oct2026
#                                     where harden and mw-harden keep the backup
#                                     of each config file they change
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
KEY_REF="DSA-6417-1"
HEIF_FIXED_UPSTREAM="${HEIF_FIXED_UPSTREAM:-1.22.0}"
# Changelog entries that prove the fixes, used when a dpkg build is not in
# FIXED_BUILDS. Any one is enough.
CHANGELOG_MARKERS=(DSA-6417-1 CVE-2026-32740 CVE-2026-32741 CVE-2025-68431 CVE-2026-47178)
FIXED_BUILDS="${FIXED_BUILDS:-}"
DISCOURSE_ROOT="${DISCOURSE_ROOT:-/var/discourse}"
DISCOURSE_APP="${DISCOURSE_APP:-/var/www/discourse}"
POLICY_PATHS="${POLICY_PATHS:-/etc/ImageMagick-7 /etc/ImageMagick-6 /etc/ImageMagick /usr/local/etc/ImageMagick-7 /usr/local/etc/ImageMagick-6}"
MW_PATHS="${MW_PATHS:-/var/www/mediawiki /var/www/html /var/www/html/mediawiki /var/www/html/w /var/www/w /srv/mediawiki /srv/www/mediawiki /usr/share/mediawiki}"
# The HEIF-family MIME types MediaWiki detects. Blocking these rejects a
# crafted upload by its detected type, whatever extension it was given.
MW_HEIF_MIMES=("image/heif" "image/heic" "image/avif" "image/heif-sequence" "image/heic-sequence")
HUNT_SINCE="${HUNT_SINCE:-2026-07-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCRIPT_NAME="libheif-oct2026-check.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
ADVISORY="https://www.hacktron.ai/blog/hacking-openai"
MARKER="managed-by: libheif-oct2026-check"
# Begin carries the version for humans; detection and stripping key on the
# version-independent MARKER so a block written by any version is recognized.
BLOCK_BEGIN="<!-- BEGIN ${MARKER} (v${SCRIPT_VERSION}) -->"
BLOCK_END="<!-- END ${MARKER} -->"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/libheif-oct2026}"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

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
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- libheif discovery and versioning ---------------------------------
# One resolved path per line, for libheif or libde265 shared objects.
find_libs() {   # <soname-stem> -> paths
    local stem="$1" c
    {
        shopt -s nullglob
        for c in /usr/lib/*/"${stem}".so* /usr/lib/"${stem}".so* /usr/lib64/"${stem}".so* \
                 /usr/local/lib/*/"${stem}".so* /usr/local/lib/"${stem}".so* /lib/*/"${stem}".so* \
                 /opt/*/lib/"${stem}".so* /opt/*/*/lib/"${stem}".so*; do
            echo "$c"
        done
        shopt -u nullglob
        have ldconfig && ldconfig -p 2>/dev/null | grep -oE "/[^ ]*${stem}\.so[^ ]*" || true
    } | while read -r c; do [[ -e "$c" ]] && readlink -f "$c"; done | sort -u
}

# The real version is the soname's own version, which the package sets to the
# library version (libheif.so.1.19.7 is libheif 1.19.7). A shared object also
# carries unrelated X.Y.Z build strings from its dependencies, so grabbing the
# first string in the file is wrong. Prefer the resolved filename's trailing
# version; fall back to a standalone X.Y.Z string in the file. Reading either
# runs nothing.
lib_version() {   # <path> -> X.Y.Z or empty
    local real base v
    real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
    # libheif.so.1.19.7  ->  1.19.7 ; the final .so.N.N.N is the version
    base="$(basename "$real")"
    v="$(grep -oE '\.so\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$base" | sed 's/^\.so\.//' || true)"
    if [[ -z "$v" ]]; then
        # Not in the filename (a bare libheif.so symlink target, say): take a
        # standalone version-only string, which is how libheif stores its own.
        v="$(grep -aoE '^[0-9]+\.[0-9]+\.[0-9]+$' "$real" 2>/dev/null | head -1 || true)"
    fi
    echo "$v"
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# "<rc>|<explanation>": rc 0 = fixed, 1 = vulnerable, 2 = unknown
# A distro package can carry the fixes under an older upstream number, so a
# dpkg-owned library is judged on its package build first, then on the
# upstream floor. Nothing is executed.
heif_state() {   # <X.Y.Z> [path]
    local v="$1" p="${2:-}" pkg full f m
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if [[ -n "$p" ]]; then
        pkg="$(owner_pkg "$p")"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            for f in $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            local cl
            cl="/usr/share/doc/${pkg}/changelog.Debian.gz"
            if [[ -f "$cl" && "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]]; then
                for m in "${CHANGELOG_MARKERS[@]}"; do
                    if zgrep -q "$m" "$cl" 2>/dev/null; then echo "0|${pkg} ${full}: changelog lists ${m}"; return; fi
                done
            fi
            # dpkg-owned but no proof of the fix: upstream number can't clear a
            # distro build, because distros backport under old numbers.
            if ver_ge "$v" "$HEIF_FIXED_UPSTREAM"; then
                echo "2|${pkg} ${full} (upstream ${v} >= ${HEIF_FIXED_UPSTREAM} but the package changelog doesn't name the fixes; add the build to FIXED_BUILDS if you know it's patched)"
            else
                echo "1|${pkg} ${full} (upstream ${v} < ${HEIF_FIXED_UPSTREAM}, changelog doesn't name the fixes). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS"
            fi
            return
        fi
    fi
    # Not dpkg-owned (self-built, bundled, another distro): upstream floor only.
    if ver_ge "$v" "$HEIF_FIXED_UPSTREAM"; then echo "0|upstream ${v} >= ${HEIF_FIXED_UPSTREAM}"
    else echo "1|upstream ${v} < ${HEIF_FIXED_UPSTREAM}"; fi
}

# ImageMagick and libvips are how a web app reaches libheif. Report their
# version and whether they can even decode HEIF (no HEIF delegate = not a
# path to this bug through that tool).
tool_report() {
    local magick v heif
    for magick in magick convert; do
        have "$magick" || continue
        v="$("$magick" -version 2>/dev/null | grep -oE 'ImageMagick [0-9][^ ]*' | head -1 || true)"
        heif="$("$magick" -list format 2>/dev/null | grep -iE '^\s*HEIC|^\s*HEIF|^\s*AVIF' | tr -s ' ' | head -3 || true)"
        if [[ -n "$heif" ]]; then
            caution "${magick}: ${v:-present}, HEIF/AVIF decoding ENABLED (reaches libheif). Disable it in policy.xml as defense in depth: ${SELF} policy"
        else
            ok "${magick}: ${v:-present}, no HEIF/AVIF delegate (doesn't reach libheif)"
        fi
        break
    done
    if have vips; then v="$(vips --version 2>/dev/null | head -1 || true)"; inf "libvips present (${v:-?}): also links libheif; the library verdict above applies to it too"; fi
    return 0
}

# ---------- Discourse (an image-upload path into libheif) --------------------
discourse_installs() {   # "kind|where|version"
    local v
    if [[ -x "${DISCOURSE_ROOT}/launcher" || -d "${DISCOURSE_ROOT}/containers" ]]; then
        v=""
        [[ -r "${DISCOURSE_ROOT}/version" ]] && v="$(grep -oE '[0-9a-f]{7,40}|v?[0-9]+\.[0-9]+\.[0-9]+' "${DISCOURSE_ROOT}/version" | head -1 || true)"
        echo "docker|${DISCOURSE_ROOT}|${v}"
    fi
    local app f
    for app in "$DISCOURSE_APP" /home/*/discourse /srv/discourse; do
        f="${app}/lib/version.rb"
        [[ -r "$f" || -r "${app}/VERSION" ]] || continue
        v=""
        [[ -r "$f" ]] && v="$(grep -oE 'STRING *= *"[0-9.]+(\.beta[0-9]*)?"' "$f" | grep -oE '[0-9][0-9.]*' | head -1 || true)"
        [[ -z "$v" && -r "${app}/VERSION" ]] && v="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${app}/VERSION" | head -1 || true)"
        echo "source|${app}|${v}"
    done
    local rt img
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)discourse/(discourse|base):' | sort -u | while read -r img; do
            echo "${rt} image|${img}|"
        done
    done
}

# ---------- MediaWiki (another image-upload path into libheif) ---------------
# MediaWiki is a path to this bug only when it is configured for it: the
# scaler must be ImageMagick (not GD, its default when both exist), and HEIF
# must be an allowed upload type (not a default). So this reads LocalSettings
# rather than assuming. Reading a PHP config file is not executing it.
mw_installs() { for d in $MW_PATHS; do [[ -r "${d}/LocalSettings.php" ]] && echo "${d}/LocalSettings.php"; done; }

# Last assignment wins in PHP, so read the last one. Values are read as text,
# nothing is evaluated.
mw_last() {   # <file> <var-without-$>
    grep -oE "\\\$${2}[[:space:]]*=[^;]*" "$1" 2>/dev/null | tail -1 || true
}

# "uses_im|accepts_heif|version"  (1/0 flags, version may be empty)
mw_profile() {   # <LocalSettings.php>
    local f="$1" uses_im=0 accepts=0 ver="" a dir rl
    a="$(mw_last "$f" wgUseImageMagick)"
    [[ "$a" == *[Tt]rue* ]] && uses_im=1
    # An explicit convert command with ImageMagick not disabled also counts
    a="$(mw_last "$f" wgImageMagickConvertCommand)"
    [[ -n "$a" && "$(mw_last "$f" wgUseImageMagick)" != *[Ff]alse* ]] && uses_im=1
    # HEIF reachable if any heif-family extension is in wgFileExtensions
    if grep -oE '\$wgFileExtensions[^;]*' "$f" 2>/dev/null | grep -iE "['\"](heif|heic|avif)['\"]" >/dev/null; then accepts=1; fi
    # Version from the sibling install (RELEASE-NOTES or includes/Defines)
    dir="$(dirname "$f")"
    for rl in "${dir}/includes/Defines.php" "${dir}/RELEASE-NOTES-"*; do
        [[ -r "$rl" ]] || continue
        ver="$(grep -oE "MW_VERSION'?,?[[:space:]]*'?[0-9]+\.[0-9]+(\.[0-9]+)?" "$rl" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)"
        [[ -n "$ver" ]] && break
    done
    echo "${uses_im}|${accepts}|${ver}"
}

# ---------- containers -------------------------------------------------------
# Report libheif inside running containers. Reading a file from an image or a
# container is not executing the app, and it is how a Discourse web container
# that still carries the old library gets caught: a web-interface update does
# not replace it, only a rebuild does.
container_libs() {   # "runtime|ref|kind|version"  kind = container|image
    local rt
    for rt in docker podman; do
        have "$rt" || continue
        local id name v
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'for p in /usr/lib/*/libheif.so* /usr/lib/libheif.so* /usr/local/lib/libheif.so*; do [ -e "$p" ] && { strings "$p" 2>/dev/null | grep -aoE "[0-9]+\.[0-9]+\.[0-9]+" | head -1; break; }; done' 2>/dev/null | head -1 || true)"
            [[ -n "$v" ]] && echo "${rt}|${name:-$id}|container|${v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 p v ps how any

    step "libheif on the host"
    any=0
    while read -r p; do
        [[ -n "$p" ]] || continue
        any=1
        v="$(lib_version "$p")"
        IFS='|' read -r ps how <<<"$(heif_state "$v" "$p")"
        case $ps in
            0) ok "${p}  ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "${p}  ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "${p}  ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
        esac
    done < <(find_libs libheif)
    [[ $any -eq 1 ]] || inf "no libheif found on the host (it may still live only inside a container, checked below)"

    # libde265 is the HEVC codec libheif calls for HEIC. It has its own CVE
    # history and its own fixed versions, so this script reports it but does
    # not judge it against the libheif floor. Update it from your distro too.
    local dp dv dpkg dfull
    while read -r dp; do
        [[ -n "$dp" ]] || continue
        dv="$(lib_version "$dp")"
        dpkg="$(owner_pkg "$dp")"
        dfull=""
        [[ -n "$dpkg" ]] && dfull="$(dpkg-query -W -f='${Version}' "$dpkg" 2>/dev/null || true)"
        inf "libde265: ${dp}  ${dv:-?}${dfull:+  (${dpkg} ${dfull})} - update it from your distro; judged by your distro advisory, not by this script"
    done < <(find_libs libde265)

    step "What reaches libheif"
    tool_report

    step "Discourse (image uploads run through ImageMagick into libheif)"
    local dkind dwhere dv n=0
    while IFS='|' read -r dkind dwhere dv; do
        [[ -n "$dkind" ]] || continue
        n=1
        case "$dkind" in
            docker)    caution "${dkind} ${dwhere}${dv:+  ${dv}}: libheif lives inside the web container. A web-interface update does NOT replace it. Rebuild: ${DISCOURSE_ROOT}/launcher rebuild app. The container section below reads the running library" ;;
            *" image") caution "${dkind} ${dwhere}: rebuild on a base image whose libheif carries the fixes" ;;
            *)         caution "${dkind} ${dwhere}${dv:+  Discourse ${dv}}: uses the host libheif above. If that is vulnerable, this forum is a path to it through image uploads" ;;
        esac
    done < <(discourse_installs)
    [[ $n -eq 1 ]] || inf "no Discourse install found (Docker launcher under ${DISCOURSE_ROOT}, checkout under ${DISCOURSE_APP}, or discourse images)"

    step "MediaWiki (image uploads run through ImageMagick into libheif)"
    local mf uses accepts mver mw_n=0
    while read -r mf; do
        [[ -n "$mf" ]] || continue
        mw_n=1
        IFS='|' read -r uses accepts mver <<<"$(mw_profile "$mf")"
        if [[ $uses -eq 1 && $accepts -eq 1 ]]; then
            bad "${mf}${mver:+  MediaWiki ${mver}}: uses ImageMagick AND accepts HEIF/HEIC/AVIF uploads. A crafted upload reaches the host libheif above. Block it at the wiki: sudo ${SELF} mw-harden"
            exposed=1
        elif [[ $uses -eq 1 ]]; then
            ok "${mf}${mver:+  MediaWiki ${mver}}: uses ImageMagick but HEIF/HEIC/AVIF is not in wgFileExtensions, so the wiki won't accept it. Keep it that way, or if you add it run: ${SELF} mw-harden"
        elif [[ $accepts -eq 1 ]]; then
            caution "${mf}${mver:+  MediaWiki ${mver}}: accepts HEIF uploads but ImageMagick isn't enabled (GD doesn't reach libheif). If you switch to ImageMagick, block HEIF first: ${SELF} mw-harden"
        else
            ok "${mf}${mver:+  MediaWiki ${mver}}: not a path to libheif (GD scaler and/or HEIF not accepted)"
        fi
    done < <(mw_installs)
    [[ $mw_n -eq 1 ]] || inf "no MediaWiki install found (looked under ${MW_PATHS}; set MW_PATHS if yours is elsewhere)"

    step "libheif inside running containers"
    local rt ref kind cv any_c=0
    if ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        while IFS='|' read -r rt ref kind cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r ps how <<<"$(heif_state "$cv")"
            case $ps in
                0) ok "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 1)  (${how}); rebuild the image/container, a restart won't change the library"; exposed=1 ;;
                *) caution "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_libs)
        [[ $any_c -eq 1 ]] || inf "no running container exposes a readable libheif (or no permission to exec in them). Images that install it another way aren't detected"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable libheif found where this could read one" ;;
        1) warn "A vulnerable libheif is reachable. Update libheif and libde265, rebuild anything that bundles them (Discourse: ${DISCOURSE_ROOT}/launcher rebuild app), and disable untrusted HEIF/AVIF in ImageMagick: ${SELF} policy" ;;
        *) warn "Some libheif builds couldn't be judged. For a dpkg build, confirm against the distro advisory and add it to FIXED_BUILDS. Rerun as root to read more" ;;
    esac
    return "$rc"
}

# ---------- policy -----------------------------------------------------------
# HEIC/HEIF/AVIF are disabled when a <policy domain="coder" rights="none" ...>
# line names them (or a pattern that covers them). This is a read of the XML,
# not a parse of ImageMagick's effective policy, so it errs toward caution.
coder_blocked() {   # <file> <CODER> -> 0 if a none-rights policy names it
    local f="$1" coder="$2"
    # -o isolates each matching <policy> element, so one element's rights cannot vouch for another
    # element's pattern when a policy file is written on a single line
    grep -oiE "<policy[^>]*domain=\"coder\"[^>]*rights=\"none\"[^>]*pattern=\"(\\{?(HEIC|HEIF|AVIF)[^\"]*|[*]|\\{[^\"]*(HEIC|HEIF|AVIF)[^\"]*)\"" "$f" 2>/dev/null \
        | grep -iE "pattern=\"([*]|[^\"]*${coder})" >/dev/null && return 0
    return 1
}

# Every policy.xml this host has, one per line. Shared by policy/harden/unharden.
policy_files() {
    local d p
    {
        for p in $POLICY_PATHS; do
            [[ -d "$p" && -e "$p/policy.xml" ]] && echo "$p/policy.xml"
        done
        if have magick; then
            d="$(magick -list configure 2>/dev/null | awk '/CONFIGURE_PATH/{print $2}' | head -1 || true)"
            [[ -n "$d" && -e "$d/policy.xml" ]] && echo "$d/policy.xml"
        fi
    } | sort -u
}

cmd_policy() {
    step "ImageMagick HEIF/AVIF coder policy"
    local f found=0 allowed=0
    local -a files=()
    mapfile -t files < <(policy_files)
    [[ ${#files[@]} -gt 0 ]] || { caution "no readable policy.xml under ${POLICY_PATHS}. ImageMagick with no coder policy decodes HEIF by default, which is the exposed case"; return 2; }

    local c
    for f in "${files[@]}"; do
        [[ -n "$f" ]] || continue
        found=1
        local blocked=() open=()
        for c in HEIC HEIF AVIF; do
            if coder_blocked "$f" "$c"; then blocked+=("$c"); else open+=("$c"); fi
        done
        if [[ ${#open[@]} -eq 0 ]]; then
            ok "${f}: HEIC, HEIF and AVIF are disabled"
        else
            bad "${f}: still allows ${open[*]}${blocked:+ (blocks ${blocked[*]})}"
            allowed=1
        fi
    done
    echo
    echo "  To block the decode path as defense in depth, add inside <policymap> in policy.xml:"
    echo '      <policy domain="coder" rights="none" pattern="HEIC" />'
    echo '      <policy domain="coder" rights="none" pattern="HEIF" />'
    echo '      <policy domain="coder" rights="none" pattern="AVIF" />'
    echo "  This stops ImageMagick handing HEIF/AVIF to libheif. It is not a substitute for"
    echo "  updating libheif, and it won't help a caller that reaches libheif without ImageMagick."
    [[ $allowed -eq 1 ]] && echo "  To write this block for you (reversible): sudo ${SELF} harden"
    [[ $found -eq 1 ]] || return 2
    return "$allowed"
}

# ---------- harden / unharden (the only writes this script makes) ------------

backup_file() {   # <path> -> prints backup path
    # Every backup gets its own private directory (mode 0700): two runs in the same second must not
    # share one, or the second copy would overwrite the true original, and a LocalSettings.php
    # holds database credentials.
    local dst
    mkdir -p "$BACKUP_ROOT" || die "could not create ${BACKUP_ROOT}"
    dst="$(mktemp -d "${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S).XXXXXX")" || die "could not create a backup directory under ${BACKUP_ROOT}"
    cp -a "$1" "$dst/" || die "could not back up $1"
    echo "${dst}/$(basename "$1")"
}

# The managed block, indented to sit inside <policymap>.
managed_block() {
    printf '  %s\n' "$BLOCK_BEGIN"
    printf '  <policy domain="coder" rights="none" pattern="HEIC" />\n'
    printf '  <policy domain="coder" rights="none" pattern="HEIF" />\n'
    printf '  <policy domain="coder" rights="none" pattern="AVIF" />\n'
    printf '  %s\n' "$BLOCK_END"
}

# True if the file carries a managed block from any version of this script.
has_block() { grep -qF "BEGIN ${MARKER}" "$1" 2>/dev/null; }

# Print <file> with every managed block (from any version) removed. Matches
# markers as literal substrings via index(), never as regex, so the version
# in the BEGIN line and the ( ) and . in it can't break the match. A single
# blank line immediately before a BEGIN marker is dropped too, so repeated
# harden/unharden cycles don't accumulate blank lines.
strip_block() {   # <file>
    awk -v bm="BEGIN ${MARKER}" -v em="END ${MARKER}" '
        index($0, bm) {
            if (held != "" ) held = ""   # discard a blank line held before the block
            skip=1; next
        }
        skip && index($0, em) {skip=0; next}
        skip {next}
        # Buffer a blank line: emit it only once we know a BEGIN marker does not follow
        /^[[:space:]]*$/ {
            if (held != "") print held
            held=$0; next
        }
        { if (held != "") { print held; held="" } print }
        END { if (held != "") print held }
    ' "$1"
}

cmd_harden() {
    need_root "harden edits a config file owned by another user" ""
    step "Hardening ImageMagick against HEIF/AVIF decoding"
    local -a files=()
    mapfile -t files < <(policy_files)
    if [[ ${#files[@]} -eq 0 ]]; then
        # No policy.xml at all: ImageMagick decodes HEIF by default. Create one
        # in the first configured directory that exists.
        local p
        for p in $POLICY_PATHS; do [[ -d "$p" ]] && { files=("$p/policy.xml"); break; }; done
        [[ ${#files[@]} -gt 0 ]] || die "no ImageMagick config directory found under ${POLICY_PATHS}; set POLICY_PATHS"
        caution "no policy.xml found; creating ${files[0]}"
        { echo '<policymap>'; managed_block; echo '</policymap>'; } > "${files[0]}"
        ok "wrote ${files[0]} with the HEIF/AVIF block"
        return 0
    fi

    local f bak changed=0
    for f in "${files[@]}"; do
        [[ -w "$f" ]] || { caution "${f}: not writable, skipping"; continue; }
        if has_block "$f"; then
            # Refresh in place: drop the old managed block, re-insert current one
            inf "${f}: already has a managed block; refreshing it"
        fi
        bak="$(backup_file "$f")"
        local tmp; tmp="$(mktemp)"
        # Strip any existing managed block, then insert a fresh one before
        # </policymap> (or append a policymap if the file has none).
        strip_block "$f" > "$tmp"
        if grep -qiF '</policymap>' "$tmp"; then
            local blk; blk="$(managed_block)"
            awk -v blk="$blk" 'BEGIN{done=0}
                !done && /<\/policymap>/ {print blk; done=1}
                {print}
            ' "$tmp" > "${tmp}.2" && mv "${tmp}.2" "$tmp"
        else
            { echo '<policymap>'; managed_block; echo '</policymap>'; cat "$tmp"; } > "${tmp}.2" && mv "${tmp}.2" "$tmp"
            caution "${f}: had no <policymap>; added one"
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: HEIF/AVIF coders disabled (backup ${bak})"
    done
    echo
    if [[ $changed -eq 1 ]]; then
        info "ImageMagick will now refuse HEIC/HEIF/AVIF. Verify with: ${SELF} policy"
        inf "This is defense in depth. Still update libheif and rebuild anything that bundles it"
        inf "Reverse with: sudo ${SELF} unharden"
    else
        warn "nothing was changed (no writable policy.xml)"
        return 1
    fi
}

cmd_unharden() {
    need_root "unharden edits a config file owned by another user" ""
    step "Removing the managed HEIF/AVIF block"
    local -a files=()
    mapfile -t files < <(policy_files)
    local f bak changed=0 any=0
    for f in "${files[@]}"; do
        has_block "$f" || continue
        any=1
        [[ -w "$f" ]] || { caution "${f}: has the block but is not writable, skipping"; continue; }
        bak="$(backup_file "$f")"
        local tmp; tmp="$(mktemp)"
        strip_block "$f" > "$tmp"
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: managed block removed (backup ${bak})"
    done
    if [[ $any -eq 0 ]]; then
        inf "no managed block found; nothing of this script's to remove"
        inf "If you added the coder lines by hand, remove them by hand"
        return 0
    fi
    [[ $changed -eq 1 ]] && info "Done. Verify with: ${SELF} policy"
    return 0
}

# ---------- mw-harden / mw-unharden (MediaWiki-level upload block) ------------
# A managed PHP block appended to LocalSettings.php that adds the HEIF-family
# MIME types to wgMimeTypeExclusions (and its pre-1.37 name wgMimeTypeBlacklist),
# so MediaWiki rejects a crafted HEIF upload by its detected type, whatever
# extension it carries, before the scaler ever runs. It also drops heif/heic/
# avif from wgFileExtensions if present. This complements the host libheif
# update; it does not replace it.
mw_managed_block() {
    local m
    printf '\n// %s\n' "$BLOCK_BEGIN"
    printf '// Reject HEIF/HEIC/AVIF uploads: a crafted one can reach a libheif\n'
    printf '// heap overflow through ImageMagick. Remove with the matching unharden.\n'
    printf '$wgMimeTypeExclusions = array_values( array_unique( array_merge(\n'
    printf '\t( $wgMimeTypeExclusions ?? [] ),\n\t[\n'
    for m in "${MW_HEIF_MIMES[@]}"; do printf "\t\t'%s',\n" "$m"; done
    printf '\t]\n) ) );\n'
    # Pre-1.37 fallback name, honored when the new one is absent
    printf 'if ( isset( $wgMimeTypeBlacklist ) ) {\n'
    printf '\t$wgMimeTypeBlacklist = $wgMimeTypeExclusions;\n}\n'
    # Drop the extensions from the allow-list if they were added
    printf 'if ( isset( $wgFileExtensions ) ) {\n'
    printf "\t\$wgFileExtensions = array_values( array_diff( \$wgFileExtensions, [ 'heif', 'heic', 'avif', 'heifs', 'heics' ] ) );\n}\n"
    printf '// %s\n' "$BLOCK_END"
}

# Insert text before a closing "?>" if the file has one, else append. A
# LocalSettings.php that ends inside PHP (no "?>") is the common case.
mw_insert() {   # <stripped-file> <block-text>  -> writes combined to stdout
    local f="$1" blk="$2"
    if grep -qE '^\s*\?>\s*$' "$f"; then
        awk -v blk="$blk" 'BEGIN{done=0}
            !done && /^[[:space:]]*\?>[[:space:]]*$/ {print blk; done=1}
            {print}
        ' "$f"
    else
        cat "$f"; printf '%s\n' "$blk"
    fi
}

cmd_mw_harden() {
    need_root "mw-harden edits a config file owned by another user" ""
    step "Blocking HEIF/HEIC/AVIF uploads in MediaWiki"
    local -a files=()
    mapfile -t files < <(mw_installs)
    [[ ${#files[@]} -gt 0 ]] || { warn "no LocalSettings.php found under ${MW_PATHS}; set MW_PATHS"; return 2; }
    local f bak changed=0 uses accepts mver
    for f in "${files[@]}"; do
        [[ -w "$f" ]] || { caution "${f}: not writable, skipping"; continue; }
        IFS='|' read -r uses accepts mver <<<"$(mw_profile "$f")"
        has_block "$f" && inf "${f}: already has a managed block; refreshing it"
        bak="$(backup_file "$f")"
        local tmp blk; tmp="$(mktemp)"; blk="$(mw_managed_block)"
        strip_block "$f" > "$tmp"
        mw_insert "$tmp" "$blk" > "${tmp}.2" && mv "${tmp}.2" "$tmp"
        # Refuse to install a file that no longer parses, if php is available
        if have php && ! php -l "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"; caution "${f}: edit would not parse as PHP; left unchanged (backup ${bak} kept)"; continue
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: HEIF/HEIC/AVIF uploads blocked (backup ${bak})"
        [[ $uses -eq 1 ]] || inf "    note: this wiki uses GD, not ImageMagick, so it wasn't a libheif path anyway; the block is harmless"
    done
    echo
    if [[ $changed -eq 1 ]]; then
        info "MediaWiki will now reject HEIF/HEIC/AVIF uploads by detected type. Verify with: ${SELF} check"
        inf "This is an application-level block. Still update the host libheif"
        inf "Reverse with: sudo ${SELF} mw-unharden"
    else
        warn "nothing was changed (no writable LocalSettings.php, or edits wouldn't parse)"
        return 1
    fi
}

cmd_mw_unharden() {
    need_root "mw-unharden edits a config file owned by another user" ""
    step "Removing the MediaWiki HEIF upload block"
    local -a files=()
    mapfile -t files < <(mw_installs)
    local f bak changed=0 any=0 tmp
    for f in "${files[@]}"; do
        has_block "$f" || continue
        any=1
        [[ -w "$f" ]] || { caution "${f}: has the block but is not writable, skipping"; continue; }
        bak="$(backup_file "$f")"
        tmp="$(mktemp)"
        strip_block "$f" > "$tmp"
        if have php && ! php -l "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"; caution "${f}: removal would not parse as PHP; left unchanged (backup ${bak} kept)"; continue
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: managed block removed (backup ${bak})"
    done
    [[ $any -eq 1 ]] || { inf "no managed block found; nothing of this script's to remove"; return 0; }
    [[ $changed -eq 1 ]] && info "Done. Verify with: ${SELF} check"
    return 0
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for image-processor crashes since ${HUNT_SINCE}"
    limited_view
    local jr; jr="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$jr'" RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >"$jr" || true; fi
    local -a files=()
    [[ -s "$jr" ]] && files+=("$jr")
    local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /var/discourse/shared/*/log/rails/production.log /var/www/*/log/*.log \
             /var/log/nginx/*.log /var/log/apache2/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS): nothing was read, which is not a clean result"; return 2; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "ImageMagick/convert/magick killed by a crash signal|(convert|magick|MagickCore|identify|mogrify)[^:]*\[[0-9]+\]: (segfault at|general protection|trap invalid opcode)"
        "libheif or libde265 frames in a crash/backtrace|(libheif|libde265|heif_|de265_|UncompressedImageCodec|unc_decoder|HeifPixelImage)"
        "service killed by SIGSEGV/SIGABRT (check which run image processing)|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
        "heap corruption abort near image decode|(double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned))"
        "repeated HEIF/HEIC/AVIF handling errors in app logs|(unable to read image|no decode delegate|corrupt image).*\.(heic|heif|avif)"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit tells you where to look: image decoders crash on genuinely broken files too. A"
    echo "  crash with libheif or libde265 frames on a vulnerable build, or a burst of HEIF"
    echo "  decode errors from one source before a worker died, is worth treating as an incident:"
    echo "  check what the process could reach (secrets, database credentials, tokens, and for a"
    echo "  forum its admin and session stores) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "reference: ${KEY_REF}; writeup: ${ADVISORY}"
case "$CMD" in
    check|policy|harden|unharden|hunt) "cmd_${CMD}" ;;
    mw-harden)   cmd_mw_harden ;;
    mw-unharden) cmd_mw_unharden ;;
    *) die "Unknown command: $CMD (check|policy|harden|unharden|mw-harden|mw-unharden|hunt|version)" ;;
esac
}
# ---------- one change at a time ---------------------------------------------------------------------
# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a dry run
# (a * in CMDS stands for the default command, for a tool whose default changes the host),
# run the script again under flock(1), so two runs cannot interleave their changes. The second run waits
# PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. flock -o leaves the lock with the waiting
# flock process, so a service this script starts does not inherit it and hold it. The lock file is
# STATE_DIR/.lock, or /var/lib/psf-security-patches/<script>/.lock. Without flock (macOS) nothing is locked.
# PSF_LOCK_HELD marks the re-run so it does not lock again: the script sets it, leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_words=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
        case "$lk_arg" in -*) ;; *) lk_words=$((lk_words + 1)) ;; esac
    done
    [[ $lk_words -eq 0 && "$lk_cmds" == *" * "* ]] && lk_hit=1      # no command named, and the default command changes the host
    [[ $lk_hit -eq 1 ]] || return 0
    psf_refuse_change "lock_for_change"
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "harden unharden mw-harden mw-unharden" "$@"

main "$@"; exit

# Assisted-by: Claude Opus 5.5
