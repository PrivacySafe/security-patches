#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# psf-run: manual (macOS only; psf-run runs on GNU/Linux)
# =============================================================================
# eMudhra intermediate CA compromise, macOS mitigation  (v1)
# Disclosed 20 Oct 2026: https://emudhra.we-have-a-problem.com/
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The private keys of eight eMudhra intermediate CAs can be recovered from their
# certificates. macOS blocks them in apps that use Apple's own networking and
# security frameworks, but the command line tools that ship with macOS and with
# the Xcode Command Line Tools (curl, git, python3, ruby, perl, openssl and pip)
# verify certificates against /etc/ssl/cert.pem without checking revocation, and that file still contains the roots the intermediates
# chain to. Apple has said it will update the file in a future release. Until
# then this script removes those roots from it, the way Apple's support page
# (support.apple.com/en-us/149555) and the disclosure page describe, and proves
# they are gone.
#
# Homebrew has already shipped a fixed ca-certificates. The script reports its
# bundle and the formula version, but never runs brew: brew refuses to run as
# root, so update it as your own user (brew update && brew upgrade ca-certificates).
#
# Usage:
#   ./emudhra-macos-mitigate.sh [command] [options]
#
#   check (default)  [--online] [--cert-file FILE]
#                    read-only; changes nothing, root not needed. Reports
#                    whether emSign ECC Root CA - G3 and AAA Certificate
#                    Services are still in the system bundle and in
#                    Homebrew's, and whether the pip fix is in place.
#                    --online also connects to the disclosure site's test
#                    hosts with curl: a connection that succeeds means the
#                    client still trusts a compromised intermediate.
#                    Exit 0 = both roots absent, 1 = emSign ECC Root CA - G3
#                    present or a test host accepted, 2 = only AAA
#                    Certificate Services remains (your decision, see below)
#                    or the bundle could not be read.
#   apply            [--include-aaa] [--pip] [--dry-run] [--cert-file FILE]
#                    back up the bundle, remove emSign ECC Root CA - G3 from
#                    it, and check the result. --include-aaa also removes
#                    AAA Certificate Services, which blocks the six Sectigo
#                    cross-signed intermediates but may break unaffected
#                    sites that chain to it. --pip makes the built-in pip
#                    use the fixed system file. Needs root.
#   rollback         [--dry-run] [--force]
#                    put the original bundle back and remove the pip line.
#                    This re-exposes you. It refuses when the bundle has
#                    changed since apply (a macOS update) unless --force.
#   version          print the script version and exit
#
# Environment:
#   CERT_FILE=/etc/ssl/cert.pem        the bundle to check and change
#   STATE_DIR=/var/lib/psf-security-patches/emudhra-macos   backups and record
#   PLATFORM=Darwin                    override the detected platform
#   BREW_PREFIX=/opt/homebrew          where Homebrew is installed
#   CURL_BIN=/usr/bin/curl             the curl that --online uses
#   PYTHON_BIN=/usr/bin/python3        the Python whose standard library folder holds the
#                                      sitecustomize.py that --pip checks
#   SITECUSTOMIZE=FILE                 that sitecustomize.py, instead of asking PYTHON_BIN
#   LIVE_HOSTS="host ..."              replace the disclosure site's test hosts
#   PSF_NO_ROOT_NOTE=1                 hide the note about a root login
#
# Exit codes: 0 done or clear, 1 exposed or a failed change, 2 usage error or
# a bundle that could not be read. Every command prints the script version on
# its first line.
#
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

set -uo pipefail

SCRIPT_NAME="emudhra-macos-mitigate.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"

PLATFORM="${PLATFORM:-$(uname -s 2>/dev/null || echo unknown)}"
CERT_FILE="${CERT_FILE:-/etc/ssl/cert.pem}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/emudhra-macos}"
LIVE_HOSTS="${LIVE_HOSTS:-dv-g3b-emudhra.we-have-a-problem.com dv-g3b-aaa-emudhra.we-have-a-problem.com dv-g3b-noct-emudhra.we-have-a-problem.com dv-g3b-aaa-noct-emudhra.we-have-a-problem.com}"
FIXED_BREW="2026-09-25_1"   # first Homebrew ca-certificates with the fix (disclosure page)
PIP_LINE='import os; os.environ.setdefault("PIP_CERT", "/etc/ssl/cert.pem")'

# The two roots, and the SHA-256 fingerprint of each (Mozilla's CA program records for emSign ECC Root CA - G3
# and Sectigo's for AAA Certificate Services). A block is only cut out when its certificate has this fingerprint.
ECC_NAME="emSign ECC Root CA - G3"
ECC_SHA256="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"
AAA_NAME="AAA Certificate Services"
AAA_SHA256="D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
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

print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- bundle helpers ---------------------------------------------------
OPENSSL=""
find_openssl() {
    if [[ -n "${OPENSSL_BIN:-}" ]]; then OPENSSL="$OPENSSL_BIN"
    elif [[ -x /usr/bin/openssl ]]; then OPENSSL=/usr/bin/openssl
    elif have openssl; then OPENSSL="$(command -v openssl)"
    else OPENSSL=""; fi
}

# bundle_has FILE NAME: does the PEM bundle hold a certificate whose subject names NAME?
bundle_has() {
    "$OPENSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | "$OPENSSL" pkcs7 -print_certs -noout 2>/dev/null \
        | grep -E '^subject' | grep -qF -- "$2"
}

count_certs() { grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null || true; }

sha() {
    if have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'
    else sha256sum "$1" 2>/dev/null | awk '{print $1}'; fi
}

# A block in Apple's bundle starts at a header line, "=== /C=IN/.../CN=NAME" (or "### NAME"), and runs to the
# next header line, whatever lies between. This is the rule in Apple's own steps (support.apple.com/en-us/149555),
# widened from one exact header string to "a header line that ends with the root's name" so a different order of
# the subject fields still matches. The fingerprint check below is what makes that safe.
AWK_TARGET='function target(l, s,   t, n) { t = "/CN=" s; n = length(t); return (l ~ /^(===|###) /) && (substr(l, length(l) - n + 1) == t || l == "=== " s || l == "### " s) }'

# block_text FILE NAME: the lines of the block for NAME
block_text() {
    awk -v s="$2" "$AWK_TARGET"' /^(===|###) /{inb=0} target($0, s){inb=1} inb' "$1"
}

# block_fingerprint FILE NAME: SHA-256 of the first certificate in the block for NAME (upper case hex, no colons),
# or nothing when there is no such block
block_fingerprint() {
    block_text "$1" "$2" | awk '/BEGIN CERTIFICATE/{p=1} p{print} /END CERTIFICATE/{exit}' \
        | "$OPENSSL" x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//; s/://g' | tr 'a-f' 'A-F'
}

# remove_block FILE NAME OUT: copy FILE to OUT without the block for NAME
remove_block() {
    awk -v s="$2" "$AWK_TARGET"' /^(===|###) /{skip=0} target($0, s){skip=1} !skip' "$1" > "$3"
}

# parsed_count FILE: how many certificates OpenSSL can read from the bundle
parsed_count() {
    "$OPENSSL" crl2pkcs7 -nocrl -certfile "$1" 2>/dev/null | "$OPENSSL" pkcs7 -print_certs -noout 2>/dev/null | grep -c '^subject' || true
}

# write_bundle SRC DEST: on a real Mac this is Apple's own command from support.apple.com/en-us/149555
# (install -m 0644 -o root -g wheel), which replaces the file and also works if it is a symbolic link.
# With PLATFORM=Darwin set on GNU/Linux there is no wheel group, so it copies over the file instead.
write_bundle() {
    if [[ "$(uname -s 2>/dev/null)" == "Darwin" ]]; then install -m 0644 -o root -g wheel "$1" "$2"
    else cat "$1" > "$2"; fi
}

# brew_prefix: where Homebrew lives, empty when it is not installed
brew_prefix() {
    local p
    if [[ -n "${BREW_PREFIX:-}" ]]; then echo "$BREW_PREFIX"; return; fi
    for p in /opt/homebrew /usr/local /home/linuxbrew/.linuxbrew; do
        [[ -x "$p/bin/brew" ]] && { echo "$p"; return; }
    done
    echo ""
}

# version_lt A B for Homebrew's 2026-09-25_1 style: dates and a revision, compared as numbers
version_lt() {
    local a b
    a="$(echo "$1" | tr '_-' '..')"; b="$(echo "$2" | tr '_-' '..')"
    [[ "$a" != "$b" && "$(printf '%s\n%s\n' "$a" "$b" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | head -n1)" == "$a" ]]
}

sitecustomize_path() {
    local py
    if [[ -n "${SITECUSTOMIZE:-}" ]]; then echo "$SITECUSTOMIZE"; return; fi
    py="${PYTHON_BIN:-/usr/bin/python3}"
    [[ -x "$py" ]] || py="$(command -v python3 2>/dev/null || true)"
    [[ -n "$py" ]] || return 0
    "$py" -c 'import sysconfig; print(sysconfig.get_path("stdlib"))' 2>/dev/null | sed 's|$|/sitecustomize.py|'
}

MANIFEST=""
need_platform() {
    [[ "$PLATFORM" == "Darwin" ]] || die "this script is for macOS (found ${PLATFORM}). On Debian, Ubuntu and Trisquel use emudhra-mitigate.sh; other systems are in the disclosure page: https://emudhra.we-have-a-problem.com/#workarounds"
    find_openssl
    [[ -n "$OPENSSL" ]] || die "openssl was not found (it is /usr/bin/openssl on macOS)"
    MANIFEST="${STATE_DIR}/manifest.txt"
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local online=0 file="$CERT_FILE" rc=0 ecc=0 aaa=0 unread=0 prefix hb v
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --online) online=1 ;;
            --cert-file) shift; [[ $# -gt 0 ]] || die "--cert-file needs a path"; file="$1" ;;
            *) die "Unknown check option: $1 (--online --cert-file FILE)" ;;
        esac
        shift
    done
    need_platform
    step "System bundle: ${file}"
    if [[ ! -r "$file" ]]; then
        bad "cannot read ${file}: nothing was checked"; unread=1
    elif [[ "$(parsed_count "$file")" -ne "$(count_certs "$file")" ]]; then
        bad "OpenSSL reads $(parsed_count "$file") of the $(count_certs "$file") certificates in ${file}. One damaged certificate makes it read none, so it cannot say whether the roots are there. Restore the file from ${file}.orig or a backup first"; unread=1
    else
        inf "$(count_certs "$file") certificates in the bundle"
        if bundle_has "$file" "$ECC_NAME"; then ecc=1; bad "${ECC_NAME} is in the bundle: curl, git, python3, ruby, perl, openssl and pip trust the eMudhra intermediates that chain to it"
        else ok "${ECC_NAME} is not in the bundle"; fi
        if bundle_has "$file" "$AAA_NAME"; then aaa=1; caution "${AAA_NAME} is in the bundle: the six Sectigo cross-signed intermediates still chain to it. Removing it may break unaffected sites that chain to it, so it is your choice (apply --include-aaa)"
        else ok "${AAA_NAME} is not in the bundle"; fi
        if [[ -f "${STATE_DIR}/manifest.txt" ]] && grep -q '^cert|' "${STATE_DIR}/manifest.txt" 2>/dev/null; then
            if [[ $ecc -eq 1 ]]; then caution "this script removed the root before, but it is back: a macOS update replaced ${file}. Run apply again"
            else inf "applied by this script (record in ${STATE_DIR})"; fi
        fi
    fi

    step "Built-in pip"
    local sc; sc="$(sitecustomize_path)"
    if [[ -z "$sc" ]]; then inf "python3 was not found, so the pip setting was not checked"
    elif [[ -f "$sc" ]] && grep -qxF -- "$PIP_LINE" "$sc" 2>/dev/null; then ok "pip is set to use ${file} (${sc})"
    else inf "the built-in pip uses its own copy of the roots; apply --pip points it at the system file (${sc})"; fi

    step "Homebrew"
    prefix="$(brew_prefix)"
    if [[ -z "$prefix" ]]; then inf "Homebrew was not found"
    else
        hb="${prefix}/etc/ca-certificates/cert.pem"
        v=""
        if [[ -L "${prefix}/opt/ca-certificates" ]]; then v="$(basename "$(readlink "${prefix}/opt/ca-certificates")")"; fi
        [[ -n "$v" ]] || v="$(find "${prefix}/Cellar/ca-certificates" -mindepth 1 -maxdepth 1 -exec basename {} \; 2>/dev/null | sort | tail -n1)"
        if [[ -n "$v" ]]; then
            if version_lt "$v" "$FIXED_BREW"; then bad "Homebrew ca-certificates ${v} is older than the fixed ${FIXED_BREW}"; ecc=1
            else ok "Homebrew ca-certificates ${v} (fixed from ${FIXED_BREW})"; fi
        else inf "the Homebrew ca-certificates formula is not installed"; fi
        if [[ -r "$hb" && "$(parsed_count "$hb")" -ne "$(count_certs "$hb")" ]]; then
            caution "OpenSSL reads $(parsed_count "$hb") of the $(count_certs "$hb") certificates in ${hb}, so the roots cannot be looked for there: run brew postinstall ca-certificates as your own user"
        elif [[ -r "$hb" ]]; then
            if bundle_has "$hb" "$ECC_NAME"; then bad "${hb} still holds ${ECC_NAME}: Homebrew's curl and git trust it"; ecc=1
            else ok "${hb} does not hold ${ECC_NAME}"; fi
        fi
        if [[ $ecc -eq 1 ]]; then inf "update Homebrew as your own user, not with sudo: brew update && brew upgrade ca-certificates. Hosted CI images that disable brew updates need that step in the workflow"; fi
    fi

    if [[ $online -eq 1 ]]; then
        step "Live test (curl against the disclosure site's test hosts)"
        local c h r seen=0 done_list=" "
        for c in "${CURL_BIN:-}" /usr/bin/curl "${prefix:+${prefix}/bin/curl}"; do
            [[ -n "$c" && -x "$c" ]] || continue
            case "$done_list" in *" $c "*) continue ;; esac
            done_list="${done_list}${c} "
            seen=1
            for h in $LIVE_HOSTS; do
                "$c" --silent --head --output /dev/null --max-time 8 "https://${h}/" >/dev/null 2>&1; r=$?
                case "$r" in
                    0) bad "${c} connected to ${h}: it trusts a compromised intermediate"
                       case "$h" in *aaa*) aaa=1 ;; *) ecc=1 ;; esac ;;
                    35|51|58|60|77|83|91) ok "${c} rejected ${h} (certificate error ${r})" ;;
                    *) caution "${c} could not reach ${h} (curl exit ${r}): no answer either way" ;;
                esac
            done
        done
        [[ $seen -eq 1 ]] || inf "no curl found to test with"
    fi

    step "Verdict"
    if [[ $unread -eq 1 ]]; then warn "The bundle could not be read, so nothing is known."; rc=2
    elif [[ $ecc -eq 1 ]]; then warn "Exposed. Run: sudo ${SELF} apply   (add --dry-run first to see the change)"; rc=1
    elif [[ $aaa -eq 1 ]]; then warn "emSign ECC Root CA - G3 is gone. AAA Certificate Services remains, so the six Sectigo cross-signed intermediates are still trusted. Decide: apply --include-aaa removes it and may break unaffected sites"; rc=2
    else info "Neither root is in the bundle."; fi
    inf "A macOS update may replace ${file}: run check after each update. Apple's guidance: https://support.apple.com/en-us/149555"
    return "$rc"
}

# ---------- apply ------------------------------------------------------------
cmd_apply() {
    local dry=0 incl=0 pip=0 file="$CERT_FILE" targets="" n before after t1 t2 bk ts
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) dry=1 ;;
            --include-aaa) incl=1 ;;
            --pip) pip=1 ;;
            --cert-file) shift; [[ $# -gt 0 ]] || die "--cert-file needs a path"; file="$1" ;;
            *) die "Unknown apply option: $1 (--include-aaa --pip --dry-run --cert-file FILE)" ;;
        esac
        shift
    done
    need_platform
    [[ $dry -eq 1 ]] || need_root "apply changes the host"
    [[ -r "$file" ]] || die "cannot read ${file}"
    if [[ "$(parsed_count "$file")" -ne "$(count_certs "$file")" ]]; then
        bad "OpenSSL reads $(parsed_count "$file") of the $(count_certs "$file") certificates in ${file}: not touching it. Restore it from ${file}.orig or a backup first"; return 1
    fi
    step "Plan"
    n=0
    if bundle_has "$file" "$ECC_NAME"; then targets="ecc"; n=$((n+1)); inf "remove ${ECC_NAME}"
    else ok "${ECC_NAME} is already absent"; fi
    if [[ $incl -eq 1 ]]; then
        if bundle_has "$file" "$AAA_NAME"; then targets="${targets} aaa"; n=$((n+1)); inf "remove ${AAA_NAME} (this may break unaffected sites that chain to it)"
        else ok "${AAA_NAME} is already absent"; fi
    fi
    if [[ $n -gt 0 ]]; then
        for t1 in $targets; do
            local nm exp fp
            case "$t1" in ecc) nm="$ECC_NAME"; exp="$ECC_SHA256" ;; aaa) nm="$AAA_NAME"; exp="$AAA_SHA256" ;; esac
            fp="$(block_fingerprint "$file" "$nm")"
            if [[ -z "$fp" ]]; then
                bad "found ${nm} in ${file} but no block with a header line that names it, so it cannot be cut out safely: remove it by hand (steps: https://emudhra.we-have-a-problem.com/#macos-curl)"; return 1
            elif [[ "$fp" != "$exp" ]]; then
                bad "the block named ${nm} holds a certificate with SHA-256 ${fp}, not the published ${exp}: not touching ${file}"; return 1
            else ok "the block for ${nm} is the published certificate (SHA-256 ${exp:0:16}...)"; fi
        done
        before="$(count_certs "$file")"
        t1="$(mktemp "${TMPDIR:-/tmp}/emudhra-macos.XXXXXX")" || die "no temporary file"
        PSF_TMP+=("$t1")
        t2="$(mktemp "${TMPDIR:-/tmp}/emudhra-macos.XXXXXX")" || { rm -f "$t1"; die "no temporary file"; }
        PSF_TMP+=("$t2")
        cp "$file" "$t1"
        for n in $targets; do
            case "$n" in ecc) remove_block "$t1" "$ECC_NAME" "$t2" ;; aaa) remove_block "$t1" "$AAA_NAME" "$t2" ;; esac
            cp "$t2" "$t1"
        done
        after="$(count_certs "$t1")"
        local want; want=$((before - $(echo "$targets" | wc -w | tr -d ' ')))
        if [[ ! -s "$t1" || "$after" -ne "$want" || "$(parsed_count "$t1")" -ne "$want" ]]; then
            rm -f "$t1" "$t2"
            bad "cutting the block would leave ${after} certificates (OpenSSL reads $(parsed_count "$t1")) instead of ${want}: not touching ${file}. Remove the roots by hand (steps: https://emudhra.we-have-a-problem.com/#macos-curl)"
            return 1
        fi
        inf "the bundle goes from ${before} to ${after} certificates"
        if [[ $dry -eq 1 ]]; then
            inf "Dry run: nothing was changed."
            rm -f "$t1" "$t2"
        else
            ts="$(date -u +%Y%m%d-%H%M%S)"
            mkdir -p "$STATE_DIR" || { rm -f "$t1" "$t2"; bad "cannot create ${STATE_DIR}"; return 1; }
            bk="${STATE_DIR}/cert.pem.${ts}-$$"   # two runs in the same second never share a backup
            while [[ -e "$bk" ]]; do bk="${bk}x"; done
            cp -p "$file" "$bk" || { rm -f "$t1" "$t2"; bad "cannot back up ${file}"; return 1; }
            # Apple's steps keep one copy as cert.pem.orig and say to delete an old one and repeat after an update.
            # The file still holds the roots, so it is Apple's current version: keep the .orig in step with it.
            if [[ ! -e "${file}.orig" ]] || ! cmp -s "$file" "${file}.orig"; then cp -p "$file" "${file}.orig" 2>/dev/null || true; fi
            step "Applying"
            if ! write_bundle "$t1" "$file" 2>/dev/null; then
                write_bundle "$bk" "$file" 2>/dev/null
                rm -f "$t1" "$t2"
                bad "cannot write ${file} (it may be protected): the original is untouched. Backup: ${bk}"
                return 1
            fi
            rm -f "$t1" "$t2"
            ok "backed up to ${bk}"
            local failed=0
            for n in $targets; do
                case "$n" in ecc) t1="$ECC_NAME" ;; aaa) t1="$AAA_NAME" ;; esac
                if bundle_has "$file" "$t1"; then failed=1; bad "${t1} is still in the bundle"; else ok "${t1} is no longer in the bundle"; fi
            done
            if [[ "$(count_certs "$file")" -ne "$after" ]]; then failed=1; bad "the certificate count is not ${after}"; fi
            if [[ $failed -eq 1 ]]; then
                write_bundle "$bk" "$file"
                warn "The check failed, so the original bundle was put back."
                return 1
            fi
            echo "cert|${file}|${bk}|$(sha "$bk")|$(sha "$file")|$(echo "$targets" | tr -s ' ' ',' | sed 's/^,//')" >> "$MANIFEST"
            info "Done. Verify with: ${SELF} check"
            inf "A macOS update may replace ${file} and bring the roots back: run check after each update."
        fi
    else
        info "Nothing to remove from ${file}."
    fi

    if [[ $pip -eq 1 ]]; then
        step "Built-in pip"
        local sc; sc="$(sitecustomize_path)"
        if [[ -z "$sc" ]]; then caution "python3 was not found: pip was not changed"
        elif [[ -f "$sc" ]] && grep -qxF -- "$PIP_LINE" "$sc" 2>/dev/null; then ok "pip already uses the system file (${sc})"
        elif [[ $dry -eq 1 ]]; then inf "would add to ${sc}: ${PIP_LINE}"
        else
            local created=0; [[ -f "$sc" ]] || created=1
            mkdir -p "$STATE_DIR" 2>/dev/null
            if echo "$PIP_LINE" >> "$sc" 2>/dev/null; then
                chmod 644 "$sc" 2>/dev/null
                echo "pip|${sc}|${created}" >> "$MANIFEST"
                ok "added the PIP_CERT line to ${sc}"
            else caution "cannot write ${sc} (it may be protected): pip was not changed"; fi
        fi
    fi

    local prefix; prefix="$(brew_prefix)"
    if [[ -n "$prefix" ]]; then inf "Homebrew is separate: as your own user, not with sudo, run brew update && brew upgrade ca-certificates"; fi
    return 0
}

# ---------- rollback ---------------------------------------------------------
cmd_rollback() {
    local dry=0 force=0 kind a b c d e now rc=0 found=0 restored=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) dry=1 ;;
            --force) force=1 ;;
            *) die "Unknown rollback option: $1 (--dry-run --force)" ;;
        esac
        shift
    done
    need_platform
    [[ -s "$MANIFEST" ]] || { info "Nothing to roll back (no record in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS='|' read -r kind a b c d e; do
        case "$kind" in
            pip)
                found=1
                if [[ $dry -eq 1 ]]; then inf "would remove the PIP_CERT line from ${a}"
                elif [[ -f "$a" ]]; then
                    grep -vxF -- "$PIP_LINE" "$a" > "${a}.psf.$$" 2>/dev/null; cat "${a}.psf.$$" > "$a"; rm -f "${a}.psf.$$"
                    if [[ "$b" == 1 && ! -s "$a" ]]; then rm -f "$a"; fi
                    ok "removed the PIP_CERT line from ${a}"
                fi ;;
            cert)
                found=1
                # a = bundle, b = backup, c = hash of the backup, d = hash after apply, e = roots removed
                now="$(sha "$a")"
                if [[ ! -f "$b" ]]; then caution "the backup ${b} is missing: ${a} was not restored"; rc=1
                elif [[ "$now" != "$d" && $force -eq 0 ]]; then
                    if [[ $restored -eq 1 ]]; then
                        inf "skipped an older record: a macOS update replaced ${a} after it was made, so its backup is out of date"
                    else
                        caution "${a} has changed since apply (a macOS update or an edit). Restoring the old copy would bring the roots back and drop anything Apple changed. Run check; use rollback --force to restore it anyway"; rc=1
                    fi
                elif [[ $dry -eq 1 ]]; then inf "would restore ${a} from ${b} (this brings back: ${e})"
                else
                    if write_bundle "$b" "$a" 2>/dev/null; then restored=1; ok "restored ${a} from ${b}"; warn "The roots (${e}) are trusted again."
                    else bad "cannot write ${a}"; rc=1; fi
                fi ;;
        esac
    done < <(awk '{a[NR]=$0} END {for (i = NR; i >= 1; i--) print a[i]}' "$MANIFEST")   # newest record first
    if [[ $found -eq 1 && $dry -eq 0 && $rc -eq 0 ]]; then rm -f "$MANIFEST"; info "Rolled back. The backups stay in ${STATE_DIR}."; fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "eMudhra intermediate CAs (disclosed 20 October 2026), macOS bundle /etc/ssl/cert.pem; Apple: https://support.apple.com/en-us/149555"
    case "$CMD" in
        check) cmd_check "$@" ;;
        apply) cmd_apply "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|apply|rollback|version)" ;;
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
lock_for_change "apply rollback" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
