#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Ghostscript Upload2Shell -dSAFER sandbox escape check/mitigate  (v1)
# CVE-2026-125396
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-125396 ("Upload2Shell"), found by pwn.ai, fixed in Ghostscript
# 10.08.0. A use-after-free in the Type 1 font loader: the .putgstringcopy
# procedure in gs_fonts.ps calls the privileged .forceput operator without
# checking operand types; a crafted font in a PostScript, EPS or PDF
# document triggers a type error, a custom error handler recovers
# .forceput, and a use-after-free across a save/restore boundary lets the
# attacker execute arbitrary code as the user running Ghostscript, even
# with -dSAFER set. No Ghostscript setting disables Type 1 font loading, so
# there is no in-Ghostscript configuration workaround; the only fixes are
# upgrading Ghostscript itself or keeping files that might contain crafted
# fonts away from it entirely (see 'mitigate' and 'rules').
#
# The file does not need to look like a PostScript file: Ghostscript (and
# the libraries that silently invoke it) identify the format by content,
# not by name or declared MIME type, so a file uploaded as '.png' or
# '.jpg' that is actually PostScript, EPS or a PDF carrying an embedded
# Type 1 font still reaches this code path. pwn.ai's own write-up
# documents working chains through, among others: ImageMagick/Imagick
# (its default delegate for PS/EPS/PDF input), Pillow (which opens EPS by
# shelling out to Ghostscript once pixels are requested, a separate issue
# from Pillow's own CVE-2026-112900), WordPress uploads by Authors and
# above or a public upload form (WordPress's own CVE-2026-65640 covers
# that specific upload route), Roundcube attachment thumbnails (fixed
# separately in Roundcube's own CVE-2026-114727), DokuWiki's image resize
# pipeline, and CUPS print queues shared without a login. On a desktop,
# simply opening a malicious file in a Ghostscript-based viewer is enough.
#
# Usage:
#   ./ghostscript-upload2shell-check.sh [command] [...]
#
#   check     - read-only. Finds every Ghostscript install this host's
#               package manager knows about (dpkg or rpm) plus any gs
#               binary on PATH, and reports each one's version against
#               10.08.0. A distribution's own backport is checked against
#               its own package changelog the same way other scripts in
#               this collection handle a backport that does not change
#               the upstream version string. One real trap: Ghostscript's
#               own 10.08.0 release candidate, tagged before the fix
#               commit, also reports its version as plain "10.08.0" with
#               nothing in `gs --version` distinguishing it from the final
#               release; this script cannot tell the two apart from the
#               version string alone and says so wherever gs reports
#               exactly 10.08.0 outside a distribution package. Also
#               audits ImageMagick's policy.xml, if present, for whether
#               the PS/EPS/XPS coders this mitigation would disable are
#               already blocked. Exits 1 if an exposed Ghostscript is
#               found (or the RC ambiguity could not be resolved), 0 if
#               every one found is confirmed at or above the fix (or
#               fully blocked by policy.xml), 2 if none was found.
#   hunt      - read-only. Looks for Ghostscript crash signatures (a
#               segfault or abort naming gs, libgs, or a Type 1 charstring
#               routine) in the system journal and dmesg; this is a weak
#               signal at best, since a successful exploit need not crash
#               the process, and an unrelated Ghostscript bug could also
#               produce the same crash signature.
#   mitigate [--include-pdf] [--dry-run] [--force] - adds the
#               long-standing community-documented ImageMagick policy.xml
#               lines that block the PS, PS2, PS3, EPS and XPS coders (the
#               formats always routed through Ghostscript with no
#               alternative renderer), backing up the file first and
#               checking the result is still well-formed XML. PDF is left
#               alone by default, since many ImageMagick users genuinely
#               need PDF read/write and not every PDF workflow touches
#               Ghostscript's Type 1 loader; --include-pdf also blocks the
#               PDF coder, which is more thorough but breaks any PDF
#               rasterization or thumbnailing ImageMagick does. This
#               covers only ImageMagick. It has no effect on Pillow,
#               WordPress, Roundcube, DokuWiki, or a print queue that
#               calls Ghostscript directly; see 'rules' for those.
#               Blocking these coders has a real cost, not just a benefit:
#               it stops ImageMagick processing those formats at all, even
#               where that is wanted. So by default, mitigate only acts
#               when 'check' would report a Ghostscript here as exposed or
#               undetermined (never found counts as undetermined, not
#               clear, since that could mean a reachable copy this host's
#               package manager simply does not know about); when every
#               Ghostscript found is confirmed fixed, it changes nothing
#               and says so, unless --force is given to add the hardening
#               anyway regardless of what was found. Requires root (or
#               whatever account owns policy.xml), unless --dry-run is
#               given, which prints a diff of what would change and
#               writes nothing, so it needs no privilege (and skips the
#               exposure gate, so you can preview the change either way).
#   rollback [--dry-run] - restores the policy.xml 'mitigate' backed up.
#               Requires root, unless --dry-run is given, which prints
#               which file would be restored from which backup and
#               writes nothing, so it needs no privilege.
#   rules     - prints the guidance 'mitigate' cannot automate: upgrading,
#               the Pillow formats= argument, WordPress and Roundcube
#               version thresholds, and print-queue authentication.
#   version   - prints this script's version.
#
# Environment: IMAGEMAGICK_POLICY_FILES, a space-separated list of
# policy.xml paths, replacing the usual ImageMagick 6/7 locations.
# FIXED_BUILDS, additional known-fixed distribution package strings,
# space-separated, checked alongside the ones this script already knows.
# PSF_BACKUP_DIR, where backups and the restore manifest are kept (default
# /var/backups/psf-security-patches/ghostscript-upload2shell).
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="ghostscript-upload2shell-check.sh"
SCRIPT_VERSION="1.6.0"
SCRIPT_DATE="2026-11-25"
ADVISORY="https://security-tracker.debian.org/tracker/CVE-2026-125396"
WRITEUP="https://pwn.ai/upload2shell"
PSF_TMP=()
trap '[ "${#PSF_TMP[@]}" -eq 0 ] || rm -f "${PSF_TMP[@]}"' EXIT

if [ -t 2 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED=$(tput setaf 1); GRN=$(tput setaf 2); YEL=$(tput setaf 3); BLU=$(tput setaf 4); RST=$(tput sgr0)
else
    RED=""; GRN=""; YEL=""; BLU=""; RST=""
fi

# A binary this script found may belong to someone else (under /home, or an /opt folder an
# application account owns). Running it as root would run their code as root. So, as root, a binary
# runs as root only when root owns it, nobody else can write it, and every folder above it is root's
# and not writable by others (a sticky folder such as /tmp counts as safe: others cannot replace root's
# entries in it). Otherwise it runs as its owner, or not at all.
fb_safe_to_exec() {   # <binary>
    local f d m
    f="$(readlink -f "$1" 2>/dev/null)" || return 1
    [[ -f "$f" && -x "$f" ]] || return 1
    [[ "$(stat -c %u "$f" 2>/dev/null)" == 0 ]] || return 1
    m="$(stat -c %a "$f" 2>/dev/null)" || return 1; [[ $(( 8#$m & 8#022 )) -eq 0 ]] || return 1
    d="$(dirname "$f")"
    while :; do
        [[ "$(stat -c %u "$d" 2>/dev/null)" == 0 ]] || return 1
        m="$(stat -c %a "$d" 2>/dev/null)" || return 1
        [[ $(( 8#$m & 8#022 )) -eq 0 || $(( 8#$m & 8#1000 )) -ne 0 ]] || return 1
        [[ "$d" == / ]] && break
        d="$(dirname "$d")"
    done
}
run_found() {   # <binary> <args...>: run a binary this script found, as root only when that is safe
    local b="$1" o; shift
    if [[ "${EUID:-$(id -u)}" -ne 0 ]] || fb_safe_to_exec "$b"; then timeout "${RUN_FOUND_TIMEOUT:-20}" "$b" "$@"; return; fi
    o="$(stat -Lc %U "$b" 2>/dev/null)"
    [[ -n "$o" && "$o" != root && "$o" != UNKNOWN ]] || return 1
    command -v runuser >/dev/null 2>&1 || return 1
    timeout "${RUN_FOUND_TIMEOUT:-20}" runuser -u "$o" -- "$b" "$@"
}

warn() { printf '%s[!]%s %s\n' "$RED" "$RST" "$1" >&2; }
note() { printf '%s[*]%s %s\n' "$YEL" "$RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
inf()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$1"; }
die()  { warn "$1"; exit 2; }

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
# Nothing to check on this host: say so in a Verdict section, record "not applicable" and stop with exit 0.
na_exit() { psf_not_applicable "$1"; echo; echo "===== Verdict ====="; echo "[i] Not applicable: $1."; exit 0; }

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then
        die "${1}: run it as root, for example: sudo ${SELF_CMD}"
    else
        die "${1}: run it as root (sudo is not installed here)"
    fi
}

FIXED="10.08.0"
BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/ghostscript-upload2shell}"
POLICY_FILES="${IMAGEMAGICK_POLICY_FILES:-/etc/ImageMagick-6/policy.xml /etc/ImageMagick-7/policy.xml /usr/local/etc/ImageMagick-7/policy.xml}"
# Known distribution fixed builds, confirmed against each vendor's own security
# tracker on 22 November 2026 (not from gs --version, which a distro backport
# does not change): Debian bookworm/trixie, Ubuntu's USN-8949-1 (21 Oct 2026,
# which folded Upload2Shell in alongside two other Ghostscript CVEs).
FIXED_BUILDS_KNOWN="10.0.0~dfsg-11+deb12u9 10.05.1~dfsg-1+deb13u2 10.02.1~dfsg1-0ubuntu7.10 9.55.0~dfsg1-0ubuntu5.15"
FIXED_BUILDS="${FIXED_BUILDS:-}"
CHANGELOG_MARKERS=(CVE-2026-125396)

print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$0"; }

ver_ge() {   # ver_ge A B: true if version A >= version B
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

owner_pkg() {   # owner_pkg BINARY-PATH: the dpkg/rpm package owning it, if any
    local p="$1"
    if command -v dpkg-query >/dev/null 2>&1; then dpkg-query -S "$p" 2>/dev/null | head -1 | cut -d: -f1; return; fi
    if command -v rpm >/dev/null 2>&1; then rpm -qf "$p" 2>/dev/null | head -1; return; fi
}

# check_binary PATH: prints "rc|message" for one gs binary.
check_binary() {
    local bin="$1" v pkg full rc
    v="$(run_found "$bin" --version 2>/dev/null | head -1 | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' || true)"
    [ -n "$v" ] || { echo "2|${bin}: could not read a version from --version"; return; }
    pkg="$(owner_pkg "$bin")"
    if [ -n "$pkg" ]; then
        full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' "$pkg" 2>/dev/null || true)"
        for f in $FIXED_BUILDS_KNOWN $FIXED_BUILDS; do
            if [ -n "$full" ] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
               && [ "${f%%[-+~]*}" = "${full%%[-+~]*}" ]; then
                echo "0|${pkg} ${full} >= known fixed build ${f}"; return
            fi
        done
        local cl="/usr/share/doc/${pkg}/changelog.Debian.gz"
        if [ -f "$cl" ] && zcat "$cl" 2>/dev/null | head -1 | grep -q "(${full})"; then
            for m in "${CHANGELOG_MARKERS[@]}"; do
                if zgrep -q "$m" "$cl" 2>/dev/null; then echo "0|${pkg} ${full}: changelog lists ${m}"; return; fi
            done
        fi
        rc=1; ver_ge "$v" "$FIXED" && rc=0
        echo "${rc}|${pkg} ${full} (gs reports ${v}; this distro backport was not matched against a known fixed build or changelog marker, so treat the gs version as the only signal, same caveat as an unmatched backport elsewhere)"
        return
    fi
    if ver_ge "$v" "$FIXED"; then
        if [ "$v" = "$FIXED" ]; then
            echo "2|${bin}: reports exactly ${FIXED} with no owning package found. Ghostscript's own 10.08.0 release candidate, built before the fix commit, reports the same version string as the final release; gs --version cannot tell them apart. Confirm this build's actual date or provenance before trusting it."
        else
            echo "0|${bin}: ${v} > ${FIXED}"
        fi
    else
        echo "1|${bin}: ${v} < ${FIXED}"
    fi
}

gs_binaries() {
    { type -a -P gs 2>/dev/null || true
      shopt -s nullglob
      for c in /usr/bin/gs /usr/local/bin/gs /opt/*/bin/gs; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [ -x "$c" ] && readlink -f "$c"; done | sort -u
}

check_policy_xml() {
    local f found=0
    for f in $POLICY_FILES; do
        [ -f "$f" ] || continue
        found=1
        inf "ImageMagick policy: $f"
        local blocked=1 c
        for c in PS EPS; do
            grep -qE "domain=\"coder\"[^>]*rights=\"none\"[^>]*pattern=\"${c}\"" "$f" 2>/dev/null || blocked=0
        done
        if [ "$blocked" -eq 1 ]; then
            ok "PS and EPS coders are blocked: ImageMagick cannot reach Ghostscript through those formats."
        else
            note "PS and/or EPS coders are not blocked here. If this Ghostscript is unpatched, ImageMagick can still reach it; run 'mitigate', or confirm Ghostscript itself is >= ${FIXED}."
        fi
    done
    [ "$found" -eq 1 ] || inf "No ImageMagick policy.xml found at the usual locations (set IMAGEMAGICK_POLICY_FILES for a non-default path)."
}

# gs_exposure_rc: 0 every found gs confirmed fixed, 1 any confirmed
# exposed, 2 none found or undetermined (the RC-ambiguous case counts as
# undetermined, not clear). Prints nothing; do_check prints, this is also
# used quietly by do_mitigate to decide whether mitigate needs --force.
gs_exposure_rc() {
    local any=0 worst=0 b rc msg
    while IFS= read -r b; do
        any=1
        IFS='|' read -r rc msg <<<"$(check_binary "$b")"
        [ "$rc" -gt "$worst" ] && worst=$rc
        [ -z "${1:-}" ] || "$1" "$rc" "$msg"
    done < <(gs_binaries)
    [ "$any" -eq 1 ] || { NA_MSG="no Ghostscript (gs) is installed"; [ -z "${1:-}" ] || "$1" none ""; return 2; }
    return "$worst"
}

do_check() {
    local rc
    gs_exposure_rc _check_print; rc=$?
    [ -z "${NA_MSG:-}" ] || na_exit "$NA_MSG"
    echo
    check_policy_xml
    return "$rc"
}
_check_print() {
    case "$1" in
        0) ok "$2" ;;
        1) warn "$2. Advisory: ${ADVISORY} ; write-up: ${WRITEUP}" ;;
        none) inf "No gs binary found on PATH or in the usual locations." ;;
        *) note "$2" ;;
    esac
}

do_hunt() {
    local any=0 hit
    if command -v journalctl >/dev/null 2>&1; then
        hit="$(journalctl -k -o cat 2>/dev/null | grep -iE 'segfault.*\b(gs|libgs)\b|\b(gs|libgs)\b.*segfault' | tail -20)"
        if [ -n "$hit" ]; then any=1; warn "journalctl kernel log matches:"; echo "$hit" | sed 's/^/      /'; fi
    fi
    if [ -r /var/log/syslog ] || [ -r /var/log/kern.log ]; then
        hit="$(grep -iE 'segfault.*\b(gs|libgs)\b|\b(gs|libgs)\b.*segfault' /var/log/syslog /var/log/kern.log 2>/dev/null | tail -20)"
        if [ -n "$hit" ]; then any=1; warn "Log matches:"; echo "$hit" | sed 's/^/      /'; fi
    fi
    if [ "$any" -eq 0 ]; then
        inf "No Ghostscript crash signature found in the logs checked. This is weak evidence either way: a successful exploit need not crash the process, and an unrelated Ghostscript bug could produce the same signature."
        return 2
    fi
    note "A crash naming gs/libgs is not proof of this exploit specifically. Investigate the files that were being processed around that time."
    return 1
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" 2>/dev/null || die "Could not create $BACKUP_DIR"; }

backup_file() {
    local f="$1" base
    base="${BACKUP_DIR}/$(echo "$f" | tr '/' '_').orig"
    [ -f "$base" ] || cp -a "$f" "$base" || die "Could not back up $f"
    echo "${f}	${base}" >> "${BACKUP_DIR}/.manifest.tsv"
}

xml_wellformed() {
    if command -v xmllint >/dev/null 2>&1; then xmllint --noout "$1" 2>/dev/null; return $?; fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$1" 2>/dev/null; return $?
    fi
    return 0
}

do_mitigate() {
    local include_pdf="${1:-0}" dry="${2:-0}" force="${3:-0}" f changed=0 coders="PS PS2 PS3 EPS XPS"
    [ "$include_pdf" -eq 1 ] && coders="$coders PDF"
    if [ "$force" -ne 1 ] && [ "$dry" != "1" ]; then
        gs_exposure_rc; local exprc=$?
        if [ "$exprc" -eq 0 ]; then
            note "Every Ghostscript found is already confirmed fixed, and blocking these coders has a real cost: ImageMagick would no longer process PostScript, EPS or XPS at all, even where that's wanted. Not changing anything; pass --force to add the hardening anyway, or --dry-run to preview it."
            return 0
        fi
    fi
    [ "$dry" = "1" ] || need_root "mitigate changes the host"
    [ "$dry" = "1" ] || ensure_backup_dir
    for f in $POLICY_FILES; do
        [ -f "$f" ] || continue
        local tmp; tmp="$(mktemp)"; PSF_TMP+=("$tmp")
        cp "$f" "$tmp"
        local c added=0
        for c in $coders; do
            grep -qE "domain=\"coder\"[^>]*rights=\"none\"[^>]*pattern=\"${c}\"" "$tmp" 2>/dev/null && continue
            sed -i "s#</policymap>#  <policy domain=\"coder\" rights=\"none\" pattern=\"${c}\" />\n</policymap>#" "$tmp"
            added=1
        done
        if [ "$added" -eq 1 ] && ! cmp -s "$f" "$tmp"; then
            if [ "$dry" = "1" ]; then
                inf "Would edit $f:"
                diff -u "$f" "$tmp" 2>/dev/null | sed -n '3,$p' | sed 's/^/      /'
                changed=1
                rm -f "$tmp"
                continue
            fi
            backup_file "$f"
            cp "$tmp" "$f"
            if xml_wellformed "$f"; then
                ok "Edited $f: blocked ${coders}"
                changed=1
            else
                warn "$f is not well-formed XML after editing; rolling back."
                local base; base="$(grep "^${f}	" "${BACKUP_DIR}/.manifest.tsv" | tail -1 | cut -f2)"
                [ -n "$base" ] && cp -a "$base" "$f"
            fi
        fi
        rm -f "$tmp"
    done
    if [ "$dry" = "1" ]; then
        if [ "$changed" -eq 1 ]; then
            inf "Dry run: no files were changed."
        else
            inf "Dry run: nothing found that mitigate would change."
        fi
        return 0
    fi
    if [ "$changed" -eq 0 ]; then
        note "No change made: no policy.xml found, or every coder in {${coders}} was already blocked."
        return 0
    fi
    note "This covers ImageMagick only. It does nothing for Pillow, WordPress, Roundcube, DokuWiki, or a print queue that calls Ghostscript directly; see 'rules'."
    return 0
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "${BACKUP_DIR}/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0
    tac "${BACKUP_DIR}/.manifest.tsv" 2>/dev/null | while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then
            inf "Would restore $orig from $backup"
        else
            cp -a "$backup" "$orig" && ok "Restored $orig" || { warn "Failed to restore $orig"; failed=1; }
        fi
    done
    return "$failed"
}

do_rules() {
    cat <<'RULES'
Ghostscript Upload2Shell (CVE-2026-125396)

Fix: upgrade to Ghostscript 10.08.0, or your distribution's backport
(Debian: DSA-6516-1/DLA-4914-1; Ubuntu: USN-8949-1). There is no
Ghostscript setting that disables Type 1 font loading, so there is no
in-Ghostscript configuration workaround.

Watch for the release-candidate trap: Ghostscript's own 10.08.0rc1, built
before the fix commit, reports its version as plain "10.08.0", identical
to the real fixed release. Check your package's actual build date or
changelog, not just the string gs --version prints.

Rebuild and redeploy any container image that installs Ghostscript,
ImageMagick, or a Python image stack with Pillow and a system gs binary:
patching the host does not touch a copy baked into an image.

Downstream applications, each with their own separate fix:

  - ImageMagick: 'mitigate' blocks the PS/PS2/PS3/EPS/XPS coders in
    policy.xml; --include-pdf also blocks PDF.
  - Pillow: pass formats=[...] (the formats you actually accept) to
    Image.open() so EPS is never loaded; Pillow only shells out to gs for
    EPS. This is a code change in the application using Pillow; this
    script cannot make it for you.
  - WordPress: update to a release carrying CVE-2026-65640's fix for the
    separate upload-handling issue.
  - Roundcube: update to 1.6.20 or 1.7.5, which also carries CVE-2026-114727's
    fix (stops passing certain attachment image types to ImageMagick). This
    collection's own roundcube-oct2026-check.sh already checks for exactly
    this version threshold, for its own, larger October release; run that
    script rather than checking the version by hand.
  - CUPS or any other shared print queue: require authentication. An
    anonymous, unauthenticated print queue that renders PostScript is a
    path to this bug with no login at all.
  - Any other service that renders a user-supplied file by invoking gs,
    directly or through a library: treat it as exposed until Ghostscript
    itself is confirmed at or above 10.08.0.
RULES
}

case "${1:-check}" in
    --help|-h) print_help; exit 0 ;;
esac

verdict() {
    printf '\n===== Verdict =====\n'
    case "$1" in
        0) ok "Not exposed, by what this check can see." ;;
        1) warn "Exposed: see the findings above. Upgrade, or preview the interim measure with 'mitigate --dry-run'." ;;
        *) note "Undetermined: no install was found, or not enough could be read to decide. See the notes above." ;;
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
lock_for_change "mitigate rollback" "$@"

case "${1:-check}" in
    check) do_check; rc=$?; verdict "$rc"; exit "$rc" ;;
    hunt) do_hunt; exit $? ;;
    mitigate)
        shift; include_pdf=0; dry=0; force=0
        for a in "$@"; do
            case "$a" in
                --include-pdf) include_pdf=1 ;;
                --dry-run) dry=1 ;;
                --force) force=1 ;;
                *) die "Unknown mitigate option: $a (--include-pdf --dry-run --force)" ;;
            esac
        done
        do_mitigate "$include_pdf" "$dry" "$force"; exit $?
        ;;
    rollback)
        shift; dry=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                *) die "Unknown rollback option: $a (--dry-run)" ;;
            esac
        done
        do_rollback "$dry"; exit $?
        ;;
    rules) do_rules; exit 0 ;;
    version|--version|-V) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
    *) die "Usage: $0 {check|hunt|mitigate [--include-pdf] [--dry-run] [--force]|rollback [--dry-run]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
