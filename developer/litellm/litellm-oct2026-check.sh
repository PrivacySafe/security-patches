#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# LiteLLM 1.107.0 supply-chain compromise: detect, hunt and contain  (v1)
# No CVE (malicious package release, PyPI and Docker)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On 21 October 2026 a malicious release of litellm, version 1.107.0, was
# published to PyPI (all seven wheels, plus an sdist with a tampered
# pyproject.toml) and to the project's Docker images (tags v1.107.0, latest,
# main-latest, main-stable), after attacker-controlled GitHub accounts
# triggered a release. Each wheel drops three files into the ROOT of
# site-packages, beside litellm/ rather than inside it:
#   cook.pth           one line, "import cook"
#   cook.py            a zlib+base64 blob; a credential stealer ("privcollect")
#   sitecustomize.py   an hourly backdoor that fetches and runs attacker code
# Python runs .pth files and sitecustomize.py at interpreter startup, so the
# malware runs on every Python start on the host, even if litellm is never
# imported. The stealer targets cloud tokens, developer and private keys, AI
# tooling credentials, browser data, environment variables, and a LiteLLM
# proxy's saved credentials, and exfiltrates to litellm[.]dev; the backdoor
# reads a domain from a GitHub dead drop (letters9813) and runs code from it.
# The last clean release before it is 1.106.2.
#
# The remedy is to rebuild, not to clean in place: if 1.107.0 was installed from
# a wheel, or a LiteLLM container pulled on 21 October 2026 ran, treat the host
# as FULLY COMPROMISED. The stealer already ran. Rebuild the host, and from a
# clean machine revoke and rotate every credential it could reach (cloud keys,
# API tokens, SSH and signing keys, browser sessions, the LiteLLM proxy's
# keys), then reinstall litellm pinned to 1.106.2 by digest. This script finds
# the compromise, hunts the indicators, and can contain the auto-executing
# backdoor (quarantine) so it stops running while you rebuild; containment is
# not remediation.
#
# Usage:
#   ./litellm-oct2026-check.sh [command]
#
#   check (default)  find litellm in every Python environment (and running
#                    containers) and flag 1.107.0, and report the dropped
#                    malware files in site-packages. Read-only. Exit 0 = nothing
#                    found, 1 = compromise indicators present, 2 = couldn't read.
#   hunt             read-only, deeper: the malware files across site-packages,
#                    the /tmp markers it leaves, and logs for its network
#                    indicators (litellm.dev, the GitHub dead drop). Exit 0 =
#                    clean, 1 = findings.
#   quarantine       CONTAINMENT: back up (for forensics) and remove
#                    cook.pth and cook.py, and sitecustomize.py when it carries
#                    the malware markers, so they stop running at Python start.
#                    Needs write access. The host is still compromised: rebuild
#                    and rotate credentials.
#   version          print the script version.
#
# Env overrides:
#   SCAN_PATHS="/usr /opt /srv /home /root /var/www"
#                                     where to look for site-packages
#   SCAN_DEPTH=9                      how deep the search goes
#   SAFE_PIN=1.106.2                  the last clean release to pin to
#   BACKUP_ROOT=/var/backups/litellm-oct2026
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt's network check
#   SCAN_CONTAINERS=1                 1 = also look inside running containers;
#                                     0 = skip them
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
COMPROMISED_VER="1.107.0"
SAFE_PIN="${SAFE_PIN:-1.106.2}"
SCAN_PATHS="${SCAN_PATHS:-/usr/lib /usr/local/lib /opt /srv /home /root /var/www}"
SCAN_DEPTH="${SCAN_DEPTH:-9}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/litellm-oct2026}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
# Markers that identify the malicious sitecustomize.py (a legitimate
# sitecustomize.py exists in some environments, so it is only acted on when it
# carries one of these).
SITE_MARKERS='privcollect|PRIVCOLLECT|letters9813|remote_code_loader|litellm\.dev|import cook|domain\.txt'
NET_MARKERS='litellm\.dev|letters9813|remote_code_loader|/codepy|pythonclient-test'
TMP_MARKERS=(/tmp/.pc_once_* /tmp/remote_code_loader.lock)
SCRIPT_NAME="litellm-oct2026-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
REF="https://github.com/BerriAI/litellm/issues/47826"

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

# ---------- discovery --------------------------------------------------------
site_dirs() {
    {
        if have python3; then
            python3 - <<'PY' 2>/dev/null || true
import site, sys
seen=set()
try:
    for d in site.getsitepackages(): seen.add(d)
except Exception: pass
try: seen.add(site.getusersitepackages())
except Exception: pass
for d in sys.path:
    if d.endswith("site-packages"): seen.add(d)
for d in sorted(x for x in seen if x): print(d)
PY
        fi
        # shellcheck disable=SC2086
        find $SCAN_PATHS -maxdepth "$SCAN_DEPTH" -type d -name site-packages 2>/dev/null || true
    } | while read -r d; do [[ -d "$d" ]] && echo "$d"; done | sort -u
}

litellm_version_in() {   # <site-packages> -> version or empty
    local sp="$1" di v
    di="$(ls -d "$sp"/litellm-*.dist-info 2>/dev/null | head -1 || true)"
    if [[ -n "$di" ]]; then
        v="$(basename "$di")"; v="${v#litellm-}"; v="${v%.dist-info}"; echo "$v"; return
    fi
    [[ -f "$sp/litellm/__init__.py" ]] && grep -oE '__version__\s*=\s*"[0-9][0-9.]*"' "$sp/litellm/__init__.py" 2>/dev/null | head -1 | grep -oE '[0-9][0-9.]+' || true
}

# Which malware artifacts are in this site-packages root. Prints one per line.
artifacts_in() {   # <site-packages>
    local sp="$1" f
    [[ -f "$sp/cook.pth" ]] && echo "cook.pth"
    [[ -f "$sp/cook.py" ]] && echo "cook.py"
    if [[ -f "$sp/sitecustomize.py" ]] && grep -qE "$SITE_MARKERS" "$sp/sitecustomize.py" 2>/dev/null; then echo "sitecustomize.py"; fi
}

tmp_markers_present() {
    local m hit=1 g
    shopt -s nullglob
    for g in "${TMP_MARKERS[@]}"; do for m in $g; do [[ -e "$m" ]] && { echo "$m"; hit=0; }; done; done
    shopt -u nullglob
    return "$hit"
}

# A scan path that exists but cannot be read leaves the scan partial: with nothing found that is
# exit 2, not a clean result. A path that does not exist is simply skipped.
SCAN_PARTIAL=0
scan_roots() {
    local p
    for p in $SCAN_PATHS; do
        if [[ -e "$p" && ( ! -r "$p" || ( -d "$p" && ! -x "$p" ) ) ]]; then caution "scan path exists but is not readable: ${p}"; SCAN_PARTIAL=1; fi
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 found=0 sp v arts a any=0
    scan_roots
    step "litellm in Python environments"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        v="$(litellm_version_in "$sp")"
        [[ -n "$v" ]] || continue
        any=1
        if [[ "$v" == "$COMPROMISED_VER" ]]; then bad "${sp}: litellm ${v}  COMPROMISED (remove it; pin ${SAFE_PIN} by digest)"; found=1
        else ok "${sp}: litellm ${v}  (not the compromised release; verify integrity and pin ${SAFE_PIN} by digest)"; fi
    done < <(site_dirs)
    [[ $any -eq 1 ]] || inf "no litellm install found under the scanned paths"

    step "Dropped malware files in site-packages"
    local any_art=0
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        if [[ -n "$arts" ]]; then
            any_art=1; found=1
            while read -r a; do [[ -n "$a" ]] && bad "${sp}/${a}  malware artifact"; done <<<"$arts"
        fi
    done < <(site_dirs)
    [[ $any_art -eq 1 ]] || ok "no cook.pth / cook.py / malicious sitecustomize.py found in site-packages"

    step "Runtime markers"
    local tm
    tm="$(tmp_markers_present || true)"
    if [[ -n "$tm" ]]; then found=1; while read -r m; do [[ -n "$m" ]] && bad "runtime marker present: ${m} (the stealer ran / is running)"; done <<<"$tm"
    else ok "no /tmp runtime markers (.pc_once_*, remote_code_loader.lock)"; fi

    step "litellm inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt id name out any_c=0
        for rt in docker podman; do
            have "$rt" || continue
            while read -r id name; do
                [[ -n "$id" ]] || continue
                out="$("$rt" exec "$id" sh -c 'for d in $(python3 -c "import site,sys;[print(p) for p in set(site.getsitepackages()+[site.getusersitepackages()])]" 2>/dev/null); do [ -e "$d/cook.pth" ] && echo COOK; ls -d "$d"/litellm-*.dist-info 2>/dev/null | head -1; done' 2>/dev/null || true)"
                if grep -q 'COOK' <<<"$out" || grep -q "litellm-${COMPROMISED_VER}\.dist-info" <<<"$out"; then
                    any_c=1; found=1; bad "${rt} ${name:-$id}: compromised litellm (cook.pth or ${COMPROMISED_VER} inside); rebuild the image on a clean 1.106.2 digest"
                fi
            done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
        done
        [[ $any_c -eq 1 ]] || inf "no running container shows the compromise (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $found -eq 1 ]] && rc=1
    if [[ $rc -eq 0 && $SCAN_PARTIAL -eq 1 ]]; then rc=2; fi
    case $rc in
        0) info "No sign of the litellm 1.107.0 compromise where this could read" ;;
        2) warn "No indicators in what could be read, but a scan path could not be read: this is not a clean result. Run it again as a user who can read that path" ;;
        1) warn "Compromise indicators found. TREAT THE HOST AS FULLY COMPROMISED: the stealer runs on every Python start. From a clean machine, revoke and rotate every credential this host could reach (cloud keys, API tokens, SSH and signing keys, browser sessions, the LiteLLM proxy's keys). Then rebuild, and reinstall litellm pinned to ${SAFE_PIN} by digest. Run 'quarantine' to stop the backdoor re-running in the meantime. Incident: ${REF}" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0 sp arts a
    step "Malware files across site-packages"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        [[ -n "$arts" ]] && { found=1; while read -r a; do [[ -n "$a" ]] && bad "${sp}/${a}"; done <<<"$arts"; }
    done < <(site_dirs)
    [[ $found -eq 1 ]] || ok "none found"

    step "Runtime markers (/tmp)"
    local tm; tm="$(tmp_markers_present || true)"
    if [[ -n "$tm" ]]; then found=1; while read -r m; do [[ -n "$m" ]] && bad "$m"; done <<<"$tm"; else ok "none"; fi
    inf "also look for a detached python process holding /tmp/remote_code_loader.lock, and PRIVCOLLECT_ACTIVE=1 in process environments"

    step "Network indicators in logs"
    local -a files=(); local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/messages /var/log/nginx/*.log /var/log/apache2/*.log \
             /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then inf "no readable logs to scan for network indicators"
    else
        local n; n="$( { grep -hEc "$NET_MARKERS" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "network indicators in logs: ${n}"; { grep -hE "$NET_MARKERS" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-200 | sed 's/^/      /'
        else ok "no litellm.dev / dead-drop indicators in the scanned logs"; fi
    fi
    echo
    echo "  If anything here matched, the host is compromised: rotate every credential it"
    echo "  could reach from a clean machine, rebuild, and reinstall litellm ${SAFE_PIN} by"
    echo "  digest. 'quarantine' stops the backdoor re-running but does not make the host safe."
    return "$found"
}

# ---------- quarantine (containment) -----------------------------------------
cmd_quarantine() {
    [[ "$(id -u)" -eq 0 ]] || warn "not running as root; removing site-packages files may need root or the owning user"
    local sp arts a bdir did=0
    step "Containment: quarantining the auto-executing malware files"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        [[ -n "$arts" ]] || continue
        bdir="${BACKUP_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)/$(echo "$sp" | sed 's#^/##; s#/#_#g')"
        mkdir -p "$bdir"
        while read -r a; do
            [[ -n "$a" ]] || continue
            if cp -p "${sp}/${a}" "${bdir}/${a}" 2>/dev/null && rm -f "${sp}/${a}" 2>/dev/null; then
                ok "${sp}/${a} -> quarantined to ${bdir}/${a}"; did=$((did+1))
            else bad "${sp}/${a}: could not quarantine (permission?)"; fi
        done <<<"$arts"
    done < <(site_dirs)
    echo
    if [[ $did -gt 0 ]]; then
        info "quarantined ${did} file(s); forensic copies are under ${BACKUP_ROOT}"
    else inf "nothing to quarantine"; fi
    warn "CONTAINMENT ONLY. The stealer already ran on every Python start. The host is compromised: from a clean machine rotate every credential it could reach, remove the litellm ${COMPROMISED_VER} install, rebuild, and reinstall litellm ${SAFE_PIN} by digest. Also check /tmp for remote_code_loader.lock and kill any detached python holding it."
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "litellm ${COMPROMISED_VER} supply-chain compromise; incident: ${REF}"
case "$CMD" in
    check|hunt|quarantine) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|quarantine|version)" ;;
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
lock_for_change "quarantine" "$@"

main "$@"; exit

# Assisted-by: Claude Opus 5.5
