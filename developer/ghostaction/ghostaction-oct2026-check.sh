#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# GhostAction stage-2 developer-machine stealer: scan, hunt and contain  (v1)
# No CVE (supply-chain campaign targeting GitHub repositories and developers)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The GhostAction campaign, which injects credential-stealing GitHub Actions
# workflows into compromised repositories, added a second stage in October 2026
# that persists on a developer's own machine. In 94 repositories it committed
# three things:
#   .vscode/tasks.json  a task (seen labeled "eslint-check") with
#                       "runOn": "folderOpen" and hidden output, which runs
#                       automatically when the folder is opened in VS Code and
#                       executes the fake font with Node.
#   public/fonts/fa-solid-400.woff2
#                       named like a normal Font Awesome asset, but it is not a
#                       font: it is a Node.js credential stealer. It harvests
#                       AWS keys, PyPI and npm tokens, Git logins, Kubernetes
#                       credentials, SSH private keys, and Anthropic Claude and
#                       Google Gemini keys, installs a cron job that runs
#                       attacker code every five minutes, and exfiltrates over
#                       plain HTTP. The same file name was used in North Korea's
#                       Fake Font / PolinRider campaign.
#   a second Actions workflow  a backup that runs if the stealer never does.
# Related phishing uses my-github[.]com (and my-gitlab[.]com) to complete a
# GitHub OAuth device flow for repo, workflow and read:org scopes and steal a
# token. Exfiltration and C2 are at 193.32.204[.]199 (TCP 8443 and 8080).
#
# GhostAction is a supply-chain compromise, so the remedy is detection,
# containment and credential rotation. This script is a detector: it scans your
# repositories for the dropped artifacts (a "font" that is not a valid font, a
# folder-open task, a workflow carrying the C2), hunts the machine for the cron
# job and the network indicators, and can quarantine the confirmed artifacts.
# None of that undoes a stolen token. If anything here matches, from a CLEAN
# device revoke your GitHub tokens and authorized OAuth apps, change your
# password, rotate every credential the repositories and workflows could reach,
# audit your repositories, and warn anyone who cloned them. Keep VS Code
# workspace trust on, so opening a cloned folder does not run its tasks.
#
# Usage:
#   ./ghostaction-oct2026-check.sh [command]
#
#   check (default)  scan the paths for the dropped artifacts: a .woff2/.woff
#                    whose magic bytes are not a real font, a .vscode/tasks.json
#                    that runs on folderOpen, a workflow carrying the C2, npm
#                    lifecycle hooks that pipe a download to a shell, and the
#                    campaign's domains/IP in files. Read-only. Exit 0 = clean,
#                    1 = indicators found, 2 = couldn't read something.
#   hunt             read-only, machine-level: cron jobs that run attacker code,
#                    the domains/IP in shell history, git config and logs, and a
#                    stealer/miner-style process running. Exit 0 = clean, 1 =
#                    findings.
#   quarantine       CONTAINMENT: back up (for forensics) and remove
#                    the confirmed artifacts (a fake font, a tasks.json that
#                    executes it, a workflow carrying the C2). Needs write
#                    access. Your tokens are still stolen: revoke and rotate.
#   version          print the script version.
#
# Env overrides:
#   SCAN_PATHS="$PWD $HOME"           where to scan for repositories
#   SCAN_DEPTH=12                     how deep to search
#   BACKUP_ROOT=/var/backups/ghostaction-oct2026
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
SCAN_PATHS="${SCAN_PATHS:-$PWD $HOME}"
SCAN_DEPTH="${SCAN_DEPTH:-12}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/ghostaction-oct2026}"
HUNT_LOGS="${HUNT_LOGS:-}"
GA_NET='my-github\.com|my-gitlab\.com|193\.32\.204\.199'
# Prune these heavy/irrelevant directories from the scan.
PRUNE=(node_modules .git .cache .venv venv site-packages .mypy_cache dist build .next)
SCRIPT_NAME="ghostaction-oct2026-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
REF="https://opensourcemalware.com/blog/ghostaction-attack-escalates"

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

# find under SCAN_PATHS, pruning heavy dirs, matching the given args.
fscan() {   # <find-test-args...>
    local p prune=() x
    for x in "${PRUNE[@]}"; do prune+=(-name "$x" -o); done
    unset 'prune[${#prune[@]}-1]'
    for p in $SCAN_PATHS; do
        [[ -e "$p" ]] || continue
        find "$p" -maxdepth "$SCAN_DEPTH" \( "${prune[@]}" \) -prune -o "$@" 2>/dev/null || true
    done | sort -u
}

magic4() { od -An -tx1 -N4 "$1" 2>/dev/null | tr -d ' \n'; }

# This script's own text names the indicators it looks for, so a content scan that reaches
# the script (run from the directory it was downloaded to, or saved under /tmp) would report
# the script itself. The script's own file, and only that exact file, is left out.
SELF_REAL="$(readlink -f "$0" 2>/dev/null || echo "$0")"
not_self() { local x; while IFS= read -r x; do [[ "$(readlink -f "$x" 2>/dev/null || echo "$x")" == "$SELF_REAL" ]] || echo "$x"; done; }

# At least one scan path must be readable, or nothing was scanned and "clean" would be false.
# A path that does not exist is skipped (the default $HOME may not exist for a service account);
# a path that exists but cannot be read leaves the scan partial (exit 2 when nothing is found).
SCAN_PARTIAL=0
scan_roots() {
    local p n=0
    for p in $SCAN_PATHS; do
        if [[ ! -e "$p" ]]; then inf "scan path does not exist, skipped: ${p}"
        elif [[ ! -r "$p" || ( -d "$p" && ! -x "$p" ) ]]; then caution "scan path exists but is not readable: ${p}"; SCAN_PARTIAL=1
        else n=$((n + 1)); fi
    done
    [[ $n -gt 0 ]] || die "none of the scan paths can be read (${SCAN_PATHS}): nothing was scanned"
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local found=0 f m
    scan_roots

    step "Fonts that are not fonts (the stealer vector)"
    local fx=0
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        m="$(magic4 "$f")"
        case "$f" in
            *.woff2) [[ "$m" == "774f4632" ]] || { found=1; fx=1; bad "not a valid WOFF2 (magic ${m:-empty}): ${f}"; } ;;
            *.woff)  [[ "$m" == "774f4646" ]] || { found=1; fx=1; bad "not a valid WOFF (magic ${m:-empty}): ${f}"; } ;;
        esac
    done < <(fscan \( -name '*.woff2' -o -name '*.woff' \) -type f -print)
    [[ $fx -eq 1 ]] || ok "every .woff2/.woff found has valid font magic bytes"

    step ".vscode/tasks.json auto-run on folder open"
    local tx=0
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        grep -q 'folderOpen' "$f" 2>/dev/null || continue
        tx=1
        if grep -qE "$GA_NET" "$f" 2>/dev/null || grep -qE '\.woff2|\.woff|node .*\.(woff2|png|wasm|dat|bin)' "$f" 2>/dev/null; then
            found=1; bad "folderOpen task that runs a non-script file or carries the C2: ${f}"
        else
            caution "folderOpen task (review the command it runs): ${f}"
        fi
    done < <(fscan -path '*/.vscode/tasks.json' -type f -print)
    [[ $tx -eq 1 ]] || ok "no .vscode/tasks.json runs on folderOpen"

    step "GitHub Actions workflows carrying the C2"
    local wx=0
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        if grep -qE "$GA_NET" "$f" 2>/dev/null; then found=1; wx=1; bad "workflow references the campaign's C2: ${f}"; fi
    done < <(fscan -path '*/.github/workflows/*' \( -name '*.yml' -o -name '*.yaml' \) -type f -print)
    [[ $wx -eq 1 ]] || ok "no workflow references the campaign's domains or IP"

    step "npm lifecycle hooks that pipe a download into a shell"
    local nx=0
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        if grep -qE '"(preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]*(curl|wget)[^"]*(\|\s*(ba)?sh|node -e)' "$f" 2>/dev/null; then
            found=1; nx=1; bad "package.json lifecycle hook pipes a download to a shell: ${f}"
        fi
    done < <(fscan -name 'package.json' -type f -print)
    [[ $nx -eq 1 ]] || ok "no package.json lifecycle hook pipes a download into a shell"

    step "Campaign domains / IP anywhere in the scanned files"
    local gx=0 g
    while read -r g; do [[ -n "$g" ]] && { found=1; gx=1; bad "C2 indicator in: ${g}"; }; done \
        < <(fscan -type f -print 2>/dev/null | head -20000 | xargs -r -d '\n' grep -lE "$GA_NET" 2>/dev/null | not_self | head -40 || true)
    [[ $gx -eq 1 ]] || ok "no my-github.com / my-gitlab.com / 193.32.204.199 in the scanned files"

    step "Verdict"
    if [[ $found -eq 1 ]]; then
        warn "GhostAction stage-2 indicators found. Your credentials may be stolen: from a CLEAN device, revoke your GitHub tokens and authorized OAuth apps (Settings > Applications), change your password, and rotate every credential the repositories and workflows could reach (cloud keys, npm/PyPI tokens, SSH and signing keys, Kubernetes and AI provider keys). Run 'hunt', audit the repositories, and warn anyone who cloned them. Keep VS Code workspace trust on. Context: ${REF}"
        return 1
    fi
    if [[ $SCAN_PARTIAL -eq 1 ]]; then
        caution "no indicators in the paths that could be read, but at least one path could not be read: this is not a clean result"
        return 2
    fi
    info "No GhostAction stage-2 artifacts found in the scanned paths"
    return 0
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0

    step "Cron jobs that fetch and run attacker code"
    local -a cronsrc=()
    local cronf; cronf="$(mktemp)" || die "cannot create a temporary file"
    trap 'rm -f "${cronf:-}"' EXIT
    have crontab && { crontab -l >"$cronf" 2>/dev/null && cronsrc+=("$cronf"); }
    local g f
    shopt -s nullglob
    for g in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && cronsrc+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#cronsrc[@]} -gt 0 ]]; then
        local n
        n="$( { grep -hEc "$GA_NET|\*/5 .*(curl|wget).*(\|\s*(ba)?sh)|(curl|wget)[^|]*\|\s*(ba)?sh" "${cronsrc[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "suspicious cron entries: ${n}"; { grep -hE "$GA_NET|(curl|wget)[^|]*\|\s*(ba)?sh" "${cronsrc[@]}" 2>/dev/null || true; } | tail -4 | cut -c1-200 | sed 's/^/      /'
        else ok "no cron entry fetches and runs code or names the C2"; fi
    else inf "no readable crontabs (try as root, or check your user crontab)"; fi
    rm -f "$cronf" 2>/dev/null || true

    step "Campaign domains / IP in shell history, git config and logs"
    local -a files=()
    shopt -s nullglob
    for g in "$HOME"/.bash_history "$HOME"/.zsh_history /home/*/.bash_history /home/*/.zsh_history \
             "$HOME"/.gitconfig /home/*/.gitconfig /var/log/syslog /var/log/messages $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -gt 0 ]]; then
        local n; n="$( { grep -hEc "$GA_NET" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "C2 indicators: ${n}"; { grep -hE "$GA_NET" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-200 | sed 's/^/      /'
        else ok "no campaign domains or IP in shell history, git config or logs"; fi
    else inf "no readable history/config/logs to scan"; fi

    step "Stealer-style process running"
    if have ps; then
        local pn
        pn="$(ps -eo pid,comm,args 2>/dev/null | grep -E 'node .*\.(woff2|woff)|'"$GA_NET" | grep -v grep || true)"
        if [[ -n "$pn" ]]; then found=1; caution "suspicious process(es):"; echo "$pn" | sed 's/^/      /'
        else ok "no node-running-a-font or C2 process found"; fi
    fi

    echo
    echo "  If anything matched, treat your developer account as compromised. From a clean"
    echo "  device revoke GitHub tokens and authorized OAuth apps, rotate every credential"
    echo "  the repos and workflows could reach, and remove any cron job the stealer added."
    return "$found"
}

# ---------- quarantine (containment) -----------------------------------------
cmd_quarantine() {
    local f m bdir did=0
    scan_roots
    step "Containment: quarantining confirmed GhostAction artifacts"
    _save() {   # <path>
        local p="$1"
        bdir="${BACKUP_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)/$(dirname "$p" | sed 's#^/##; s#/#_#g')"
        mkdir -p "$bdir"
        if cp -p "$p" "${bdir}/$(basename "$p")" 2>/dev/null && rm -f "$p" 2>/dev/null; then
            ok "${p} -> quarantined to ${bdir}/$(basename "$p")"; did=$((did+1))
        else bad "${p}: could not quarantine (permission?)"; fi
    }
    # fake fonts (invalid magic)
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        m="$(magic4 "$f")"
        case "$f" in
            *.woff2) [[ "$m" == "774f4632" ]] || _save "$f" ;;
            *.woff)  [[ "$m" == "774f4646" ]] || _save "$f" ;;
        esac
    done < <(fscan \( -name '*.woff2' -o -name '*.woff' \) -type f -print)
    # tasks.json that runs a non-script on folderOpen or carries the C2
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        grep -q 'folderOpen' "$f" 2>/dev/null || continue
        if grep -qE "$GA_NET" "$f" 2>/dev/null || grep -qE '\.woff2|\.woff|node .*\.(woff2|png|wasm|dat|bin)' "$f" 2>/dev/null; then _save "$f"; fi
    done < <(fscan -path '*/.vscode/tasks.json' -type f -print)
    # workflows carrying the C2
    while read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        grep -qE "$GA_NET" "$f" 2>/dev/null && _save "$f"
    done < <(fscan -path '*/.github/workflows/*' \( -name '*.yml' -o -name '*.yaml' \) -type f -print)
    echo
    if [[ $did -gt 0 ]]; then info "quarantined ${did} file(s); forensic copies under ${BACKUP_ROOT}"
    else inf "nothing to quarantine (a folderOpen task that only runs a real script is left for you to review by hand)"; fi
    warn "CONTAINMENT ONLY. Removing files does not undo a stolen token. From a clean device revoke GitHub tokens and authorized OAuth apps, change your password, rotate every credential the repos and workflows could reach, and remove any cron job the stealer added."
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "GhostAction stage-2 (no CVE); context: ${REF}"
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
