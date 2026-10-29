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
#   .vscode/tasks.json  a task (seen labelled "eslint-check") with
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
# There is no CVE and no patch. This script is a detector: it scans your
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
#   quarantine       CONTAINMENT, not a fix: back up (for forensics) and remove
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
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"
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
main "$@"; exit

# Assisted-by: Claude Opus 5.5
# Assisted-by: Claude Sonnet 5.5
