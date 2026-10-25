#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Plex Media Server "Plex2Shell" RCE chain: check and hunt  (v1)
# CVE-2026-96651 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# "Plex2Shell" chains flaws in Plex Media Server into unauthenticated remote
# code execution: an SSRF on /player/timeline (CVE-2026-96652), an admin-token
# theft via searchOne (CVE-2026-96654), a second SSRF on the transcode path
# (CVE-2026-96655), and a file write into the Codecs directory that drops and
# runs an ELF shared object (CVE-2026-96656); CVE-2026-96651 was fixed in the
# same release. Plex fixed all of them in Plex Media Server 1.43.3.10861 (3
# August 2026). A public proof-of-concept landed on 16 October 2026 and
# exploitation began the next day: attackers drop an XMRig miner (seen as
# "mylovelyminer", fetched as "x12345") and a reverse-proxy backdoor
# ("myawesomeproxy"), with mining and proxy traffic to proxystream[.]st.
#
# The fix is to upgrade to 1.43.3.10861 or later (including NAS, Docker and VM
# installs) and restart, which this script does not do for you. It is
# read-only: it reports the Plex version on the host and in containers and
# judges it, and hunts for the known compromise indicators. Successful
# exploitation runs code as the Plex service account, so if this host was
# exposed and unpatched, treat it as compromised: rebuild from a clean install,
# rotate the Plex account credentials and server token, and (interim) remove
# any router port-forwarding to Plex until it is updated. Attackers rotate file
# names, domains and ports, so a clean hunt is not proof; the version is.
#
# Usage:
#   ./plex2shell-oct2026-check.sh [command]
#
#   check (default)  the Plex Media Server version on the host and in running
#                    containers, judged against 1.43.3.10861. Read-only, root
#                    optional. Exit 0 = fixed/none, 1 = a vulnerable Plex is
#                    present, 2 = a version couldn't be read.
#   hunt             read-only: Plex data directories, /tmp and logs for the
#                    known indicators (the miner and proxy file names, the
#                    Codecs-directory payload, the proxyware banner, the mining
#                    domain and attacker IPs) and for the miner/proxy running.
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   PLEX_FIXED=1.43.3.10861           first fixed Plex Media Server build
#   PLEX_DATA_PATHS="/var/lib/plexmediaserver ..."
#                                     where to look for Plex data directories
#   SCAN_CONTAINERS=1                 1 = read the Plex version inside containers
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES="CVE-2026-96651 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656"
PLEX_FIXED="${PLEX_FIXED:-1.43.3.10861}"
PLEX_DATA_PATHS="${PLEX_DATA_PATHS:-/var/lib/plexmediaserver /config /opt /srv /home /root}"
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
SCAN_DEPTH="${SCAN_DEPTH:-7}"
HUNT_LOGS="${HUNT_LOGS:-}"
# Known indicators (attackers rotate these; see the caveat hunt prints).
IOC_NAMES='x12345|mylovelyminer|myawesomeproxy'
IOC_NET='proxystream\.st|217\.60\.194\.116|91\.92\.40\.202|176\.65\.139\.228|45\.194\.92\.222'
IOC_BANNER='agree to the potential external use of your internet traffic'
SCRIPT_NAME="plex2shell-oct2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-24"
SELF="$0"
REF="https://github.com/code-zm/plex2shell/"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
have() { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# Plex versions look like 1.43.3.10861-xxxxxxxxx; compare the numeric part.
plex_num() { local v="${1%%-*}"; grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<<"$v" || grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$v" || true; }
plex_state() {   # <version> -> rc|why
    local v; v="$(plex_num "$1")"
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if ver_ge "$v" "$PLEX_FIXED"; then echo "0|${v} >= ${PLEX_FIXED}"
    else echo "1|${v} < ${PLEX_FIXED} (Plex2Shell is fixed in ${PLEX_FIXED})"; fi
}

# ---------- host version -----------------------------------------------------
host_plex_version() {
    if have dpkg-query; then dpkg-query -W -f='${Version}' plexmediaserver 2>/dev/null && return 0; fi
    # Non-dpkg installs: look for a version string in the server resources.
    local f
    for f in /usr/lib/plexmediaserver/*.txt /usr/lib/plexmediaserver/VERSION; do
        [[ -f "$f" ]] && { grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -1 && return 0; }
    done
    return 0
}
plex_installed() { have dpkg-query && dpkg-query -W plexmediaserver >/dev/null 2>&1 && return 0; [[ -e "/usr/lib/plexmediaserver/Plex Media Server" ]]; }

# ---------- data directories -------------------------------------------------
plex_data_dirs() {
    # shellcheck disable=SC2086
    find $PLEX_DATA_PATHS -maxdepth "$SCAN_DEPTH" -type d -name "Plex Media Server" 2>/dev/null \
        | while read -r d; do [[ -d "$d/Codecs" || -d "$d/Logs" ]] && echo "$d"; done | sort -u
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 v st how
    step "Plex Media Server on the host"
    if plex_installed; then
        v="$(host_plex_version)"
        IFS='|' read -r st how <<<"$(plex_state "$v")"
        case $st in
            0) ok "Plex Media Server ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "Plex Media Server ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "Plex Media Server found but version unreadable; confirm it reports ${PLEX_FIXED} or later"; unknownz=1 ;;
        esac
    else inf "no Plex Media Server install found on the host"; fi

    step "Plex Media Server inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt id name cv any_c=0
        for rt in docker podman; do
            have "$rt" || continue
            while read -r id name; do
                [[ -n "$id" ]] || continue
                cv="$("$rt" exec "$id" sh -c 'dpkg-query -W -f="${Version}" plexmediaserver 2>/dev/null || cat /usr/lib/plexmediaserver/*.txt 2>/dev/null' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
                [[ -n "$cv" ]] || continue
                any_c=1
                IFS='|' read -r st how <<<"$(plex_state "$cv")"
                case $st in
                    0) ok "${rt} ${name:-$id}: Plex ${cv}  $(state_word 0)  (${how})" ;;
                    1) bad "${rt} ${name:-$id}: Plex ${cv}  $(state_word 1)  (${how}); pull a fixed image and recreate the container"; exposed=1 ;;
                    *) caution "${rt} ${name:-$id}: Plex version unreadable"; unknownz=1 ;;
                esac
            done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
        done
        [[ $any_c -eq 1 ]] || inf "no running container reports a Plex version (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable Plex Media Server found where this could read a version" ;;
        1) warn "A vulnerable Plex Media Server is present and Plex2Shell is exploited in the wild. Upgrade to ${PLEX_FIXED} or later (NAS, Docker and VM installs too) and restart. Until then, remove any router port-forwarding to Plex so it is not reachable from the internet. Then run 'hunt'. Advisory/PoC context: ${REF}" ;;
        *) warn "A Plex version couldn't be read. Confirm the running build is ${PLEX_FIXED} or later, especially on Docker and NAS" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0
    step "Known payload file names in Plex data, /tmp and scratch dirs"
    local -a roots=(/tmp /var/tmp /dev/shm)
    local d
    while read -r d; do [[ -n "$d" ]] && roots+=("$d"); done < <(plex_data_dirs)
    local f
    for d in "${roots[@]}"; do
        [[ -d "$d" ]] || continue
        while read -r f; do
            [[ -n "$f" ]] || continue
            found=1; bad "payload-named file: ${f}"
        done < <(find "$d" -maxdepth "$SCAN_DEPTH" -type f 2>/dev/null | grep -E "/($IOC_NAMES)(\.|$|[^/]*)" || true)
    done
    [[ $found -eq 1 ]] || ok "no files named like the known miner/proxy payloads"

    step "Recently changed files in the Codecs directory"
    # CVE-2026-96656 writes the payload here. Plex's own codecs are ELF shared
    # objects too, so this does not flag them as malware; it lists what changed
    # recently for you to review.
    local cx=0 since="${CODECS_SINCE_DAYS:-30}"
    while read -r d; do
        [[ -n "$d" && -d "$d/Codecs" ]] || continue
        while read -r f; do
            [[ -n "$f" ]] || continue
            cx=1; caution "changed in the last ${since} days: ${f}"
        done < <(find "$d/Codecs" -maxdepth 4 -type f -mtime "-${since}" 2>/dev/null || true)
    done < <(plex_data_dirs)
    [[ $cx -eq 1 ]] || ok "no files changed in the Codecs directories in the last ${since} days"
    inf "a payload-named file above, or an unexpected shared object here, is the concern; CVE-2026-96656 writes to Codecs"

    step "Proxyware banner and mining domain in files"
    local bn=0
    for d in "${roots[@]}"; do
        [[ -d "$d" ]] || continue
        while read -r f; do [[ -n "$f" ]] && { found=1; bn=1; bad "proxyware/mining indicator in: ${f}"; }; done \
            < <(grep -rlaE "$IOC_BANNER|$IOC_NET" "$d" 2>/dev/null | head -20 || true)
    done
    [[ $bn -eq 1 ]] || ok "no proxyware banner or proxystream.st indicator in the scanned files"

    step "Miner or proxy process running"
    if have ps; then
        local pn
        pn="$(ps -eo pid,comm,args 2>/dev/null | grep -E "$IOC_NAMES|xmrig" | grep -v grep || true)"
        if [[ -n "$pn" ]]; then found=1; caution "suspicious process(es):"; echo "$pn" | sed 's/^/      /'
        else ok "no miner/proxy process by the known names is running"; fi
    fi

    step "Attacker IPs and mining domain in logs"
    local -a files=(); local g
    shopt -s nullglob
    while read -r d; do [[ -d "$d/Logs" ]] && for f in "$d"/Logs/*.log; do [[ -r "$f" ]] && files+=("$f"); done; done < <(plex_data_dirs)
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/messages /var/log/nginx/*.log /var/log/apache2/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then inf "no readable logs to scan"
    else
        local n; n="$( { grep -hEc "$IOC_NET" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "attacker IP / mining-domain hits in logs: ${n}"; { grep -hE "$IOC_NET" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-200 | sed 's/^/      /'
        else ok "no attacker IPs or mining domain in the scanned logs"; fi
    fi

    echo
    echo "  Attackers rotate file names, domains and ports, so a clean hunt is not proof of"
    echo "  safety; the Plex version is. If anything matched, or this host was exposed and"
    echo "  unpatched, treat it as compromised: rebuild from a clean install, rotate the Plex"
    echo "  account credentials and server token, and remove port-forwarding until updated."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "Plex2Shell: ${CVES}; context: ${REF}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
