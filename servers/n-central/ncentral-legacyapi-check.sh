#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# 4EverAble2Shell: Apache Axis unsafe reflection via the N-able N-central Legacy API (v1)
# CVE-2026-90436 (Apache Axis 1.x through 1.4, no fixed release; exploited, CISA KEV 18 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Apache Axis 1.x processes attacker-chosen objects while it parses a SOAP request, before any
# service checks a login. On-premises N-able N-central exposes Axis through its Legacy API
# (/dms/services/ServerUI); a public chain turns that into root on the server with no login.
# Huntress found crypto miners on 21 servers within hours; N-able reported attacks on 13
# November, and the same Axis flaw was used against Confluence Data Center the same day.
# N-central 2026.4 HF3 (2026.4.1.39, 16 November) removes the Legacy API; HF2 (2026.4.1.26)
# does not stop the chain. Axis itself has no fixed release: every 1.x through 1.4 is affected,
# and products that bundle it need their own vendor fix.
#
# Usage:
#   ./ncentral-legacyapi-check.sh [command] [arguments]
#
#   check [HOST...]   Read-only. With hosts: asks each N-central server for the
#                    Legacy API's description (GET /dms/services/ServerUI?wsdl)
#                    without logging in or sending a payload; an answer means
#                    the API is on and reachable from here. On this machine:
#                    finds Apache Axis 1.x (axis.jar, axis-1.*.jar, inside web
#                    applications and in running Java processes' class paths)
#                    under ROOTS. Exit 0 = nothing exposed, 1 = a Legacy API
#                    that answers or an Axis 1.x copy, 2 = a host or file
#                    could not be read.
#   hunt             Read-only. Looks on this machine for what the attacks
#                    left: an xvd.service unit, /tmp/.xvd and /var/tmp/.xvd,
#                    connections to or log lines naming 157.20.241.16, miner
#                    processes, cron entries that start them, and web log
#                    requests to /dms/services/ServerUI that carry the
#                    jline.internal.TerminalLineSettings gadget. Exit 0 =
#                    nothing found, 1 = leads, 2 = nothing could be read.
#   version          Prints the script version.
#
# There is nothing to change on the server short of the hotfix: install 2026.4 HF3, and until
# then turn LEGACY APIS off (Administration > Mail and Network Settings > Network Security).
# The README shows how to refuse /dms/services/ at a reverse proxy in front of it.
#
# Env overrides:
#   ROOTS="/opt /srv /var/lib /usr/share /usr/local /home"   where check looks for Axis
#   MAX_DEPTH=10
#   HTTP_PORT=443      port of each N-central server
#   CURL_TIMEOUT=10
#   HUNT_DAYS=60
#   HUNT_LOG_DIRS="/var/log /opt/nable /var/opt"   where hunt reads logs
#   IOC_IP=157.20.241.16
#   SCAN_CONTAINERS=1  0 skips running docker and podman containers in check
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="ncentral-legacyapi-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"
CVE="CVE-2026-90436"
ROOTS_GIVEN="${ROOTS:+1}"
ROOTS="${ROOTS:-/opt /srv /var/lib /usr/share /usr/local /home}"
MAX_DEPTH="${MAX_DEPTH:-10}"
HTTP_PORT="${HTTP_PORT:-443}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
HUNT_DAYS="${HUNT_DAYS:-60}"
HUNT_LOG_DIRS="${HUNT_LOG_DIRS:-/var/log /opt/nable /var/opt}"
IOC_IP="${IOC_IP:-157.20.241.16}"
IOC_FILES="${IOC_FILES:-/tmp/.xvd /var/tmp/.xvd}"
UNIT_DIRS="${UNIT_DIRS:-/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /run/systemd/system}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
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

# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
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
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
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
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}


N_EXP=0; N_UNK=0
probe_host() {
    local h="$1" code body
    if [[ -n "${HTTP_RESPONSE_DIR:-}" ]]; then   # testing only: "<status>\n<body>"
        code="$(head -n1 "$HTTP_RESPONSE_DIR/$h" 2>/dev/null)"; body="$(tail -n +2 "$HTTP_RESPONSE_DIR/$h" 2>/dev/null)"
    else
        have curl || die "curl is needed to ask a server for the Legacy API"
        # -k: on-premises N-central often has a self-signed certificate. A plain GET of the service
        # description; nothing is sent that Axis would deserialize.
        body="$(curl -sk --max-time "$CURL_TIMEOUT" -w '\n%{http_code}' "https://${h}:${HTTP_PORT}/dms/services/ServerUI?wsdl" 2>/dev/null)"
        code="${body##*$'\n'}"; body="${body%$'\n'*}"
    fi
    if [[ -z "$code" || "$code" == 000 ]]; then N_UNK=$((N_UNK + 1)); caution "${h}: no answer on port ${HTTP_PORT}"; return; fi
    if [[ "$code" == 200 ]] && grep -qiE 'wsdl:definitions|<definitions|ServerUI' <<<"$body"; then
        N_EXP=$((N_EXP + 1)); bad "${h}: the Legacy API answers (/dms/services/ServerUI, HTTP 200 with its service description): ${RED}exposed${NC} to the 4EverAble2Shell chain from here"
    else
        info "${h}: the Legacy API does not answer (HTTP ${code}): off, removed by HF3, or blocked on the way"
    fi
}

AXIS_PROBE="$(cat <<'EOS'
R="/opt /srv /var/lib /usr/share /usr/local /app"
find $R -maxdepth 10 -type f \( -iname 'axis.jar' -o -iname 'axis-1*.jar' \) 2>/dev/null | head -n 100 | while read -r f; do echo "E $f"; done
exit 0
EOS
)"
axis_version() {   # <jar> -> version from its manifest or file name
    local j="$1" v=""
    if have unzip; then v="$(unzip -p "$j" META-INF/MANIFEST.MF 2>/dev/null | tr -d '\r' | sed -nE 's/^(Implementation-Version|Specification-Version): *//p' | head -n1)"; fi
    [[ -n "$v" ]] || v="$(basename "$j" | sed -nE 's/^axis-([0-9][0-9A-Za-z.-]*)\.jar$/\1/p')"
    printf '%s' "${v:-1.x}"
}
cmd_check() {
    local h f n=0 _s
    if [[ $# -gt 0 ]]; then
        step "N-central servers"
        for h in "$@"; do
            [[ "$h" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Not a host name or address: ${h}"
            probe_host "$h"
        done
    fi
    step "Apache Axis 1.x on this machine"
    limited_view "application folders"
    if [[ -z "${ROOTS_GIVEN:-}" && "${SCAN_CONTAINERS:-1}" == 1 && -z "${PSF_IN_COPY:-}" ]]; then
        stage_probe "$AXIS_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            while IFS= read -r f; do n=$((n + 1)); N_EXP=$((N_EXP + 1)); bad "container ${_s##*/}: ${f#"$_s"}: Apache Axis 1.x (version not read inside containers)"; done \
                < <(find "$_s" -type f 2>/dev/null)
        done
    fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        n=$((n + 1)); N_EXP=$((N_EXP + 1))
        bad "${f}: Apache Axis $(axis_version "$f"). Every Axis 1.x through 1.4 is affected and there is no fixed release"
    done < <({ for r in $ROOTS; do [[ -d "$r" ]] && find "$r" -maxdepth "$MAX_DEPTH" -type f \( -iname 'axis.jar' -o -iname 'axis-1*.jar' \) 2>/dev/null; done
               [[ -n "${ROOTS_GIVEN:-}" ]] || ps -eo args= 2>/dev/null | grep -E '(^|/)java ' | grep -oE '[^ :]*axis(-1[^ :/]*)?\.jar' | while IFS= read -r f; do [[ -f "$f" ]] && echo "$f"; done
             } | awk '!seen[$0]++')
    [[ $n -gt 0 ]] || inf "no Apache Axis 1.x jar under ${ROOTS}"
    if [[ -d /opt/atlassian/confluence || -d /opt/atlassian/confluence-data ]]; then
        caution "Confluence is installed here: Atlassian's own advisory for ${CVE} says which Confluence Data Center releases are fixed. Read it and update"
    fi
    step "Verdict"
    if [[ $N_EXP -gt 0 ]]; then
        warn "${N_EXP} exposure(s) above (${CVE}, exploited). N-central: install 2026.4 HF3 (2026.4.1.39) now, and until then turn LEGACY APIS off and keep /dms/services/ off the internet; update Agents and Probes to HF3 and Patch Management Engine to 2.14.4.5829 or later. Other products that bundle Axis 1.x: apply the vendor's fix, or keep their SOAP endpoints away from untrusted networks. Then run 'hunt'."
        return 1
    fi
    if [[ $N_UNK -gt 0 ]]; then warn "${N_UNK} server(s) could not be asked (above)."; return 2; fi
    info "No exposed Legacy API and no Apache Axis 1.x found."
    return 0
}

cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments"
    limited_view "logs and processes"
    local leads=0 p u f line n
    step "Files and services the attacks left"
    for p in $IOC_FILES; do [[ -e "$p" ]] && { leads=$((leads + 1)); bad "${p} exists: the attackers' working folder"; }; done
    for u in $UNIT_DIRS; do [[ -e "$u/xvd.service" ]] && { leads=$((leads + 1)); bad "${u}/xvd.service: the service the attackers install"; }; done
    if have systemctl && systemctl list-units --all --no-legend 2>/dev/null | grep -q 'xvd\.service'; then leads=$((leads + 1)); bad "systemd knows a unit called xvd.service: systemctl status xvd.service"; fi
    while IFS= read -r line; do leads=$((leads + 1)); bad "cron: ${line:0:200}"; done < <(cat /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* 2>/dev/null | grep -E '\.xvd|xmrig|stratum\+tcp')
    [[ $leads -gt 0 ]] || inf "no xvd.service, .xvd folder or miner cron entry"

    step "Processes and connections"
    n=0
    while IFS= read -r line; do n=$((n + 1)); leads=$((leads + 1)); bad "process: ${line:0:200}"; done < <(ps -eo pid=,user=,pcpu=,args= 2>/dev/null | grep -E '\.xvd|xmrig|stratum\+tcp|--donate-level' | grep -v grep)
    if have ss; then
        while IFS= read -r line; do n=$((n + 1)); leads=$((leads + 1)); bad "connection to ${IOC_IP}: ${line:0:200}"; done < <(ss -tunp 2>/dev/null | grep -F "$IOC_IP")
    fi
    [[ $n -gt 0 ]] || inf "no miner process and no connection to ${IOC_IP}"

    step "Logs of the last ${HUNT_DAYS} days"
    n=0
    while IFS= read -r line; do n=$((n + 1)); leads=$((leads + 1)); [[ $n -le 40 ]] && bad "${line:0:240}"; done < <(
        for d in $HUNT_LOG_DIRS; do [[ -d "$d" ]] && find "$d" -maxdepth 5 -type f -mtime "-${HUNT_DAYS}" -size -200M 2>/dev/null; done | while IFS= read -r f; do
            zcat -f "$f" 2>/dev/null | grep -aE "TerminalLineSettings|${IOC_IP//./\\.}" | sed "s#^#${f}: #"
        done)
    [[ $n -gt 0 ]] || inf "no log line names the jline gadget or ${IOC_IP}"

    step "Verdict"
    if [[ $leads -gt 0 ]]; then
        warn "${leads} lead(s). Treat this server as fully owned (root): isolate it, keep the evidence, rebuild it, and because an RMM server reaches every managed client, rotate the secrets in Automation Manager policies, enforce MFA on N-central accounts and review activity since 11 November for new accounts, scripts, scheduled tasks and remote sessions."
        return 1
    fi
    info "No indicator found."
    return 0
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE} (Apache Axis 1.x, no fixed release) through the N-central Legacy API; N-central 2026.4 HF3 removes the API"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
