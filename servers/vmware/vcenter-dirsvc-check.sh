#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# VMware vCenter directory service authentication bypass, November 2026 (v1)
# CVE-2026-123890 (CVSS 3.1 9.8, VMSA-2026-0009, exploited, CISA KEV 20 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Anyone who can reach vCenter's directory service (the single sign-on port 2012) can get an
# administrator session without a password. ARMORY CASTLE (formerly UNC5221) used it from
# early September with a tool Mandiant calls BONESAW: it created an SSO administrator account
# and copied the directory database, which holds the key that signs login tokens, so the
# attackers could forge a login for any user ("golden SAML"). Broadcom fixed it on 19 November:
# vCenter 9.1.1.0200 (build 25901347), 9.0.2.0200 (build 25901331) and 8.0 Update 3m
# (8.0.3.01200, build 25934264); VCF 5.x through 5.2.5. There is no workaround and no public
# fix for 7.0 (extended-support customers ask Broadcom); 6.5 and 6.7 are presumed affected.
#
# vCenter is an appliance on Photon OS. This tool runs from any GNU/Linux machine, asking each
# vCenter for its version over its web API the way the vSphere client does, without logging
# in; or on the appliance itself from its root shell.
#
# Usage:
#   ./vcenter-dirsvc-check.sh [command] [arguments]
#
#   check [HOST...]   Read-only. With hosts: asks each vCenter for its version
#                    and build (an unauthenticated RetrieveServiceContent call
#                    to https://HOST/sdk, the call every vSphere client makes
#                    first) and judges it; says whether this machine can reach
#                    the host's port 2012. Without hosts, on a vCenter
#                    appliance: judges the local build (vpxd -v). Exit 0 = all
#                    fixed, 1 = affected, 2 = a version could not be read.
#   hunt             Read-only. On any GNU/Linux machine: the files Mandiant
#                    found on the GNU/Linux machines the attackers used to reach
#                    vCenter (/tmp/123, /tmp/sss, /tmp/dbr, /usr/bin/vmtoolscs).
#                    On a vCenter appliance also: single sign-on log entries
#                    of the last HUNT_DAYS days that create users or add them
#                    to groups, for a look by hand. Exit 0 = nothing found,
#                    1 = leads, 2 = nothing could be read.
#   mitigate [--dry-run]   (root, on the appliance) Lets only the addresses in
#                    ALLOW_FROM reach the directory service port 2012 (and
#                    PORTS, if you add 443), with an iptables chain of its own,
#                    as Mandiant recommends. Keeps loopback and connections
#                    already open. Not a fix, and not supported by Broadcom:
#                    it narrows who can attack until you patch. The appliance
#                    rebuilds its firewall at boot, so run it again after a
#                    reboot. Include every other vCenter in the same SSO domain
#                    (Enhanced Linked Mode) in ALLOW_FROM.
#   rollback [--dry-run]   Removes that chain.
#   version          Prints the script version.
#
# Env overrides:
#   ALLOW_FROM="10.0.0.5 10.0.1.0/24"  who may reach the ports (mitigate)
#   PORTS="2012"       ports mitigate restricts (Mandiant: 443 too stops forged logins being used)
#   VPXD_V_OUTPUT      text that stands in for "vpxd -v" (testing only)
#   SDK_PORT=443       port of the vCenter web API
#   CURL_TIMEOUT=10    seconds per host
#   HUNT_DAYS=60       how far back hunt reads the SSO logs
#   SSO_LOG_DIR=/var/log/vmware/sso
#   IOC_PATHS="/tmp/123 /tmp/sss /tmp/dbr /usr/bin/vmtoolscs"
#   PSF_LOCK_WAIT      seconds a run that changes the host waits for another (default 30)
#   STATE_DIR          (default /var/lib/psf-security-patches/vcenter-dirsvc)
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="vcenter-dirsvc-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"
CVE="CVE-2026-123890"
# Fixed builds per release line (Broadcom VMSA-2026-0009, build numbers from KB 326316)
FIX_91=25901347; FIX_90=25901331; FIX_80=25934264
ALLOW_FROM="${ALLOW_FROM:-}"
PORTS="${PORTS:-2012}"
SDK_PORT="${SDK_PORT:-443}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
HUNT_DAYS="${HUNT_DAYS:-60}"
SSO_LOG_DIR="${SSO_LOG_DIR:-/var/log/vmware/sso}"
IOC_PATHS="${IOC_PATHS:-/tmp/123 /tmp/sss /tmp/dbr /usr/bin/vmtoolscs}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/vcenter-dirsvc}"
CHAIN="PSF_VCENTER_DIRSVC"

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
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how=", or add --dry-run to see what it would do" msg
    if is_root; then root_note; return 0; fi
    if have sudo; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    have sudo && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
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

# judge VERSION BUILD -> "<rc>|<text>": 0 fixed, 1 affected, 2 unknown
judge() {
    local v="$1" b="$2" line fix
    [[ "$b" =~ ^[0-9]+$ ]] || { echo "2|build '${b:-?}' could not be read"; return; }
    line="$(printf '%s' "$v" | cut -d. -f1,2)"
    case "$line" in
        9.1) fix=$FIX_91 ;;
        9.0) fix=$FIX_90 ;;
        8.0) fix=$FIX_80 ;;
        7.0) echo "1|7.0 is affected and has no public fix (extended-support customers ask Broadcom)"; return ;;
        6.*|5.*) echo "1|${line} is past end of support and presumed affected: no fix will come"; return ;;
        9.*) [[ "${line#9.}" -gt 1 ]] 2>/dev/null && { echo "0|${line} is newer than the fixed lines"; return; }
             echo "2|${line} is not a line Broadcom's advisory lists"; return ;;
        *) echo "2|version '${v:-?}' is not one this script knows"; return ;;
    esac
    if [[ "$b" -ge "$fix" ]]; then echo "0|build ${b} is at or after the fix (${fix})"
    else echo "1|build ${b} is before the fix (${line}: build ${fix})"; fi
}

N_AFF=0; N_UNK=0; N_FIX=0
report() {   # <where> <version> <build>
    local rc why; IFS='|' read -r rc why <<<"$(judge "$2" "$3")"
    case "$rc" in
        0) N_FIX=$((N_FIX + 1)); info "${1}: vCenter ${2} build ${3}: fixed (${why})" ;;
        1) N_AFF=$((N_AFF + 1)); bad "${1}: vCenter ${2} build ${3}: ${RED}affected${NC} (${why})" ;;
        *) N_UNK=$((N_UNK + 1)); caution "${1}: ${why}" ;;
    esac
}

# The SOAP call every vSphere client makes before logging in; it returns the product, version and build.
SOAP='<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body><urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'
xml_field() { sed -n "s:.*<$1>\([^<]*\)</$1>.*:\1:p" | head -n1; }
probe_host() {
    local h="$1" out name v b api
    if [[ -n "${SDK_RESPONSE_DIR:-}" ]]; then out="$(cat "$SDK_RESPONSE_DIR/$h" 2>/dev/null)"   # testing only
    else
        have curl || die "curl is needed to ask a vCenter for its version"
        # -k: vCenter ships a self-signed certificate. Nothing secret is sent; only the reply's version is read.
        out="$(curl -sk --max-time "$CURL_TIMEOUT" -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: "urn:vim25/8.0"' \
               --data "$SOAP" "https://${h}:${SDK_PORT}/sdk" 2>/dev/null)"
    fi
    out="$(printf '%s' "$out" | tr -d '\r\n')"
    api="$(printf '%s' "$out" | xml_field apiType)"; name="$(printf '%s' "$out" | xml_field fullName)"
    v="$(printf '%s' "$out" | xml_field version)"; b="$(printf '%s' "$out" | xml_field build)"
    if [[ -z "$out" ]]; then N_UNK=$((N_UNK + 1)); caution "${h}: no answer from https://${h}:${SDK_PORT}/sdk"; return; fi
    if [[ "$api" == HostAgent ]]; then inf "${h}: ${name:-an ESXi host}: ESXi is not affected by this flaw"; return; fi
    if [[ "$api" != VirtualCenter ]]; then N_UNK=$((N_UNK + 1)); caution "${h}: answered, but not as a vCenter (${name:-no product name})"; return; fi
    report "$h" "$v" "$b"
    if [[ -z "${SDK_RESPONSE_DIR:-}" ]] && timeout 3 bash -c "exec 3<>/dev/tcp/${h}/2012" 2>/dev/null; then
        caution "${h}: this machine can reach its directory service port 2012. Anything on this machine, or on this network segment, could attack it"
    fi
}

is_appliance() { [[ -n "${VPXD_V_OUTPUT:-}" || -x /usr/sbin/vpxd || -f /etc/vmware/deployment.node.type ]]; }
local_build() {   # -> "version build"
    local out
    if [[ -n "${VPXD_V_OUTPUT:-}" ]]; then out="$VPXD_V_OUTPUT"; else out="$(/usr/sbin/vpxd -v 2>/dev/null)"; fi
    printf '%s' "$out" | sed -nE 's/.*VirtualCenter ([0-9.]+) build-([0-9]+).*/\1 \2/p' | head -n1
}

cmd_check() {
    local h v b
    if [[ $# -gt 0 ]]; then
        step "vCenter servers"
        for h in "$@"; do
            [[ "$h" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Not a host name or address: ${h}"
            probe_host "$h"
        done
    elif is_appliance; then
        step "This vCenter appliance"
        read -r v b <<<"$(local_build)"
        report "this appliance" "${v:-?}" "${b:-?}"
    else
        die "not a vCenter appliance: name the vCenter servers to check, for example: ${SELF} check vcenter.example.com"
    fi
    step "Verdict"
    if [[ $N_AFF -gt 0 ]]; then
        warn "${N_AFF} affected vCenter(s) (${CVE}, exploited). Patch now: 9.1.1.0200, 9.0.2.0200 or 8.0 Update 3m (VCF 5.x: 5.2.5); there is no workaround. Until then, let only trusted hosts reach ports 2012 and 443 ('mitigate' on the appliance, or your network firewall), and run 'hunt': a patch does not remove an attacker who is already in."
        warn "Before upgrading to VCF 9.1.1: Broadcom says 8.0 U3m and 9.0.2.0200 block that upgrade until 9.1.2."
        return 1
    fi
    if [[ $N_UNK -gt 0 ]]; then warn "${N_UNK} vCenter(s) could not be judged (above)."; return 2; fi
    info "Every vCenter checked is fixed."
    return 0
}

cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments"
    limited_view "files and logs"
    local p leads=0 read=0 f line
    step "Files Mandiant found on the machines used to reach vCenter"
    for p in $IOC_PATHS; do
        if [[ -e "$p" ]]; then leads=$((leads + 1)); bad "${p} exists ($(stat -c '%s bytes, modified %y' "$p" 2>/dev/null | cut -d. -f1)): keep a copy for investigators and treat this machine as compromised"; fi
    done
    [[ $leads -gt 0 ]] || inf "none of ${IOC_PATHS}"
    read=1
    if is_appliance || [[ -d "$SSO_LOG_DIR" ]]; then
        step "SSO users created or added to groups (last ${HUNT_DAYS} days)"
        local n=0
        if [[ -d "$SSO_LOG_DIR" ]]; then
            while IFS= read -r line; do
                n=$((n + 1)); [[ $n -le 40 ]] && caution "${line:0:240}"
            done < <(find "$SSO_LOG_DIR" -type f -mtime "-${HUNT_DAYS}" 2>/dev/null | while IFS= read -r f; do
                        zcat -f "$f" 2>/dev/null | grep -aiE 'createLocal(Person|Solution)User|addUsersToGroup|addUserToGroup|addSubjectsToGroup|createLocalGroup' | sed "s#^#${f##*/}: #"
                     done)
            [[ $n -gt 0 ]] || inf "no user or group change in ${SSO_LOG_DIR}"
            [[ $n -eq 0 ]] || inf "check each one against your own changes. An administrator you did not create is a break-in: the attackers also took the token-signing key, so also replace the STS signing certificate"
        else inf "${SSO_LOG_DIR} not found"; fi
    fi
    step "Verdict"
    if [[ $leads -gt 0 ]]; then warn "${leads} indicator(s) found: treat this machine as compromised and look at every vCenter it could reach."; return 1; fi
    [[ $read -eq 1 ]] || return 2
    info "No indicator found on this machine. Run hunt on the other GNU/Linux machines that can reach vCenter, too."
    return 0
}

cmd_mitigate() {
    local dry=0 a ip p
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (mitigate [--dry-run])" ;; esac; done
    is_appliance || die "mitigate runs on the vCenter appliance itself (its root shell). Elsewhere, restrict ports ${PORTS} in your network firewall"
    [[ -n "$ALLOW_FROM" ]] || die "set ALLOW_FROM to the addresses that may reach ports ${PORTS} (your admin hosts, and every other vCenter in the same SSO domain)"
    for ip in $ALLOW_FROM; do [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || die "Not an IPv4 address or network: ${ip}"; done
    for p in $PORTS; do [[ "$p" =~ ^[0-9]+$ ]] || die "Not a port: ${p}"; done
    [[ $dry -eq 1 ]] || need_root "mitigate changes the firewall"
    local ports; ports="$(echo $PORTS | tr ' ' ',')"
    local rules=("-N ${CHAIN}" "-A ${CHAIN} -i lo -j RETURN" "-A ${CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
    for ip in $ALLOW_FROM; do rules+=("-A ${CHAIN} -s ${ip} -j RETURN"); done
    rules+=("-A ${CHAIN} -j DROP" "-I INPUT 1 -p tcp -m multiport --dports ${ports} -j ${CHAIN}")
    step "Rules"
    for r in "${rules[@]}"; do echo "  iptables $r"; done
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was changed."; return 0; fi
    have iptables || die "iptables not found"
    if iptables -n -L "$CHAIN" >/dev/null 2>&1; then die "the ${CHAIN} chain is already in place: run rollback first to change it"; fi
    local r
    for r in "${rules[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables $r; then bad "iptables ${r} failed: removing what was added"; cmd_rollback >/dev/null 2>&1; return 1; fi
    done
    mkdir -p "$STATE_DIR" && printf '%s\n' "$ALLOW_FROM" > "$STATE_DIR/allow_from"
    info "Only ${ALLOW_FROM} (and this appliance itself) can now open new connections to ports ${ports}."
    warn "Not persistent: the appliance rebuilds its firewall at boot, so run this again after a reboot. This narrows the attack; only the patch fixes it."
    return 0
}

cmd_rollback() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (rollback [--dry-run])" ;; esac; done
    if [[ $dry -eq 1 ]]; then echo "  would remove the INPUT jump to ${CHAIN}, then the chain"; return 0; fi
    need_root "rollback changes the firewall"
    have iptables || die "iptables not found"
    local ports; ports="$(echo $PORTS | tr ' ' ',')"
    while iptables -D INPUT -p tcp -m multiport --dports "$ports" -j "$CHAIN" 2>/dev/null; do :; done
    iptables -F "$CHAIN" 2>/dev/null; iptables -X "$CHAIN" 2>/dev/null
    if iptables -n -L "$CHAIN" >/dev/null 2>&1; then bad "the ${CHAIN} chain could not be removed (another rule still jumps to it?)"; return 1; fi
    info "Removed: ports ${ports} are open to whoever the appliance's own firewall allows."
    return 0
}
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
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}: vCenter directory service authentication bypass; fixed in 9.1.1.0200, 9.0.2.0200 and 8.0 U3m"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
