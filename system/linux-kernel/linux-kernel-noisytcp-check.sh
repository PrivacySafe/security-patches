#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# NoisyTCP: Linux kernel TCP pre-auth remote crash, and its sibling ordering flaw  (v1)
# CVE-2026-99288 (NoisyTCP) and CVE-2026-99676
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# NoisyTCP (CVE-2026-99288). TCP's established-socket lookup is lockless, and the memory of a
# socket it found can be freed and reused for a new socket with the same addresses and ports
# before the lookup takes its reference. The lookup then returned an unhashed request socket that
# a SYN cookie had just rebuilt, with no listener attached, and the receive path dereferenced the
# missing listener: a kernel panic. Anyone who can send TCP packets to a listening port can do it,
# with no account: Nginx, Apache and SSH in their default setup were crashed on virtual machines
# in 5 seconds to 2 minutes, and a quiet physical server with 8 receive queues in about 14 hours.
# A crash takes down the whole host, containers included. It needs packets for the same
# connection handled at the same time on different CPUs: two or more receive queues on the
# interface the attacker's packets arrive on, or RPS spreading them across CPUs. The researcher
# describes a second, much harder path to a use after free; the kernel maintainers disputed it,
# and Red Hat states the flaw does not allow data alteration or code execution. Ratings: CVE
# record 7.5 (kernel CVE team), Red Hat Important, Ubuntu High, CVSS 3.1 5.9 from CISA in the CVE
# record. The researcher's own exploit is not public; an exploit tracker lists third-party proof
# of concept code. No attacks were reported and it is not on CISA's KEV list (as of 24 November).
#
#   Affected: every kernel from 4.4 (commit 079096f103fa, October 2015) up to the fixed releases.
#   First fixed stable release of each branch (mainline: 4e2b3ef19e0e, in 7.4-rc2):
#     5.10.275   5.15.226   6.1.193   6.6.163   6.12.117   6.18.63   7.3.4
#   Every other branch from 4.4 on has no upstream fix (6.19 to 7.2 included: 7.2 reached its end
#   at 7.2.15, before the fix). Vendors that maintain such a branch backport it.
#   Distributions, as their trackers and advisories said on 24 November:
#     Debian 12: 6.1.192-1 (DLA-4906-1; Debian carried it before upstream 6.1.193), and
#       linux-6.12 6.12.117-1~deb12u1; Debian 13: 6.12.117-1 (DSA-6628-1)
#     RHEL 8.8: 4.18.0-477.181.1.el8_8 (RHSA-2026:102709, 24 November)
#     RHEL 8.10: 4.18.0-553.189.1.el8_10 (RHSA-2026:102218; kernel-rt RHSA-2026:102219)
#     RHEL 9.9: 5.14.0-741.26.1.el9_9 (RHSA-2026:102167)
#     RHEL 10.3: 6.12.0-264.19.1.el10_3 (RHSA-2026:102168)
#     Other RHEL update streams (9.8, 10.2 and so on) had no fixed kernel listed (Red Hat's list of 25 November).
#     Ubuntu: every release from 16.04 to 26.10 still vulnerable; fixes in progress for the main
#       linux package (24.04 in 6.8.0-152.152, 22.04 in 5.15.0-205.215, 26.04 in 7.0.0-45.45,
#       26.10 in 7.3.0-12.13, 20.04 in 5.4.0-248.268, 18.04 in 4.15.0-264.276, 16.04 in
#       4.4.0-294.328); its other kernels (cloud, HWE, Raspberry Pi and more) with none yet.
#
# The sibling (CVE-2026-99676). The same patch series restores the memory ordering of those
# lockless lookups, which a 2019 change (fb041bb7c0a9, in 5.5, and a backport of it in 5.4.208)
# removed on weakly ordered processors. x86 keeps that ordering in hardware, so on x86 it is not
# reachable; on Arm, POWER, RISC-V and other weakly ordered processors a kernel fixed for NoisyTCP
# may still not be fixed for this. A review bot asked for both patches to be backported together
# for that reason; no maintainer has confirmed that the crash is still reachable without it.
#   First fixed: 6.12.118   6.18.64   7.3.5 (mainline 5b5d8f351dd9, in 7.4-rc2). The 5.4 (from
#   5.4.208), 5.10, 5.15, 6.1 and 6.6 branches have no upstream fix. Debian 13: 6.12.118-1
#   (DSA-6652-1). NVD scores it 9.8; that score does not reflect that it needs a weakly ordered
#   processor.
#
# Why this script reads the kernel's origin first. The upstream patch level is in the release
# string only on kernels that follow the stable series (vanilla, Arch, Alpine, most custom
# builds). Debian puts it in `uname -v`. For RHEL itself the fixed builds above are compared
# directly. Ubuntu, the RHEL rebuilds, SUSE and Amazon Linux backport fixes under release strings
# that do not say which fixes they carry: for those the vendor changelog is the evidence, and the
# script points to the vendor's page when it does not name the CVE. A stable release candidate
# (-rc) is judged as the release before it.
#
# What the exposure lines mean. They report SYN cookies (net.ipv4.tcp_syncookies), the receive
# queues of each interface and whether RPS or RFS spreads packets across CPUs, the TCP listeners
# that are not on loopback, the processor architecture, and the other network namespaces. That is
# information for you to weigh, not a verdict: a kernel below its fixed release is affected
# whatever these show. Which interface faces the attacker, and which CPUs its queues are bound
# to, this script cannot know.
#
# A container shows the host's kernel, so run this on the host.
#
# Usage:
#   ./linux-kernel-noisytcp-check.sh [check]
#   check (default)  Exit 0 = the running kernel has the fix for NoisyTCP (and the sibling where
#                    it applies), 1 = affected, or a fix could not be confirmed. Read-only.
#   hunt             Read the kernel logs for the crash: a NULL pointer dereference or panic
#                    whose trace runs through tcp_v4_rcv, tcp_v6_rcv, the established lookups or
#                    the SYN cookie code. It reads dmesg, the journal's kernel messages, the
#                    rotated logs under /var/log, and notes crash dumps in /var/crash and
#                    /sys/fs/pstore. A hit is a lead, not proof of an attack. A clean result is
#                    not clearance: a crashed host reboots and loses its ring buffer. Exit 0 =
#                    nothing in the logs that were read, 1 = hits, 2 = no log could be read.
#   mitigate [--syncookies] [--single-queue IFACE[,IFACE]] [--force] [--dry-run]   (root)
#                    changes the host. Stopgaps, not a fix; they only act when check finds the
#                    kernel affected (--force overrides). Choose what to apply:
#                      --syncookies    net.ipv4.tcp_syncookies=0, applied now and written to a
#                                      sysctl.d file. It closes the SYN cookie path the crash
#                                      uses and weakens protection against SYN floods. It is
#                                      per network namespace: each container with its own
#                                      namespace needs it too, and this says how.
#                      --single-queue IFACE   for the named interfaces (the ones that face the
#                                      attacker): one receive queue (ethtool), RPS and RFS
#                                      off. Lowers network throughput, may reset the link for a
#                                      moment (an SSH session over it can drop), and is not
#                                      kept across reboots or a driver reset.
#                    --dry-run shows everything and changes nothing. Previous values are saved so
#                    that rollback can put them back.
#   rollback [--dry-run]   restore the saved values and remove the file mitigate wrote.
#   version          print the script version.
#
# Env: KERNEL_CHANGELOG   a vendor changelog file to read, plain or .gz
#      STATE_DIR (default /var/lib/psf-security-patches/linux-kernel-noisytcp), SYSCTL_D
#      (default /etc/sysctl.d) for mitigate and rollback
#      KERNEL_RELEASE, KERNEL_VERSION_STRING, KERNEL_ARCH   override uname -r, -v and -m
#      KERNEL_PROC_SYS, KERNEL_SYS_NET   override /proc/sys and /sys/class/net
#      KERNEL_LOG_FILES   kernel log files for hunt, instead of dmesg, journalctl -k and the
#                         usual /var/log files; KERNEL_CRASH_DIRS instead of /var/crash and
#                         /sys/fs/pstore
#      KERNEL_INSTALLED_RELEASES   the kernel releases installed, instead of /lib/modules/*
#      OS_RELEASE_FILE   instead of /etc/os-release
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30); the lock is STATE_DIR/.lock
# =============================================================================

set -uo pipefail

SCRIPT_NAME="linux-kernel-noisytcp-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/linux-kernel-noisytcp}"
CVE="CVE-2026-99288"
SIB_CVE="CVE-2026-99676"

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
        local type="$1" level="$2" msg="$3" ts cves="" rest extra="${4:-}" c
        TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1
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
        printf '%s{"schema":1,"type":"%s","run":%s,"tool":%s,"version":%s,"host":%s,"command":%s,"ts":"%s"%s,"msg":%s,"cve":[%s]%s}\n' \
            "$_PSF_MARK" "$type" "$(_psf_s "$_PSF_RUN")" "$(_psf_s "$_PSF_TOOL")" "$(_psf_s "${SCRIPT_VERSION:-}")" "$(_psf_s "$_PSF_HOST")" \
            "$(_psf_s "$_PSF_CMD")" "$ts" "${level:+,\"level\":\"$level\"}" "$(_psf_s "$msg")" "$cves" "$extra"
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
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}

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

# take_lock: one change at a time. Two runs that change this host together would interleave their backup
# and manifest writes, so the second waits (PSF_LOCK_WAIT seconds, default 30) and then stops. The lock is
# released when the script exits.
take_lock() {
    have flock || return 0
    mkdir -p "$STATE_DIR" 2>/dev/null || return 0
    { exec 9>"${STATE_DIR}/.lock"; } 2>/dev/null || return 0
    flock -w "${PSF_LOCK_WAIT:-30}" 9 || die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: ${STATE_DIR}/.lock): wait for it to finish, then run it again"
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- shared with the other kernel checks ------------------------------
# does a vendor changelog name this CVE?
changelog_names() {   # <release> <CVE>
    local c pkg rel="$1" cve="$2" ov="${KERNEL_CHANGELOG:-}"
    [[ -n "$ov" && -r "${ov}.${rel}" ]] && ov="${ov}.${rel}"   # a file per release, for the installed kernels
    if [[ -n "$ov" && -r "$ov" ]]; then
        if zcat -f "$ov" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
        return 1
    fi
    if have dpkg; then
        for pkg in $(dpkg -S "/boot/vmlinuz-${rel}" "/lib/modules/${rel}" 2>/dev/null | cut -d: -f1 | sort -u); do
            for c in /usr/share/doc/"${pkg}"/changelog*; do
                [[ -r "$c" ]] || continue
                if zcat -f "$c" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
            done
        done
    fi
    if have rpm; then
        pkg="$(rpm -qf "/lib/modules/${rel}" 2>/dev/null | head -n1)"
        if [[ -n "$pkg" && "$pkg" != *"not owned"* ]]; then
            if rpm -q --changelog "$pkg" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
        fi
    fi
    return 1
}

# prints the value of a /proc/sys entry, or nothing when it is absent
sysval() { local f="${KERNEL_PROC_SYS:-/proc/sys}/$1"; [[ -r "$f" ]] && tr -d '\n' <"$f"; }

# prints: <family> <id> <version_id>; the family is debian | rhel | suse | arch | alpine | other
os_info() {
    local f="${OS_RELEASE_FILE:-/etc/os-release}" id like vid fam all kv
    [[ -r "$f" ]] || { echo "other unknown unknown"; return; }
    # shellcheck source=/dev/null
    kv="$( . "$f" 2>/dev/null; printf '%s|%s|%s' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" )"
    id="${kv%%|*}"; kv="${kv#*|}"; like="${kv%%|*}"; vid="${kv#*|}"
    all=" ${id} ${like} "
    case "$all" in
        *" debian "*|*" ubuntu "*|*" trisquel "*|*" raspbian "*|*" devuan "*) fam=debian ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*|*" amzn "*|*" cloudlinux "*|*" scientific "*) fam=rhel ;;
        *" suse "*|*" opensuse "*|*" sles "*|*" sled "*) fam=suse ;;
        *" arch "*) fam=arch ;;
        *" alpine "*) fam=alpine ;;
        *) fam=other ;;
    esac
    echo "${fam} ${id:-unknown} ${vid:-unknown}"
}

# a reboot may be all that is left to do
pending_reboot() {
    local rel="$1" newest
    [[ -e /var/run/reboot-required ]] && { echo "this host reports a pending reboot (/var/run/reboot-required)"; return 0; }
    if have needs-restarting; then
        needs-restarting -r >/dev/null 2>&1
        [[ $? -eq 1 ]] && { echo "needs-restarting -r says a reboot is needed"; return 0; }
        return 1
    fi
    if have rpm; then
        newest="$(rpm -qa 'kernel*' --qf '%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}\n' 2>/dev/null | awk -F'|' '$1 ~ /^kernel(-core|[0-9.]+)?$/ {print $2}' | sort -V | tail -n 1)"
        if [[ -n "$newest" && "$newest" != "$rel" && "$(printf '%s\n%s\n' "$rel" "$newest" | sort -V | tail -n 1)" == "$newest" ]]; then
            echo "the newest installed kernel package is ${newest}, not the running ${rel}"; return 0
        fi
    fi
    return 1
}

# ---------- the flaws ---------------------------------------------------------
# NoisyTCP: first fixed patch release of each branch; anything newer than the newest listed branch
# carries the mainline fix, except a 7.4 release candidate before rc2
NT_INTRODUCED="4.4"
NT_FIXES="5.10:275 5.15:226 6.1:193 6.6:163 6.12:117 6.18:63 7.3:4"
NT_NEWEST="7.3"
# Debian carried the fix in its own 6.1 build before upstream 6.1.193 (DLA-4906-1: 6.1.192-1)
NT_DEBIAN="6.1:192"
# RHEL itself: the first fixed build of each update stream (Red Hat advisories of 23 and 24 November)
NT_RHEL="el8_8:4.18.0-477.181.1 el8_10:4.18.0-553.189.1 el9_9:5.14.0-741.26.1 el10_3:6.12.0-264.19.1"
# Ubuntu's main linux package: the ABI of the build it named for the fix (in progress on 23 November)
NT_UBUNTU="7.3.0:12 7.0.0:45 6.8.0:152 5.15.0:205 5.4.0:248 4.15.0:264 4.4.0:294"
# the sibling: 5.4 from 5.4.208, then every release from 5.5 up to the fixed ones
SIB_INTRODUCED="5.5"
SIB_FIXES="6.12:118 6.18:64 7.3:5"
SIB_NEWEST="7.3"
MAINLINE_FIX_RC="7.4:2"

# prints: fixed | notaffected | affected | nofix (a listed long-term branch with no fix yet) | eol | unknown
branch_status() {   # <x.y.z> <introduced> <fixes> <newest> [<extra x.y:first-affected-patch>]
    local ver="${1%%-*}" intro="$2" fixes="$3" newest="$4" extra="${5:-}" maj min pat line e fx rcl rcn
    [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; line="${maj}.${min}"
    if [[ -n "$extra" && "${extra%%:*}" == "$line" ]]; then
        if (( pat >= ${extra#*:} )); then echo nofix; else echo notaffected; fi
        return
    fi
    if ver_lt "$ver" "$intro"; then echo notaffected; return; fi
    for e in $fixes; do
        if [[ "${e%%:*}" == "$line" ]]; then
            fx="${e#*:}"
            if (( pat >= fx )); then echo fixed; else echo affected; fi
            return
        fi
    done
    rcl="${MAINLINE_FIX_RC%%:*}"; rcn="${MAINLINE_FIX_RC#*:}"
    if [[ "$line" == "$rcl" && "${1}" =~ -rc([0-9]+) ]]; then
        if (( BASH_REMATCH[1] >= rcn )); then echo fixed; else echo affected; fi
        return
    fi
    if ver_lt "$newest" "$line"; then echo fixed; return; fi
    local lts=" 5.4 5.10 5.15 6.1 6.6 "   # long-term branches still maintained when the sibling was fixed
    if [[ "$lts" == *" $line "* ]]; then echo nofix; else echo eol; fi
}
nt_status()  { local s; s="$(branch_status "$1" "$NT_INTRODUCED" "$NT_FIXES" "$NT_NEWEST")"; [[ "$s" == nofix ]] && s=eol; echo "$s"; }
sib_status() { branch_status "$1" "$SIB_INTRODUCED" "$SIB_FIXES" "$SIB_NEWEST" "5.4:208"; }

# prints: stable <x.y.z> | debian <x.y.z> | rhel <stream> <build> | ubuntu <base> <abi> | vendor
kernel_origin() {
    local rel="$1" ver="$2" up
    if [[ "$ver" =~ Debian[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)- ]]; then echo "debian ${BASH_REMATCH[1]}"; return; fi
    if [[ "$ver" == *Ubuntu* && "$rel" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-(generic|generic-64k|generic-lpae)$ ]]; then
        echo "ubuntu ${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"; return
    fi
    if [[ "$rel" =~ ^([0-9]+\.[0-9]+\.[0-9]+-[0-9.]+)\.(el[0-9]+_[0-9]+)(\.|$) && "$rel" != *.rt* && "$(os_id)" == rhel ]]; then
        echo "rhel ${BASH_REMATCH[2]} ${BASH_REMATCH[1]}"; return
    fi
    if [[ "$ver" == *Ubuntu* ]] \
       || [[ "$rel" =~ \.(el|fc|amzn|azl|oe|ael)[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+ ]]; then echo vendor; return; fi
    up="${rel%%-*}"
    if [[ "$up" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "stable ${up}"; else echo vendor; fi
}

os_id() { local f="${OS_RELEASE_FILE:-/etc/os-release}"; [[ -r "$f" ]] && sed -n 's/^ID="\{0,1\}\([^"]*\)"\{0,1\}$/\1/p' "$f" | head -n 1; }

# x86 keeps the memory ordering the sibling flaw needs to lose; every other processor is treated as
# weakly ordered, which is true of Arm, POWER and RISC-V and the safe assumption for the rest
weakly_ordered() { case "$1" in x86_64|amd64|i[3-6]86) return 1 ;; *) return 0 ;; esac; }

# prints: fixed | affected | nostream    for RHEL itself
rhel_status() {   # <stream> <build>
    local e
    for e in $NT_RHEL; do
        if [[ "${e%%:*}" == "$1" ]]; then
            if [[ "$(printf '%s\n%s\n' "${e#*:}" "$2" | sort -V | head -n 1)" == "${e#*:}" ]]; then echo fixed; else echo affected; fi
            return
        fi
    done
    echo nostream
}

# prints: atfix | below | none    for Ubuntu's main linux package
ubuntu_status() {   # <base> <abi>
    local e
    for e in $NT_UBUNTU; do
        if [[ "${e%%:*}" == "$1" ]]; then if (( $2 >= ${e#*:} )); then echo atfix; else echo below; fi; return; fi
    done
    echo none
}

# A script running as root must not run a program that another account could have changed: the program
# and every folder above it must be root's and writable by no one else (a sticky folder such as /tmp aside)
root_safe_bin() {   # <name or path>: prints the path when it may be run
    local b p st mode
    b="$(command -v "$1" 2>/dev/null)" || return 1
    [[ -x "$b" ]] || return 1
    is_root || { echo "$b"; return 0; }
    p="$(readlink -f "$b" 2>/dev/null)" || return 1
    while :; do
        st="$(stat -c '%u %a' "$p" 2>/dev/null)" || return 1
        [[ "${st%% *}" == 0 ]] || return 1
        mode="${st##* }"
        if (( (8#$mode & 8#022) != 0 )); then [[ -d "$p" && ${#mode} -eq 4 && "${mode:0:1}" =~ [1357] ]] || return 1; fi
        [[ "$p" == / ]] && break
        p="$(dirname "$p")"
    done
    echo "$b"
}

# Write a whole file as root without following a link that may stand at its name: a new file beside it,
# then a rename over it (a rename replaces a link, it does not follow it)
safe_write() {   # <path> <content>
    local d tmp
    d="$(dirname "$1")"
    [[ -L "$1" ]] && { bad "${1} is a symbolic link: not writing through it"; return 1; }
    mkdir -p "$d" || return 1
    tmp="$(mktemp "${d}/.psf-noisytcp.XXXXXXXX")" || return 1
    printf '%s\n' "$2" >"$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$1" && return 0
    rm -f "$tmp"; return 1
}

# ---------- exposure ---------------------------------------------------------
NET_SPREAD=0
exposure_report() {
    local ps="${KERNEL_PROC_SYS:-/proc/sys}" sn="${KERNEL_SYS_NET:-/sys/class/net}" v d n q r rps flow arch others
    v="$(sysval net/ipv4/tcp_syncookies)"
    case "$v" in
        0) inf "net.ipv4.tcp_syncookies=0: SYN cookies are off in this network namespace; the crash path that rebuilds a request from a cookie is closed here" ;;
        1) inf "net.ipv4.tcp_syncookies=1 (the usual default): cookies are sent once the SYN queue overflows, and an attacker can make it overflow" ;;
        2) inf "net.ipv4.tcp_syncookies=2: cookies are sent for every connection" ;;
        *) inf "net.ipv4.tcp_syncookies could not be read" ;;
    esac
    NET_SPREAD=0
    for d in "$sn"/*; do
        [[ -d "$d/queues" ]] || continue
        n="${d##*/}"; [[ "$n" == lo ]] && continue
        q=0; rps=0; flow=0
        for r in "$d"/queues/rx-*; do
            [[ -d "$r" ]] || continue
            q=$((q + 1))
            if [[ -r "$r/rps_cpus" ]] && tr -d ',0\n' <"$r/rps_cpus" | grep -q .; then rps=1; fi
            if [[ -r "$r/rps_flow_cnt" ]] && [[ "$(cat "$r/rps_flow_cnt" 2>/dev/null)" != 0 ]]; then flow=1; fi
        done
        [[ $q -gt 0 ]] || continue
        if [[ $q -gt 1 || $rps -eq 1 ]]; then NET_SPREAD=1; fi
        inf "${n}: ${q} receive queue(s), RPS $([[ $rps -eq 1 ]] && echo on || echo off)$([[ $flow -eq 1 ]] && echo ', RFS flow table set')$([[ $q -gt 1 || $rps -eq 1 ]] && echo ': packets can be spread across CPUs')"
    done
    v="$(sysval net/core/rps_sock_flow_entries)"
    [[ -n "$v" ]] && inf "net.core.rps_sock_flow_entries=${v} (RFS is off when it is 0)"
    if [[ $NET_SPREAD -eq 0 ]]; then inf "no interface here has more than one receive queue or RPS on: the race needs packets handled on different CPUs at once"; fi
    if have ss; then
        n="$(ss -H -t -l -n 2>/dev/null | awk '{print $4}' | grep -vEc '^(127\.|\[?::1\]?:|\[::ffff:127\.)')"
        inf "TCP listeners that are not on loopback: ${n} (each one is a target unless a filter stands in front)"
    else inf "ss was not found: the listeners were not counted"; fi
    if is_root && [[ -z "${KERNEL_SYS_NET:-}" ]]; then
        others="$(for p in /proc/[0-9]*/ns/net; do readlink "$p" 2>/dev/null; done | sort -u | grep -vcFx "$(readlink /proc/self/ns/net 2>/dev/null)")"
        [[ "$others" -gt 0 ]] && inf "${others} other network namespace(s) on this host (containers, most often): each has its own net.ipv4.tcp_syncookies, and a crash in any of them takes the whole host down"
    fi
    arch="${KERNEL_ARCH:-$(uname -m 2>/dev/null)}"
    inf "processor: ${arch}$(weakly_ordered "$arch" && echo ' (weakly ordered: the sibling flaw applies)' || echo ' (x86: the sibling flaw does not apply)')"
    return 0
}

# ---------- check ---------------------------------------------------------------
cmd_check() {
    local rc=0 rel ver origin kind up st sst arch fam fid fvid fixedk="" v
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"; ver="${KERNEL_VERSION_STRING:-$(uname -v 2>/dev/null)}"
    arch="${KERNEL_ARCH:-$(uname -m 2>/dev/null)}"
    read -r fam fid fvid <<<"$(os_info)"
    step "Running kernel"
    [[ -n "$rel" ]] || { caution "uname -r returned nothing: cannot check"; return 1; }
    inf "release: ${rel}"
    origin="$(kernel_origin "$rel" "$ver")"; kind="${origin%% *}"; up=""
    case "$kind" in
        stable) up="${origin#* }"; inf "origin: follows the stable series; upstream version ${up}" ;;
        debian) up="${origin#* }"; inf "origin: Debian; upstream version ${up} (from uname -v)" ;;
        rhel)   inf "origin: Red Hat Enterprise Linux, update stream $(cut -d' ' -f2 <<<"$origin"), build $(cut -d' ' -f3 <<<"$origin")" ;;
        ubuntu) inf "origin: Ubuntu's main linux package, $(cut -d' ' -f2 <<<"$origin") with ABI $(cut -d' ' -f3 <<<"$origin")" ;;
        *)      inf "origin: a vendor kernel that backports fixes; its release string does not show which" ;;
    esac
    if [[ "$kind" == stable && "$rel" =~ -rc[0-9]+ && "$up" =~ ^([0-9]+\.[0-9]+)\.([0-9]+)$ && "${BASH_REMATCH[2]}" -gt 0 ]]; then
        up="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] - 1 ))"; inf "a stable release candidate is not the release: judged as the release before it, ${up}"
    fi
    # a mainline release candidate (7.4.0-rc1) is judged by its rc number: both fixes came in 7.4-rc2
    local upj="$up"
    [[ "$kind" == stable && "$rel" =~ ^[0-9]+\.[0-9]+\.0-rc[0-9]+ ]] && upj="${rel%%[!0-9.rc-]*}"

    step "${CVE} (NoisyTCP)"
    case "$kind" in
        stable|debian)
            st="$(nt_status "$upj")"
            if [[ "$kind" == debian && "$st" == affected && "${up%.*}" == "${NT_DEBIAN%%:*}" && "${up##*.}" -ge "${NT_DEBIAN#*:}" ]]; then st=fixed; fi ;;
        rhel) st="$(rhel_status "$(cut -d' ' -f2 <<<"$origin")" "$(cut -d' ' -f3 <<<"$origin")")" ;;
        ubuntu) st="ubuntu-$(ubuntu_status "$(cut -d' ' -f2 <<<"$origin")" "$(cut -d' ' -f3 <<<"$origin")")" ;;
        *) st=vendor ;;
    esac
    [[ "$kind" == vendor && "$rel" =~ \.el[67]([._]|$) ]] && st=rhel67
    case "$st" in
        fixed)       ok "this kernel is at or beyond the first fixed release for its branch$([[ $kind == rhel ]] && echo ' (Red Hat advisory)')" ;;
        notaffected) ok "upstream ${up} is not affected (the bug came in with ${NT_INTRODUCED})" ;;
        rhel67)      ok "RHEL 6 and 7 kernels are older than the change that brought the bug (4.4), and Red Hat lists RHEL 6 and 7 as not affected" ;;
        *)
            if changelog_names "$rel" "$CVE"; then
                ok "the vendor changelog names ${CVE}: this kernel carries a backport, so its version number understates its state"
            else
                case "$st" in
                    affected)  bad "this kernel is below the first fixed release for its branch" ;;
                    eol)       bad "upstream ${up} is on a branch with no upstream fix (end of life): move to a fixed branch or a vendor kernel that carries the fix" ;;
                    nostream)  bad "Red Hat listed no fixed kernel for this RHEL update stream ($(cut -d' ' -f2 <<<"$origin")) as of 25 November: fixed builds exist for 8.8, 8.10, 9.9 and 10.3" ;;
                    ubuntu-below) bad "Ubuntu lists this release as vulnerable; the fix it has in progress is in ABI $(ubuntu_fix_abi "$(cut -d' ' -f2 <<<"$origin")") or later" ;;
                    ubuntu-atfix) caution "this build is at or past the one Ubuntu named for its fix, which was still in progress on 23 November, and its changelog does not name ${CVE}: confirm on $(tracker_url ubuntu ubuntu "$CVE")" ;;
                    ubuntu-none) bad "Ubuntu lists this kernel as vulnerable, with no fix in progress for it on 23 November" ;;
                    unknown)   caution "cannot parse upstream version '${up}', and the vendor changelog does not name ${CVE}" ;;
                    *)         caution "the vendor changelog does not name ${CVE} (or is not readable), and this release string cannot be compared with the upstream table: check $(tracker_url "$fam" "$fid" "$CVE")" ;;
                esac
                rc=1
            fi ;;
    esac

    step "${SIB_CVE} (the sibling: weakly ordered processors only)"
    if ! weakly_ordered "$arch"; then
        ok "not reachable on ${arch}: x86 keeps the memory ordering this flaw needs to lose"
    else
        case "$kind" in stable|debian) sst="$(sib_status "$upj")" ;; *) sst=vendor ;; esac
        if [[ "$sst" == fixed ]]; then ok "upstream ${up} carries the fix"
        elif [[ "$sst" == notaffected ]]; then ok "upstream ${up} is older than the change that brought it (5.5, and 5.4.208)"
        elif changelog_names "$rel" "$SIB_CVE"; then ok "the vendor changelog names ${SIB_CVE}"
        else
            case "$sst" in
                affected) caution "below the first fixed release for its branch (6.12.118, 6.18.64, 7.3.5)" ;;
                nofix)    caution "the ${up%.*} branch has no upstream fix yet: only 6.12.118, 6.18.64 and 7.3.5 and later carry it" ;;
                eol)      caution "upstream ${up} is on a branch with no upstream fix (end of life)" ;;
                *)        caution "the vendor changelog does not name ${SIB_CVE}: check $(tracker_url "$fam" "$fid" "$SIB_CVE")" ;;
            esac
            inf "on this processor a kernel fixed for NoisyTCP may still not be fixed for this; keep a NoisyTCP stopgap until both are"
            rc=1
        fi
    fi

    step "Exposure (information; a kernel below its fixed release is affected whatever this shows)"
    exposure_report
    if [[ $rc -eq 1 ]]; then
        pm_evidence "$fam" "$CVE"
        if fixedk="$(installed_fixed_kernel "$rel" "$CVE")"; then inf "kernel ${fixedk} is installed and its changelog names ${CVE}: you are running ${rel}"; fi
    fi
    if v="$(pending_reboot "$rel")"; then inf "$v"; fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The running kernel has the fix for NoisyTCP (${CVE})$(weakly_ordered "$arch" && echo " and ${SIB_CVE}")."
    else
        if [[ -n "$fixedk" ]]; then warn "The running kernel is affected, but a kernel that names ${CVE} is already installed (${fixedk}). Reboot into it."
        else warn "The running kernel is affected, or a fix could not be confirmed. Update to your vendor's fixed kernel and reboot: that is the only complete remedy."; fi
        update_advice "$fam" "$fid" "$fvid"
        inf "Upstream first fixed releases: 5.10.275, 5.15.226, 6.1.193, 6.6.163, 6.12.117, 6.18.63 and 7.3.4 (sibling: 6.12.118, 6.18.64, 7.3.5)"
        inf "Until then, stopgaps only: mitigate --syncookies (in every network namespace), or mitigate --single-queue IFACE on the interfaces that face the attacker"
    fi
    return "$rc"
}

ubuntu_fix_abi() { local e; for e in $NT_UBUNTU; do [[ "${e%%:*}" == "$1" ]] && { echo "${e#*:}"; return; }; done; }

# the vendor's page for a CVE
tracker_url() {   # <family> <id> <CVE>
    local c="${3:-$CVE}"
    case "$2" in
        ubuntu) echo "https://ubuntu.com/security/${c}"; return ;;
        amzn) echo "https://explore.alas.aws.amazon.com/${c}.html"; return ;;
    esac
    case "$1" in
        debian) echo "https://security-tracker.debian.org/tracker/${c}" ;;
        rhel) echo "https://access.redhat.com/security/cve/${c}" ;;
        suse) echo "https://www.suse.com/security/cve/${c}.html" ;;
        arch) echo "https://security.archlinux.org/${c}" ;;
        alpine) echo "https://security.alpinelinux.org/vuln/${c}" ;;
        *) echo "https://nvd.nist.gov/vuln/detail/${c}" ;;
    esac
}

update_advice() {   # <family> <id> <version_id>
    case "$1" in
        debian) inf "update: sudo apt update && sudo apt full-upgrade, then reboot (full-upgrade, not upgrade: a new linux-image package comes in as a new dependency, which plain upgrade holds back)" ;;
        rhel)
            if have dnf; then inf "update: sudo dnf update kernel && sudo reboot. To see whether your repositories have the advisory: sudo dnf updateinfo list --cve ${CVE}. After the reboot: needs-restarting -r"
            else inf "update: sudo yum update kernel && sudo reboot"; fi ;;
        suse)   inf "update: sudo zypper refresh && sudo zypper patch (or update kernel-default), then reboot" ;;
        arch)   inf "update: sudo pacman -Syu, then reboot" ;;
        alpine) inf "update: sudo apk update && sudo apk upgrade, then reboot" ;;
        *)      inf "update the kernel with your distribution's package manager and reboot" ;;
    esac
    inf "vendor page: $(tracker_url "$1" "$2" "$CVE")"
    return 0
}

# what the package manager already knows, from cached data only (no network)
pm_evidence() {   # <family> <CVE>
    local out
    case "$1" in
        debian)
            if have apt && out="$(apt list --upgradable 2>/dev/null | grep -E '^linux-(image|generic|signed|headers-generic)' | head -n 3 | cut -d/ -f1 | tr '\n' ' ')" && [[ -n "$out" ]]; then
                inf "apt lists a newer kernel package: ${out}(from the cached package lists; apt changelog shows whether it names ${2})"
            fi ;;
        rhel)
            if have dnf && out="$(dnf -q -C updateinfo list --cve "$2" 2>/dev/null | grep -F "$2" | head -n 2)" && [[ -n "$out" ]]; then
                inf "the cached repository data has an advisory that names ${2}: $(echo "$out" | head -n 1 | tr -s ' ')"
            fi ;;
    esac
    return 0
}

# the first installed kernel, other than the running one, whose changelog names the CVE
installed_fixed_kernel() {   # <running release> <CVE>
    local run="$1" r d
    local -a rels=()
    if [[ -n "${KERNEL_INSTALLED_RELEASES:-}" ]]; then for r in $KERNEL_INSTALLED_RELEASES; do rels+=("$r"); done
    else for d in /lib/modules/*; do [[ -d "$d" ]] && rels+=("${d##*/}"); done; fi
    for r in "${rels[@]+"${rels[@]}"}"; do
        [[ "$r" == "$run" ]] && continue
        if changelog_names "$r" "$2"; then echo "$r"; return 0; fi
    done
    return 1
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local rc=0 nsrc=0 f d out hits total=0 n
    local pat='tcp_v4_rcv|tcp_v6_rcv|__inet_lookup_established|__inet6_lookup_established|inet_lookup_established|tcp_get_cookie_sock|cookie_v4_check|cookie_v6_check'
    local sig='NULL pointer dereference|Kernel panic|Oops'
    step "Kernel log"
    limited_view "kernel logs"
    local -a files=()
    if [[ -n "${KERNEL_LOG_FILES:-}" ]]; then for f in $KERNEL_LOG_FILES; do files+=("$f"); done
    else for f in /var/log/kern.log* /var/log/syslog* /var/log/messages*; do [[ -f "$f" ]] && files+=("$f"); [[ ${#files[@]} -ge 24 ]] && break; done; fi
    scan() {   # <label>, reads stdin: a lead is a line naming that code within 40 lines after a fault
        local -a res=()
        mapfile -t res < <(awk -v pat="$pat" -v sig="$sig" '$0 ~ sig {w = 40} w > 0 && $0 ~ pat {n++; if (n <= 3) keep[n] = $0} {if (w > 0) w--} END {print n + 0; for (i = 1; i <= n && i <= 3; i++) print keep[i]}')
        hits="${res[0]:-0}"
        if [[ "$hits" -gt 0 ]]; then bad "${hits} fault trace line(s) in ${1} run through the TCP receive or lookup code"; total=$((total+hits)); printf '        %s\n' "${res[@]:1}"
        else ok "${1}: nothing"; fi
    }
    for f in "${files[@]+"${files[@]}"}"; do
        if [[ ! -r "$f" ]]; then caution "${f} exists but cannot be read by this user"; rc=2; continue; fi
        nsrc=$((nsrc+1)); scan "$f" < <(zcat -f "$f" 2>/dev/null)   # not a pipe: scan must count in this shell
    done
    if [[ -z "${KERNEL_LOG_FILES:-}" ]]; then
        if have dmesg && out="$(dmesg 2>/dev/null)" && [[ -n "$out" ]]; then nsrc=$((nsrc+1)); scan "the kernel ring buffer" <<<"$out"; fi
        if have journalctl && out="$(journalctl -k --no-pager -q 2>/dev/null)" && [[ -n "$out" ]]; then nsrc=$((nsrc+1)); scan "the journal's kernel messages" <<<"$out"; fi
    fi
    step "Crash dumps"
    for d in ${KERNEL_CRASH_DIRS:-/var/crash /sys/fs/pstore}; do
        [[ -d "$d" ]] || continue
        if [[ ! -r "$d" ]]; then caution "${d} cannot be read by this user"; continue; fi
        n="$(find "$d" -mindepth 1 -maxdepth 2 -mtime -30 2>/dev/null | wc -l | tr -d ' ')"
        if [[ "$n" -gt 0 ]]; then inf "${d}: ${n} entr(ies) from the last 30 days. A panic reboots the host and loses the ring buffer, so a dump may hold the only trace: look for tcp_v4_rcv or __inet_lookup_established in it"
        else ok "${d}: nothing from the last 30 days"; fi
    done
    step "Verdict"
    if [[ $total -gt 0 ]]; then
        warn "The kernel faulted in the TCP receive or lookup code. That is a lead, not proof of an attack: look at the full trace and at what connected just before it."
        return 1
    elif [[ $nsrc -eq 0 ]]; then warn "No kernel log could be read, so nothing was judged. This is not a clean result."; return 2
    elif [[ $rc -eq 2 ]]; then warn "Nothing in the logs that could be read, but not every log could be read: this is not a clean result."; return 2
    fi
    info "Nothing in the kernel logs that were read (${nsrc})."
    inf "That is not clearance: a crashed host reboots and loses its ring buffer, and an attempt that failed leaves no trace."
    return 0
}

# ---------- mitigate and rollback --------------------------------------------
LM_MANIFEST=""; LM_DRY=0
lm_note() { [[ "$LM_DRY" -eq 1 ]] || echo "$1" >>"$LM_MANIFEST"; }

lm_write_value() {   # <file> <value> <label>: a /proc/sys or /sys value, its old value kept for rollback
    local f="$1" old
    old="$(tr -d '\n' <"$f" 2>/dev/null)"
    if [[ "$LM_DRY" -eq 1 ]]; then echo "  would set ${3}=${2} (now ${old:-unreadable})"; return 0; fi
    if printf '%s\n' "$2" >"$f" 2>/dev/null; then lm_note "value|${f}|${old}"; ok "set ${3}=${2} (was ${old:-unknown}), applied now"; return 0; fi
    bad "could not write ${f}: read-only (a container?) or no permission"; return 1
}

# the sysctl configuration that runs last decides the value at boot
syncookies_override() {   # <our file>: prints the file that sets tcp_syncookies after ours, if any
    local f b last="" ours="$1"
    local -A seen=()
    local -a list=()
    for f in /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf; do
        [[ -f "$f" ]] || continue; b="${f##*/}"; [[ -n "${seen[$b]:-}" ]] && continue; seen[$b]=1; list+=("$b|$f")
    done
    while IFS='|' read -r b f; do
        grep -Eq '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=' "$f" 2>/dev/null && last="$f"
    done < <(printf '%s\n' "${list[@]+"${list[@]}"}" | sort -t'|' -k1,1)
    [[ -f /etc/sysctl.conf ]] && grep -Eq '^[[:space:]]*net\.ipv4\.tcp_syncookies[[:space:]]*=' /etc/sysctl.conf && last=/etc/sysctl.conf
    [[ -n "$last" && "$last" != "$ours" ]] && echo "$last"
    return 0
}

cmd_mitigate() {
    local cookies=0 ifaces="" force=0 rc=0 rel ps sn sd did=0 i r f eth cur rxc comb other
    LM_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --syncookies) cookies=1 ;; --force) force=1 ;; --dry-run) LM_DRY=1 ;;
            --single-queue) shift; ifaces="${1:-}"; [[ -n "$ifaces" && "$ifaces" != -* ]] || die "--single-queue needs the interfaces that face the attacker, for example --single-queue eth0" ;;
            *) die "Unknown mitigate option: $1 (--syncookies --single-queue IFACE --force --dry-run)" ;;
        esac
        shift
    done
    [[ $cookies -eq 1 || -n "$ifaces" ]] || die "mitigate needs --syncookies and/or --single-queue IFACE, because each one has a cost (see --help). Nothing was changed."
    [[ $LM_DRY -eq 1 ]] || need_root "mitigate changes the host"
    rel="${KERNEL_RELEASE:-$(uname -r)}"; ps="${KERNEL_PROC_SYS:-/proc/sys}"; sn="${KERNEL_SYS_NET:-/sys/class/net}"
    for i in ${ifaces//,/ }; do [[ "$i" =~ ^[A-Za-z0-9_.:@-]+$ && -d "$sn/$i" ]] || die "no such network interface: ${i}"; done
    step "Is this kernel affected?"
    if cmd_check >/dev/null 2>&1; then
        if [[ $force -eq 0 ]]; then info "check finds this kernel fixed: nothing to do (use --force to apply anyway)"; return 0; fi
        caution "check finds this kernel fixed, applying anyway because of --force"
    else bad "check finds kernel ${rel} affected, or a fix could not be confirmed: applying the stopgaps you chose"; fi
    if [[ $LM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" && chmod 0700 "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        take_lock
        LM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$LM_MANIFEST"
    else LM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    sd="${SYSCTL_D:-/etc/sysctl.d}"
    if [[ $cookies -eq 1 ]]; then
        step "SYN cookies"
        if [[ -e "$ps/net/ipv4/tcp_syncookies" ]]; then
            if lm_write_value "$ps/net/ipv4/tcp_syncookies" 0 net.ipv4.tcp_syncookies; then
                did=1; f="$sd/99-psf-kernel-noisytcp.conf"
                if [[ $LM_DRY -eq 1 ]]; then echo "  would write ${f} (net.ipv4.tcp_syncookies = 0), kept across reboots"
                elif safe_write "$f" "# psf-security-patches: ${CVE} stopgap (linux-kernel-noisytcp-check.sh mitigate). Remove with: rollback"$'\n'"net.ipv4.tcp_syncookies = 0"; then
                    lm_note "file|${f}"; ok "written ${f} (kept across reboots)"
                    if other="$(syncookies_override "$f")" && [[ -n "$other" ]]; then caution "${other} also sets net.ipv4.tcp_syncookies and is read after ${f}: at boot its value wins. Change it there too"; fi
                else bad "could not write ${f}"; rc=1; fi
                caution "net.ipv4.tcp_syncookies was set in this network namespace only. Each container with its own namespace keeps its own value (a new one starts at 1): start it with --sysctl net.ipv4.tcp_syncookies=0 (Docker, Podman), set securityContext.sysctls in Kubernetes (it is a safe, namespaced sysctl), or set it from inside with nsenter -t PID -n sysctl -w net.ipv4.tcp_syncookies=0"
                inf "with SYN cookies off, a SYN flood can fill the SYN queue and refuse new connections: watch for it until the patched kernel runs"
            else rc=1; fi
        else inf "this kernel has no net.ipv4.tcp_syncookies: nothing to turn off"; fi
    fi
    if [[ -n "$ifaces" ]]; then
        step "One receive queue, RPS and RFS off"
        eth="$(root_safe_bin ethtool)" || eth=""
        [[ -z "$eth" ]] && have ethtool && caution "ethtool is not root's, or a folder above it can be changed by another account: not running it as root"
        for i in ${ifaces//,/ }; do
            if [[ -n "$eth" ]] && cur="$("$eth" -l "$i" 2>/dev/null | awk '/Current hardware settings/ {c=1} c && /^RX:/ {rx=$2} c && /^Combined:/ {cb=$2} END {print (rx==""?"n/a":rx) " " (cb==""?"n/a":cb)}')"; then
                rxc="${cur% *}"; comb="${cur#* }"
                if [[ "$comb" =~ ^[0-9]+$ && "$comb" -gt 1 ]]; then
                    if [[ $LM_DRY -eq 1 ]]; then echo "  would run: ethtool -L ${i} combined 1 (now ${comb})"
                    elif "$eth" -L "$i" combined 1 2>/dev/null; then lm_note "ethtool|${i}|combined|${comb}"; ok "${i}: combined channels ${comb} -> 1"; did=1
                    else bad "${i}: ethtool could not set one combined channel (a driver that does not allow it?)"; rc=1; fi
                elif [[ "$rxc" =~ ^[0-9]+$ && "$rxc" -gt 1 ]]; then
                    if [[ $LM_DRY -eq 1 ]]; then echo "  would run: ethtool -L ${i} rx 1 (now ${rxc})"
                    elif "$eth" -L "$i" rx 1 2>/dev/null; then lm_note "ethtool|${i}|rx|${rxc}"; ok "${i}: receive channels ${rxc} -> 1"; did=1
                    else bad "${i}: ethtool could not set one receive channel"; rc=1; fi
                else inf "${i}: already one receive channel, or the driver does not report channels"; fi
            elif [[ -z "$eth" ]]; then caution "${i}: ethtool is not available to run: the queue count was not changed (RPS and RFS still are)"; rc=1
            else caution "${i}: ethtool reports no channel settings for it (a driver without them?): the queue count was not changed (RPS and RFS still are)"; fi
            for r in "$sn/$i"/queues/rx-*; do
                [[ -d "$r" ]] || continue
                if [[ -w "$r/rps_cpus" || $LM_DRY -eq 1 ]] && tr -d ',0\n' <"$r/rps_cpus" 2>/dev/null | grep -q .; then lm_write_value "$r/rps_cpus" 0 "${i} ${r##*/} rps_cpus" && did=1 || rc=1; fi
                if [[ -r "$r/rps_flow_cnt" && "$(cat "$r/rps_flow_cnt" 2>/dev/null)" != 0 ]]; then lm_write_value "$r/rps_flow_cnt" 0 "${i} ${r##*/} rps_flow_cnt" && did=1 || rc=1; fi
            done
        done
        if [[ "$(sysval net/core/rps_sock_flow_entries)" =~ ^[1-9] ]]; then lm_write_value "$ps/net/core/rps_sock_flow_entries" 0 net.core.rps_sock_flow_entries && did=1 || rc=1; fi
        inf "not kept across reboots or a driver reset, and lower throughput until undone: undo with rollback once the patched kernel runs"
    fi
    step "Result"
    if [[ $LM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Applied. Saved values and manifest: ${STATE_DIR}. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    inf "These are stopgaps. They do not fix the flaw: the fix is a patched kernel and a reboot."
    return "$rc"
}

cmd_rollback() {
    local line kind rest f old dev what n rc=0 eth=""
    LM_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) LM_DRY=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac
        shift
    done
    LM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$LM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $LM_DRY -eq 1 ]] || { need_root "rollback changes the host"; take_lock; }
    step "Rolling back"
    while IFS= read -r line; do
        kind="${line%%|*}"; rest="${line#*|}"
        case "$kind" in
            value) f="${rest%%|*}"; old="${rest#*|}"
                if [[ -z "$old" ]]; then caution "${f}: previous value unknown, left alone"; rc=1; continue; fi
                if [[ $LM_DRY -eq 1 ]]; then echo "  would write ${old} to ${f}"; elif printf '%s\n' "$old" >"$f" 2>/dev/null; then ok "restored ${f} = ${old}"; else bad "could not restore ${f}"; rc=1; fi ;;
            file) f="$rest"
                if [[ $LM_DRY -eq 1 ]]; then echo "  would remove ${f}"; elif [[ -L "$f" ]]; then caution "${f} is now a symbolic link: left alone"; rc=1; else rm -f "$f" && ok "removed ${f}"; fi ;;
            ethtool) dev="${rest%%|*}"; rest="${rest#*|}"; what="${rest%%|*}"; n="${rest#*|}"
                [[ -n "$eth" ]] || eth="$(root_safe_bin ethtool)" || eth=""
                if [[ $LM_DRY -eq 1 ]]; then echo "  would run: ethtool -L ${dev} ${what} ${n}"
                elif [[ -n "$eth" ]] && "$eth" -L "$dev" "$what" "$n" 2>/dev/null; then ok "${dev}: ${what} channels back to ${n}"
                else bad "${dev}: could not restore ${what} channels to ${n} (ethtool -L ${dev} ${what} ${n})"; rc=1; fi ;;
        esac
    done <"$LM_MANIFEST"
    if [[ $LM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$LM_MANIFEST" "${LM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. SYN cookies, receive queues, RPS and RFS are as they were."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE} (NoisyTCP) and ${SIB_CVE}: Linux kernel TCP pre-auth remote crash"
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
