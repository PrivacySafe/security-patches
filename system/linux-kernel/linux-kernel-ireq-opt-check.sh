#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Linux kernel IPv4 TCP use-after-free, remote code execution with MPTCP  (v1)
# CVE-2026-98432
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# A race in the Linux kernel's IPv4 TCP handshake. tcp_v4_syn_recv_sock() hands the request
# socket's IP options (ireq->ireq_opt) to the child socket without copying them. A retransmitted
# SYN for the same request socket, handled on another CPU, can still be building a SYNACK from
# those options when the child socket is destroyed, and inet_sock_destruct() and
# tcp_v4_reqsk_destructor() free them with a plain kfree() instead of kfree_rcu(): a use after
# free in ip_options_build(). The same happens through request socket migration
# (net.ipv4.tcp_migrate_req=1 or a BPF_SK_REUSEPORT_SELECT_OR_MIGRATE program). The attacker is
# an unauthenticated peer who sends a SYN that carries IPv4 options (Record Route or Timestamp)
# to any listening TCP port: no account, no user interaction. The CVE record scores it 9.8; Red
# Hat scores it lower (5.9, Moderate, draft). AWS reports that researchers have demonstrated
# unauthenticated remote code execution against a host with a Multipath TCP (MPTCP) listener, and
# that a crash, a leak of kernel memory or memory corruption are the other outcomes. At the time of
# AWS's bulletin of 2 November there was no evidence of exploitation in the wild.
#
# Two things independent, public testing has since added, neither of them from a primary source
# (CVE record, vendor advisory or the upstream patch) and neither changing whether a kernel below
# its fixed release is affected:
#   - The duplicate SYN and the ACK that races it share one 4-tuple, so normal flow affinity
#     (RSS, RPS, sk_incoming_cpu) puts both on the same CPU, where softirqs run one at a time: no
#     second CPU is left to be the reader while the first one frees the options. One report
#     reproduced a read of the freed memory locally on 6.12.112 (the release just before 6.12.113)
#     only after steering the duplicate SYN to a different CPU by hand; it also found every cloud
#     and ISP edge it tried (not an exhaustive list, and not this script's own test) silently
#     dropped packets that carried IP options, so the SYN this flaw needs never arrived. Neither
#     observation is a fix, and both can differ on another network path or a differently tuned host
#     (oversubscribed virtualisation, irqbalance, custom RPS, request-socket migration all change
#     which CPU handles which packet).
#   - The same report could not get remote code execution outside of an MPTCP listener either, in
#     line with AWS's bulletin above.
#
#   Affected: every kernel from 4.4 (commit 079096f103fa) up to the fixed releases below, on
#             IPv4. IPv6 is not affected by this flaw. Kernels before 4.4 are not affected.
#   First fixed stable release of each branch (the mainline fix is in 7.3):
#     5.10.272   5.15.223   6.1.190   6.6.159   6.12.113   6.18.56   7.2.10   7.3
#   Every release of a branch not in that list (4.4 to 5.9 other than 5.10, 5.11 to 5.14,
#   5.16 to 6.0, 6.2 to 6.5, 6.7 to 6.11, 6.13 to 6.17, 6.19 to 7.1, and older ones such as
#   4.14, 4.19 and 5.4) has no upstream fix. Vendors that maintain such a branch backport it.
#
# Why this script reads the kernel's origin first. The upstream patch level is in the release
# string only on kernels that follow the stable series (vanilla, Arch, Alpine, most custom
# builds). Debian puts it in `uname -v`. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux
# backport fixes under release strings that do not say which fixes they carry, so a number from
# them cannot be compared with the table. For those the vendor changelog is the evidence: the
# script looks in it for the CVE, and points you to the vendor's tracker when it is absent. A
# kernel that is a stable release candidate (-rc) is judged as the release before it.
#
# What the exposure lines mean. They report whether MPTCP is on (net.mptcp.enabled) and built
# in, loaded or loadable, how many MPTCP and IPv4 TCP listeners exist, whether
# net.ipv4.tcp_migrate_req is set, and whether a filter that drops TCP packets with IP options is
# in place. That is information for you to weigh, not a verdict: a kernel below its fixed release
# is affected whatever these show. Turning MPTCP off reduces the conditions for running code on
# the host; it does not fix the flaw, and a crash stays possible. Go programs built with Go 1.24
# or later listen with MPTCP by default when the kernel allows it; GODEBUG=multipathtcp=0 turns
# that off for one program. The only complete remedy is a patched kernel and a reboot.
#
# Distributions. Debian, Ubuntu, Trisquel and their derivatives come first: the exact update
# command, the apt evidence and the vendor tracker. RHEL, Alma, Rocky, Fedora, CloudLinux, Oracle
# Linux and Amazon Linux come next, ready to use: the dnf (or yum) advisory check, `needs-restarting`,
# the right kernel package on Amazon Linux 2023 (kernel, kernel6.12 or kernel6.18), and nftables rather
# than the iptables front end that has no u32 match. SUSE, Arch and Alpine get the command and the
# tracker, nothing more. A fixed kernel that is already installed but not running is reported as such.
#
# A container shows the host's kernel, so run this on the host.
#
# Usage:
#   ./linux-kernel-ireq-opt-check.sh [check]
#   check (default)  Exit 0 = the running kernel has the fix (or a vendor backport), 1 =
#                    affected, or a vendor backport could not be confirmed. Read-only.
#   verify [--vmlinux PATH]   Static ground truth, not a guess: disassembles the running kernel's
#                    own two destructors (inet_sock_destruct, tcp_v4_reqsk_destructor) from its
#                    debug image and reports which one calls plain kfree() (the pre-fix shape) and
#                    which calls kvfree_call_rcu() (the fix). Needs a debug image that matches the
#                    running kernel's build-id: Debian/Ubuntu linux-image-RELEASE-dbgsym (Ubuntu's
#                    come from ddebs.ubuntu.com, not the main archive), RHEL/Alma/Rocky/Fedora
#                    debuginfo-install kernel, SUSE kernel-debuginfo. Without --vmlinux it looks in
#                    the usual places for the running release. check runs this automatically when
#                    such an image is found, and its verdict overrides a version/changelog guess
#                    in either direction: it is the strongest evidence this script can offer. Exit
#                    0 = patched, 1 = vulnerable, 2 = no usable image, or the two functions
#                    disagree (not a verdict either way). Read-only.
#   hunt             Read the kernel log for the crash side of the flaw: a call trace through
#                    ip_options_build, ip_build_and_send_pkt, tcp_v4_send_synack,
#                    tcp_v4_reqsk_destructor or inet_sock_destruct, or a skb_under_panic.
#                    It reads dmesg, the journal's kernel messages and the rotated logs under
#                    /var/log (kern.log, syslog, messages). A hit means the kernel faulted in
#                    this code, not that someone attacked it. A clean result is not clearance: a successful exploit need not crash
#                    the host, and a rebooted host has lost its ring buffer. Exit 0 = nothing
#                    in the logs that were read, 1 = hits, 2 = no log could be read. Read-only.
#   mitigate [--mptcp] [--ip-options] [--modules LIST] [--force] [--dry-run]   (root)
#                    changes the host. Reductions, not a fix; they only act when check finds
#                    the kernel affected (--force overrides). Choose what to apply:
#                      --mptcp         net.mptcp.enabled=0, applied now and written to a
#                                      sysctl.d file. Stops new MPTCP sockets; a listener that
#                                      exists keeps listening until its service restarts, and
#                                      this says so. Breaks software that needs MPTCP (some
#                                      mobile and multi-path setups).
#                      --ip-options    drops inbound IPv4 TCP packets that carry IP options,
#                                      with nftables (a table of its own) or, without it,
#                                      iptables (u32 match). Nothing legitimate uses IP options
#                                      on TCP, but a few diagnostic tools do. The rule is not
#                                      saved: a reboot removes it, which is when the patched
#                                      kernel should be running. When a filter of this kind
#                                      is already there (Red Hat's table in RHSB-2026-016,
#                                      say), it adds nothing and rollback leaves that one alone.
#                      --modules LIST  prevents loading of the listed modules, from: mptcp
#                                      and mptcp_diag. all means mptcp: mptcp_diag is what
#                                      ss -M reads, so it is blocked only when named and with
#                                      --force. "install NAME /bin/false" lines in
#                                      a modprobe.d file. MPTCP is built into most kernels, and
#                                      a modprobe rule cannot block what is built in: use
#                                      --mptcp there. A module that is loaded now is left alone
#                                      unless --force, which still only blocks later loads.
#                    --dry-run shows everything and changes nothing. Previous sysctl values are
#                    saved so that rollback can put them back.
#   rollback [--dry-run]   restore the saved sysctl values and remove the files and the packet
#                    filter mitigate wrote.
#   version          print the script version.
#
# Env: KERNEL_CHANGELOG   a vendor changelog file to read, plain or .gz
#      STATE_DIR (default /var/lib/psf-security-patches/linux-kernel-ireq-opt), SYSCTL_D and
#      MODPROBE_D (default /etc/sysctl.d and /etc/modprobe.d) for mitigate and rollback
#      KERNEL_RELEASE, KERNEL_VERSION_STRING   override uname -r and uname -v
#      KERNEL_VMLINUX_FILE   a debug image to use for verify, instead of looking in the usual places
#      KERNEL_NOTES_FILE   instead of /sys/kernel/notes, for the running kernel's build-id
#      KERNEL_MODULES_FILE, KERNEL_PROC_SYS    override /proc/modules and /proc/sys
#      KERNEL_PROTOCOLS_FILE   override /proc/net/protocols (the MPTCP socket count)
#      KERNEL_BUILTIN_FILE   override /lib/modules/<release>/modules.builtin
#      KERNEL_LOG_FILES   kernel log files for hunt, instead of dmesg, journalctl -k and the
#                         usual /var/log files
#      KERNEL_INSTALLED_RELEASES   the kernel releases installed, instead of /lib/modules/*
#      OS_RELEASE_FILE   instead of /etc/os-release
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30); the lock is STATE_DIR/.lock
# =============================================================================

set -uo pipefail

SCRIPT_NAME="linux-kernel-ireq-opt-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/linux-kernel-ireq-opt}"
CVE="CVE-2026-98432"

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

# ---------- the flaw ---------------------------------------------------------
INTRODUCED="4.4"
FIXES="5.10:272 5.15:223 6.1:190 6.6:159 6.12:113 6.18:56 7.2:10"
NEWEST_LISTED="7.2"

# prints: fixed | notaffected | affected | eol | unknown        (for an upstream x.y.z)
#   eol = a branch with no upstream fix listed; anything newer than the newest listed branch
#   carries the mainline fix
kernel_status() {   # <x.y.z>
    local ver="${1%%-*}" maj min pat line e fx
    [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    if ver_lt "$ver" "$INTRODUCED"; then echo notaffected; return; fi
    line="${maj}.${min}"
    for e in $FIXES; do
        if [[ "${e%%:*}" == "$line" ]]; then
            fx="${e#*:}"
            if (( pat >= fx )); then echo fixed; else echo affected; fi
            return
        fi
    done
    if ver_lt "$NEWEST_LISTED" "$line"; then echo fixed; else echo eol; fi
}

# prints: stable <x.y.z> | debian <x.y.z> | vendor
kernel_origin() {
    local rel="$1" ver="$2" up
    if [[ "$ver" =~ Debian[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)- ]]; then echo "debian ${BASH_REMATCH[1]}"; return; fi
    if [[ "$ver" == *Ubuntu* ]] \
       || [[ "$rel" =~ \.(el|fc|amzn|azl|oe|ael)[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+ ]]; then echo vendor; return; fi
    up="${rel%%-*}"
    if [[ "$up" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "stable ${up}"; else echo vendor; fi
}

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

# prints: loaded | builtin | loadable | absent
mod_state() {   # <module> <release>
    local m="$1" rel="$2" mods="${KERNEL_MODULES_FILE:-/proc/modules}" bi="${KERNEL_BUILTIN_FILE:-/lib/modules/$2/modules.builtin}"
    if [[ -r "$mods" ]] && grep -E "^${m} " "$mods" >/dev/null; then echo loaded; return; fi
    if [[ -r "$bi" ]] && grep -E "/${m}\.ko" "$bi" >/dev/null; then echo builtin; return; fi
    if have modinfo && modinfo "$m" >/dev/null 2>&1; then echo loadable; return; fi
    echo absent
}

# prints the value of a /proc/sys entry, or nothing when it is absent
sysval() { local f="${KERNEL_PROC_SYS:-/proc/sys}/$1"; [[ -r "$f" ]] && tr -d '\n' <"$f"; }

# MPTCP sockets in use in this network namespace, listening or not: the count /proc/net/protocols keeps. It does
# not need the mptcp_diag module that ss -M reads, so it still counts when ss -M shows nothing
mptcp_sockets_in_use() {
    local f="${KERNEL_PROTOCOLS_FILE:-/proc/net/protocols}"
    [[ -r "$f" ]] || return 0
    awk '$1 ~ /^MPTCP(v6)?$/ {n += $3; seen = 1} END {if (seen) print n + 0}' "$f"
}

# a filter of the same kind that this script did not add (Red Hat's own table in RHSB-2026-016, say): prints
# what it is and returns 0
ipopt_filter_foreign() {
    local rs t x
    if have nft; then
        rs="$(nft list ruleset 2>/dev/null)"
        t="$(awk '/^table /{t = $2 " " $3} /hdrlength/{print t}' <<<"$rs" | grep -vx 'ip psf_ireq_opt' | head -n 1)"
        [[ -n "$t" ]] && { echo "nftables table ${t#* }"; return 0; }
    fi
    if have iptables; then
        rs="$(iptables -S 2>/dev/null)"
        x="$(grep -E 'u32.*(0>>24&0x0f=6:15|0x0>>0x18&0xf=0x6:0xf)' <<<"$rs" | grep -v 'psf-ireq-opt')"
        [[ -n "$x" ]] && { echo "an iptables rule"; return 0; }
    fi
    return 1
}

# is a filter that drops TCP packets with IP options in place? (ours, or one of the same kind; iptables -S
# prints the u32 argument normalized, 0x0>>0x18&0xf=0x6:0xf, whatever way it was written)
ipopt_filter_present() {
    # the output is captured first: a pipeline into grep -q can fail with SIGPIPE when grep stops at its
    # first match while the command is still writing, and pipefail would then call that "no filter"
    local rs
    if have nft; then rs="$(nft list ruleset 2>/dev/null)"; grep -Eq 'psf_ireq_opt|hdrlength' <<<"$rs" && return 0; fi
    if have iptables; then rs="$(iptables -S 2>/dev/null)"; grep -Eq 'u32.*(0>>24&0x0f=6:15|0x0>>0x18&0xf=0x6:0xf)|psf-ireq-opt' <<<"$rs" && return 0; fi
    return 1
}

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

# the vendor's page for the CVE
tracker_url() {   # <family> <id>
    case "$2" in
        ubuntu) echo "https://ubuntu.com/security/${CVE}"; return ;;
        amzn) echo "https://explore.alas.aws.amazon.com/${CVE}.html"; return ;;
    esac
    case "$1" in
        debian) echo "https://security-tracker.debian.org/tracker/${CVE}" ;;
        rhel) echo "https://access.redhat.com/security/cve/${CVE}" ;;
        suse) echo "https://www.suse.com/security/cve/${CVE}.html" ;;
        arch) echo "https://security.archlinux.org/${CVE}" ;;
        alpine) echo "https://security.alpinelinux.org/vuln/${CVE}" ;;
        *) echo "https://nvd.nist.gov/vuln/detail/${CVE}" ;;
    esac
}

# the update command for this system, then the vendor's page
update_advice() {   # <family> <id> <version_id> <release>
    local fam="$1" id="$2" vid="$3" rel="$4" pkg=kernel
    case "$fam" in
        debian) inf "update: sudo apt update && sudo apt full-upgrade, then reboot (full-upgrade, not upgrade: a new linux-image package comes in as a new dependency, which plain upgrade holds back)" ;;
        rhel)
            if [[ "$id" == amzn ]]; then
                if [[ "$vid" == 2 ]]; then inf "update: sudo yum update kernel && sudo reboot"
                else
                    [[ "$rel" =~ ^6\.12\. ]] && pkg=kernel6.12
                    [[ "$rel" =~ ^6\.18\. ]] && pkg=kernel6.18
                    inf "update: sudo dnf update ${pkg} --releasever=latest && sudo reboot (an Amazon Linux 2023 instance locked to a release needs 2023.12.20261102 or later, per AWS)"
                fi
            elif have dnf; then inf "update: sudo dnf update kernel && sudo reboot. To see whether your repositories have the advisory: sudo dnf updateinfo list --cve ${CVE}. After the reboot: needs-restarting -r"
            else inf "update: sudo yum update kernel && sudo reboot"; fi ;;
        suse)   inf "update: sudo zypper refresh && sudo zypper patch (or update kernel-default), then reboot" ;;
        arch)   inf "update: sudo pacman -Syu, then reboot" ;;
        alpine) inf "update: sudo apk update && sudo apk upgrade, then reboot" ;;
        *)      inf "update the kernel with your distribution's package manager and reboot" ;;
    esac
    inf "vendor page: $(tracker_url "$fam" "$id")"
    [[ "$id" == ubuntu ]] && inf "Ubuntu publishes the fix in the -proposed pocket first, then in the regular archive: https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432"
    [[ "$fam" == rhel && "$id" != amzn ]] && inf "Red Hat bulletin: https://access.redhat.com/security/vulnerabilities/RHSB-2026-016"
}

# what the package manager already knows, from cached data only (no network)
pm_evidence() {   # <family>
    local out
    case "$1" in
        debian)
            if have apt && out="$(apt list --upgradable 2>/dev/null | grep -E '^linux-(image|generic|signed|headers-generic)' | head -n 3 | cut -d/ -f1 | tr '\n' ' ')" && [[ -n "$out" ]]; then
                inf "apt lists a newer kernel package: ${out}(from the cached package lists; apt changelog shows whether it names ${CVE})"
            fi ;;
        rhel)
            if have dnf && out="$(dnf -q -C updateinfo list --cve "$CVE" 2>/dev/null | grep -F "$CVE" | head -n 2)" && [[ -n "$out" ]]; then
                inf "the cached repository data has an advisory that names ${CVE}: $(echo "$out" | head -n 1 | tr -s ' ')"
            elif have yum && ! have dnf && out="$(yum -q -C updateinfo list cves 2>/dev/null | grep -F "$CVE" | head -n 2)" && [[ -n "$out" ]]; then
                inf "the cached repository data has an advisory that names ${CVE}: $(echo "$out" | head -n 1 | tr -s ' ')"
            fi ;;
    esac
    return 0
}

# the first installed kernel, other than the running one, whose changelog names the CVE
installed_fixed_kernel() {   # <running release>
    local run="$1" r d
    local -a rels=()
    if [[ -n "${KERNEL_INSTALLED_RELEASES:-}" ]]; then for r in $KERNEL_INSTALLED_RELEASES; do rels+=("$r"); done
    else for d in /lib/modules/*; do [[ -d "$d" ]] && rels+=("${d##*/}"); done; fi
    for r in "${rels[@]+"${rels[@]}"}"; do
        [[ "$r" == "$run" ]] && continue
        if changelog_names "$r" "$CVE"; then echo "$r"; return 0; fi
    done
    return 1
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

# ---------- static verification (disassembly of the running kernel's own debug image) --------
# This is ground truth, not a guess: it reads the two functions the fix changed and reports which
# shape of the free call each one has. KERNEL_VMLINUX_FILE and KERNEL_NOTES_FILE (default
# /sys/kernel/notes) let the test suite and an operator with an unusual layout point this at a
# file directly.
STATIC_FUNCS="inet_sock_destruct tcp_v4_reqsk_destructor"
locate_vmlinux() {
    local rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}" cand
    if [[ -n "${KERNEL_VMLINUX_FILE:-}" ]]; then echo "$KERNEL_VMLINUX_FILE"; return 0; fi
    for cand in "/usr/lib/debug/boot/vmlinux-${rel}" "/boot/vmlinux-${rel}" "/usr/lib/debug/lib/modules/${rel}/vmlinux"; do
        [[ -r "$cand" ]] && { echo "$cand"; return 0; }
    done
    return 1
}
no_debug_image_help() {
    local rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"
    inf "no kernel debug image was found for ${rel}. This needs one that matches it: Debian/Ubuntu"
    inf "  apt install linux-image-${rel}-dbgsym (Ubuntu's come from ddebs.ubuntu.com, not the main"
    inf "  archive: see the Ubuntu wiki page \"DebugSymbolPackages\" to enable it); RHEL, Alma, Rocky,"
    inf "  Fedora: dnf debuginfo-install kernel (or kernel-core); SUSE: zypper install kernel-debuginfo."
    inf "  Or pass --vmlinux PATH if you already have a matching image somewhere else."
}
# disassemble_calls FUNC VMLINUX: the call targets found in FUNC's disassembly, one per line, or
# nothing (and a non-zero return) if the symbol was not found in this image.
disassemble_calls() {
    local fn="$1" vmlinux="$2" out
    out="$(objdump -d --no-show-raw-insn --disassemble="$fn" "$vmlinux" 2>/dev/null)"
    grep -qE "^[0-9a-f]+ <${fn}>:" <<<"$out" || return 1
    grep -oE 'call[[:space:]]+[0-9a-f]+ <[A-Za-z0-9_.@]+>' <<<"$out" | sed -E 's/.*<([A-Za-z0-9_.@]+)>.*/\1/; s/@.*$//'
}
# cmd_verify: read-only. Exit 0 = both destructors still call kfree (vulnerable), 1 = both call
# kvfree_call_rcu (patched), 2 = no usable image, the two functions disagree, or one is unreadable.
cmd_verify() {
    local vmlinux=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --vmlinux) vmlinux="${2:?--vmlinux needs a path}"; shift 2 ;;
            --vmlinux=*) vmlinux="${1#--vmlinux=}"; shift ;;
            *) die "verify: unknown argument: $1 (usage: verify [--vmlinux PATH])" ;;
        esac
    done
    step "Static verification (disassembly of the running kernel's own debug image)"
    if ! have objdump || ! have readelf; then
        caution "objdump and readelf are both needed for this and were not found: install binutils"
        return 2
    fi
    [[ -n "$vmlinux" ]] || vmlinux="$(locate_vmlinux || true)"
    if [[ -z "$vmlinux" || ! -r "$vmlinux" ]]; then no_debug_image_help; return 2; fi
    inf "image: ${vmlinux}"
    local notes="${KERNEL_NOTES_FILE:-/sys/kernel/notes}" running_bid image_bid match=""
    running_bid="$(readelf -n "$notes" 2>/dev/null | awk '/Build ID/{print $NF; exit}')"
    image_bid="$(readelf -n "$vmlinux" 2>/dev/null | awk '/Build ID/{print $NF; exit}')"
    if [[ -z "$image_bid" ]]; then caution "could not read a build-id from ${vmlinux}: this may not be a kernel debug image"
    elif [[ -z "$running_bid" ]]; then caution "the running kernel's build-id could not be read from ${notes}: the match with ${vmlinux} could not be confirmed"
    elif [[ "$running_bid" == "$image_bid" ]]; then ok "this image's build-id matches the running kernel (${image_bid}): the verdict below is for what is actually running"; match=1
    else bad "this image's build-id (${image_bid}) does not match the running kernel's (${running_bid}): ${vmlinux} is not what is running, and the verdict below does not apply to it"; match=0
    fi
    local fn calls has_kfree has_kvfree n_vuln=0 n_patched=0 n_unknown=0 n_mixed=0
    for fn in $STATIC_FUNCS; do
        if ! calls="$(disassemble_calls "$fn" "$vmlinux")"; then
            inf "  ${fn}: symbol not found in this image (stripped, renamed, or inlined differently)"; n_unknown=$((n_unknown+1)); continue
        fi
        has_kfree=0; has_kvfree=0
        grep -qx 'kfree' <<<"$calls" && has_kfree=1
        grep -qx 'kvfree_call_rcu' <<<"$calls" && has_kvfree=1
        if [[ $has_kfree -eq 1 && $has_kvfree -eq 0 ]]; then bad "  ${fn}: calls kfree (the shape before the fix)"; n_vuln=$((n_vuln+1))
        elif [[ $has_kvfree -eq 1 && $has_kfree -eq 0 ]]; then ok "  ${fn}: calls kvfree_call_rcu (the fixed shape)"; n_patched=$((n_patched+1))
        elif [[ $has_kfree -eq 1 && $has_kvfree -eq 1 ]]; then caution "  ${fn}: calls both kfree and kvfree_call_rcu: cannot tell which one frees the option pointer"; n_mixed=$((n_mixed+1))
        else inf "  ${fn}: neither kfree nor kvfree_call_rcu appears in its disassembly: inconclusive"; n_unknown=$((n_unknown+1))
        fi
    done
    step "Static verdict"
    local label rc
    if [[ $n_mixed -gt 0 || ( $n_vuln -gt 0 && $n_patched -gt 0 ) ]]; then
        caution "the two functions do not agree: this is not a clean verdict. Treat it as inconclusive and rely on check's version and changelog evidence instead."
        label=UNKNOWN; rc=2
    elif [[ $n_vuln -gt 0 ]]; then
        bad "both destructors have the pre-fix shape: VULNERABLE, by direct inspection of the running kernel's own code"
        label=VULNERABLE; rc=1
    elif [[ $n_patched -gt 0 ]]; then
        ok "both destructors have the fixed shape: PATCHED, by direct inspection of the running kernel's own code"
        label=PATCHED; rc=0
    else
        inf "neither destructor could be classified in this image"
        label=UNKNOWN; rc=2
    fi
    if [[ "$match" == 0 ]]; then
        caution "that verdict is for ${vmlinux}, which is not the running kernel's own image, so it is reported as inconclusive here"
        label=UNKNOWN; rc=2
    fi
    echo "STATIC_VERDICT=${label}"
    return "$rc"
}

cmd_check() {
    local rc=0 rel ver origin kind up st v ms n p mpv
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"; ver="${KERNEL_VERSION_STRING:-$(uname -v 2>/dev/null)}"
    step "Running kernel"
    [[ -n "$rel" ]] || { caution "uname -r returned nothing: cannot check"; return 1; }
    inf "release: ${rel}"
    origin="$(kernel_origin "$rel" "$ver")"; kind="${origin%% *}"; up=""; [[ "$origin" == *" "* ]] && up="${origin#* }"
    case "$kind" in
        stable) inf "origin: follows the stable series; upstream version ${up}" ;;
        debian) inf "origin: Debian; upstream version ${up} (from uname -v)" ;;
        *)      inf "origin: a vendor kernel that backports fixes; its release string does not show which" ;;
    esac
    # a stable release candidate (6.12.113-rc1) comes before the release it leads to and may not
    # carry the fix: judge it as the release before it
    if [[ "$kind" == stable && "$rel" =~ -rc[0-9]+ && "$up" =~ ^([0-9]+\.[0-9]+)\.([0-9]+)$ && "${BASH_REMATCH[2]}" -gt 0 ]]; then
        up="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] - 1 ))"; inf "a release candidate is not the release: judged as the release before it, ${up}"
    fi
    step "${CVE}"
    if [[ -n "$up" ]]; then st="$(kernel_status "$up")"; else st=vendor; fi
    case "$st" in
        fixed)       ok "upstream ${up} is at or beyond the first fixed release of its branch" ;;
        notaffected) ok "upstream ${up} is not affected (the bug came in with ${INTRODUCED})" ;;
        affected|eol|unknown|vendor)
            if changelog_names "$rel" "$CVE"; then
                ok "the vendor changelog names ${CVE}: this kernel carries a backport, so its version number understates its state"
            else
                case "$st" in
                    affected) bad "upstream ${up} is below the first fixed release of its branch" ;;
                    eol)      bad "upstream ${up} is on a branch with no upstream fix listed (end of life): only a vendor backport fixes it" ;;
                    unknown)  caution "cannot parse upstream version '${up}', and the vendor changelog does not name ${CVE}" ;;
                    vendor)   caution "the vendor changelog does not name ${CVE} (or is not readable), and this release string cannot be compared with the upstream table: check your vendor's page for ${CVE}: $(tracker_url "$(os_info | cut -d' ' -f1)" "$(os_info | cut -d' ' -f2)")" ;;
                esac
                rc=1
            fi ;;
    esac
    # If this host's own debug image is present, static disassembly is ground truth and can
    # override the version/changelog guess above in either direction. Silent when no image is
    # there (the common case): run `verify` on its own for the installation pointer.
    local vmlinux_auto static_rc=9
    if have objdump && have readelf && vmlinux_auto="$(locate_vmlinux 2>/dev/null)"; then
        cmd_verify --vmlinux "$vmlinux_auto"; static_rc=$?
        case "$static_rc" in
            0) if [[ $rc -eq 1 ]]; then ok "static verification overrides the guess above: this exact kernel's code already has the fix (both destructors call kvfree_call_rcu), whatever its version string or changelog say"; rc=0
               else ok "static verification agrees: this kernel has the fix" ; fi ;;
            1) if [[ $rc -eq 0 ]]; then bad "static verification overrides the guess above: this exact kernel's code is still vulnerable (both destructors call plain kfree), despite the version/changelog evidence saying it is fixed. Trust the code"; rc=1
               else bad "static verification agrees: this kernel is vulnerable" ; fi ;;
            *) : ;;
        esac
    fi
    if [[ $rc -eq 1 ]]; then
        step "Exposure (information; a kernel below its fixed release is affected whatever this shows)"
        v="$(sysval net/mptcp/enabled)"; ms="$(mod_state mptcp "$rel")"
        case "$v" in
            1) inf "MPTCP is on (net.mptcp.enabled=1): the flaw is reported as remote code execution against an MPTCP listener" ;;
            0) inf "MPTCP is off (net.mptcp.enabled=0): that reduces the conditions for running code; a crash stays possible" ;;
            *) inf "this kernel has no net.mptcp.enabled switch (no MPTCP, or it cannot be read here)" ;;
        esac
        inf "mptcp module: ${ms}"
        mpv="$v"; p="$(mptcp_sockets_in_use)"
        [[ -n "$p" ]] && inf "MPTCP sockets in use, listening or not (/proc/net/protocols): ${p}"
        if have ss; then
            if ss -H -M -l -n >/dev/null 2>&1; then n="$(ss -H -M -l -n 2>/dev/null | wc -l | tr -d ' ')"; inf "MPTCP listening sockets: ${n}"
                if [[ -n "$p" && "$p" -gt 0 && "$n" -eq 0 ]]; then caution "ss -M lists no MPTCP socket but /proc/net/protocols counts ${p}: ss -M reads the mptcp_diag module, which may not be loaded (on Ubuntu cloud kernels it is in linux-modules-extra-${rel}). Run modprobe mptcp_diag and look again, or go by the count"; fi
                if [[ "$v" == 0 && "$n" -gt 0 ]]; then caution "${n} MPTCP listening socket(s) still exist: net.mptcp.enabled=0 stops new MPTCP sockets and does not close these. Restart the services that own them (ss -M -l -p shows which)"; fi
            else inf "this ss has no -M option: MPTCP sockets were not counted"; fi
            n="$(ss -H -4 -t -l -n 2>/dev/null | awk '{print $4}' | grep -vEc '^(127\.|\[?::1)')"; inf "IPv4 TCP listeners that are not on loopback: ${n} (any of them is reachable by the attack unless a filter stands in front)"
        else inf "ss was not found: the listeners were not counted"; fi
        [[ "$mpv" == 0 || "$mpv" == 1 ]] && inf "net.mptcp.enabled, ss and /proc/net/protocols describe this network namespace only. A container with its own namespace has its own value (a new namespace starts at 1, whatever the host says) and is not shown here: look from inside it, or with nsenter -t PID -n"
        v="$(sysval net/ipv4/tcp_migrate_req)"
        case "$v" in 1) inf "net.ipv4.tcp_migrate_req=1: the request socket migration path is open too" ;; 0) inf "net.ipv4.tcp_migrate_req=0 (the default): the migration path is closed unless a BPF program does it" ;; *) inf "net.ipv4.tcp_migrate_req could not be read" ;; esac
        if ipopt_filter_present; then inf "a filter that drops TCP packets with IP options is in place"
        else inf "no filter that drops TCP packets with IP options was found. Some network edges drop such packets before they reach any host behind them; that is not something this script, or you, can see from here, and it is not something to rely on: the SYN only needs to reach this host once"; fi
    fi
    local fam fid fvid fixedk=""
    read -r fam fid fvid <<<"$(os_info)"
    if [[ $rc -eq 1 ]]; then
        pm_evidence "$fam"
        if fixedk="$(installed_fixed_kernel "$rel")"; then inf "kernel ${fixedk} is installed and its changelog names ${CVE}: you are running ${rel}"; fi
    fi
    if v="$(pending_reboot "$rel")"; then inf "$v"; fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The running kernel has the fix for ${CVE} (or a vendor backport)."
    elif [[ -n "$fixedk" ]]; then
        warn "The running kernel is affected, but a kernel that names ${CVE} is already installed (${fixedk}). Reboot into it."
        update_advice "$fam" "$fid" "$fvid" "$rel"
    else
        warn "The running kernel is affected by ${CVE}, or a fix could not be confirmed. Update to your vendor's fixed kernel and reboot: that is the only complete remedy."
        update_advice "$fam" "$fid" "$fvid" "$rel"
        inf "Upstream first fixed releases: 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10 and 7.3"
        inf "Until then, reductions only: mitigate --mptcp (net.mptcp.enabled=0), mitigate --ip-options (drop TCP packets that carry IP options), and no MPTCP listeners (GODEBUG=multipathtcp=0 for Go programs)"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local rc=0 nsrc=0 f out hits total=0 pat='ip_options_build|ip_build_and_send_pkt|tcp_v4_send_synack|tcp_v4_reqsk_destructor|inet_sock_destruct|skb_under_panic'
    step "Kernel log"
    limited_view "kernel logs"
    local -a files=()
    if [[ -n "${KERNEL_LOG_FILES:-}" ]]; then for f in $KERNEL_LOG_FILES; do files+=("$f"); done
    else for f in /var/log/kern.log* /var/log/syslog* /var/log/messages*; do [[ -f "$f" ]] && files+=("$f"); [[ ${#files[@]} -ge 24 ]] && break; done; fi
    for f in "${files[@]+"${files[@]}"}"; do
        if [[ ! -r "$f" ]]; then caution "${f} exists but cannot be read by this user"; rc=2; continue; fi
        nsrc=$((nsrc+1)); hits="$(zcat -f "$f" 2>/dev/null | grep -cE "$pat" || true)"
        if [[ "$hits" -gt 0 ]]; then bad "${hits} line(s) in ${f} name the code this flaw is in"; total=$((total+hits)); zcat -f "$f" 2>/dev/null | grep -E "$pat" | head -n 3 | sed 's/^/        /'; else ok "${f}: nothing"; fi
    done
    if [[ -z "${KERNEL_LOG_FILES:-}" ]]; then
        if have dmesg && out="$(dmesg 2>/dev/null)" && [[ -n "$out" ]]; then
            nsrc=$((nsrc+1)); hits="$(printf '%s\n' "$out" | grep -cE "$pat" || true)"
            if [[ "$hits" -gt 0 ]]; then bad "${hits} line(s) in the kernel ring buffer name the code this flaw is in"; total=$((total+hits)); printf '%s\n' "$out" | grep -E "$pat" | head -n 3 | sed 's/^/        /'; else ok "kernel ring buffer: nothing"; fi
        fi
        if have journalctl && out="$(journalctl -k --no-pager -q 2>/dev/null)" && [[ -n "$out" ]]; then
            nsrc=$((nsrc+1)); hits="$(printf '%s\n' "$out" | grep -cE "$pat" || true)"
            if [[ "$hits" -gt 0 ]]; then bad "${hits} line(s) in the journal's kernel messages name the code this flaw is in"; total=$((total+hits)); printf '%s\n' "$out" | grep -E "$pat" | head -n 3 | sed 's/^/        /'; else ok "journal kernel messages: nothing"; fi
        fi
    fi
    step "Verdict"
    if [[ $total -gt 0 ]]; then
        warn "The kernel faulted in the code this flaw is in. That is a lead, not proof of an attack: look at the full trace and at what connected just before it."
        return 1
    elif [[ $nsrc -eq 0 ]]; then
        warn "No kernel log could be read, so nothing was judged. This is not a clean result."; return 2
    elif [[ $rc -eq 2 ]]; then
        warn "Nothing in the logs that could be read, but not every log could be read: this is not a clean result."; return 2
    fi
    info "Nothing in the kernel logs that were read (${nsrc})."
    inf "That is not clearance: a successful exploit need not crash the host, and a reboot clears the ring buffer."
    return 0
}

# ---------- mitigate and rollback --------------------------------------------
LM_MANIFEST=""; LM_DRY=0
lm_note() { [[ "$LM_DRY" -eq 1 ]] || echo "$1" >>"$LM_MANIFEST"; }
lm_valid_mods="mptcp mptcp_diag"
FILTER_COMMENT="psf-ireq-opt"

lm_sysctl_set() {   # path-under-proc-sys value
    local ps="${KERNEL_PROC_SYS:-/proc/sys}" f old
    f="$ps/$1"; old="$(cat "$f" 2>/dev/null)"
    if [[ "$LM_DRY" -eq 1 ]]; then echo "  would set ${1//\//.}=$2 (now ${old:-unreadable})"; return 0; fi
    if printf '%s\n' "$2" >"$f" 2>/dev/null; then
        lm_note "sysctl|$1|${old}"; ok "set ${1//\//.}=$2 (was ${old:-unknown}), applied now"; return 0
    fi
    bad "could not write ${f}: read-only /proc/sys (a container?) or no permission"; return 1
}

# net.mptcp.enabled=0 stops new MPTCP sockets: a listener that exists keeps listening until its service restarts
lm_mptcp_listeners_note() {
    local n="" p
    if have ss && ss -H -M -l -n >/dev/null 2>&1; then n="$(ss -H -M -l -n 2>/dev/null | wc -l | tr -d ' ')"; fi
    p="$(mptcp_sockets_in_use)"
    if [[ -n "$n" && "$n" -gt 0 ]]; then
        caution "${n} MPTCP listening socket(s) already exist: the sysctl does not close them. Restart the services that own them (ss -M -l -p shows which); they then cannot create MPTCP sockets"
    elif [[ -n "$p" && "$p" -gt 0 ]]; then
        caution "${p} MPTCP socket(s) are in use (/proc/net/protocols; ss -M lists none, so mptcp_diag is probably not loaded): the sysctl does not close them. Restart the services that own them"
    fi
    caution "net.mptcp.enabled was set in this network namespace only. A container with its own namespace keeps its own value: start it with --sysctl net.mptcp.enabled=0 (Docker, Podman), or set it from inside"
    return 0
}

cmd_mitigate() {
    local mptcp=0 ipopt=0 mods="" force=0 rc=0 rel ps m st sd md mf did=0 mt other
    local -a want=() mlines=()
    LM_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mptcp) mptcp=1 ;; --ip-options) ipopt=1 ;; --force) force=1 ;; --dry-run) LM_DRY=1 ;;
            --modules) shift; mods="${1:-}"; [[ -n "$mods" ]] || die "--modules needs a comma separated list (${lm_valid_mods// /,} or all)" ;;
            *) die "Unknown mitigate option: $1 (--mptcp --ip-options --modules LIST --force --dry-run)" ;;
        esac
        shift
    done
    [[ $mptcp -eq 1 || $ipopt -eq 1 || -n "$mods" ]] || die "mitigate needs --mptcp, --ip-options and/or --modules LIST, because each measure can break software that depends on it (see --help). Nothing was changed."
    if [[ -n "$mods" ]]; then
        [[ "$mods" == all ]] && mods="mptcp"
        for m in ${mods//,/ }; do
            case " $lm_valid_mods " in *" $m "*) want+=("$m") ;; *) die "not a module this tool knows: ${m} (${lm_valid_mods// /,})" ;; esac
        done
    fi
    [[ $LM_DRY -eq 1 ]] || need_root "mitigate changes the host"
    rel="${KERNEL_RELEASE:-$(uname -r)}"; ps="${KERNEL_PROC_SYS:-/proc/sys}"
    step "Is this kernel affected?"
    if cmd_check >/dev/null 2>&1; then
        if [[ $force -eq 0 ]]; then info "check finds this kernel fixed (or carrying vendor backports): nothing to do (use --force to apply anyway)"; return 0; fi
        caution "check finds this kernel fixed, applying anyway because of --force"
    else bad "check finds kernel ${rel} affected or no vendor backport is confirmed: applying the measures you chose"; fi
    if [[ $LM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        take_lock
        LM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$LM_MANIFEST"
    else LM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    sd="${SYSCTL_D:-/etc/sysctl.d}"; md="${MODPROBE_D:-/etc/modprobe.d}"
    if [[ $mptcp -eq 1 ]]; then
        step "MPTCP"
        if [[ -e "$ps/net/mptcp/enabled" ]]; then
            if lm_sysctl_set "net/mptcp/enabled" 0; then
                did=1
                if [[ $LM_DRY -eq 0 ]]; then
                    lm_mptcp_listeners_note
                    mkdir -p "$sd" && { printf '# psf-security-patches: %s protective measure (linux-kernel-ireq-opt-check.sh mitigate). Remove with: rollback\nnet.mptcp.enabled = 0\n' "$CVE" >"$sd/99-psf-kernel-ireq-opt.conf"; lm_note "file|$sd/99-psf-kernel-ireq-opt.conf"; ok "written ${sd}/99-psf-kernel-ireq-opt.conf (kept across reboots)"; }
                else echo "  would write ${sd}/99-psf-kernel-ireq-opt.conf"; fi
            else rc=1; fi
        else inf "this kernel has no net.mptcp.enabled switch: no MPTCP to turn off"; fi
    fi
    if [[ $ipopt -eq 1 ]]; then
        step "Drop TCP packets that carry IP options"
        if other="$(ipopt_filter_foreign)"; then
            inf "a filter that drops TCP packets with IP options is already in place (${other}): not adding a second one. Remove it first if you want this script's own"
        elif have nft; then
            if [[ $LM_DRY -eq 1 ]]; then echo "  would run: nft add table ip psf_ireq_opt, a chain at hook input, and the rule: ip protocol tcp ip hdrlength gt 5 counter drop"
            elif nft add table ip psf_ireq_opt 2>/dev/null \
               && nft add chain ip psf_ireq_opt input '{ type filter hook input priority -300 ; policy accept ; }' 2>/dev/null \
               && nft add rule ip psf_ireq_opt input ip protocol tcp ip hdrlength gt 5 counter drop 2>/dev/null; then
                lm_note "nft|psf_ireq_opt"; ok "nftables table psf_ireq_opt drops inbound IPv4 TCP packets with IP options (not saved: a reboot removes it)"; did=1
                if have systemctl && systemctl is-active --quiet firewalld 2>/dev/null; then inf "firewalld is running: it keeps its own tables, so this one sits beside them. Look at nft list ruleset after a firewalld reload to see that it is still there"; fi
            else bad "nft could not add the rule (a missing nf_tables module, or no permission)"; nft delete table ip psf_ireq_opt 2>/dev/null; rc=1; fi
        elif have iptables && [[ "$(iptables -V 2>/dev/null)" == *nf_tables* ]]; then
            caution "this iptables is the nftables front end, which has no u32 match (the RHEL 8 and later default). Install nftables (sudo dnf install nftables, or sudo apt install nftables) and run this again: it adds a table of its own and needs no u32"; rc=1
        elif have iptables; then
            if [[ $LM_DRY -eq 1 ]]; then echo "  would run: iptables -I INPUT 1 -p tcp -m u32 --u32 '0>>24&0x0f=6:15' -m comment --comment ${FILTER_COMMENT} -j DROP"
            elif iptables -w -C INPUT -p tcp -m u32 --u32 '0>>24&0x0f=6:15' -m comment --comment "$FILTER_COMMENT" -j DROP 2>/dev/null; then inf "the iptables rule is already there"
            elif iptables -w -I INPUT 1 -p tcp -m u32 --u32 '0>>24&0x0f=6:15' -m comment --comment "$FILTER_COMMENT" -j DROP 2>/dev/null; then
                lm_note "ipt|${FILTER_COMMENT}"; ok "iptables rule drops inbound IPv4 TCP packets with IP options (not saved: a reboot removes it)"; did=1
            else bad "iptables could not add the rule (no u32 match in this kernel, or no permission)"; rc=1; fi
        else caution "neither nft nor iptables was found: no packet filter was added"; rc=1; fi
    fi
    if [[ " ${want[*]} " == *" mptcp_diag "* && $force -eq 0 ]]; then
        local -a w2=(); for m in "${want[@]}"; do [[ "$m" == mptcp_diag ]] || w2+=("$m"); done; want=("${w2[@]+"${w2[@]}"}")
        caution "mptcp_diag: left alone: it is the module ss -M reads, so blocking it hides the MPTCP listeners you would look for, and the flawed code is in IPv4 TCP, not in this module. --force blocks it anyway"
    fi
    if [[ ${#want[@]} -gt 0 ]]; then
        step "Module loading"
        [[ " ${want[*]} " == *" mptcp_diag "* ]] && inf "mptcp_diag is the module ss -M reads to list MPTCP sockets: blocking it hides the listeners you would look for. The flawed code is in IPv4 TCP, not in this module"
        for m in "${want[@]}"; do
            st="$(mod_state "$m" "$rel")"
            case "$st" in
                loaded) if [[ $force -eq 1 ]]; then caution "${m}: loaded now; blocking later loads only (it stays loaded until reboot or unload)"; mlines+=("$m")
                        else caution "${m}: loaded and probably in use: left alone (--force blocks later loads only)"; fi ;;
                builtin) inf "${m}: built into the kernel: a modprobe rule cannot block it. Use --mptcp" ;;
                absent) inf "${m}: not present on this kernel: nothing to block" ;;
                *) mlines+=("$m") ;;
            esac
        done
        if [[ ${#mlines[@]} -gt 0 ]]; then
            mf="$md/psf-kernel-ireq-opt.conf"
            mt="# psf-security-patches: ${CVE} protective measure (linux-kernel-ireq-opt-check.sh mitigate). Remove with: rollback"
            for m in "${mlines[@]}"; do mt+=$'\n'"blacklist ${m}"$'\n'"install ${m} /bin/false"; done
            if [[ $LM_DRY -eq 1 ]]; then echo "  would write ${mf}:"; printf '%s\n' "$mt" | sed 's/^/      /'
            else
                mkdir -p "$md" && printf '%s\n' "$mt" >"$mf" && { lm_note "file|${mf}"; ok "loading blocked for: ${mlines[*]} (${mf})"; did=1; }
            fi
        fi
    fi
    step "Result"
    if [[ $LM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Applied. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    inf "These reduce the exposure. They do not fix the flaw: the fix is a patched kernel and a reboot."
    return "$rc"
}

cmd_rollback() {
    local line kind rest path old f rc=0 ps="${KERNEL_PROC_SYS:-/proc/sys}"
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
            sysctl) path="${rest%%|*}"; old="${rest#*|}"
                if [[ -z "$old" ]]; then caution "${path//\//.}: previous value unknown, left alone"; rc=1; continue; fi
                if [[ $LM_DRY -eq 1 ]]; then echo "  would set ${path//\//.}=${old}"; elif printf '%s\n' "$old" >"$ps/$path" 2>/dev/null; then ok "restored ${path//\//.}=${old}"; else bad "could not restore ${path//\//.}"; rc=1; fi ;;
            file) f="$rest"; if [[ $LM_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
            nft) if [[ $LM_DRY -eq 1 ]]; then echo "  would run: nft delete table ip ${rest}"; elif have nft && nft delete table ip "$rest" 2>/dev/null; then ok "removed the nftables table ${rest}"; else caution "could not remove the nftables table ${rest} (already gone?)"; fi ;;
            ipt) if [[ $LM_DRY -eq 1 ]]; then echo "  would run: iptables -D INPUT ... (comment ${rest})"; elif have iptables && iptables -w -D INPUT -p tcp -m u32 --u32 '0>>24&0x0f=6:15' -m comment --comment "$rest" -j DROP 2>/dev/null; then ok "removed the iptables rule"; else caution "could not remove the iptables rule (already gone?)"; fi ;;
        esac
    done <"$LM_MANIFEST"
    if [[ $LM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$LM_MANIFEST" "${LM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. MPTCP and the blocked modules are as they were."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}: Linux kernel IPv4 TCP use-after-free, remote code execution with an MPTCP listener"
    case "$CMD" in
        check) cmd_check "$@" ;;
        verify) cmd_verify "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|verify|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
