#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# psf-run: manual (check needs the names of the modules)
# =============================================================================
# Linux kernel module blocker: list, check, block, status, rollback  (v1)
# Generic. A curated list of modules behind recent kernel flaws, or any name you give it.
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Many kernel flaws sit in a module that almost nobody needs and that loads by itself the
# moment an unprivileged process opens the right socket or a device appears. Stopping that
# module from loading removes the attack surface until a patched kernel is running. This
# script does it the way the kernel documents, with a file of its own in modprobe.d for each
# module, a manifest, and a rollback, and it tells you when a block cannot work.
#
# What a block is. A `blacklist NAME` line stops the alias-based autoload, and an
# `install NAME /bin/false` line also stops an explicit `modprobe NAME`. Both are written to
# /etc/modprobe.d/psf-block-NAME.conf. Names are normalized: a hyphen and an underscore are the
# same thing to the kernel.
#
# What a block cannot do, and what the script does about it:
#   built into the kernel   no modprobe rule can block it. The script refuses, and prints the
#                           switch the list knows for it (a sysctl, for MPTCP).
#   loaded now              it stays loaded until it is unloaded or the host reboots. The script
#                           refuses unless you pass --force, which writes the rule anyway, and
#                           --unload tries `modprobe -r` afterwards (it fails if something uses
#                           the module).
#   in the initramfs        a module can load from the initramfs before modprobe.d is read. After
#                           a block the script prints the command that rebuilds it for this
#                           system; --initramfs runs it (update-initramfs on Debian, Ubuntu and
#                           Trisquel; dracut with -I on the RPM family and SUSE, because dracut
#                           reads /etc/modprobe.d only for a host-only image). It is off by default because a rebuild
#                           is slow and can fail on a full /boot.
#   a module others need    blocking a module also stops the modules that depend on it: modprobe runs
#                           the install rule of the blocked dependency, which fails, so the
#                           dependent cannot load either. Blocking only the dependent leaves the base
#                           module loadable. The list names both for a CVE and --cve blocks both.
#   needed to boot or log in  a short protected list (storage, the root filesystems, USB host and
#                           input drivers, virtio, device mapper) is refused, even with --force.
#                           Only --force --allow-protected overrides it.
#
# The list. Three groups, labeled for what they are:
#   exploited   modules behind flaws that this collection has a tool for (the CVE is shown)
#   historic    modules behind older kernel local root or remote flaws that are well known
#   hardening   modules that almost no system needs and that carry attack surface (CIS style:
#               rare filesystems and network protocols, DMA buses, USB storage). No CVE is
#               claimed for these. Blocking them is a policy choice.
# Each row says what a block breaks. Add your own rows with --list-file. A row ending in "keep" marks a
# module that detection depends on (mptcp_diag, which ss -M reads): --group and --cve skip it, and it is
# blocked only when named and with --force, because blocking it hides what you are looking for.
#
# Usage:
#   ./linux-kernel-module-block.sh [list]
#   list   [--group exploited|historic|hardening|all] [--present] [--list-file FILE]
#                    the table, with the state of each module on this host: loaded, built in,
#                    loadable or absent, and whether a block is in place. --present shows only
#                    the modules this host has. Read-only.
#   check  NAME...   for any module: its state, what holds it, its aliases, how it autoloads,
#                    and where it is blocked already. Exit 0 = every module named is absent or
#                    blocked, 1 = at least one is present and can still load. Read-only.
#   block  NAME... | --group G | --cve ID   [--force] [--unload] [--initramfs]
#                    [--even-if-absent] [--allow-protected] [--list-file FILE] [--dry-run]
#                    (root) changes the host: writes the block files and a manifest.
#                    --group blocks every module of a group, --cve every module that lists the
#                    CVE. Built-in and loaded modules are skipped with the reason.
#   status           what this script blocked, and whether each block is effective: the file is
#                    still there and unchanged, and the module is not loaded. Exit 0 = all
#                    effective, 1 = at least one is not. Read-only.
#   rollback [NAME...] [--force] [--initramfs] [--dry-run]   (root) removes the block files
#                    this script wrote (all, or the named ones). A file you edited since is
#                    kept unless --force.
#   version          print the script version.
#
# Exit codes: 0 done, or nothing found; 1 something needs attention (check: a module is present and can
# still load; status: a block is not effective; block or rollback: something was refused or failed, and
# the rest was done); 2 usage error, or the run cannot go on (nothing was changed).
#
# Env: STATE_DIR (default /var/lib/psf-security-patches/linux-kernel-module-block) and
#      MODPROBE_D (default /etc/modprobe.d)
#      KERNEL_RELEASE   override uname -r
#      KERNEL_MODULES_FILE, KERNEL_BUILTIN_FILE   override /proc/modules and
#                       /lib/modules/<release>/modules.builtin
#      SYS_MODULE_DIR   override /sys/module
#      MODPROBE_DIRS    the directories searched for rules that already exist, besides MODPROBE_D
#                       (default /etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d /run/modprobe.d)
#      OS_RELEASE_FILE   instead of /etc/os-release
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30); the lock is STATE_DIR/.lock
# =============================================================================

set -uo pipefail

SCRIPT_NAME="linux-kernel-module-block.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/linux-kernel-module-block}"
MODPROBE_D="${MODPROBE_D:-/etc/modprobe.d}"

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

# ---------- the list ---------------------------------------------------------
# One row per module: module|group|CVEs|what needs it|what a block breaks|the switch for a built-in module
ROWS=(
"ah6|exploited|CVE-2026-80844|IPsec AH over IPv6 (DirtyAH6)|IPsec with the AH header over IPv6|"
"tun|exploited|CVE-2026-81000|TUN/TAP devices (TUNderflow)|OpenVPN, Tailscale, QEMU and libvirt networking, many VPN clients|"
"pppoe|exploited|CVE-2026-68121|PPP over Ethernet (PPPoEject)|DSL dial-up connections that use PPPoE|"
"sctp|exploited|CVE-2026-74469|SCTP (DiagSpill)|telecom signalling software and anything that speaks SCTP|"
"sctp_diag|exploited|CVE-2026-74469|SCTP socket diagnostics (DiagSpill)|ss and other tools that query SCTP sockets|"
"ebt_snat|exploited|CVE-2026-53266|ebtables SNAT target, exploited in the wild|bridge firewalls that use the ebtables snat target|"
"mptcp|exploited|CVE-2026-98432|Multipath TCP; a reduction, not a fix|software that uses MPTCP|sysctl net.mptcp.enabled=0 (linux-kernel-ireq-opt-check.sh mitigate --mptcp)"
"kvm_amd|exploited|CVE-2026-99312|AMD nested virtualization, guest-to-host escape|any AMD KVM virtualization at all, nested or not, since this module runs it all; blocking it fully is far more than this flaw needs|options kvm_amd nested=0 (linux-kernel-kvm-escape-check.sh mitigate)"
"mptcp_diag|hardening||MPTCP socket diagnostics, the module ss -M reads; not the flawed code|ss -M, the only way to list MPTCP listeners, and this collection's own checks||keep"
"dccp|historic|CVE-2017-6074 CVE-2020-16119|DCCP, local root double free and use after free|DCCP users, practically none|"
"rds|historic|CVE-2010-3904|Reliable Datagram Sockets, local root through the RDS page copy|Oracle RAC and other RDS clusters|"
"rds_tcp|historic|CVE-2010-3904|RDS over TCP|RDS over TCP clusters|"
"tipc|historic|CVE-2021-43267|TIPC, remote heap overflow in message parsing|TIPC clusters|"
"n_hdlc|historic|CVE-2017-2636|HDLC line discipline, local root race|legacy serial and HDLC links|"
"bluetooth|historic|CVE-2017-1000251|Bluetooth stack (BlueBorne), remote code execution in L2CAP|every Bluetooth device: keyboards, headsets, tethering|"
"vsock|historic|CVE-2021-26708|VM sockets, local root race|hypervisor guest agents and host to guest sockets|"
"vmw_vsock_virtio_transport|historic|CVE-2021-26708|virtio transport for VM sockets|guest agents on KVM and others|"
"esp6|historic|CVE-2022-27666|IPsec ESP over IPv6, local root heap overflow|IPsec with ESP over IPv6, which is most IPsec on IPv6|"
"cramfs|hardening||compressed ROM filesystem, mounted from crafted images|read-only embedded images|"
"freevxfs|hardening||Veritas filesystem, mounted from crafted images|old Veritas volumes|"
"jffs2|hardening||flash filesystem, mounted from crafted images|flash devices that use JFFS2|"
"hfs|hardening||Apple HFS filesystem, mounted from crafted images|reading classic Mac disks|"
"hfsplus|hardening||Apple HFS+ filesystem, mounted from crafted images|reading Mac disks and Time Machine volumes|"
"udf|hardening||UDF filesystem, mounted from crafted images|DVDs, Blu-ray discs and some large USB drives|"
"squashfs|hardening||compressed read-only filesystem|snaps, AppImages, live media and some containers|"
"usb_storage|hardening||USB mass storage|USB sticks and external drives (keyboards and mice are not affected)|"
"uas|hardening||USB attached SCSI|fast external drives|"
"firewire_core|hardening||FireWire core, a DMA attack path|FireWire cameras and audio interfaces|"
"firewire_ohci|hardening||FireWire controller, a DMA attack path|FireWire controllers|"
"firewire_sbp2|hardening||FireWire storage, a DMA attack path|FireWire disks|"
"thunderbolt|hardening||Thunderbolt bus, a DMA attack path|Thunderbolt docks and devices|"
"ax25|hardening||amateur radio packet protocol|amateur radio software|"
"netrom|hardening||amateur radio NET/ROM|amateur radio software|"
"rose|hardening||amateur radio ROSE|amateur radio software|"
"appletalk|hardening||AppleTalk|ancient Mac networks|"
"x25|hardening||X.25|X.25 links|"
"atm|hardening||ATM|ATM links|"
"can|hardening||CAN bus|vehicle and industrial CAN hardware|"
"nfc|hardening||near field communication|NFC readers|"
"ieee802154|hardening||low-rate wireless, 6LoWPAN|IoT radio hardware|"
"parport_pc|hardening||PC parallel port|parallel ports and some legacy scanners|"
"ppdev|hardening||user space parallel port access|programs that drive a parallel port directly|"
"floppy|hardening||floppy disk driver|floppy drives, including virtual ones|"
)
GROUPS_VALID="exploited historic hardening custom all"

# modules that must not be blocked: a block can stop the machine booting or leave you without a keyboard
PROTECTED=" ext2 ext3 ext4 xfs btrfs vfat fat jbd2 mbcache crc32c crc32c_generic libcrc32c nvme nvme_core ahci libahci sd_mod sr_mod scsi_mod virtio virtio_pci virtio_blk virtio_net virtio_scsi virtio_ring dm_mod dm_crypt dm_mirror dm_snapshot dm_thin_pool dm_multipath usbcore usb_common xhci_hcd xhci_pci ehci_hcd ehci_pci ohci_hcd uhci_hcd hid hid_generic usbhid i8042 atkbd psmouse loop overlay efivarfs "

load_user_rows() {
    local f="$1" line
    [[ -r "$f" ]] || die "cannot read the list file ${f}"
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" =~ ^[A-Za-z0-9_-]+\|(exploited|historic|hardening|custom)\| ]] || die "bad line in ${f}: ${line} (module|group|CVEs|what needs it|what a block breaks|switch)"
        ROWS+=("$line")
    done <"$f"
}

norm_name() { local n="${1//-/_}"; echo "$n"; }
valid_name() { [[ "$1" =~ ^[A-Za-z0-9_-]+$ && ${#1} -le 64 ]]; }
is_protected() { [[ "$PROTECTED" == *" $1 "* ]]; }

# prints the row of a module, or nothing
row_of() {
    local n r
    n="$(norm_name "$1")"
    for r in "${ROWS[@]}"; do [[ "${r%%|*}" == "$n" ]] && { echo "$r"; return 0; }; done
    return 1
}

# ---------- module state -----------------------------------------------------
# prints: loaded | builtin | loadable | absent
mod_state() {   # <module>
    local m rel mods bi re
    m="$(norm_name "$1")"; re="${m//_/[-_]}"
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"
    mods="${KERNEL_MODULES_FILE:-/proc/modules}"; bi="${KERNEL_BUILTIN_FILE:-/lib/modules/${rel}/modules.builtin}"
    if [[ -r "$mods" ]] && grep -E "^${m} " "$mods" >/dev/null; then echo loaded; return; fi
    if [[ -r "$bi" ]] && grep -E "/${re}\.ko" "$bi" >/dev/null; then echo builtin; return; fi
    if have modinfo && modinfo "$m" >/dev/null 2>&1; then echo loadable; return; fi
    echo absent
}

# prints "<use count> <holders>" of a loaded module
mod_use() {   # <module>
    local m mods
    m="$(norm_name "$1")"; mods="${KERNEL_MODULES_FILE:-/proc/modules}"
    awk -v m="$m" '$1==m {d=$4; if (d=="-") d="nothing"; print $3, d}' "$mods" 2>/dev/null | head -n 1
}

# the files under modprobe.d that already mention a module, one line each: "<file> <kind>", where the kind
# is install (an install rule to /bin/false or /bin/true: nothing loads it, by name, by alias or as a
# dependency) or blacklist (the automatic load by alias is stopped, an explicit modprobe still loads it)
blocked_in() {   # <module>
    local m re f d dirs
    m="$(norm_name "$1")"; re="${m//_/[-_]}"
    dirs="${MODPROBE_DIRS-/etc/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d /run/modprobe.d}"
    for d in "$MODPROBE_D" $dirs; do
        [[ -d "$d" ]] || continue
        for f in "$d"/*.conf; do
            [[ -f "$f" ]] || continue
            if grep -Eq "^[[:space:]]*install[[:space:]]+${re}[[:space:]]+(/bin/false|/bin/true|/usr/bin/false|/usr/bin/true)([[:space:]]|$)" "$f" 2>/dev/null; then echo "$f install"; fi
            if grep -Eq "^[[:space:]]*blacklist[[:space:]]+${re}([[:space:]]|$)" "$f" 2>/dev/null; then echo "$f blacklist"; fi
        done
    done | sort -u
}
# install | blacklist | none
block_kind() {   # <module>
    local b; b="$(blocked_in "$1")"
    if grep -q ' install$' <<<"$b"; then echo install; elif [[ -n "$b" ]]; then echo blacklist; else echo none; fi
}

host_state() {   # <module>: the word shown in the table
    local st k
    st="$(mod_state "$1")"; k="$(block_kind "$1")"
    if [[ "$st" == loaded || "$st" == builtin ]]; then echo "$st"
    elif [[ "$k" == install ]]; then echo "blocked"
    elif [[ "$k" == blacklist ]]; then echo "blacklist"
    else echo "$st"; fi
}

sha() { if have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}'; else shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; fi; }

# ---------- the initramfs ----------------------------------------------------
os_family() {
    local f="${OS_RELEASE_FILE:-/etc/os-release}" kv id like all
    [[ -r "$f" ]] || { echo other; return; }
    # shellcheck source=/dev/null
    kv="$( . "$f" 2>/dev/null; printf '%s|%s' "${ID:-}" "${ID_LIKE:-}" )"
    id="${kv%%|*}"; like="${kv#*|}"; all=" ${id} ${like} "
    case "$all" in
        *" debian "*|*" ubuntu "*|*" trisquel "*|*" raspbian "*|*" devuan "*) echo debian ;;
        *" rhel "*|*" fedora "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*|*" amzn "*|*" cloudlinux "*|*" scientific "*) echo rhel ;;
        *" suse "*|*" opensuse "*|*" sles "*|*" sled "*) echo suse ;;
        *" arch "*) echo arch ;;
        *" alpine "*) echo alpine ;;
        *) echo other ;;
    esac
}
# the rebuild command for this system, as text. dracut leaves /etc/modprobe.d out of a generic image
# (it reads it only for a host-only one), so -I puts the block files in whichever kind it builds;
# update-initramfs always copies /etc/modprobe.d
initramfs_cmd() {
    case "$(os_family)" in
        debian) echo "update-initramfs -u -k all" ;;
        rhel|suse) echo "dracut -f --regenerate-all -I \"${MODPROBE_D}/psf-block-*.conf\"" ;;
        arch) echo "mkinitcpio -P" ;;
        alpine) echo "mkinitfs" ;;
        *) echo "" ;;
    esac
}
# runs it: an argument list, so the quoted pattern reaches dracut as one word
run_initramfs() {
    case "$(os_family)" in
        debian) update-initramfs -u -k all ;;
        rhel|suse) dracut -f --regenerate-all -I "${MODPROBE_D}/psf-block-*.conf" ;;
        arch) mkinitcpio -P ;;
        alpine) mkinitfs ;;
        *) return 127 ;;
    esac
}

# ---------- list -------------------------------------------------------------
cmd_list() {
    local group=all present=0 r m g cves needs breaks alt st shown=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --group) shift; group="${1:-}"; [[ " $GROUPS_VALID " == *" $group "* ]] || die "--group takes one of: ${GROUPS_VALID}" ;;
            --present) present=1 ;;
            --list-file) shift; load_user_rows "${1:-}" ;;
            *) die "Unknown list option: $1 (--group G --present --list-file FILE)" ;;
        esac
        shift
    done
    step "Modules"
    printf '  %-28s %-10s %-9s %-22s %s\n' MODULE GROUP HOST CVE "A BLOCK BREAKS"
    for r in "${ROWS[@]}"; do
        IFS='|' read -r m g cves needs breaks alt keep <<<"$r"
        [[ "$group" == all || "$group" == "$g" ]] || continue
        st="$(host_state "$m")"
        [[ $present -eq 1 && "$st" == absent ]] && continue
        [[ "$keep" == keep ]] && m="${m}*"
        printf '  %-28s %-10s %-9s %-22s %s\n' "$m" "$g" "$st" "${cves:--}" "$breaks"
        shown=$((shown+1))
    done
    inf "${shown} modules shown. HOST is loaded, built in (no modprobe rule can block it), loadable, absent, blocked (an install rule), or blacklist (the automatic load only: an explicit modprobe still loads it)."
    inf "exploited = a flaw this collection has a tool for; historic = older well known flaws; hardening = attack surface, no CVE claimed."
    inf "* = detection depends on it: --group and --cve skip it, and it is blocked only when named and with --force."
    inf "Block one with: ${SCRIPT_NAME} block NAME   (see check NAME first)"
    return 0
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local n m st row rc=0 use aliases b first k g cves needs breaks alt keep
    local -a names=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list-file) shift; load_user_rows "${1:-}" ;;
            -*) die "Unknown check option: $1 (--list-file FILE)" ;;
            *) names+=("$1") ;;
        esac
        shift
    done
    [[ ${#names[@]} -gt 0 ]] || die "check needs at least one module name"
    for n in "${names[@]}"; do
        valid_name "$n" || die "not a module name: ${n}"
        m="$(norm_name "$n")"; st="$(mod_state "$m")"
        step "Module ${m}"
        if row="$(row_of "$m")"; then
            IFS='|' read -r _ g cves needs breaks alt keep <<<"$row"
            inf "on the list (${g}): ${needs}${cves:+; ${cves}}"
            inf "a block breaks: ${breaks}"
            [[ "$keep" == keep ]] && caution "detection depends on ${m}: blocking it hides what you are looking for and removes no known exposure. --group and --cve skip it, and block needs --force to write it"
        else inf "not on the list: any module name works, but this script knows nothing about what needs it"; fi
        is_protected "$m" && caution "${m} is on the protected list: a block can stop the machine booting or leave you without input. block refuses it"
        case "$st" in
            loaded) use="$(mod_use "$m")"; caution "loaded now (use count ${use%% *}, held by ${use#* }): a block only stops later loads" ;;
            builtin) caution "built into the kernel: no modprobe rule can block it${alt:+. The switch: ${alt}}" ;;
            loadable) inf "loadable but not loaded" ;;
            absent) ok "absent: this kernel has no such module" ;;
        esac
        if [[ "$st" == loaded || "$st" == loadable ]] && have modinfo; then
            aliases="$(modinfo -F alias "$m" 2>/dev/null | head -n 40)"
            if [[ -n "$aliases" ]]; then
                first="$(echo "$aliases" | head -n 3 | tr '\n' ' ')"
                inf "aliases: ${first}"
                if grep -q '^net-pf-' <<<"$aliases"; then inf "autoloads when any process opens a socket of this protocol family: no privileges needed. That is why a block helps"
                elif grep -q '^fs-' <<<"$aliases"; then inf "autoloads when something mounts this filesystem type (mounting needs privileges, or a desktop automounter)"
                elif grep -q '^usb:' <<<"$aliases"; then inf "autoloads when a matching USB device is plugged in"
                elif grep -q '^pci:' <<<"$aliases"; then inf "autoloads when matching PCI hardware is present" ; fi
            fi
        fi
        b="$(blocked_in "$m" | awk '{print $1}' | sort -u | tr '\n' ' ')"; k="$(block_kind "$m")"
        if [[ "$k" == install ]]; then ok "already blocked by: ${b}"
            [[ "$st" == loaded ]] && { caution "but it is loaded now, so the block is not effective until it is unloaded or the host reboots"; rc=1; }
        elif [[ "$k" == blacklist ]]; then
            caution "blacklisted by: ${b}. That stops the automatic load only: an explicit modprobe, or a module that depends on this one, still loads it. block adds the install rule"
            [[ "$st" == loaded || "$st" == loadable ]] && rc=1
        else
            [[ "$st" == loaded || "$st" == loadable ]] && rc=1
            [[ "$st" == builtin ]] && rc=1
        fi
    done
    return "$rc"
}

# ---------- block and rollback -----------------------------------------------
MB_DRY=0; MB_MANIFEST=""
# the manifest is replaced whole, through a temporary file in the same folder, so an interrupted run
# leaves the old manifest or the new one and never half of it
manifest_put() {   # <the whole new content, one line per entry, may be empty>
    local tmp="${MB_MANIFEST}.new.$$"
    if [[ -n "$1" ]]; then printf '%s\n' "$1" >"$tmp"; else : >"$tmp"; fi || return 1
    mv -f "$tmp" "$MB_MANIFEST"
}
mb_note() {   # a block file is recorded once: a repeated block replaces its line
    [[ $MB_DRY -eq 1 ]] && return 0
    local old=""
    if [[ "$1" == file\|* ]]; then old="$(grep -vF "${1%|*|*|*}|" "$MB_MANIFEST" 2>/dev/null || true)"
    else old="$(cat "$MB_MANIFEST" 2>/dev/null || true)"; fi
    manifest_put "${old:+${old}$'\n'}$1"
}

block_one() {   # <module> <reason> ; uses the FORCE, UNLOAD, ABSENT_OK, ALLOW_PROTECTED globals
    local m="$1" reason="$2" st row alt f use content
    m="$(norm_name "$m")"
    valid_name "$m" || { bad "not a module name: ${m}"; return 1; }
    if is_protected "$m"; then
        if [[ $FORCE -eq 1 && $ALLOW_PROTECTED -eq 1 ]]; then caution "${m} is protected, and you passed --force --allow-protected: continuing. Keep a console or rescue medium at hand"
        else bad "${m} is on the protected list: a block can stop the machine booting or leave you without input. Refused (only --force --allow-protected overrides it)"; return 1; fi
    fi
    st="$(mod_state "$m")"
    row="$(row_of "$m")"; alt=""; [[ -n "$row" ]] && alt="$(echo "$row" | cut -d'|' -f6)"
    if [[ "$(echo "$row" | cut -d'|' -f7)" == keep ]]; then
        if [[ $FORCE -eq 0 ]]; then caution "${m}: left alone: detection depends on it (this collection's own checks read it, and ss -M needs it) and the flawed code is not in it, so blocking it hides what you are looking for and removes no known exposure. --force blocks it anyway"; return 0; fi
        caution "${m}: blocking it anyway (--force): ss -M will list no MPTCP socket afterwards. /proc/net/protocols still counts them"
    fi
    case "$st" in
        builtin) bad "${m}: built into the kernel, so no modprobe rule can block it${alt:+. The switch: ${alt}}"; return 1 ;;
        absent) if [[ $ABSENT_OK -eq 0 ]]; then inf "${m}: not present on this kernel: nothing to block (--even-if-absent writes the rule anyway)"; return 0; fi ;;
        loaded)
            use="$(mod_use "$m")"
            if [[ $FORCE -eq 0 ]]; then caution "${m}: loaded now (held by ${use#* }): left alone. --force writes the rule anyway; it blocks later loads only, and --unload tries to unload it"; return 0; fi
            caution "${m}: loaded now: writing the rule anyway (--force)" ;;
    esac
    f="${MODPROBE_D}/psf-block-${m}.conf"
    content="# psf-security-patches: module block written by ${SCRIPT_NAME}
# module: ${m}   reason: ${reason}   written: $(date -u +%FT%TZ)
# Remove with: ${SCRIPT_NAME} rollback ${m}
blacklist ${m}
install ${m} /bin/false"
    if [[ $MB_DRY -eq 1 ]]; then echo "  would write ${f}:"; printf '%s\n' "$content" | sed 's/^/      /'
    else
        mkdir -p "$MODPROBE_D" || { bad "cannot create ${MODPROBE_D}"; return 1; }
        printf '%s\n' "$content" >"$f" || { bad "cannot write ${f}"; return 1; }
        chmod 644 "$f" 2>/dev/null
        mb_note "file|${f}|${m}|${reason}|$(sha "$f")|$(date +%s)"
        ok "${m}: later loads blocked (${f})"
    fi
    BLOCKED_NOW=$((BLOCKED_NOW+1))
    if [[ "$st" == loaded && $UNLOAD -eq 1 ]]; then
        if [[ $MB_DRY -eq 1 ]]; then echo "  would run: modprobe -r ${m}"
        elif modprobe -r "$m" 2>/dev/null; then ok "${m}: unloaded"
        else caution "${m}: could not be unloaded (something uses it): it stays loaded until reboot"; fi
    fi
    return 0
}

cmd_block() {
    local group="" cve="" r g cves m reason rc=0 cmd rel keep
    local -a names=() todo=() kept=()
    FORCE=0; UNLOAD=0; ABSENT_OK=0; ALLOW_PROTECTED=0; INITRAMFS=0; MB_DRY=0; BLOCKED_NOW=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --group) shift; group="${1:-}"; [[ " exploited historic hardening custom " == *" $group "* ]] || die "--group takes one of: exploited historic hardening custom (custom is the rows of a --list-file)" ;;
            --cve) shift; cve="${1:-}"; [[ "$cve" =~ ^CVE-[0-9]{4}-[0-9]{4,7}$ ]] || die "--cve takes an id like CVE-2026-98432" ;;
            --force) FORCE=1 ;; --unload) UNLOAD=1 ;; --even-if-absent) ABSENT_OK=1 ;; --allow-protected) ALLOW_PROTECTED=1 ;;
            --initramfs) INITRAMFS=1 ;; --dry-run) MB_DRY=1 ;;
            --list-file) shift; load_user_rows "${1:-}" ;;
            -*) die "Unknown block option: $1 (--group G --cve ID --force --unload --initramfs --even-if-absent --allow-protected --list-file FILE --dry-run)" ;;
            *) names+=("$1") ;;
        esac
        shift
    done
    [[ ${#names[@]} -gt 0 || -n "$group" || -n "$cve" ]] || die "block needs module names, --group G or --cve ID (see list). Nothing was changed."
    for m in "${names[@]+"${names[@]}"}"; do valid_name "$m" || die "not a module name: ${m}"; todo+=("$m|named on the command line"); done
    for r in "${ROWS[@]}"; do
        IFS='|' read -r m g cves _ _ _ keep <<<"$r"
        if [[ -n "$group" && "$g" == "$group" ]] || [[ -n "$cve" && " $cves " == *" $cve "* ]]; then
            if [[ "$keep" == keep ]]; then kept+=("$m"); continue; fi
        fi
        if [[ -n "$group" && "$g" == "$group" ]]; then todo+=("$m|group ${group}"); fi
        if [[ -n "$cve" && " $cves " == *" $cve "* ]]; then todo+=("$m|${cve}"); fi
    done
    [[ ${#todo[@]} -gt 0 || ${#kept[@]} -gt 0 ]] || die "nothing on the list matches: ${group:-${cve}}"
    [[ $MB_DRY -eq 1 ]] || need_root "block changes the host"
    if [[ $MB_DRY -eq 0 ]]; then mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"; take_lock; MB_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$MB_MANIFEST"
    else MB_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    step "Blocking"
    for m in "${kept[@]+"${kept[@]}"}"; do inf "${m}: left out of the group or CVE block: detection depends on it (ss -M reads it), and the flawed code is not in it. To block it anyway, name it and add --force"; done
    local -A seen=()
    for r in "${todo[@]}"; do
        m="${r%%|*}"; reason="${r#*|}"; m="$(norm_name "$m")"
        [[ -n "${seen[$m]:-}" ]] && continue; seen[$m]=1
        block_one "$m" "$reason" || rc=1
    done
    step "Result"
    cmd="$(initramfs_cmd)"
    if [[ $BLOCKED_NOW -gt 0 ]]; then
        if [[ $MB_DRY -eq 1 ]]; then info "Dry run finished: ${BLOCKED_NOW} block file(s) would be written"
        else info "${BLOCKED_NOW} block file(s) written. Manifest: ${STATE_DIR}. Check with: ${SCRIPT_NAME} status. Undo with: ${SCRIPT_NAME} rollback"; fi
        if [[ -n "$cmd" ]]; then
            if [[ $INITRAMFS -eq 1 && $MB_DRY -eq 0 ]]; then
                inf "rebuilding the initramfs: ${cmd}"
                if run_initramfs >/dev/null 2>&1; then ok "initramfs rebuilt"; mb_note "initramfs|${cmd}||||$(date +%s)"; else bad "the initramfs rebuild failed: run it by hand and read its output: ${cmd}"; rc=1; fi
            elif [[ $INITRAMFS -eq 1 ]]; then echo "  would run: ${cmd}"
            else inf "a module can also load from the initramfs before modprobe.d is read. To cover that, add --initramfs or run: ${cmd}"; fi
        else inf "no initramfs command is known for this system: if your boot loads these modules early, rebuild the initramfs by hand"; fi
    else info "Nothing was written."; fi
    return "$rc"
}

cmd_status() {
    local kind f m reason hash st nowhash eff=0 ineff=0 other
    [[ $# -eq 0 ]] || die "status takes no options"
    MB_MANIFEST="${STATE_DIR}/manifest.txt"
    step "Blocks written by this script"
    if [[ -s "$MB_MANIFEST" ]]; then
        while IFS='|' read -r kind f m reason hash _; do
            [[ "$kind" == file ]] || continue
            st="$(mod_state "$m")"
            if [[ ! -f "$f" ]]; then bad "${m}: the block file ${f} is gone"; ineff=$((ineff+1)); continue; fi
            nowhash="$(sha "$f")"
            if [[ "$nowhash" != "$hash" ]]; then caution "${m}: ${f} was edited since this script wrote it"; fi
            if [[ "$st" == loaded ]]; then caution "${m}: blocked for future loads, but loaded now: not effective until it is unloaded or the host reboots"; ineff=$((ineff+1))
            else ok "${m}: effective (${st}), ${reason}"; eff=$((eff+1)); fi
        done <"$MB_MANIFEST"
        grep -q '^initramfs|' "$MB_MANIFEST" 2>/dev/null && inf "the initramfs was rebuilt after a block"
    else inf "none: this script has blocked nothing here (no manifest in ${STATE_DIR})"; fi
    other=""
    for f in "$MODPROBE_D"/psf-*.conf; do
        [[ -f "$f" && "${f##*/}" != psf-block-* ]] && other+="${f##*/} "
    done
    [[ -n "$other" ]] && inf "other psf-security-patches tools wrote: ${other}"
    step "Verdict"
    if [[ $ineff -gt 0 ]]; then warn "${ineff} block(s) are not effective yet."; return 1; fi
    info "${eff} block(s), all effective."; return 0
}

cmd_rollback() {
    local force=0 init=0 line kind f m reason hash nowhash rc=0 removed=0 cmd
    local -a names=() keep=()
    MB_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force=1 ;; --initramfs) init=1 ;; --dry-run) MB_DRY=1 ;;
            -*) die "Unknown rollback option: $1 (--force --initramfs --dry-run)" ;;
            *) valid_name "$1" || die "not a module name: $1"; names+=("$(norm_name "$1")") ;;
        esac
        shift
    done
    MB_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$MB_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $MB_DRY -eq 1 ]] || { need_root "rollback changes the host"; take_lock; }
    step "Rolling back"
    while IFS= read -r line; do
        IFS='|' read -r kind f m reason hash _ <<<"$line"
        if [[ "$kind" != file ]]; then keep+=("$line"); continue; fi
        if [[ ${#names[@]} -gt 0 && " ${names[*]} " != *" $m "* ]]; then keep+=("$line"); continue; fi
        if [[ ! -f "$f" ]]; then inf "${m}: the file ${f} is already gone"; continue; fi
        nowhash="$(sha "$f")"
        if [[ "$nowhash" != "$hash" && $force -eq 0 ]]; then caution "${m}: ${f} was edited since this script wrote it: kept (--force removes it)"; keep+=("$line"); rc=1; continue; fi
        if [[ $MB_DRY -eq 1 ]]; then echo "  would remove ${f}"; keep+=("$line")
        else rm -f "$f" && { ok "${m}: removed ${f}"; removed=$((removed+1)); }; fi
    done <"$MB_MANIFEST"
    if [[ $MB_DRY -eq 0 ]]; then
        if [[ ${#keep[@]} -gt 0 ]]; then manifest_put "$(printf '%s\n' "${keep[@]}")"; else mv -f "$MB_MANIFEST" "${MB_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || manifest_put ""; fi
    fi
    step "Result"
    if [[ $removed -gt 0 ]]; then
        info "${removed} block file(s) removed. The modules can load again."
        cmd="$(initramfs_cmd)"
        if [[ -n "$cmd" ]]; then
            if [[ $init -eq 1 ]]; then if run_initramfs >/dev/null 2>&1; then ok "initramfs rebuilt"; else bad "the initramfs rebuild failed: ${cmd}"; rc=1; fi
            else inf "if you rebuilt the initramfs after the block, rebuild it again: ${cmd}"; fi
        fi
    elif [[ $MB_DRY -eq 1 ]]; then info "Dry run finished"; else info "Nothing was removed"; fi
    return "$rc"
}

main() {
    CMD="${1:-list}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Linux kernel modules behind recent flaws, or any module you name: block them from loading, and undo it"
    case "$CMD" in
        list) cmd_list "$@" ;;
        check) cmd_check "$@" ;;
        block) cmd_block "$@" ;;
        status) cmd_status "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (list|check|block|status|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
