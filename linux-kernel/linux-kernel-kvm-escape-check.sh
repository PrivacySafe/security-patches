#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Linux kernel KVM guest-to-host escape on AMD (nested SVM): checker  (v1)
# CVE-2026-99312
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Terra Security (Oren Yomtov) disclosed CVE-2026-99312 on 18 November 2026: a guest VM on an
# AMD KVM host with nested virtualization on can read and write the host's physical memory,
# which on a shared host means every other tenant's memory too. Terra demonstrated the read on
# an ordinary DigitalOcean droplet (the host's kernel banner, then about 127 GB of host RAM) and
# the write on their own server, so as not to disrupt other customers. Arbitrary write to host
# memory is the step before code execution on the host.
#
# The official record (the Linux kernel's own CNA entry, mirrored by NVD and Red Hat) describes
# the underlying bug, an unconditional MMU-context reset missing when KVM emulates an INIT while
# a nested guest's paging is off, and scores it as a local denial-of-service (CVSS vector ending
# C:N/I:N/A:H: no confidentiality or integrity impact, only availability). Terra's own research,
# corroborated independently, found the same bug chains with a use-after-free in KVM's nested SVM
# handling (a stale nCR3 pointer left referencing a recycled page-table page) and an Accessed-bit
# timing oracle, into a full guest-to-host memory read and write. Treat it accordingly: the
# official score describes the kernel's own accounting of the bug class, not what was actually
# demonstrated against it.
#
# This is a fix landing on top of an older one. In 2022, a different, already-fixed KVM reset
# flaw was fixed by switching a reset back to the control block of the VM that runs
# the nested one before anything is freed. CVE-2026-99312 is a flaw that fix itself opened,
# unrelated to three other 2026 KVM guest-to-host escapes found by a different researcher under
# the names ITScape (arm64), Januscape and Zapscape (x86, both affecting Intel and AMD); do not
# confuse this script's one CVE and one AMD-only mitigation with those.
#
# Affected: nested virtualization on AMD (kvm_amd), on any kernel from 6.1 up to, but not
# including, the fixed releases below. INIT is an unconditional intercept on Intel VMX, so Intel
# nested virtualization (kvm_intel) cannot reach this specific bug. The precondition for this
# flaw came from a November 2022 commit that was itself widely backported at the time, confirmed
# at least as far back as the (now unsupported) stable branches 5.15.81 and 6.0.11. Nothing
# confirms that other branches below 6.1 also receiving backports in November 2022 (5.10 and
# 5.4, for instance) escaped it, so `check` reports those as unknown rather than clear. First
# fixed stable release of each currently maintained branch: 6.12.118, 6.18.64, 7.3.5; first
# mainline release with the fix: 7.4-rc2 (9 November 2026).
#
# check and hunt change nothing. check reports the kernel version against the fixed releases,
# whether this is an AMD host, whether kvm_amd is loaded, and the current nested parameter.
# mitigate sets kvm_amd's nested module parameter to 0, which closes this path entirely: it
# writes a modprobe.d file so this applies the next time kvm_amd loads, and separately, only
# with --unload, unloads and reloads kvm_amd now (every VM on the host must already be stopped,
# since the module cannot unload while any are running, and the parameter is read only at load
# time, so there is no way to apply it to an already-loaded module without a reload or reboot).
#
# Usage:
#   ./linux-kernel-kvm-escape-check.sh [command] [options]
#
#   check (default)   kernel version against the fixed releases; whether this is an AMD host;
#                     kvm_amd's load state and current nested parameter. Exit 0 = not exposed
#                     (patched, not AMD, module absent, or nested already off), 1 = exposed,
#                     2 = something couldn't be read.
#   mitigate [--unload] [--force] [--dry-run]   (root for anything but --dry-run) Writes
#                     /etc/modprobe.d/psf-kvm-amd-nested-off.conf ("options kvm_amd nested=0").
#                     Refuses if kvm_amd is currently loaded, unless --unload (which refuses in
#                     turn if any VM is running on it, since modprobe -r fails while anything
#                     uses the module) or --force (writes the file regardless, with a reminder
#                     that it only takes effect on kvm_amd's next load, which on most hosts
#                     means after a reboot). --dry-run shows what would happen.
#   rollback [--dry-run]   (root) removes the modprobe.d file. Does not reload kvm_amd with
#                     nested back on; that needs the same drain this script will not do for you.
#   rules             prints the file mitigate writes and the manual unload/reload commands.
#   version           print the script version.
#
# Env overrides:
#   NESTED_FIXED_6_12=6.12.118   NESTED_FIXED_6_18=6.18.64   NESTED_FIXED_7=7.3.5
#   NESTED_FIXED_MAINLINE=7.4-rc2
#   KERNEL_RELEASE, KERNEL_VERSION_STRING   for testing: override `uname -r` and `uname -v`
#   KERNEL_MODULES_FILE (default /proc/modules), KERNEL_BUILTIN_FILE, KERNEL_CHANGELOG
#   CPU_VENDOR_FILE (default /proc/cpuinfo)   for testing: override where the CPU vendor is read
#   NESTED_PARAM_FILE (default /sys/module/kvm_amd/parameters/nested)
#   STATE_DIR (default /var/lib/psf-security-patches/linux-kernel-kvm-escape)
#   PSF_LOCK_WAIT   seconds a run that changes the host waits for another one already changing
#                   it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================
set -uo pipefail
SELF="$0"
SCRIPT_NAME="linux-kernel-kvm-escape-check.sh"
SCRIPT_VERSION="1.0.1"
SCRIPT_DATE="2026-11-22"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/linux-kernel-kvm-escape}"
MODPROBE_FILE="/etc/modprobe.d/psf-kvm-amd-nested-off.conf"
ADVISORY="https://www.terra.security/blog/kvm-guest-to-host-escape"

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
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}

norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
ver_ge() { ! ver_lt "$1" "$2"; }

kernel_origin() {   # <release> <version-string> -> "stable X.Y.Z" | "debian X.Y.Z" | vendor
    local rel="$1" ver="$2" up
    if [[ "$ver" =~ Debian[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)- ]]; then echo "debian ${BASH_REMATCH[1]}"; return; fi
    if [[ "$ver" == *Ubuntu* ]] \
       || [[ "$rel" =~ \.(el|fc|amzn|azl|oe|ael)[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+ ]]; then echo vendor; return; fi
    up="${rel%%-*}"
    if [[ "$up" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "stable ${up}"; else echo vendor; fi
}

changelog_names() {   # <release> <CVE>
    local c pkg rel="$1" cve="$2"
    if [[ -n "${KERNEL_CHANGELOG:-}" && -r "${KERNEL_CHANGELOG}" ]]; then
        if zcat -f "${KERNEL_CHANGELOG}" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
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

mod_state() {   # <module> <release> -> loaded | builtin | loadable | absent
    local m="$1" rel="$2" mods="${KERNEL_MODULES_FILE:-/proc/modules}" bi="${KERNEL_BUILTIN_FILE:-/lib/modules/$2/modules.builtin}"
    if [[ -r "$mods" ]] && grep -E "^${m} " "$mods" >/dev/null; then echo loaded; return; fi
    if [[ -r "$bi" ]] && grep -E "/${m}\.ko" "$bi" >/dev/null; then echo builtin; return; fi
    if have modinfo && modinfo "$m" >/dev/null 2>&1; then echo loadable; return; fi
    echo absent
}

is_amd_host() {
    local f="${CPU_VENDOR_FILE:-/proc/cpuinfo}"
    [[ -r "$f" ]] && grep -qi 'AuthenticAMD\|vendor_id.*AMD' "$f" 2>/dev/null
}

# nested_param -> current value (0/1/Y/N), or empty if unreadable
nested_param() {
    local f="${NESTED_PARAM_FILE:-/sys/module/kvm_amd/parameters/nested}"
    [[ -r "$f" ]] && cat "$f" 2>/dev/null
}

# kernel_state <release> <version-string> -> rc|why   (0 fixed, 1 affected, 2 unknown)
kernel_state() {
    local rel="$1" ver="$2" origin br up f612 f618 f7 fmain
    f612="${NESTED_FIXED_6_12:-6.12.118}"; f618="${NESTED_FIXED_6_18:-6.18.64}"
    f7="${NESTED_FIXED_7:-7.3.5}"; fmain="${NESTED_FIXED_MAINLINE:-7.4-rc2}"
    origin="$(kernel_origin "$rel" "$ver")"
    if [[ "$origin" == vendor ]]; then
        if changelog_names "$rel" CVE-2026-99312; then echo "0|${rel}: vendor changelog lists CVE-2026-99312"; return; fi
        echo "2|${rel}: a vendor kernel; the release string does not say which upstream fixes it carries. Check your distribution's own advisory for CVE-2026-99312"
        return
    fi
    up="${origin#* }"
    if ver_lt "$up" "6.1"; then
        if ver_ge "$up" "5.15.81" && ver_lt "$up" "5.16"; then echo "1|${up}: in the affected range of the (now unsupported) 5.15 branch; upgrade to a maintained branch"; return; fi
        if ver_ge "$up" "6.0.11" && ver_lt "$up" "6.1"; then echo "1|${up}: in the affected range of the (now unsupported) 6.0 branch; upgrade to a maintained branch"; return; fi
        # The 2022 commit this flaw's precondition came from was backported widely, as far back as
        # 5.15.81 and 6.0.11; those two are confirmed above, but nothing here confirms any other
        # branch below 6.1 did NOT also receive that backport. Reporting "not affected" here would
        # be an assumption this script cannot verify, so an unlisted branch is reported unknown
        # rather than clear, and the operator is pointed at their own branch's changelog.
        echo "2|${up}: not 5.15.81+ or 6.0.11+, the two confirmed older ranges, but this does not confirm this branch never received the 2022 backport that created this flaw's precondition. Check this branch's own changelog for CVE-2026-99312 rather than assuming its age puts it out of scope"; return
    fi
    br="${up%.*}"
    case "$br" in
        6.12) if ver_ge "$up" "$f612"; then echo "0|${up} >= ${f612}"; else echo "1|${up} < ${f612} (6.12 fix)"; fi ;;
        6.18) if ver_ge "$up" "$f618"; then echo "0|${up} >= ${f618}"; else echo "1|${up} < ${f618} (6.18 fix)"; fi ;;
        7.3)  if ver_ge "$up" "$f7"; then echo "0|${up} >= ${f7}"; else echo "1|${up} < ${f7} (7.3 fix)"; fi ;;
        *)
            if ver_ge "$up" "$fmain"; then echo "0|${up} >= ${fmain} (mainline fix)"
            else echo "1|${up}: branch ${br} is not one of the stable branches with a backported fix (6.12, 6.18, 7.3); upgrade to one of those or to ${fmain} or later"; fi
            ;;
    esac
}

cmd_check() {
    # st/rc are deliberately separate: st is just the kernel-version finding (the code is
    # present or absent), while rc, the exit code, is decided below from the combination of st,
    # whether this is an AMD host, and the nested parameter. A kernel with the vulnerable code
    # is not itself "exposed" to CVE-2026-99312 on an Intel host, or with nested already off.
    local rc=0 rel ver amd=0 ms np origin st why
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"
    ver="${KERNEL_VERSION_STRING:-$(uname -v 2>/dev/null)}"
    step "Kernel version"
    IFS='|' read -r st why <<<"$(kernel_state "$rel" "$ver")"
    case $st in
        0) ok "${rel}: ${why}" ;;
        1) bad "${rel}: ${why}" ;;
        *) caution "${rel}: ${why}"; rc=2 ;;
    esac

    step "CPU vendor and nested SVM exposure"
    if is_amd_host; then
        amd=1
        ok "AMD host: this bug can be reached here if nested virtualization is on"
    else
        inf "not an AMD host (or CPU vendor could not be read): CVE-2026-99312 only reaches nested SVM on AMD; Intel VMX is not affected by this specific bug"
    fi
    ms="$(mod_state kvm_amd "$rel")"
    case "$ms" in
        loaded) inf "kvm_amd: loaded" ;;
        builtin) inf "kvm_amd: built into this kernel" ;;
        loadable) inf "kvm_amd: not loaded, loadable" ;;
        absent) inf "kvm_amd: not present on this host" ;;
    esac
    np="$(nested_param)"
    if [[ "$ms" == absent ]]; then
        ok "kvm_amd is not present: nested AMD virtualization is not possible here"
    elif [[ -z "$np" ]]; then
        caution "could not read kvm_amd's nested parameter (module not loaded yet, or not readable here)"
        [[ $rc -eq 0 ]] && rc=2
    elif [[ "$np" == "N" || "$np" == "0" ]]; then
        ok "kvm_amd nested=${np}: nested virtualization is off, so this path is closed regardless of kernel version"
    else
        if [[ $amd -eq 1 && $st -eq 1 ]]; then
            bad "kvm_amd nested=${np} on an unpatched, AMD host: exposed. See mitigate, or upgrade the kernel"
            rc=1
        else
            caution "kvm_amd nested=${np}: nested virtualization is on. Not currently flagged as exposed (${amd} = AMD host, kernel state ${st}), but worth confirming by hand"
        fi
    fi

    step "Verdict"
    case $rc in
        0) info "Not exposed: patched kernel, not an AMD host, kvm_amd absent, or nested already off." ;;
        1) warn "Exposed. Upgrade the kernel to the fixed release shown above, or run mitigate to turn nested SVM off until you can. Advisory: ${ADVISORY}" ;;
        *) warn "Something could not be read. Run as root, or check the vendor advisory for this kernel's own CVE-2026-99312 status." ;;
    esac
    return "$rc"
}

lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    mkdir -p "$STATE_DIR" 2>/dev/null || return 0
    { exec 9>"${STATE_DIR}/.lock"; } 2>/dev/null || return 0
    PSF_LOCK_HELD=1 flock -w "${PSF_LOCK_WAIT:-30}" 9 || die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: ${STATE_DIR}/.lock): wait for it to finish, then run it again"
}

cmd_mitigate() {
    local dry=0 force=0 unload=0 ms rel
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) dry=1 ;; --force) force=1 ;; --unload) unload=1 ;;
            *) die "Unknown mitigate option: $1 (--unload --force --dry-run)" ;; esac
        shift
    done
    [[ $dry -eq 1 ]] || need_root "mitigate changes the host"
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"
    ms="$(mod_state kvm_amd "$rel")"
    step "Writing the persistent setting"
    if [[ $dry -eq 1 ]]; then
        echo "  would write ${MODPROBE_FILE}:"
        echo "      options kvm_amd nested=0"
    else
        mkdir -p "$(dirname "$MODPROBE_FILE")" || die "cannot create $(dirname "$MODPROBE_FILE")"
        printf 'options kvm_amd nested=0\n' > "$MODPROBE_FILE" || die "could not write ${MODPROBE_FILE}"
        ok "wrote ${MODPROBE_FILE}"
    fi
    if [[ "$ms" != loaded ]]; then
        inf "kvm_amd is not currently loaded (${ms}): the setting above takes effect the next time it loads. Nothing further to do"
        [[ $dry -eq 1 ]] && info "Dry run finished: nothing was changed" || info "Applied. Undo with: $0 rollback"
        return 0
    fi
    step "kvm_amd is loaded now"
    caution "the nested parameter is read only when the module loads, so this does not change a running host until kvm_amd is reloaded or the host reboots"
    if [[ $unload -eq 0 ]]; then
        if [[ $force -eq 0 ]]; then
            caution "kvm_amd is loaded: pass --unload to unload and reload it now (every VM on this host must already be stopped), or --force to only write the file and apply it on the next reboot, or run with --dry-run to see what would happen without deciding yet"
            [[ $dry -eq 1 ]] && { info "Dry run finished: nothing was changed"; return 0; }
            return 1
        fi
        inf "--force given: the file is written; it takes effect on the next reboot or manual reload of kvm_amd"
        info "Applied. Undo with: $0 rollback"
        return 0
    fi
    if [[ $dry -eq 1 ]]; then
        echo "  would run: modprobe -r kvm_amd && modprobe kvm_amd"
        info "Dry run finished: nothing was changed"
        return 0
    fi
    if ! have modprobe; then die "modprobe not found: cannot reload kvm_amd here"; fi
    # modprobe's messages are captured in a variable, never in a file: a fixed or PID-based
    # name under /tmp could be a symlink planted by another local user
    local mp_err
    if ! mp_err="$(modprobe -r kvm_amd 2>&1 >/dev/null)"; then
        bad "could not unload kvm_amd: ${mp_err}"
        caution "this almost always means a VM is still running on it. Stop every VM on this host, then try again"
        return 1
    fi
    ok "unloaded kvm_amd"
    if ! mp_err="$(modprobe kvm_amd 2>&1 >/dev/null)"; then
        bad "could not reload kvm_amd: ${mp_err}"
        return 1
    fi
    ok "reloaded kvm_amd"
    local np; np="$(nested_param)"
    if [[ "$np" == "N" || "$np" == "0" ]]; then ok "kvm_amd nested=${np}: confirmed off"
    else caution "kvm_amd nested=${np}: not confirmed off after reload; check ${MODPROBE_FILE} and modprobe -c"; fi
    info "Applied. Undo with: $0 rollback"
}

cmd_rollback() {
    local dry=0
    while [[ $# -gt 0 ]]; do case "$1" in --dry-run) dry=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac; shift; done
    [[ -f "$MODPROBE_FILE" ]] || { info "Nothing to roll back (${MODPROBE_FILE} does not exist)"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes the host"
    if [[ $dry -eq 1 ]]; then echo "  would remove ${MODPROBE_FILE}"; info "Dry run finished: nothing was changed"; return 0; fi
    rm -f "$MODPROBE_FILE" && ok "removed ${MODPROBE_FILE}"
    info "Rolled back. This does not turn nested virtualization back on for an already-loaded kvm_amd; reload the module (draining VMs first) or reboot if you need nested back now."
}

cmd_rules() {
    step "What mitigate writes"
    cat <<'EOF'
/etc/modprobe.d/psf-kvm-amd-nested-off.conf:

    options kvm_amd nested=0

This takes effect the next time kvm_amd loads. If it is already loaded, reloading it live needs
every VM on the host to be stopped first, since the module cannot unload while anything is using
it:

    modprobe -r kvm_amd
    modprobe kvm_amd
    cat /sys/module/kvm_amd/parameters/nested   # confirm it reads N or 0

On a host that cannot be drained right now, write the file anyway (mitigate --force) and apply
it at the next planned reboot or maintenance window. Only kvm_amd needs this for CVE-2026-99312:
the bug does not reach Intel's kvm_intel, so there is no matching options kvm_intel line here.
EOF
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-99312: KVM guest-to-host escape on AMD nested virtualization; advisory: ${ADVISORY}"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate|rollback) lock_for_change; "cmd_${CMD}" "$@" ;;
        rules) cmd_rules ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|rules|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5
