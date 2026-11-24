#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Java4Shell: OpenJDK Base64 decoder intrinsic out-of-bounds write, November 2026 (v1)
# CVE-2026-114938 (Oracle CVSS 3.1 8.1; public memory-corruption proof of concept)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On x86-64 processors with AVX-512 VBMI (Intel Ice Lake or newer, AMD Zen 4 or newer), the JIT's
# fast path for java.util.Base64 decoding can write past the end of its buffer when it decodes
# input an attacker chose. Tokens, authorization headers, SAML and uploads all go through Base64,
# and researchers showed it against Jira, Confluence, Artifactory and Jenkins. ARM servers and
# older x86 processors never take that path.
#
# Affected: Java 17.0.6 and later, 21, 25 and 27 from any vendor without the November 2026 fix,
# and Oracle's Java 8 Performance Pack. Standard Java 8 and 11 are not affected. Fixed (Oracle):
# 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, 17 November 2026; Corretto, Temurin, Red Hat,
# Ubuntu and Debian builds followed, and a distribution package is judged by its changelog.
#
# Usage:
#   ./java4shell-check.sh [command] [options]
#
#   check (default)  Read-only. Reads this CPU's flags, then every Java runtime:
#                    the ones under /usr/lib/jvm and ROOTS (including the copies
#                    Jira, Confluence, Jenkins and others bundle), and the ones
#                    running now, whose command line and environment also show
#                    whether the workaround flag is in effect. A runtime is
#                    judged by its release file and is never run; a
#                    distribution package also by its changelog. Exit 0 = not
#                    exposed, 1 = an affected runtime on a CPU with AVX-512 VBMI
#                    (or a CPU whose flags could not be read), 2 = a runtime
#                    could not be judged.
#   mitigate [--dry-run] [--restart]   (root) For each running systemd service
#                    whose Java is affected and does not already have it, adds
#                    a drop-in that sets JAVA_TOOL_OPTIONS to the service's own
#                    value plus "-XX:+IgnoreUnrecognizedVMOptions
#                    -XX:-UseBASE64Intrinsics", which turns off only the
#                    vulnerable fast path (the workaround AWS documents; not an
#                    official Oracle one). It takes effect when the service
#                    restarts: add --restart, or restart them yourself. Java
#                    started some other way is listed with the flag to add.
#   rollback [--dry-run] [--restart]   Removes those drop-ins.
#   version          Prints the script version.
#
# Env overrides:
#   ROOTS="/usr/lib/jvm /opt /srv /usr/local /var/lib /home"   where check looks for runtimes
#   MAX_DEPTH=7
#   CPUINFO_FILE=/proc/cpuinfo
#   DROPIN_ROOT=/etc/systemd/system
#   STATE_DIR (default /var/lib/psf-security-patches/java4shell)
#   PSF_LOCK_WAIT      seconds a run that changes the host waits for another (default 30)
#   UNIT_FOR_PID       the service every Java process belongs to (testing only)
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="java4shell-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"
CVE="CVE-2026-114938"
ROOTS="${ROOTS:-/usr/lib/jvm /opt /srv /usr/local /var/lib /home}"
MAX_DEPTH="${MAX_DEPTH:-7}"
CPUINFO_FILE="${CPUINFO_FILE:-/proc/cpuinfo}"
DROPIN_ROOT="${DROPIN_ROOT:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/java4shell}"
FLAG="-XX:-UseBASE64Intrinsics"
DROPIN_NAME="90-psf-java4shell.conf"

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

# ---------- judging a runtime ------------------------------------------------
ver_lt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }
four() {   # "21.0.13.0.3+1-Ubuntu" -> "21.0.13.0"; "21.0.13" -> "21.0.13.0"
    local v="${1%%[+-]*}" a b c d
    IFS=. read -r a b c d _ <<<"$v"
    printf '%s.%s.%s.%s' "${a:-0}" "${b:-0}" "${c:-0}" "${d:-0}"
}
# judge VERSION -> "<rc>|<text>": 0 not affected or fixed, 1 affected, 2 unknown
judge() {
    local raw="$1" v major
    if [[ "$raw" =~ ^1\.8\. || "$raw" =~ ^8u || "$raw" == 8 || "$raw" =~ ^8\. ]]; then
        if [[ "$raw" == *perf* ]]; then echo "1|Java 8 Performance Pack: see Oracle's advisory for its fixed build"; else echo "0|Java 8 is not affected"; fi; return
    fi
    [[ "$raw" =~ ^[0-9]+(\.[0-9]+)* ]] || { echo "2|version '${raw:-?}' could not be read"; return; }
    v="$(four "$raw")"; major="${v%%.*}"
    case "$major" in
        9|10|11) echo "0|Java ${major} is not affected" ;;
        17) if ver_lt "$v" 17.0.6.0; then echo "0|before 17.0.6, not affected"
            elif ver_lt "$v" 17.0.21.1; then echo "1|before 17.0.21.1"; else echo "0|17.0.21.1 or later"; fi ;;
        21) if ver_lt "$v" 21.0.13.1; then echo "1|before 21.0.13.1"; else echo "0|21.0.13.1 or later"; fi ;;
        25) if ver_lt "$v" 25.0.5.1; then echo "1|before 25.0.5.1"; else echo "0|25.0.5.1 or later"; fi ;;
        27) if ver_lt "$v" 27.0.1.1; then echo "1|before 27.0.1.1"; else echo "0|27.0.1.1 or later"; fi ;;
        12|13|14|15|16) echo "0|Java ${major} predates the vulnerable code (and is out of support: move to a supported line)" ;;
        18|19|20|22|23|24|26) echo "1|Java ${major} is out of support and has no fix: move to 21, 25 or 27" ;;
        *) if [[ "$major" -gt 27 ]]; then echo "0|newer than the affected lines"; else echo "2|Java ${major} is not a line the advisory covers"; fi ;;
    esac
}

# A distribution's package can carry the fix under its own version: read its changelog.
backported() {   # <java binary> -> 0 if the owning package's changelog names the CVE
    local bin="$1" pkg doc
    if have dpkg-query; then
        pkg="$(dpkg-query -S "$(readlink -f "$bin")" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for doc in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg%%:*}/changelog.Debian.gz"; do
                [[ -r "$doc" ]] && zcat "$doc" 2>/dev/null | head -n 400 | grep -q "$CVE" && return 0
            done
        fi
    fi
    if have rpm; then
        pkg="$(rpm -qf "$(readlink -f "$bin")" 2>/dev/null | head -n1)"
        [[ -n "$pkg" && "$pkg" != *"not owned"* ]] && rpm -q --changelog "$pkg" 2>/dev/null | head -n 400 | grep -q "$CVE" && return 0
    fi
    return 1
}

# Only the release file is read. A runtime is never run: under /home or /opt it may belong to
# anyone, and running it as root would run their code. -f is false for a link to a FIFO or device.
runtime_version() {   # <java home> -> version from its release file
    local home="$1" v=""
    if [[ -f "$home/release" && -r "$home/release" ]]; then
        v="$(sed -nE 's/^JAVA_RUNTIME_VERSION="?([^"]*)"?.*/\1/p' "$home/release" | head -n1)"
        [[ -n "$v" ]] || v="$(sed -nE 's/^JAVA_VERSION="?([^"]*)"?.*/\1/p' "$home/release" | head -n1)"
    fi
    printf '%s' "$v"
}

VBMI=""   # yes, no or unknown
cpu_check() {
    if [[ ! -r "$CPUINFO_FILE" ]]; then VBMI=unknown; return; fi
    if [[ "$(uname -m 2>/dev/null)" != x86_64 && -z "${CPUINFO_FILE_GIVEN:-}" ]] && ! grep -q '^flags' "$CPUINFO_FILE"; then VBMI=no; return; fi
    if grep -qw avx512vbmi "$CPUINFO_FILE" 2>/dev/null; then VBMI=yes; else VBMI=no; fi
}

N_AFF=0; N_UNK=0; N_MITIGATED=0
AFFECTED_HOMES=" "
judge_home() {   # <java home> <label>
    local home="$1" label="$2" v rc why
    v="$(runtime_version "$home")"
    IFS='|' read -r rc why <<<"$(judge "$v")"
    if [[ $rc -eq 1 ]] && backported "$home/bin/java"; then rc=0; why="the package's changelog names ${CVE}: fixed by the distribution"; fi
    case "$rc" in
        0) inf "${label}  ${v}  (${why})" ;;
        1) N_AFF=$((N_AFF + 1)); AFFECTED_HOMES+="$(readlink -f "$home") "; bad "${label}  ${v:-?}  ${RED}affected${NC} (${why})" ;;
        *) N_UNK=$((N_UNK + 1)); caution "${label}: ${why}" ;;
    esac
    return "$rc"
}

java_homes() {   # every directory with bin/java under ROOTS, once
    local r
    for r in $ROOTS; do [[ -d "$r" ]] && find "$r" -maxdepth "$MAX_DEPTH" -type f -path '*/bin/java' 2>/dev/null; done \
        | while IFS= read -r j; do d="$(dirname "$(dirname "$j")")"; readlink -f "$d"; done | awk '!seen[$0]++'
}
# running JVMs: "pid<TAB>java home<TAB>flag-state"
running_jvms() {
    local p exe home flag
    for p in /proc/[0-9]*; do
        exe="$(readlink "$p/exe" 2>/dev/null)" || continue
        [[ "${exe##*/}" == java ]] || continue
        home="$(dirname "$(dirname "$exe")")"
        # A JVM in a container: its paths are inside the container, which /proc/PID/root shows from here.
        if [[ ! -f "$home/release" && -f "${p}/root${home}/release" ]]; then home="${p}/root${home}"; fi
        flag=no
        if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q -- "$FLAG"; then flag=yes
        elif tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' | grep -q -- "$FLAG"; then flag=yes; fi
        printf '%s\t%s\t%s\n' "${p#/proc/}" "$home" "$flag"
    done
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments (set ROOTS to choose where it looks)"
    limited_view "Java runtimes and processes"
    [[ "${CPUINFO_FILE}" != /proc/cpuinfo ]] && CPUINFO_FILE_GIVEN=1
    cpu_check
    step "CPU"
    case "$VBMI" in
        yes) bad "this CPU has AVX-512 VBMI: an affected Java takes the vulnerable path" ;;
        no) inf "this CPU has no AVX-512 VBMI: the vulnerable path is never taken here (a move to another host can change that)" ;;
        *) caution "the CPU flags could not be read: treated as exposed" ;;
    esac
    step "Java runtimes"
    local h n=0
    while IFS= read -r h; do [[ -n "$h" ]] || continue; n=$((n + 1)); judge_home "$h" "$h"; done < <(java_homes)
    [[ $n -gt 0 ]] || inf "no Java runtime under ${ROOTS}"
    step "Running Java processes"
    local pid home flag v rc why m=0
    while IFS=$'\t' read -r pid home flag; do
        [[ -n "$pid" ]] || continue; m=$((m + 1))
        v="$(runtime_version "$home")"; IFS='|' read -r rc why <<<"$(judge "$v")"
        if [[ $rc -eq 1 ]] && backported "$home/bin/java"; then rc=0; fi
        if [[ $rc -eq 1 && $flag == yes ]]; then N_MITIGATED=$((N_MITIGATED + 1)); info "pid ${pid}: ${home} ${v}: affected, but runs with ${FLAG}"
        elif [[ $rc -eq 1 ]]; then
            case "$AFFECTED_HOMES" in *" $(readlink -f "$home") "*) ;; *) N_AFF=$((N_AFF + 1)); AFFECTED_HOMES+="$(readlink -f "$home") " ;; esac
            bad "pid ${pid}: ${home} ${v}: ${RED}affected${NC}, without the workaround flag ($(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120))"
        else inf "pid ${pid}: ${home} ${v:-?}"; fi
    done < <(running_jvms)
    [[ $m -gt 0 ]] || inf "no Java process running"

    step "Verdict"
    if [[ $N_AFF -gt 0 && "$VBMI" != no ]]; then
        warn "${N_AFF} affected runtime(s) on a CPU that takes the vulnerable path (${CVE}). Update Java (Oracle 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, or your vendor's November build); for a product that bundles its own Java (Jira, Confluence, Jenkins and others), update the product or its bundled runtime. Restart each JVM after updating. Until then: 'sudo ${SELF} mitigate --restart' sets ${FLAG} for running services."
        return 1
    fi
    if [[ $N_AFF -gt 0 ]]; then warn "${N_AFF} affected runtime(s), not exposed on this CPU. Update anyway: a migration, a cluster node or a new instance type can have AVX-512 VBMI."; return 0; fi
    if [[ $N_UNK -gt 0 ]]; then warn "${N_UNK} runtime(s) could not be judged (above)."; return 2; fi
    info "No affected Java runtime found."
    return 0
}

# ---------- mitigate and rollback ---------------------------------------------
RESTART=0
manifest_add() { mkdir -p "$STATE_DIR" && printf '%s\t%s\n' "$1" "$2" >> "$STATE_DIR/manifest"; }
unit_of_pid() { [[ -n "${UNIT_FOR_PID:-}" ]] && { echo "$UNIT_FOR_PID"; return; }; sed -nE 's#.*/([^/]+\.service)$#\1#p' "/proc/$1/cgroup" 2>/dev/null | head -n1; }
cmd_mitigate() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (mitigate [--dry-run] [--restart])" ;; esac; done
    [[ $dry -eq 1 ]] || need_root "mitigate adds systemd drop-ins"
    have systemctl || die "systemctl not found: add ${FLAG} to each JVM's options yourself"
    local pid home flag v rc why unit cur new f units=() others=()
    while IFS=$'\t' read -r pid home flag; do
        [[ -n "$pid" && "$flag" == no ]] || continue
        v="$(runtime_version "$home")"; IFS='|' read -r rc why <<<"$(judge "$v")"
        [[ $rc -eq 1 ]] || continue
        backported "$home/bin/java" && continue
        unit="$(unit_of_pid "$pid")"
        if [[ -z "$unit" ]]; then others+=("pid ${pid} (${home} ${v})"); continue; fi
        case " ${units[*]-} " in *" $unit "*) continue ;; esac
        units+=("$unit")
    done < <(running_jvms)
    step "Services to change"
    if [[ ${#units[@]} -eq 0 ]]; then inf "no running systemd service runs an affected Java without the flag"; fi
    for unit in ${units[@]+"${units[@]}"}; do
        cur="$(systemctl show -p Environment --value "$unit" 2>/dev/null | tr ' ' '\n' | sed -nE 's/^JAVA_TOOL_OPTIONS=//p' | head -n1)"
        if [[ "$cur" == *[\"\\\$\`]* ]]; then caution "${unit}: its JAVA_TOOL_OPTIONS holds quotes or backslashes: add ${FLAG} to it yourself"; continue; fi
        new="${cur:+$cur }-XX:+IgnoreUnrecognizedVMOptions ${FLAG}"
        f="${DROPIN_ROOT}/${unit}.d/${DROPIN_NAME}"
        if [[ $dry -eq 1 ]]; then inf "would write ${f}: Environment=\"JAVA_TOOL_OPTIONS=${new}\""; continue; fi
        mkdir -p "$(dirname "$f")" || { bad "${unit}: cannot create $(dirname "$f")"; continue; }
        printf '# Written by %s %s: workaround for %s until Java is updated. Remove with: %s rollback\n[Service]\nEnvironment="JAVA_TOOL_OPTIONS=%s"\n' \
            "$SCRIPT_NAME" "$SCRIPT_VERSION" "$CVE" "$SCRIPT_NAME" "$new" > "$f"
        manifest_add dropin "$f"
        info "${unit}: ${f}"
    done
    for v in ${others[@]+"${others[@]}"}; do caution "${v}: not a systemd service: add ${FLAG} to its JVM options yourself, then restart it"; done
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was written."; return 0; fi
    [[ ${#units[@]} -eq 0 ]] && return 0
    systemctl daemon-reload 2>/dev/null || bad "systemctl daemon-reload failed"
    if [[ $RESTART -eq 1 ]]; then
        for unit in "${units[@]}"; do if systemctl restart "$unit"; then info "restarted ${unit}"; else bad "${unit} did not restart: run '${SELF} rollback' if the flag is the cause"; fi; done
    else warn "Not in effect until each service restarts: add --restart, or run: systemctl restart ${units[*]}"; fi
    return 0
}
cmd_rollback() {
    local dry=0 a kind f
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (rollback [--dry-run] [--restart])" ;; esac; done
    local manifest="${STATE_DIR}/manifest"
    [[ -s "$manifest" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback removes systemd drop-ins"
    local units=()
    while IFS=$'\t' read -r kind f; do
        [[ "$kind" == dropin ]] || continue
        if [[ $dry -eq 1 ]]; then echo "  would remove ${f}"; continue; fi
        rm -f "$f" && info "removed ${f}"; rmdir "$(dirname "$f")" 2>/dev/null || true
        units+=("$(basename "$(dirname "$f")" .d)")
    done < "$manifest"
    [[ $dry -eq 1 ]] && return 0
    mv "$manifest" "${manifest}.rolled-back-$(date +%s)" 2>/dev/null || true
    have systemctl && systemctl daemon-reload 2>/dev/null
    if [[ $RESTART -eq 1 ]]; then for a in ${units[@]+"${units[@]}"}; do systemctl restart "$a" && info "restarted ${a}"; done
    elif [[ ${#units[@]} -gt 0 ]]; then warn "Restart to drop the flag: systemctl restart ${units[*]}"; fi
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
    echo "${CVE} (Java4Shell): Java 17.0.6+, 21, 25 and 27 on CPUs with AVX-512 VBMI"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
