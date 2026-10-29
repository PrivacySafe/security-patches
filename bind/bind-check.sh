#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# ISC BIND 9 GSS-TSIG memory corruption: read-only checker  (v1)
# CVE-2026-94300
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Replaying a GSS-TSIG signed UDP message can corrupt memory in named, the BIND 9
# name server. ISC says that, combined with crafted queries to a zone the attacker
# controls, it can lead to remote code execution, and at minimum it can crash
# named. Rated High, CVSS 8.1 (the attack is complex: the attacker must capture a
# signed message and replay it while the key is still valid). ISC knows of no
# active exploitation and lists NO WORKAROUND.
#
#   Affected: BIND 9.11.0 through 9.18.50, 9.20.0 through 9.20.29,
#             9.21.0 through 9.21.26 (and matching -S1 Supported Preview builds)
#   Fixed:    9.20.30 and 9.21.27 (9.20.30-S1 for the Preview Edition)
#   No fix:   the 9.18 branch and everything older is end of life; ISC does not
#             ship security fixes for it. Move to 9.20. Distributions that still
#             support 9.18 may backport the fix: the script looks for that.
#
# The code is present in every build, but the vulnerable path needs GSS-TSIG,
# which is used for secure dynamic updates against Kerberos or Active Directory.
# One analysis says builds without GSS-TSIG configured do not reach it; ISC's
# advisory text does not spell out which configuration is required,
# so the script reports whether GSS-TSIG is configured as a hint, never as proof
# of safety, and tells you to update either way.
#
# The same BIND releases fix three other denial of service flaws, which only the
# update fixes.
#
# This script is read-only. It finds named binaries (PATH, usual locations and
# running processes), reads the version from "named -v", reads named.conf and its
# include files, and looks for GSS-TSIG settings. It never reloads named.
#
# Usage:
#   ./bind-check.sh [command] [PATH-TO-named ...]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version is exposed
#                    or its configuration could not be read.
#   version          print the script version.
#
# Environment: NAMED_CONF (space separated files) replaces configuration discovery.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="bind-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"
SELF="$0"

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
have()    { command -v "$1" >/dev/null 2>&1; }

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
ver_ge() { ! ver_lt "$1" "$2"; }
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
DISTRO_PKG=""; DISTRO_HIT=""
distro_mentions() {
    local f real pkg="" cl="" c id
    f="$1"; shift
    real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if have dpkg; then
        pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] && cl+="$(zcat "$c" 2>/dev/null)"
            done
        fi
    fi
    if [[ -z "$pkg" ]] && have rpm; then
        pkg="$(rpm -qf "$real" 2>/dev/null | head -n1)"
        [[ "$pkg" == *"not owned"* ]] && pkg=""
        [[ -n "$pkg" ]] && cl="$(rpm -q --changelog "$pkg" 2>/dev/null)"
    fi
    [[ -n "$pkg" ]] || return 2
    DISTRO_PKG="$pkg"
    for id in "$@"; do
        if grep -qF "$id" <<<"$cl"; then DISTRO_HIT="$id"; return 0; fi
    done
    return 1
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- version rule -----------------------------------------------------
# prints: vulnerable | eol | fixed | unknown
bind_status() {
    local v="$1" major minor patch
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
    (( major == 9 )) || { (( major > 9 )) && echo fixed || echo eol; return; }
    if (( minor <= 19 )); then echo eol; return; fi          # 9.11 .. 9.18 and the 9.19 development line
    if (( minor == 20 )); then (( patch < 30 )) && echo vulnerable || echo fixed; return; fi
    if (( minor == 21 )); then (( patch < 27 )) && echo vulnerable || echo fixed; return; fi
    echo fixed                                              # 9.22 and later
}

# ---------- discovery --------------------------------------------------------
bin_version() {   # binary -> the first x.y.z found in "named -v"
    "$1" -v 2>/dev/null | head -n1 | grep -oE '9\.[0-9]+\.[0-9]+' | head -n1
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v named 2>/dev/null)" /usr/sbin/named /usr/local/sbin/named /usr/bin/named /usr/local/bin/named; do
        [[ -n "$b" && -x "$b" ]] && out+=("$(readlink -f "$b")")
    done
    shopt -s nullglob
    for b in /opt/bind*/sbin/named /opt/isc/*/sbin/named; do [[ -x "$b" ]] && out+=("$(readlink -f "$b")"); done
    shopt -u nullglob
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2=="named"{print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

# resolve named.conf and the files it includes (depth-limited, no loops)
collect_conf() {   # file depth -> prints readable files, one per line
    local f="$1" depth="$2" inc g
    [[ -r "$f" && -f "$f" ]] || return 0
    case " ${SEEN_CONF:-} " in *" $f "*) return 0 ;; esac
    SEEN_CONF="${SEEN_CONF:-} $f"
    echo "$f"
    (( depth >= 5 )) && return 0
    while IFS= read -r inc; do
        [[ -n "$inc" ]] || continue
        [[ "$inc" == /* && -n "${CONF_ROOT:-}" ]] && inc="${CONF_ROOT}${inc}"   # a configuration staged from a container
        [[ "$inc" == /* ]] || inc="$(dirname "$f")/$inc"
        # shellcheck disable=SC2086
        for g in $inc; do collect_conf "$g" $((depth+1)); done
    done < <(sed -E 's#//.*$##; s/^[[:space:]]*#.*$//' "$f" | grep -oE '^[[:space:]]*include[[:space:]]+"[^"]+"' | sed -E 's/^[[:space:]]*include[[:space:]]+"([^"]+)"/\1/')
}

config_files() {
    local f p
    SEEN_CONF=""
    if [[ -n "${NAMED_CONF:-}" ]]; then
        for f in $NAMED_CONF; do collect_conf "$f" 0; done
        return 0
    fi
    p=""
    if have ps; then p="$(ps -eo args= 2>/dev/null | grep -E '(^|/)named( |$)' | grep -oE -- '-c[[:space:]]+[^[:space:]]+' | head -n1 | sed -E 's/^-c[[:space:]]+//')"; fi
    for f in $p /etc/bind/named.conf /etc/named.conf /usr/local/etc/named.conf /usr/local/etc/namedb/named.conf /var/named/chroot/etc/named.conf; do
        [[ -n "$f" && -r "$f" ]] && { collect_conf "$f" 0; break; }
    done
}

# GSS-TSIG indicators in configuration text (comments removed)
GSS_HITS=""
scan_gss() {   # file
    local hit
    hit="$(sed -E 's#//.*$##; s/^[[:space:]]*#.*$//' "$1" | grep -noE 'tkey-gssapi-keytab|tkey-gssapi-credential|tkey-domain|krb5-self|krb5-selfsub|krb5-subdomain|krb5-subdomain-self-rhs|ms-self|ms-selfsub|ms-subdomain|ms-subdomain-self-rhs' | head -n3)"
    [[ -n "$hit" ]] && GSS_HITS+="$(sed "s#^#$1:#" <<<"$hit")"$'\n'
    return 0
}

# ---------- check ------------------------------------------------------------
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

BIND_PROBE="$(cat <<'EOS'
n=""
for c in /usr/sbin/named /usr/local/sbin/named /usr/bin/named /usr/local/bin/named /opt/bind*/sbin/named /opt/isc/*/sbin/named; do [ -x "$c" ] && { n=$c; break; }; done
[ -n "$n" ] || exit 0
echo "B /.out_v $("$n" -v 2>/dev/null | head -n 1 | base64 | tr -d '\n')"
echo "B /.out_V $("$n" -V 2>/dev/null | head -n 40 | base64 | tr -d '\n')"
red() { sed -E 's/(secret[[:space:]]+")[^"]*"/\1REDACTED"/g' "$1" | base64 | tr -d '\n'; }
for f in /etc/bind /etc/named /usr/local/etc/namedb /var/named/chroot/etc; do
  [ -d "$f" ] && find "$f" -maxdepth 3 -type f -size -512k 2>/dev/null | head -n 60 | while read -r p; do echo "B $p $(red "$p")"; done
done
for f in /etc/named.conf /usr/local/etc/named.conf; do [ -f "$f" ] && echo "B $f $(red "$f")"; done
exit 0
EOS
)"

container_run() {   # <staged directory> : BIND in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -s "$s/.out_v" ]] || return 0
    printf '#!/bin/sh\ncase "$1" in\n  -v) cat "%s/.out_v" ;;\n  -V) cat "%s/.out_V" ;;\nesac\n' "$s" "$s" > "$s/named"; chmod 755 "$s/named"
    step "BIND in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 CONF_ROOT="$s" NAMED_CONF="$s/etc/bind/named.conf $s/etc/named.conf $s/usr/local/etc/named.conf $s/usr/local/etc/namedb/named.conf $s/var/named/chroot/etc/named.conf" bash "$SELF" check "$s/named" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$BIND_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a bins=()
    local rc=0 found=0 b raw st f read_any
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for BIND"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No named (BIND) found on this host"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        raw="$(bin_version "$b")"
        [[ -n "$raw" ]] || { caution "${b}: could not read a BIND 9 version from -v"; continue; }
        found=$((found+1))
        step "BIND ${raw} at ${b}"
        st="$(bind_status "$raw")"
        case "$st" in
            fixed)      ok "BIND ${raw} has the fix (9.20.30, 9.21.27 or newer)"; continue ;;
            unknown)    caution "cannot parse version '${raw}'"; continue ;;
            eol)        bad "BIND ${raw} is on an end-of-life branch (9.18 and older, or 9.19): affected by CVE-2026-94300 and ISC will not patch it" ;;
            vulnerable) bad "BIND ${raw} is affected by CVE-2026-94300 (fixed in 9.20.30 and 9.21.27)" ;;
        esac
        if distro_mentions "$b" CVE-2026-94300; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution has probably backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention the CVE yet"
            [[ "$st" == eol ]] && inf "if your distribution still supports this branch it may ship a backport: watch its security tracker"
        fi
        if "$b" -V 2>/dev/null | grep -- "--with-gssapi=yes\|--with-gssapi'\|--with-gssapi " >/dev/null; then
            inf "this build was compiled with GSSAPI support (--with-gssapi)"
        else
            inf "no --with-gssapi in this build's configure options, which suggests GSS-TSIG is not compiled in (the advisory does not say that this removes the flaw)"
        fi
        GSS_HITS=""; read_any=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            read_any=1; scan_gss "$f"; inf "read ${f}"
        done < <(config_files)
        if [[ $read_any -eq 0 ]]; then
            caution "no readable named.conf found: GSS-TSIG use cannot be checked, treating as exposed"
            rc=1; continue
        fi
        if [[ -n "$GSS_HITS" ]]; then
            bad "GSS-TSIG settings are present (the vulnerable path needs GSS-TSIG), first matches:"
            grep -v '^$' <<<"$GSS_HITS" | sed 's/^/        /' | head -n4
            rc=1
        else
            caution "no GSS-TSIG setting found in the configuration files read. One analysis says the flaw needs GSS-TSIG; ISC does not spell this out, so update anyway."
            [[ "$st" == eol ]] && inf "an end-of-life branch with no GSS-TSIG still has no upstream fix: plan the move to 9.20"
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No BIND version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed BIND found (${found} checked). Affected builds without GSS-TSIG still need the update."
    else
        warn "Exposed or unverifiable BIND found. Upgrade to 9.20.30 or 9.21.27 (or a distribution build that carries the fix), then restart named."
        inf "ISC lists no workaround. If you do not use GSS-TSIG (secure dynamic updates against Kerberos or Active Directory), removing those settings is our suggestion, not ISC's, and does not replace the update."
        inf "Advisory: https://kb.isc.org/docs/cve-2026-94300"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-94300; fixed in BIND 9.20.30 and 9.21.27"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
