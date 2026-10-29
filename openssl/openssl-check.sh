#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# OpenSSL DTLS handshake retransmission read (heap disclosure): read-only checker  (v1)
# CVE-2026-84782
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# OpenSSL's security release of 29 September 2026 fixed 14 flaws. One is rated High:
# CVE-2026-84782, "DTLS retransmits handshake messages from a stale buffer offset".
# When DTLS retransmits a handshake message it can read from the wrong place in a buffer,
# so a remote peer may receive unintended plaintext heap memory in the handshake data, or
# the program may crash. CISA scored it 8.2 (confidentiality low, availability high).
# Found by Laurent Gaffie (Secorizon); fix by Ryan Hooper. The FIPS module is not affected.
#
# It matters only to software that speaks DTLS (TLS over UDP): VPN servers such as ocserv,
# VoIP and WebRTC servers such as Asterisk, FreeSWITCH, Janus and coturn, and IoT
# endpoints. Ordinary TLS (HTTPS, SMTP, IMAP, databases) does not use the vulnerable
# code. Node.js and Python's ssl module have no DTLS API.
#
#   Affected: 4.0.0 before 4.0.3, 3.6 before 3.6.5, 3.5 before 3.5.9, 3.4 before 3.4.8,
#             3.0 before 3.0.23, 1.1.1 before 1.1.1zj, 1.0.2 before 1.0.2zs.
#   Fixed:    public releases 4.0.3, 3.6.5, 3.5.9, 3.4.8. The fixes for 3.0 (3.0.23),
#             1.1.1 (1.1.1zj) and 1.0.2 (1.0.2zs) are available only to premium-support
#             customers, and public support for 3.0 ended on 7 September 2026. Branches
#             3.1 to 3.3 are end of life and were not evaluated by OpenSSL.
#   Ubuntu:   fixed in openssl 3.5.5-1ubuntu3.6 (26.04), 3.0.13-0ubuntu3.16 (24.04) and
#             3.0.2-0ubuntu1.30 (22.04); older Ubuntu releases were still "needs
#             evaluation". Other distributions backport under their own version numbers.
#
# How this script decides. A distribution package is judged by its changelog naming
# CVE-2026-84782 (a backport), and for Ubuntu also against the fixed package versions
# above. A copy that no package owns (a local build, a bundled library) is judged by the
# upstream version compared with the table. A "cannot confirm" is reported when a
# distribution package has no changelog entry and no published fixed version to compare.
# It also reports DTLS-capable daemons that are running and processes still holding an
# old libssl in memory (a library update does not reach a running process until it
# restarts).
#
# This script is read-only.
#
# Usage:
#   ./openssl-check.sh [check]
#   check (default)  Exit 0 = nothing exposed, 1 = an affected or unconfirmed OpenSSL.
#   version          print the script version.
#
# Env: OPENSSL_BIN, OPENSSL_PKG_VERSION, OPENSSL_OS_RELEASE, OPENSSL_CHANGELOG, OPENSSL_PROC,
#      OPENSSL_NODE override the openssl command, the package version, /etc/os-release, a
#      changelog file (plain or .gz), /proc and the node command. OPENSSL_NO_PACKAGE=1 treats
#      the installed openssl as not owned by a package (a local build).
#      SCAN_CONTAINERS=1 (the default) also reads OpenSSL inside running docker and podman
#      containers, judged by each container's own distribution and packages; 0 skips them.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="openssl-check.sh"
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
# ---------- version rules ----------------------------------------------------
# compare the letter suffix of 1.0.2 and 1.1.1 releases: a < z < za < zj  (length first, then letters)
suffix_ge() {   # A B -> 0 if A >= B
    local a="$1" b="$2"
    (( ${#a} > ${#b} )) && return 0
    (( ${#a} < ${#b} )) && return 1
    [[ "$a" > "$b" || "$a" == "$b" ]]
}
# prints: fixed | affected | nopublicfix | eol | unknown     (for an upstream version)
#   nopublicfix = affected, and the fix exists only for premium-support customers (3.0, 1.1.1, 1.0.2)
#   eol         = a branch OpenSSL no longer supports and did not evaluate (3.1 to 3.3)
openssl_status() {
    local v="$1" maj min pat suf pre=""
    # a development or alpha/beta build of a release is a tree heading toward that release: of the
    # fixed release itself it may not carry the fix; of a later release it does
    if [[ "$v" =~ ^(.+)-(dev|alpha[0-9]*|beta[0-9]*)$ ]]; then
        v="${BASH_REMATCH[1]}"; pre=1
        case "$v" in 4.0.3|3.6.5|3.5.9|3.4.8|3.0.23|1.1.1zj|1.0.2zs) echo prerelease; return ;; esac
    fi
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([a-z]*)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; suf="${BASH_REMATCH[4]}"
    case "${maj}.${min}.${pat}" in
        1.1.1) suffix_ge "$suf" zj && echo fixed || echo nopublicfix; return ;;
        1.0.2) suffix_ge "$suf" zs && echo fixed || echo nopublicfix; return ;;
    esac
    case "${maj}.${min}" in
        4.0) (( pat >= 3 ))  && echo fixed || echo affected ;;
        3.6) (( pat >= 5 ))  && echo fixed || echo affected ;;
        3.5) (( pat >= 9 ))  && echo fixed || echo affected ;;
        3.4) (( pat >= 8 ))  && echo fixed || echo affected ;;
        3.0) (( pat >= 23 )) && echo fixed || echo nopublicfix ;;
        3.1|3.2|3.3) echo eol ;;
        *) if (( maj > 4 || (maj == 4 && min > 0) )); then echo fixed; else echo unknown; fi ;;
    esac
}

# ---------- the installed OpenSSL --------------------------------------------
parse_cli_line() {   # "OpenSSL 3.0.13 30 Jan 2024" -> 3.0.13 ; a LibreSSL line -> libressl ; else nothing
    local out="$1"
    if [[ "$out" =~ ^OpenSSL[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+[a-z]*(-(dev|alpha[0-9]*|beta[0-9]*))?)([[:space:]]|$) ]]; then echo "${BASH_REMATCH[1]}"
    elif [[ "$out" == LibreSSL* ]]; then echo "libressl"; fi
}
cli_version() {   # the version the openssl command reports, or LibreSSL, or empty
    parse_cli_line "$("${OPENSSL_BIN:-openssl}" version 2>/dev/null | head -n1)"
}
package_info() {   # "<package> <version>" of the installed runtime library, or nothing
    local line
    [[ -n "${OPENSSL_NO_PACKAGE:-}" ]] && return 0
    if [[ -n "${OPENSSL_PKG_VERSION:-}" ]]; then echo "libssl ${OPENSSL_PKG_VERSION}"; return; fi
    if have dpkg-query; then
        line="$(dpkg-query -W -f='${Package} ${Version}\n' libssl3t64 libssl3 libssl1.1 libssl1.0.0 openssl 2>/dev/null | awk 'NF>=2 {print; exit}')"
        [[ -n "$line" ]] && { echo "$line"; return; }
    fi
    if have rpm; then
        line="$(rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' openssl-libs openssl 2>/dev/null | awk 'NF>=2 && $0 !~ /not installed/ {print; exit}')"
        [[ -n "$line" ]] && echo "$line"
    fi
}
changelog_names_cve() {
    local pkg c
    if [[ -n "${OPENSSL_CHANGELOG:-}" ]]; then
        [[ -r "${OPENSSL_CHANGELOG}" ]] || return 1
        if zcat -f "${OPENSSL_CHANGELOG}" 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
        return 1
    fi
    if have dpkg; then
        for pkg in libssl3t64 libssl3 libssl1.1 openssl; do
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] || continue
                if zcat -f "$c" 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
            done
        done
    fi
    if have rpm && rpm -q openssl-libs >/dev/null 2>&1; then
        if rpm -q --changelog openssl-libs 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
    fi
    return 1
}
ubuntu_fix_for() {   # <os id> <version id> -> the fixed package version for that Ubuntu release, or empty
    local id="$1" vid="$2"
    [[ "$id" == ubuntu ]] || return 0
    case "$vid" in
        26.04) echo "3.5.5-1ubuntu3.6" ;;
        24.04) echo "3.0.13-0ubuntu3.16" ;;
        22.04) echo "3.0.2-0ubuntu1.30" ;;
        *)     echo "unlisted" ;;
    esac
}
ubuntu_fixed_package() {   # os-release -> the fixed package version for this Ubuntu release, or empty
    local f="${OPENSSL_OS_RELEASE:-/etc/os-release}" id vid
    [[ -r "$f" ]] || return 0
    id="$(sed -nE 's/^ID=//p' "$f" | tr -d '"')"; vid="$(sed -nE 's/^VERSION_ID=//p' "$f" | tr -d '"')"
    ubuntu_fix_for "$id" "$vid"
}

# ---------- running containers -----------------------------------------------
# One probe script, fed to "sh -s" inside each running container, prints what is needed to judge
# its OpenSSL by the container's OWN distribution and package database, never the host's.
OPENSSL_PROBE='. /etc/os-release 2>/dev/null
echo "OSID=${ID:-}"; echo "OSVER=${VERSION_ID:-}"
if command -v dpkg-query >/dev/null 2>&1; then
    echo "PKG=$(dpkg-query -W -f="\${Package} \${Version}\n" libssl3t64 libssl3 libssl1.1 libssl1.0.0 openssl 2>/dev/null | awk "NF>=2 {print; exit}")"
elif command -v rpm >/dev/null 2>&1; then
    echo "PKG=$(rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE}\n" openssl-libs openssl 2>/dev/null | awk "NF>=2 && \$0 !~ /not installed/ {print; exit}")"
elif command -v apk >/dev/null 2>&1; then
    echo "PKG=$(apk info -v 2>/dev/null | grep -E "^(libssl|libcrypto|openssl)" | head -n1 | sed -E "s/^(.*)-([0-9][^-]*-r[0-9]+)\$/\1 \2/")"
fi
echo "CLI=$(openssl version 2>/dev/null | head -n1)"
for c in /usr/share/doc/libssl3t64/changelog.Debian.gz /usr/share/doc/libssl3/changelog.Debian.gz /usr/share/doc/libssl1.1/changelog.Debian.gz /usr/share/doc/openssl/changelog.Debian.gz; do
    if [ -r "$c" ] && zcat -f "$c" 2>/dev/null | grep -F CVE-2026-84782 >/dev/null; then echo "CHG=1"; fi
done
exit 0'

# The verdict for one container's OpenSSL, by the same rules as the system OpenSSL above.
# Returns 0 fixed or not affected, 1 affected or unconfirmed, 2 no OpenSSL in this container.
container_openssl() {   # <label> <os id> <os version> <"package version"> <changelog 0|1> <openssl version line>
    local label="$1" osid="$2" osver="$3" pkginfo="$4" chg="$5" cline="$6" cliv pkg pkgver ufix st
    cliv="$(parse_cli_line "$cline")"; pkg="${pkginfo%% *}"; pkgver="${pkginfo#* }"; [[ -n "$pkginfo" ]] || pkgver=""
    if [[ "$cliv" == libressl ]]; then inf "${label}: LibreSSL, which is not OpenSSL and not affected"; return 0; fi
    if [[ -z "$cliv" && -z "$pkginfo" ]]; then
        # nothing readable: no OpenSSL here, or an openssl command whose output cannot be read
        [[ -n "$cline" ]] || return 2
        caution "${label}: an openssl command is present but its version could not be read ('${cline}'): check it by hand"; return 1
    fi
    if [[ "$chg" == 1 ]]; then ok "${label}: the package changelog names CVE-2026-84782: this build carries the fix (a backport), whatever its version number says"; return 0; fi
    if [[ -n "$pkginfo" ]]; then
        ufix="$(ubuntu_fix_for "$osid" "$osver")"
        if [[ -n "$ufix" && "$ufix" != unlisted ]]; then
            if ! have dpkg || [[ ! "$pkgver" =~ ^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$ ]]; then
                caution "${label}: package ${pkg} ${pkgver} cannot be compared here: check it against Ubuntu's fixed version ${ufix}"; return 1
            fi
            if dpkg --compare-versions "$pkgver" ge "$ufix" 2>/dev/null; then ok "${label}: package ${pkgver} is at or beyond Ubuntu's fixed version ${ufix}"; return 0; fi
            bad "${label}: package ${pkgver} is older than Ubuntu's fixed version ${ufix}: CVE-2026-84782 is NOT fixed in this container"; return 1
        fi
        if [[ "$ufix" == unlisted ]]; then
            caution "${label}: this Ubuntu release had no fixed package listed in the sources used: check ubuntu.com/security/ for ${pkg} ${pkgver}"; return 1
        fi
        caution "${label}: cannot confirm: the changelog of ${pkg} does not name CVE-2026-84782 and this distribution's fixed version is not in the sources used. Check your distribution's advisory for ${pkg} ${pkgver}"; return 1
    fi
    st="$(openssl_status "$cliv")"
    case "$st" in
        fixed)      ok "${label}: OpenSSL ${cliv} (no package database in the container) is at or beyond the fixed release of its branch"; return 0 ;;
        affected)   bad "${label}: OpenSSL ${cliv} (no package database in the container) is below the fixed release of its branch (4.0.3, 3.6.5, 3.5.9, 3.4.8): rebuild the image on a fixed base"; return 1 ;;
        nopublicfix|eol) bad "${label}: OpenSSL ${cliv} is on a branch with no public fix (${st}): move the image to a supported branch"; return 1 ;;
        prerelease) caution "${label}: OpenSSL ${cliv} is a development or pre-release build of the fixed release, not the release: it may not carry the fix"; return 1 ;;
        *)          caution "${label}: cannot interpret OpenSSL version '${cliv}'"; return 1 ;;
    esac
}

CONT_RC=0
containers_report() {
    CONT_RC=0
    local rt id name osid osver pkginfo chg cline l seen=0 any=0 r
    step "Running containers"
    if [[ "${SCAN_CONTAINERS:-1}" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"; return 0; fi
    if ! have docker && ! have podman; then inf "no docker or podman CLI"; return 0; fi
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            seen=$((seen + 1)); osid=""; osver=""; pkginfo=""; chg=0; cline=""
            while IFS= read -r l; do
                case "$l" in OSID=*) osid="${l#OSID=}" ;; OSVER=*) osver="${l#OSVER=}" ;; PKG=*) pkginfo="${l#PKG=}" ;; CLI=*) cline="${l#CLI=}" ;; CHG=1) chg=1 ;; esac
            done < <(printf '%s\n' "$OPENSSL_PROBE" | "$rt" exec -i "$id" sh -s 2>/dev/null)
            container_openssl "${rt} ${name:-$id}" "$osid" "$osver" "$pkginfo" "$chg" "$cline"; r=$?
            case $r in 0) any=$((any + 1)) ;; 1) any=$((any + 1)); CONT_RC=1 ;; esac
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
    inf "${seen} running container(s) examined, ${any} with an OpenSSL"
    inf "OpenSSL linked statically into a program inside a container is not visible here; rebuild such images on a fixed base"
}

cmd_check() {
    local rc=0 cliv pkginfo pkg pkgver ufix st f v
    step "The system OpenSSL"
    cliv="$(cli_version)"; pkginfo="$(package_info)"; pkg="${pkginfo%% *}"; pkgver="${pkginfo#* }"; [[ -n "$pkginfo" ]] || pkgver=""
    if [[ "$cliv" == libressl ]]; then inf "the openssl command is LibreSSL, which is not OpenSSL and not affected"
    elif [[ -z "$cliv" && -z "$pkginfo" ]] && have "${OPENSSL_BIN:-openssl}"; then caution "an openssl command was found but its version could not be read: check it by hand against 4.0.3, 3.6.5, 3.5.9 or 3.4.8"; rc=1
    elif [[ -z "$cliv" && -z "$pkginfo" ]]; then info "no openssl command or OpenSSL package found"
    else
        [[ -n "$cliv" ]] && inf "openssl command: OpenSSL ${cliv}"
        [[ -n "$pkginfo" ]] && inf "package: ${pkg} ${pkgver}"
        if changelog_names_cve; then
            ok "the package changelog names CVE-2026-84782: this build carries the fix (a backport), whatever its version number says"
        elif [[ -n "$pkginfo" ]]; then
            ufix="$(ubuntu_fixed_package)"
            if [[ -n "$ufix" && "$ufix" != unlisted && ! "$pkgver" =~ ^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$ ]]; then
                caution "the package version '${pkgver}' is not a version string this script can compare: check ${pkg} against Ubuntu's fixed version ${ufix}"; rc=1
            elif [[ -n "$ufix" && "$ufix" != unlisted ]]; then
                if have dpkg && dpkg --compare-versions "$pkgver" ge "$ufix" 2>/dev/null; then ok "package ${pkgver} is at or beyond Ubuntu's fixed version ${ufix}"
                else bad "package ${pkgver} is older than Ubuntu's fixed version ${ufix}: CVE-2026-84782 is NOT fixed on this host"; rc=1; fi
            elif [[ "$ufix" == unlisted ]]; then
                caution "this Ubuntu release had no fixed package listed in the sources used (Ubuntu marked older releases 'needs evaluation'): check ubuntu.com/security/CVE-2026-84782"; rc=1
            else
                caution "cannot confirm: the changelog of ${pkg} does not name CVE-2026-84782 and this distribution's fixed version is not in the sources used. Check your vendor's security tracker"; rc=1
            fi
        else
            st="$(openssl_status "$cliv")"
            case "$st" in
                fixed)       ok "OpenSSL ${cliv} (not from a package) is at or beyond the fixed release of its branch" ;;
                affected)    bad "OpenSSL ${cliv} (not from a package) is below the fixed release of its branch (4.0.3, 3.6.5, 3.5.9, 3.4.8): update"; rc=1 ;;
                nopublicfix) bad "OpenSSL ${cliv} (not from a package) is affected, and the fix for this branch is available only to premium-support customers: move to a supported branch (3.4 or later) or use a vendor package that carries the fix"; rc=1 ;;
                eol)         bad "OpenSSL ${cliv} is on an end-of-life branch OpenSSL did not evaluate: move to a supported branch"; rc=1 ;;
                prerelease)  caution "OpenSSL ${cliv} is a development or pre-release build of the fixed release, not the release: it may not carry the fix. Build or install 3.6.5, 3.5.9, 3.4.8 or 4.0.3 or later"; rc=1 ;;
                *)           caution "cannot interpret OpenSSL version '${cliv}'"; rc=1 ;;
            esac
        fi
    fi
    step "Copies bundled outside the system"
    local n=0 seen=""
    while IFS= read -r f; do
        f="$(readlink -f "$f" 2>/dev/null)"; [[ -n "$f" && "$seen" != *"|$f|"* ]] || continue; seen+="|$f|"
        v="$(grep -a -oE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]*' "$f" 2>/dev/null | head -n1 | sed 's/^OpenSSL //')"
        [[ -n "$v" ]] || continue
        n=$((n+1)); st="$(openssl_status "$v")"
        if [[ "$st" == fixed ]]; then ok "${f}: OpenSSL ${v}"
        else bad "${f}: bundled OpenSSL ${v} is affected (${st}); it is updated by whoever ships that software, not by the system package"; rc=1; fi
    done < <(find /opt /usr/local /srv /home -xdev -maxdepth 6 -type f \( -name 'libcrypto.so*' -o -name 'libcrypto-*.so' \) 2>/dev/null | head -n 60)
    [[ $n -eq 0 ]] && ok "no OpenSSL library found under /opt, /usr/local, /srv or /home"
    local nv; nv="$("${OPENSSL_NODE:-node}" -p 'process.versions.openssl' 2>/dev/null | head -n1)"
    if [[ -n "$nv" ]]; then
        st="$(openssl_status "$nv")"
        inf "Node.js bundles OpenSSL ${nv} ($([[ "$st" == fixed ]] && echo 'fixed' || echo 'below the fixed release')). Node.js has no DTLS API, so this flaw is not reachable through it; it still updates with Node.js releases"
    fi
    step "Where DTLS could be in use"
    local base="${OPENSSL_PROC:-/proc}" p comm m nmap=0 nstale=0 dl="" sl=""
    local dtls_re='^(turnserver|coturn|asterisk|freeswitch|janus|janus-gateway|kamailio|opensips|ocserv|ocserv-main|dtls.*|coap.*)$'
    for p in "$base"/[0-9]*; do
        [[ -r "$p/maps" ]] || continue
        m="$(grep -E 'lib(ssl|crypto)[^ ]*\.so' "$p/maps" 2>/dev/null)"; [[ -n "$m" ]] || continue
        nmap=$((nmap+1)); comm="$(cat "$p/comm" 2>/dev/null)"
        if [[ "$comm" =~ $dtls_re && "$dl" != *"|$comm|"* ]]; then dl+="|$comm|"; fi
        if grep -E '\(deleted\)' <<<"$m" >/dev/null; then nstale=$((nstale+1)); [[ "$sl" != *"|$comm|"* ]] && sl+="|$comm|"; fi
    done
    inf "${nmap} process(es) have OpenSSL mapped"
    if [[ -n "$dl" ]]; then caution "DTLS-capable services are running: $(sed 's/^|*//; s/|*$//; s/||*/ /g' <<<"$dl"): these are the software the flaw can reach"
    else inf "no DTLS-capable service from the usual list is running; ordinary TLS services do not use the vulnerable code"; fi
    if [[ $nstale -gt 0 ]]; then caution "${nstale} process(es) still hold a replaced OpenSSL in memory and keep the old code until restarted: $(sed 's/^|*//; s/|*$//; s/||*/ /g' <<<"$sl")"; rc=1; fi
    containers_report
    if [[ $CONT_RC -eq 1 ]]; then rc=1; fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No affected or unconfirmed OpenSSL found."
    else
        warn "OpenSSL affected or unconfirmed (CVE-2026-84782, High). Update the OpenSSL package, then restart services that use it (needrestart or a reboot)."
        inf "Fixed public releases: 4.0.3, 3.6.5, 3.5.9, 3.4.8. Ubuntu: 3.5.5-1ubuntu3.6, 3.0.13-0ubuntu3.16, 3.0.2-0ubuntu1.30"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-84782 (OpenSSL DTLS handshake retransmission read); fixed in 4.0.3, 3.6.5, 3.5.9, 3.4.8"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
