#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Roundcube Webmail 1.6.20 and 1.7.5 security release: read-only checker  (v1)
# CVE-2026-114716 (mail header injection, CVSS 8.5)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Roundcube released 1.6.20 (LTS) and 1.7.5 (mainline) on 19 October 2026. Both
# carry the same 20 security fixes, the largest batch since 1.7.0: IMAP command
# injection, four mail header injection flaws, XSS, SSRF, CSRF, an object
# injection primitive in session handling and ImageMagick limit bypasses.
# CVE-2026-114716 is one of the mail header injection fixes (the release notes
# list header injection through the From display-name in Bounce, through the
# References, In-Reply-To, Message-ID and From parameters, through the subject
# of a message forwarded as an attachment, and through the media type of an
# inline image). A header injection lets an attacker add or alter headers of an
# outgoing message, which feeds phishing and mail forgery from a trusted host.
#
#   Affected: Roundcube 1.6.x before 1.6.20, and 1.7.x before 1.7.5
#   Fixed:    1.6.20 and 1.7.5. These releases do not cover 1.5 and earlier.
#
# Roundcube is bundled by hosting panels. cPanel and Plesk ship their own copy
# and update it with the panel, so the panel's changelog decides when it is safe.
#
# This script is read-only. It finds Roundcube installs, reads the version from
# program/include/iniset.php, and can search web server logs for CRLF probing
# of the _uid and _flag parameters (the IMAP injection that the same release
# fixes), which is a sign someone has been testing your webmail.
#
# Usage:
#   ./roundcube-oct2026-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home
#                    /usr/share/roundcube /usr/share/roundcubemail
#                    /var/lib/roundcube plus the cPanel and Plesk paths).
#                    Exit 0 = nothing affected, 1 = an affected install found.
#   hunt             search readable web server logs for _uid or _flag values
#                    that contain an encoded carriage return or line feed.
#                    Exit 0 = none found, 1 = matches found.
#   version          print the script version.
#
# Distribution packages backport fixes without changing the version string. The
# script reads the owning package changelog and reports a mention of the CVE.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="roundcube-oct2026-check.sh"
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

# ---------- helpers ----------------------------------------------------------
# prints fixed | vulnerable | eol | unknown
roundcube_status() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || { echo unknown; return; }
    case "${v%.*}" in
        1.6) ver_lt "$v" "1.6.20" && echo vulnerable || echo fixed ;;
        1.7) ver_lt "$v" "1.7.5"  && echo vulnerable || echo fixed ;;
        *)   if ver_lt "$v" "1.6.0"; then echo eol; else echo fixed; fi ;;
    esac
}

rc_version() {   # iniset.php -> version
    local f="$1" v dir
    v="$(sed -n "s/.*define([[:space:]]*['\"]RCMAIL_VERSION['\"],[[:space:]]*['\"]\([^'\"]*\)['\"].*/\1/p" "$f" | head -n1)"
    if [[ -z "$v" ]]; then
        dir="$(dirname "$(dirname "$(dirname "$f")")")"
        for c in "$dir/CHANGELOG.md" "$dir/CHANGELOG"; do
            [[ -r "$c" ]] || continue
            v="$(grep -m1 -oiE 'release [0-9]+\.[0-9]+\.[0-9]+' "$c" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')"
            [[ -n "$v" ]] && break
        done
    fi
    echo "$v"
}

# ---------- check ------------------------------------------------------------
# ---------- running containers -----------------------------------------------
# An install inside a container is not on the host. For each running container, find installs by
# their marker file, copy ONLY the files this check reads into a temporary directory (one per
# install, named after the container and the path inside it, mode 0700, removed on exit), and let
# the normal checks judge it like a host install. Paths the container reports are checked before
# they are used. The check never runs anything in a container beyond "find" and a file copy.
# It runs once, in the main shell (a subshell's exit would delete the copies early).
STAGE=""
declare -a STAGED_DIRS=()
stage_containers() {   # <marker file, relative to the install root> <other relative files the check reads>...
    local marker="$1" rt id name roots r f s; shift
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            roots="$("$rt" exec "$id" sh -c "find /var/www /srv /opt /home /usr/share -maxdepth 8 -path '*/${marker}' -type f 2>/dev/null | head -n 20" 2>/dev/null)" || continue
            while read -r r; do
                [[ "$r" =~ ^/[A-Za-z0-9._/@+-]+$ && "$r" == */"$marker" ]] || continue
                r="${r%/"$marker"}"
                if [[ -z "$STAGE" ]]; then
                    STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${STAGE:-}"' EXIT
                fi
                s="$STAGE/${rt}_${name:-$id}_${r//\//_}"; mkdir -p "$s"
                for f in "$marker" "$@"; do
                    mkdir -p "$s/$(dirname "$f")"
                    "$rt" cp "${id}:${r}/${f}" "$s/$f" >/dev/null 2>&1 || rm -f "$s/$f"
                    [[ -L "$s/$f" ]] && rm -f "$s/$f"
                done
                STAGED_DIRS+=("$s")
            done <<<"$roots"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'program/include/iniset.php' 'CHANGELOG.md'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home /usr/share/roundcube /usr/share/roundcubemail /var/lib/roundcube /usr/local/cpanel/base/3rdparty/roundcube /usr/share/psa-roundcube /usr/share/psa-webmail; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f ver st root
    if [[ $# -gt 0 ]]; then dirs=("$@")
    else dirs=(/var/www /srv /opt /home /usr/share/roundcube /usr/share/roundcubemail /var/lib/roundcube \
               /usr/local/cpanel/base/3rdparty/roundcube /usr/share/psa-roundcube /usr/share/psa-webmail); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Roundcube Webmail"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        root="$(dirname "$(dirname "$(dirname "$f")")")"
        ver="$(rc_version "$f")"
        found=$((found+1))
        step "Roundcube ${ver:-?} at ${root}"
        if [[ -z "$ver" ]]; then caution "version not found in ${f}"; continue; fi
        st="$(roundcube_status "$ver")"
        case "$st" in
            fixed)   ok "Roundcube ${ver} has the 1.6.20 / 1.7.5 fixes"; continue ;;
            unknown) caution "could not parse version '${ver}'"; continue ;;
            eol)     bad "Roundcube ${ver} is on a branch these releases do not cover (1.5 and earlier): move to 1.6.20 or 1.7.5" ;;
            vulnerable) bad "Roundcube ${ver} is affected by CVE-2026-114716 and 19 other fixes (fixed in 1.6.20 / 1.7.5)" ;;
        esac
        if distro_mentions "$f" CVE-2026-114716; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this copy and its changelog does not mention the CVE yet"
        fi
        case "$root" in
            */cpanel/*|*/psa-*) inf "bundled with a hosting panel: the panel's own update delivers the fix" ;;
        esac
        rc=1
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/program/include/iniset.php' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Roundcube found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Roundcube found (${found} checked)"
    else
        warn "Affected Roundcube found. Update to 1.6.20 (LTS) or 1.7.5, and back up first as the project advises."
        inf "Release notes: https://roundcube.net/news/2026/10/19/security-updates-1.6.20-and-1.7.5"
        inf "Then run: $0 hunt   to look for probing of the IMAP injection parameters."
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local -a logs=()
    local f n total=0 rc=0
    shopt -s nullglob
    for f in /var/log/apache2/*access*.log /var/log/apache2/*access*.log.1 \
             /var/log/nginx/*access*.log /var/log/nginx/*access*.log.1 \
             /var/log/httpd/*access*log /var/log/httpd/*access*log.1 \
             /var/log/apache2/other_vhosts_access.log /usr/local/apache/logs/access_log \
             "${HUNT_LOGS:-/nonexistent}"; do
        [[ -r "$f" && -f "$f" ]] && logs+=("$f")
    done
    shopt -u nullglob
    step "Searching web logs for CRLF in the Roundcube _uid and _flag parameters"
    if [[ ${#logs[@]} -eq 0 ]]; then
        warn "No readable access logs found (run as root, or set HUNT_LOGS to a log path)"
        return 0
    fi
    inf "reading ${#logs[@]} log file(s)"
    for f in "${logs[@]}"; do
        n="$(grep -cE '[?&_]_(uid|flag)=[^ &"]*(%0[dD]|%0[aA]|\\r|\\n)' "$f" 2>/dev/null)"
        [[ "${n:-0}" -gt 0 ]] || continue
        total=$((total+n)); rc=1
        bad "${f}: ${n} request(s) with an encoded CR or LF in _uid or _flag"
        grep -E '[?&_]_(uid|flag)=[^ &"]*(%0[dD]|%0[aA]|\\r|\\n)' "$f" 2>/dev/null | head -n3 | cut -c1-200 | sed 's/^/        /'
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No CRLF probing of _uid or _flag found in the readable logs"
        inf "A clean result does not prove nothing happened: logs rotate, and POST bodies are not logged."
    else
        warn "${total} suspicious request(s). Someone has been testing IMAP command injection against your webmail."
        inf "Update first, then review the IMAP server log for commands you did not expect."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114716; fixed in Roundcube 1.6.20 and 1.7.5"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
