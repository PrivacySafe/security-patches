#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Gitea SSH certificate principal impersonation: read-only checker  (v1)
# CVE-2026-109553 (GHSA-vcp6-2qc6-gvq3)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Gitea resolved the principals of an SSH certificate by searching the content of
# ALL stored public keys instead of only the keys registered as principals. So a
# certificate that lists another user's public-key line as a principal
# authenticated as that user. It applies to the HTTP signature API and to the
# built-in SSH server. Rated High, CVSS 7.5.
#
# It only applies to instances that trust a user certificate authority:
#   * SSH_TRUSTED_USER_CA_KEYS is set (in [server] of app.ini), AND
#   * either SSH_AUTHORIZED_PRINCIPALS_ALLOW=anything (documented as performing no
#     check on principal text), so an ordinary user can register another person's
#     public-key line as their own principal; or a holder of a certificate signed
#     by that authority can list the victim's key line.
# Instances that do not trust a user CA are not affected.
#
#   Affected: Gitea up to and including 28.1.0 (the advisory confirmed it on 1.27.3)
#   Fixed:    28.2.0 (released 18 October 2026)
#
# The same Gitea release fixes eight other flaws that only the update fixes.
# Forgejo is a separate project: this script reads Gitea's version output and does
# not judge Forgejo.
#
# This script is read-only. It finds Gitea binaries (PATH, usual locations and
# running processes), reads "gitea --version", reads app.ini, and reports whether a
# user CA is trusted and how principals are allowed. It NEVER prints the CA keys or
# any other value from app.ini beyond the principal policy word.
#
# Usage:
#   ./gitea-check.sh [command] [PATH-TO-gitea ...]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version that trusts
#                    a user CA, or whose configuration could not be read.
#   version          print the script version.
#
# Environment: GITEA_INI (space separated files) replaces app.ini discovery.
# Running docker and podman containers are inspected too (see "Containers" below). An image that is
# not running is not: check its tag yourself.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="gitea-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
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
gitea_affected() { ver_lt "$1" "28.2.0"; }

bin_version() {   # binary -> x.y.z from "gitea --version"
    timeout 10 "$1" --version 2>/dev/null | head -n1 | sed -n 's/^[Gg]itea version \([0-9][0-9.]*\).*/\1/p'
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v gitea 2>/dev/null)" /usr/local/bin/gitea /usr/bin/gitea /opt/gitea/gitea /home/git/gitea /srv/gitea/gitea /usr/local/sbin/gitea; do
        [[ -n "$b" && -x "$b" && -f "$b" ]] && out+=("$(readlink -f "$b")")
    done
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2 ~ /^gitea/ {print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

ini_files() {
    local f p=""
    if [[ -n "${GITEA_INI:-}" ]]; then for f in $GITEA_INI; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    if have ps; then p="$(ps -eo args= 2>/dev/null | grep -E '(^|/)gitea( |$)' | grep -oE -- '(--config|-c)[ =][^ ]+' | head -n1 | sed -E 's/^(--config|-c)[ =]//')"; fi
    for f in $p /etc/gitea/app.ini /var/lib/gitea/custom/conf/app.ini /home/git/gitea/custom/conf/app.ini /opt/gitea/custom/conf/app.ini /srv/gitea/custom/conf/app.ini /data/gitea/conf/app.ini /usr/local/etc/gitea/conf/app.ini; do
        [[ -n "$f" && -r "$f" ]] && { echo "$f"; return 0; }
    done
}

# value of key in [section], case-insensitive on section and key; values are returned but callers decide what to show
ini_value() {   # file section key
    awk -v sec="$(tr 'A-Z' 'a-z' <<<"$2")" -v key="$(tr 'A-Z' 'a-z' <<<"$3")" '
        /^[[:space:]]*[;#]/ {next}
        /^[[:space:]]*\[/ {s=tolower($0); gsub(/[[:space:]\[\]]/,"",s); cur=s; next}
        cur==sec { line=$0; sub(/^[[:space:]]+/,"",line); n=index(line,"="); if(n>0){k=tolower(substr(line,1,n-1)); gsub(/[[:space:]]/,"",k)
                   if(k==key){v=substr(line,n+1); sub(/^[[:space:]]+/,"",v); sub(/[[:space:]]+$/,"",v); out=v}}}
        END{print out}' "$1"
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

GITEA_PROBE="$(cat <<'EOS'
g=""
for c in /usr/local/bin/gitea /usr/bin/gitea /app/gitea/gitea /opt/gitea/gitea /home/git/gitea/gitea /srv/gitea/gitea; do [ -x "$c" ] && { g=$c; break; }; done
[ -n "$g" ] || exit 0
echo "B /.out_v $("$g" --version 2>/dev/null | head -n 1 | base64 | tr -d '\n')"
find /etc/gitea /data/gitea /var/lib/gitea /home /opt /srv -maxdepth 6 -name app.ini -type f -size -512k 2>/dev/null | head -n 5 | while read -r p; do
  echo "B $p $(awk '/^[[:space:]]*\[/ {sec=tolower($0); gsub(/[[:space:]]/,"",sec); print; next} sec=="[server]" && /^[[:space:]]*SSH_TRUSTED_USER_CA_KEYS[[:space:]]*=/ {split($0,a,"="); v=a[2]; gsub(/[[:space:]]/,"",v); if (v=="") print "SSH_TRUSTED_USER_CA_KEYS ="; else print "SSH_TRUSTED_USER_CA_KEYS = x"; next} sec=="[server]" && /^[[:space:]]*SSH_AUTHORIZED_PRINCIPALS_ALLOW[[:space:]]*=/ {print; next}' "$p" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Gitea in one container, judged by this script run in isolation
    local s="$1" out rc ini
    [[ -s "$s/.out_v" ]] || return 0
    printf '#!/bin/sh\ncase "$1" in\n  --version) cat "%s/.out_v" ;;\nesac\n' "$s" > "$s/gitea"; chmod 755 "$s/gitea"
    ini="$(find "$s" -name app.ini -type f 2>/dev/null | tr '\n' ' ')"
    step "Gitea in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 GITEA_INI="$ini" bash "$SELF" check "$s/gitea" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$GITEA_PROBE"
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
    local rc=0 found=0 b ver ini ca allow policy
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for Gitea"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No Gitea found on this host (containers: run this inside the container)"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        ver="$(bin_version "$b")"
        [[ -n "$ver" ]] || { caution "${b}: could not read a Gitea version from --version"; continue; }
        found=$((found+1))
        step "Gitea ${ver} at ${b}"
        if ! gitea_affected "$ver"; then ok "Gitea ${ver} has the fix (28.2.0 or newer)"; continue; fi
        bad "Gitea ${ver} is affected by CVE-2026-109553 (fixed in 28.2.0)"
        ini="$(ini_files | head -n1)"
        if [[ -z "$ini" ]]; then
            caution "no readable app.ini found: whether a user CA is trusted cannot be checked, treating as exposed"
            inf "check [server] SSH_TRUSTED_USER_CA_KEYS in your app.ini (set GITEA_INI=/path/to/app.ini to point this script at it)"
            rc=1; continue
        fi
        inf "read ${ini}"
        ca="$(ini_value "$ini" server SSH_TRUSTED_USER_CA_KEYS)"
        allow="$(ini_value "$ini" server SSH_AUTHORIZED_PRINCIPALS_ALLOW)"
        if [[ -z "$ca" ]]; then
            ok "no user certificate authority is trusted (SSH_TRUSTED_USER_CA_KEYS is empty or unset): per the advisory this flaw does not apply"
            caution "update anyway: the same release fixes eight other flaws, and a CA may be added later"
            continue
        fi
        inf "a user certificate authority IS trusted (SSH_TRUSTED_USER_CA_KEYS is set; its value is not shown)"
        policy="$(tr 'A-Z' 'a-z' <<<"${allow:-}")"
        if [[ "$policy" == *anything* ]]; then
            bad "SSH_AUTHORIZED_PRINCIPALS_ALLOW includes 'anything': any user can register another person's public-key line as a principal and authenticate as them"
        else
            bad "a user CA is trusted: a holder of a certificate signed by it can list another user's public-key line as a principal and authenticate as them (SSH_AUTHORIZED_PRINCIPALS_ALLOW is '${allow:-default}')"
        fi
        rc=1
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Gitea version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Gitea found (${found} checked)"
    else
        warn "Exposed or unverifiable Gitea found. Upgrade to Gitea 28.2.0 or later, then restart."
        inf "Until then (PrivacySafe recommendation): if you do not need certificate login, empty SSH_TRUSTED_USER_CA_KEYS, which takes the instance out of the affected configuration. Then review recent SSH and API signature logins."
        inf "Release notes: https://blog.gitea.com/release-of-28.2.0/"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-109553; fixed in Gitea 28.2.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
