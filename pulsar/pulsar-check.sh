#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Pulsar October 2026: read-only checker  (v1)
# CVE-2026-105869 (broker, forged JWT roles, critical 9.2)
# CVE-2026-105942 (broker, proxied requests, high 7.7)
# CVE-2026-105944 (Pulsar Manager, missing authentication, CVSS 10, NO FIX)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# BROKER. The Apache Pulsar PMC published 14 advisories on 21 October 2026, all fixed in
# 4.0.14, 4.2.5 and 5.0.0. This script covers two that depend on configuration:
#
#   CVE-2026-105869  2.8.1 before 4.0.14, and 4.1.0 before 4.2.5. With
#                    MultiRolesTokenAuthorizationProvider and a NON-EMPTY
#                    anonymousUserRole, HTTP and WebSocket requests whose credentials
#                    FAIL authentication fall back to the anonymous role, and the
#                    provider then authorizes them with the roles listed in the
#                    UNVERIFIED bearer token. A forged or unsigned token can claim a
#                    superuser role. The binary protocol is not affected.
#   CVE-2026-105942  2.8.1 before 4.0.14, and 4.1.0 before 4.2.5. For requests a proxy
#                    sends on behalf of a user, the broker authorized the original
#                    principal with the proxy's own authentication data: with
#                    MultiRolesTokenAuthorizationProvider the user gains the roles in
#                    the proxy's token, and, whatever the provider, the tenant admin
#                    check of a proxied admin REST request passed without checking the
#                    original principal when the proxy role was a tenant admin.
#                    Only relevant when a proxy role is configured (proxyRoles).
#
# Neither is reachable on a default broker: authentication, authorization,
# anonymousUserRole and proxyRoles are all off or empty by default.
# The other twelve advisories in the same announcement are fixed by the same
# upgrade; they are not counted separately here.
#
# PULSAR MANAGER. CVE-2026-105944 (CVSS 10): in 0.3.0 and later anyone who can reach
# Pulsar Manager over the network can take full control of it (the call that creates the
# first administrator is available without authentication and stays available after
# setup), and in all versions, when it holds an HTTP authentication credential for a
# cluster, any user who can reach it can perform the admin operations that credential
# permits and can have it send the credential to a host of their choosing. Affected:
# 0.1.0 through 0.4.0, which is every release. The Pulsar PMC has RETIRED it: there is no
# fix and there will not be one. The advice is to stop using it and remove it.
#
# This script is read-only. It finds Pulsar brokers (by their jars), reads their
# broker.conf and standalone.conf, scans configuration files, compose files, Helm values
# and env files for the exposing settings, and looks for Pulsar Manager (jars, running
# processes, listeners on 7750 and 9527, container images). It does not open the
# container images: for containers it reads the files beside them and tells you to
# check the tag.
#
# Usage:
#   ./pulsar-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /opt /srv /usr/local /var/lib /etc /home /root).
#                    Exit 0 = nothing exposed, 1 = an affected broker with an exposing
#                    configuration, an exposing configuration of unknown version, or
#                    Pulsar Manager present.
#   version          print the script version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies the broker jar names
# (empty files, only the name carries the version) and, from each configuration file, only the lines
# that mention authorizationProvider, anonymousUserRole, authorizationEnabled or proxyRoles, so
# tokens and secret keys never leave the container. This script then runs once per container in
# isolation against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="pulsar-check.sh"
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

# ---------- version rule (broker) --------------------------------------------
# prints: vulnerable | fixed | unknown
pulsar_status() {
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    local maj="${n%%.*}" rest min pat
    rest="${n#*.}"; min="${rest%%.*}"; pat="${rest#*.}"
    (( maj < 4 )) && { echo vulnerable; return; }
    if (( maj == 4 )); then
        case "$min" in
            0) (( pat < 14 )) && echo vulnerable || echo fixed ;;
            1) echo vulnerable ;;
            2) (( pat < 5 )) && echo vulnerable || echo fixed ;;
            *) echo fixed ;;
        esac
        return
    fi
    echo fixed
}

# ---------- configuration ----------------------------------------------------
# A setting appears as key=value (broker.conf, env files), key: value (YAML) or
# PULSAR_PREFIX_key=value. These helpers read one file and ignore comment lines.
conf_lines() { grep -vE '^[[:space:]]*#' "$1" 2>/dev/null; }
# Every test below reads all of its input (grep without -q, output discarded). With
# pipefail, a pipeline ending in "grep -q" can report a miss when grep exits at its
# first match and the producer dies of SIGPIPE, which happens on large files.
setting_nonempty() {   # file, key -> 0 if the key is set to a non-empty value
    conf_lines "$1" | grep -E "(^|[^A-Za-z0-9]|PULSAR_PREFIX_)${2}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9_.@:/,-]+" >/dev/null
}
setting_true() { conf_lines "$1" | grep -E "(^|[^A-Za-z0-9]|PULSAR_PREFIX_)${2}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?true" >/dev/null; }
uses_multiroles() { conf_lines "$1" | grep -E "authorizationProvider[\"']?[[:space:]]*[:=].*MultiRolesTokenAuthorizationProvider" >/dev/null; }

# prints a one-line summary of what a configuration file exposes: 105869 and/or 105942
conf_exposure() {
    local f="$1" out=""
    if uses_multiroles "$f" && setting_nonempty "$f" anonymousUserRole && setting_true "$f" authorizationEnabled; then out+="105869 "; fi
    if setting_nonempty "$f" proxyRoles && setting_true "$f" authorizationEnabled; then out+="105942 "; fi
    echo "$out"
}

# ---------- listeners --------------------------------------------------------
listeners_on() {   # port(s) -> prints "addr (loopback only|reachable from the network)" lines
    have ss || return 0
    local p addr line
    while read -r line; do
        addr="$(awk '{print $4}' <<<"$line")"
        for p in "$@"; do
            [[ "$addr" == *":${p}" ]] || continue
            case "$addr" in
                127.0.0.1:*|"[::1]:"*) echo "${addr} (loopback only)" ;;
                *) echo "${addr} (reachable from the network)" ;;
            esac
        done
    done < <(ss -H -ltn 2>/dev/null)
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

PULSAR_PROBE="$(cat <<'EOS'
R="/opt /srv /usr/local /var/lib /etc /home /root /pulsar /app"
KEYS="authorizationProvider|anonymousUserRole|authorizationEnabled|proxyRoles"
find $R -xdev -maxdepth 9 -type f \( -name "pulsar-broker-[0-9]*.jar" -o -name "org.apache.pulsar-pulsar-broker-[0-9]*.jar" -o -name "pulsar-manager*.jar" -o -path "*pulsar-manager/bin/pulsar-manager" \) 2>/dev/null | head -n 40 | while read -r f; do echo "E $f"; done
find $R -xdev -maxdepth 9 -type f \( -name "broker.conf" -o -name "standalone.conf" \) -size -2000k 2>/dev/null | head -n 40 | while read -r f; do
  v=$(grep -E "$KEYS" "$f" 2>/dev/null)
  [ -n "$v" ] || v="# none of the settings this check reads"
  echo "B $f $(printf '%s\n' "$v" | base64 | tr -d '\n')"
done
find $R -xdev -maxdepth 9 -type f \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "compose*.yml" -o -name "compose*.yaml" -o -name "values*.yaml" -o -name "values*.yml" -o -name "*.env" \) -not -path "*/node_modules/*" -size -2000k 2>/dev/null | head -n 100 | while read -r f; do
  v=$(grep -E "$KEYS" "$f" 2>/dev/null)
  [ -n "$v" ] && echo "B $f $(printf '%s\n' "$v" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Pulsar in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "Apache Pulsar in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$PULSAR_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a dirs=() existing=()
    local rc=0 d f base ver root st conf any_conf ex nbrokers=0 nmgr=0 l
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/opt /srv /usr/local /var/lib /etc /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Apache Pulsar brokers"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    declare -A seen=() known=() mgr_seen=()
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        base="$(basename "$f")"
        ver="$(sed -E 's/^(org\.apache\.pulsar-)?pulsar-broker-([0-9][0-9A-Za-z.]*)\.jar$/\2/' <<<"$base")"
        ver="$(norm_ver "$ver")"
        root="$(dirname "$(dirname "$f")")"
        [[ -n "${seen[$root|$ver]:-}" ]] && continue; seen["$root|$ver"]=1
        nbrokers=$((nbrokers+1))
        known["$root/conf/broker.conf"]=1; known["$root/conf/standalone.conf"]=1
        step "Pulsar broker ${ver} at ${root}"
        st="$(pulsar_status "$ver")"
        case "$st" in
            fixed)   ok "${ver} has the fixes (4.0.14, 4.2.5 or 5.0.0 or newer)"; continue ;;
            unknown) caution "cannot parse version '${ver}': check it against 4.0.14, 4.2.5 and 5.0.0"; rc=1; continue ;;
        esac
        inf "version ${ver} is in an affected range of the 21 October 2026 advisories (fixed in 4.0.14, 4.2.5 and 5.0.0; 3.x and 4.1.x are end of life with no fix of their own)"
        if ver_lt "$(norm_ver "$ver")" "2.8.1"; then
            caution "older than 2.8.1: the two configuration-dependent flaws checked here start at 2.8.1, but this release is unsupported and affected by other advisories in the set: upgrade"
            continue
        fi
        any_conf=0
        for conf in "$root/conf/broker.conf" "$root/conf/standalone.conf"; do
            [[ -r "$conf" ]] || continue
            any_conf=1
            ex="$(conf_exposure "$conf")"
            if [[ -z "$ex" ]]; then
                ok "$(basename "$conf"): none of the exposing settings is present (MultiRoles provider with anonymousUserRole, or proxyRoles, with authorization enabled)"
            else
                [[ "$ex" == *105869* ]] && { bad "$(basename "$conf"): MultiRolesTokenAuthorizationProvider, a non-empty anonymousUserRole and authorizationEnabled=true: CVE-2026-105869, a client with a forged token can claim any role over HTTP or WebSocket"; rc=1; }
                [[ "$ex" == *105942* ]] && { bad "$(basename "$conf"): proxyRoles is set and authorization is enabled: CVE-2026-105942, proxied requests are authorized with the proxy's credentials"; rc=1; }
            fi
        done
        if [[ $any_conf -eq 0 ]]; then
            caution "no conf/broker.conf or conf/standalone.conf beside this install: the settings cannot be read (they may come from environment variables or a mounted file). Treating as unverified."
            rc=1
        fi
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'pulsar-broker-[0-9]*.jar' -o -name 'org.apache.pulsar-pulsar-broker-[0-9]*.jar' \) 2>/dev/null | sort -u)

    step "Configuration files (compose, Helm values, env files, broker.conf), whatever the version"
    local nconf=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        [[ -n "${known[$f]:-}" ]] && continue
        ex="$(conf_exposure "$f")"
        [[ -n "$ex" ]] || continue
        nconf=$((nconf+1))
        [[ "$ex" == *105869* ]] && { bad "${f}: MultiRolesTokenAuthorizationProvider with a non-empty anonymousUserRole and authorizationEnabled=true (CVE-2026-105869)"; rc=1; }
        [[ "$ex" == *105942* ]] && { bad "${f}: proxyRoles is set with authorization enabled (CVE-2026-105942)"; rc=1; }
        inf "this file does not say which version runs: if the broker image or release is older than 4.0.14 (or 4.1.x, or 4.2.x before 4.2.5) it is exposed; check the tag"
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'broker.conf' -o -name 'standalone.conf' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' -o -name 'values*.yaml' -o -name 'values*.yml' -o -name '*.env' \) \
                -not -path '*/node_modules/*' -size -2000k 2>/dev/null | sort -u)
    [[ $nconf -eq 0 ]] && ok "no configuration file with the exposing settings"

    step "Looking for Pulsar Manager (CVE-2026-105944, no fix exists)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        root="$(dirname "$f")"; [[ "$(basename "$root")" == bin ]] && root="$(dirname "$root")"
        [[ -n "${mgr_seen[$root]:-}" ]] && continue; mgr_seen["$root"]=1
        nmgr=$((nmgr+1))
        ver="$(sed -nE 's/^pulsar-manager-([0-9][0-9.]*)\.jar$/\1/p' <<<"$(basename "$f")")"
        bad "Pulsar Manager found: ${f}${ver:+ (version ${ver})}: every release (0.1.0 to 0.4.0) is affected and the project is retired, so no fix will ever ship"
        rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'pulsar-manager*.jar' -o -path '*pulsar-manager/bin/pulsar-manager' \) 2>/dev/null | sort -u)
    if have ps; then
        while IFS= read -r l; do
            [[ -n "$l" ]] || continue
            nmgr=$((nmgr+1)); bad "a running process looks like Pulsar Manager: $(cut -c1-120 <<<"$l")"; rc=1
        done < <(ps -eo args= 2>/dev/null | grep -iE 'pulsar-manager' | grep -v grep | grep -v "${SCRIPT_NAME}" | head -n 3)
    fi
    while IFS= read -r l; do
        [[ -n "$l" ]] || continue
        inf "listener on a Pulsar Manager port: ${l}"
        [[ "$l" == *"reachable from the network"* ]] && { warn "a listener on 7750 or 9527 is reachable from the network: if that is Pulsar Manager, anyone who can reach it can take it over"; }
    done < <(listeners_on 7750 9527)
    if have docker && timeout 5 docker ps -a --format '{{.Image}}' >/tmp/.psf_pm_img 2>/dev/null; then
        while IFS= read -r l; do
            [[ -n "$l" ]] || continue
            nmgr=$((nmgr+1)); bad "a container uses a Pulsar Manager image: ${l}"; rc=1
        done < <(grep -iE 'pulsar-manager' /tmp/.psf_pm_img)
        rm -f /tmp/.psf_pm_img
    fi
    [[ $nmgr -eq 0 ]] && ok "no Pulsar Manager found (jars, running processes, container images)"

    step "Verdict"
    if [[ $nbrokers -eq 0 && $nconf -eq 0 && $nmgr -eq 0 ]]; then
        info "No Apache Pulsar broker, exposing configuration or Pulsar Manager found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "Nothing exposed (${nbrokers} broker install(s) checked). An affected broker without the exposing settings still needs the upgrade."
    else
        warn "Exposed Pulsar component found."
        [[ $nmgr -gt 0 ]] && {
            inf "Pulsar Manager: stop and remove it (the Pulsar PMC retired it; there will be no fix) and move to an alternative from https://pulsar.apache.org/docs/administration-ui"
            inf "If it was reachable from a network you do not fully trust, treat the Pulsar credential or token signing key it held as compromised and replace it, and check its user list for administrators you did not create."
        }
        inf "Broker: upgrade to 4.0.14, 4.2.5 or 5.0.0 or newer. Until then (ours): empty anonymousUserRole, do not expose the HTTP and WebSocket ports to untrusted clients, and keep the broker behind the proxy with strict network rules."
        inf "Advisories: https://pulsar.apache.org/security/CVE-2026-105869/ and https://seclists.org/oss-sec/2026/q4/296"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-105869 and CVE-2026-105942 (fixed in Pulsar 4.0.14, 4.2.5, 5.0.0); CVE-2026-105944 (Pulsar Manager, retired, no fix)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
