#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Jenkins plugin security advisory of 16 September 2026 (20 CVEs): read-only checker  (v1)
# CVE-2026-92122 to CVE-2026-92141
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Jenkins published a security advisory on 16 September 2026 covering 20 vulnerabilities
# in 13 widely deployed plugins. Eight are High-severity flaws in Script Security, the
# plugin that sandboxes Groovy for Pipelines and is present on nearly every Jenkins
# server: ways around the sandbox (interface coercion, calls on a null receiver,
# collection casts, AST transformations, @Builder at compile time, dynamic methods, a
# classpath approval bypass, and a time-of-check to time-of-use race on approved remote
# JARs) that let a user who may define Pipeline scripts run code in the controller's JVM.
#
#   Plugin (short name)                 Fixed in                   CVE          Severity
#   script-security                     1422.v06869826dd9b_        92122-92129  High (8 issues)
#   workflow-multibranch                842.v3a_b_59b_57b_e6e      92130        Low
#   pipeline-groovy-lib                 806.v408277b_33d1d         92131        Medium
#   gradle                              2.20.1253.vc116f0763a_eb_  92132        Medium
#   gitlab-plugin                       1.2152.veec0897048b_0      92133        Medium
#   warnings-ng                         13.10259.v80f407cb_03a_e   92134        High
#   coverage                            3.3361.v0626103a_67e6      92135        High
#   dependency-check-jenkins-plugin     5.6.5                      92136        High
#   robot                               6.3.0                      92137        High
#   atlassian-bitbucket-server-integration  6.0.2                  92138        Medium
#   bitbucket-push-and-pull-request     4.1.0                      92139        Medium
#   gitee                               1304.v2702f1d71cde         92140        High
#   keycloak                            2.4.2                      92141        Medium
#
# What the High ones allow: Script Security, sandbox bypass and code execution in the
# controller JVM; Robot Framework (92137), arbitrary file creation or replacement on the
# controller, which can lead to code execution; Warnings, Coverage, Dependency-Check and
# Gitee, stored cross-site scripting. Credentials can leak through Pipeline: Multibranch
# (System-scoped credentials), GitLab (API tokens), Gradle (the Develocity access key),
# and Bitbucket Push and Pull Request (Bitbucket credentials, by SSRF).
#
# How this script reads an install. A plugin's version is the Plugin-Version line of its
# META-INF/MANIFEST.MF, in the expanded plugin directory or inside the .jpi or .hpi file
# under $JENKINS_HOME/plugins. Versions are compared by their leading dotted number; two
# builds with the same number but different build hashes cannot be ordered, and are
# reported as such. A plugin that is disabled does not run and is reported as such.
# The 13 short names were checked against each plugin's own project file.
#
# This script is read-only.
#
# Usage:
#   ./jenkins-check.sh [command] [JENKINS_HOME ...]
#   check (default)  Exit 0 = nothing exposed, 1 = a plugin below its fixed version.
#   version          print the script version.
#
# Env: JENKINS_HOME  the Jenkins home directory (default /var/lib/jenkins, /var/jenkins_home)
#      SCAN_CONTAINERS=1 (the default) also reads the advisory plugins' manifests inside running
#      docker and podman containers (JENKINS_HOME there, default /var/jenkins_home); 0 skips them.
#      It is skipped when you name the home directories yourself.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="jenkins-check.sh"
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
# short name | fixed version | CVEs | severity | what it allows
PLUGINS=(
 "script-security|1422.v06869826dd9b_|CVE-2026-92122 CVE-2026-92123 CVE-2026-92124 CVE-2026-92125 CVE-2026-92126 CVE-2026-92127 CVE-2026-92128 CVE-2026-92129|High|sandbox bypass: code execution in the controller JVM"
 "workflow-multibranch|842.v3a_b_59b_57b_e6e|CVE-2026-92130|Low|System-scoped credential exposure"
 "pipeline-groovy-lib|806.v408277b_33d1d|CVE-2026-92131|Medium|path traversal: file read and deletion"
 "gradle|2.20.1253.vc116f0763a_eb_|CVE-2026-92132|Medium|SSRF: Develocity access key theft"
 "gitlab-plugin|1.2152.veec0897048b_0|CVE-2026-92133|Medium|GitLab API token exposure"
 "warnings-ng|13.10259.v80f407cb_03a_e|CVE-2026-92134|High|stored XSS"
 "coverage|3.3361.v0626103a_67e6|CVE-2026-92135|High|stored XSS"
 "dependency-check-jenkins-plugin|5.6.5|CVE-2026-92136|High|stored XSS"
 "robot|6.3.0|CVE-2026-92137|High|arbitrary file write on the controller, potentially code execution"
 "atlassian-bitbucket-server-integration|6.0.2|CVE-2026-92138|Medium|OAuth access token hijacking"
 "bitbucket-push-and-pull-request|4.1.0|CVE-2026-92139|Medium|SSRF: Bitbucket credential theft"
 "gitee|1304.v2702f1d71cde|CVE-2026-92140|High|stored XSS"
 "keycloak|2.4.2|CVE-2026-92141|Medium|open redirect"
)

# the Plugin-Version of a plugin: expanded directory first, then the packaged archive.
# A manifest wraps long lines: a line that starts with one space continues the line before.
manifest_of() {   # plugins-dir short-name -> manifest text
    local pd="$1" n="$2" a
    if [[ -r "$pd/$n/META-INF/MANIFEST.MF" ]]; then cat "$pd/$n/META-INF/MANIFEST.MF"; return; fi
    for a in "$pd/$n.jpi" "$pd/$n.hpi"; do
        [[ -r "$a" ]] || continue
        if have unzip; then unzip -p "$a" META-INF/MANIFEST.MF 2>/dev/null && return
        elif have python3; then python3 -c 'import sys,zipfile; sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read("META-INF/MANIFEST.MF").decode("utf-8","replace"))' "$a" 2>/dev/null && return; fi
    done
    return 1
}
plugin_version() {
    local m; m="$(manifest_of "$1" "$2")" || return 1
    printf '%s' "$m" | tr -d '\r' | sed ':a;N;$!ba;s/\n //g' | sed -nE 's/^Plugin-Version:[[:space:]]*//p' | head -n1 | sed -E 's/[[:space:]]+$//'
}
# prints: fixed | affected | unordered
#   unordered = the same leading number with different build hashes: the order is not knowable
jver_status() {
    local inst="$1" fix="$2" pi pf
    [[ "$inst" == "$fix" ]] && { echo fixed; return; }
    pi="$(sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/' <<<"$inst")"; pf="$(sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/' <<<"$fix")"
    [[ "$pi" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo unordered; return; }
    if ver_lt "$pi" "$pf"; then echo affected
    elif ver_lt "$pf" "$pi"; then echo fixed
    else echo unordered; fi
}

# ---------- running containers -----------------------------------------------
# A Jenkins home inside a container is not on the host. For each running container, copy out the
# manifests of the advisory plugins into a staging directory laid out like a plugins directory,
# so the same checks (disabled plugins, unreadable versions, build-hash ordering) judge it.
JK_STAGE=""
declare -a JK_STAGED=()
declare -A JK_LABEL=()
stage_containers() {
    local rt id name h list entry n x s
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            h="$("$rt" exec "$id" sh -c 'printf %s "${JENKINS_HOME:-/var/jenkins_home}"' 2>/dev/null)" || continue
            [[ "$h" =~ ^/[A-Za-z0-9._/-]+$ ]] || continue
            list="$("$rt" exec "$id" sh -c "ls -1 '${h}/plugins' 2>/dev/null" 2>/dev/null)" || continue
            [[ -n "$list" ]] || continue
            if [[ -z "$JK_STAGE" ]]; then
                JK_STAGE="$(mktemp -d)" || return 0
                trap 'rm -rf "${JK_STAGE:-}"' EXIT
            fi
            s="$JK_STAGE/${rt}_${id}"; mkdir -p "$s/plugins"
            for entry in "${PLUGINS[@]}"; do
                n="${entry%%|*}"
                if grep -Fx -- "$n" <<<"$list" >/dev/null; then
                    mkdir -p "$s/plugins/$n/META-INF"
                    "$rt" exec "$id" cat "${h}/plugins/${n}/META-INF/MANIFEST.MF" > "$s/plugins/$n/META-INF/MANIFEST.MF" 2>/dev/null || rm -f "$s/plugins/$n/META-INF/MANIFEST.MF"
                fi
                for x in jpi hpi; do
                    if grep -Fx -- "$n.$x" <<<"$list" >/dev/null; then
                        "$rt" cp "${id}:${h}/plugins/${n}.${x}" "$s/plugins/${n}.${x}" >/dev/null 2>&1 || : > "$s/plugins/${n}.${x}"
                    fi
                    if grep -Fx -- "$n.$x.disabled" <<<"$list" >/dev/null; then : > "$s/plugins/${n}.${x}.disabled"; fi
                done
            done
            JK_STAGED+=("$s"); JK_LABEL["$s"]="${rt} container ${name:-$id} (${h})"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

cmd_check() {
    local -a homes=(); local rc=0 h pd entry n fix cves sev what v st disabled found=0 present=0 exposed=0 line
    if [[ $# -gt 0 ]]; then homes=("$@")
    else
        [[ -n "${JENKINS_HOME:-}" ]] && homes+=("$JENKINS_HOME")
        for h in /var/lib/jenkins /var/jenkins_home; do [[ -d "$h/plugins" && "$h" != "${JENKINS_HOME:-}" ]] && homes+=("$h"); done
    fi
    step "Looking for Jenkins"
    local -a real=(); for h in "${homes[@]:-}"; do [[ -n "$h" && -d "$h/plugins" ]] && real+=("$h"); done
    # running containers, unless the homes to check were named on the command line
    if [[ $# -eq 0 ]]; then
        stage_containers
        for h in "${JK_STAGED[@]:-}"; do [[ -n "$h" ]] && real+=("$h"); done
    fi
    if [[ ${#real[@]} -eq 0 ]]; then info "No Jenkins plugins directory found on the host or in a running container (set JENKINS_HOME, or pass the home directory)"; return 0; fi
    for h in "${real[@]}"; do
        found=$((found+1)); pd="$h/plugins"
        step "Jenkins home ${JK_LABEL[$h]:-$h}"
        for entry in "${PLUGINS[@]}"; do
            IFS='|' read -r n fix cves sev what <<<"$entry"
            v="$(plugin_version "$pd" "$n")" || v=""
            if [[ -z "$v" ]]; then
                # listed in the advisory and installed, but its version cannot be read: do not skip it
                if [[ -e "$pd/$n" || -e "$pd/$n.jpi" || -e "$pd/$n.hpi" || -e "$pd/$n.jpi.disabled" || -e "$pd/$n.hpi.disabled" ]]; then
                    present=$((present+1)); caution "${n} is installed but its version could not be read (no Plugin-Version in its manifest): confirm it is at least ${fix} in the Plugin Manager"; rc=1
                fi
                continue
            fi
            present=$((present+1))
            disabled=""; [[ -e "$pd/$n.jpi.disabled" || -e "$pd/$n.hpi.disabled" ]] && disabled=1
            st="$(jver_status "$v" "$fix")"
            case "$st" in
                fixed)     ok "${n} ${v}" ;;
                affected)
                    if [[ -n "$disabled" ]]; then inf "${n} ${v} is below ${fix} (${sev}: ${what}) but is DISABLED, so it does not run: update or remove it anyway"
                    else bad "${n} ${v} is below the fixed ${fix}: ${sev}, ${what} (${cves})"; rc=1; exposed=$((exposed+1)); fi ;;
                unordered) caution "${n} ${v}: same build number as the fixed ${fix} but a different build: cannot order them, confirm in the Plugin Manager"; rc=1 ;;
            esac
        done
    done
    inf "${present} affected-list plugin(s) installed across ${found} Jenkins home(s)"
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No plugin below its fixed version."
    else
        warn "${exposed} plugin(s) below their fixed version. Update them in Manage Jenkins, Plugins, then restart Jenkins."
        inf "If an affected Script Security, GitLab, Gradle or Bitbucket plugin was installed while users you do not fully trust could define Pipelines or edit jobs, treat the credentials those plugins could reach as possibly exposed and rotate them"
        inf "Until then (the project's suggestion, not Jenkins's): limit who holds Pipeline authoring and Item/Configure permissions"
        inf "Advisory: https://www.jenkins.io/security/advisory/2026-09-16/"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Jenkins plugin advisory of 16 September 2026 (CVE-2026-92122 to CVE-2026-92141)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
