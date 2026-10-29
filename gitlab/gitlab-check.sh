#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# GitLab security releases of October 2026: read-only checker  (v5)
# CVE-2026-16301, CVE-2026-92883, CVE-2026-14814, CVE-2026-81839, CVE-2026-96893,
# CVE-2026-15723, CVE-2026-112212
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# GitLab's critical patch release of 12 October 2026 (19.4.2, 19.3.5, 19.2.8) fixed 24
# vulnerabilities in Community Edition (CE) and Enterprise Edition (EE). Five of them are
# rated High and are covered here, with the affected ranges GitLab published for each:
#
#   CVE-2026-92883  8.7  CE/EE  stored cross-site scripting in syntax highlighting, through
#                              a crafted repository. From 19.1 before 19.2.8, 19.3 before
#                              19.3.5, 19.4 before 19.4.2.
#   CVE-2026-16301  8.5  CE/EE  a user with the Developer role can run CI/CD pipelines on
#                              protected branches without authorization. From 18.7 before
#                              19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-14814  8.2  CE/EE  a permissive regular expression in repository file access
#                              lets a user poison the cache of raw repository files, so
#                              other users' pipelines run crafted content and protected
#                              variables can be exposed. Every version before 19.2.8, 19.3
#                              before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-81839  7.7  EE only  after a project is transferred, scheduled pipeline
#                              execution policy records are not cleaned up, so pipelines
#                              run with the new group's privileges. From 18.1 before
#                              19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-96893  7.3  EE only  prompt injection in the GitLab Duo Agent Platform: crafted
#                              content in the AI conversation context can cause unintended
#                              commands attributed to other users. From 19.1 before 19.2.8,
#                              19.3 before 19.3.5, 19.4 before 19.4.2. (GitLab rates it High.)
#
# GitLab published fixes for those three lines only. Every line below 19.2 (19.1, 19.0 and
# all 18.x) is affected by the ones whose range reaches it and has no fixed release: the fix
# there is to move to a fixed release of a supported line. 19.5 is not listed as affected.
#
# The critical patch release of 21 October 2026 (19.5.1, 19.4.3, 19.3.6, plus backports of its
# critical fix to 19.2.9, 19.1.9, 19.0.10 and 18.11.13) added two more High flaws:
#
#   CVE-2026-15723   8.2  CE/EE  account takeover: when OmniAuth SAML and LDAP auto-linking are
#                              both enabled, an authenticated user can take over an existing
#                              LDAP-backed account, because the LDAP email lookup used during
#                              identity linking does not sanitize its input. From 10.1 before
#                              19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1.
#   CVE-2026-112212  7.5  CE/EE  cache poisoning of the OAuth and OpenID Connect discovery
#                              document, so an attacker without an account can point some
#                              sign-in flows at a server they control (it needs a shared cache).
#                              From 18.3 before 19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1.
#
# Those two are fixed on 19.3.6, 19.4.3 and 19.5.1 only. The backports of 19.2.9 and older carry
# the regular-expression fix alone, so 19.2.9 is NOT a full fix for this set. The Medium and Low
# flaws of both releases are not checked here.
#
# The two regular-expression flaws of October (CVE-2026-97229 and CVE-2026-110264) are
# covered by the ruby/ checker in this collection; run both. Each flaw has its own fixed
# versions, so being current for one says nothing about the other.
#
# The version is read from GitLab's own VERSION file (Omnibus: <root>/embedded/service/
# gitlab-rails/VERSION, or version-manifest.txt; source installs: /home/git/gitlab/VERSION)
# and from the tags of gitlab/gitlab-ce and gitlab/gitlab-ee images known to docker or
# podman. The edition (Community or Enterprise) matters for CVE-2026-81839 and CVE-2026-96893
# and is read from the package or image marker (-ee, -ce), the manifest's product name, or the
# presence of GitLab's ee directory. If it cannot be read, the script says those flaws apply
# only to Enterprise Edition rather than skipping them.
#
# GitLab published no indicators of exploitation for these flaws, so there is no hunt.
# This script is read-only.
#
# Usage:
#   ./gitlab-check.sh [command]
#   check (default)  Exit 0 = nothing exposed, 1 = an install without a fix.
#   version          print the script version.
#
# Env: GITLAB_ROOT         Omnibus root (default /opt/gitlab)
#      GITLAB_SOURCE_DIRS  source install directories (default /home/git/gitlab)
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="gitlab-check.sh"
SCRIPT_VERSION="5.0.0"
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
# One row per flaw: id|cvss|edition|introduced|fixed patch per branch|what
# "introduced" is the first affected release line (0.0 = every version). A line below the
# highest fixed line that has no fixed patch listed is affected with no fix available.
GL_CVES=(
"CVE-2026-92883|8.7|any|19.1|19.2:8 19.3:5 19.4:2|stored cross-site scripting in syntax highlighting"
"CVE-2026-16301|8.5|any|18.7|19.2:8 19.3:5 19.4:2|a Developer can run pipelines on protected branches"
"CVE-2026-14814|8.2|any|0.0|19.2:8 19.3:5 19.4:2|poisoned raw-file cache runs crafted content in pipelines"
"CVE-2026-81839|7.7|ee|18.1|19.2:8 19.3:5 19.4:2|pipelines run with a new group's privileges after a transfer"
"CVE-2026-96893|7.3|ee|19.1|19.2:8 19.3:5 19.4:2|prompt injection in the Duo Agent Platform: crafted content in the AI conversation context can cause unintended commands attributed to other users"
"CVE-2026-15723|8.2|any|10.1|19.3:6 19.4:3 19.5:1|account takeover when SAML and LDAP auto-linking are both enabled"
"CVE-2026-112212|7.5|any|18.3|19.3:6 19.4:3 19.5:1|OAuth and OpenID Connect discovery cache poisoning, redirecting sign-in flows"
)

# gitlab_state <X.Y.Z> <introduced X.Y> "<fixed list>"  ->  notaffected | affected | nofix | fixed | unknown
gitlab_state() {
    local v="$1" intro="$2" fixed="$3" maj min pat imaj imin key top=0 want="" ent
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    imaj="${intro%%.*}"; imin="${intro##*.}"
    (( maj < imaj || (maj == imaj && min < imin) )) && { echo notaffected; return; }
    key=$(( maj * 1000 + min ))
    for ent in $fixed; do
        local b="${ent%%:*}" p="${ent##*:}" bk
        bk=$(( ${b%%.*} * 1000 + ${b##*.} )); (( bk > top )) && top=$bk
        (( bk == key )) && want="$p"
    done
    if [[ -n "$want" ]]; then (( pat >= want )) && echo fixed || echo affected; return; fi
    (( key > top )) && echo fixed || echo nofix
}

# the fixed patch release for this line, or empty
gitlab_fix_for() { local v="$1" fixed="$2" ent; for ent in $fixed; do [[ "${v%.*}" == "${ent%%:*}" ]] && { echo "${ent%%:*}.${ent##*:}"; return; }; done; }

# edition from a marker: ee | ce | unknown
gitlab_edition_of() {
    case "$1" in
        *gitlab-ee*|*-ee|*-ee.*|*"-ee "*) echo ee ;;
        *gitlab-ce*|*-ce|*-ce.*|*"-ce "*) echo ce ;;
        *) echo unknown ;;
    esac
}

# "<kind>|<where>|<version>|<edition>" for each install found
gitlab_installs() {
    local root="${GITLAB_ROOT:-/opt/gitlab}" f v d rt img ed man
    f="$root/embedded/service/gitlab-rails/VERSION"; man="$root/version-manifest.txt"
    if [[ -r "$f" || -r "$man" ]]; then
        v=""; ed=unknown
        if [[ -r "$f" ]]; then v="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -n1)"; head -n1 "$f" 2>/dev/null | grep -qiE '^[0-9]+\.[0-9]+\.[0-9]+-(pre|rc)' && [[ -n "$v" ]] && v="${v}-pre"; ed="$(gitlab_edition_of "$(head -n1 "$f" 2>/dev/null)")"; fi
        if [[ -r "$man" ]]; then
            [[ -n "$v" ]] || v="$(head -n1 "$man" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
            [[ "$ed" != unknown ]] || ed="$(gitlab_edition_of "$(head -n1 "$man" 2>/dev/null)")"
        fi
        [[ "$ed" != unknown ]] || { [[ -d "$root/embedded/service/gitlab-rails/ee" ]] && ed=ee; }
        echo "omnibus|${root}|${v}|${ed}"
    fi
    # shellcheck disable=SC2086
    for d in ${GITLAB_SOURCE_DIRS:-/home/git/gitlab}; do
        [[ -r "$d/VERSION" ]] || continue
        v="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$d/VERSION" 2>/dev/null | head -n1)"
        head -n1 "$d/VERSION" 2>/dev/null | grep -qiE '^[0-9]+\.[0-9]+\.[0-9]+-(pre|rc)' && [[ -n "$v" ]] && v="${v}-pre"
        ed="$(gitlab_edition_of "$(head -n1 "$d/VERSION" 2>/dev/null)")"
        [[ "$ed" != unknown ]] || { [[ -d "$d/ee" ]] && ed=ee; }
        echo "source|${d}|${v}|${ed}"
    done
    for rt in docker podman; do
        have "$rt" || continue
        while IFS= read -r img; do
            [[ -n "$img" ]] || continue
            v="$(grep -oE ':[0-9]+\.[0-9]+\.[0-9]+' <<<"$img" | tr -d ':' | head -n1)"
            case "$img" in *gitlab-ee*) ed=ee ;; *gitlab-ce*) ed=ce ;; *) ed=unknown ;; esac
            echo "${rt} image|${img}|${v}|${ed}"
        done < <("$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)gitlab/gitlab-(ce|ee):' | sort -u)
    done
}

cmd_check() {
    local rc=0 found=0 line kind where v ed row id cvss need intro fixed what st fx nbad
    step "Looking for GitLab"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        found=$((found+1)); IFS='|' read -r kind where v ed <<<"$line"
        step "GitLab ${v:-unknown}, edition ${ed:-unknown} (${kind}: ${where})"
        [[ -n "$v" ]] || { caution "could not read a version"; rc=1; continue; }
        nbad=0
        for row in "${GL_CVES[@]}"; do
            IFS='|' read -r id cvss need intro fixed what <<<"$row"
            st="$(gitlab_state "$v" "$intro" "$fixed")"
            if [[ "$st" == unknown ]]; then
                if [[ "$v" == *-pre ]]; then caution "${v} is a pre-release build, not a release: it may not have the fixes. Upgrade to a released version"
                else caution "cannot interpret version '${v}'"; fi
                nbad=$((nbad+1)); rc=1; break
            fi
            [[ "$st" == fixed || "$st" == notaffected ]] && continue
            if [[ "$need" == ee && "$ed" == ce ]]; then inf "${id} (${cvss}) applies to Enterprise Edition only; this is Community Edition"; continue; fi
            nbad=$((nbad+1)); fx="$(gitlab_fix_for "$v" "$fixed")"
            local sev="CVSS ${cvss}"
            if [[ "$need" == ee && "$ed" != ee ]]; then
                caution "${id} (${sev}): ${what}. Applies to Enterprise Edition only and the edition could not be read: if this is EE it is exposed"; rc=1; continue
            fi
            if [[ "$st" == affected ]]; then bad "${id} (${sev}): ${what}. Fixed in ${fx}"
            else bad "${id} (${sev}): ${what}. GitLab published no fix for the ${v%.*} line"; fi
            rc=1
        done
        [[ $nbad -eq 0 ]] && ok "no flaw in this set applies to ${v}"
        case "$kind" in *image*) [[ $nbad -eq 0 ]] || inf "this is an image on disk, not necessarily a running container: pull a fixed tag and recreate the container" ;; esac
    done < <(gitlab_installs)
    [[ $found -eq 0 ]] && info "No GitLab found (Omnibus under ${GITLAB_ROOT:-/opt/gitlab}, source under ${GITLAB_SOURCE_DIRS:-/home/git/gitlab}, or gitlab/gitlab-ce and gitlab-ee images)"
    step "Verdict"
    if [[ $found -gt 0 && $rc -eq 0 ]]; then info "No exposed GitLab found (${found} checked)."
    elif [[ $rc -ne 0 ]]; then
        warn "Exposed GitLab found. Upgrade to 19.5.1, 19.4.3 or 19.3.6."
        inf "Move to 19.5.1, 19.4.3 or 19.3.6: only these carry every fix in this set and the October regular-expression fixes. 19.2.9 and the older backports (19.1.9, 19.0.10, 18.11.13) carry only the regular-expression fix, so they leave the flaws above open"
        inf "If CVE-2026-14814 applied, CI/CD variables that pipelines could read may have been exposed too: rotate protected variables"
        inf "If CVE-2026-15723 applied (SAML and LDAP auto-linking both on), review LDAP-backed accounts for sign-ins you do not recognise"
        inf "Until you can upgrade (the project's suggestion, not GitLab's): take the instance off the public internet, or restrict it at the reverse proxy or firewall to trusted networks"
        inf "The October regular-expression flaws are a separate problem: run the ruby/ checker as well"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "GitLab: CVE-2026-16301, -92883, -14814, -81839, -96893, -15723, -112212"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
