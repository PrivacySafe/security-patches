#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Grav CMS Login plugin invitation privilege escalation: read-only checker  (v1)
# CVE-2026-114658 (GHSA-j8jx-ccrg-m7h2)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Login plugin's invitation task (login.invite) sends an invitation without
# checking who submitted the form, and takes the new account's access straight from
# the page's frontmatter (form: meta: invite: account:) with no cap on what is
# granted. A page author can therefore define an invitation form that grants super
# user access, submit it, and register the invited address for full control of the
# site. VulnCheck describes the submission as possible without authentication.
# CVSS 8.7 (v4.0), 8.8 (v3.1).
#
#   Affected: Grav Login plugin 3.6.0 through 3.9.12 (Grav 1.7 and 2.x)
#   Fixed:    3.9.13. Only a super user can then invite someone into super access
#             or into groups; for anyone else those are removed from the invitation.
#             A page restricted with "access: admin.login" now needs an account
#             management permission to send invitations.
#
# This script is read-only. "check" finds Grav sites (a user/plugins/login directory),
# reads the Login plugin version from blueprints.yaml, and lists pages that declare an
# invitation form. "hunt" also looks for what an attack leaves behind: pending
# invitations and page frontmatter that grant super access, and super-user accounts
# changed recently. It NEVER prints invitation tokens (the keys of invites.yaml),
# password hashes or any account secret: it reports only account file names, email
# addresses of invitations and modification times.
#
# Usage:
#   ./grav-login-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home). Exit 0 = nothing
#                    affected, 1 = an affected Login plugin found.
#   hunt             check, then search for signs of abuse. Exit 0 = nothing found,
#                    1 = an affected version or an indicator was found.
#   version          print the script version.
#
# Environment: HUNT_ADMIN_SINCE (default 2026-10-01): super-user accounts modified
# since this date are flagged for review.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="grav-login-check.sh"
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
# prints: vulnerable | fixed | notaffected | unknown
login_status() {
    local n; n="$(norm_ver "$1")"
    is_semver "$n" || { echo unknown; return; }
    ver_lt "$n" "3.6.0" && { echo notaffected; return; }
    ver_lt "$n" "3.9.13" && echo vulnerable || echo fixed
}

plugin_version() { sed -n 's/^version:[[:space:]]*\([0-9][0-9A-Za-z.\-]*\).*/\1/p' "$1" 2>/dev/null | head -n1 | tr -d "\"' \r"; }

# frontmatter check: prints "super" if a page declares form/meta/invite granting super access,
# "plain" if it declares an invitation form without it, nothing otherwise
page_invite_kind() {
    awk '
        NR==1 && $0 !~ /^---[[:space:]]*$/ {exit}
        NR>1 && /^---[[:space:]]*$/ {exit}
        /^[[:space:]]*invite:[[:space:]]*$/ { match($0,/^[ \t]*/); base=RLENGTH; inb=1; seen=1; next }
        inb { match($0,/^[ \t]*/); ind=RLENGTH
              if ($0 ~ /^[[:space:]]*$/) next
              if (ind <= base) { inb=0 }
              else if (tolower($0) ~ /super:[[:space:]]*["\047]?(true|1|yes|on)/) sup=1 }
        END { if (sup) print "super"; else if (seen) print "plain" }' "$1" 2>/dev/null
}

# ---------- check ------------------------------------------------------------
SITES=()
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
        stage_containers 'user/plugins/login/blueprints.yaml'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d bp root ver st pg kind n_plain n_super out
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Grav sites with the Login plugin"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    SITES=()
    while IFS= read -r bp; do
        [[ -n "$bp" ]] || continue
        root="$(dirname "$(dirname "$(dirname "$(dirname "$bp")")")")"
        found=$((found+1)); SITES+=("$root")
        ver="$(plugin_version "$bp")"
        step "Grav Login plugin ${ver:-version unreadable} at ${root}"
        if [[ -z "$ver" ]]; then caution "could not read the plugin version from ${bp}: affected is 3.6.0 through 3.9.12, fixed is 3.9.13"; rc=1; continue; fi
        st="$(login_status "$ver")"
        case "$st" in
            fixed)       ok "Login ${ver} has the fix (3.9.13 or newer)" ;;
            notaffected) ok "Login ${ver} is older than 3.6.0, the start of the affected range. It is far out of date, so update it anyway." ;;
            unknown)     caution "cannot compare version '${ver}': check it against 3.9.13"; rc=1 ;;
            vulnerable)  bad "Login ${ver} is affected by CVE-2026-114658 (fixed in 3.9.13): a page author can create a super user account through an invitation form"
                         inf "update now (bin/gpm update login, or the Admin plugin), then run: $0 hunt"
                         rc=1 ;;
        esac
        # pages that declare an invitation form (review who can edit pages)
        n_plain=0; n_super=0; out=""
        while IFS= read -r pg; do
            [[ -n "$pg" ]] || continue
            kind="$(page_invite_kind "$pg")"
            case "$kind" in
                super) n_super=$((n_super+1)); out+="${pg}"$'\n' ;;
                plain) n_plain=$((n_plain+1)) ;;
            esac
        done < <(find "$root/user/pages" -type f -name '*.md' 2>/dev/null | head -n2000)
        if [[ $n_super -gt 0 ]]; then
            bad "${n_super} page(s) declare an invitation form that grants SUPER access in their frontmatter (this is what the attack plants):"
            grep -v '^$' <<<"$out" | sed 's/^/        /' | head -n10; rc=1
        fi
        [[ $n_plain -gt 0 ]] && inf "${n_plain} page(s) declare an invitation form without super access (normal if you use invitations; confirm who can edit those pages)"
        [[ $n_super -eq 0 && $n_plain -eq 0 ]] && inf "no page declares an invitation form"
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -path '*/user/plugins/login/blueprints.yaml' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Grav Login plugin found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Login plugin found (${found} checked)"
    else
        warn "Affected or unverifiable Grav Login plugin found. Update the Login plugin to 3.9.13 or later."
        inf "Interim (ours, not vendor documented): remove or disable any page that declares an invitation form, and restrict who can create or edit pages. An update does not delete accounts already created."
        inf "Advisory: https://github.com/getgrav/grav/security/advisories/GHSA-j8jx-ccrg-m7h2"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
hunt_site() {   # site root
    local root="$1" rc=0 inv acc f name since out
    since="${HUNT_ADMIN_SINCE:-2026-10-01}"
    step "Hunting in ${root}"
    # pending invitations. The keys of invites.yaml are registration tokens: never printed.
    inv="${root}/user/data/accounts/invites.yaml"
    if [[ -r "$inv" ]]; then
        out="$(awk '
            /^[^[:space:]#][^:]*:[[:space:]]*$/ { if (inb) flush(); inb=1; email=""; by=""; sup=0; next }
            inb && /^[[:space:]]+email:/ { v=$0; sub(/^[^:]*:[[:space:]]*/,"",v); gsub(/["\047]/,"",v); email=v }
            inb && /^[[:space:]]+created_by:/ { v=$0; sub(/^[^:]*:[[:space:]]*/,"",v); gsub(/["\047]/,"",v); by=v }
            inb && tolower($0) ~ /super:[[:space:]]*["\047]?(true|1|yes|on)/ { sup=1 }
            function flush() { n++; if (sup) { s++; printf "SUPER\t%s\t%s\n", email, by } }
            END { if (inb) flush(); printf "COUNT\t%d\t%d\n", n+0, s+0 }' "$inv")"
        local total supers
        total="$(awk -F'\t' '$1=="COUNT"{print $2}' <<<"$out")"; supers="$(awk -F'\t' '$1=="COUNT"{print $3}' <<<"$out")"
        if [[ "${supers:-0}" -gt 0 ]]; then
            bad "${supers} pending invitation(s) grant SUPER access (invited address, issued by; tokens are not shown):"
            awk -F'\t' '$1=="SUPER"{printf "        %s  (issued by %s)\n",$2,$3}' <<<"$out" | head -n10; rc=1
        else
            ok "no pending invitation grants super access (${total:-0} pending)"
        fi
    else
        inf "no invites.yaml at ${inv}: no pending invitations"
    fi
    # super-user accounts
    acc="${root}/user/accounts"
    if [[ -d "$acc" ]]; then
        out=""
        while IFS= read -r f; do
            grep -qiE '^[[:space:]]+super:[[:space:]]*["\047]?(true|1|yes|on)' "$f" 2>/dev/null || continue
            name="$(basename "$f" .yaml)"
            if [[ -n "$(find "$f" -newermt "$since" 2>/dev/null)" ]]; then
                out+="  ${name}  (modified $(date -r "$f" +%F))"$'\n'
            fi
        done < <(find "$acc" -maxdepth 1 -type f -name '*.yaml' ! -name 'invites.yaml' 2>/dev/null)
        if [[ -n "$out" ]]; then
            caution "super-user accounts created or changed since ${since} (confirm each one is yours):"
            sed 's/^/      /' <<<"$out" | head -n10; rc=1
        else
            ok "no super-user account was created or changed since ${since}"
        fi
    else
        inf "no user/accounts directory found"
    fi
    return "$rc"
}

cmd_hunt() {
    local rc=0 site
    cmd_check "$@" || rc=1
    for site in "${SITES[@]:-}"; do
        [[ -n "$site" ]] || continue
        hunt_site "$site" || rc=1
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No indicator found. This is not proof of a clean site."
    else
        warn "An affected version or an indicator was found."
        inf "Remove any super-user account or pending invitation you did not create, update the Login plugin, and reset the passwords of real super users."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114658; fixed in the Grav Login plugin 3.9.13"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
