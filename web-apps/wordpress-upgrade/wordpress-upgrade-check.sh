#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# WordPress core upgrade-window remote code execution: read-only checker  (v1)
# CVE-2026-119977
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Fixed on 28 October 2026 in WordPress 7.1.4 and the matching branch releases. CWE-367, a
# time of check to time of use race, CVSS 3.1 8.1 (High, by the CVE Numbering Authority,
# Wordfence; the WordPress project rates it low). Exploitation attempts began within hours
# of the release, and CISA added CVE-2026-119977 to its Known Exploited Vulnerabilities
# catalog on 3 November 2026. Reported by Umut Bayram (Picus Security).
#
# While WordPress applies a full core update it unpacks the new release into a folder under
# wp-content/upgrade/, and on most servers that folder is reachable over HTTP. The unpacked
# copy is a second WordPress with its own setup-config.php installer, and it cannot see the
# live wp-config.php, so it offers to set itself up. An unauthenticated visitor can finish that
# installer during the update, which writes a wp-config.php into the staging folder; the
# updater then copies that file over the live wp-config.php. The site now uses the attacker's
# database, the attacker creates the first administrator, and a plugin upload runs PHP as the
# web server user. It needs the update to be running, which is only seconds on most sites.
#
# What the fix changed (WordPress 7.1.4, as the researcher describes it): the staging
# folder gets a 16 character random suffix; wp-content/upgrade/index.php is kept; and
# wp-config.php is added to the skip list of the copy in update-core.php. The first update
# from an unfixed release is still exposed to the temporary installer, because the old
# updater does the unpacking, so block the folder before you update.
#
#   Affected: WordPress 4.7.0 through 7.1.3 (the CVE record), in every branch.
#   Fixed:    7.1.4, 7.0.8, 6.9.11, 6.8.12, 6.7.11, 6.6.11 and so on down to 4.7.39. A branch's
#             fixed number is the release after its last affected one in the CVE record; on 28
#             October WordPress said the older backports would ship as they became ready.
#   Not fixed: WordPress 4.6 and older no longer receive security fixes. The CVE record lists
#             4.7 and later, and the researcher reports the same updater behavior since 2.7.
#   Less exposed: 4.4 through 5.8 add a random suffix to the staging folder name, which the
#             researcher says makes the path guessable only if something else discloses it.
#
# Workaround, from the researcher and Wordfence: deny web access to wp-content/upgrade/ (WordPress
# reads and writes it through the filesystem and never serves it), before you update. A manual
# update outside the web root also avoids the temporary installer; wp core update does not,
# because it uses the same updater. This script only reads; "rules" prints the lines to add.
#
# Usage:
#   ./wordpress-upgrade-check.sh [check] [DIR ...]
#   check (default)  find WordPress under DIR, read each version, look for the three fixes in
#                    the source, look for a web server rule that blocks wp-content/upgrade/, and
#                    list leftover files in it. Exit 0 = nothing exposed, 1 = an install without
#                    the fix, or one whose state is unclear.
#   hunt [DIR ...]   look in web server logs for requests under /wp-content/upgrade/ and in each
#                    install's wp-content/upgrade/ for a wp-config.php or other PHP file. Exit 0 =
#                    nothing found, 1 = a lead. A clean hunt means the published indicators were
#                    not found; it does not show that the live wp-config.php is the original one.
#   rules            print the nginx, Apache and .htaccess lines that deny web access to
#                    wp-content/upgrade/. It changes nothing.
#   version          print the script version.
#
# Env: WUP_LOGS (space separated paths or globs) names web server logs. WUP_CONF (space
# separated paths or globs) names the web server configuration to read for a blocking rule.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="wordpress-upgrade-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-05"
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
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"

# Version helpers: strip a leading v and any -prerelease or +build suffix, then compare with
# sort -V. A pre-release of the boundary itself (7.1.4-rc2 against 7.1.4) is below it, as in
# semantic versioning, so a pre-release of a fixed release is never reported as the release.
norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- version table (the CVE record, CNA Wordfence) ---------------------------------
# The last affected release of each branch. A branch's first fixed release is the next one.
WUP_LAST=(
    "4.7:4.7.38" "4.8:4.8.33" "4.9:4.9.34" "5.0:5.0.30" "5.1:5.1.27" "5.2:5.2.29" "5.3:5.3.26"
    "5.4:5.4.24" "5.5:5.5.23" "5.6:5.6.22" "5.7:5.7.20" "5.8:5.8.18" "5.9:5.9.19" "6.0:6.0.17"
    "6.1:6.1.15" "6.2:6.2.14" "6.3:6.3.13" "6.4:6.4.13" "6.5:6.5.13" "6.6:6.6.10" "6.7:6.7.10"
    "6.8:6.8.11" "6.9:6.9.10" "7.0:7.0.7" "7.1:7.1.3"
)
# wp_up_fixed VERSION: prints the first fixed release of the version's branch, or nothing
wp_up_fixed() {
    local raw="${1%-src}" v maj min e last a b c
    v="${raw%%-*}"
    [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]] || return 0
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"
    for e in "${WUP_LAST[@]}"; do
        [[ "${e%%:*}" == "${maj}.${min}" ]] || continue
        last="${e#*:}"; IFS=. read -r a b c <<<"$last"; echo "${a}.${b}.$((c + 1))"; return
    done
}
# wp_up_status VERSION: prints affected | fixed | old | unknown
wp_up_status() {
    local raw="$1" v maj min fx
    raw="${raw%-src}"; v="${raw%%-*}"
    [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"
    (( maj < 4 || (maj == 4 && min < 7) )) && { echo old; return; }
    (( maj > 7 || (maj == 7 && min > 1) )) && { echo fixed; return; }
    fx="$(wp_up_fixed "$v")"
    [[ -n "$fx" ]] || { echo unknown; return; }
    ver_lt "$raw" "$fx" && echo affected || echo fixed
}

# ---------- source signatures: what the researcher says the fix changed -------------------
# Confirmed against the real 7.1.4 source (class-wp-upgrader.php, update-core.php). Used to recognize
# a backport under an older version number, and never to downgrade a release the version table calls fixed.
#   1. class-wp-upgrader.php: the staging folder gets a 16 character random suffix
#   2. update-core.php: wp-config.php is in the skip list of the copy
rand_in_source() {
    local f="$1/wp-admin/includes/class-wp-upgrader.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -E 'wp_generate_password\([[:space:]]*16' "$f" >/dev/null; then echo yes; else echo no; fi
}
skip_in_source() {
    local f="$1/wp-admin/includes/update-core.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if awk '/^[[:space:]]*(\/\/|#|\*|\/\*)/ {next} /\$skip[[:space:]]*=[[:space:]]*array[[:space:]]*\(/ {on=1} on {print} on && /\)[[:space:]]*;/ {exit}' "$f" | grep -F "'wp-config.php'" >/dev/null; then echo yes; else echo no; fi
}

# ---------- is the folder blocked on the web server? -------------------------------------
# Looks for a line that names wp-content/upgrade together with a deny, in the web server
# configuration and in the install's own .htaccess. It reads text; it does not ask the server.
blocked_by_rule() {   # <install root>
    local g f hit="" r="$1"
    local -a files=()
    if [[ -n "${WUP_CONF:-}" ]]; then
        # shellcheck disable=SC2206
        for g in $WUP_CONF; do for f in $g; do [[ -f "$f" && -r "$f" ]] && files+=("$f"); done; done
    else
        for g in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* /etc/nginx/snippets/*.conf \
                 /etc/apache2/apache2.conf /etc/apache2/sites-enabled/*.conf /etc/apache2/conf-enabled/*.conf \
                 /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf; do
            for f in $g; do [[ -f "$f" && -r "$f" ]] && files+=("$f"); done
        done
    fi
    [[ -r "$r/.htaccess" ]] && files+=("$r/.htaccess")
    for f in "${files[@]:-}"; do
        [[ -n "$f" ]] || continue
        if awk '/^[[:space:]]*#/ {next} /wp-content\/upgrade/ {print; on=3} on>0 && /(deny|Deny|403|Require[[:space:]]+all[[:space:]]+denied|return[[:space:]]+40[34])/ {found=1} on>0 {on--} END {exit found?0:1}' "$f" >/dev/null 2>&1; then hit="$f"; break; fi
    done
    echo "$hit"
}

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

cmd_rules() {
    cat <<'EOR'
# nginx: inside the server block of the site, before the update
location ^~ /wp-content/upgrade/ {
    deny all;
}

# Apache: in the virtual host
<Directory "/var/www/html/wp-content/upgrade">
    Require all denied
</Directory>

# Apache, only if you can edit .htaccess in the WordPress root: put this line above the WordPress
# rewrite block. Do not put an .htaccess file inside wp-content/upgrade/ itself: the updater
# deletes that folder's contents before it unpacks.
RedirectMatch 403 ^/wp-content/upgrade/

# Reload the web server, then check that /wp-content/upgrade/ answers 403 before you update.
EOR
}

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'wp-includes/version.php' 'wp-admin/includes/class-wp-upgrader.php' 'wp-admin/includes/update-core.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() roots=()
    local rc=0 found=0 d f root ver st rd sd rule left WUP_FIXED
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for WordPress"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do [[ -n "$f" ]] && roots+=("$(dirname "$(dirname "$f")")"); done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/wp-includes/version.php' -type f 2>/dev/null | sort)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        found=$((found+1))
        ver="$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*'([^']+)'.*/\\1/p" "$root/wp-includes/version.php" 2>/dev/null | head -n1)"
        step "WordPress ${ver:-unknown} at ${root}"
        [[ -n "$ver" ]] || { caution "could not read the version from wp-includes/version.php"; rc=1; continue; }
        st="$(wp_up_status "$ver")"; WUP_FIXED="$(wp_up_fixed "$ver")"
        rd="$(rand_in_source "$root")"; sd="$(skip_in_source "$root")"
        case "$st" in
            old)
                bad "WordPress ${ver} is older than 4.7: it no longer receives security fixes, and the researcher reports the same updater behavior since 2.7. Move to a supported release."
                rc=1 ;;
            fixed)
                ok "${ver} has the fix for CVE-2026-119977"
                if [[ "$rd" == no || "$sd" == no ]]; then inf "source check: random staging suffix ${rd}; wp-config.php in the skip list ${sd}. The version decides."; fi ;;
            affected|unknown)
                if [[ "$rd" == yes && "$sd" == yes ]]; then
                    ok "version ${ver} would be in the affected range, but the source carries both fixes (a distribution backport): not exposed"
                    inf "the version string understates this install's state; update to ${WUP_FIXED:-a fixed release} when you can"
                elif [[ "$st" == unknown ]]; then
                    caution "WordPress ${ver}: this branch is not in the CVE record's table and the source does not show the fixes: update to the newest release"
                    rc=1
                else
                    bad "WordPress ${ver} has CVE-2026-119977: an unauthenticated visitor can use the temporary installer in the update folder to replace wp-config.php during a core update. Fixed in ${WUP_FIXED} for this branch (7.1.4 for 7.1)."
                    inf "source check: random staging suffix ${rd}; wp-config.php in the skip list ${sd}"
                    rc=1
                fi ;;
        esac
        if [[ "$st" == affected || "$st" == old || "$st" == unknown ]]; then
            case "${ver%%.*}.$(norm_ver "$ver" | cut -d. -f2)" in 4.[4-9]|5.[0-8]) inf "this branch adds a random suffix to the staging folder name, which the researcher says makes the path guessable only if something else discloses it. Update anyway." ;; esac
            rule="$(blocked_by_rule "$root")"
            if [[ -n "$rule" ]]; then ok "a rule that denies wp-content/upgrade/ is in ${rule}"
            else caution "no web server rule that denies wp-content/upgrade/ was found (the configuration may be elsewhere: set WUP_CONF). Add one before you update: ${SELF} rules"; fi
        fi
        left="$(find "$root/wp-content/upgrade" -mindepth 1 -maxdepth 1 ! -name index.php 2>/dev/null | head -n 5 | tr '\n' ' ')"
        if [[ -n "$left" ]]; then caution "wp-content/upgrade/ is not empty: ${left}. A finished update removes its folder. Run: ${SELF} hunt ${root}"; fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No WordPress found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed WordPress found (${found} checked)."
    else
        warn "Exposed WordPress found. First deny web access to wp-content/upgrade/ (${SELF} rules), then update core: 7.1.4, 7.0.8, 6.9.11, 6.8.12 or the fixed release of your branch. The update that installs the fix is itself exposed without that rule."
        inf "If the site was reachable after 28 October 2026, run: ${SELF} hunt"
        inf "Advisory: https://wordpress.org/news/2026/10/wordpress-7-1-4/ and https://www.cve.org/CVERecord?id=CVE-2026-119977"
    fi
    return "$rc"
}

cmd_hunt() {
    local -a logs=() dirs=() existing=() roots=()
    local unread=0 rc=0 n m f g total=0 totalphp=0 nlog=0 d root w
    step "Hunting for CVE-2026-119977 exploitation in web server logs"
    if [[ -n "${WUP_LOGS:-}" ]]; then
        # shellcheck disable=SC2206
        for g in $WUP_LOGS; do for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done; done
    else
        for g in /var/log/nginx/access.log* /var/log/nginx/*access*.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* /var/log/httpd/access_log* /var/log/httpd/*access*log*; do
            for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done
        done
    fi
    if [[ ${#logs[@]} -eq 0 ]]; then
        inf "no web server access logs found (set WUP_LOGS to name them)"
    else
        # any request under the staging area (WordPress never serves it), and the ones for a PHP file
        for f in "${logs[@]}"; do
            nlog=$((nlog+1))
            n="$(zcat -f "$f" 2>/dev/null | grep -Ec '/wp-content/upgrade/')"
            m="$(zcat -f "$f" 2>/dev/null | grep -Ec '/wp-content/upgrade/[^ "?]*\.php')"
            total=$((total+n)); totalphp=$((totalphp+m))
            [[ "$n" -gt 0 ]] && inf "${f}: ${n} request(s) under /wp-content/upgrade/, ${m} for a PHP file"
        done
        inf "read ${nlog} log file(s)"
        if [[ $totalphp -gt 0 ]]; then
            bad "${totalphp} request(s) for a PHP file under /wp-content/upgrade/ (the temporary installer is setup-config.php): a strong lead"
            for f in "${logs[@]}"; do zcat -f "$f" 2>/dev/null | grep -E '/wp-content/upgrade/[^ "?]*\.php' | head -n 3 | cut -c1-200 | sed 's/^/        /'; done | head -n 8
            rc=1
        elif [[ $total -gt 0 ]]; then
            caution "${total} request(s) under /wp-content/upgrade/, none for a PHP file: a probe, not necessarily a success"
            rc=1
        else
            ok "no request under /wp-content/upgrade/ found in the logs read"
        fi
        inf "a POST body is not recorded in an access log: a quiet log does not rule out an attempt"
    fi

    step "Looking in wp-content/upgrade/ of each install"
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    if [[ ${#existing[@]} -gt 0 ]]; then
        while IFS= read -r f; do [[ -n "$f" ]] && roots+=("$(dirname "$(dirname "$f")")"); done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/wp-includes/version.php' -type f 2>/dev/null | sort)
    fi
    if [[ ${#roots[@]} -eq 0 ]]; then
        inf "no WordPress found to look in"
    else
        for root in "${roots[@]}"; do
            [[ -d "$root/wp-content/upgrade" ]] || { inf "${root}: no wp-content/upgrade folder"; continue; }
            w="$(find "$root/wp-content/upgrade" -name wp-config.php -type f 2>/dev/null | head -n 5)"
            if [[ -n "$w" ]]; then
                bad "${root}: a wp-config.php inside wp-content/upgrade/: the temporary installer was completed here. $(tr '\n' ' ' <<<"$w")"
                rc=1
            fi
            n="$(find "$root/wp-content/upgrade" -type f -name '*.php' ! -path '*/wordpress/*' ! -name index.php 2>/dev/null | head -n 5)"
            if [[ -n "$n" ]]; then caution "${root}: PHP files in wp-content/upgrade/ outside an unpacked wordpress folder: $(tr '\n' ' ' <<<"$n")"; rc=1; fi
            if [[ -z "$w" && -z "$n" ]]; then ok "${root}: no wp-config.php and no stray PHP file in wp-content/upgrade/"; fi
        done
        inf "if the live wp-config.php may have been replaced: compare its DB_NAME and DB_HOST with what you expect, and list the administrators (wp user list --role=administrator)"
    fi

    step "Verdict"
    if [[ $rc -eq 0 && $unread -gt 0 ]]; then
        warn "No lead in the logs that could be read, but ${unread} log file(s) could not be read by this user, so this is not a clean result. Run it with sudo: sudo ${SELF_CMD}"
    elif [[ $rc -eq 0 ]]; then info "No lead found: none of the published indicators were found."
    else warn "Lead found. Check the live wp-config.php, the administrator accounts, and plugins or PHP files added since 28 October."; fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    case "$CMD" in rules) cmd_rules; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-119977 (WordPress core upgrade-window RCE); fixed in 7.1.4, 7.0.8, 6.9.11, 6.8.12 and older-branch backports; block wp-content/upgrade/ first"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|rules|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
