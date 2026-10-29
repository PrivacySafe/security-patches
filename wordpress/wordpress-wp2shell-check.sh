#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# wp2shell, WordPress core pre-authentication RCE: read-only checker and hunter  (v1)
# CVE-2026-63030 (REST batch route confusion)
# CVE-2026-60137 (SQL injection in WP_Query author__not_in)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Disclosed and fixed on 17 July 2026, exploited in the wild from 20 July, and added to
# CISA's Known Exploited Vulnerabilities catalog on 21 July. Chained, the two flaws give an
# unauthenticated attacker remote code execution on a default WordPress install, with no
# plugins and no login. Observed attacks create rogue administrator accounts and install
# webshells.
#
#   CVE-2026-63030  REST API batch endpoint (/wp-json/batch/v1 or /?rest_route=/batch/v1).
#                   A malformed sub-request path desynchronizes the matched handlers from
#                   the requests, so later sub-requests run under the wrong permission
#                   check. Affects 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1.
#   CVE-2026-60137  When author__not_in reaches WP_Query as a string rather than an array
#                   it skips integer sanitization and is interpolated into the SQL WHERE
#                   clause. Affects 6.8.0 through 6.8.5, 6.9.0 through 6.9.4 and 7.0.0
#                   through 7.0.1. On 6.8.x the batch flaw is absent, so the SQL injection
#                   needs another way to reach it and the full chain does not apply.
#
#   Fixed: 6.8.6, 6.9.5, 7.0.2, and 7.1 beta 2 (every 7.1 release after beta 1).
#          WordPress before 6.8.0 is not affected.
#
#   Object cache: when a persistent object cache (Redis, Memcached) is active, the
#   SQL injection sink is not reached and the chain does not fire on currently
#   affected installs. The site still needs the update; disabling or flushing the
#   cache later re-exposes it. Discovered by Adam Kues of Searchlight Cyber.
#
# The fixes are recognisable in the source. The SQL injection fix replaces the is_array
# test and implode() in wp-includes/class-wp-query.php with wp_parse_id_list(); the batch
# fix adds a guard against starting a new top-level REST cycle while one is already
# dispatching, in wp-includes/rest-api/class-wp-rest-server.php. A distribution package
# can carry both fixes under an older version number, so this script reads the files as
# well as the version.
#
# Interim measure when you cannot update at once: refuse both URL forms of the batch
# route at the web server, for example in nginx
#     location ~* "^/wp-json/batch" { return 403; }
#     if ($args ~* "rest_route=(%2F|/)batch") { return 403; }
# or in Apache
#     RewriteRule ^wp-json/batch - [F,L]
#     RewriteCond %{QUERY_STRING} rest_route=(%2F|/)batch [NC]
#     RewriteRule ^ - [F,L]
# Both forms must be covered. The block stops the chain's entry point; it does not fix
# the SQL injection, so update anyway. The block editor uses the batch route for some
# saves, so expect that editing may be affected until you update.
#
# This script is read-only. It finds WordPress installs by wp-includes/version.php.
#
# Usage:
#   ./wordpress-wp2shell-check.sh [command] [DIR ...]
#
#   check (default)  find WordPress under DIR (default /var/www /srv /home /opt
#                    /usr/share/wordpress /usr/share/nginx /var/lib/wordpress), read each
#                    version, read the two source files for the fixes, and look for a
#                    web server block on the batch route. Exit 0 = nothing exposed,
#                    1 = an install without the fixes, or one whose state is unclear.
#   hunt             look for signs of exploitation: batch route requests and SQL
#                    injection strings in web server logs, PHP files in wp-content/
#                    uploads, and recent changes to mu-plugins. Exit 0 = nothing found,
#                    1 = a strong lead. A lead is not proof, and a clean hunt is not
#                    proof of safety.
#   version          print the script version.
#
# Env: HUNT_SINCE (YYYY-MM-DD, default 2026-07-17) for file changes;
#      WP2S_LOGS (space separated paths or globs) to name web server logs.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="wordpress-wp2shell-check.sh"
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
# prints: full | sqli | fixed | notaffected | unknown
#   full = both flaws (the RCE chain), sqli = only CVE-2026-60137, fixed = patched by version
wp_status() {
    local raw="$1" maj min pat pre
    raw="${raw%-src}"
    [[ "$raw" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?(-(alpha|beta|RC)([0-9]*))?$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[4]:-0}"; pre="${BASH_REMATCH[6]:-}"
    local prenum="${BASH_REMATCH[7]:-0}"
    (( maj > 7 )) && { echo fixed; return; }
    (( maj < 6 )) && { echo notaffected; return; }
    if (( maj == 6 )); then
        (( min < 8 )) && { echo notaffected; return; }
        (( min > 9 )) && { echo fixed; return; }
        if (( min == 8 )); then (( pat < 6 )) && echo sqli || echo fixed; return; fi
        (( pat < 5 )) && echo full || echo fixed; return
    fi
    # maj == 7
    case "$min" in
        0) (( pat < 2 )) && echo full || echo fixed ;;
        1) if [[ "$pre" == alpha ]]; then echo full
           elif [[ "$pre" == beta && "$prenum" -lt 2 ]]; then echo full
           else echo fixed; fi ;;
        *) echo fixed ;;
    esac
}

# ---------- reading an install -----------------------------------------------
wp_version_of() {   # wordpress root -> version string or empty
    sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*'([^']+)'.*/\\1/p" "$1/wp-includes/version.php" 2>/dev/null | head -n1
}
# Signatures of the two fixes in the source. prints yes | no | n/a
sqli_fix_in_source() {
    local f="$1/wp-includes/class-wp-query.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F 'author__not_in_id_list' "$f" >/dev/null; then echo yes; else echo no; fi
}
batch_fix_in_source() {
    local f="$1/wp-includes/rest-api/class-wp-rest-server.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F 'while another dispatch' "$f" >/dev/null; then echo yes; else echo no; fi
}

# ---------- web server block on the batch route ------------------------------
# Looks for a refusing rule for each URL form in the usual web server configuration.
BLOCK_PRETTY=""; BLOCK_QUERY=""
scan_batch_block() {
    BLOCK_PRETTY=""; BLOCK_QUERY=""
    local f line
    while IFS= read -r f; do
        [[ -r "$f" ]] || continue
        line="$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null)"
        if grep -E 'wp-json/\??batch|\^/?wp-json/batch|wp-json.*batch' <<<"$line" >/dev/null && grep -E 'return[[:space:]]+(403|404|410)|deny[[:space:]]+all|\[F|R=40[34]|Require[[:space:]]+all[[:space:]]+denied' <<<"$line" >/dev/null; then BLOCK_PRETTY="$f"; fi
        if grep -E 'rest_route=\(?[^ ]*batch|rest_route=.*batch' <<<"$line" >/dev/null && grep -E 'return[[:space:]]+(403|404|410)|deny[[:space:]]+all|\[F|R=40[34]|Require[[:space:]]+all[[:space:]]+denied' <<<"$line" >/dev/null; then BLOCK_QUERY="$f"; fi
    done < <(find /etc/nginx /etc/apache2 /etc/httpd /etc/angie /usr/local/etc/nginx /usr/local/etc/apache2 "$@" -xdev -maxdepth 8 -type f \
                \( -name '*.conf' -o -name '*.vhost' -o -name '.htaccess' -o -name 'sites-enabled' -o -path '*/sites-enabled/*' -o -path '*/conf.d/*' -o -path '*/sites-available/*' \) -size -1000k 2>/dev/null | sort -u)
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local -a dirs=() existing=() roots=()
    local rc=0 found=0 d f root ver st sqli batch eff
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for WordPress"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    scan_batch_block "${existing[@]}"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        roots+=("$(dirname "$(dirname "$f")")")
    done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/wp-includes/version.php' -type f 2>/dev/null | sort -u)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        found=$((found+1))
        ver="$(wp_version_of "$root")"
        step "WordPress ${ver:-unknown} at ${root}"
        [[ -n "$ver" ]] || { caution "could not read the version from wp-includes/version.php"; rc=1; continue; }
        st="$(wp_status "$ver")"
        sqli="$(sqli_fix_in_source "$root")"; batch="$(batch_fix_in_source "$root")"
        case "$st" in
            notaffected) ok "${ver} is older than 6.8.0: not affected"; continue ;;
            unknown)     caution "cannot parse version '${ver}': check it against 6.8.6, 6.9.5 and 7.0.2"; rc=1; continue ;;
        esac
        # decide from the source first: a backport changes the files, not always the version
        if [[ "$st" == fixed ]]; then
            if [[ "$sqli" == no ]]; then
                caution "version ${ver} is a fixed release, but class-wp-query.php still has the vulnerable author__not_in code: the files do not match the version (a partial or failed update)"
                rc=1
            else
                ok "${ver} has the fixes"
            fi
            continue
        fi
        # judge each flaw from its own signature in the source
        local sqli_open=1 batch_open=0
        [[ "$sqli" == yes ]] && sqli_open=0
        if [[ "$st" == full ]]; then batch_open=1; [[ "$batch" == yes ]] && batch_open=0; fi
        if [[ $sqli_open -eq 0 && $batch_open -eq 0 ]]; then
            ok "version ${ver} is in an affected range, but the source already carries the fixes (a distribution backport): not exposed"
            inf "the version string understates this install's state; update to a fixed release when you can"
            continue
        fi
        if [[ $sqli_open -eq 1 && $batch_open -eq 1 ]]; then
            bad "WordPress ${ver} has CVE-2026-63030 and CVE-2026-60137: the unauthenticated RCE chain applies (fixed in 6.9.5, 7.0.2)"
        elif [[ $batch_open -eq 1 ]]; then
            bad "WordPress ${ver}: the SQL injection (CVE-2026-60137) is fixed in the source, but the batch route flaw (CVE-2026-63030) is not: partially patched (fixed in 6.9.5, 7.0.2)"
        elif [[ "$st" == full ]]; then
            bad "WordPress ${ver}: the batch route flaw (CVE-2026-63030) is fixed in the source, but the SQL injection (CVE-2026-60137) is not: partially patched (fixed in 6.9.5, 7.0.2)"
        else
            bad "WordPress ${ver} has CVE-2026-60137, the WP_Query SQL injection (fixed in 6.8.6). The batch flaw is absent on 6.8.x, so the full chain does not apply, but the injection is reachable through other code paths such as plugins"
        fi
        inf "source check: author__not_in fix ${sqli}; batch route fix ${batch}"
        rc=1
    done
    if [[ $found -gt 0 && $rc -ne 0 ]]; then
        step "Web server block on the batch route"
        if [[ -n "$BLOCK_PRETTY" && -n "$BLOCK_QUERY" ]]; then
            ok "a refusing rule was found for both URL forms (${BLOCK_PRETTY}; ${BLOCK_QUERY})"
            inf "this closes the chain's entry point for affected installs behind this server; it is not the fix, so update"
        elif [[ -n "$BLOCK_PRETTY" || -n "$BLOCK_QUERY" ]]; then
            caution "a rule was found for only one URL form (${BLOCK_PRETTY:-none} for /wp-json/batch, ${BLOCK_QUERY:-none} for ?rest_route=/batch): the other form still reaches the route"
        else
            inf "no web server rule refusing the batch route was found in the usual configuration locations"
        fi
    fi
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No WordPress found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed WordPress found (${found} checked)."
    else
        warn "Exposed WordPress found. Update core: wp core update (6.8.6, 6.9.5, 7.0.2 or newer on your branch)."
        inf "Because this was exploited at scale, if an affected install was reachable from the internet after 17 July 2026, run: $0 hunt"
        inf "Advisories: https://wordpress.org/news/ and https://www.cve.org/CVERecord?id=CVE-2026-63030"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local -a dirs=() existing=() logs=() roots=()
    local rc=0 d f root since="${HUNT_SINCE:-2026-07-17}" nlog=0 total=0 sus=0 n m g lead=0
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Hunting for wp2shell exploitation (changes since ${since})"
    # web server logs
    if [[ -n "${WP2S_LOGS:-}" ]]; then
        # shellcheck disable=SC2206
        for g in $WP2S_LOGS; do for f in $g; do [[ -f "$f" ]] && logs+=("$f"); done; done
    else
        for g in /var/log/nginx/access.log* /var/log/nginx/*access*.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* /var/log/httpd/access_log* /var/log/httpd/*access*log* /var/log/angie/access.log*; do
            for f in $g; do [[ -f "$f" ]] && logs+=("$f"); done
        done
    fi
    # remove duplicates
    local -a uniq=(); declare -A seen=()
    for f in "${logs[@]:-}"; do [[ -n "$f" && -z "${seen[$f]:-}" ]] && { seen[$f]=1; uniq+=("$f"); }; done
    logs=("${uniq[@]:-}")
    if [[ ${#logs[@]} -eq 0 || -z "${logs[0]:-}" ]]; then
        inf "no web server access logs found in the usual places (set WP2S_LOGS to name them)"
    else
        local re_batch='(/wp-json/batch/v1|rest_route=(%2[Ff]|/)batch(%2[Ff]|/)v1)'
        local re_sqli='(author_exclude|author__not_in|[Uu][Nn][Ii][Oo][Nn]([+]|%20| )+([Aa][Ll][Ll]([+]|%20| )+)?[Ss][Ee][Ll][Ee][Cc][Tt]|[Ss][Ll][Ee][Ee][Pp]\(|[Ss][Ll][Ee][Ee][Pp]%28|[Bb][Ee][Nn][Cc][Hh][Mm][Aa][Rr][Kk])'
        for f in "${logs[@]}"; do
            nlog=$((nlog+1))
            n="$(zcat -f "$f" 2>/dev/null | grep -Ec "$re_batch")"
            m="$(zcat -f "$f" 2>/dev/null | grep -E "$re_batch" | grep -Ec "$re_sqli")"
            total=$((total+n)); sus=$((sus+m))
            [[ "$n" -gt 0 ]] && inf "${f}: ${n} request(s) to the batch route, ${m} of them with SQL injection strings in the URL"
        done
        inf "read ${nlog} log file(s)"
        if [[ $sus -gt 0 ]]; then
            bad "${sus} batch route request(s) carry SQL injection strings (author_exclude, UNION SELECT, SLEEP, BENCHMARK): a strong lead"
            for f in "${logs[@]}"; do
                zcat -f "$f" 2>/dev/null | grep -E "$re_batch" | grep -E "$re_sqli" | head -n 3 | cut -c1-220 | sed 's/^/        /'
            done | head -n 8
            rc=1
        elif [[ $total -gt 0 ]]; then
            caution "${total} request(s) to the batch route and none with injection strings in the URL. The block editor also uses this route, and the exploit's payload is in the request body, which access logs do not record: look at who sent them (unknown IPs, no logged-in cookie, bursts)"
        else
            ok "no request to the batch route in the logs read"
        fi
    fi
    # files on disk
    local -a roots=()
    while IFS= read -r f; do [[ -n "$f" ]] && roots+=("$(dirname "$(dirname "$f")")"); done < <(find "${existing[@]:-/nonexistent}" -xdev -maxdepth 8 -path '*/wp-includes/version.php' -type f 2>/dev/null | sort -u)
    if [[ ${#roots[@]} -eq 0 || -z "${roots[0]:-}" ]]; then inf "no WordPress install found under: ${existing[*]:-none}"; fi
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        step "Files under ${root}"
        n="$(find "$root/wp-content/uploads" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) 2>/dev/null | grep -c .)"
        if [[ "$n" -gt 0 ]]; then
            bad "${n} PHP file(s) inside wp-content/uploads, where WordPress never stores code:"
            find "$root/wp-content/uploads" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' -o -name '*.php[0-9]' \) 2>/dev/null | head -n 10 | sed 's/^/        /'
            rc=1
        else ok "no PHP files in wp-content/uploads"; fi
        n="$(find "$root/wp-content/mu-plugins" -type f -newermt "$since" 2>/dev/null | grep -c .)"
        if [[ "$n" -gt 0 ]]; then
            bad "${n} file(s) in wp-content/mu-plugins changed since ${since} (must-use plugins load on every request and are a favourite place to persist):"
            find "$root/wp-content/mu-plugins" -type f -newermt "$since" 2>/dev/null | head -n 10 | sed 's/^/        /'
            rc=1
        else ok "no changes in wp-content/mu-plugins since ${since}"; fi
        n="$(find "$root/wp-content/plugins" -mindepth 1 -maxdepth 1 -type d -newermt "$since" 2>/dev/null | grep -c .)"
        if [[ "$n" -gt 0 ]]; then
            caution "${n} plugin folder(s) created or changed since ${since} (normal updates also do this): confirm each one is expected"
            find "$root/wp-content/plugins" -mindepth 1 -maxdepth 1 -type d -newermt "$since" 2>/dev/null | head -n 10 | sed 's/^/        /'
        fi
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No strong lead found. This is not proof that the site was not compromised."
    else
        warn "Strong leads found. Treat the site as possibly compromised: update core, then in the database look for administrator accounts you did not create (wp user list --role=administrator) and for unexpected customize_changeset posts, review wp-content/plugins and mu-plugins, and rotate the database password, the salts in wp-config.php and every administrator password."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-63030 and CVE-2026-60137 (wp2shell); fixed in WordPress 6.8.6, 6.9.5 and 7.0.2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
