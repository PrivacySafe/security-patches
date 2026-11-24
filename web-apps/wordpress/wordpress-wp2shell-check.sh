#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# wp2shell, WordPress core pre-authentication RCE: checker, hunter and mitigation  (v1)
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
# The fixes are recognizable in the source. The SQL injection fix replaces the is_array
# test and implode() in wp-includes/class-wp-query.php with wp_parse_id_list(); the batch
# fix adds a guard against starting a new top-level REST cycle while one is already
# dispatching, in wp-includes/rest-api/class-wp-rest-server.php. A distribution package
# can carry both fixes under an older version number, so this script reads the files as
# well as the version.
#
# Protective measure when you cannot update at once: refuse both URL forms of the batch
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
# "check" and "hunt" are read-only; "mitigate" and "rollback" are the only commands that change
# anything. It finds WordPress installs by wp-includes/version.php.
#
# Usage:
#   ./wordpress-wp2shell-check.sh [command] [DIR ...]
#
#   check (default)  find WordPress under DIR (default /var/www /srv /home /opt
#                    /usr/share/wordpress /usr/share/nginx /var/lib/wordpress), read each
#                    version, read the two source files for the fixes, and look for a
#                    web server block on the batch route. Exit 0 = nothing exposed,
#                    1 = an install without the fixes, or one whose state is unclear.
#   mitigate [options]   (root) changes the host. The documented protective measure: refuses
#                    both URL forms of the REST batch route (/wp-json/batch and
#                    ?rest_route=/batch) at the web server, which closes the entry point of
#                    the unauthenticated chain. It does not fix the SQL injection, so
#                    update. Only when an exposed WordPress is found (--force overrides).
#                    nginx: an include as the first line of every PHP-serving server block,
#                    checked with nginx -t. Apache: psf-wp2shell-batch-block.conf (server
#                    scope, so virtual hosts inherit it), checked with a configtest. If the
#                    web server rejects the result everything is undone at once. Matches
#                    the route anywhere in the path, so a WordPress in a subdirectory is
#                    covered. The block editor uses the route for some saves.
#                      --web auto|apache|nginx  which web server (default auto)
#                      --dir DIR                where to look for WordPress (repeat)
#                      --server-name NAME       nginx: only the server block that lists NAME
#                      --dry-run, --reload, --force
#   rollback [--dry-run] [--reload]   remove what mitigate added and restore the files it edited.
#   hunt             look for signs of exploitation: batch route requests and SQL
#                    injection strings in web server logs, PHP files in wp-content/
#                    uploads, and recent changes to mu-plugins. Exit 0 = nothing found,
#                    1 = a strong lead. A clean hunt means none of the published indicators were found.
#                    proof of safety.
#   version          print the script version.
#
# Env: HUNT_SINCE (YYYY-MM-DD, default 2026-07-17) for file changes;
#      WP2S_LOGS (space separated paths or globs) to name web server logs.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="wordpress-wp2shell-check.sh"
SCRIPT_VERSION="1.0.1"
SCRIPT_DATE="2026-11-03"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/wp2shell}"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
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
    local rc=0 found=0 d f root ver st sqli batch
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
    local unread=0
    local -a dirs=() existing=() logs=() roots=()
    local rc=0 d f root since="${HUNT_SINCE:-2026-07-17}" nlog=0 total=0 sus=0 n m g
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Hunting for wp2shell exploitation (changes since ${since})"
    # web server logs
    if [[ -n "${WP2S_LOGS:-}" ]]; then
        # shellcheck disable=SC2206
        for g in $WP2S_LOGS; do for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done; done
    else
        for g in /var/log/nginx/access.log* /var/log/nginx/*access*.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* /var/log/httpd/access_log* /var/log/httpd/*access*log* /var/log/angie/access.log*; do
            for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done
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
            bad "${n} file(s) in wp-content/mu-plugins changed since ${since} (must-use plugins load on every request and are a favorite place to persist):"
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
    if [[ $rc -eq 0 && $unread -gt 0 ]]; then
        warn "No strong lead in the logs that could be read, but ${unread} log file(s) could not be read by this user, so this is not a clean result. Run it with sudo: sudo ${SELF_CMD}"; rc=2
    elif [[ $rc -eq 0 ]]; then
        info "No strong lead found: none of the published indicators were found."
    else
        warn "Strong leads found. Treat the site as possibly compromised: update core, then in the database look for administrator accounts you did not create (wp user list --role=administrator) and for unexpected customize_changeset posts, review wp-content/plugins and mu-plugins, and rotate the database password, the salts in wp-config.php and every administrator password."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------

# ---------- mitigate and rollback --------------------------------------------
W2_MANIFEST=""; W2_DRY=0
w2_run() { if [[ "$W2_DRY" -eq 1 ]]; then echo "  would run: $*"; return 0; fi; "$@"; }
w2_note() { [[ "$W2_DRY" -eq 1 ]] || echo "$1" >>"$W2_MANIFEST"; }
w2_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$W2_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$W2_MANIFEST"
}
w2_restore_all() {
    local line f
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f"
    done <"$W2_MANIFEST"
}
w2_nginx_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    { nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p'
      echo /etc/nginx/nginx.conf; ls /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done | awk '!s[$0]++'
}
read -r -d '' W2_AWK_SERVER <<'AWKEOF'
function chk(code,    t) {
    if (code ~ trig) hit = 1
    if (only != "" && code ~ /server_name/) {
        t = code; sub(/;.*/, "", t); sub(/^[ \t]*server_name[ \t]+/, "", t)
        if (index(" " t " ", " " only " ") > 0) sn = 1
    }
}
function flush(   i) {
    for (i = 1; i <= n; i++) {
        print buf[i]
        if (i == 1 && hit && (only == "" || sn) && !has) print "    include " snip ";"
    }
    n = 0; hit = 0; has = 0; sn = 0
}
{
    raw = $0; code = raw; sub(/#.*/, "", code)
    o = gsub(/\{/, "{", code); c = gsub(/\}/, "}", code)
    if (!inserv) {
        if (raw ~ /^[ \t]*server[ \t]*\{/) {
            inserv = 1; sdepth = depth; buf[++n] = raw; chk(code); depth += o - c
            if (depth <= sdepth) { flush(); inserv = 0 }
        } else { print raw; depth += o - c }
    } else {
        buf[++n] = raw; chk(code)
        if (index(raw, snip)) has = 1
        depth += o - c
        if (depth <= sdepth) { flush(); inserv = 0 }
    }
}
END { if (n > 0) flush() }
AWKEOF
read -r -d '' W2_AWK_HTTP <<'AWKEOF'
{
    print $0
    if (!done && $0 !~ /^[ \t]*#/ && $0 ~ /^[ \t]*http[ \t]*\{/) {
        if (!already) print "    include " snip ";"
        done = 1
    }
}
AWKEOF
w2_nginx_test() {
    if [[ -n "${NGINX_MAIN_CONF:-}" ]]; then nginx -t -c "$NGINX_MAIN_CONF" >/dev/null 2>&1; else nginx -t >/dev/null 2>&1; fi
}
# w2_nginx_apply HTTP_TEXT SERVER_TEXT TRIGGER_REGEX ONLY_SERVER_NAME -> 0 ok, 1 failed (undone), 2 no nginx
w2_nginx_apply() {
    local http_text="$1" server_text="$2" trig="$3" only="$4"
    local snipdir sh ss f tmp n changed=0 already files=() hdr
    have nginx || return 2
    snipdir="${NGINX_SNIPPET_DIR:-/etc/nginx/snippets}"; sh="${snipdir}/psf-wp2shell-http.conf"; ss="${snipdir}/psf-wp2shell-server.conf"
    hdr='# psf-security-patches: WordPress core wp2shell protective measure (wordpress-wp2shell-check.sh mitigate). Remove with: rollback'
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(w2_nginx_files)
    if [[ ${#files[@]} -eq 0 ]]; then caution "nginx found but no readable configuration file: add the rule by hand (see the README)"; return 1; fi
    if [[ "$W2_DRY" -eq 0 ]]; then
        mkdir -p "$snipdir" || return 1
        if [[ -n "$http_text" ]]; then printf '%s\n%s\n' "$hdr" "$http_text" >"$sh" || return 1; w2_note "file|${sh}"; fi
        printf '%s\n%s\n' "$hdr" "$server_text" >"$ss" || return 1
        w2_note "file|${ss}"
    else
        if [[ -n "$http_text" ]]; then echo "  would write ${sh}:"; printf '%s\n' "$http_text" | sed 's/^/      /'; fi
        echo "  would write ${ss}:"; printf '%s\n' "$server_text" | sed 's/^/      /'
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/psfng.XXXXXX")" || return 1
    PSF_TMP+=("$tmp")
    for f in "${files[@]}"; do
        if [[ -n "$http_text" ]]; then
            already=0; grep -qF "$sh" "$f" && already=1
            awk -v snip="$sh" -v already="$already" "$W2_AWK_HTTP" "$f" >"$tmp" || continue
            if ! cmp -s "$f" "$tmp"; then
                if [[ "$W2_DRY" -eq 1 ]]; then echo "  would add the http include to ${f}"
                elif w2_backup "$f" && cat "$tmp" >"$f"; then ok "nginx: added the http-level include to ${f}"; changed=1; fi
            fi
        fi
        awk -v snip="$ss" -v trig="$trig" -v only="$only" "$W2_AWK_SERVER" "$f" >"$tmp" || continue
        if ! cmp -s "$f" "$tmp"; then
            n=$(diff "$f" "$tmp" | grep -c '^>')
            if [[ "$W2_DRY" -eq 1 ]]; then echo "  would add the include to ${n} server block(s) in ${f}"
            elif w2_backup "$f" && cat "$tmp" >"$f"; then ok "nginx: added the include to ${n} server block(s) in ${f}"; changed=1; fi
        fi
    done
    rm -f "$tmp"
    if [[ "$W2_DRY" -eq 1 ]]; then echo "  would run: nginx -t"; return 0; fi
    [[ $changed -eq 1 ]] || inf "nginx: no matching server block needed the include"
    if w2_nginx_test; then ok "nginx: nginx -t accepts the new configuration"; return 0; fi
    bad "nginx: nginx -t REJECTS the new configuration: restoring the originals now"
    w2_restore_all; rm -f "$sh" "$ss"; : >"$W2_MANIFEST"; return 1
}
w2_reload() {
    [[ "${W2_RELOAD:-0}" -eq 1 ]] || return 0
    local u did=0
    for u in "$@"; do
        if have systemctl && grep -q "^${u}" <<<"$(systemctl list-unit-files 2>/dev/null)"; then w2_run systemctl reload "$u" && inf "reloaded ${u} (graceful)"; did=1; fi
    done
    [[ $did -eq 1 ]] || caution "--reload given but no matching systemd unit found: reload the web server yourself"
}
w2_rollback_core() {   # shared rollback loop
    local line f b kind rc=0 name enabled
    while IFS= read -r line; do
        kind="${line%%|*}"
        case "$kind" in
            conf) f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
                  if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
                  if [[ $W2_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi ;;
            a2conf) name="${line#a2conf|}"; enabled="${name#*|}"; name="${name%%|*}"
                  if [[ $W2_DRY -eq 1 ]]; then echo "  would disable ${name}"; else { have a2disconf && a2disconf "$name" >/dev/null 2>&1; rm -f "${enabled}/${name}.conf"; } || true; ok "disabled ${name}"; fi ;;
            file) f="${line#file|}"
                  if [[ $W2_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
        esac
    done <"$W2_MANIFEST"
    return $rc
}

w2_apache_ctl() { local c; for c in apache2ctl apachectl httpd; do have "$c" && { echo "$c"; return 0; }; done; return 1; }
w2_apache_text() {
    printf '%s\n' '# psf-security-patches: WordPress core wp2shell protective measure (wordpress-wp2shell-check.sh mitigate). Remove with: rollback' \
        '<LocationMatch "(?i)/wp-json/batch">' '    Require all denied' '</LocationMatch>' \
        '<If "%{QUERY_STRING} =~ m#rest_route=(%2F|/)batch#i">' '    Require all denied' '</If>'
}
w2_apache_apply() {   # -> 0 ok, 1 failed (undone), 2 no apache
    local ctl avail enabled confd target name=psf-wp2shell-batch-block
    ctl="$(w2_apache_ctl)" || return 2
    avail="${APACHE_CONF_AVAILABLE:-/etc/apache2/conf-available}"; enabled="${APACHE_CONF_ENABLED:-/etc/apache2/conf-enabled}"; confd="${APACHE_CONFD:-/etc/httpd/conf.d}"
    if [[ -d "$avail" ]]; then target="${avail}/${name}.conf"
    elif [[ -d "$confd" ]]; then target="${confd}/${name}.conf"
    else caution "Apache found but neither ${avail} nor ${confd} exists: add the rule by hand (see the README)"; return 1; fi
    if [[ "$W2_DRY" -eq 1 ]]; then
        echo "  would write ${target}:"; w2_apache_text | sed 's/^/      /'
        [[ "$target" == "${avail}/"* ]] && echo "  would run: a2enconf ${name}"
        echo "  would run: ${ctl} configtest"; return 0
    fi
    w2_apache_text >"$target" || return 1
    w2_note "file|${target}"
    if [[ "$target" == "${avail}/"* ]]; then
        if have a2enconf; then a2enconf "$name" >/dev/null 2>&1 || true
        else mkdir -p "$enabled" && ln -sf "$target" "${enabled}/${name}.conf"; fi
        w2_note "a2conf|${name}|${enabled}"
    fi
    if "$ctl" configtest >/dev/null 2>&1; then ok "Apache: ${target} written and ${ctl} configtest accepts it"; return 0; fi
    bad "Apache: configtest REJECTS the new rule: removing it"
    have a2disconf && a2disconf "$name" >/dev/null 2>&1 || true
    rm -f "${enabled}/${name}.conf" "$target"; return 1
}

cmd_mitigate() {
    local web=auto force=0 rc=0 r any_web=0 only=""
    local -a dirs=() reload_units=()
    W2_DRY=0; W2_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) W2_DRY=1 ;; --reload) W2_RELOAD=1 ;; --force) force=1 ;;
            --web) shift; web="${1:-}"; case "$web" in auto|apache|nginx) ;; *) die "--web needs auto, apache or nginx" ;; esac ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            --server-name) shift; [[ -n "${1:-}" ]] || die "--server-name needs a name"; only="$1" ;;
            *) die "Unknown mitigate option: $1 (--web --dir --server-name --dry-run --reload --force)" ;;
        esac
        shift
    done
    [[ $W2_DRY -eq 1 ]] || need_root "mitigate changes the host"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress)
    step "Is there an exposed WordPress?"
    if cmd_check "${dirs[@]}" >/dev/null 2>&1; then
        if [[ $force -eq 0 ]]; then info "No exposed WordPress found: nothing to do (use --force to apply the rule anyway)"; return 0; fi
        caution "no exposed WordPress found, applying anyway because of --force"
    else bad "an exposed WordPress was found: refusing the batch route at the web server"; fi
    if [[ $W2_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        W2_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$W2_MANIFEST"
    else W2_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    caution "the block editor uses the batch route for some saves: editing may be affected until you update. The block applies to EVERY PHP virtual host on the machine and also refuses any other site's /wp-json/batch"
    step "Web server rule"
    if [[ "$web" == auto || "$web" == apache ]]; then
        w2_apache_apply; r=$?
        case $r in 0) any_web=1; reload_units+=(apache2 httpd) ;; 1) rc=1 ;; 2) [[ "$web" == apache ]] && { caution "no Apache found"; rc=1; } ;; esac
    fi
    if [[ "$web" == auto || "$web" == nginx ]]; then
        w2_nginx_apply "" 'location ~* "/wp-json/batch" { return 403; }
if ($args ~* "rest_route=(%2F|/)batch") { return 403; }' 'fastcgi_pass|fastcgi_param|[.]php' "$only"; r=$?
        case $r in 0) any_web=1; reload_units+=(nginx) ;; 1) rc=1 ;; 2) [[ "$web" == nginx ]] && { caution "no nginx found"; rc=1; } ;; esac
    fi
    if [[ $any_web -eq 0 && $rc -eq 0 ]]; then caution "no Apache or nginx found: add the rule by hand (see the README)"; rc=1; fi
    [[ $any_web -eq 1 && $W2_DRY -eq 0 ]] && w2_reload "${reload_units[@]}"
    step "Result"
    if [[ $W2_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $any_web -eq 1 ]]; then
        info "/wp-json/batch and ?rest_route=/batch now answer 403. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $W2_RELOAD -eq 1 ]] || inf "reload the web server for it to take effect (or re-run with --reload)"
    fi
    inf "This closes the chain's entry point (CVE-2026-63030); it does not fix the SQL injection (CVE-2026-60137). Update core: wp core update."
    return "$rc"
}

cmd_rollback() {
    local rc=0
    W2_DRY=0; W2_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) W2_DRY=1 ;; --reload) W2_RELOAD=1 ;; *) die "Unknown rollback option: $1 (--dry-run --reload)" ;; esac
        shift
    done
    W2_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$W2_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $W2_DRY -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    w2_rollback_core || rc=1
    if [[ $W2_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$W2_MANIFEST" "${W2_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload the web server for it to take effect."
    fi
    w2_reload apache2 httpd nginx
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-63030 and CVE-2026-60137 (wp2shell); fixed in WordPress 6.8.6, 6.9.5 and 7.0.2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
# ---------- one change at a time ---------------------------------------------------------------------
# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a dry run
# (a * in CMDS stands for the default command, for a tool whose default changes the host),
# run the script again under flock(1), so two runs cannot interleave their changes. The second run waits
# PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. flock -o leaves the lock with the waiting
# flock process, so a service this script starts does not inherit it and hold it. The lock file is
# STATE_DIR/.lock, or /var/lib/psf-security-patches/<script>/.lock. Without flock (macOS) nothing is locked.
# PSF_LOCK_HELD marks the re-run so it does not lock again: the script sets it, leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_words=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
        case "$lk_arg" in -*) ;; *) lk_words=$((lk_words + 1)) ;; esac
    done
    [[ $lk_words -eq 0 && "$lk_cmds" == *" * "* ]] && lk_hit=1      # no command named, and the default command changes the host
    [[ $lk_hit -eq 1 ]] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "mitigate rollback" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
