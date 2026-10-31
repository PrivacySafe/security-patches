#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Laravel TokenGuard authentication bypass: read-only checker  (v1)
# CVE-2026-114509 (GHSA-f9x3-7vq9-cph6)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Laravel's built-in token guard ('driver' => 'token') does not reject a
# crafted non-string credential, such as a JSON body {"api_token": [0]}. On
# MySQL and MariaDB the lookup can then match an unintended existing user, so an
# unauthenticated attacker can sign in as that user on any route protected by
# the token guard. CVSS 9.2 (v4.0). Reported by Hristijan Manasijev.
#
# Fixed in laravel/framework 12.68.0 and 13.29.0, both released 25 August 2026,
# two months before the advisory was published on 19 October 2026. The 11.x
# branch carries the same is_string() check from v11.56.1. 10.x and 9.x apps upgrade to a fixed branch. Apps that use
# Laravel Sanctum or Laravel Passport register their own guard drivers and are
# not the target of this bug.
#
# This script is read-only. It looks at composer.lock and the installed
# vendor/ copy, at config/auth.php for a guard with the token driver, at routes
# that use that guard, and at the database driver in .env.
#
# Usage:
#   ./laravel-tokenguard-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /home /opt) for Laravel
#                    projects. Exit 0 = nothing exposed, 1 = an affected
#                    project looks exposed or is on a branch that needs an upgrade.
#   middleware       print a protective PHP middleware that rejects non-string
#                    api_token values. It prints to stdout only.
#   version          print the script version.
#
# The protective middleware is for apps that cannot upgrade today. 9.x and 10.x apps should plan an upgrade.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="laravel-tokenguard-check.sh"
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

# ---------- version rules ----------------------------------------------------
# prints "fixed", "vulnerable" or "unfixed" (vulnerable, no upstream fix)
laravel_status() {
    local v raw="${1#v}"; v="$(norm_ver "$1")"
    # norm_ver drops a pre-release suffix, so 12.68.0-RC1 would read as 12.68.0. A pre-release of a
    # fixed release comes BEFORE it and does not have the fix.
    if [[ "$raw" == *-* ]] && [[ "$v" == 13.29.0 || "$v" == 12.68.0 || "$v" == 11.56.1 ]]; then echo vulnerable; return; fi
    case "${v%%.*}" in
        13) ver_lt "$v" "13.29.0" && echo vulnerable || echo fixed ;;
        12) ver_lt "$v" "12.68.0" && echo vulnerable || echo fixed ;;
        11) ver_lt "$v" "11.56.1" && echo vulnerable || echo fixed ;;
        ''|*[!0-9]*) echo unknown ;;
        *)  if (( ${v%%.*} > 13 )); then echo fixed; else echo unfixed; fi ;;
    esac
}

lock_pkg_version() {   # composer.lock package -> version
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

installed_version() {  # project dir -> version of vendor/laravel/framework
    local app="$1/vendor/laravel/framework/src/Illuminate/Foundation/Application.php"
    [[ -r "$app" ]] && sed -n "s/.*const VERSION = '\([^']*\)'.*/\1/p" "$app" | head -n1
    return 0
}

token_guards() {       # config/auth.php -> names of guards that use the token driver
    local auth="$1" ln name
    while IFS=: read -r ln _; do
        [[ -n "$ln" ]] || continue
        name="$(sed -n "$(( ln > 6 ? ln-6 : 1 )),${ln}p" "$auth" \
                | grep -E "=>[[:space:]]*\\[" | tail -n1 \
                | sed -E "s/^[[:space:]]*['\"]([A-Za-z0-9_-]+)['\"].*/\\1/")"
        [[ -n "$name" ]] && echo "$name"
    done < <(grep -nE "['\"]driver['\"][[:space:]]*=>[[:space:]]*['\"]token['\"]" "$auth")
    return 0
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
#   L <path> <text>   write one short sanitized line of text (used so .env itself is never copied)
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
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != */../* && "$p" != */.. ]] || continue   # no ".." path component
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

LARAVEL_PROBE="$(cat <<'EOS'
R="/var/www /srv /home /opt"
find $R -maxdepth 7 \( -name node_modules -o -name vendor \) -prune -o -name composer.lock -type f -print 2>/dev/null | head -n 30 | while read -r l; do
  grep -q "\"name\": \"laravel/framework\"" "$l" 2>/dev/null || continue
  d=${l%/*}
  echo "F $l"
  f=vendor/laravel/framework/src/Illuminate/Foundation/Application.php
  [ -f "$d/$f" ] && echo "F $d/$f"
  [ -f "$d/config/auth.php" ] && echo "F $d/config/auth.php"
  for b in routes app bootstrap; do [ -d "$d/$b" ] && echo "D $d/$b"; done
  find "$d/routes" "$d/app" "$d/bootstrap" -type f -name "*.php" 2>/dev/null | head -n 3000 | xargs -r grep -lIE "auth:[A-Za-z0-9_-]|Auth::guard\(" 2>/dev/null | head -n 50 | while read -r f; do echo "F $f"; done
  if [ -f "$d/.env" ]; then
    v=$(grep -E "^DB_CONNECTION=" "$d/.env" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d "\"'")
    [ -n "$v" ] && echo "L $d/.env DB_CONNECTION=$v"
  fi
done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$LARAVEL_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() locks=()
    local rc=0 found=0 lock dir lv iv ver st auth guards g routes db
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt); fi
    local -a existing=()
    for dir in "${dirs[@]}"; do [[ -d "$dir" ]] && existing+=("$dir"); done
    step "Looking for Laravel projects"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r lock; do [[ -n "$lock" ]] && locks+=("$lock"); done < <(
        find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name vendor \) -prune \
             -o -name composer.lock -type f -print 2>/dev/null)
    for lock in "${locks[@]}"; do
        lv="$(lock_pkg_version "$lock" laravel/framework)"
        dir="$(dirname "$lock")"
        iv="$(installed_version "$dir")"
        [[ -z "$lv" && -z "$iv" ]] && continue
        found=$((found+1))
        ver="${iv:-$lv}"
        step "Laravel ${ver} in ${dir}"
        [[ -n "$lv" && -n "$iv" && "$(norm_ver "$lv")" != "$(norm_ver "$iv")" ]] \
            && inf "composer.lock says ${lv}, vendor/ has ${iv}; using the installed copy"
        st="$(laravel_status "$ver")"
        case "$st" in
            fixed)      ok "laravel/framework ${ver} has the TokenGuard fix"; continue ;;
            unknown)    caution "could not parse version '${ver}'"; continue ;;
            vulnerable) bad "laravel/framework ${ver} is affected by CVE-2026-114509 (fixed in 12.68.0 / 13.29.0, 11.x from 11.56.1)" ;;
            unfixed)    bad "laravel/framework ${ver} is affected by CVE-2026-114509: upgrade to 12.68.0, 13.29.0 or, on 11.x, 11.56.1 or later" ;;
        esac
        auth="${dir}/config/auth.php"
        guards=""
        [[ -r "$auth" ]] && guards="$(token_guards "$auth")"
        db="$(grep -E '^DB_CONNECTION=' "${dir}/.env" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
        [[ -n "$db" ]] && inf "DB_CONNECTION=${db}" || inf "DB_CONNECTION not set in .env"
        if [[ -z "$guards" ]]; then
            if [[ -r "$auth" ]]; then
                ok "no guard in config/auth.php uses the token driver: the TokenGuard path is not in use"
                caution "version is still affected; custom code could build a TokenGuard directly, so upgrade"
            else
                caution "config/auth.php not readable: cannot tell whether the token driver is in use, treating as exposed"
                rc=1
            fi
            continue
        fi
        local exposed=0
        for g in $guards; do
            routes="$(grep -rIlE "auth:${g}([^A-Za-z0-9_]|\$)|Auth::guard\(['\"]${g}['\"]\)" \
                       "${dir}/routes" "${dir}/app" "${dir}/bootstrap" 2>/dev/null | head -n3 | tr '\n' ' ')"
            if [[ -n "$routes" ]]; then
                bad "guard '${g}' uses the token driver and is referenced in: ${routes}"; exposed=1
            else
                caution "guard '${g}' uses the token driver but no route or code references it"
            fi
        done
        case "$db" in
            mysql|mariadb) [[ $exposed -eq 1 ]] && bad "database driver is ${db}: the reported bypass applies" ;;
            '')            [[ $exposed -eq 1 ]] && caution "database driver unknown: the advisory limits the bypass to MySQL and MariaDB" ;;
            *)             [[ $exposed -eq 1 ]] && caution "database driver is ${db}: the advisory describes the bypass on MySQL and MariaDB, still upgrade" ;;
        esac
        if [[ $exposed -eq 1 && "$db" != "sqlite" && "$db" != "pgsql" && "$db" != "sqlsrv" ]]; then rc=1
        elif [[ "$st" == "unfixed" ]]; then rc=1
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Laravel project found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Laravel project found (${found} checked)"
    else
        warn "Exposed Laravel found. Run: composer update laravel/framework  (12.68.0+ or 13.29.0+)"
        inf "Cannot upgrade today? Run: $0 middleware  and register the output as global middleware that runs before authentication."
        inf "Longer term, move API auth to Sanctum or Passport and drop the token driver."
        inf "Advisory: GHSA-f9x3-7vq9-cph6 (published 19 October 2026)"
    fi
    return "$rc"
}

cmd_middleware() {
    cat <<'PHP'
<?php
// RejectNonStringApiToken: protection for CVE-2026-114509 (Laravel TokenGuard).
// Save as app/Http/Middleware/RejectNonStringApiToken.php and register it as
// GLOBAL middleware that runs before authentication:
//   Laravel 11 and newer, in bootstrap/app.php:
//     ->withMiddleware(function (Middleware $middleware) {
//         $middleware->prepend(\App\Http\Middleware\RejectNonStringApiToken::class);
//     })
//   Laravel 10 and older, first entry of $middleware in app/Http/Kernel.php.
// Upgrading laravel/framework is the real fix. This only blocks the crafted input.

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RejectNonStringApiToken
{
    public function handle(Request $request, Closure $next)
    {
        $candidates = [
            $request->query('api_token'),
            $request->request->get('api_token'),
            $request->isJson() ? $request->json('api_token') : null,
        ];
        foreach ($candidates as $value) {
            if ($value !== null && !is_string($value)) {
                abort(401, 'Unauthenticated.');
            }
        }
        return $next($request);
    }
}
PHP
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    if [[ "$CMD" == "middleware" ]]; then cmd_middleware; exit 0; fi
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114509; fixed in laravel/framework 12.68.0 and 13.29.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|middleware|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
