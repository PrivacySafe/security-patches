#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Joomla core, September 2026 security release (16 issues): checker with mitigation  (v1)
# CVE-2026-90915 and CVE-2026-92222 (High), CVE-2026-92227 (MFA bypass) and others
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Joomla 5.4.9 and 6.1.4, released 29 September 2026, fix 16 core security issues
# (CVE-2026-90906 to CVE-2026-92232). The Joomla Security Strike Team rates two High:
#
#   CVE-2026-90915  Arbitrary directory deletion. The cache purge action (System, Clear
#                   Cache) did not confine the cache group name, so a path traversal in
#                   the file-based cache could delete any directory the web server can
#                   write to. Affects 4.0.0 to 5.4.8 and 6.0.0 to 6.1.3.
#   CVE-2026-92222  Server-side request forgery through URL fields (feed and request URLs)
#                   in several core extensions. Affects 3.0.0 and later; needs a Manager
#                   account or above.
#
# Others in the same release, as named in the advisories: CVE-2026-92227 (a multi-factor
# authentication bypass through remember-me cookies issued too early; needs the password
# first), CVE-2026-90916 (improper access checks in the content history comparison view),
# cross-site scripting in HTMLHelper::link and the link toolbar (CVE-2026-90906,
# CVE-2026-92224), tagged items (CVE-2026-90917) and two InputFilter bypasses
# (CVE-2026-92231, CVE-2026-92232), and access-control fixes in the Joomla API
# (CVE-2026-90913, CVE-2026-92226).
#
#   Affected: Joomla 6.0.0 to 6.1.3, and 4.0.0 to 5.4.8 (the SSRF flaw reaches back to
#             3.0.0, one XSS flaw to 1.5.0).
#   Fixed:    5.4.9 and 6.1.4. Sites on 3.x or 4.x or on 5.0 to 5.3 are past
#             security support, so the fix is to move to 5.4.9 or later in 5.x, or to
#             6.1.4 or later.
#
# How this script reads an install. Version.php holds the version as constants
# (MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION). It also reads one file the fix changed,
# libraries/src/Cache/Storage/FileStorage.php: the cache-purge fix adds
# Path::check($dir, $this->_root). That single signature confirms the High cache flaw and
# catches a partial update; the other fifteen fixes are judged by the version.
#
# "check" is read-only; "mitigate" and "rollback" are the only commands that change anything.
#
# Usage:
#   ./joomla-check.sh [command] [DIR ...]
#   check (default)  find Joomla by libraries/src/Version.php (default /var/www /srv /home
#                    /opt /usr/share). Exit 0 = nothing exposed, 1 = exposed or unclear.
#   mitigate --allow LIST [options]   (root) changes the host. PrivacySafe protection:
#                    restricts /administrator to the
#                    addresses or CIDRs in LIST (comma separated) plus loopback; every
#                    other address gets a 403. Only when an exposed Joomla is found
#                    (--force overrides). --allow is mandatory, because without it
#                    everyone would be locked out. Options:
#                      --web auto|apache|nginx  which web server (default auto: every one found)
#                      --dir DIR                where to look for Joomla (repeat)
#                      --server-name NAME       nginx: only the server block that lists NAME
#                      --dry-run                show the changes, change nothing
#                      --reload                 graceful reload afterwards (systemd)
#                      --force                  apply even if no exposed Joomla is found
#                    Apache: psf-joomla-admin-allow.conf with "Require ip", checked with a
#                    configtest. nginx: a geo and map block included right after "http {",
#                    and an include as the first line of every PHP-serving server block,
#                    checked with nginx -t. If the web server rejects the result everything
#                    is undone at once. A proxy or CDN in front hides client addresses:
#                    the rule then sees only the proxy. Keep a second way in.
#   rollback [--dry-run] [--reload]   remove what mitigate added and restore the files it edited.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="joomla-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/joomla}"

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
# ---------- reading an install -----------------------------------------------
jm_const() {   # root NAME -> the number in "const NAME = 5;"
    sed -nE "s/^[[:space:]]*(public[[:space:]]+)?const[[:space:]]+$2[[:space:]]*=[[:space:]]*([0-9]+);.*/\\2/p" "$1/libraries/src/Version.php" 2>/dev/null | head -n1
}
# prints: fixed | affected | eol
#   eol = a branch with no fixed release (3.x, 4.x, and 5.0 to 5.3): move to 5.4.9+ or 6.1.4+
joomla_status() {
    local maj="$1" min="$2" pat="$3" v="$1.$2.$3"
    (( maj >= 7 )) && { echo fixed; return; }
    if (( maj == 6 )); then ver_lt "$v" 6.1.4 && echo affected || echo fixed; return; fi
    if (( maj == 5 )); then
        (( min < 4 )) && { echo eol; return; }
        ver_lt "$v" 5.4.9 && echo affected || echo fixed; return
    fi
    echo eol
}
cache_fix_in_source() {
    local f="$1/libraries/src/Cache/Storage/FileStorage.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F -- 'Path::check($dir, $this->_root)' "$f" >/dev/null; then echo yes; else echo no; fi
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

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'libraries/src/Version.php' 'libraries/src/Cache/Storage/FileStorage.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt /usr/share; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() roots=()
    local rc=0 found=0 d f root maj min pat ver st sig
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Joomla"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do roots+=("$(dirname "$(dirname "$(dirname "$f")")")"); done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/libraries/src/Version.php' -type f 2>/dev/null | sort -u)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        found=$((found+1))
        maj="$(jm_const "$root" MAJOR_VERSION)"; min="$(jm_const "$root" MINOR_VERSION)"; pat="$(jm_const "$root" PATCH_VERSION)"
        step "Joomla ${maj:-?}.${min:-?}.${pat:-?} at ${root}"
        if [[ -z "$maj" || -z "$min" || -z "$pat" ]]; then caution "could not read the version constants from libraries/src/Version.php"; rc=1; continue; fi
        ver="${maj}.${min}.${pat}"; st="$(joomla_status "$maj" "$min" "$pat")"; sig="$(cache_fix_in_source "$root")"
        case "$st" in
            fixed)
                if [[ "$sig" == no ]]; then caution "Joomla ${ver} is a fixed release, but FileStorage.php still lacks the cache-purge fix (CVE-2026-90915): the files do not match the version (a partial or failed update)"; rc=1
                else ok "Joomla ${ver} has the September 2026 fixes"; fi ;;
            affected)
                bad "Joomla ${ver} is below the fixed release of its branch: it has the 16 core issues of the September 2026 release, including CVE-2026-90915 (arbitrary directory deletion) and CVE-2026-92222 (SSRF). Update to $([[ $maj -eq 6 ]] && echo 6.1.4 || echo 5.4.9) or later"
                [[ "$sig" == yes ]] && inf "FileStorage.php already carries the cache-purge fix, so this looks like a partial update or a manual patch: the other fixes are still missing"
                rc=1 ;;
            eol)
                bad "Joomla ${ver} is on a branch past security support (3.x, 4.x and 5.0 to 5.3) and has these flaws. Move to 5.4.9 or later, or 6.1.4 or later"
                rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then info "No Joomla found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then info "No exposed Joomla found (${found} checked)."
    else
        warn "Exposed Joomla found. Update from the Joomla administrator (System, Update, Joomla) or with the update package."
        inf "Until then (the project's suggestion, not Joomla's): most of these need a logged-in account, so limit who holds Manager or higher and restrict the administrator path by address"
        inf "Advisories: https://developer.joomla.org/security-centre.html"
    fi
    return "$rc"
}


# ---------- mitigate and rollback --------------------------------------------
JM_MANIFEST=""; JM_DRY=0
jm_run() { if [[ "$JM_DRY" -eq 1 ]]; then echo "  would run: $*"; return 0; fi; "$@"; }
jm_note() { [[ "$JM_DRY" -eq 1 ]] || echo "$1" >>"$JM_MANIFEST"; }
jm_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$JM_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$JM_MANIFEST"
}
jm_restore_all() {
    local line f
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f"
    done <"$JM_MANIFEST"
}
jm_nginx_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    { nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p'
      echo /etc/nginx/nginx.conf; ls /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done | awk '!s[$0]++'
}
read -r -d '' JM_AWK_SERVER <<'AWKEOF'
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
read -r -d '' JM_AWK_HTTP <<'AWKEOF'
{
    print $0
    if (!done && $0 !~ /^[ \t]*#/ && $0 ~ /^[ \t]*http[ \t]*\{/) {
        if (!already) print "    include " snip ";"
        done = 1
    }
}
AWKEOF
jm_nginx_test() {
    if [[ -n "${NGINX_MAIN_CONF:-}" ]]; then nginx -t -c "$NGINX_MAIN_CONF" >/dev/null 2>&1; else nginx -t >/dev/null 2>&1; fi
}
# jm_nginx_apply HTTP_TEXT SERVER_TEXT TRIGGER_REGEX ONLY_SERVER_NAME -> 0 ok, 1 failed (undone), 2 no nginx
jm_nginx_apply() {
    local http_text="$1" server_text="$2" trig="$3" only="$4"
    local snipdir sh ss f tmp n changed=0 already files=() hdr
    have nginx || return 2
    snipdir="${NGINX_SNIPPET_DIR:-/etc/nginx/snippets}"; sh="${snipdir}/psf-joomla-admin-http.conf"; ss="${snipdir}/psf-joomla-admin-server.conf"
    hdr='# psf-security-patches: Joomla core protective measure (joomla-check.sh mitigate). Remove with: rollback'
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(jm_nginx_files)
    if [[ ${#files[@]} -eq 0 ]]; then caution "nginx found but no readable configuration file: add the rule by hand (see the README)"; return 1; fi
    if [[ "$JM_DRY" -eq 0 ]]; then
        mkdir -p "$snipdir" || return 1
        printf '%s\n%s\n' "$hdr" "$http_text" >"$sh" || return 1
        printf '%s\n%s\n' "$hdr" "$server_text" >"$ss" || return 1
        jm_note "file|${sh}"; jm_note "file|${ss}"
    else
        echo "  would write ${sh}:"; printf '%s\n' "$http_text" | sed 's/^/      /'
        echo "  would write ${ss}:"; printf '%s\n' "$server_text" | sed 's/^/      /'
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/psfng.XXXXXX")" || return 1
    for f in "${files[@]}"; do
        already=0; grep -qF "$sh" "$f" && already=1
        awk -v snip="$sh" -v already="$already" "$JM_AWK_HTTP" "$f" >"$tmp" || continue
        if ! cmp -s "$f" "$tmp"; then
            if [[ "$JM_DRY" -eq 1 ]]; then echo "  would add the http include to ${f}"
            elif jm_backup "$f" && cat "$tmp" >"$f"; then ok "nginx: added the http-level include to ${f}"; changed=1; fi
        fi
        awk -v snip="$ss" -v trig="$trig" -v only="$only" "$JM_AWK_SERVER" "$f" >"$tmp" || continue
        if ! cmp -s "$f" "$tmp"; then
            n=$(diff "$f" "$tmp" | grep -c '^>')
            if [[ "$JM_DRY" -eq 1 ]]; then echo "  would add the include to ${n} server block(s) in ${f}"
            elif jm_backup "$f" && cat "$tmp" >"$f"; then ok "nginx: added the include to ${n} server block(s) in ${f}"; changed=1; fi
        fi
    done
    rm -f "$tmp"
    if [[ "$JM_DRY" -eq 1 ]]; then echo "  would run: nginx -t"; return 0; fi
    [[ $changed -eq 1 ]] || inf "nginx: no matching server block needed the include"
    if jm_nginx_test; then ok "nginx: nginx -t accepts the new configuration"; return 0; fi
    bad "nginx: nginx -t REJECTS the new configuration: restoring the originals now"
    jm_restore_all; rm -f "$sh" "$ss"; : >"$JM_MANIFEST"; return 1
}
jm_reload() {
    [[ "${JM_RELOAD:-0}" -eq 1 ]] || return 0
    local u did=0
    for u in "$@"; do
        if have systemctl && grep -q "^${u}" <<<"$(systemctl list-unit-files 2>/dev/null)"; then jm_run systemctl reload "$u" && inf "reloaded ${u} (graceful)"; did=1; fi
    done
    [[ $did -eq 1 ]] || caution "--reload given but no matching systemd unit found: reload the web server yourself"
}
jm_rollback_core() {   # shared rollback loop
    local line f b kind rc=0 name enabled
    while IFS= read -r line; do
        kind="${line%%|*}"
        case "$kind" in
            conf) f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
                  if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
                  if [[ $JM_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi ;;
            a2conf) name="${line#a2conf|}"; enabled="${name#*|}"; name="${name%%|*}"
                  if [[ $JM_DRY -eq 1 ]]; then echo "  would disable ${name}"; else { have a2disconf && a2disconf "$name" >/dev/null 2>&1; rm -f "${enabled}/${name}.conf"; } || true; ok "disabled ${name}"; fi ;;
            file) f="${line#file|}"
                  if [[ $JM_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
        esac
    done <"$JM_MANIFEST"
    return $rc
}

jm_valid_cidr() {
    local c="$1"
    [[ "$c" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] && return 0
    [[ "$c" == *:* && "$c" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] && return 0
    return 1
}
jm_apache_ctl() { local c; for c in apache2ctl apachectl httpd; do have "$c" && { echo "$c"; return 0; }; done; return 1; }
jm_apache_text() {   # CIDR list (space separated)
    printf '%s\n' '# psf-security-patches: Joomla core protective measure (joomla-check.sh mitigate). Remove with: rollback' \
        '<LocationMatch "(?i)^/administrator(/|$)">' "    Require ip 127.0.0.1 ::1 ${1}" '</LocationMatch>'
}
jm_apache_apply() {   # CIDRs -> 0 ok, 1 failed (undone), 2 no apache
    local ctl avail enabled confd target name=psf-joomla-admin-allow
    ctl="$(jm_apache_ctl)" || return 2
    avail="${APACHE_CONF_AVAILABLE:-/etc/apache2/conf-available}"; enabled="${APACHE_CONF_ENABLED:-/etc/apache2/conf-enabled}"; confd="${APACHE_CONFD:-/etc/httpd/conf.d}"
    if [[ -d "$avail" ]]; then target="${avail}/${name}.conf"
    elif [[ -d "$confd" ]]; then target="${confd}/${name}.conf"
    else caution "Apache found but neither ${avail} nor ${confd} exists: add the rule by hand (see the README)"; return 1; fi
    if [[ "$JM_DRY" -eq 1 ]]; then
        echo "  would write ${target}:"; jm_apache_text "$1" | sed 's/^/      /'
        [[ "$target" == "${avail}/"* ]] && echo "  would run: a2enconf ${name}"
        echo "  would run: ${ctl} configtest"; return 0
    fi
    jm_apache_text "$1" >"$target" || return 1
    jm_note "file|${target}"
    if [[ "$target" == "${avail}/"* ]]; then
        if have a2enconf; then a2enconf "$name" >/dev/null 2>&1 || true
        else mkdir -p "$enabled" && ln -sf "$target" "${enabled}/${name}.conf"; fi
        jm_note "a2conf|${name}|${enabled}"
    fi
    if "$ctl" configtest >/dev/null 2>&1; then ok "Apache: ${target} written and ${ctl} configtest accepts it"; return 0; fi
    bad "Apache: configtest REJECTS the new rule: removing it"
    have a2disconf && a2disconf "$name" >/dev/null 2>&1 || true
    rm -f "${enabled}/${name}.conf" "$target"; return 1
}

cmd_mitigate() {
    local web=auto force=0 rc=0 allow="" c r any_web=0 only="" geo=""
    local -a dirs=() cidrs=() reload_units=()
    JM_DRY=0; JM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) JM_DRY=1 ;; --reload) JM_RELOAD=1 ;; --force) force=1 ;;
            --allow) shift; [[ -n "${1:-}" ]] || die "--allow needs a comma separated list of addresses or CIDRs"; allow="$1" ;;
            --web) shift; web="${1:-}"; case "$web" in auto|apache|nginx) ;; *) die "--web needs auto, apache or nginx" ;; esac ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            --server-name) shift; [[ -n "${1:-}" ]] || die "--server-name needs a name"; only="$1" ;;
            *) die "Unknown mitigate option: $1 (--allow LIST --web --dir --server-name --dry-run --reload --force)" ;;
        esac
        shift
    done
    [[ -n "$allow" ]] || die "mitigate needs --allow LIST: the addresses or CIDRs that may still reach /administrator. Without it everyone would be locked out. Nothing was changed."
    for c in ${allow//,/ }; do jm_valid_cidr "$c" || die "not an address or CIDR: ${c}"; cidrs+=("$c"); done
    [[ $JM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "mitigate changes the host: run it as root, or add --dry-run to see what it would do"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /home /opt /usr/share)
    step "Is there an affected Joomla?"
    if cmd_check "${dirs[@]}" >/dev/null 2>&1; then
        if [[ $force -eq 0 ]]; then info "No exposed Joomla found: nothing to do (use --force to apply the rule anyway)"; return 0; fi
        caution "no exposed Joomla found, applying anyway because of --force"
    else bad "an exposed Joomla was found: restricting /administrator to ${allow} (and loopback)"; fi
    if [[ $JM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        JM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$JM_MANIFEST"
    else JM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    caution "if a proxy or CDN sits in front of this server, the address it sees is the proxy's: check that real client addresses reach the web server before relying on this rule, and keep a way in (a second session, console access)"
    step "Web server rule"
    if [[ "$web" == auto || "$web" == apache ]]; then
        jm_apache_apply "${cidrs[*]}"; r=$?
        case $r in 0) any_web=1; reload_units+=(apache2 httpd) ;; 1) rc=1 ;; 2) [[ "$web" == apache ]] && { caution "no Apache found"; rc=1; } ;; esac
    fi
    if [[ "$web" == auto || "$web" == nginx ]]; then
        geo=$'geo $psf_admin_ok {\n    default 0;\n    127.0.0.1 1;\n    ::1 1;'
        for c in "${cidrs[@]}"; do geo+=$'\n'"    ${c} 1;"; done
        geo+=$'\n}\nmap "$psf_admin_ok:$uri" $psf_admin_denied {\n    default 0;\n    "~*^0:/administrator(/|$)" 1;\n}'
        jm_nginx_apply "$geo" 'if ($psf_admin_denied) { return 403; }' 'fastcgi_pass|fastcgi_param|[.]php' "$only"; r=$?
        case $r in 0) any_web=1; reload_units+=(nginx) ;; 1) rc=1 ;; 2) [[ "$web" == nginx ]] && { caution "no nginx found"; rc=1; } ;; esac
    fi
    if [[ $any_web -eq 0 && $rc -eq 0 ]]; then caution "no Apache or nginx found: add the rule by hand (see the README)"; rc=1; fi
    [[ $any_web -eq 1 && $JM_DRY -eq 0 ]] && jm_reload "${reload_units[@]}"
    step "Result"
    if [[ $JM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $any_web -eq 1 ]]; then
        info "/administrator now answers 403 to every address except ${allow} and loopback. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $JM_RELOAD -eq 1 ]] || inf "reload the web server for it to take effect (or re-run with --reload)"
    fi
    inf "This is PrivacySafe's recommendation: it limits who can reach the administrator login. Update to 5.4.9 or 6.1.4 or newer."
    return "$rc"
}

cmd_rollback() {
    local rc=0
    JM_DRY=0; JM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) JM_DRY=1 ;; --reload) JM_RELOAD=1 ;; *) die "Unknown rollback option: $1 (--dry-run --reload)" ;; esac
        shift
    done
    JM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$JM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $JM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "rollback changes the host: run it as root, or add --dry-run"
    step "Rolling back"
    jm_rollback_core || rc=1
    if [[ $JM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$JM_MANIFEST" "${JM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload the web server for it to take effect."
    fi
    jm_reload apache2 httpd nginx
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Joomla 5.4.9 and 6.1.4 security release (CVE-2026-90915, CVE-2026-92222 and others)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
