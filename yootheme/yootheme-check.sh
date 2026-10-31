#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# YOOtheme Pro 5 unauthenticated remote code execution: checker  (v1)
# CVE-2026-102785
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# YOOtheme Pro is a widely used commercial theme and page builder for WordPress
# and Joomla. Its publicly reachable image handler (the route that creates and
# caches resized and cropped images) does not fully bind the normalized image
# operations and the output destination to the request signature. An
# unauthenticated attacker can reuse a signature disclosed in an ordinary public
# image URL, inject extra image operations, traverse out of the intended cache
# directory, and write an attacker-controlled PNG/PHP polyglot file into an
# executable public media directory. That file is then requested to run code.
# CVSS 10.0. Disclosed 21 to 22 October 2026. It is not listed as known
# exploited, but a CVSS 10 pre-authentication flaw with a published
# mechanism should be treated as likely to be exploited quickly.
#
#   Affected: YOOtheme Pro 5.0.0 through 5.0.52
#   Fixed:    5.0.53 (released 21 October 2026)
#   Not affected: YOOtheme Pro 4 and earlier (vendor statement)
#
# Sources disagree slightly: the CVE record is filed against the Joomla extension
# and one aggregator title says "5.0.0-5.0.55". The vendor's own notice, the
# changelog and the CVE description text say 5.0.52 and earlier, fixed in 5.0.53,
# for YOOtheme Pro 5 in general, so this script applies the rule to the WordPress
# theme as well as the Joomla template.
#
# This script is read-only. "check" finds YOOtheme Pro installs and reads their
# version. "hunt" looks for what the attack leaves behind: PHP files inside
# media, upload and cache directories, PHP code inside image files, and web log
# requests that run such files. It sends nothing to your site and exercises no
# part of the flaw.
#
# Usage:
#   ./yootheme-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for YOOtheme.
#                    Exit 0 = nothing affected, 1 = an affected version found.
#   hunt             check, then search for signs of the attack. Exit 0 = nothing
#                    found, 1 = an indicator or an affected version was found.
#   mitigate [options]   (root) changes the host. PrivacySafe protection
#                    documented: refuses PHP files under uploads, media, images and
#                    cache paths with a 403, so a file an attacker managed to write
#                    cannot run. It does NOT stop the write: update to 5.0.53. It
#                    only acts when an affected or unreadable YOOtheme is found
#                    (--force overrides). Options:
#                      --web auto|apache|nginx  which web server (default auto: every
#                                               one found)
#                      --dir DIR                where to look for YOOtheme (repeat;
#                                               default /var/www /srv /opt /home)
#                      --dry-run                show the changes, change nothing
#                      --reload                 graceful reload afterwards (systemd)
#                      --force                  apply even if no affected install is found
#                    Apache: writes psf-yootheme-deny-php.conf (conf-available and
#                    a2enconf on Debian, conf.d on RHEL) and checks it with a
#                    configtest. nginx: writes a snippet and adds an include as the
#                    FIRST line of every server block that serves PHP (the first
#                    matching regex location wins), then checks with nginx -t
#                    (NGINX_MAIN_CONF=FILE checks a non-default main file). If the
#                    web server rejects the result everything is undone at once.
#                    The rule applies to EVERY PHP virtual host on the machine, and
#                    it also blocks a legitimate PHP file requested directly under a
#                    directory named cache, images, media or uploads.
#   rollback [--dry-run] [--reload]   remove what mitigate added and restore the files
#                    it edited.
#   version          print the script version.
#
# Environment: HUNT_WEB_LOGS (extra web access log paths for the hunt). STATE_DIR
# (default /var/lib/psf-security-patches/yootheme) holds the backups and manifest.
#
# Version reading: the script reads the standard WordPress theme header
# (style.css, Version:) and the Joomla template manifest (templateDetails.xml,
# <version>). If it cannot read a version it says so; the YOOtheme dashboard also
# shows the version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies only the first few KB of
# each theme's style.css or templateDetails.xml, where the version is, into a private temporary
# directory, and this script runs once per container in isolation against that copy. The hunt
# command does not look inside containers. Paths shown as .../docker_NAME/... are inside the
# container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="yootheme-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/yootheme}"

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

# ---------- version rule -----------------------------------------------------
# prints: vulnerable | fixed | notaffected | unknown
yoo_status() {
    local n; n="$(norm_ver "$1")"
    is_semver "$n" || { echo unknown; return; }
    case "${n%%.*}" in
        0|1|2|3|4) echo notaffected ;;
        5) ver_lt "$n" "5.0.53" && echo vulnerable || echo fixed ;;
        *) echo fixed ;;
    esac
}

find_installs() {   # prints  kind<TAB>dir  (wp or joomla)
    local d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        case "$d" in
            */wp-content/themes/yootheme) [[ -r "$d/style.css" ]] && printf 'wp\t%s\n' "$d" ;;
            */templates/yootheme)         [[ -r "$d/templateDetails.xml" ]] && printf 'joomla\t%s\n' "$d" ;;
        esac
    done < <(find "$@" -xdev -maxdepth 9 -type d -name yootheme \( -path '*/wp-content/themes/*' -o -path '*/templates/*' \) 2>/dev/null | sort -u)
}

read_version() {   # kind dir
    case "$1" in
        wp)     sed -n 's/^[[:space:]]*Version:[[:space:]]*//p' "$2/style.css" 2>/dev/null | head -n1 | tr -d '\r ' ;;
        joomla) sed -n 's#.*<version>\([^<]*\)</version>.*#\1#p' "$2/templateDetails.xml" 2>/dev/null | head -n1 | tr -d '\r ' ;;
    esac
}

site_root() {   # kind dir
    case "$1" in
        wp)     dirname "$(dirname "$(dirname "$2")")" ;;    # .../wp-content/themes/yootheme -> site root
        joomla) dirname "$(dirname "$2")" ;;                 # .../templates/yootheme -> site root
    esac
}

# ---------- check ------------------------------------------------------------
INSTALLS=()
# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   M <path> <epoch>  set the modification time of a staged file (a copy would otherwise carry the copy time)
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
                    M) [[ "$rest" =~ ^[0-9]{1,12}$ && -e "$s$p" ]] && touch -d "@$rest" "$s$p" 2>/dev/null ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

YOOTHEME_PROBE="$(cat <<'EOS'
find /var/www /srv /opt /home -xdev -maxdepth 9 -type d -name yootheme \( -path "*/wp-content/themes/*" -o -path "*/templates/*" \) 2>/dev/null | head -n 40 | while read -r d; do
  [ -f "$d/style.css" ] && echo "B $d/style.css $(head -c 8192 "$d/style.css" | base64 | tr -d '\n')"
  [ -f "$d/templateDetails.xml" ] && echo "B $d/templateDetails.xml $(head -c 20000 "$d/templateDetails.xml" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : YOOtheme in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "YOOtheme in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$YOOTHEME_PROBE"
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
    local rc=0 found=0 d kind dir ver st
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for YOOtheme"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    INSTALLS=()
    while IFS=$'\t' read -r kind dir; do
        [[ -n "$kind" ]] || continue
        found=$((found+1)); INSTALLS+=("${kind}"$'\t'"${dir}")
        ver="$(read_version "$kind" "$dir")"
        step "YOOtheme (${kind}) ${ver:-version unreadable} at ${dir}"
        if [[ -z "$ver" ]]; then
            caution "could not read a version: check it in the YOOtheme dashboard. Affected is 5.0.0 through 5.0.52; fixed is 5.0.53."
            rc=1; continue
        fi
        st="$(yoo_status "$ver")"
        case "$st" in
            fixed)       ok "YOOtheme ${ver} has the fix (5.0.53 or newer)" ;;
            notaffected) ok "YOOtheme ${ver} is older than 5, which the vendor says is not affected" ;;
            unknown)     caution "cannot compare version '${ver}': check it against 5.0.53"; rc=1 ;;
            vulnerable)  bad "YOOtheme Pro ${ver} is affected by CVE-2026-102785 (fixed in 5.0.53): unauthenticated remote code execution"
                         inf "update now, then run: $0 hunt   (an update does not remove files an attacker already wrote)"
                         rc=1 ;;
        esac
    done < <(find_installs "${existing[@]}")
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No YOOtheme found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected YOOtheme found (${found} checked)"
    else
        warn "Affected or unverifiable YOOtheme found. Update YOOtheme Pro to 5.0.53 or later."
        inf "PrivacySafe protection: deny the web server from running PHP in upload, media and cache directories (see the README for nginx and Apache rules). That blocks the written file from running; it does not stop the write."
        inf "Vendor notice: https://x.com/yootheme and the YOOtheme Pro changelog (5.0.53)"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
hunt_site() {   # kind dir
    local kind="$1" dir="$2" root rc=0 out f
    local -a media=()
    root="$(site_root "$kind" "$dir")"
    step "Hunting in ${root} (${kind})"
    case "$kind" in
        wp)     media=("$root/wp-content/uploads" "$root/wp-content/cache" "$dir/cache") ;;
        joomla) media=("$root/images" "$root/cache" "$root/media" "$dir/cache") ;;
    esac
    local -a ex=(); for f in "${media[@]}"; do [[ -d "$f" ]] && ex+=("$f"); done
    if [[ ${#ex[@]} -eq 0 ]]; then inf "no upload, media or cache directory found to search"; return 0; fi
    inf "searching: ${ex[*]}"

    # 1. PHP files where none belongs (WordPress writes tiny index.php placeholders into some directories)
    out=""
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ "$(basename "$f")" == "index.php" ]] && [[ "$(wc -c <"$f" 2>/dev/null)" -lt 120 ]] && grep -qi 'silence is golden' "$f" 2>/dev/null; then continue; fi
        out+="${f}"$'\n'
    done < <(find "${ex[@]}" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' -o -iname '*.pht' \) 2>/dev/null | head -n200)
    if [[ -n "$out" ]]; then bad "PHP files inside upload, media or cache directories (nothing legitimate normally puts PHP there):"; grep -v '^$' <<<"$out" | sed 's/^/        /' | head -n15; rc=1
    else ok "no PHP file in the upload, media and cache directories"; fi

    # 2. PHP code inside image files (a PNG/PHP polyglot). Only the 5-byte "<?php": a 3-byte "<?=" would match random image data.
    out="$(find "${ex[@]}" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.gif' -o -iname '*.webp' \) -size -8M \
              -exec grep -laE '<\?php' {} + 2>/dev/null | head -n50)"
    if [[ -n "$out" ]]; then bad "image files that contain PHP code (a polyglot):"; sed 's/^/        /' <<<"$out" | head -n15; rc=1
    else ok "no image file contains a PHP open tag"; fi
    return "$rc"
}

hunt_logs() {
    local rc=0 f out
    local -a wl=()
    shopt -s nullglob
    for f in /var/log/apache2/*access*.log /var/log/nginx/*access*.log /var/log/httpd/*access*log \
             /var/log/apache2/other_vhosts_access.log ${HUNT_WEB_LOGS:-}; do
        [[ -r "$f" && -f "$f" ]] && wl+=("$f")
    done
    shopt -u nullglob
    step "Web logs: requests that run a PHP file from a media, upload or cache path"
    if [[ ${#wl[@]} -eq 0 ]]; then inf "no readable web access logs found (set HUNT_WEB_LOGS to add paths)"; return 0; fi
    # common/combined log format: $1 client, $7 path, $9 status
    out="$(cat "${wl[@]}" 2>/dev/null | awk '{p=tolower($7); s=$9; sub(/\?.*/,"",p)} p ~ /\/(cache|images|media|uploads)\/.*\.(php|phtml|phar)$/ && s ~ /^2/ {print $1, p}' | sort | uniq -c | sort -rn | head -n8)"
    if [[ -n "$out" ]]; then
        bad "successful requests (2xx) to PHP files under cache, images, media or uploads paths (count, client, path):"
        sed 's/^/        /' <<<"$out"; rc=1
    else
        ok "no successful request to a PHP file under a cache, images, media or uploads path in the readable logs"
    fi
    return "$rc"
}

cmd_hunt() {
    local rc=0 line kind dir
    cmd_check "$@" || rc=1
    if [[ ${#INSTALLS[@]} -gt 0 ]]; then
        for line in "${INSTALLS[@]}"; do
            kind="${line%%$'\t'*}"; dir="${line#*$'\t'}"
            hunt_site "$kind" "$dir" || rc=1
        done
        hunt_logs || rc=1
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No indicator found: none of the published indicators were found."
    else
        warn "An affected version or an indicator was found. If a PHP file or polyglot is present, treat the site as compromised."
        inf "Keep a copy of the file for analysis before you delete it, update YOOtheme Pro, and remove any file you did not put there."
        inf "Then look for other changes (new admin users, modified theme and plugin files), rotate the CMS, database and hosting credentials, and consider restoring from a backup taken before 21 October 2026."
    fi
    return "$rc"
}


# ---------- mitigate and rollback --------------------------------------------
YM_RULE_RE='^/(.+/)?(cache|images|media|uploads)/.+\.(php|phtml|phar|pht|php[0-9])$'
YM_MANIFEST=""; YM_DRY=0
ym_run() { if [[ "$YM_DRY" -eq 1 ]]; then echo "  would run: $*"; return 0; fi; "$@"; }
ym_note() { [[ "$YM_DRY" -eq 1 ]] || echo "$1" >>"$YM_MANIFEST"; }

ym_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$YM_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$YM_MANIFEST"
}

ym_apache_ctl() { local c; for c in apache2ctl apachectl httpd; do have "$c" && { echo "$c"; return 0; }; done; return 1; }

ym_apache_apply() {   # -> 0 ok, 1 failed (and undone)
    local ctl avail enabled confd target name=psf-yootheme-deny-php
    ctl="$(ym_apache_ctl)" || return 2
    avail="${APACHE_CONF_AVAILABLE:-/etc/apache2/conf-available}"; enabled="${APACHE_CONF_ENABLED:-/etc/apache2/conf-enabled}"
    confd="${APACHE_CONFD:-/etc/httpd/conf.d}"
    if [[ -d "$avail" ]]; then target="${avail}/${name}.conf"
    elif [[ -d "$confd" ]]; then target="${confd}/${name}.conf"
    else caution "Apache found but neither ${avail} nor ${confd} exists: add the rule by hand (see the README)"; return 1; fi
    if [[ "$YM_DRY" -eq 1 ]]; then
        echo "  would write ${target}:"; ym_apache_text | sed 's/^/      /'
        [[ "$target" == "${avail}/"* ]] && echo "  would run: a2enconf ${name}"
        echo "  would run: ${ctl} configtest"; return 0
    fi
    ym_apache_text >"$target" || return 1
    ym_note "file|${target}"
    if [[ "$target" == "${avail}/"* ]]; then
        if have a2enconf; then a2enconf "$name" >/dev/null 2>&1 || true
        else mkdir -p "$enabled" && ln -sf "$target" "${enabled}/${name}.conf"; fi
        ym_note "a2conf|${name}|${enabled}"
    fi
    if "$ctl" configtest >/dev/null 2>&1; then ok "Apache: ${target} written and ${ctl} configtest accepts it"; return 0; fi
    bad "Apache: configtest REJECTS the new rule: removing it"
    ym_apache_remove "$target" "$name" "$enabled"; return 1
}
ym_apache_text() {
    printf '%s\n' '# psf-security-patches: CVE-2026-102785 protective measure (yootheme-check.sh mitigate). Remove with: rollback' \
        "<LocationMatch \"(?i)${YM_RULE_RE}\">" '    Require all denied' '</LocationMatch>'
}
ym_apache_remove() {   # target name enabled
    have a2disconf && a2disconf "$2" >/dev/null 2>&1 || true
    rm -f "${3}/${2}.conf" "$1"
}

ym_nginx_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    { nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p'
      echo /etc/nginx/nginx.conf; ls /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done | awk '!s[$0]++'
}
read -r -d '' YM_AWK_NGINX <<'AWKEOF'
function flush(   i) {
    for (i = 1; i <= n; i++) {
        print buf[i]
        if (i == 1 && php && !has) print "    include " snip ";"
    }
    n = 0; php = 0; has = 0
}
{
    raw = $0; code = raw; sub(/#.*/, "", code)
    o = gsub(/\{/, "{", code); c = gsub(/\}/, "}", code)
    if (!inserv) {
        if (raw ~ /^[ \t]*server[ \t]*\{/) {
            inserv = 1; sdepth = depth; buf[++n] = raw; depth += o - c
            if (index(raw, "fastcgi_pass") || raw ~ /\.php/) php = 1
            if (depth <= sdepth) { flush(); inserv = 0 }
        } else { print raw; depth += o - c }
    } else {
        buf[++n] = raw
        if (code ~ /fastcgi_pass|fastcgi_param|\.php/) php = 1
        if (index(raw, snip)) has = 1
        depth += o - c
        if (depth <= sdepth) { flush(); inserv = 0 }
    }
}
END { if (n > 0) flush() }
AWKEOF

ym_nginx_test() {   # NGINX_MAIN_CONF names a non-default main configuration file
    if [[ -n "${NGINX_MAIN_CONF:-}" ]]; then nginx -t -c "$NGINX_MAIN_CONF" >/dev/null 2>&1; else nginx -t >/dev/null 2>&1; fi
}

ym_nginx_apply() {
    local snipdir snip f tmp n changed=0 files=() line
    have nginx || return 2
    snipdir="${NGINX_SNIPPET_DIR:-/etc/nginx/snippets}"; snip="${snipdir}/psf-yootheme-deny-php.conf"
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(ym_nginx_files)
    if [[ ${#files[@]} -eq 0 ]]; then caution "nginx found but no readable configuration file: add the rule by hand (see the README)"; return 1; fi
    if [[ "$YM_DRY" -eq 0 ]]; then
        mkdir -p "$snipdir" || return 1
        printf '%s\n%s\n' '# psf-security-patches: CVE-2026-102785 protective measure (yootheme-check.sh mitigate). Remove with: rollback' \
            "location ~* ${YM_RULE_RE} { return 403; }" >"$snip" || return 1
        ym_note "file|${snip}"
    else echo "  would write ${snip}: location ~* ${YM_RULE_RE} { return 403; }"; fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/ymng.XXXXXX")" || return 1
    for f in "${files[@]}"; do
        awk -v snip="$snip" "$YM_AWK_NGINX" "$f" >"$tmp" || continue
        cmp -s "$f" "$tmp" && continue
        n=$(diff "$f" "$tmp" | grep -c '^>')
        if [[ "$YM_DRY" -eq 1 ]]; then echo "  would add ${n} include line(s) to ${f}"
        else ym_backup "$f" && cat "$tmp" >"$f" && { ok "nginx: added the include to ${n} server block(s) in ${f}"; changed=1; }; fi
    done
    rm -f "$tmp"
    if [[ "$YM_DRY" -eq 1 ]]; then echo "  would run: nginx -t"; return 0; fi
    if [[ $changed -eq 0 ]]; then inf "nginx: no PHP-serving server block needed the include"; fi
    if ym_nginx_test; then ok "nginx: nginx -t accepts the new configuration"; return 0; fi
    bad "nginx: nginx -t REJECTS the new configuration: restoring the originals now"
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f"
    done <"$YM_MANIFEST"
    rm -f "$snip"; : >"$YM_MANIFEST"; return 1
}

ym_reload() {
    [[ "${YM_RELOAD:-0}" -eq 1 ]] || return 0
    local u did=0
    for u in "$@"; do
        if have systemctl && grep -q "^${u}" <<<"$(systemctl list-unit-files 2>/dev/null)"; then
            ym_run systemctl reload "$u" && inf "reloaded ${u} (graceful)"; did=1
        fi
    done
    [[ $did -eq 1 ]] || caution "--reload given but no matching systemd unit found: reload the web server yourself"
}

cmd_mitigate() {
    local web=auto force=0 rc=0 kind dir ver st bad_n=0 any_web=0 r
    local -a dirs=() reload_units=()
    YM_DRY=0; YM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) YM_DRY=1 ;; --reload) YM_RELOAD=1 ;; --force) force=1 ;;
            --web) shift; web="${1:-}"; case "$web" in auto|apache|nginx) ;; *) die "--web needs auto, apache or nginx" ;; esac ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            *) die "Unknown mitigate option: $1 (--web --dir --dry-run --reload --force)" ;;
        esac
        shift
    done
    [[ $YM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "mitigate changes the host: run it as root, or add --dry-run to see what it would do"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /opt /home)
    step "Looking for YOOtheme"
    local -a existing=(); for dir in "${dirs[@]}"; do [[ -d "$dir" ]] && existing+=("$dir"); done
    if [[ ${#existing[@]} -gt 0 ]]; then
        while IFS=$'\t' read -r kind dir; do
            [[ -n "$kind" ]] || continue
            ver="$(read_version "$kind" "$dir")"; st="$(yoo_status "${ver:-x}")"
            case "$st" in
                vulnerable) bad "YOOtheme ${ver} at ${dir} is affected"; bad_n=$((bad_n+1)) ;;
                unknown) caution "YOOtheme at ${dir}: version unreadable, treated as affected"; bad_n=$((bad_n+1)) ;;
                *) ok "YOOtheme ${ver} at ${dir}: not affected" ;;
            esac
        done < <(find_installs "${existing[@]}")
    fi
    if [[ $bad_n -eq 0 && $force -eq 0 ]]; then info "No affected YOOtheme found: nothing to do (use --force to apply the rule anyway)"; return 0; fi
    if [[ $YM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        YM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$YM_MANIFEST"
    else YM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    step "Web server rule"
    if [[ "$web" == auto || "$web" == apache ]]; then
        ym_apache_apply; r=$?
        case $r in 0) any_web=1; reload_units+=(apache2 httpd) ;; 1) rc=1 ;; 2) [[ "$web" == apache ]] && { caution "no Apache found"; rc=1; } ;; esac
    fi
    if [[ "$web" == auto || "$web" == nginx ]]; then
        ym_nginx_apply; r=$?
        case $r in 0) any_web=1; reload_units+=(nginx) ;; 1) rc=1 ;; 2) [[ "$web" == nginx ]] && { caution "no nginx found"; rc=1; } ;; esac
    fi
    if [[ $any_web -eq 0 && $rc -eq 0 ]]; then caution "no Apache or nginx found: add the rule by hand (see the README), or put it in your proxy"; rc=1; fi
    if [[ $any_web -eq 1 && $YM_RELOAD -eq 1 && $YM_DRY -eq 0 ]]; then
        ym_reload "${reload_units[@]}"
    fi
    step "Result"
    if [[ $YM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $any_web -eq 1 ]]; then
        info "PHP under uploads, media, images and cache paths is now refused. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $YM_RELOAD -eq 1 ]] || inf "reload the web server for it to take effect (or re-run with --reload)"
    fi
    inf "This stops a written file from running; it does not stop the write. Update YOOtheme Pro to 5.0.53, then rotate credentials if the site was exposed."
    return "$rc"
}

cmd_rollback() {
    local line f b kind rc=0 name enabled
    YM_DRY=0; YM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) YM_DRY=1 ;; --reload) YM_RELOAD=1 ;; *) die "Unknown rollback option: $1 (--dry-run --reload)" ;; esac
        shift
    done
    YM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$YM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $YM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "rollback changes the host: run it as root, or add --dry-run"
    step "Rolling back"
    while IFS= read -r line; do
        kind="${line%%|*}"
        case "$kind" in
            conf) f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
                  if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi ;;
            a2conf) name="${line#a2conf|}"; enabled="${name#*|}"; name="${name%%|*}"
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would disable ${name}"; else { have a2disconf && a2disconf "$name" >/dev/null 2>&1; rm -f "${enabled}/${name}.conf"; } || true; ok "disabled ${name}"; fi ;;
            file) f="${line#file|}"
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
        esac
    done <"$YM_MANIFEST"
    if [[ $YM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$YM_MANIFEST" "${YM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload the web server for it to take effect."
    fi
    ym_reload apache2 httpd nginx
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-102785; fixed in YOOtheme Pro 5.0.53"
    case "$CMD" in
        check|hunt|mitigate|rollback) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
