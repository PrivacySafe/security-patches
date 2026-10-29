#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# YOOtheme Pro 5 unauthenticated remote code execution: read-only checker  (v1)
# CVE-2026-102785
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# YOOtheme Pro is a widely used commercial theme and page builder for WordPress
# and Joomla. Its publicly reachable image handler (the route that creates and
# caches resized and cropped images) does not fully bind the normalised image
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
#   version          print the script version.
#
# Environment: HUNT_WEB_LOGS (extra web access log paths for the hunt).
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
        inf "No vendor workaround is documented. Interim, ours: deny the web server from running PHP in upload, media and cache directories (see the README for nginx and Apache rules). That blocks the written file from running; it does not stop the write."
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
        info "No indicator found. This is not proof of a clean site."
    else
        warn "An affected version or an indicator was found. If a PHP file or polyglot is present, treat the site as compromised."
        inf "Keep a copy of the file for analysis before you delete it, update YOOtheme Pro, and remove any file you did not put there."
        inf "Then look for other changes (new admin users, modified theme and plugin files), rotate the CMS, database and hosting credentials, and consider restoring from a backup taken before 21 October 2026."
    fi
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
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
