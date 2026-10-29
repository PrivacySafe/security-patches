#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Traffic Server experimental plugins, October 2026: read-only checker  (v1)
# CVE-2026-111813 (magick plugin, CVSS 10.0)
# CVE-2026-111811 (tsmemcache plugin, CVSS 9.0)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Apache Traffic Server (ATS) is a caching reverse and forward proxy used in front
# of large sites and CDNs. The October 2026 release fixes 15 vulnerabilities. Two of
# them sit in EXPERIMENTAL plugins and are the severe ones:
#
# CVE-2026-111813  The magick plugin passes client query strings unfiltered to
#                  ImageMagick's convert in its default (unsigned) configuration,
#                  so an unauthenticated client controls convert's arguments:
#                  command injection / argument injection. CVSS 10.0, critical.
# CVE-2026-111811  The tsmemcache plugin exposes the shared proxy cache over the
#                  network with no authentication: unauthenticated read, write and
#                  deletion of the cache. CVSS 9.0 by Apache's rating (Moderate on
#                  their scale), listed as 9.4 Critical by some aggregators.
#
#   Affected: 8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0
#             (the magick plugin from 8.0.1)
#   Fixed:    9.2.16, 10.1.5 and 10.2.1 (released 20 October 2026)
#   No fix:   8.x, 9.0, 9.1 and 10.0 are end of life branches that Apache does not
#             patch: move to a fixed branch
#
# Both flaws only matter when the plugin is LOADED. The script therefore reads the
# configuration (plugin.config and the remap files) for magick.so and tsmemcache.so
# rather than looking for files: the plugins are experimental, are not enabled by
# default, and a magick.so on disk can just as well be an ImageMagick coder.
#
# The same release fixes thirteen other flaws (request smuggling, cache poisoning,
# denial of service) that only the update fixes.
#
# This script is read-only. It finds traffic_server (PATH, usual locations and running
# processes), reads its version from "traffic_server -V", reads the configuration
# directory, and checks the owning package's changelog for a backported fix.
#
# Usage:
#   ./trafficserver-check.sh [command] [PATH-TO-traffic_server ...]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version loads one of
#                    the two plugins, or its configuration could not be read.
#   version          print the script version.
#
# Environment: ATS_CONFIG_DIR (space separated directories) replaces config discovery.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the output of
# traffic_server -V and the configuration files with every line that does not load magick.so or
# tsmemcache.so blanked inside the container (so credentials never leave it, and line numbers stay
# exact) into a private temporary directory, and this script then runs once per container in
# isolation against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="trafficserver-check.sh"
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
# prints: vulnerable | eol | fixed | outside | unknown
ats_status() {
    local v="$1" maj min pat
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    (( maj < 8 )) && { echo outside; return; }
    (( maj == 8 )) && { echo eol; return; }
    if (( maj == 9 )); then
        (( min < 2 )) && { echo eol; return; }
        (( min == 2 )) && { (( pat < 16 )) && echo vulnerable || echo fixed; return; }
        echo fixed; return
    fi
    if (( maj == 10 )); then
        (( min == 0 )) && { echo eol; return; }
        (( min == 1 )) && { (( pat < 5 )) && echo vulnerable || echo fixed; return; }
        (( min == 2 )) && { (( pat < 1 )) && echo vulnerable || echo fixed; return; }
        echo fixed; return
    fi
    echo fixed
}

bin_version() {
    timeout 15 "$1" -V 2>&1 | grep -oE 'traffic_server - [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/^traffic_server - //'
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v traffic_server 2>/dev/null)" /usr/bin/traffic_server /usr/local/bin/traffic_server /opt/ts/bin/traffic_server /opt/trafficserver/bin/traffic_server; do
        [[ -n "$b" && -x "$b" && -f "$b" ]] && out+=("$(readlink -f "$b")")
    done
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2=="traffic_server"{print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

config_dirs() {
    local d
    if [[ -n "${ATS_CONFIG_DIR:-}" ]]; then for d in $ATS_CONFIG_DIR; do [[ -d "$d" ]] && echo "$d"; done; return 0; fi
    for d in /etc/trafficserver /usr/local/etc/trafficserver /opt/ts/etc/trafficserver /opt/trafficserver/etc/trafficserver; do
        [[ -d "$d" ]] && echo "$d"
    done
}

# lines that load a plugin by name; comments are ignored. Prints  file:line:plugin
PLUGIN_HITS=""
scan_plugins() {   # config dir
    local dir="$1" f out
    for f in "$dir"/plugin.config "$dir"/remap.config "$dir"/remap.yaml "$dir"/plugin.yaml "$dir"/*.config "$dir"/*.yaml; do
        [[ -r "$f" && -f "$f" ]] || continue
        case " ${SEEN_F:-} " in *" $f "*) continue ;; esac
        SEEN_F="${SEEN_F:-} $f"
        out="$(sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -nE '(^|[[:space:]=@/"'"'"'-])(magick|tsmemcache)\.so([[:space:]"'"'"']|$)' | sed -E 's/^([0-9]+):.*(magick|tsmemcache)\.so.*/\1:\2/' )"
        [[ -n "$out" ]] && PLUGIN_HITS+="$(sed "s#^#${f}:#" <<<"$out")"$'\n'
    done
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
#   L <path> <text>   write one short sanitized line of text
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

ATS_PROBE="$(cat <<'EOS'
n=""
for c in /usr/bin/traffic_server /usr/local/bin/traffic_server /opt/ts/bin/traffic_server /opt/trafficserver/bin/traffic_server; do [ -x "$c" ] && [ -f "$c" ] && { n=$c; break; }; done
[ -n "$n" ] || exit 0
echo "B /.out_V $("$n" -V 2>&1 | head -n 5 | base64 | tr -d '\n')"
for d in /etc/trafficserver /usr/local/etc/trafficserver /opt/ts/etc/trafficserver /opt/trafficserver/etc/trafficserver; do
  [ -d "$d" ] || continue
  echo "D $d"
  for f in "$d"/*.config "$d"/*.yaml; do
    [ -f "$f" ] && [ "$(wc -c < "$f")" -lt 512000 ] && echo "B $f $(awk '/magick\.so|tsmemcache\.so/ {print; next} {print ""}' "$f" | base64 | tr -d '\n')"
  done
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Traffic Server in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -s "$s/.out_V" ]] || return 0
    printf '#!/bin/sh\ncase "$1" in\n  -V) cat "%s/.out_V" ;;\nesac\n' "$s" > "$s/traffic_server"; chmod 755 "$s/traffic_server"
    step "Apache Traffic Server in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 ATS_CONFIG_DIR="$s/etc/trafficserver $s/usr/local/etc/trafficserver $s/opt/ts/etc/trafficserver $s/opt/trafficserver/etc/trafficserver" bash "$SELF" check "$s/traffic_server" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$ATS_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a bins=()
    local rc=0 found=0 b ver st d read_any hit pl magick tsm
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for Apache Traffic Server"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No traffic_server found on this host"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        ver="$(bin_version "$b")"
        [[ -n "$ver" ]] || { caution "${b}: could not read a version from -V"; continue; }
        found=$((found+1))
        step "Apache Traffic Server ${ver} at ${b}"
        st="$(ats_status "$ver")"
        case "$st" in
            fixed)   ok "Traffic Server ${ver} has the fix (9.2.16, 10.1.5, 10.2.1 or newer)"; continue ;;
            outside) caution "Traffic Server ${ver} is older than 8.0: outside the stated range, and long end of life"; continue ;;
            unknown) caution "cannot parse version '${ver}'"; continue ;;
            eol)     bad "Traffic Server ${ver} is on an end-of-life branch (8.x, 9.0, 9.1 or 10.0): in the affected range and Apache will not patch it. Move to 9.2.16, 10.1.5 or 10.2.1 or newer." ;;
            vulnerable) bad "Traffic Server ${ver} is in the affected range (fixed in 9.2.16, 10.1.5 and 10.2.1)" ;;
        esac
        if distro_mentions "$b" CVE-2026-111813 CVE-2026-111811; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution has probably backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention either CVE yet"
        fi
        PLUGIN_HITS=""; SEEN_F=""; read_any=0
        while IFS= read -r d; do
            [[ -n "$d" ]] || continue
            read_any=1; scan_plugins "$d"; inf "read ${d}"
        done < <(config_dirs)
        if [[ $read_any -eq 0 ]]; then
            caution "no readable Traffic Server configuration directory found: plugin use cannot be checked, treating as exposed (set ATS_CONFIG_DIR to point at it)"
            rc=1; continue
        fi
        magick=0; tsm=0
        while IFS= read -r hit; do
            [[ -n "$hit" ]] || continue
            pl="${hit##*:}"
            [[ "$pl" == magick ]] && magick=1
            [[ "$pl" == tsmemcache ]] && tsm=1
        done <<<"$PLUGIN_HITS"
        if [[ $magick -eq 1 ]]; then
            bad "the experimental magick plugin is LOADED (CVE-2026-111813, CVSS 10: unauthenticated clients control ImageMagick convert arguments), at:"
            grep -E ':magick$' <<<"$PLUGIN_HITS" | sed -E 's/:magick$//; s/^/        /' | head -n4; rc=1
        fi
        if [[ $tsm -eq 1 ]]; then
            bad "the experimental tsmemcache plugin is LOADED (CVE-2026-111811: unauthenticated network read, write and deletion of the shared cache), at:"
            grep -E ':tsmemcache$' <<<"$PLUGIN_HITS" | sed -E 's/:tsmemcache$//; s/^/        /' | head -n4; rc=1
        fi
        if [[ $magick -eq 0 && $tsm -eq 0 ]]; then
            ok "neither the magick nor the tsmemcache plugin is loaded in the configuration read: these two flaws are not reachable here"
            caution "update anyway: the same release fixes thirteen other flaws (request smuggling, cache poisoning, denial of service) that only the update fixes"
        fi
        [[ "$st" == eol && $magick -eq 0 && $tsm -eq 0 ]] && inf "an end-of-life branch has no upstream fix for those other flaws: plan the move to a supported branch"
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Traffic Server version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Traffic Server found (${found} checked). An affected version without these two plugins still needs the update."
    else
        warn "Exposed or unverifiable Traffic Server found. Upgrade to 9.2.16, 10.1.5 or 10.2.1 (or a distribution build that carries the fix)."
        inf "Interim (ours, not vendor documented): remove magick.so and tsmemcache.so from plugin.config and the remap files and restart Traffic Server; neither plugin is enabled by default and both are experimental."
        inf "Advisory: https://trafficserver.apache.org/security-2026-10.html"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-111813 and CVE-2026-111811; fixed in Apache Traffic Server 9.2.16, 10.1.5 and 10.2.1"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
