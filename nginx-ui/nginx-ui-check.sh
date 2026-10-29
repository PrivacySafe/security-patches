#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# nginx-ui restricted-directive bypass (authenticated RCE): read-only checker  (v2)
# CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# nginx-ui is a web interface for managing nginx. It has a security control,
# ValidateConfigFile, that refuses configuration containing directives that can run
# code or raise privileges (load_module of the njs or Perl modules, js_import,
# js_content, perl_*, user root). Four advisories published 12 October 2026 describe
# ways around that control for a logged-in user. Where nginx loads the njs, Perl or
# Lua module (the official Docker image does), the injected configuration runs code
# in the nginx worker.
#
#   CVE-2026-84316  CVSS 8.8  The validator split the configuration on newlines and
#                   looked only at the first token of each line. nginx separates
#                   directives with ";", so a harmless directive first and a
#                   restricted one after a semicolon on the same line passed.
#   CVE-2026-84317  CVSS 8.8  The MCP tool nginx_config_add wrote the caller's
#   CVE-2026-84318  CVSS 8.8  configuration to disk and reloaded nginx without calling
#                   ValidateConfigFile at all. The REST paths do call it. Two IDs
#                   describe this one gap, with different affected ranges.
#   CVE-2026-84319  CVSS 8.3  The MCP configuration interface let a secondary
#                   authenticated user write and apply the restricted directives the
#                   regular API refuses (load_module of the njs module, js_import),
#                   which executes njs in the nginx worker.
#
#   Affected: nginx-ui below 2.4.1 (84318 from 2.0.0-rc.6).
#   Fixed:    nginx-ui 2.4.1.
#
# How this script reads an install. The nginx-ui binary has no version flag, and its
# version endpoint needs a login, so a read-only check cannot ask it. Instead:
#   0. The official container image, uozi/nginx-ui, is judged by its tag when the tag names a
#      version (a tag such as latest does not, and is a warning). With no binary and no image
#      on the host, a version you supply in NGINX_UI_VERSION is judged on its own.
#   1. NGINX_UI_VERSION (you set it) or the package version, when there is one;
#   2. a string inside the binary. The 2.4.1 validator adds the restricted names
#      lua_package_cpath and lua_package_path, which 2.4.0 does not contain. A binary
#      without them is the older validator (strong finding). A binary with them is
#      consistent with 2.4.1 or later; it is a string match, so confirm the version
#      shown in the web interface.
#
# This script is read-only.
#
# Usage:
#   ./nginx-ui-check.sh [command]
#   check (default)  find nginx-ui, read its version and the binary signature, report.
#                    Exit 0 = nothing exposed, 1 = exposed or unclear.
#   hunt             read nginx configuration for the semicolon bypass shape and list
#                    restricted directives present, for review. Exit 0 = nothing found,
#                    1 = a strong lead. A clean hunt is not proof.
#   version          print the script version.
#
# Env: NGINX_UI_BIN      path to the nginx-ui binary
#      NGINX_UI_VERSION  the version, from the web interface, if you know it
#      NGINX_UI_CONF_DIRS  space separated nginx configuration directories for hunt
#                          (default /etc/nginx /etc/angie /usr/local/etc/nginx /usr/local/nginx/conf)
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe runs the two signature tests
# this check applies to the binary (lua_package_cpath and lua_package_path) inside the container
# and copies only a small file recording the answer, so the binary itself is never copied. The
# version is not read by running nginx-ui, so a container is judged by that signature alone. Paths
# shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="nginx-ui-check.sh"
SCRIPT_VERSION="2.0.0"
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
# ---------- locating nginx-ui ------------------------------------------------
find_binaries() {
    local p e t u line
    [[ -n "${NGINX_UI_BIN:-}" && -e "${NGINX_UI_BIN}" ]] && echo "${NGINX_UI_BIN}"
    # a run staged from a container looks only at the file it was given
    [[ -z "${NGINX_UI_ISOLATED:-}" ]] || return 0
    for p in /usr/local/bin/nginx-ui /usr/bin/nginx-ui /opt/nginx-ui/nginx-ui /usr/local/nginx-ui/nginx-ui; do [[ -e "$p" ]] && echo "$p"; done
    # the ExecStart of the systemd unit
    for u in /etc/systemd/system/nginx-ui.service /lib/systemd/system/nginx-ui.service /usr/lib/systemd/system/nginx-ui.service; do
        [[ -r "$u" ]] || continue
        line="$(sed -nE 's/^[[:space:]]*ExecStart=[-@+!]*([^[:space:]]+).*/\1/p' "$u" | head -n1)"
        [[ -n "$line" && -e "$line" ]] && echo "$line"
    done
    # a running process
    for e in /proc/[0-9]*/exe; do
        t="$(readlink "$e" 2>/dev/null)" || continue
        [[ "${t##*/}" == nginx-ui* ]] && echo "${t% (deleted)}"
    done
}
package_version() {
    local v=""
    [[ -z "${NGINX_UI_ISOLATED:-}" ]] || return 0
    if have dpkg-query; then v="$(dpkg-query -W -f='${Version}' nginx-ui 2>/dev/null)"; fi
    if [[ -z "$v" ]] && have rpm; then v="$(rpm -q --qf '%{VERSION}' nginx-ui 2>/dev/null)"; [[ "$v" == *"not installed"* ]] && v=""; fi
    echo "$v" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?' | head -n1
}

# prints: affected | fixed | unknown, for a semantic version string
nui_status() {
    local v="${1#v}" maj min pat pre
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.+)?$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; pre="${BASH_REMATCH[4]:-}"
    (( maj > 2 )) && { echo fixed; return; }
    (( maj < 2 )) && { echo affected; return; }
    (( min > 4 )) && { echo fixed; return; }
    if (( min == 4 && pat >= 1 )) && [[ -z "$pre" ]]; then echo fixed; return; fi
    echo affected
}

# the binary signature: does the validator carry the names added in 2.4.1?
binary_signature() {
    local b="$1"
    [[ -r "$b" && -f "$b" ]] || { echo "n/a"; return; }
    if grep -a -F -- 'lua_package_cpath' "$b" >/dev/null && grep -a -F -- 'lua_package_path' "$b" >/dev/null; then echo yes; else echo no; fi
}

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

NGINXUI_PROBE="$(cat <<'EOS'
for b in /usr/local/bin/nginx-ui /usr/bin/nginx-ui /opt/nginx-ui/nginx-ui /usr/local/nginx-ui/nginx-ui; do
  [ -f "$b" ] || continue
  if grep -a -F -- "lua_package_cpath" "$b" >/dev/null 2>&1 && grep -a -F -- "lua_package_path" "$b" >/dev/null 2>&1; then c="lua_package_cpath lua_package_path"; else c="nginx-ui without the 2.4.1 validator names"; fi
  echo "B $b $(printf '%s\n' "$c" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : nginx-ui in one container, judged by this script run in isolation
    local s="$1" out rc b bad_rc=0
    for b in usr/local/bin/nginx-ui usr/bin/nginx-ui opt/nginx-ui/nginx-ui usr/local/nginx-ui/nginx-ui; do
        [[ -f "$s/$b" ]] || continue
        step "nginx-ui in a container (${s##*/}), /${b}"
        out="$(SCAN_CONTAINERS=0 NGINX_UI_ISOLATED=1 NGINX_UI_BIN="$s/$b" bash "$SELF" check 2>&1)"; rc=$?
        tail -n +3 <<<"$out"
        [[ $rc -eq 0 ]] || bad_rc=1
    done
    return "$bad_rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$NGINXUI_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local rc=0 found=0 bin ver pver sig st declared="${NGINX_UI_VERSION:-}"
    step "Looking for nginx-ui"
    local -a bins=(); local -A seen=()
    while IFS= read -r bin; do [[ -n "$bin" && -z "${seen[$bin]:-}" ]] && { seen[$bin]=1; bins+=("$bin"); }; done < <(find_binaries)
    local -a imgs=(); local img rt tag
    for rt in docker podman; do
        have "$rt" || continue
        [[ -z "${NGINX_UI_ISOLATED:-}" ]] || continue
        while IFS= read -r img; do [[ -n "$img" ]] && imgs+=("$img"); done < <("$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)uozi/nginx-ui:' | sort -u)
    done
    for img in "${imgs[@]:-}"; do
        [[ -n "$img" ]] || continue
        found=$((found+1)); step "nginx-ui image ${img}"
        tag="${img##*:}"; tag="${tag#v}"
        if [[ "$tag" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
            st="$(nui_status "$tag")"
            if [[ "$st" == affected ]]; then bad "image tag ${tag} is not a release of 2.4.1 or later: authenticated users can bypass the restricted-directive check (CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319). Pull 2.4.1 or later and recreate the container"; rc=1
            else ok "image tag ${tag} is 2.4.1 or later"; fi
        else
            caution "the tag '${tag}' does not name a version, and the version inside the image cannot be read from outside: confirm it in the web interface, or pull a tag of 2.4.1 or later and recreate the container"; rc=1
        fi
        inf "an image on disk is not necessarily a running container"
    done
    if [[ ${#bins[@]} -eq 0 ]]; then
        if [[ ${#imgs[@]} -gt 0 ]]; then :
        elif [[ -n "$declared" ]]; then
            found=$((found+1)); step "nginx-ui version supplied in NGINX_UI_VERSION (${declared})"
            local dv="${declared#v}"; dv="${dv// /}"
            if [[ "$(nui_status "$dv")" == unknown ]]; then caution "'${declared}' is not a version this script can compare: update to 2.4.1 or later to be safe"; rc=1
            elif [[ "$(nui_status "$dv")" == affected ]]; then bad "nginx-ui ${declared} is below 2.4.1: authenticated users can bypass the restricted-directive check (CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319). Update to 2.4.1 or later"; rc=1
            else ok "version ${declared} is 2.4.1 or later (no binary was found on this host to confirm)"; fi
        else
            info "No nginx-ui found (binary: PATH locations, the systemd unit and running processes; images: uozi/nginx-ui; set NGINX_UI_BIN if it is elsewhere)"
            return 0
        fi
    fi
    pver="$(package_version)"
    for bin in "${bins[@]}"; do
        found=$((found+1))
        step "nginx-ui at ${bin}"
        ver="${declared:-$pver}"
        sig="$(binary_signature "$bin")"
        [[ -n "$ver" ]] && inf "version ${ver} (from ${declared:+NGINX_UI_VERSION}${declared:-the package})" || inf "no version available from the environment or a package"
        inf "binary signature: ${sig}"
        st="unknown"; [[ -n "$ver" ]] && st="$(nui_status "$ver")"
        if [[ "$st" == affected && "$sig" == yes ]]; then
            caution "version ${ver} is below 2.4.1, but the binary contains the 2.4.1 validator names: the version you supplied may be stale; confirm in the web interface"; rc=1
        elif [[ "$st" == fixed && "$sig" == no ]]; then
            caution "version ${ver} is 2.4.1 or later, but the binary lacks the 2.4.1 validator names: the files do not match the version"; rc=1
        elif [[ "$sig" == no || "$st" == affected ]]; then
            bad "nginx-ui is below 2.4.1: authenticated users can bypass the restricted-directive check (CVE-2026-84316, CVE-2026-84317, CVE-2026-84318, CVE-2026-84319). Update to 2.4.1 or later"; rc=1
        elif [[ "$sig" == yes ]]; then
            ok "the binary carries the 2.4.1 validator; this is a string match, so confirm the version in the web interface"
        elif [[ "$st" == fixed ]]; then
            ok "version ${ver} is 2.4.1 or later (the binary could not be read to confirm)"
        else
            caution "cannot tell the version or read the binary: update to 2.4.1 or later to be safe"; rc=1
        fi
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No exposed nginx-ui found (${found} checked)."
    else
        warn "nginx-ui exposed or unclear. Update to 2.4.1 or later, then run: $0 hunt"
        inf "Until then (the project's suggestion, not the vendor's): limit who has an nginx-ui account, keep it off untrusted networks, and do not give secondary users write access"
        inf "Advisories: GHSA-cf23-7qxj-xmhr, GHSA-76pm-mq2q-9gcr, GHSA-9jww-cxg5-rj9m"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local rc=0 f d nread=0 n
    local d_re='(load_module|js_import|js_content|js_include|js_set|js_var|js_path|perl_require|perl_modules|perl_set|perl|user[[:space:]]+root)'
    local bypass_re=";[[:space:]]*${d_re}([[:space:]]|;|\$)"
    step "Hunting for the restricted-directive bypass in nginx configuration"
    local -a confs=()
    # shellcheck disable=SC2086
    for d in ${NGINX_UI_CONF_DIRS:-/etc/nginx /etc/angie /usr/local/etc/nginx /usr/local/nginx/conf}; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do confs+=("$f"); done < <(find "$d" -xdev -maxdepth 8 -type f -size -2000k 2>/dev/null | sort -u)
    done
    if [[ ${#confs[@]} -eq 0 ]]; then inf "no nginx configuration found in the usual paths"; fi
    for f in "${confs[@]:-}"; do
        [[ -r "$f" ]] || continue
        nread=$((nread+1))
        n="$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ec "$bypass_re")"
        if [[ "${n:-0}" -gt 0 ]]; then
            bad "${f}: ${n} line(s) with a restricted directive after a semicolon (the CVE-2026-84316 shape):"
            grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -E "$bypass_re" | head -n 3 | cut -c1-160 | sed 's/^/        /'
            rc=1
        fi
    done
    [[ $nread -gt 0 ]] && inf "read ${nread} configuration file(s)"
    # restricted directives in plain form: review, not proof (administrators use njs too)
    local review=0
    for f in "${confs[@]:-}"; do
        [[ -r "$f" ]] || continue
        n="$(grep -vE '^[[:space:]]*#' "$f" 2>/dev/null | grep -Ec "^[[:space:]]*${d_re}([[:space:]]|;)")"
        if [[ "${n:-0}" -gt 0 ]]; then
            [[ $review -eq 0 ]] && inf "restricted directives present in plain form (review each: legitimate njs or Perl use looks the same):"
            review=1; inf "  ${f}: ${n} line(s)"
        fi
    done
    [[ $review -eq 0 && $nread -gt 0 ]] && ok "no restricted directive found in any readable configuration file"
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No strong lead found."
        inf "The MCP paths (84317, 84318, 84319) write ordinary-looking directives, so a clean result does not rule them out: compare configuration against your own records"
    else
        warn "Suspicious nginx configuration found. If you did not put it there, treat the nginx worker as possibly compromised: remove it, reload nginx, rotate nginx-ui credentials and review who has accounts."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-84316, CVE-2026-84317, CVE-2026-84318 and CVE-2026-84319 (nginx-ui restricted-directive bypass); fixed in 2.4.1"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
