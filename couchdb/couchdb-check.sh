#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache CouchDB admin-to-OS-command execution: read-only checker  (v1)
# CVE-2026-86471
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# An unvalidated runtime configuration value in Apache CouchDB lets a CouchDB
# server admin run arbitrary shell commands as the operating system user that
# runs CouchDB. CVSS 9.3 on the v4 scale. The attacker needs server-admin
# credentials, so this is a privilege escalation from a CouchDB admin (a stolen
# or weak admin password, an exposed admin interface, or a compromised
# application that holds admin credentials) to the host. It is not a flaw an
# anonymous visitor can use alone.
#
#   Affected: Apache CouchDB 3.5.2 and earlier, on all platforms
#   Fixed:    3.5.3
#
# The same release fixes other CouchDB flaws, among them a pre-authentication
# gzip decompression bomb on POST /_session. That one needs no credentials, which
# is why it matters whether the node listens beyond localhost.
#
# This script is read-only. It reads the CouchDB version from the release files
# (releases/start_erl.data), the installed package, and, if you give it URLs, from
# a single unauthenticated GET of the server's root document. It reads the ini
# files for the bind address, require_valid_user and how many admin entries
# exist. It NEVER prints a value from the [admins] section (they are password
# hashes or passwords).
#
# Usage:
#   ./couchdb-check.sh [command] [URL ...]
#
#   check (default)  Exit 0 = nothing affected, 1 = an affected version was found.
#                    With URL arguments (such as http://10.0.0.5:5984/) it also
#                    asks each server for its version. Without arguments it asks
#                    only http://127.0.0.1:5984/ and ignores a refusal.
#   version          print the script version.
#
# Environment: COUCHDB_ROOT (default /opt/couchdb) and COUCHDB_ETC (space
# separated, default "/opt/couchdb/etc /etc/couchdb /usr/local/etc/couchdb")
# point the script at unusual layouts.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="couchdb-check.sh"
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
couch_affected() { ver_lt "$1" "3.5.3"; }

AFFECTED=0; CHECKED=0
report() {   # label version [probe file for the distribution check]
    local label="$1" ver="$2" probe="${3:-}"
    CHECKED=$((CHECKED+1))
    if ! is_semver "$(norm_ver "$ver")"; then caution "${label}: cannot parse version '${ver}'"; return 0; fi
    if ! couch_affected "$ver"; then ok "${label}: CouchDB ${ver} has the fix (3.5.3 or newer)"; return 0; fi
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-86471; then
            ok "${label}: CouchDB ${ver}, and package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: a backported fix is likely"
            return 0
        elif [[ $? -eq 1 ]]; then
            bad "${label}: CouchDB ${ver} is affected by CVE-2026-86471 (fixed in 3.5.3); package ${DISTRO_PKG} does not mention it"
            AFFECTED=$((AFFECTED+1)); return 0
        fi
    fi
    bad "${label}: CouchDB ${ver} is affected by CVE-2026-86471 (fixed in 3.5.3)"
    AFFECTED=$((AFFECTED+1))
}

# ini parsing: the last value wins across default.ini, local.ini and local.d/*.ini
ini_value() {   # section key files...
    local sec="$1" key="$2"; shift 2
    local f v=""
    for f in "$@"; do
        [[ -r "$f" ]] || continue
        v2="$(awk -v sec="[$sec]" -v key="$key" '
            /^[[:space:]]*[;#]/ {next}
            /^[[:space:]]*\[/ {s=$0; gsub(/[[:space:]]/,"",s); cur=s; next}
            cur==sec { line=$0; sub(/^[[:space:]]+/,"",line)
                       n=index(line,"="); if(n>0){k=substr(line,1,n-1); gsub(/[[:space:]]/,"",k)
                         if(k==key){val=substr(line,n+1); sub(/^[[:space:]]+/,"",val); sub(/[[:space:]]+$/,"",val); sub(/[[:space:]]*[;#].*$/,"",val); out=val}}}
            END{print out}' "$f")"
        [[ -n "$v2" ]] && v="$v2"
    done
    printf '%s' "$v"
}
ini_count() {   # section files... -> number of key = value lines (values are never printed)
    local sec="$1"; shift
    local f t=0 n
    for f in "$@"; do
        [[ -r "$f" ]] || continue
        n="$(awk -v sec="[$sec]" '
            /^[[:space:]]*[;#]/ {next}
            /^[[:space:]]*\[/ {s=$0; gsub(/[[:space:]]/,"",s); cur=s; next}
            cur==sec && /=/ {c++}
            END{print c+0}' "$f")"
        t=$((t+n))
    done
    echo "$t"
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

COUCHDB_PROBE="$(cat <<'EOS'
find /opt /usr/local /home /srv -maxdepth 4 -path "*/releases/start_erl.data" -type f 2>/dev/null | head -n 5 | while read -r l; do
  r=${l%/releases/start_erl.data}
  echo "F $l"
  for e in "$r/etc" /etc/couchdb /usr/local/etc/couchdb; do
    [ -d "$e" ] && find "$e" -maxdepth 2 -type f -name "*.ini" -size -512k 2>/dev/null | head -n 20 | while read -r p; do
      echo "B $p $(awk '/^\[/ {s=$0} s=="[admins]" && /=/ {sub(/=.*/,"= REDACTED"); print; next} {print}' "$p" | base64 | tr -d '\n')"
    done
  done
done
exit 0
EOS
)"

container_run() {   # <staged directory> : CouchDB in one container, judged by this script run in isolation
    local s="$1" out rc l r bad_rc=0; local -i n=0
    while IFS= read -r l; do
        [[ -n "$l" ]] || continue
        r="${l%/releases/start_erl.data}"; n=$((n + 1))
        step "CouchDB in a container (${s##*/}), ${r#"$s"}"
        out="$(SCAN_CONTAINERS=0 COUCHDB_ISOLATED=1 COUCHDB_ROOT="$r" COUCHDB_ETC="$r/etc $s/etc/couchdb $s/usr/local/etc/couchdb" bash "$SELF" check  2>&1)"; rc=$?
        tail -n +3 <<<"$out"
        [[ $rc -eq 0 ]] || bad_rc=1
    done < <(find "$s" -path '*/releases/start_erl.data' -type f 2>/dev/null)
    return "$bad_rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$COUCHDB_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local root="${COUCHDB_ROOT:-/opt/couchdb}"
    local -a urls=() inis=() etcs=()
    local erl f v d u body pv etc bind rvu na
    # versions on disk
    step "CouchDB installation"
    local found=0
    f="${root}/releases/start_erl.data"
    if [[ -r "$f" ]]; then
        v="$(awk '{print $2}' "$f" | head -n1)"
        [[ -n "$v" ]] && { found=1; report "${f}" "$v" "${root}/bin/couchdb"; }
    fi
    if [[ -d "${root}/releases" ]]; then
        for d in "${root}"/releases/[0-9]*; do
            [[ -d "$d" ]] || continue
            v="$(basename "$d")"
            [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
            # skip the one already reported from start_erl.data
            [[ -r "${root}/releases/start_erl.data" && "$(awk '{print $2}' "${root}/releases/start_erl.data")" == "$v" ]] && continue
            found=1; inf "also present: ${d} (an older release directory, not necessarily the running one)"
        done
    fi
    # package manager
    pv=""
    if have dpkg; then pv="$(dpkg-query -W -f='${Version}' couchdb 2>/dev/null)"; fi
    if [[ -z "$pv" ]] && have rpm; then pv="$(rpm -q --qf '%{VERSION}' couchdb 2>/dev/null | grep -v 'not installed')"; fi
    if [[ -n "$pv" ]]; then
        found=1
        v="$(norm_ver "$pv")"
        if [[ "$(norm_ver "$v")" == "$(awk '{print $2}' "${root}/releases/start_erl.data" 2>/dev/null | head -n1)" ]]; then
            inf "package version ${pv} matches the release files"
        else
            report "package couchdb ${pv}" "$v" ""
        fi
    fi
    # live server (read-only GET of the root document)
    if [[ $# -gt 0 ]]; then urls=("$@"); else urls=("http://127.0.0.1:5984/"); fi
    # a run staged from a container reads only the copied files: no package database, no live server
    if [[ -n "${COUCHDB_ISOLATED:-}" ]]; then urls=(); fi
    if [[ -n "${COUCHDB_ISOLATED:-}" ]]; then :
    elif have curl; then
        for u in "${urls[@]}"; do
            body="$(curl -fsS --max-time 4 "$u" 2>/dev/null)" || { [[ $# -gt 0 ]] && inf "${u}: no answer (down, filtered, or it requires a login)"; continue; }
            v="$(sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' <<<"$body" | head -n1)"
            if [[ -n "$v" && "$body" == *'"couchdb"'* ]]; then found=1; report "server at ${u}" "$v" ""; fi
        done
    else
        inf "curl not found: the live server was not asked for its version"
    fi
    [[ $found -eq 0 ]] && inf "no CouchDB found at ${root}, in the package database, or at the URL(s) probed"

    step "Configuration"
    read -r -a etcs <<<"${COUCHDB_ETC:-/opt/couchdb/etc /etc/couchdb /usr/local/etc/couchdb}"
    for etc in "${etcs[@]}"; do
        [[ -d "$etc" ]] || continue
        shopt -s nullglob
        for f in "$etc/default.ini" "$etc/default.d"/*.ini "$etc/local.ini" "$etc/local.d"/*.ini; do [[ -r "$f" ]] && inis+=("$f"); done
        shopt -u nullglob
    done
    if [[ ${#inis[@]} -eq 0 ]]; then
        inf "no readable CouchDB ini files (looked in: ${etcs[*]})"
    else
        inf "read ${#inis[@]} ini file(s) under: ${etcs[*]}"
        bind="$(ini_value chttpd bind_address "${inis[@]}")"
        rvu="$(ini_value chttpd require_valid_user "${inis[@]}")"
        na="$(ini_count admins "${inis[@]}")"
        case "$bind" in
            0.0.0.0|::|"[::]") caution "chttpd bind_address is ${bind}: CouchDB listens on every interface, so the unauthenticated /_session gzip flaw fixed in the same release is reachable by anyone who can connect" ;;
            127.0.0.1|localhost|::1) ok "chttpd bind_address is ${bind}: loopback only" ;;
            "") inf "chttpd bind_address not set in these files (the compiled default applies)" ;;
            *) inf "chttpd bind_address is ${bind}: confirm that address is not reachable from untrusted networks" ;;
        esac
        [[ "$rvu" == "true" ]] && inf "require_valid_user is true: anonymous requests are refused" \
            || inf "require_valid_user is not true: some endpoints answer without a login"
        inf "${na} entr(y/ies) in [admins] across these files (values are not read out); this CVE needs one of these credentials, or admin rights granted another way"
    fi

    step "Verdict"
    if [[ $CHECKED -eq 0 ]]; then
        info "No CouchDB version could be read"
    elif [[ $AFFECTED -eq 0 ]]; then
        info "No affected CouchDB found (${CHECKED} checked)"
    else
        warn "${AFFECTED} affected CouchDB instance(s) of ${CHECKED} checked. Upgrade to 3.5.3 or later."
        inf "Interim (ours, not vendor documented): keep port 5984 off untrusted networks, give admins long unique passwords, and do not let applications hold admin credentials they do not need."
        inf "After upgrading, rotate any admin password that may have been exposed."
        inf "Release information: https://couchdb.apache.org/"
    fi
    [[ $AFFECTED -eq 0 ]]
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-86471; fixed in Apache CouchDB 3.5.3"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
