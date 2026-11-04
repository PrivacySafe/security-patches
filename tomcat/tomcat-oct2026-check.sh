#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Tomcat October 2026: request/response mix-up checker  (v1)
# CVE-2026-103119 (AJP response mix-up, 11.0.x)
# CVE-2026-101356 (HTTP/2 request and response mix-up, 9.0 / 10.1 / 11.0)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Two Apache Tomcat bugs disclosed on 20 October 2026 can hand one user's
# response, or part of it, to another user.
#
#   CVE-2026-103119  A buffer under-read means a large non-blocking write over
#                    AJP can split the response body between the current request
#                    and the next request on the same connection.
#                    Affected: 11.0.0-M25 through 11.0.26.  Fixed: 11.0.27.
#   CVE-2026-101356  Incorrect object recycling in HTTP/2 handling of
#                    asynchronous servlets can mix up requests or responses
#                    between users.
#                    Affected: 11.0.22 - 11.0.26, 10.1.55 - 10.1.60,
#                    9.0.118 - 9.0.122.  Fixed: 11.0.27, 10.1.61, 9.0.123.
#
# "check" is read-only; "mitigate" and "rollback" are the only commands that change
# anything. "check" finds Tomcat installs, reads the exact version
# from lib/catalina.jar, and reads server.xml to see whether the AJP connector
# and HTTP/2 are switched on. It never starts or stops Tomcat.
#
# Usage:
#   ./tomcat-oct2026-check.sh [command] [CATALINA_HOME ...]
#
#   check (default)  find installs (CATALINA_HOME, CATALINA_BASE, running
#                    processes, and common paths such as /opt/tomcat*,
#                    /usr/share/tomcat*, /usr/local/tomcat) or use the
#                    directories you pass. Exit 0 = nothing exposed, 1 = an
#                    affected version is exposed or its config could not be read.
#   mitigate --ajp | --http2 [...]   (root) changes the host. The protective measures from
#                    the README, applied to server.xml. With no option it applies --http2,
#                    the low-impact measure; --ajp is added on request because it can break
#                    something:
#                      --ajp     comments out every AJP Connector. Only for 11.x below
#                                11.0.27 (CVE-2026-103119). Anything that reaches
#                                Tomcat over AJP (Apache mod_proxy_ajp or mod_jk) stops
#                                working: move it to HTTP proxying first.
#                      --http2   comments out every UpgradeProtocol element for HTTP/2.
#                                Only for 11.0.22-11.0.26, 10.1.55-10.1.60 and
#                                9.0.118-9.0.122 (CVE-2026-101356). Clients that talk
#                                HTTP/2 straight to Tomcat fall back to HTTP/1.1; a
#                                proxy in front can still speak HTTP/2 to them.
#                    Elements are commented out, never deleted. server.xml is copied
#                    first and checked with xmllint (or python3) before and after; if
#                    the result is not well-formed the original is put back at once.
#                    Nothing is restarted unless you add --restart (Tomcat reads
#                    server.xml at start; a restart ends requests in progress).
#                    Other options: --dry-run, --restart, and CATALINA_HOME
#                    directories to use instead of discovery. These are our
#                    measures from PrivacySafe; the permanent fix is the upgrade.
#   rollback [--dry-run] [--restart]   put back every file mitigate changed.
#   version          print the script version.
#
# STATE_DIR (default /var/lib/psf-security-patches/tomcat) holds the backups and manifest.
#
# Running docker and podman containers are inspected too (see "Containers" below). An image that is
# not running is not: check its tag against the fixed versions.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="tomcat-oct2026-check.sh"
SCRIPT_VERSION="1.0.1"
SCRIPT_DATE="2026-11-03"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/tomcat}"

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
# CVE-2026-103119: any 11.x below 11.0.27 (11.0.0-M1 to M24 are not listed as
# affected, but those are old development milestones and are treated as affected).
ajp_affected() {
    local v; v="$(norm_ver "$1")"
    [[ "${v%%.*}" == "11" ]] && ver_lt "$v" "11.0.27"
}
# CVE-2026-101356: exact ranges per branch.
h2_affected() {
    local v; v="$(norm_ver "$1")"
    case "$v" in
        11.*)   ver_ge "$v" "11.0.22" && ver_lt "$v" "11.0.27" ;;
        10.1.*) ver_ge "$v" "10.1.55" && ver_lt "$v" "10.1.61" ;;
        9.0.*)  ver_ge "$v" "9.0.118" && ver_lt "$v" "9.0.123" ;;
        *)      return 1 ;;
    esac
}

# ---------- helpers ----------------------------------------------------------
strip_xml_comments() {
    if have perl; then perl -0pe 's/<!--.*?-->//gs' "$1"
    elif have python3; then
        python3 -c 'import re,sys;sys.stdout.write(re.sub(r"<!--.*?-->","",open(sys.argv[1],errors="replace").read(),flags=re.S))' "$1"
    else cat "$1"; fi
}

jar_read() {   # jar entry
    if have unzip; then unzip -p "$1" "$2" 2>/dev/null
    elif have python3; then
        python3 -c 'import sys,zipfile;sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read(sys.argv[2]).decode("utf-8","replace"))' "$1" "$2" 2>/dev/null
    else return 1; fi
}

tomcat_version() {   # CATALINA_HOME -> version or nothing
    local home="$1" jar v=""
    for jar in "$home/lib/catalina.jar" "$home/server/lib/catalina.jar"; do
        [[ -r "$jar" ]] || continue
        v="$(jar_read "$jar" org/apache/catalina/util/ServerInfo.properties \
             | sed -n 's/^server\.info=Apache Tomcat\/\([^ ]*\).*/\1/p' | head -n1)"
        [[ -n "$v" ]] && { echo "$v"; return; }
    done
    if [[ -r "$home/RELEASE-NOTES" ]]; then
        v="$(sed -n 's/^ *Apache Tomcat Version \([0-9][^ ]*\).*/\1/p' "$home/RELEASE-NOTES" | head -n1)"
        [[ -n "$v" ]] && echo "$v"
    fi
    return 0
}

PROC_BASES=""
discover_roots() {
    local -a out=()
    local d p
    for d in "${CATALINA_HOME:-}" "${CATALINA_BASE:-}"; do [[ -n "$d" ]] && out+=("$d"); done
    if have ps; then
        while read -r p; do [[ -n "$p" ]] && out+=("$p"); done \
            < <(ps -eo args 2>/dev/null | grep -oE -- '-Dcatalina\.home=[^ ]+' | cut -d= -f2- | sort -u)
        PROC_BASES="$(ps -eo args 2>/dev/null | grep -oE -- '-Dcatalina\.base=[^ ]+' | cut -d= -f2- | sort -u | tr '\n' ' ')"
    fi
    shopt -s nullglob
    for d in /opt/tomcat* /opt/apache-tomcat* /opt/*/tomcat* /opt/*/apache-tomcat* \
             /usr/share/tomcat* /usr/local/tomcat* /usr/local/apache-tomcat* \
             /srv/tomcat* /srv/apache-tomcat* /var/lib/tomcat* \
             /home/*/apache-tomcat* /home/*/tomcat*; do
        [[ -d "$d" ]] && out+=("$d")
    done
    shopt -u nullglob
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

conf_candidates() {   # CATALINA_HOME -> readable server.xml paths
    local root="$1" b f base
    b="$(basename "$root")"
    {
        echo "$root/conf/server.xml"
        echo "/etc/$b/server.xml"
        echo "/var/lib/$b/conf/server.xml"
        [[ -n "${CATALINA_BASE:-}" ]] && echo "${CATALINA_BASE}/conf/server.xml"
        for base in $PROC_BASES; do echo "$base/conf/server.xml"; done
    } | awk '!s[$0]++' | while read -r f; do [[ -r "$f" ]] && echo "$f"; done
    return 0
}

AJP_FOUND=0; AJP_DETAIL=""; H2_FOUND=0
analyze_conf() {   # server.xml -> sets AJP_FOUND, AJP_DETAIL, H2_FOUND
    local flat t port addr sec
    flat="$(strip_xml_comments "$1" | tr '\n\t' '  ' | tr "'" '"')"
    while IFS= read -r t; do
        [[ -n "$t" ]] || continue
        if grep -qiE 'protocol="(AJP/1\.3|AJPS|org\.apache\.coyote\.ajp\.[A-Za-z0-9]+)"' <<<"$t"; then
            AJP_FOUND=1
            port="$(sed -n 's/.* port="\([0-9]*\)".*/\1/p' <<<"$t")"
            addr="$(sed -n 's/.*address="\([^"]*\)".*/\1/p' <<<"$t")"
            sec="secret not set"
            grep -qE 'secret(Required)?="' <<<"$t" && sec="secret configured"
            grep -qE 'secretRequired="false"' <<<"$t" && sec="secretRequired=false"
            AJP_DETAIL+="port ${port:-8009}, address ${addr:-default}, ${sec}; "
        fi
    done < <(grep -oE '<Connector[^>]*>' <<<"$flat" || true)
    grep -qE '<UpgradeProtocol[^>]*Http2Protocol' <<<"$flat" && H2_FOUND=1
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

TOMCAT_PROBE="$(cat <<'EOS'
find /opt /usr/local /usr/share /srv /var/lib -maxdepth 4 -path "*/lib/catalina.jar" -type f 2>/dev/null | head -n 10 | while read -r l; do
  h=${l%/lib/catalina.jar}
  if [ "$(wc -c < "$l")" -lt 8000000 ]; then echo "F $l"; fi
  [ -f "$h/RELEASE-NOTES" ] && echo "F $h/RELEASE-NOTES"
  [ -f "$h/conf/server.xml" ] && echo "B $h/conf/server.xml $(sed -E 's/((Pass|pass|secret|Secret)[A-Za-z]*=")[^"]*"/\1REDACTED"/g' "$h/conf/server.xml" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Tomcat in one container, judged by this script run in isolation
    local s="$1" out rc l; local -a homes=()
    while IFS= read -r l; do [[ -n "$l" ]] && homes+=("${l%/lib/catalina.jar}"); done < <(find "$s" -path '*/lib/catalina.jar' -type f 2>/dev/null)
    [[ ${#homes[@]} -gt 0 ]] || return 0
    step "Tomcat in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "${homes[@]}" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$TOMCAT_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a roots=()
    local rc=0 found=0 root ver f ajp_v h2_v conf_read
    if [[ $# -gt 0 ]]; then
        roots=("$@")
    else
        while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(discover_roots)
    fi
    step "Looking for Apache Tomcat installs"
    if [[ ${#roots[@]} -eq 0 ]]; then
        info "No Tomcat install found on this host (try passing CATALINA_HOME as an argument)"
        return 0
    fi
    for root in "${roots[@]}"; do
        [[ -d "$root" ]] || { caution "${root}: not a directory"; continue; }
        ver="$(tomcat_version "$root")"
        if [[ -z "$ver" ]]; then
            [[ $# -gt 0 ]] && caution "${root}: version not found (no lib/catalina.jar or RELEASE-NOTES)"
            continue
        fi
        found=$((found+1))
        step "Tomcat ${ver} at ${root}"
        ajp_v=0; h2_v=0
        ajp_affected "$ver" && ajp_v=1
        h2_affected "$ver" && h2_v=1
        if [[ $ajp_v -eq 0 && $h2_v -eq 0 ]]; then
            ok "version ${ver} is outside the affected ranges of CVE-2026-103119 and CVE-2026-101356"
            continue
        fi
        [[ $ajp_v -eq 1 ]] && bad "CVE-2026-103119 (AJP response mix-up): ${ver} is affected, fixed in 11.0.27"
        [[ $h2_v -eq 1 ]]  && bad "CVE-2026-101356 (HTTP/2 mix-up): ${ver} is affected, fixed in 11.0.27, 10.1.61 or 9.0.123"

        local jar="${root}/lib/catalina.jar"
        if distro_mentions "$jar" CVE-2026-103119 CVE-2026-101356; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this install and its changelog does not mention either CVE yet"
        fi

        AJP_FOUND=0; AJP_DETAIL=""; H2_FOUND=0; conf_read=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            conf_read=1
            analyze_conf "$f"
            inf "read ${f}"
        done < <(conf_candidates "$root")
        if [[ $conf_read -eq 0 ]]; then
            caution "server.xml not found or not readable: exposure cannot be decided, treating as exposed"
            rc=1; continue
        fi
        local exposed=0
        if [[ $ajp_v -eq 1 ]]; then
            if [[ $AJP_FOUND -eq 1 ]]; then
                bad "AJP connector is ACTIVE (${AJP_DETAIL%; }): exposed to CVE-2026-103119"; exposed=1
            else
                ok "no active AJP connector in server.xml: CVE-2026-103119 is not reachable here"
            fi
        fi
        if [[ $h2_v -eq 1 ]]; then
            if [[ $H2_FOUND -eq 1 ]]; then
                bad "HTTP/2 is ENABLED (UpgradeProtocol Http2Protocol): exposed to CVE-2026-101356 wherever asynchronous servlets are used"; exposed=1
            else
                ok "HTTP/2 is not enabled on a Connector: CVE-2026-101356 is not reachable here"
            fi
        fi
        if [[ $exposed -eq 1 ]]; then rc=1
        else caution "affected version but not exposed per server.xml: still upgrade, the config could change"; fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Tomcat version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Tomcat found (${found} install(s) checked)"
    else
        warn "Exposed or unverifiable Tomcat found. Upgrade to 11.0.27, 10.1.61 or 9.0.123 and restart."
        inf "PrivacySafe recommendation: for AJP, disable the AJP connector and proxy over HTTP instead."
        inf "PrivacySafe recommendation: for HTTP/2, remove the UpgradeProtocol element and let the front proxy speak HTTP/1.1 to Tomcat."
        inf "Advisories: https://www.openwall.com/lists/oss-security/2026/10/20/28 and .../27"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------

# ---------- mitigate and rollback --------------------------------------------
read -r -d '' AWK_XML_FIX <<'AWKEOF'
function tag_end(s, from,    i, c, q) {      # index of the ">" that ends the start tag, quotes respected
    q = ""
    for (i = from; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (q != "") { if (c == q) q = ""; continue }
        if (c == "\"" || c == "'") { q = c; continue }
        if (c == ">") return i
    }
    return 0
}
function wrap(elem, cve, what) {
    return "<!-- psf-security-patches " cve ": " what " (rollback restores the original) " elem " -->"
}
{ txt = txt $0 "\n" }
END {
    out = ""; i = 1; n = length(txt)
    while (i <= n) {
        rest = substr(txt, i)
        c = index(rest, "<!--"); k = index(rest, "<Connector"); u = index(rest, "<UpgradeProtocol")
        p = 0; kind = ""
        if (c > 0)                 { p = c; kind = "c" }
        if (k > 0 && (p == 0 || k < p)) { p = k; kind = "k" }
        if (u > 0 && (p == 0 || u < p)) { p = u; kind = "u" }
        if (p == 0) { out = out rest; break }
        out = out substr(rest, 1, p - 1)
        rest = substr(rest, p)
        if (kind == "c") {
            e = index(rest, "-->")
            if (e == 0) { out = out rest; break }
            out = out substr(rest, 1, e + 2); i = i + p - 1 + e + 2; continue
        }
        te = tag_end(rest, 1)
        if (te == 0) { out = out rest; break }
        tagtxt = substr(rest, 1, te)
        selfclose = (substr(tagtxt, length(tagtxt) - 1, 1) == "/")
        elem = tagtxt; elen = te
        if (!selfclose) {
            close_tag = (kind == "k") ? "</Connector>" : "</UpgradeProtocol>"
            ce = index(rest, close_tag)
            if (ce > 0) { elem = substr(rest, 1, ce + length(close_tag) - 1); elen = ce + length(close_tag) - 1 }
        }
        do_wrap = 0
        lt = tolower(tagtxt)
        if (kind == "k" && ajp && lt ~ /protocol[ \t\n]*=[ \t\n]*["'](ajp\/1\.3|ajps|org\.apache\.coyote\.ajp\.[a-z0-9]+)["']/) { do_wrap = 1; cve = "CVE-2026-103119"; what = "AJP connector disabled" }
        if (kind == "u" && http2 && index(tagtxt, "Http2Protocol") > 0) { do_wrap = 1; cve = "CVE-2026-101356"; what = "HTTP/2 upgrade disabled" }
        if (do_wrap && index(elem, "--") > 0) { print "SKIP " cve > "/dev/stderr"; do_wrap = 0 }
        if (do_wrap) { out = out wrap(elem, cve, what); i = i + p - 1 + elen }
        else { out = out tagtxt; i = i + p - 1 + te }
    }
    printf "%s", out
}
AWKEOF

TM_MANIFEST=""; TM_DRY=0; TM_RESTART=0
tm_run() { if [[ "$TM_DRY" -eq 1 ]]; then echo "  would run: $*"; return 0; fi; "$@"; }
tm_xml_ok() {   # file -> 0 when well-formed
    if have xmllint; then xmllint --noout "$1" >/dev/null 2>&1
    elif have python3; then python3 -c 'import sys,xml.dom.minidom as m; m.parse(sys.argv[1])' "$1" >/dev/null 2>&1
    else return 2; fi
}
tm_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$TM_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$TM_MANIFEST"
}
tm_restart() {
    [[ "$TM_RESTART" -eq 1 ]] || return 0
    local u did=0
    if have systemctl; then
        for u in $(systemctl list-unit-files 2>/dev/null | awk '/^tomcat[^ ]*\.service/{print $1}'); do tm_run systemctl restart "$u" && inf "restarted ${u}"; did=1; done
    fi
    [[ $did -eq 1 ]] || caution "--restart given but no tomcat systemd unit found: restart Tomcat yourself"
}

cmd_mitigate() {
    local ajp=0 http2=0 root ver f n t1 rc=0 changed=0 skipped=0 line sk
    local -a roots=() posroots=()
    TM_DRY=0; TM_RESTART=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ajp) ajp=1 ;; --http2) http2=1 ;; --dry-run) TM_DRY=1 ;; --restart) TM_RESTART=1 ;;
            -*) die "Unknown mitigate option: $1 (--ajp --http2 --dry-run --restart)" ;;
            *) posroots+=("$1") ;;
        esac
        shift
    done
    local defaulted=0
    if [[ $ajp -eq 0 && $http2 -eq 0 ]]; then http2=1; defaulted=1; fi
    [[ $TM_DRY -eq 1 ]] || need_root "mitigate changes the host"
    have xmllint || have python3 || die "need xmllint or python3 to check that server.xml is still well-formed afterwards: refusing to edit without it"
    if [[ ${#posroots[@]} -gt 0 ]]; then roots=("${posroots[@]}")
    else while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(discover_roots); fi
    [[ $defaulted -eq 0 ]] || info "No option given: applying --http2, the low-impact measure. Add --ajp for the AJP connector."
    step "Looking for Apache Tomcat installs"
    if [[ ${#roots[@]} -eq 0 ]]; then info "No Tomcat install found on this host (try passing CATALINA_HOME as an argument)"; return 0; fi
    if [[ $TM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        TM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$TM_MANIFEST"
    else TM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    for root in "${roots[@]}"; do
        [[ -d "$root" ]] || { caution "${root}: not a directory"; continue; }
        ver="$(tomcat_version "$root")"
        [[ -n "$ver" ]] || { caution "${root}: version not found, left alone"; continue; }
        step "Tomcat ${ver} at ${root}"
        local do_ajp=0 do_h2=0
        if [[ $ajp -eq 1 ]]; then
            if ajp_affected "$ver"; then do_ajp=1; else ok "${ver} is outside the range of CVE-2026-103119: no AJP change needed"; fi
        fi
        if [[ $http2 -eq 1 ]]; then
            if h2_affected "$ver"; then do_h2=1; else ok "${ver} is outside the range of CVE-2026-101356: no HTTP/2 change needed"; fi
        fi
        [[ $do_ajp -eq 1 || $do_h2 -eq 1 ]] || continue
        local nconf=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            nconf=$((nconf+1))
            if ! tm_xml_ok "$f"; then bad "${f}: not well-formed XML as it is now: left alone"; rc=1; continue; fi
            t1="$(mktemp "${TMPDIR:-/tmp}/tcxml.XXXXXX")" || { bad "no temp file"; return 1; }
            sk="$(awk -v ajp="$do_ajp" -v http2="$do_h2" "$AWK_XML_FIX" "$f" 2>&1 >"$t1" | grep -c '^SKIP')"
            if [[ "${sk:-0}" -gt 0 ]]; then caution "${f}: ${sk} element(s) contain '--' and cannot be commented out safely: edit them by hand"; skipped=1; fi
            if cmp -s "$f" "$t1"; then inf "${f}: nothing to change"; rm -f "$t1"; continue; fi
            n=$(diff "$f" "$t1" | grep -c '^>')
            if [[ $TM_DRY -eq 1 ]]; then
                echo "  would comment out element(s) in ${f} (${n} new line(s)):"; diff "$f" "$t1" | grep '^>' | sed 's/^/      /' | cut -c1-150
            else
                if ! tm_backup "$f"; then bad "${f}: could not back it up, left alone"; rm -f "$t1"; rc=1; continue; fi
                cat "$t1" >"$f" || { rc=1; rm -f "$t1"; continue; }
                if tm_xml_ok "$f"; then ok "${f}: commented out the connector element(s); the file is still well-formed"; changed=1
                else
                    bad "${f}: the result is NOT well-formed XML: restoring the original now"
                    cat "$(grep -F "conf|${f}|" "$TM_MANIFEST" | head -n1 | sed 's/.*|//')" >"$f"; rc=1
                fi
            fi
            rm -f "$t1"
        done < <(conf_candidates "$root")
        [[ $nconf -gt 0 ]] || { caution "${root}: no readable server.xml found"; rc=1; }
    done
    tm_restart
    step "Result"
    if [[ $TM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $changed -eq 1 ]]; then
        info "server.xml changed. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $TM_RESTART -eq 1 ]] || inf "restart Tomcat for it to take effect (or re-run with --restart)"
    else info "Nothing needed changing"; fi
    [[ $skipped -eq 0 ]] || rc=1
    inf "These are PrivacySafe's measures; the permanent fix is to upgrade to 11.0.27, 10.1.61 or 9.0.123."
    return "$rc"
}

cmd_rollback() {
    local line f b rc=0
    TM_DRY=0; TM_RESTART=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) TM_DRY=1 ;; --restart) TM_RESTART=1 ;; *) die "Unknown rollback option: $1 (--dry-run --restart)" ;; esac
        shift
    done
    TM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$TM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $TM_DRY -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
        if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
        if [[ $TM_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi
    done <"$TM_MANIFEST"
    if [[ $TM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$TM_MANIFEST" "${TM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Restart Tomcat for the restored configuration to take effect."
    fi
    tm_restart
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-103119, CVE-2026-101356; fixed in Tomcat 11.0.27, 10.1.61, 9.0.123"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
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
