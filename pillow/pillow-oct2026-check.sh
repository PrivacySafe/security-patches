#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Pillow 13.0.0 security release: read-only checker  (v1)
# CVE-2026-96639  (stale image storage reused after mode transitions, CVSS 9.8)
# CVE-2026-112900 (EPS filename argument injection into Ghostscript)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Pillow 13.0.0 (announced 21 October 2026) fixes a long list of memory-safety and
# parsing bugs in the most widely installed Python imaging library. Two of
# them are covered here.
#
#   CVE-2026-96639  Multi-frame loaders can keep an allocation made for a narrow
#                   frame mode while a later frame of the same size switches to
#                   wider RGB or CMYK data. Crafted PSD, MPO, DCX or MIC files
#                   then write past the allocation. The MPO path can also read
#                   out of bounds and, in demonstrated runtime-specific cases,
#                   run commands. Affected: 11.0.0 up to 13.0.0.
#   CVE-2026-112900 EpsImagePlugin passes the caller-supplied filename after -f
#                   to Ghostscript without making it absolute. A name that
#                   starts with a hyphen is read as a Ghostscript option, and a
#                   name that starts with @ names an argument file. Command
#                   execution needs the attacker to control the filename and
#                   the referenced text file. Affected: 2.6.0 up to 13.0.0.
#
# Fixed in 13.0.0 for both. This script is read-only: it finds Pillow in Python
# environments (installed dist-info and egg-info metadata) and in lock files,
# compares versions, and reports whether Ghostscript is installed, since the
# EPS bug needs the gs binary.
#
# Usage:
#   ./pillow-oct2026-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv
#                    /var/www /var/lib /home /root) for Pillow installs and
#                    lock file pins. Exit 0 = nothing affected, 1 = an affected
#                    version was found.
#   version          print the script version.
#
# Distribution packages often backport fixes without changing the version
# string. For packages owned by dpkg or rpm the script reads the package
# changelog and reports a mention of either CVE.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="pillow-oct2026-check.sh"
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
# CVE-2026-96639 affects 11.0.0 up to 13.0.0; CVE-2026-112900 affects 2.6.0 up to 13.0.0
affects_96639()  { ver_ge "$1" "11.0.0" && ver_lt "$1" "13.0.0"; }
affects_112900() { ver_ge "$1" "2.6.0"  && ver_lt "$1" "13.0.0"; }

GS_STATE=""
gs_info() {
    if have gs; then
        GS_STATE="installed ($(gs --version 2>/dev/null | head -n1))"
    else
        GS_STATE=""
    fi
}

report_version() {   # label version source [file for distro check]
    local label="$1" ver="$2" src="$3" probe="${4:-}" hit=0
    if ! is_semver "$ver"; then caution "${label}: cannot parse version '${ver}' (${src})"; return 0; fi
    # a copy staged from a container is judged by that container's Ghostscript (the probe leaves a
    # marker), not the host's
    local gsv="$GS_STATE" _ref _r
    if [[ -n "${STAGE:-}" ]]; then
        for _ref in "$label" "$src"; do
            if [[ "$_ref" == "$STAGE"/* ]]; then
                _r="${_ref#"$STAGE"/}"; _r="$STAGE/${_r%%/*}"
                if [[ -e "$_r/.gs_present" ]]; then gsv="installed in the container"; else gsv=""; fi
                break
            fi
        done
    fi
    local a96=0 a11=0
    affects_96639 "$ver" && a96=1
    affects_112900 "$ver" && a11=1
    if [[ $a96 -eq 0 && $a11 -eq 0 ]]; then
        if ver_lt "$ver" "13.0.0"; then
            ok "${label}: Pillow ${ver} predates both bugs (older than 2.6.0), but is far out of date"
        else
            ok "${label}: Pillow ${ver} is 13.0.0 or newer"
        fi
        return 0
    fi
    [[ $a96 -eq 1 ]] && bad "${label}: Pillow ${ver} is affected by CVE-2026-96639 (PSD, MPO, DCX, MIC files)"
    if [[ $a11 -eq 1 ]]; then
        if [[ -n "$gsv" ]]; then
            bad "${label}: Pillow ${ver} is affected by CVE-2026-112900 and Ghostscript is ${gsv}"
        else
            caution "${label}: Pillow ${ver} is affected by CVE-2026-112900 but no gs binary was found on PATH, so the EPS path is inert here"
        fi
    fi
    inf "source: ${src}"
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-96639 CVE-2026-112900; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            return 0
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this copy and its changelog does not mention either CVE yet"
        fi
    fi
    hit=1
    return "$hit"
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

PILLOW_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root"
find $R -xdev -maxdepth 9 -type d \( -iname "pillow-*.dist-info" -o -iname "pillow-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do
  echo "D $d"; [ -f "$d/METADATA" ] && echo "E $d/METADATA"; [ -f "$d/PKG-INFO" ] && echo "E $d/PKG-INFO"
done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "requirements*.txt" -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | head -n 200 | while read -r f; do
  grep -qi pillow "$f" 2>/dev/null && echo "F $f"
done
if command -v gs >/dev/null 2>&1; then echo "E /.gs_present"; fi
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$PILLOW_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d base ver f pin line
    if [[ $# -gt 0 ]]; then dirs=("$@")
    else dirs=(/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    gs_info
    step "Looking for Pillow"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    [[ -n "$GS_STATE" ]] && inf "Ghostscript is ${GS_STATE}" || inf "Ghostscript (gs) is not on PATH"

    step "Installed copies (dist-info and egg-info metadata)"
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"; ver="$(norm_ver "$ver")"
        found=$((found+1))
        f="$d/METADATA"; [[ -r "$f" ]] || f="$d/PKG-INFO"; [[ -r "$f" ]] || f="$d"
        report_version "$(dirname "$d")" "$ver" "$d" "$f" || rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \
                \( -iname 'pillow-*.dist-info' -o -iname 'pillow-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins, not installed copies)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        pin=""
        case "$(basename "$f")" in
            poetry.lock|uv.lock|pdm.lock)
                pin="$(awk 'tolower($0) ~ /^name = "pillow"/ {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
            Pipfile.lock)
                pin="$(awk 'tolower($0) ~ /"pillow": *\{/ {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
            *)
                line="$(grep -iE '^[[:space:]]*pillow[[:space:]]*==' "$f" | head -n1)"
                pin="$(sed -E 's/^[[:space:]]*[Pp]illow[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\1/' <<<"$line")"
                [[ -z "$line" ]] && pin="" ;;
        esac
        [[ -n "$pin" ]] || continue
        found=$((found+1))
        report_version "$f" "$pin" "pinned in $(basename "$f")" || rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | sort -u)

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Pillow found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Pillow found (${found} copy or pin checked)"
    else
        warn "Affected Pillow found. Upgrade: pip install --upgrade 'Pillow>=13.0.0'  (check your Python version is supported by 13.x)"
        inf "Stopgap for CVE-2026-96639: open untrusted files with an allowlist, Image.open(f, formats=['JPEG','PNG','GIF','WEBP']), which keeps PSD, MPO, DCX and MIC out."
        inf "Stopgap for CVE-2026-112900: refuse EPS input, or refuse any filename that starts with '-' or '@' before it reaches Pillow, or remove Ghostscript."
        inf "Pillow 13.0.0 notes: https://github.com/python-pillow/Pillow/blob/main/docs/releasenotes/13.0.0.rst"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-96639, CVE-2026-112900; fixed in Pillow 13.0.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
