#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# LiteLLM proxy admin escalation: read-only checker  (v1)
# CVE-2026-114612 (CVSS 9.9, GHSA-7hp6-4w63-5g45)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The LiteLLM proxy uses one cryptographic context for two purposes: sealing secrets
# at rest and minting session tokens. An authenticated user with internal_user
# privileges can request a new API key with a crafted metadata field that holds a forged
# administrator credential as the "secret"; the proxy encrypts it and returns it, and the
# user replays it as a bearer token to become proxy_admin, which reaches arbitrary
# commands through the MCP stdio endpoint.
#
#   Affected (CVE record): 1.87.0 up to 1.100.4, 1.101.0 up to 1.101.3, 1.102.0 up to
#             1.102.2, 1.103.0 up to 1.103.1, and 1.104.0-rc.1 up to 1.104.0-rc.2
#   Fixed:    1.100.4, 1.101.3, 1.102.2, 1.103.1 and 1.104.0-rc.2 (all on PyPI), and
#             every later release. 1.87.0 through 1.99.x have no fixed release of their
#             own: move to 1.100.4 or newer.
#   Note:     The vendor advisory lists 1.91.0 as the first exploitable version; a
#             third-party reading says 1.87.0 to 1.90.x need EXPERIMENTAL_UI_LOGIN and
#             1.91.0 and later are exploitable by default. This script treats the whole
#             CVE range as affected.
#
# It is the PROXY that is affected. Using litellm only as a Python library (the SDK), with
# no proxy running, does not expose it; this script says which it found evidence of.
#
# DO NOT CONFUSE THIS WITH THE MALICIOUS RELEASE. litellm 1.107.0 is a different problem
# (a supply-chain compromise, see litellm-oct2026-check.sh in this folder). If this script
# meets 1.107.0 it says so and stops: treat that host as compromised.
#
# This script is read-only. It finds installed copies (dist-info), pinned versions
# (requirements, poetry.lock, uv.lock, pdm.lock, Pipfile.lock), and container image tags
# in compose, Helm and Kubernetes files, and looks for proxy evidence. It does not open
# running containers.
#
# Usage:
#   ./litellm-escalation-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv /var/lib /etc
#                    /home /root). Exit 0 = nothing exposed, 1 = an affected proxy, a
#                    floating image tag, or the malicious 1.107.0.
#   version          print the script version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies what this check reads
# (the package metadata, the lock and requirements files that mention litellm, a one-line marker for
# each proxy config, and only the matched image-tag strings) into a private temporary directory,
# and this script runs once per container in isolation against that copy. API keys, master keys
# and index credentials never leave the container. Paths shown as .../docker_NAME/... are inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="litellm-escalation-check.sh"
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
# prints: affected | fixed | notaffected | malicious | unknown
ll_status() {
    local raw="${1#v}" maj min pat pre prenum
    [[ "$raw" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(\.?(rc|a|b|alpha|beta)\.?([0-9]+))?$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; pre="${BASH_REMATCH[5]:-}"; prenum="${BASH_REMATCH[6]:-}"
    (( maj > 1 )) && { echo fixed; return; }
    (( maj < 1 )) && { echo notaffected; return; }
    [[ "$min" == 107 && "$pat" == 0 && -z "$pre" ]] && { echo malicious; return; }
    (( min < 87 )) && { echo notaffected; return; }
    (( min < 100 )) && { echo affected; return; }
    case "$min" in
        100) (( pat < 4 )) && echo affected || echo fixed ;;
        101) (( pat < 3 )) && echo affected || echo fixed ;;
        102) (( pat < 2 )) && echo affected || echo fixed ;;
        103) (( pat < 1 )) && echo affected || echo fixed ;;
        104) if (( pat == 0 )) && [[ -n "$pre" ]]; then
                 if [[ "$pre" == rc && "$prenum" -ge 2 ]]; then echo fixed; else echo affected; fi
             else echo fixed; fi ;;
        *) echo fixed ;;
    esac
}

# ---------- proxy evidence ---------------------------------------------------
proxy_evidence_site() {   # site-packages dir -> 0 if the proxy's web stack is installed beside litellm
    local s="$1"
    compgen -G "$s/fastapi-*.dist-info" >/dev/null && compgen -G "$s/uvicorn-*.dist-info" >/dev/null
}
proxy_config_files() {   # prints litellm proxy config files found under the search dirs
    grep -rlE --include='*.yaml' --include='*.yml' -e '^general_settings:' -e '^model_list:' "$@" 2>/dev/null \
        | grep -vE '/(site-packages|dist-packages|node_modules)/' | head -n 20
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

LITELLM_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/lib /etc /home /root /app"
find $R -xdev -maxdepth 9 -type d \( -iname "litellm-*.dist-info" -o -iname "litellm-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do
  echo "D $d"; s=${d%/*}
  for p in fastapi uvicorn; do find "$s" -maxdepth 1 -type d -iname "$p-*.dist-info" 2>/dev/null | head -n 1 | while read -r x; do echo "D $x"; done; done
done
find $R -xdev -maxdepth 9 -type f \( -name "*.yaml" -o -name "*.yml" \) -size -2000k 2>/dev/null | grep -vE "/(site-packages|dist-packages|node_modules)/" | head -n 4000 | xargs -r grep -lE "^(general_settings|model_list):" 2>/dev/null | head -n 20 | while read -r f; do echo "L $f general_settings:"; done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "poetry.lock" -o -name "uv.lock" -o -name "pdm.lock" -o -name "Pipfile.lock" \) -type f -print 2>/dev/null | head -n 60 | while read -r f; do
  grep -qi litellm "$f" 2>/dev/null && echo "F $f"
done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o -name "requirements*.txt" -type f -print 2>/dev/null | head -n 60 | while read -r f; do
  grep -qiE "litellm" "$f" 2>/dev/null && echo "B $f $(grep -viE '://|^[[:space:]]*(-i|--index-url|--extra-index-url)' "$f" | base64 | tr -d '\n')"
done
find $R -xdev -maxdepth 9 -type f \( -name "docker-compose*.y*ml" -o -name "compose*.y*ml" -o -name "values*.y*ml" -o -name "Dockerfile*" -o -name "*.env" -o -name "deployment*.y*ml" \) -size -2000k 2>/dev/null | head -n 200 | while read -r f; do
  t=$(grep -ohiE "berriai/litellm[A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+" "$f" 2>/dev/null | sort -u)
  [ -n "$t" ] && echo "B $f $(printf '%s\n' "$t" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : LiteLLM in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "LiteLLM in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$LITELLM_PROBE"
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
    local rc=0 found=0 d base ver f st pkg pin line site tag label cfg ncfg=0 any_proxy=0
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/usr/lib /usr/local/lib /opt /srv /var/lib /etc /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for the LiteLLM proxy"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    local cfgs; cfgs="$(proxy_config_files "${existing[@]}")"
    ncfg="$(grep -c . <<<"$cfgs")"
    [[ "$ncfg" -gt 0 ]] && { inf "LiteLLM-style proxy configuration found (model_list or general_settings):"; head -n 3 <<<"$cfgs" | sed 's/^/        /'; any_proxy=1; }

    report() {   # label version proxy-flag(0/1)
        local lab="$1" v="$2" prx="$3" s
        s="$(ll_status "$v")"
        case "$s" in
            malicious)   bad "${lab}: litellm ${v} is the MALICIOUS release (supply-chain compromise), not this CVE: stop and run litellm-oct2026-check.sh; treat the host as compromised"; rc=1 ;;
            fixed)       ok "${lab}: litellm ${v} has the fix" ;;
            notaffected) ok "${lab}: litellm ${v} is older than 1.87.0, before the affected code (very old: update anyway)" ;;
            unknown)     caution "${lab}: cannot parse version '${v}'"; rc=1 ;;
            affected)
                if [[ "$prx" == 1 || $any_proxy -eq 1 ]]; then
                    bad "${lab}: litellm ${v} is affected by CVE-2026-114612 and proxy evidence was found: an internal_user can become proxy_admin and run commands (fixed in 1.100.4, 1.101.3, 1.102.2, 1.103.1, 1.104.0-rc.2)"; rc=1
                else
                    caution "${lab}: litellm ${v} is in the affected range, but no proxy evidence was found (no fastapi and uvicorn beside it, no proxy config). The flaw is in the proxy: SDK-only use is not exposed, but upgrade anyway."
                fi
                local m="${v#*.}"; m="${m%%.*}"
                (( m < 91 )) && inf "1.87.0 to 1.90.x: a third-party reading says exploitation also needs EXPERIMENTAL_UI_LOGIN; the vendor lists 1.91.0 as the first exploitable release. Treated as affected." ;;
        esac
    }

    step "Installed copies (dist-info metadata)"
    declare -A seen=()
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        pkg="$(tr 'A-Z_' 'a-z-' <<<"${base%%-[0-9]*}")"
        [[ "$pkg" == litellm ]] || continue
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"
        [[ "$ver" =~ ^[0-9] ]] || continue
        [[ -n "${seen[$d]:-}" ]] && continue; seen[$d]=1
        found=$((found+1)); site="$(dirname "$d")"
        local prx=0; proxy_evidence_site "$site" && prx=1
        report "$site" "$ver" "$prx"
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \( -iname 'litellm-*.dist-info' -o -iname 'litellm-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        pin=""
        case "$(basename "$f")" in
            poetry.lock|uv.lock|pdm.lock) pin="$(awk '/^name = "litellm"/ {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
            Pipfile.lock) pin="$(awk '/"litellm": *\{/ {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
            *) line="$(grep -iE '^[[:space:]-]*litellm(\[[A-Za-z,_-]*\])?[[:space:]]*==' "$f" | head -n1)"
               [[ -n "$line" ]] && pin="$(sed -E 's/^[[:space:]-]*litellm(\[[A-Za-z,_-]*\])?[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\2/I' <<<"$line")" ;;
        esac
        [[ -n "$pin" ]] || continue
        found=$((found+1))
        local prx=0
        if grep -iE 'litellm\[[A-Za-z,_-]*proxy|^[[:space:]-]*(fastapi|uvicorn)[[:space:]]*(==|>=|$)|^name = "(fastapi|uvicorn)"' "$f" >/dev/null; then prx=1; fi
        report "$f" "$pin" "$prx"
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | sort -u)

    step "Container image tags (compose, Helm, Kubernetes, Dockerfiles)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        while IFS= read -r tag; do
            [[ -n "$tag" ]] || continue
            found=$((found+1))
            ver="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\.?rc\.?[0-9]+)?' <<<"$tag" | head -n1)"
            if [[ -n "$ver" ]]; then report "${f} (image ${tag})" "${ver/rc./rc}" 1
            else caution "${f}: image tag '${tag}' does not name a version (a floating tag): check which release the running container really is"; rc=1; fi
        done < <(grep -ohiE 'berriai/litellm[A-Za-z0-9_.-]*:[A-Za-z0-9_.-]+' "$f" 2>/dev/null | sed -E 's/^[^:]*://' | sort -u)
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' -o -name 'values*.y*ml' -o -name 'Dockerfile*' -o -name '*.env' -o -name 'deployment*.y*ml' \) -size -2000k 2>/dev/null | sort -u)

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No LiteLLM found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed LiteLLM proxy found (${found} copy, pin or image checked)."
    else
        warn "Exposed or unverifiable LiteLLM found. Upgrade to 1.100.4, 1.101.3, 1.102.2, 1.103.1 or 1.104.0-rc.2 or newer, on the line you run."
        inf "Never install 1.107.0: it is the malicious release. The last clean release before it is 1.106.2."
        inf "After upgrading, check the proxy's user list for administrators you did not create (ours, not the vendor's)."
        inf "Advisory: https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114612; fixed in LiteLLM 1.100.4, 1.101.3, 1.102.2, 1.103.1 and 1.104.0-rc.2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
