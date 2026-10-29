#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Amazon SageMaker Python SDK default_bucket() takeover: read-only checker  (v1)
# CVE-2026-112408
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The SDK's default_bucket() uses an S3 bucket named sagemaker-{region}-{AWS account ID}
# and, in affected versions, does not check that the bucket belongs to your account.
# Region and account ID are not secret, so another AWS account can pre-create a bucket
# with that name; the SDK then reads from and writes to the attacker's bucket, which can
# give the attacker code execution in your SageMaker execution environment and your IAM
# credentials. Amazon rates it 8.1 (CVSS 3.1); the CNA record also carries 9.4.
#
#   Affected: V2 before 2.257.3, and V3 (3.0.0) before 3.10.0
#   Fixed:    2.257.3 and 3.10.0 (both exist on PyPI). The fix adds an
#             ExpectedBucketOwner check to the SDK's S3 operations.
#   Bulletin: https://aws.amazon.com/security/security-bulletins/2026-142-aws/
#
# A separate flaw in the same releases (repository credentials written to CloudWatch
# Logs by git_utils) is fixed by the same upgrade; it is not counted separately here.
#
# This script is read-only and makes no AWS calls. It finds installed copies and pinned
# versions, and lists the Python files and notebooks that call default_bucket() so you
# know where the default bucket is relied on. It cannot tell whether someone has
# already pre-created your bucket name: see the manual check it prints.
#
# Usage:
#   ./sagemaker-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv /var/lib /home
#                    /root). Exit 0 = nothing affected, 1 = an affected SDK found.
#   version          print the script version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies the package metadata
# directories and the lock, requirements and environment files that mention sagemaker (index URLs
# and credentials are dropped inside the container) into a private temporary directory, and this
# script runs once per container in isolation against that copy. Paths shown as .../docker_NAME/...
# are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="sagemaker-check.sh"
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
# prints: vulnerable | fixed | unknown
sm_status() {
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    local major="${n%%.*}"
    if (( major <= 2 )); then ver_lt "$n" "2.257.3" && echo vulnerable || echo fixed
    else ver_lt "$n" "3.10.0" && echo vulnerable || echo fixed
    fi
}

# ---------- code that relies on the default bucket ---------------------------
scan_usage() {   # directories to search
    local f n=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        n=$((n+1)); [[ $n -le 8 ]] && inf "calls default_bucket(): ${f}"
    done < <(grep -rlE --include='*.py' --include='*.ipynb' 'default_bucket[[:space:]]*\(' "$@" 2>/dev/null \
                | grep -vE '/(site-packages|dist-packages|node_modules)/' | head -n 60)
    [[ $n -gt 8 ]] && inf "... and $((n-8)) more file(s) call default_bucket()"
    [[ $n -eq 0 ]] && inf "no Python file or notebook under the search directories calls default_bucket() directly (estimators and processors can still use it implicitly)"
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

SAGEMAKER_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/lib /home /root"
find $R -xdev -maxdepth 9 -type d \( -iname "sagemaker-*.dist-info" -o -iname "sagemaker-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do echo "D $d"; done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "poetry.lock" -o -name "uv.lock" -o -name "pdm.lock" -o -name "Pipfile.lock" \) -type f -print 2>/dev/null | head -n 60 | while read -r f; do
  grep -qi sagemaker "$f" 2>/dev/null && echo "F $f"
done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "requirements*.txt" -o -name "environment*.yml" \) -type f -print 2>/dev/null | head -n 100 | while read -r f; do
  grep -qi sagemaker "$f" 2>/dev/null && echo "B $f $(grep -viE '://|^[[:space:]]*(-i|--index-url|--extra-index-url)' "$f" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : SageMaker in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "SageMaker SDK in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$SAGEMAKER_PROBE"
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
    local rc=0 found=0 d base ver f pin line pkg st label
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/usr/lib /usr/local/lib /opt /srv /var/lib /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for the SageMaker Python SDK"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    declare -A seen=()
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        pkg="$(tr 'A-Z_' 'a-z-' <<<"${base%%-[0-9]*}")"
        [[ "$pkg" == sagemaker ]] || continue
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"
        [[ "$ver" =~ ^[0-9] ]] || continue
        ver="$(norm_ver "$ver")"
        found=$((found+1)); label="$(dirname "$d")"
        [[ -n "${seen[$d]:-}" ]] && continue; seen[$d]=1
        st="$(sm_status "$ver")"
        case "$st" in
            fixed)   ok "${label}: sagemaker ${ver} has the fix" ;;
            unknown) caution "${label}: cannot parse version '${ver}'" ;;
            *)       bad "${label}: sagemaker ${ver} is affected by CVE-2026-112408 (fixed in 2.257.3 and 3.10.0)"; rc=1 ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \( -iname 'sagemaker-*.dist-info' -o -iname 'sagemaker-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins, not installed copies)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        pin=""
        case "$(basename "$f")" in
            poetry.lock|uv.lock|pdm.lock)
                pin="$(awk '/^name = "sagemaker"/ {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
            Pipfile.lock)
                pin="$(awk '/"sagemaker": *\{/ {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
            *)
                line="$(grep -iE '^[[:space:]-]*sagemaker[[:space:]]*==' "$f" | head -n1)"
                [[ -n "$line" ]] && pin="$(sed -E 's/^[[:space:]-]*[A-Za-z_.-]+[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\1/' <<<"$line")" ;;
        esac
        [[ -n "$pin" ]] || continue
        found=$((found+1))
        st="$(sm_status "$pin")"
        case "$st" in
            fixed)   ok "${f}: sagemaker ${pin} pinned, has the fix" ;;
            unknown) caution "${f}: cannot parse pinned version '${pin}'" ;;
            *)       bad "${f}: sagemaker ${pin} pinned, affected by CVE-2026-112408 (fixed in 2.257.3 and 3.10.0)"; rc=1 ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock -o -name 'environment*.yml' \) -type f -print 2>/dev/null | sort -u)

    if [[ $found -gt 0 ]]; then
        step "Where the default bucket is relied on"
        scan_usage "${existing[@]}"
    fi
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No SageMaker Python SDK found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected SageMaker Python SDK found (${found} copy or pin checked)."
    else
        warn "Affected SageMaker Python SDK found. Upgrade: pip install --upgrade 'sagemaker>=2.257.3' (V2) or 'sagemaker>=3.10.0' (V3)."
        inf "Interim (ours, not the vendor's): pass an explicit bucket you own instead of relying on the default, and create the default bucket sagemaker-<region>-<account-id> yourself so no one else can."
        inf "Check by hand whether that name is already someone else's (needs the AWS CLI and read access; this script does not run it):"
        inf "    aws s3api head-bucket --bucket sagemaker-REGION-ACCOUNTID --expected-bucket-owner ACCOUNTID"
        inf "A 404 suggests the name is unclaimed and anyone could take it; a 403 usually means it exists under a different account (or that you lack permission). If it is someone else's, review what the SDK uploaded there."
        inf "Advisory: https://github.com/aws/sagemaker-python-sdk/security/advisories/GHSA-5rx8-8fr2-f855"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-112408; fixed in the SageMaker Python SDK 2.257.3 and 3.10.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
