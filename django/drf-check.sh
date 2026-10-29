#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Django REST framework October 2026: read-only checker  (v1)
# CVE-2026-114138 (Accept header CPU exhaustion)
# CVE-2026-114137 (TokenProxy.delete() revokes nothing)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Django REST framework (DRF) is the standard toolkit for building web APIs on
# Django. Both flaws are fixed in DRF 3.18.2.
#
# CVE-2026-114138  DefaultContentNegotiation accepts an unbounded number and size
#                  of Accept header tokens, and parses each one repeatedly for
#                  every renderer. A remote, unauthenticated client can send many
#                  distinct media types with large quoted parameters and burn
#                  about 19 seconds of CPU per request. Every API view does
#                  content negotiation, so any reachable endpoint is a target.
#                  CVSS 7.5. Affected: every release before 3.18.2 (the 0.x and
#                  2.x lines are not fixed upstream). The cost also involves
#                  Django's own header parameter parser, which Django fixed
#                  separately in 5.2.18, 6.0.9 and 6.1.2, so keep Django current
#                  as well.
#
# CVE-2026-114137  From 3.12.0 until 3.18.2, TokenProxy.delete() in
#                  rest_framework.authtoken uses the wrong primary key, so the
#                  delete matches no row and reports success. The token keeps
#                  working. DRF tokens do not expire, so code that revokes access
#                  through a TokenProxy instance leaves the access open
#                  indefinitely. CVSS 7.4. Only sites with rest_framework.authtoken
#                  installed are exposed, and DRF's own admin delete is not
#                  affected. Revocation done with Token.objects (not TokenProxy)
#                  works on every version.
#
# This script is read-only. It finds installed copies (dist-info and egg-info
# metadata) and declared pins (requirements, poetry.lock, uv.lock, pdm.lock,
# Pipfile.lock), notes where rest_framework.authtoken and TokenProxy appear in
# project source, and for installed copies compares the neighbouring Django.
#
# Usage:
#   ./drf-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv /var/www
#                    /var/lib /home /root). Exit 0 = nothing affected, 1 = an
#                    affected copy or pin was found.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="drf-check.sh"
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
drf_affected()      { ver_lt "$1" "3.18.2"; }                                  # CVE-2026-114138
drf_token_range()   { ver_ge "$1" "3.12.0" && ver_lt "$1" "3.18.2"; }          # CVE-2026-114137

# Django branches that carry the fix for the related header parser flaw
django_note() {   # version -> message on stdout when it needs attention
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || return 0
    case "$v" in
        5.2.*) ver_lt "$v" "5.2.18" && echo "Django ${v} is below 5.2.18, which fixes the related header-parsing flaw" ;;
        6.0.*) ver_lt "$v" "6.0.9"  && echo "Django ${v} is below 6.0.9, which fixes the related header-parsing flaw" ;;
        6.1.*) ver_lt "$v" "6.1.2"  && echo "Django ${v} is below 6.1.2, which fixes the related header-parsing flaw" ;;
        [0-4].*|5.0.*|5.1.*) echo "Django ${v} is an unsupported series: Django did not evaluate it for the related header-parsing flaw, so assume it is affected and move to a supported series" ;;
    esac
    return 0
}

authtoken_use() {   # project dir -> prints findings about authtoken and TokenProxy
    local dir="$1" hit proxy
    [[ -d "$dir" ]] || return 0
    hit="$(grep -rIl --include='*.py' --exclude-dir=node_modules --exclude-dir=site-packages --exclude-dir=dist-packages \
            --exclude-dir=.venv --exclude-dir=venv --exclude-dir=.git -e 'rest_framework.authtoken' "$dir" 2>/dev/null | head -n3)"
    if [[ -n "$hit" ]]; then
        caution "rest_framework.authtoken is referenced in this project, so CVE-2026-114137 applies (first matches: $(echo "$hit" | tr '\n' ' '))"
        proxy="$(grep -rIl --include='*.py' --exclude-dir=node_modules --exclude-dir=site-packages --exclude-dir=dist-packages \
                  --exclude-dir=.venv --exclude-dir=venv --exclude-dir=.git -e 'TokenProxy' "$dir" 2>/dev/null | head -n3)"
        [[ -n "$proxy" ]] && caution "TokenProxy is used in: $(echo "$proxy" | tr '\n' ' '): revocations made through it did nothing on an affected version"
    else
        inf "rest_framework.authtoken is not referenced in this project's Python files (CVE-2026-114137 does not apply unless it is installed some other way)"
    fi
}

TOKEN_REMEDIATE=0
report_version() {   # label version source [dist-info dir for Django] [project dir for authtoken] [probe file]
    local label="$1" ver="$2" src="$3" di="${4:-}" proj="${5:-}" probe="${6:-}" sd d dv note
    if ! is_semver "$ver"; then caution "${label}: cannot parse version '${ver}' (${src})"; return 0; fi
    if ! drf_affected "$ver"; then ok "${label}: Django REST framework ${ver} has both fixes (3.18.2 or newer)"; return 0; fi
    bad "${label}: Django REST framework ${ver} is affected by CVE-2026-114138 (Accept header CPU exhaustion, fixed in 3.18.2)"
    if drf_token_range "$ver"; then
        TOKEN_REMEDIATE=1
        caution "${label}: ${ver} is also in the range of CVE-2026-114137 (TokenProxy.delete() revokes nothing) if rest_framework.authtoken is installed"
    fi
    inf "source: ${src}"
    [[ -n "$proj" ]] && authtoken_use "$proj"
    if [[ -n "$di" ]]; then
        sd="$(dirname "$di")"
        d="$(find "$sd" -maxdepth 1 -type d -iname 'django-[0-9]*.dist-info' 2>/dev/null | head -n1)"
        if [[ -n "$d" ]]; then
            dv="$(basename "$d")"; dv="${dv#*-}"; dv="${dv%.dist-info}"
            note="$(django_note "$dv")"
            [[ -n "$note" ]] && caution "${note}"
        fi
    fi
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-114138 CVE-2026-114137; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            return 0
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this copy and its changelog does not mention either CVE yet"
        fi
    fi
    return 1
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

DRF_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root"
find $R -xdev -maxdepth 9 -type d \( -iname "djangorestframework-*.dist-info" -o -iname "djangorestframework-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do
  echo "D $d"; [ -f "$d/METADATA" ] && echo "E $d/METADATA"; [ -f "$d/PKG-INFO" ] && echo "E $d/PKG-INFO"
  sd=${d%/*}
  find "$sd" -maxdepth 1 -type d -iname "django-[0-9]*.dist-info" 2>/dev/null | head -n 1 | while read -r dj; do echo "D $dj"; done
done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "requirements*.txt" -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | head -n 200 | while read -r f; do
  grep -qi djangorestframework "$f" 2>/dev/null || continue
  echo "F $f"; d=${f%/*}
  find "$d" \( -name node_modules -o -name site-packages -o -name dist-packages -o -name .venv -o -name venv -o -name .git \) -prune -o -type f -name "*.py" -print 2>/dev/null | head -n 5000 | xargs -r grep -lE "rest_framework\.authtoken|TokenProxy" 2>/dev/null | head -n 6 | while read -r p; do echo "F $p"; done
done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$DRF_PROBE"
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
    step "Looking for Django REST framework"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi

    step "Installed copies (dist-info and egg-info metadata)"
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"
        [[ "$ver" =~ ^[0-9] ]] || continue          # skips djangorestframework-<other-package> names
        ver="$(norm_ver "$ver")"
        found=$((found+1))
        f="$d/METADATA"; [[ -r "$f" ]] || f="$d/PKG-INFO"; [[ -r "$f" ]] || f="$d"
        report_version "$(dirname "$d")" "$ver" "$d" "$d" "" "$f" || rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \
                \( -iname 'djangorestframework-*.dist-info' -o -iname 'djangorestframework-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins, not installed copies)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        pin=""
        case "$(basename "$f")" in
            poetry.lock|uv.lock|pdm.lock)
                pin="$(awk 'tolower($0) ~ /^name = "djangorestframework"/ {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
            Pipfile.lock)
                pin="$(awk 'tolower($0) ~ /"djangorestframework": *\{/ {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
            *)
                line="$(grep -iE '^[[:space:]]*djangorestframework[[:space:]]*==' "$f" | head -n1)"
                pin="$(sed -E 's/^[[:space:]]*[Dd]jangorestframework[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\1/' <<<"$line")"
                [[ -z "$line" ]] && pin="" ;;
        esac
        [[ -n "$pin" ]] || continue
        found=$((found+1))
        report_version "$f" "$pin" "pinned in $(basename "$f")" "" "$(dirname "$f")" "" || rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | sort -u)

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Django REST framework found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Django REST framework found (${found} copy or pin checked)"
    else
        warn "Affected Django REST framework found. Upgrade: pip install --upgrade 'djangorestframework>=3.18.2'  (check that your Django version is supported by 3.18.x)"
        inf "Interim for the Accept header flaw (ours, not vendor documented): reject unusually long Accept headers at the reverse proxy. In nginx, define map \$http_accept \$psf_bad_accept { default 0; \"~^.{1024,}\$\" 1; } in http{} and add if (\$psf_bad_accept) { return 406; } in the server block. Real Accept headers are far shorter."
        if [[ $TOKEN_REMEDIATE -eq 1 ]]; then
            inf "After upgrading, tokens you believed revoked through TokenProxy may still work. Tokens of deactivated users can be cleared with Token, not TokenProxy:"
            inf "  python manage.py shell -c \"from rest_framework.authtoken.models import Token; print(Token.objects.filter(user__is_active=False).delete())\""
            inf "For anyone else you meant to revoke, delete with Token.objects.filter(user=...).delete() and review who still holds a token."
        fi
        inf "Release: https://github.com/encode/django-rest-framework/releases/tag/3.18.2"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114138, CVE-2026-114137; fixed in Django REST framework 3.18.2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
