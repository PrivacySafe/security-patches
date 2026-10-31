#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Jupyter Server and nbconvert October 2026: read-only checker  (v1)
# CVE-2026-114135 (Jupyter Server, gateway kernel authorization bypass)
# CVE-2026-114140 (nbconvert, path traversal file write)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-114135  Jupyter Server 2.0.0 up to 2.6.0. When GatewayClient.url is set,
#                  the normal kernel WebSocket handler is replaced by a gateway
#                  handler that authenticates the user but never asks the
#                  configured Authorizer whether that user may EXECUTE on kernels.
#                  A user the Authorizer denies can still open a kernel channel and
#                  send messages to the upstream kernel. CVSS 8.8. Fixed: 2.6.0.
#                  It only matters when BOTH are true: a gateway is configured, AND
#                  a restrictive Authorizer is in use. With the default
#                  AllowAllAuthorizer nobody is denied, so there is nothing to
#                  bypass. Even in 2.6.0 and later the bypass remains possible if a
#                  deployment manually registers the deprecated
#                  jupyter_server.gateway.handlers module.
#
# CVE-2026-114140  nbconvert 5.4.0 up to 7.17.2. ExtractOutputPreprocessor joins the
#                  attacker-controlled "filename" in a cell's output metadata to the
#                  output directory without checking the result, so converting a
#                  MALICIOUS NOTEBOOK to markdown, LaTeX, reStructuredText or
#                  AsciiDoc writes attacker-controlled data to arbitrary locations
#                  the victim can write to. Needs the victim to convert the notebook
#                  (user interaction). CVSS 8.8 (some trackers 9.0). Fixed: 7.17.2.
#
# This script is read-only. It finds installed copies (dist-info and egg-info) and
# declared pins (requirements, poetry.lock, uv.lock, pdm.lock, Pipfile.lock), and for
# Jupyter Server reads the Jupyter configuration files for GatewayClient.url and
# authorizer_class. It cannot see settings given only on the command line or in the
# environment (JUPYTER_GATEWAY_URL, --gateway-url): it reads the arguments of running
# jupyter processes for those, and says so when it cannot.
#
# Usage:
#   ./jupyter-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv /var/www
#                    /var/lib /home /root). Exit 0 = nothing exposed, 1 = an affected
#                    nbconvert, or an affected Jupyter Server with a gateway and a
#                    custom authorizer.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="jupyter-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
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

# ---------- version rules ----------------------------------------------------
server_status() {   # prints vulnerable | fixed | notaffected | unknown
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    ver_lt "$n" "2.0.0" && { echo notaffected; return; }
    ver_lt "$n" "2.6.0" && echo vulnerable || echo fixed
}
nbconvert_status() {
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    ver_lt "$n" "5.4.0" && { echo notaffected; return; }
    ver_lt "$n" "7.17.2" && echo vulnerable || echo fixed
}

# ---------- configuration (Jupyter Server) -----------------------------------
GATEWAY_ON=0; CUSTOM_AUTH=0; CONF_READ=0; CONF_FILES=""
read_jupyter_config() {   # directories to search
    local f flat
    GATEWAY_ON=0; CUSTOM_AUTH=0; CONF_READ=0; CONF_FILES=""
    while IFS= read -r f; do
        [[ -n "$f" && -r "$f" ]] || continue
        CONF_READ=1; CONF_FILES+="${f}"$'\n'
        case "$f" in
            *.py)
                sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -E "^[[:space:]]*c\.GatewayClient\.url[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" >/dev/null && GATEWAY_ON=1
                sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -E "^[[:space:]]*c\.ServerApp\.authorizer_class[[:space:]]*=" | grep -v "AllowAllAuthorizer" >/dev/null && CUSTOM_AUTH=1 ;;
            *.json)
                flat="$(tr -d '\n\r' < "$f")"
                grep -qE '"GatewayClient"[[:space:]]*:[[:space:]]*\{[^}]*"url"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$flat" && GATEWAY_ON=1
                grep -oE '"authorizer_class"[[:space:]]*:[[:space:]]*"[^"]*"' <<<"$flat" | grep -v "AllowAllAuthorizer" >/dev/null && CUSTOM_AUTH=1 ;;
        esac
    done < <(
        for d in "$@"; do
            [[ -d "$d" ]] && find "$d" -maxdepth 6 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'jupyter_server_config.py' -o -name 'jupyter_server_config.json' -o -name 'jupyter_config.py' -o -name 'jupyter_config.json' \
                   -o -name 'jupyter_notebook_config.py' -o -name 'jupyter_notebook_config.json' -o -path '*/jupyter_server_config.d/*.json' \) -type f -print 2>/dev/null
        done | sort -u)
}
process_hints() {   # sets GATEWAY_ON / CUSTOM_AUTH from the arguments of running jupyter processes
    have ps || return 0
    local args; args="$(ps -eo args= 2>/dev/null | grep -iE 'jupyter' | grep -v grep)"
    [[ -n "$args" ]] || return 0
    grep -qE -- '--gateway-url|--GatewayClient\.url' <<<"$args" && { GATEWAY_ON=1; inf "a running jupyter process was started with a gateway URL on its command line"; }
    grep -E -- '--ServerApp\.authorizer_class' <<<"$args" | grep -v AllowAllAuthorizer >/dev/null && { CUSTOM_AUTH=1; inf "a running jupyter process was started with a custom authorizer_class on its command line"; }
    return 0
}

# ---------- reporting --------------------------------------------------------
AFFECTED_NB=0; SERVER_EXPOSED=0
report() {   # kind label version src projdir
    local kind="$1" label="$2" ver="$3" src="$4" st
    if [[ "$kind" == server ]]; then st="$(server_status "$ver")"; else st="$(nbconvert_status "$ver")"; fi
    case "$st" in
        fixed)       ok "${label}: ${kind/server/jupyter_server} ${ver} has the fix"; [[ "$kind" == server ]] && inf "even on a fixed Jupyter Server, do not manually register the deprecated jupyter_server.gateway.handlers module: it still omits the authorization check"; return 0 ;;
        notaffected) ok "${label}: ${kind/server/jupyter_server} ${ver} is older than the affected range"; return 0 ;;
        unknown)     caution "${label}: cannot parse version '${ver}'"; return 0 ;;
    esac
    inf "source: ${src}"
    if [[ "$kind" == nbconvert ]]; then
        bad "${label}: nbconvert ${ver} is affected by CVE-2026-114140 (fixed in 7.17.2): converting a malicious notebook to markdown, LaTeX, reST or AsciiDoc can write attacker-controlled data to arbitrary paths"
        inf "this only matters if you convert notebooks you did not write (including JupyterLab's Download as on a shared hub or a notebook-rendering service)"
        AFFECTED_NB=$((AFFECTED_NB+1)); return 1
    fi
    # jupyter_server: exposure depends on configuration
    if [[ $GATEWAY_ON -eq 1 && $CUSTOM_AUTH -eq 1 ]]; then
        bad "${label}: jupyter_server ${ver} is affected by CVE-2026-114135 (fixed in 2.6.0), a gateway IS configured and a custom authorizer IS set: a user the authorizer denies can still execute on kernels"
        SERVER_EXPOSED=$((SERVER_EXPOSED+1)); return 1
    elif [[ $GATEWAY_ON -eq 1 ]]; then
        caution "${label}: jupyter_server ${ver} is in the affected range and a gateway is configured, but no custom authorizer was found: with the default allow-all authorizer there is nothing to bypass. Update anyway, and check whether an authorizer is set elsewhere."
        return 0
    elif [[ $CONF_READ -eq 1 ]]; then
        ok "${label}: jupyter_server ${ver} is in the affected range, but no GatewayClient.url is set in the configuration read, so the vulnerable gateway handler is not in use"
        caution "update anyway: a gateway enabled later, or through the command line or JUPYTER_GATEWAY_URL, would activate it"
        return 0
    else
        caution "${label}: jupyter_server ${ver} is in the affected range; no Jupyter configuration file was found, so the defaults (no gateway) apply. Settings on the command line or in JUPYTER_GATEWAY_URL cannot be seen here: update anyway."
        return 0
    fi
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

JUPYTER_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root"
find $R -xdev -maxdepth 9 -type d \( -iname "jupyter_server-*.dist-info" -o -iname "jupyter-server-*.dist-info" -o -iname "jupyter_server-*.egg-info" -o -iname "nbconvert-*.dist-info" -o -iname "nbconvert-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do
  echo "D $d"; [ -f "$d/METADATA" ] && echo "E $d/METADATA"; [ -f "$d/PKG-INFO" ] && echo "E $d/PKG-INFO"
done
find $R -maxdepth 6 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "jupyter_server_config.py" -o -name "jupyter_server_config.json" -o -name "jupyter_config.py" -o -name "jupyter_config.json" -o -name "jupyter_notebook_config.py" -o -name "jupyter_notebook_config.json" -o -path "*/jupyter_server_config.d/*.json" \) -type f -print 2>/dev/null | head -n 40 | while read -r f; do echo "F $f"; done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "requirements*.txt" -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | head -n 200 | while read -r f; do
  grep -qiE "jupyter[-_]server|nbconvert" "$f" 2>/dev/null && echo "F $f"
done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$JUPYTER_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d base ver f pin line pkg
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Jupyter Server and nbconvert"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    # configuration first, from the search roots plus the usual Jupyter locations
    local -a confdirs=("${existing[@]}")
    for d in /etc/jupyter /usr/local/etc/jupyter /usr/etc/jupyter "$HOME/.jupyter"; do [[ -d "$d" ]] && confdirs+=("$d"); done
    read_jupyter_config "${confdirs[@]}"
    process_hints
    if [[ $CONF_READ -eq 1 ]]; then
        inf "read $(grep -c . <<<"$CONF_FILES") Jupyter configuration file(s); gateway configured: $([[ $GATEWAY_ON -eq 1 ]] && echo yes || echo no); custom authorizer: $([[ $CUSTOM_AUTH -eq 1 ]] && echo yes || echo no)"
    else
        inf "no Jupyter configuration file found in the search directories or the usual locations"
    fi

    step "Installed copies (dist-info and egg-info metadata)"
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        pkg="$(tr 'A-Z_' 'a-z-' <<<"${base%%-[0-9]*}")"
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"
        [[ "$ver" =~ ^[0-9] ]] || continue
        ver="$(norm_ver "$ver")"
        case "$pkg" in
            jupyter-server) found=$((found+1)); report server "$(dirname "$d")" "$ver" "$d" || rc=1 ;;
            nbconvert)      found=$((found+1)); report nbconvert "$(dirname "$d")" "$ver" "$d" || rc=1 ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \
                \( -iname 'jupyter_server-*.dist-info' -o -iname 'jupyter-server-*.dist-info' -o -iname 'jupyter_server-*.egg-info' -o -iname 'nbconvert-*.dist-info' -o -iname 'nbconvert-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins, not installed copies)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        for pkg in server nbconvert; do
            pin=""
            local nm re
            if [[ "$pkg" == server ]]; then nm='jupyter[-_.]server'; else nm='nbconvert'; fi
            case "$(basename "$f")" in
                poetry.lock|uv.lock|pdm.lock)
                    pin="$(awk -v re="^name = \"${nm//\[-_.\]/[-_.]}\"" 'tolower($0) ~ re {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
                Pipfile.lock)
                    pin="$(awk -v re="\"${nm//\[-_.\]/[-_.]}\": *\\\\{" 'tolower($0) ~ re {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
                *)
                    line="$(grep -iE "^[[:space:]]*${nm}[[:space:]]*==" "$f" | head -n1)"
                    pin="$(sed -E "s/^[[:space:]]*[A-Za-z_.-]+[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\1/" <<<"$line")"
                    [[ -z "$line" ]] && pin="" ;;
            esac
            [[ -n "$pin" ]] || continue
            found=$((found+1))
            report "$pkg" "$f" "$pin" "pinned in $(basename "$f")" || rc=1
        done
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | sort -u)

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Jupyter Server or nbconvert found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "Nothing exposed (${found} copy or pin checked). An affected Jupyter Server without the gateway and authorizer conditions still needs the update."
    else
        warn "Exposed Jupyter component found. Upgrade: pip install --upgrade 'jupyter_server>=2.6.0' 'nbconvert>=7.17.2'"
        inf "PrivacySafe recommendation for nbconvert: do not convert notebooks from untrusted sources to markdown, LaTeX, reST or AsciiDoc, and run conversions in a throwaway directory as an unprivileged user. Re-running a cell replaces the malicious output metadata; merely converting the notebook does not."
        inf "PrivacySafe recommendation for Jupyter Server: remove GatewayClient.url if you do not need a gateway."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114135 (fixed in jupyter_server 2.6.0) and CVE-2026-114140 (fixed in nbconvert 7.17.2)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
