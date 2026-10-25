#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# LiteLLM 1.107.0 supply-chain compromise: detect, hunt and contain  (v1)
# No CVE (malicious package release, PyPI and Docker)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On 21 October 2026 a malicious release of litellm, version 1.107.0, was
# published to PyPI (all seven wheels, plus an sdist with a tampered
# pyproject.toml) and to the project's Docker images (tags v1.107.0, latest,
# main-latest, main-stable), after attacker-controlled GitHub accounts
# triggered a release. Each wheel drops three files into the ROOT of
# site-packages, beside litellm/ rather than inside it:
#   cook.pth           one line, "import cook"
#   cook.py            a zlib+base64 blob; a credential stealer ("privcollect")
#   sitecustomize.py   an hourly backdoor that fetches and runs attacker code
# Python runs .pth files and sitecustomize.py at interpreter startup, so the
# malware runs on every Python start on the host, even if litellm is never
# imported. The stealer targets cloud tokens, developer and private keys, AI
# tooling credentials, browser data, environment variables, and a LiteLLM
# proxy's saved credentials, and exfiltrates to litellm[.]dev; the backdoor
# reads a domain from a GitHub dead drop (letters9813) and runs code from it.
# The last clean release before it is 1.106.2.
#
# There is no patch and no safe in-place "clean": if 1.107.0 was installed from
# a wheel, or a LiteLLM container pulled on 21 October 2026 ran, treat the host
# as FULLY COMPROMISED. The stealer already ran. Rebuild the host, and from a
# clean machine revoke and rotate every credential it could reach (cloud keys,
# API tokens, SSH and signing keys, browser sessions, the LiteLLM proxy's
# keys), then reinstall litellm pinned to 1.106.2 by digest. This script finds
# the compromise, hunts the indicators, and can contain the auto-executing
# backdoor (quarantine) so it stops running while you rebuild; containment is
# not remediation.
#
# Usage:
#   ./litellm-oct2026-check.sh [command]
#
#   check (default)  find litellm in every Python environment (and running
#                    containers) and flag 1.107.0, and report the dropped
#                    malware files in site-packages. Read-only. Exit 0 = nothing
#                    found, 1 = compromise indicators present, 2 = couldn't read.
#   hunt             read-only, deeper: the malware files across site-packages,
#                    the /tmp markers it leaves, and logs for its network
#                    indicators (litellm.dev, the GitHub dead drop). Exit 0 =
#                    clean, 1 = findings.
#   quarantine       CONTAINMENT, not a fix: back up (for forensics) and remove
#                    cook.pth and cook.py, and sitecustomize.py when it carries
#                    the malware markers, so they stop running at Python start.
#                    Needs write access. The host is still compromised: rebuild
#                    and rotate credentials.
#   version          print the script version.
#
# Env overrides:
#   SCAN_PATHS="/usr /opt /srv /home /root /var/www"
#                                     where to look for site-packages
#   SCAN_DEPTH=9                      how deep the search goes
#   SAFE_PIN=1.106.2                  the last clean release to pin to
#   BACKUP_ROOT=/var/backups/litellm-oct2026
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt's network check
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
COMPROMISED_VER="1.107.0"
SAFE_PIN="${SAFE_PIN:-1.106.2}"
SCAN_PATHS="${SCAN_PATHS:-/usr/lib /usr/local/lib /opt /srv /home /root /var/www}"
SCAN_DEPTH="${SCAN_DEPTH:-9}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/litellm-oct2026}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
# Markers that identify the malicious sitecustomize.py (a legitimate
# sitecustomize.py exists in some environments, so it is only acted on when it
# carries one of these).
SITE_MARKERS='privcollect|PRIVCOLLECT|letters9813|remote_code_loader|litellm\.dev|import cook|domain\.txt'
NET_MARKERS='litellm\.dev|letters9813|remote_code_loader|/codepy|pythonclient-test'
TMP_MARKERS=(/tmp/.pc_once_* /tmp/remote_code_loader.lock)
SCRIPT_NAME="litellm-oct2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-24"
SELF="$0"
REF="https://github.com/BerriAI/litellm/issues/47826"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------- discovery --------------------------------------------------------
site_dirs() {
    {
        if have python3; then
            python3 - <<'PY' 2>/dev/null || true
import site, sys
seen=set()
try:
    for d in site.getsitepackages(): seen.add(d)
except Exception: pass
try: seen.add(site.getusersitepackages())
except Exception: pass
for d in sys.path:
    if d.endswith("site-packages"): seen.add(d)
for d in sorted(x for x in seen if x): print(d)
PY
        fi
        # shellcheck disable=SC2086
        find $SCAN_PATHS -maxdepth "$SCAN_DEPTH" -type d -name site-packages 2>/dev/null || true
    } | while read -r d; do [[ -d "$d" ]] && echo "$d"; done | sort -u
}

litellm_version_in() {   # <site-packages> -> version or empty
    local sp="$1" di v
    di="$(ls -d "$sp"/litellm-*.dist-info 2>/dev/null | head -1 || true)"
    if [[ -n "$di" ]]; then
        v="$(basename "$di")"; v="${v#litellm-}"; v="${v%.dist-info}"; echo "$v"; return
    fi
    [[ -f "$sp/litellm/__init__.py" ]] && grep -oE '__version__\s*=\s*"[0-9][0-9.]*"' "$sp/litellm/__init__.py" 2>/dev/null | head -1 | grep -oE '[0-9][0-9.]+' || true
}

# Which malware artifacts are in this site-packages root. Prints one per line.
artifacts_in() {   # <site-packages>
    local sp="$1" f
    [[ -f "$sp/cook.pth" ]] && echo "cook.pth"
    [[ -f "$sp/cook.py" ]] && echo "cook.py"
    if [[ -f "$sp/sitecustomize.py" ]] && grep -qE "$SITE_MARKERS" "$sp/sitecustomize.py" 2>/dev/null; then echo "sitecustomize.py"; fi
}

tmp_markers_present() {
    local m hit=1 g
    shopt -s nullglob
    for g in "${TMP_MARKERS[@]}"; do for m in $g; do [[ -e "$m" ]] && { echo "$m"; hit=0; }; done; done
    shopt -u nullglob
    return "$hit"
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 found=0 sp v arts a any=0
    step "litellm in Python environments"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        v="$(litellm_version_in "$sp")"
        [[ -n "$v" ]] || continue
        any=1
        if [[ "$v" == "$COMPROMISED_VER" ]]; then bad "${sp}: litellm ${v}  COMPROMISED (remove it; pin ${SAFE_PIN} by digest)"; found=1
        else ok "${sp}: litellm ${v}  (not the compromised release; verify integrity and pin ${SAFE_PIN} by digest)"; fi
    done < <(site_dirs)
    [[ $any -eq 1 ]] || inf "no litellm install found under the scanned paths"

    step "Dropped malware files in site-packages"
    local any_art=0
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        if [[ -n "$arts" ]]; then
            any_art=1; found=1
            while read -r a; do [[ -n "$a" ]] && bad "${sp}/${a}  malware artifact"; done <<<"$arts"
        fi
    done < <(site_dirs)
    [[ $any_art -eq 1 ]] || ok "no cook.pth / cook.py / malicious sitecustomize.py found in site-packages"

    step "Runtime markers"
    local tm
    tm="$(tmp_markers_present || true)"
    if [[ -n "$tm" ]]; then found=1; while read -r m; do [[ -n "$m" ]] && bad "runtime marker present: ${m} (the stealer ran / is running)"; done <<<"$tm"
    else ok "no /tmp runtime markers (.pc_once_*, remote_code_loader.lock)"; fi

    step "litellm inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt id name out any_c=0
        for rt in docker podman; do
            have "$rt" || continue
            while read -r id name; do
                [[ -n "$id" ]] || continue
                out="$("$rt" exec "$id" sh -c 'for d in $(python3 -c "import site,sys;[print(p) for p in set(site.getsitepackages()+[site.getusersitepackages()])]" 2>/dev/null); do [ -e "$d/cook.pth" ] && echo COOK; ls -d "$d"/litellm-*.dist-info 2>/dev/null | head -1; done' 2>/dev/null || true)"
                if grep -q 'COOK' <<<"$out" || grep -q "litellm-${COMPROMISED_VER}\.dist-info" <<<"$out"; then
                    any_c=1; found=1; bad "${rt} ${name:-$id}: compromised litellm (cook.pth or ${COMPROMISED_VER} inside); rebuild the image on a clean 1.106.2 digest"
                fi
            done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
        done
        [[ $any_c -eq 1 ]] || inf "no running container shows the compromise (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $found -eq 1 ]] && rc=1
    case $rc in
        0) info "No sign of the litellm 1.107.0 compromise where this could read" ;;
        1) warn "Compromise indicators found. TREAT THE HOST AS FULLY COMPROMISED: the stealer runs on every Python start. From a clean machine, revoke and rotate every credential this host could reach (cloud keys, API tokens, SSH and signing keys, browser sessions, the LiteLLM proxy's keys). Then rebuild, and reinstall litellm pinned to ${SAFE_PIN} by digest. Run 'quarantine' to stop the backdoor re-running in the meantime. Incident: ${REF}" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0 sp arts a
    step "Malware files across site-packages"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        [[ -n "$arts" ]] && { found=1; while read -r a; do [[ -n "$a" ]] && bad "${sp}/${a}"; done <<<"$arts"; }
    done < <(site_dirs)
    [[ $found -eq 1 ]] || ok "none found"

    step "Runtime markers (/tmp)"
    local tm; tm="$(tmp_markers_present || true)"
    if [[ -n "$tm" ]]; then found=1; while read -r m; do [[ -n "$m" ]] && bad "$m"; done <<<"$tm"; else ok "none"; fi
    inf "also look for a detached python process holding /tmp/remote_code_loader.lock, and PRIVCOLLECT_ACTIVE=1 in process environments"

    step "Network indicators in logs"
    local -a files=(); local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/messages /var/log/nginx/*.log /var/log/apache2/*.log \
             /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then inf "no readable logs to scan for network indicators"
    else
        local n; n="$( { grep -hEc "$NET_MARKERS" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "network indicators in logs: ${n}"; { grep -hE "$NET_MARKERS" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-200 | sed 's/^/      /'
        else ok "no litellm.dev / dead-drop indicators in the scanned logs"; fi
    fi
    echo
    echo "  If anything here matched, the host is compromised: rotate every credential it"
    echo "  could reach from a clean machine, rebuild, and reinstall litellm ${SAFE_PIN} by"
    echo "  digest. 'quarantine' stops the backdoor re-running but does not make the host safe."
    return "$found"
}

# ---------- quarantine (containment) -----------------------------------------
cmd_quarantine() {
    [[ "$(id -u)" -eq 0 ]] || warn "not running as root; removing site-packages files may need root or the owning user"
    local sp arts a bdir did=0
    step "Containment: quarantining the auto-executing malware files"
    while read -r sp; do
        [[ -n "$sp" ]] || continue
        arts="$(artifacts_in "$sp")"
        [[ -n "$arts" ]] || continue
        bdir="${BACKUP_ROOT}/$(date -u +%Y%m%dT%H%M%SZ)/$(echo "$sp" | sed 's#^/##; s#/#_#g')"
        mkdir -p "$bdir"
        while read -r a; do
            [[ -n "$a" ]] || continue
            if cp -p "${sp}/${a}" "${bdir}/${a}" 2>/dev/null && rm -f "${sp}/${a}" 2>/dev/null; then
                ok "${sp}/${a} -> quarantined to ${bdir}/${a}"; did=$((did+1))
            else bad "${sp}/${a}: could not quarantine (permission?)"; fi
        done <<<"$arts"
    done < <(site_dirs)
    echo
    if [[ $did -gt 0 ]]; then
        info "quarantined ${did} file(s); forensic copies are under ${BACKUP_ROOT}"
    else inf "nothing to quarantine"; fi
    warn "CONTAINMENT ONLY. The stealer already ran on every Python start. The host is compromised: from a clean machine rotate every credential it could reach, remove the litellm ${COMPROMISED_VER} install, rebuild, and reinstall litellm ${SAFE_PIN} by digest. Also check /tmp for remote_code_loader.lock and kill any detached python holding it."
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "litellm ${COMPROMISED_VER} supply-chain compromise; incident: ${REF}"
case "$CMD" in
    check|hunt|quarantine) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|quarantine|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
