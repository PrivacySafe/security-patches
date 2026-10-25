#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Nextcloud Collabora Built-in CODE Server command injection: mitigation  (v1)
# CVE-2026-110447
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The optional Nextcloud app "Collabora Online - Built-in CODE Server"
# (package richdocumentscode) ships a proxy.php that the web server runs
# directly, outside Nextcloud's code. Before 26.4.303 it built the command to
# start the local CODE server by placing text from the request, including its
# path, inside a double-quoted bash string, so a request with $(...) in its
# path ran commands as the web server account, without logging in. It is
# reachable only while the local CODE server is down (a restart, upgrade or
# crash), which is when proxy.php tries to start it. The flaw has been
# exploited in the wild since September 2026 to plant PHP web shells
# (apps/richdocumentscode/shx*.php). Collabora is explicit that DISABLING the
# app is not enough, because proxy.php is served whether or not the app is
# enabled: it must be updated to >= 26.4.303 or removed. The fixed app needs
# Nextcloud 30 or later; on Nextcloud 29 and older, upgrade Nextcloud or
# remove the app. Standalone Collabora Online servers, and Nextcloud Office
# (richdocuments) without the built-in app, are not affected. A separate
# earlier command-injection fix in the same script does not close this one.
#
# The real fix is to update richdocumentscode to >= 26.4.303 or remove it,
# which this script does not do for you (an app-store update or removal, run
# through Nextcloud's occ, is the administrator's call). What apply does is an
# interim, reversible mitigation: it neutralizes the exploited proxy.php on a
# vulnerable install by replacing it with a stub that returns HTTP 403 and
# builds no command, backing the original up first. That closes the exploited
# path at once and disables the built-in CODE server until you update or
# remove the app; restore puts the original back, and an app update replaces
# the stub with the fixed proxy.php on its own.
#
# Usage:
#   ./collabora-code-oct2026-mitigate.sh [command]
#
#   check (default)  find every Nextcloud with the built-in CODE app, report
#                    the app version (fixed at 26.4.303), the Nextcloud version
#                    (the fix needs 30+), and the proxy.php state. Read-only,
#                    root optional. Exit 0 = nothing exposed, 1 = a vulnerable
#                    app is present, 2 = something couldn't be read.
#   apply            neutralize the exploited proxy.php on every vulnerable
#                    install (backup first, idempotent, reversible). Needs
#                    write access to the app, so run as root or the web user.
#                    Refuses an already-fixed app unless --force.
#   restore          put the original proxy.php back where apply replaced it.
#   status           show which installs this script has mitigated.
#   hunt             read-only: the app folders for planted web shells
#                    (shx*.php and a known shell by hash) and the web server
#                    access logs for the exploitation markers. Exit 0 = clean,
#                    1 = findings.
#   version          print the script version.
#
# Env overrides:
#   NC_PATHS="/var/www /srv /opt"     where to look for Nextcloud installs
#   RICHDOC_FIXED=26.4.303            first fixed app version
#   NC_MIN_FOR_FIX=30                 Nextcloud major the fixed app requires
#   BACKUP_ROOT=/var/backups/collabora-code-oct2026
#   HUNT_SINCE="2026-09-01"           how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"    extra access-log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVE="CVE-2026-110447"
NC_PATHS="${NC_PATHS:-/var/www /srv /opt /usr/share/webapps /var/snap}"
RICHDOC_FIXED="${RICHDOC_FIXED:-26.4.303}"
NC_MIN_FOR_FIX="${NC_MIN_FOR_FIX:-30}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/collabora-code-oct2026}"
HUNT_SINCE="${HUNT_SINCE:-2026-09-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCAN_DEPTH="${SCAN_DEPTH:-8}"
STUB_MARKER="PRIVACYSAFE-COLLABORA-STUB"
KNOWN_SHELL_SHA256="4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562"
KNOWN_IPS="139.28.18.122 89.38.98.50"
SCRIPT_NAME="collabora-code-oct2026-mitigate.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-24"
SELF="$0"
ADVISORY="https://github.com/CollaboraOnline/online/security/advisories/GHSA-g3vx-3m76-fghh"
FORCE=0

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
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
is_root() { [[ "$(id -u)" -eq 0 ]]; }

# ---------- discovery --------------------------------------------------------
# Print the app directory of every built-in CODE app found.
find_apps() {
    local d
    # shellcheck disable=SC2086
    find $NC_PATHS -maxdepth "$SCAN_DEPTH" -type d -name richdocumentscode 2>/dev/null | while read -r d; do
        [[ -f "$d/appinfo/info.xml" ]] && echo "$d"
    done | sort -u
}

app_version() {   # <appdir> -> X.Y.Z
    local f="$1/appinfo/info.xml"
    [[ -f "$f" ]] || return 0
    grep -oE '<version>[0-9.]+</version>' "$f" 2>/dev/null | head -1 | grep -oE '[0-9.]+' || true
}

# The Nextcloud root is the directory holding apps/ (or custom_apps/).
nc_root_of() {   # <appdir> -> ncroot or empty
    local parent grand
    parent="$(dirname "$1")"       # .../apps  or .../custom_apps
    grand="$(dirname "$parent")"   # nextcloud root
    [[ -f "$grand/version.php" ]] && { echo "$grand"; return; }
    echo ""
}

nc_version() {   # <ncroot> -> X.Y.Z
    local f="$1/version.php"
    [[ -f "$f" ]] || return 0
    grep -oE "OC_VersionString\s*=\s*'[0-9.]+'" "$f" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' \
        || grep -oE 'OC_Version\s*=\s*array\([0-9, ]+\)' "$f" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -3 | paste -sd. -
}

app_state() {   # <ver> -> rc|why
    local v="$1"
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if ver_ge "$v" "$RICHDOC_FIXED"; then echo "0|${v} >= ${RICHDOC_FIXED}"
    else echo "1|${v} < ${RICHDOC_FIXED} (every version before ${RICHDOC_FIXED} is affected)"; fi
}

proxy_is_stub() { [[ -f "$1" ]] && grep -q "$STUB_MARKER" "$1" 2>/dev/null; }
backup_dir_for() { echo "${BACKUP_ROOT}/$(echo "$1" | sed 's#^/##; s#/#_#g')"; }

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 appdir v ncroot ncv st why proxy any=0
    step "Nextcloud built-in CODE app (richdocumentscode)"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        any=1
        v="$(app_version "$appdir")"
        ncroot="$(nc_root_of "$appdir")"
        ncv="$([[ -n "$ncroot" ]] && nc_version "$ncroot" || true)"
        proxy="$appdir/proxy.php"
        IFS='|' read -r st why <<<"$(app_state "$v")"
        local loc="${appdir}${ncv:+  (Nextcloud ${ncv})}"
        case $st in
            0) ok "${loc}  app ${v} fixed  (${why})" ;;
            1) if proxy_is_stub "$proxy"; then
                   caution "${loc}  app ${v} vulnerable, but proxy.php is neutralized by this script (${why}); still update to ${RICHDOC_FIXED} or remove the app"
               else
                   bad "${loc}  app ${v} vulnerable  (${why})"; exposed=1
               fi
               if [[ -n "$ncv" ]] && ! ver_ge "${ncv%%.*}" "$NC_MIN_FOR_FIX"; then
                   caution "    Nextcloud ${ncv} cannot install the fixed app (needs ${NC_MIN_FOR_FIX}+): upgrade Nextcloud or remove the app"
               fi ;;
            *) caution "${loc}  app version unreadable"; unknownz=1 ;;
        esac
        [[ -f "$proxy" ]] || inf "    note: no proxy.php in ${appdir} (nonstandard layout)"
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no built-in CODE app (richdocumentscode) found under: ${NC_PATHS}"

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable built-in CODE app found where this could read one" ;;
        1) warn "A vulnerable built-in CODE app is present. Update richdocumentscode to ${RICHDOC_FIXED} or later, or remove the app; disabling it is not enough. For an interim, reversible block run 'apply'. Then run 'hunt' to look for planted web shells. Advisory: ${ADVISORY}" ;;
        *) warn "Some installs couldn't be read. Rerun as root to read every install" ;;
    esac
    return "$rc"
}

# ---------- apply / restore --------------------------------------------------
write_stub() {   # <proxy.php path>
    local proxy="$1" tmp
    tmp="$(mktemp)"
    cat >"$tmp" <<PHP
<?php
// ${STUB_MARKER} ${CVE}
// The original proxy.php was neutralized as an interim mitigation because it
// was exploitable (${CVE}). Restore it with this repo's mitigate script
// 'restore' command, or update the app to >= ${RICHDOC_FIXED}, which replaces
// this file with the fixed proxy.php. The built-in CODE server will not start
// while this stub is in place.
http_response_code(403);
header('Content-Type: text/plain');
echo "richdocumentscode temporarily disabled pending update (${CVE}).\n";
PHP
    if have php && ! php -l "$tmp" >/dev/null 2>&1; then rm -f "$tmp"; return 1; fi
    cat "$tmp" >"$proxy"; rm -f "$tmp"
}

cmd_apply() {
    is_root || warn "not running as root; this needs write access to the app files (run as root or the web server user)"
    local appdir v proxy st why bdir did=0 skipped=0 failed=0
    step "Neutralizing the exploited proxy.php on vulnerable installs"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        v="$(app_version "$appdir")"; proxy="$appdir/proxy.php"
        IFS='|' read -r st why <<<"$(app_state "$v")"
        if [[ "$st" == 0 && $FORCE -ne 1 ]]; then inf "${appdir}: app ${v} already fixed, leaving it alone"; continue; fi
        [[ -f "$proxy" ]] || { caution "${appdir}: no proxy.php to neutralize"; continue; }
        if proxy_is_stub "$proxy"; then inf "${appdir}: proxy.php already neutralized"; skipped=$((skipped+1)); continue; fi
        bdir="$(backup_dir_for "$appdir")"; mkdir -p "$bdir"
        if ! cp -p "$proxy" "${bdir}/proxy.php.orig" 2>/dev/null; then bad "${appdir}: cannot back up proxy.php (permission?)"; failed=$((failed+1)); continue; fi
        if write_stub "$proxy"; then ok "${appdir}: proxy.php neutralized (backup at ${bdir}/proxy.php.orig)"; did=$((did+1))
        else bad "${appdir}: stub failed php -l, left untouched"; failed=$((failed+1)); fi
    done < <(find_apps)
    echo
    info "neutralized ${did}, already done ${skipped}, failed ${failed}"
    inf "This is interim. Update richdocumentscode to ${RICHDOC_FIXED} or later, or remove the app, then (optionally) 'restore'. Run 'hunt' to check for web shells already planted."
    [[ $failed -eq 0 ]]
}

cmd_restore() {
    is_root || warn "not running as root; restore needs write access to the app files"
    local appdir proxy bdir did=0
    step "Restoring original proxy.php where this script replaced it"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        proxy="$appdir/proxy.php"; bdir="$(backup_dir_for "$appdir")"
        if [[ -f "${bdir}/proxy.php.orig" ]] && proxy_is_stub "$proxy"; then
            if cp -p "${bdir}/proxy.php.orig" "$proxy" 2>/dev/null; then ok "${appdir}: proxy.php restored (the original is vulnerable; update or remove the app)"; did=$((did+1))
            else bad "${appdir}: cannot write proxy.php (permission?)"; fi
        elif proxy_is_stub "$proxy"; then caution "${appdir}: neutralized but no backup found; update or remove the app instead"
        fi
    done < <(find_apps)
    [[ $did -gt 0 ]] || inf "nothing to restore"
}

cmd_status() {
    local appdir proxy any=0
    step "Mitigation status"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        proxy="$appdir/proxy.php"
        if proxy_is_stub "$proxy"; then any=1; caution "${appdir}: proxy.php neutralized by this script"; fi
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no install is currently neutralized by this script"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0 appdir f sum any=0
    step "Web shells in the app folders"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        any=1
        shopt -s nullglob
        for f in "$appdir"/sh*.php; do
            [[ -f "$f" ]] || continue
            [[ "$(basename "$f")" == "proxy.php" ]] && continue
            found=1; caution "suspicious file name: ${f}"
        done
        for f in "$appdir"/*.php; do
            [[ -f "$f" ]] || continue
            proxy_is_stub "$f" && continue
            if have sha256sum; then sum="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"; [[ "$sum" == "$KNOWN_SHELL_SHA256" ]] && { found=1; bad "known web shell by hash: ${f}"; }; fi
            if grep -lqE '_GET\[' "$f" 2>/dev/null && grep -lqE 'shell_exec|passthru|proc_open|system\(' "$f" 2>/dev/null; then
                [[ "$(basename "$f")" == "proxy.php" ]] || { found=1; caution "file runs commands from request input: ${f}"; }
            fi
        done
        shopt -u nullglob
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no app folder to scan"
    [[ $found -eq 1 ]] || ok "no web-shell files found in the app folders"

    step "Exploitation markers in web server access logs since ${HUNT_SINCE}"
    local -a files=()
    local g
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/nginx/*access*.log /var/log/nginx/*.log /var/log/apache2/*access*.log /var/log/apache2/*.log \
             /var/log/httpd/*access*.log /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then warn "No readable access logs (try as root, or set HUNT_LOGS)"
    else
        inf "reading ${#files[@]} log file(s)"
        local name re n ip c
        local -a checks=(
            "proxy.php requests with an injection marker|richdocumentscode/proxy\.php.*(%2e%2e|\\\$\\(|\\\$\\{IFS\\}|base64 -d)"
            "proxy.php?status probes|richdocumentscode/proxy\.php\?status"
            "webhook.site callback in a request|webhook\.site"
        )
        for c in "${checks[@]}"; do
            name="${c%%|*}"; re="${c#*|}"
            n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
            if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "${name}: ${n}"; { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -2 | cut -c1-200 | sed 's/^/      /'
            else ok "${name}: none"; fi
        done
        for ip in $KNOWN_IPS; do
            n="$( { grep -hcF "$ip" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
            [[ "${n:-0}" -gt 0 ]] && { found=1; bad "known attacker IP ${ip}: ${n} hit(s)"; }
        done
    fi
    echo
    echo "  A hit is a lead, not proof. A shx*.php file in the app folder, a request to"
    echo "  proxy.php with \$( or \${IFS} in its path, or a known attacker IP is worth"
    echo "  treating as a compromise: anything the web server account could read may be"
    echo "  exposed (check for *.kdbx, wallet.dat, keystore.json and credential stores),"
    echo "  so rotate secrets, and delete any shx*.php under apps/richdocumentscode."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
for a in "$@"; do case "$a" in --force) FORCE=1 ;; esac; done
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "${CVE}; advisory: ${ADVISORY}"
case "$CMD" in
    check|apply|restore|status|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|apply|restore|status|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
