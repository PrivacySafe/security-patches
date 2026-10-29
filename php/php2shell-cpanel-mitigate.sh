#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PHP2Shell interim mitigation for cPanel EasyApache 4  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell") are fixed by updating PHP
# (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor build that names both CVEs in
# its changelog). Nothing here replaces that. This script covers the hosts the
# Debian tool (php2shell-mitigate.sh) refuses: cPanel servers running
# EasyApache 4 PHP (ea-php74 ... ea-php85) under any handler.
#
# It writes ONE drop-in per ea-php version into that version's php.d directory,
# named so it sorts after every other file there and therefore wins over
# php.ini and the MultiPHP INI Editor. It never edits php.ini. A file in php.d
# is read when the process starts, so the web server and any FPM pools must be
# restarted; apply does that unless told not to.
#
# What the drop-in sets:
#   session.upload_progress.enabled = 0     every version, patched or not:
#                                           CVE-2026-115560 is not fixed by the
#                                           21 October releases
#   fatal_error_backtraces = 0              PHP 8.5, unpatched builds only
#   memory_limit = -1                       only with --memory-unlimited, and
#                                           only on unpatched builds (PHP's own
#                                           interim measure; it trades the RCE
#                                           for denial of service, so pair it
#                                           with a request body cap)
#   post_max_size / upload_max_filesize     only with --post-max / --upload-max;
#                                           capped to the smaller of the current
#                                           value and your ceiling, never raised
#
# What check reports, besides the above:
#   * the PHP handler of each version (from WHM, when whmapi1 is present)
#   * whether each version is patched: by version, or because the package
#     changelog names both CVEs
#   * settings elsewhere that can undo the drop-in: FPM pool entries,
#     .user.ini and .htaccess php_value / php_flag lines
#   * Apache RLimitMEM / RLimitCPU, which cap processes Apache itself forks
#     (CGI, suEXEC, suPHP) and which PHP's advisory warns against as a memory
#     limit, because a failed allocation sends PHP down the vulnerable path
#   * web server and FPM processes that started before the drop-in changed
#
# Usage:
#   ./php2shell-cpanel-mitigate.sh [command] [options]
#
#   check (default)  read-only report, and the file apply would write
#   apply            write the drop-in for every version, verify it, restart
#   status           what is in place now, and whether workers need a restart
#   restore          remove the drop-ins this script wrote
#   cleanup          once a version is patched, reduce its drop-in to the one
#                    line CVE-2026-115560 still needs (--force to do it for an
#                    unpatched version too)
#
# Options:
#   --post-max SIZE       cap post_max_size (for example 32M; never raises it)
#   --upload-max SIZE     cap upload_max_filesize (default: same as --post-max)
#   --memory-unlimited    memory_limit = -1 on unpatched versions (see above)
#   --no-restart          write files only; you restart Apache and FPM
#   --no-scan             skip the per-directory scan under the home directories
#   --force               with cleanup, also reduce unpatched versions
#   -h, --help            this text
#   -V, --version, version
#
# Exit: check: 0 = every version patched and nothing to review,
#       1 = an unpatched version is present, 2 = patched but something to review.
#       Other commands: 0 = done, 1 = failed.
#
# Env overrides:
#   EA_ROOT=/opt/cpanel                where the ea-php* directories live
#   HOME_ROOT=/home                    where per-directory settings are scanned
#   CPANEL_SCRIPTS=/scripts            where restartsrv_httpd lives
#   APACHE_CONF_DIRS="/etc/apache2/conf /etc/apache2/conf.d"
#   SCAN_DEPTH=12                      how deep the home scan looks
#
# check prints the exact plan before apply makes any change, and restore reverts
# a drop-in it wrote. Run check first and review the plan before apply.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
set -euo pipefail

SCRIPT_NAME="php2shell-cpanel-mitigate.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-24"

EA_ROOT="${EA_ROOT:-/opt/cpanel}"
HOME_ROOT="${HOME_ROOT:-/home}"
CPANEL_SCRIPTS="${CPANEL_SCRIPTS:-/scripts}"
APACHE_CONF_DIRS="${APACHE_CONF_DIRS:-/etc/apache2/conf /etc/apache2/conf.d}"
SCAN_DEPTH="${SCAN_DEPTH:-12}"

DROPIN="zzzzzzzzzz-php2shell-mitigation.ini"
MARKER="; php2shell-cpanel-mitigate.sh: managed file, do not edit by hand."
MANAGED_KEYS='session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit|fatal_error_backtraces'
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }

# ---- arguments ---------------------------------------------------------------
CMD=""; POST_CAP=""; UPLOAD_CAP=""; MEM_UNLIMITED=0; DO_RESTART=1; DO_SCAN=1; FORCE=0
usage() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
        --post-max)   [[ $# -ge 2 ]] || die "--post-max needs a size"; POST_CAP="$2"; shift ;;
        --upload-max) [[ $# -ge 2 ]] || die "--upload-max needs a size"; UPLOAD_CAP="$2"; shift ;;
        --memory-unlimited) MEM_UNLIMITED=1 ;;
        --no-restart) DO_RESTART=0 ;;
        --no-scan)    DO_SCAN=0 ;;
        --force)      FORCE=1 ;;
        check|apply|status|restore|cleanup)
            [[ -z "$CMD" ]] || die "only one command at a time (got '$CMD' and '$1')"; CMD="$1" ;;
        *) echo "${SCRIPT_NAME}: unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done
CMD="${CMD:-check}"

# ---- sizes -------------------------------------------------------------------
# PHP shorthand (128M, 1G, 512K, 2048, -1) to bytes. Prints nothing if it cannot
# be read, which callers treat as "unknown".
bytes_of() {
    local v="${1^^}"
    v="${v// /}"
    [[ "$v" =~ ^(-?[0-9]+)([KMG]?)B?$ ]] || return 0
    local n="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
    case "$unit" in
        K) echo $(( n * 1024 )) ;;
        M) echo $(( n * 1024 * 1024 )) ;;
        G) echo $(( n * 1024 * 1024 * 1024 )) ;;
        *) echo "$n" ;;
    esac
}
# The smaller of <current> and <ceiling>. A current value of 0 or -1 means "no
# limit" and a value we cannot read is treated the same way, so the ceiling wins.
smaller_of() {
    local cur_b ceil_b
    cur_b="$(bytes_of "$1")"; ceil_b="$(bytes_of "$2")"
    if [[ -n "$cur_b" && "$cur_b" -gt 0 && "$cur_b" -lt "$ceil_b" ]]; then echo "$1"; else echo "$2"; fi
}
if [[ -n "$POST_CAP" ]]; then
    [[ "$(bytes_of "$POST_CAP")" -gt 0 ]] 2>/dev/null || die "--post-max: not a usable size: $POST_CAP"
    UPLOAD_CAP="${UPLOAD_CAP:-$POST_CAP}"
fi
if [[ -n "$UPLOAD_CAP" ]]; then
    [[ "$(bytes_of "$UPLOAD_CAP")" -gt 0 ]] 2>/dev/null || die "--upload-max: not a usable size: $UPLOAD_CAP"
    [[ -n "$POST_CAP" ]] || die "--upload-max needs --post-max (upload_max_filesize must not exceed post_max_size)"
fi

# ---- temp files --------------------------------------------------------------
TMPDIRS=()
cleanup_tmp() { local d; for d in ${TMPDIRS[@]+"${TMPDIRS[@]}"}; do rm -rf "$d"; done; }
trap cleanup_tmp EXIT

# ---- discovery ---------------------------------------------------------------
VERS=(); ROOTS=()
declare -A HANDLER=()
discover() {
    local r
    while IFS= read -r r; do
        [[ -d "$r" ]] || continue
        VERS+=("$(basename "$(dirname "$r")")"); ROOTS+=("$r")
    done < <(compgen -G "${EA_ROOT}/ea-php*/root" | sort -V || true)
    [[ ${#ROOTS[@]} -gt 0 ]] || die "No EasyApache 4 PHP found under ${EA_ROOT} (looked for ea-php*/root). On Debian, Ubuntu or Trisquel use php2shell-mitigate.sh instead."
}

# WHM's handler per version, best effort: the layout of whmapi1 output is read
# loosely, and any version it cannot place is reported as "unknown".
load_handlers() {
    command -v whmapi1 >/dev/null 2>&1 || return 0
    local out ver hand
    out="$(whmapi1 php_get_handlers 2>/dev/null)" || return 0
    while read -r ver hand; do
        [[ -n "$ver" ]] && HANDLER["$ver"]="$hand"
    done < <(awk '
        function emit() { if (v != "") print v, (h == "" ? "unknown" : h); v = ""; h = "" }
        /^[[:space:]]*-[[:space:]]+[A-Za-z_]+:/ { emit() }
        { s = $0; sub(/^[[:space:]]*-?[[:space:]]*/, "", s) }
        s ~ /^current_handler:/ { sub(/^current_handler:[[:space:]]*/, "", s); h = s }
        s ~ /^version:[[:space:]]*ea-php/ { sub(/^version:[[:space:]]*/, "", s); v = s }
        END { emit() }' <<<"$out")
}

# ---- reading what PHP will actually use --------------------------------------
# key=value lines for every managed setting, as the binary at <php> sees them.
# <scan> overrides PHP_INI_SCAN_DIR when given.
effective_settings() {   # <php> [scan dir]
    local php="$1" scan="${2:-}"
    # shellcheck disable=SC2016  # the dollar signs are PHP's, not the shell's
    local code='foreach (["session.upload_progress.enabled","post_max_size","upload_max_filesize","memory_limit","fatal_error_backtraces"] as $k) { $v = ini_get($k); echo $k, "=", $v === false ? "(n/a)" : $v, "\n"; }'
    if [[ -n "$scan" ]]; then PHP_INI_SCAN_DIR="$scan" "$php" -r "$code"; else "$php" -r "$code"; fi
}
# The same, with our own drop-in left out, so a second run compares against the
# real baseline and not against caps we wrote ourselves.
baseline_settings() {   # <php> <scan dir>
    local php="$1" scandir="$2" tmp f
    tmp="$(mktemp -d)"; TMPDIRS+=("$tmp")
    for f in "$scandir"/*.ini; do
        [[ -e "$f" && "$(basename "$f")" != "$DROPIN" ]] && ln -s "$f" "$tmp/$(basename "$f")"
    done
    effective_settings "$php" "$tmp"
}
setting_of() { sed -n "s/^$2=//p" <<<"$1" | head -n 1; }   # <lines> <key>

# ---- patch state -------------------------------------------------------------
fixed_release_for() {   # <major.minor> -> first fixed upstream release
    case "$1" in
        8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;;
        *) echo "" ;;
    esac
}
version_at_least() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$2" ]]; }   # <have> <want>
PATCH_STATE=""; PATCH_WHY=""; PKG_NAME=""
patch_state() {   # <php binary>   sets PATCH_STATE (patched|unpatched) and PATCH_WHY
    local php="$1" ver branch fixed
    PATCH_STATE="unpatched"; PATCH_WHY=""; PKG_NAME=""
    ver="$("$php" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    [[ -n "$ver" ]] || { PATCH_WHY="could not read the PHP version"; return 0; }
    branch="${ver%.*}"; fixed="$(fixed_release_for "$branch")"
    if [[ -n "$fixed" ]] && version_at_least "$ver" "$fixed"; then
        PATCH_STATE="patched"; PATCH_WHY="${ver} is at or above the upstream fix ${fixed}"; return 0
    fi
    if command -v rpm >/dev/null 2>&1; then
        PKG_NAME="$(rpm -qf --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$php" 2>/dev/null || true)"
        if [[ -n "$PKG_NAME" ]] && rpm -q --changelog "$PKG_NAME" 2>/dev/null | grep -q "$CVE_A" \
           && rpm -q --changelog "$PKG_NAME" 2>/dev/null | grep -q "$CVE_B"; then
            PATCH_STATE="patched"; PATCH_WHY="the package changelog of ${PKG_NAME} names both CVEs"; return 0
        fi
    fi
    if [[ -n "$fixed" ]]; then PATCH_WHY="${ver} is below the upstream fix ${fixed} and no changelog names both CVEs"
    else PATCH_WHY="${ver} is an end-of-life branch with no upstream fix and no changelog names both CVEs"; fi
}

# ---- the drop-in -------------------------------------------------------------
# <state> <php version> <baseline post> <baseline upload>
build_dropin() {
    local state="$1" ver="$2" base_post="$3" base_upload="$4" post upload
    echo "$MARKER"
    echo "; Interim measures for ${CVE_A}, ${CVE_B} and CVE-2026-115560."
    echo "; Updating PHP is the only complete fix for the first two."
    echo "; Remove with: ${SCRIPT_NAME} restore"
    echo "session.upload_progress.enabled = 0"
    if [[ "$state" == unpatched && "$ver" =~ ^8\.([5-9]|[1-9][0-9])\. ]]; then
        echo "fatal_error_backtraces = 0"
    fi
    if [[ -n "$POST_CAP" ]]; then
        post="$(smaller_of "$base_post" "$POST_CAP")"
        upload="$(smaller_of "$base_upload" "$UPLOAD_CAP")"
        if [[ "$(bytes_of "$upload")" -gt "$(bytes_of "$post")" ]]; then upload="$post"; fi
        echo "post_max_size = ${post}"
        echo "upload_max_filesize = ${upload}"
    fi
    if [[ "$MEM_UNLIMITED" -eq 1 && "$state" == unpatched ]]; then echo "memory_limit = -1"; fi
}
dropin_is_ours() { [[ -f "$1" ]] && head -n 1 "$1" | grep -qxF "$MARKER"; }
write_dropin() {   # <path> <content>
    local path="$1" content="$2" tmp
    tmp="${path}.tmp"
    printf '%s\n' "$content" > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$path"
}
# Compare what we wrote with what the binary now reports.
verify_dropin() {   # <php> <path>
    local php="$1" path="$2" eff key want got bad_n=0
    eff="$(effective_settings "$php")"
    while IFS= read -r line; do
        [[ "$line" =~ ^([a-z_.]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
        got="$(setting_of "$eff" "$key")"
        if [[ "$got" == "(n/a)" ]]; then
            caution "${key}: this PHP does not know the setting, so the line is ignored and cannot be confirmed"
        elif [[ "$got" != "$want" ]]; then
            bad "${key}: wrote '${want}', PHP reports '${got}' (another file or setting wins)"; bad_n=$((bad_n+1))
        fi
    done < <(grep -v '^;' "$path")
    [[ $bad_n -eq 0 ]]
}

# ---- services ----------------------------------------------------------------
older_workers() {   # <epoch> -> live web server / FPM processes that started before it (zombies are not workers)
    local cutoff="$1" now age n=0
    now="$(date +%s)"
    while read -r age _; do
        [[ "$age" =~ ^[0-9]+$ ]] || continue
        if (( now - age < cutoff )); then n=$((n+1)); fi
    done < <(ps -eo etimes=,stat=,comm= 2>/dev/null | awk '$3 ~ /^(httpd|apache2|php-fpm|lsphp)/ && $2 !~ /^Z/ {print $1, $3}' || true)
    echo "$n"
}
restart_services() {
    local unit units
    step "Restarting so every worker re-reads its settings"
    if [[ -x "${CPANEL_SCRIPTS}/restartsrv_httpd" ]]; then
        if "${CPANEL_SCRIPTS}/restartsrv_httpd" >/dev/null 2>&1; then ok "Apache restarted (${CPANEL_SCRIPTS}/restartsrv_httpd)"
        else bad "Apache restart failed; restart it yourself"; fi
    else
        caution "${CPANEL_SCRIPTS}/restartsrv_httpd not found; restart Apache yourself"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        units="$(systemctl list-units --type=service --state=active --no-legend --plain 'ea-php*-php-fpm*.service' 2>/dev/null | awk '{print $1}' || true)"
        if [[ -z "$units" ]]; then inf "no running ea-php FPM services"; fi
        for unit in $units; do
            if systemctl restart "$unit" >/dev/null 2>&1; then ok "restarted ${unit}"; else bad "could not restart ${unit}"; fi
        done
    else
        caution "systemctl not found; restart any ea-php FPM pools yourself"
    fi
}

# ---- scans -------------------------------------------------------------------
REVIEW=0
note_review() { REVIEW=1; }
scan_pools() {   # <root>
    local root="$1" dir hits
    dir="${root}/etc/php-fpm.d"
    [[ -d "$dir" ]] || return 0
    hits="$(grep -HnE "^[[:space:]]*php(_admin)?_(value|flag)\[(${MANAGED_KEYS})\]" "$dir"/*.conf 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        caution "FPM pool settings for managed keys (a pool value beats php.d files; admin values cannot be changed by the site):"
        # shellcheck disable=SC2001
        sed 's/^/      /' <<<"$hits" | head -n 20
        note_review
    else
        ok "no FPM pool entries for the managed settings"
    fi
}
scan_home() {
    [[ -d "$HOME_ROOT" ]] || { inf "${HOME_ROOT} not found; skipping the per-directory scan"; return 0; }
    local hits htaccess ini
    htaccess="$(find "$HOME_ROOT" -xdev -maxdepth "$SCAN_DEPTH" -path '*/virtfs' -prune -o -name .htaccess -type f -print0 2>/dev/null \
        | xargs -0 -r grep -HnEi "^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+(${MANAGED_KEYS})[[:space:]]" 2>/dev/null || true)"
    ini="$(find "$HOME_ROOT" -xdev -maxdepth "$SCAN_DEPTH" -path '*/virtfs' -prune -o \( -name .user.ini -o -name php.ini \) -type f -print0 2>/dev/null \
        | xargs -0 -r grep -HnEi "^[[:space:]]*(${MANAGED_KEYS})[[:space:]]*=" 2>/dev/null || true)"
    if [[ -z "$htaccess$ini" ]]; then ok "no per-directory settings for the managed keys under ${HOME_ROOT}"; return 0; fi
    caution "per-directory settings under ${HOME_ROOT}:"
    inf ".htaccess php_value / php_flag can undo the drop-in under mod_php; .user.ini can under FPM and CGI."
    inf "A php.ini in a home directory is read before the drop-in, so the drop-in wins; it is listed for completeness."
    { printf '%s\n' "$htaccess"; printf '%s\n' "$ini"; } | grep -v '^$' | sed 's/^/      /' | head -n 30
    note_review
}
scan_rlimits() {
    local d hits=""
    for d in $APACHE_CONF_DIRS; do
        [[ -d "$d" ]] && hits+="$(grep -rnE '^[[:space:]]*RLimit(MEM|CPU)[[:space:]]' "$d" 2>/dev/null || true)"$'\n'
    done
    hits="$(grep -v '^$' <<<"$hits" || true)"
    if [[ -n "$hits" ]]; then
        caution "Apache RLimitMEM / RLimitCPU is set:"
        # shellcheck disable=SC2001
        sed 's/^/      /' <<<"$hits"
        inf "These limit processes Apache forks (CGI, suEXEC, suPHP). PHP's advisory warns against an address-space limit as a memory cap: the failed allocation sends PHP down the vulnerable path."
        inf "In WHM, change it under Apache Configuration (httpd.conf is generated, so hand edits are lost)."
        note_review
    else
        ok "no RLimitMEM or RLimitCPU in the Apache configuration"
    fi
}

# ---- commands ----------------------------------------------------------------
UNPATCHED=0
describe_version() {   # <index>
    local i="$1" root php scan dropin ver base eff
    root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
    echo
    echo -e "  ${CYAN}${VERS[$i]}${NC}  handler: ${HANDLER[${VERS[$i]}]:-unknown}"
    if [[ ! -x "$php" || ! -d "$scan" ]]; then caution "missing ${php} or ${scan}; skipped"; return 0; fi
    ver="$("$php" -r 'echo PHP_VERSION;' 2>/dev/null || echo '?')"
    patch_state "$php"
    if [[ "$PATCH_STATE" == patched ]]; then ok "patched: ${PATCH_WHY}"
    else bad "NOT patched: ${PATCH_WHY}"; UNPATCHED=1; fi
    [[ "${HANDLER[${VERS[$i]}]:-}" == dso ]] && caution "dso (mod_php): the highest-priority exposure in PHP's advisory"
    base="$(baseline_settings "$php" "$scan")"
    inf "settings without this script's drop-in: $(tr '\n' ' ' <<<"$base")"
    if [[ -f "$dropin" ]]; then
        if dropin_is_ours "$dropin"; then
            eff="$(effective_settings "$php")"
            ok "drop-in present; PHP now reports: $(tr '\n' ' ' <<<"$eff")"
        else
            caution "${dropin} exists but was not written by this script; apply will refuse to replace it"; note_review
        fi
    else
        inf "no drop-in yet"
    fi
    if [[ "$CMD" == check ]]; then
        echo "    apply would write ${dropin}:"
        build_dropin "$PATCH_STATE" "$ver" "$(setting_of "$base" post_max_size)" "$(setting_of "$base" upload_max_filesize)" \
            | grep -v '^;' | sed 's/^/        /'
    fi
    scan_pools "$root"
}

env_banner() {
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    if [[ -r /usr/local/cpanel/version ]]; then inf "cPanel $(cat /usr/local/cpanel/version 2>/dev/null)"; fi
}

cmd_check() {
    local i
    step "EasyApache 4 PHP versions"
    for i in "${!ROOTS[@]}"; do describe_version "$i"; done
    if [[ "$DO_SCAN" -eq 1 ]]; then step "Per-directory settings that could undo the drop-in"; scan_home; fi
    step "Apache resource limits"; scan_rlimits
    step "Summary"
    if [[ "$UNPATCHED" -eq 1 ]]; then
        bad "at least one version is unpatched: update the ea-php packages (the only complete fix), then restart Apache and FPM"
        inf "interim: ${SCRIPT_NAME} apply"
        exit 1
    fi
    if [[ "$REVIEW" -eq 1 ]]; then caution "every version is patched, but something above is worth a look"; exit 2; fi
    ok "every version is patched and nothing needs review"
    inf "CVE-2026-115560 is not fixed by these releases: keep session.upload_progress.enabled off (apply, then cleanup)"
}

cmd_apply() {
    [[ $EUID -eq 0 ]] || die "apply must run as root"
    [[ "$MEM_UNLIMITED" -eq 0 ]] || caution "memory_limit = -1 trades the remote code execution for denial of service: one request can use all memory. Pair it with a request body cap (php/edge/)."
    local i root php scan dropin ver base content written=0 failed=0
    step "Writing drop-ins"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        if [[ ! -x "$php" || ! -d "$scan" ]]; then caution "${VERS[$i]}: missing ${php} or ${scan}; skipped"; continue; fi
        if [[ -e "$dropin" ]] && ! dropin_is_ours "$dropin"; then bad "${VERS[$i]}: ${dropin} exists and was not written by this script; leaving it alone"; failed=$((failed+1)); continue; fi
        ver="$("$php" -r 'echo PHP_VERSION;')"; patch_state "$php"
        base="$(baseline_settings "$php" "$scan")"
        content="$(build_dropin "$PATCH_STATE" "$ver" "$(setting_of "$base" post_max_size)" "$(setting_of "$base" upload_max_filesize)")"
        write_dropin "$dropin" "$content"; written=$((written+1))
        echo -e "  ${CYAN}${VERS[$i]}${NC} (${PATCH_STATE}): wrote ${dropin}"
        grep -v '^;' <<<"$content" | sed 's/^/        /'
        if verify_dropin "$php" "$dropin"; then ok "verified: PHP reports these values"; else failed=$((failed+1)); fi
    done
    [[ "$written" -gt 0 ]] || die "nothing was written"
    if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and any FPM pools yourself, or the old settings stay in force"; fi
    [[ "$failed" -eq 0 ]] || { bad "${failed} version(s) did not verify or were skipped"; exit 1; }
}

cmd_status() {
    local i root php scan dropin eff newest=0 m n
    step "Drop-ins"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        [[ -x "$php" ]] || continue
        if dropin_is_ours "$dropin"; then
            eff="$(effective_settings "$php")"
            ok "${VERS[$i]} (${HANDLER[${VERS[$i]}]:-unknown}): $(tr '\n' ' ' <<<"$eff")"
            m="$(stat -c %Y "$dropin" 2>/dev/null || echo 0)"; [[ "$m" -gt "$newest" ]] && newest="$m"
        else
            inf "${VERS[$i]}: no drop-in from this script"
        fi
    done
    if [[ "$newest" -gt 0 ]]; then
        n="$(older_workers "$newest")"
        if [[ "$n" -gt 0 ]]; then caution "${n} web server / FPM process(es) started before the newest drop-in and still use the old settings: restart Apache and FPM"
        else ok "no web server or FPM process predates the newest drop-in"; fi
    fi
}

cmd_restore() {
    [[ $EUID -eq 0 ]] || die "restore must run as root"
    local i dropin removed=0
    step "Removing drop-ins"
    for i in "${!ROOTS[@]}"; do
        dropin="${ROOTS[$i]}/etc/php.d/${DROPIN}"
        if [[ ! -e "$dropin" ]]; then inf "${VERS[$i]}: nothing to remove"
        elif dropin_is_ours "$dropin"; then rm -f "$dropin"; ok "${VERS[$i]}: removed"; removed=$((removed+1))
        else caution "${VERS[$i]}: ${dropin} was not written by this script; left alone"; fi
    done
    if [[ "$removed" -gt 0 ]]; then
        caution "CVE-2026-115560 is not fixed by the 21 October releases; removing the drop-in turns upload progress back on."
        if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and FPM yourself"; fi
    fi
}

cmd_cleanup() {
    [[ $EUID -eq 0 ]] || die "cleanup must run as root"
    local i root php scan dropin changed=0
    step "Reducing drop-ins to what CVE-2026-115560 still needs"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        dropin_is_ours "$dropin" || { inf "${VERS[$i]}: no drop-in from this script"; continue; }
        patch_state "$php"
        if [[ "$PATCH_STATE" != patched && "$FORCE" -eq 0 ]]; then caution "${VERS[$i]}: still unpatched; kept as is (--force to reduce it anyway)"; continue; fi
        write_dropin "$dropin" "${MARKER}
; CVE-2026-115560 is not fixed by the 21 October releases: keep upload progress off.
session.upload_progress.enabled = 0"
        ok "${VERS[$i]}: reduced to session.upload_progress.enabled = 0"; changed=$((changed+1))
    done
    if [[ "$changed" -gt 0 ]]; then
        if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and FPM yourself"; fi
    fi
}

# ---- main --------------------------------------------------------------------
env_banner
discover
load_handlers
case "$CMD" in
    check)   cmd_check ;;
    apply)   cmd_apply ;;
    status)  cmd_status ;;
    restore) cmd_restore ;;
    cleanup) cmd_cleanup ;;
esac
