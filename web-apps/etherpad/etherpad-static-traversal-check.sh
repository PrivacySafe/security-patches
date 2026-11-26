#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Etherpad static path-traversal check for CVE-2026-114516  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# GHSA-mc8w-wjhw-45x5 / CVE-2026-114516: Etherpad Lite (npm package
# "etherpad-lite"), critical, CVSS 3.1 9.8
# (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H), CWE-22/CWE-200/CWE-306.
# Reported by gcm-explo1t, published 27 October 2026. Affects 1.8.14 through
# 3.3.2; fixed in 3.3.3.
#
# Etherpad's src/node/utils/sanitizePathname.ts rejects a request path
# containing a literal '..' path component, and converts a literal backslash
# to a forward slash only on Windows, by design, since on POSIX a backslash
# is an ordinary filename byte and folding it early would make a real '..\\'
# filename impossible to reach. src/node/utils/Minify.ts, which serves a
# plugin's static assets, runs that sanitizer first and then, for the
# request's plugin-static branch only, folds every backslash to a forward
# slash again unconditionally, on every platform, justified by a comment
# asserting the opposite of the invariant above. On a GNU/Linux host this
# turns an inert '..\\' sequence the sanitizer passed as ordinary bytes into
# a live '../' sequence after the one check that would have caught it, and
# because the plugin path is joined as an absolute path first, the eventual
# path.resolve() call discards the intended root entirely, so the traversal
# reaches any file the Etherpad process can read regardless of how deep the
# install is nested.
#
# The route (src/node/hooks/express/static.ts, 'app.all("/static/*filename",
# minify)') is registered on Etherpad's expressPreSession hook, which the
# Express app runs before it installs the session and auth-check middleware
# (src/node/hooks/express.ts). It is therefore reachable by anyone who can
# send an HTTP request to the port, with no account, no session and no
# config flag (requireAuthentication, requireAuthorization, users) able to
# gate it. A request only needs the literal plugin-path prefix and a
# URL-encoded backslash, '%5C', since an encoded forward slash ('%2F') is
# decoded and re-split by Etherpad's router before reaching the sanitizer
# and is rejected there; a plain reverse proxy does not block this, because
# '%5C' is ordinary request-path text that proxies forward unchanged. The
# always-registered core pseudo-plugin name is 'ep_etherpad-lite', which
# means every installation has at least one working plugin-path prefix
# regardless of which third-party plugins are actually installed.
#
# What a successful read can reach: settings.json and credentials.json
# (admin password, session secret, database credentials, SSO client
# secrets), /proc/self/environ (any secret passed as an environment
# variable, such as an admin password set for a container deployment), TLS
# private keys, the pad database file, and ordinary OS files. The disclosed
# admin password then mints an admin session against POST /admin-auth/,
# and an admin session can install an attacker-controlled plugin through
# the /pluginfw/installer Socket.IO namespace, which Etherpad requires
# in-process, i.e. remote code execution as the Etherpad process user.
#
# What this script does:
#   check     - read-only. Finds installed etherpad-lite copies (by
#               package.json under the usual install roots, or a running
#               process's working directory) and reports each one's version
#               against the fixed release. Exits 1 if any installed copy is
#               below 3.3.3, 0 if every one found is at or above it, 2 if
#               none was found or the result could not be determined.
#   hunt      - read-only. Greps readable web server and Etherpad logs for
#               the request-path signature this exploit requires: the
#               plugin-static route together with a URL-encoded backslash.
#               A match is a strong, specific indicator, since that
#               sequence has no legitimate reason to appear in ordinary
#               traffic; finding none does not prove nothing happened, since
#               a successful read need not be logged anywhere this script
#               can reach, and a request that only reads one known-harmless
#               file would still match.
#   mitigate [--dry-run] [--reload] - nginx only (see the README for Apache). Adds an
#               nginx snippet that rejects any request whose raw URI
#               contains an encoded backslash ('%5c'/'%5C') with a 400,
#               included from the http block so it applies to every server
#               Etherpad might be proxied behind on this host, backs up
#               every file it touches, verifies the result with 'nginx -t',
#               and rolls back automatically if the test fails. This blocks
#               the one separator this exploit depends on; it is not a
#               substitute for upgrading, since any other route this script
#               does not know about that relies on the same decode quirk
#               would not be covered. Requires root. --reload gracefully
#               reloads nginx afterward (systemctl reload where that unit
#               exists, otherwise nginx -s reload); without it, reload
#               nginx yourself once you're satisfied.
#   rollback [--dry-run] [--reload] - restores every file mitigate backed up and
#               removes the snippet, then verifies with 'nginx -t'.
#               Requires root. --reload as above.
#   rules     - prints a short explanation with no side effects.
#   version   - prints this script's version.
#
# What this script can't see: a backslash-handling bug reachable through a
# path other than the plugin-static branch described above (none is known
# as of this script's writing); an Apache or other reverse proxy in front of
# Etherpad, which needs the equivalent rule added by hand (see the README);
# and an install this script's search roots do not cover, such as one built
# from source in an arbitrary directory with no readable package.json.
#
# --dry-run (mitigate, rollback): prints what would change and writes
# nothing, so it needs no root.
# Exit codes: check: 0 clear, 1 exposed, 2 undetermined/error.
#             hunt: 0 nothing found, 1 found a match, 2 error.
#             mitigate/rollback: 0 success, 2 error.
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="etherpad-static-traversal-check.sh"
SCRIPT_VERSION="1.3.0"
SCRIPT_DATE="2026-11-25"
# temporary files, removed on exit
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
case "${1:-}" in
  -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; exit 0 ;;
esac

ADVISORY="https://github.com/ether/etherpad/security/advisories/GHSA-mc8w-wjhw-45x5"
CVE_REF="https://www.cve.org/CVERecord?id=CVE-2026-114516"
FIXED_DEFAULT="3.3.3"
FIXED="${ETHERPAD_FIXED:-$FIXED_DEFAULT}"

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; RST=$'\033[0m'
[ -t 1 ] || { RED=""; YEL=""; GRN=""; BLU=""; RST=""; }
warn() { printf '%s[!]%s %s\n' "$RED" "$RST" "$1" >&2; }
note() { printf '%s[*]%s %s\n' "$YEL" "$RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
inf()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$1"; }
die()  { warn "$1"; exit 2; }

# ---------- structured output and read-only mode (the same block in every script) ----------
# Generated from automation/output-block.bash by automation/psf-output.py; edit it there.
# --output jsonl (or PSF_OUTPUT=jsonl) writes JSON Lines, one record per line, when the script ends:
# a start record, an event for each finding, a text record for any other line, and a verdict.
# The format is described in automation/README.md. --output text, the default, changes nothing.
# NO_COLOR (https://no-color.org): set to anything, no color codes in the text output, for screen readers and logs.
if [[ -n "${NO_COLOR:-}" ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v
fi
# PSF_READ_ONLY=1 refuses every command that changes the host, before it starts.
_PSF_FMT="${PSF_OUTPUT:-text}"; _psf_a=()
while (($#)); do
    case "$1" in
        --output) [[ $# -ge 2 ]] || { echo "--output needs a format: text or jsonl" >&2; exit 2; }; _PSF_FMT="$2"; shift 2 ;;
        --output=*) _PSF_FMT="${1#--output=}"; shift ;;
        *) _psf_a+=("$1"); shift ;;
    esac
done
set -- "${_psf_a[@]+"${_psf_a[@]}"}"; unset _psf_a
case "$_PSF_FMT" in text|jsonl) ;; *) echo "--output: unknown format '$_PSF_FMT' (text or jsonl; psf-report renders Markdown, HTML and PDF)" >&2; exit 2 ;; esac
_PSF_CMD=""; for _psf_x in "$@"; do [[ "$_psf_x" == -* ]] || { _PSF_CMD="$_psf_x"; break; }; done; unset _psf_x

# A command that changes the host is refused in read-only mode, whatever else it is asked to do.
psf_refuse_change() {
    [[ "${PSF_READ_ONLY:-0}" == 1 ]] || return 0
    local m="read-only mode (PSF_READ_ONLY=1): ${1:-this change} refused; nothing was changed"
    if [[ "$_PSF_FMT" == jsonl ]]; then PSF_KIND="" _psf_ev error "$m"; else echo "$m" >&2; fi
    exit 2
}

# A check that found nothing to examine says so; only the jsonl verdict records it.
psf_not_applicable() { [[ "$_PSF_FMT" == jsonl ]] && _psf_rec applicable "" "$*"; return 0; }

if [[ "$_PSF_FMT" == jsonl ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v   # the colors this script set
    _PSF_SELF="${BASH_SOURCE[0]}"; _PSF_TOOL="${SCRIPT_NAME:-${_PSF_SELF##*/}}"; _PSF_TOOL="${_PSF_TOOL%.sh}"
    _PSF_HOST="$(cat /proc/sys/kernel/hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"
    _PSF_MAIN_PID="$BASHPID"; _PSF_T0="${EPOCHREALTIME:-$(date +%s)}"; _PSF_EXIT_CMD=""
    _PSF_RUN="${_PSF_HOST}-${_PSF_TOOL}-$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)-$$"
    _psf_d="$(cd "$(dirname "$_PSF_SELF")" 2>/dev/null && pwd)"; _psf_c="${_psf_d%/*}"; _psf_c="${_psf_c##*/}"
    case "$_psf_c" in
        servers|system|runtimes|web-apps|developer|threats) _PSF_FIX="https://privacysafe.app/docs/security-patches/${_psf_c}/${_psf_d##*/}/" ;;
        *) _PSF_FIX="https://privacysafe.app/docs/security-patches/" ;;
    esac; unset _psf_d _psf_c

    _psf_s() {   # a JSON string: escapes, newlines kept, color codes and other control characters dropped
        local s="$1"
        while [[ "$s" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do s="${s/"${BASH_REMATCH[0]}"/}"; done
        s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; s="${s//$'\t'/\\t}"
        s="${s//[$'\001'-$'\037']/}"
        printf '"%s"' "$s"
    }
    # A record this block writes carries a secret marker, made fresh for each run and kept in this shell only.
    # At exit only marked lines are records; any other line, even one that looks like a record (a file name
    # with a newline in it, a log line the script prints), stays text, so output cannot forge a record.
    _PSF_MARK=""; read -r _PSF_MARK </proc/sys/kernel/random/uuid 2>/dev/null || _PSF_MARK="${RANDOM}${RANDOM}${RANDOM}${RANDOM}$$"
    _PSF_MARK=$'\036'"psf-${_PSF_MARK}"$'\036'
    _psf_rec() {   # type level message [more JSON fields]: one marked record on stdout
        local type="$1" level="$2" msg="$3" ts tsms ems cves="" rest extra="${4:-}" c er="${EPOCHREALTIME:-}"
        # one reading of the clock, written three ways: ts to the second (as records always had it), ts_ms to the
        # millisecond (as the joint event logging guide prefers), both RFC 3339 in UTC, and ts_epoch_ms, the same
        # instant as whole milliseconds since 1970 for tools that want a number. EPOCHREALTIME (bash 5) can use a
        # decimal comma; without it the time is whole seconds and the milliseconds are 000.
        if [[ "$er" =~ ^([0-9]+)[.,]([0-9]{3}) ]]; then
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' "${BASH_REMATCH[1]}"; tsms="${ts%Z}.${BASH_REMATCH[2]}Z"
            ems="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        else
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' -1; tsms="${ts%Z}.000Z"
            printf -v ems '%(%s)T' -1; ems="${ems}000"
        fi
        rest="$msg"
        while [[ "$rest" =~ (CVE-[0-9]{4}-[0-9]{4,}) ]]; do
            c="${BASH_REMATCH[1]}"; [[ ",$cves," == *",\"$c\","* ]] || cves="${cves:+$cves,}\"$c\""; rest="${rest#*"$c"}"
        done
        local kind="${PSF_KIND:-}"
        [[ -z "$kind" && "$_PSF_CMD" == hunt && "$level" =~ ^(crit|warn)$ ]] && kind=indicator
        [[ -n "$kind" && "$level" =~ ^(crit|warn)$ ]] && extra+=",\"kind\":$(_psf_s "$kind")"
        [[ -n "${PSF_CODE:-}" ]] && extra+=",\"code\":$(_psf_s "$PSF_CODE")"
        [[ -n "${PSF_PATH:-}" ]] && extra+=",\"path\":$(_psf_s "$PSF_PATH")"
        [[ "$level" =~ ^(crit|warn)$ ]] && extra+=",\"fix\":$(_psf_s "${PSF_FIX:-$_PSF_FIX}")"
        printf '%s{"schema":1,"type":"%s","run":%s,"tool":%s,"version":%s,"host":%s,"command":%s,"ts":"%s","ts_ms":"%s","ts_epoch_ms":%s%s,"msg":%s,"cve":[%s]%s}\n' \
            "$_PSF_MARK" "$type" "$(_psf_s "$_PSF_RUN")" "$(_psf_s "$_PSF_TOOL")" "$(_psf_s "${SCRIPT_VERSION:-}")" "$(_psf_s "$_PSF_HOST")" \
            "$(_psf_s "$_PSF_CMD")" "$ts" "$tsms" "$ems" "${level:+,\"level\":\"$level\"}" "$(_psf_s "$msg")" "$cves" "$extra"
    }
    _psf_ev() { local level="$1" m; shift; printf -v m '%b' "$*"; m="${m#"${m%%[![:space:]]*}"}"; m="${m%"${m##*[![:space:]]}"}"; _psf_rec event "$level" "$m"; }

    # the helpers this script defined above now write records
    declare -F ok      >/dev/null && ok()      { _psf_ev ok "$*"; }
    declare -F pass    >/dev/null && pass()    { _psf_ev ok "$*"; }
    declare -F info    >/dev/null && info()    { _psf_ev info "$*"; }
    declare -F inf     >/dev/null && inf()     { _psf_ev info "$*"; }
    declare -F inf_hunt >/dev/null && inf_hunt() { _psf_ev info "$*"; }
    declare -F note    >/dev/null && note()    { _psf_ev info "$*"; }
    declare -F tip     >/dev/null && tip()     { _psf_ev info "$*"; }
    declare -F warn    >/dev/null && warn()    { _psf_ev warn "$*"; }
    declare -F caution >/dev/null && caution() { _psf_ev warn "$*"; }
    declare -F bad     >/dev/null && bad()     { _psf_ev crit "$*"; }
    declare -F fail    >/dev/null && fail()    { _psf_ev crit "$*"; }
    declare -F step    >/dev/null && step()    { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    declare -F section >/dev/null && section() { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    die() { _psf_ev error "$*"; exit 2; }

    # Everything the script prints goes to a private file; at exit it becomes records, and a verdict closes the run.
    # As root it is always /tmp (root's, sticky): a TMPDIR another account can write would let it swap the file.
    _PSF_TMPD="${TMPDIR:-/tmp}"; [[ $EUID -eq 0 ]] && _PSF_TMPD=/tmp
    _PSF_TMP="$(mktemp "$_PSF_TMPD/psf-output.XXXXXXXXXX")" || { echo "--output jsonl: cannot make a temporary file" >&2; exit 2; }
    exec {_PSF_OUT}>&1 {_PSF_ERR}>&2
    exec {_PSF_RD}<"$_PSF_TMP"        # read back at exit through this handle
    exec >>"$_PSF_TMP" 2>&1
    rm -f "$_PSF_TMP"                 # nameless from here on: nothing is left in /tmp, even when the run is killed
    _psf_rec start "" "$_PSF_TOOL ${SCRIPT_VERSION:-} ${_PSF_CMD:-(no command)}" \
        ",\"script_date\":$(_psf_s "${SCRIPT_DATE:-}"),\"euid\":${EUID},\"read_only\":$([[ "${PSF_READ_ONLY:-0}" == 1 ]] && echo true || echo false)"
    _psf_finish() {
        local rc="$1" line crit=0 warn=0 ok=0 info=0 err=0 text=0 app=null result t1 dur seq=0
        exec 1>&"$_PSF_OUT" 2>&"$_PSF_ERR"
        _psf_out() { local r="${1#"$_PSF_MARK"}"; seq=$((seq + 1)); printf '{"schema":1,"seq":%d,%s\n' "$seq" "${r#\{\"schema\":1,}"; }   # numbered in output order
        local fd="$_PSF_RD"
        while IFS= read -r line <&"$fd" || [[ -n "$line" ]]; do
            if [[ "$line" == "$_PSF_MARK"'{"schema":1,'* ]]; then
                case "$line" in
                    *'"type":"applicable"'*) app=false ;;
                    *'"level":"crit"'*) crit=$((crit + 1)) ;;
                    *'"level":"warn"'*) warn=$((warn + 1)) ;;
                    *'"level":"ok"'*) ok=$((ok + 1)) ;;
                    *'"level":"info"'*) info=$((info + 1)) ;;
                    *'"level":"error"'*) err=$((err + 1)) ;;
                esac
                _psf_out "$line"
            else
                line="${line//$'\036'/}"
                while [[ "$line" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do line="${line/"${BASH_REMATCH[0]}"/}"; done
                line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
                [[ -n "$line" ]] || continue
                text=$((text + 1)); _psf_out "$(_psf_rec text "" "$line")"
            fi
        done
        exec {fd}<&-
        case "$rc" in 0) result=clean ;; 1) result=findings ;; *) result=undecided ;; esac
        [[ "$app" == null && $((crit + warn + ok)) -gt 0 ]] && app=true
        t1="${EPOCHREALTIME:-$(date +%s)}"; dur="$(awk -v a="$_PSF_T0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }' 2>/dev/null || echo 0)"
        _psf_out "$(_psf_rec verdict "" "$result" ",\"result\":\"$result\",\"exit\":$rc,\"applicable\":$app,\"duration_s\":$dur,\"counts\":{\"crit\":$crit,\"warn\":$warn,\"ok\":$ok,\"info\":$info,\"error\":$err,\"text\":$text}")"
    }
    _psf_on_exit() {
        local rc=$?
        if [[ -n "$_PSF_EXIT_CMD" ]]; then eval "$_PSF_EXIT_CMD"; fi
        [[ "$BASHPID" == "$_PSF_MAIN_PID" ]] && _psf_finish "$rc"
        exit "$rc"
    }
    # the script's own EXIT traps still run, before the verdict is written
    trap() {
        local action has_exit=0 s rest=()
        # shellcheck disable=SC2064   # the script's own trap arguments, passed on unchanged
        case "${1:-}" in ""|-p|-l) builtin trap "$@"; return ;; esac
        action="$1"; shift
        for s in "$@"; do if [[ "$s" == EXIT || "$s" == 0 ]]; then has_exit=1; else rest+=("$s"); fi; done
        if ((has_exit)); then
            if [[ "$action" == - ]]; then _PSF_EXIT_CMD=""; else _PSF_EXIT_CMD="$action"; fi
            builtin trap _psf_on_exit EXIT
        fi
        # shellcheck disable=SC2064   # the action string the script wrote, passed on as it was given
        ((${#rest[@]})) && builtin trap "$action" "${rest[@]}"
        return 0
    }
    builtin trap _psf_on_exit EXIT
fi
case "$_PSF_CMD" in
    mitigate|rollback|harden|fix|apply|restore|remove|uninstall|install|enable|disable|quarantine|purge|revert|undo)
        psf_refuse_change "$_PSF_CMD" ;;
esac
# ---------- end of structured output and read-only mode ----------
# Nothing to check on this host: say so in a Verdict section, record "not applicable" and stop with exit 0.
na_exit() { psf_not_applicable "$1"; echo; echo "===== Verdict ====="; echo "[i] Not applicable: $1."; exit 0; }

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT: stop unless root, and name the sudo command to run instead.
need_root() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then
        die "${1}: run it as root, for example: sudo ${SELF_CMD}"
    else
        die "${1}: run it as root (sudo is not installed here)"
    fi
}

ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# Roots to search for an etherpad-lite package.json. Overridable so a
# non-standard install location can be checked without editing the script.
ETHERPAD_ROOTS_DEFAULT="/opt/etherpad-lite /usr/share/etherpad-lite /usr/local/etherpad-lite /srv/etherpad-lite /var/www/etherpad-lite /home"
# shellcheck disable=SC2206
ETHERPAD_ROOTS=(${ETHERPAD_ROOTS:-$ETHERPAD_ROOTS_DEFAULT})

# Find every package.json that names the etherpad-lite package itself
# (not one of its dependencies, which would also be named "etherpad-lite"
# nowhere else, but a naive recursive grep could still find a copy vendored
# inside node_modules of an unrelated project; excluding node_modules
# segments below keeps this to real top-level installs).
find_installs() {
    local root f
    for root in "${ETHERPAD_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -maxdepth 6 -type f -name 'package.json' -not -path '*/node_modules/*' 2>/dev/null | while IFS= read -r f; do
            if grep -q '"name"[[:space:]]*:[[:space:]]*"etherpad-lite"' "$f" 2>/dev/null; then
                echo "$f"
            fi
        done
    done
}

pkg_version() {
    # A dependency-free JSON "version" read: good enough for the flat,
    # single-line fields package.json always uses for this.
    grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"$/\1/'
}

do_check() {
    local files found=0 worst=0 f ver
    files=$(find_installs)
    if [ -z "$files" ]; then
        # Fall back to a running process: look for node running a server.js
        # whose cwd or script path mentions etherpad, and report its
        # package.json if one is reachable alongside it.
        local pid cwd
        for pid in $(pgrep -f 'node.*etherpad' 2>/dev/null); do
            cwd=$(readlink -f "/proc/$pid/cwd" 2>/dev/null) || continue
            [ -f "$cwd/package.json" ] && grep -q '"name"[[:space:]]*:[[:space:]]*"etherpad-lite"' "$cwd/package.json" 2>/dev/null && files="$files
$cwd/package.json"
        done
    fi
    files=$(printf '%s\n' "$files" | sed '/^$/d')
    if [ -z "$files" ]; then
        na_exit "no etherpad-lite install was found under ${ETHERPAD_ROOTS[*]}, and no running Etherpad (set ETHERPAD_ROOTS if it lives elsewhere)"
    fi

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        found=1
        ver=$(pkg_version "$f")
        if [ -z "$ver" ]; then
            warn "$f: found the package but could not read its version field."
            worst=1
            continue
        fi
        if ver_ge "$ver" "$FIXED"; then
            ok "$f: etherpad-lite $ver is at or above the fixed release ($FIXED)."
        else
            warn "$f: etherpad-lite $ver is below the fixed release ($FIXED). Affected range is 1.8.14 to 3.3.2."
            worst=1
        fi
    done <<< "$files"

    if [ "$found" -eq 0 ]; then
        na_exit "no etherpad-lite install was found"
    fi
    if [ "$worst" -eq 1 ]; then
        warn "Verdict: EXPOSED. Upgrade to $FIXED, or run 'mitigate' (nginx only) to block the request pattern this needs until you can. Advisory: ${ADVISORY} ; CVE: ${CVE_REF}"
        return 1
    fi
    ok "Verdict: CLEAR."
    return 0
}

do_hunt() {
    local logs=() seen="" f found=0
    for f in /var/log/nginx/access.log* /var/log/nginx/*access*.log* \
             /var/log/apache2/access.log* /var/log/apache2/*access*.log* \
             /var/log/httpd/access_log* /var/log/httpd/*access*log* \
             /var/log/etherpad/*.log /opt/etherpad-lite/var/*.log; do
        # The glob patterns above deliberately overlap (access.log* also
        # matches *access*.log*); skip a path already added so it is not
        # scanned, and its matches not reported, twice.
        [ -r "$f" ] || continue
        case " $seen " in *" $f "*) continue ;; esac
        logs+=("$f"); seen="$seen $f"
    done
    if [ "${#logs[@]}" -eq 0 ]; then
        warn "No readable web server or Etherpad log found in the usual locations."
        return 2
    fi
    inf "Scanning: ${logs[*]}"
    # The signature this exploit needs: the plugin-static route together
    # with an encoded backslash, case-insensitively, anywhere after it on
    # the same line. Matching only the route without the encoded backslash
    # would flag ordinary legitimate plugin asset requests.
    local matches
    matches=$(grep -EHi 'static/plugins/[^[:space:]]*%5c' "${logs[@]}" 2>/dev/null)
    if [ -n "$matches" ]; then
        warn "Found log lines matching the plugin-static + encoded-backslash signature this exploit requires:"
        printf '%s\n' "$matches" | sed 's/^/      /'
        found=1
    else
        ok "No matching request signature found in the logs checked."
    fi
    return $found
}

NGINX_SNIPPET_DIR_DEFAULT="/etc/nginx/snippets"
NGINX_SNIPPET_DIR="${NGINX_SNIPPET_DIR:-$NGINX_SNIPPET_DIR_DEFAULT}"
NGINX_HTTP_SNIPPET="${NGINX_SNIPPET_DIR}/psf-etherpad-traversal-block-http.conf"
NGINX_SERVER_SNIPPET="${NGINX_SNIPPET_DIR}/psf-etherpad-traversal-block-server.conf"
BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/etherpad-static-traversal}"

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" || die "Could not create $BACKUP_DIR"; }
backup_file() {
    local f="$1" stamp base
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    base=$(echo "$f" | sed 's#^/##; s#/#_#g')
    cp -a "$f" "$BACKUP_DIR/${stamp}.${base}.bak" || die "Could not back up $f"
    printf '%s\t%s\n' "$f" "$BACKUP_DIR/${stamp}.${base}.bak" >> "$BACKUP_DIR/.manifest.tsv"
}

nginx_test() {
    # the output is kept in a variable, never in a file under /tmp
    local out rc
    out="$(nginx -t 2>&1)"; rc=$?
    printf '%s\n' "$out" >&2
    return $rc
}

# Every config file nginx actually loads: nginx -T names each one in a
# '# configuration file PATH:' header, which is more reliable than guessing
# at sites-enabled/conf.d, since a host can lay its includes out differently.
nginx_files() {
    { nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p'
      echo /etc/nginx/nginx.conf
      ls /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null
    } | while IFS= read -r f; do [ -f "$f" ] && [ -r "$f" ] && echo "$f"; done | awk '!s[$0]++'
}

# Inject "include SNIP;" as the first line of the first http{} block found
# in FILE, unless it is already included somewhere in FILE. http{} appears
# at most once per file in practice, so this stops after the first.
AWK_HTTP_INJECT='
{
    print $0
    if (!done && $0 !~ /^[ \t]*#/ && $0 ~ /^[ \t]*http[ \t]*\{/) {
        if (!already) print "    include " snip ";"
        done = 1
    }
}'

# Inject "include SNIP;" as the first line of every server{} block found
# in FILE, except one nested inside a top-level mail{} or stream{} block:
# nginx reuses the same "server {" keyword there, where "if"/"return" are
# not valid the way they are under http. A file conventionally included
# from inside http{} (such as one under sites-enabled/ or conf.d/) has no
# "http {" line of its own to detect, so the default is to treat a server{}
# as http-eligible; only an explicit mail{}/stream{} ancestor in the same
# file excludes it. Tracks brace depth so a server{} holding its own nested
# blocks (such as location{}) is still matched as a whole and only has the
# include added once, at its own top.
AWK_SERVER_INJECT='
function chk(code) { if (index(code, snip) > 0) has = 1 }
function flush(   i) {
    for (i = 1; i <= n; i++) {
        print buf[i]
        if (i == 1 && !has) print "    include " snip ";"
    }
    n = 0; has = 0
}
{
    raw = $0; code = raw; sub(/#.*/, "", code)
    o = gsub(/\{/, "{", code); c = gsub(/\}/, "}", code)
    if (!inserv) {
        if (!excldepth && code ~ /^[ \t]*(mail|stream)[ \t]*\{/) { excldepth = depth + 1 }
        if (!excldepth && raw ~ /^[ \t]*server[ \t]*\{/) {
            inserv = 1; sdepth = depth; buf[++n] = raw; chk(code); depth += o - c
            if (depth <= sdepth) { flush(); inserv = 0 }
        } else {
            print raw; depth += o - c
            if (excldepth && depth < excldepth) { excldepth = 0 }
        }
    } else {
        buf[++n] = raw; chk(code)
        depth += o - c
        if (depth <= sdepth) { flush(); inserv = 0 }
    }
}
END { if (n > 0) flush() }'

do_mitigate() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "mitigate changes the host"
    command -v nginx >/dev/null 2>&1 || die "nginx not found. This script's mitigate only covers nginx; see the README for an Apache rule to add by hand."
    local files=() f tmp changed=0
    while IFS= read -r f; do [ -n "$f" ] && files+=("$f"); done < <(nginx_files)
    [ "${#files[@]}" -gt 0 ] || die "No readable nginx configuration file found."

    if [ "$dry" = "1" ]; then
        inf "Dry run: would write $NGINX_HTTP_SNIPPET and $NGINX_SERVER_SNIPPET (their text: see 'rules')"
    else
    ensure_backup_dir
    mkdir -p "$NGINX_SNIPPET_DIR" || die "Could not create $NGINX_SNIPPET_DIR"
    [ -f "$NGINX_HTTP_SNIPPET" ] && backup_file "$NGINX_HTTP_SNIPPET"
    [ -f "$NGINX_SERVER_SNIPPET" ] && backup_file "$NGINX_SERVER_SNIPPET"

    # A bare "if" is only valid in server/location context, not at http
    # level, so the http-level snippet only computes a variable (map IS
    # valid at http level); the server-level snippet does the "if" and the
    # actual return, using that variable.
    cat > "$NGINX_HTTP_SNIPPET" <<'EOF'
# Added by psf-security-patches (CVE-2026-114516, GHSA-mc8w-wjhw-45x5).
# Remove with: etherpad-static-traversal-check.sh rollback
map $request_uri $psf_etherpad_traversal_block {
    default 0;
    "~*%5[cC]" 1;
}
EOF
    cat > "$NGINX_SERVER_SNIPPET" <<'EOF'
# Added by psf-security-patches (CVE-2026-114516, GHSA-mc8w-wjhw-45x5).
# Rejects any request whose raw URI contains a URL-encoded backslash, the
# separator this Etherpad path-traversal exploit depends on. Safe for any
# site: a real request legitimately needing a literal '%5c'/'%5C' in its
# path is not a pattern normal web traffic produces.
# Remove with: etherpad-static-traversal-check.sh rollback
if ($psf_etherpad_traversal_block) {
    return 400;
}
EOF
    fi

    tmp=$(mktemp "${TMPDIR:-/tmp}/psf-etherpad-ng.XXXXXX") || die "Could not create a temp file"
    PSF_TMP+=("$tmp")
    for f in "${files[@]}"; do
        local already=0
        grep -qF "$NGINX_HTTP_SNIPPET" "$f" 2>/dev/null && already=1
        if ! awk -v snip="$NGINX_HTTP_SNIPPET" -v already="$already" "$AWK_HTTP_INJECT" "$f" > "$tmp"; then
            warn "Could not process $f for the http-level include; leaving it untouched."
            continue
        fi
        if ! cmp -s "$f" "$tmp"; then
            if [ "$dry" = "1" ]; then inf "Dry run: would add the http-level include to $f"
            else backup_file "$f"; cat "$tmp" > "$f"; ok "nginx: added the http-level include to $f"; fi
            changed=1
        fi

        if ! awk -v snip="$NGINX_SERVER_SNIPPET" "$AWK_SERVER_INJECT" "$f" > "$tmp"; then
            warn "Could not process $f for the server-level include; leaving it untouched."
            continue
        fi
        if ! cmp -s "$f" "$tmp"; then
            # backup_file appends a second, later snapshot of the same file
            # when it was also edited for the http-level include above;
            # rollback restores in reverse order, so it still ends up at
            # the true original either way.
            if [ "$dry" = "1" ]; then inf "Dry run: would add the server-level include to $f"
            else backup_file "$f"; cat "$tmp" > "$f"; ok "nginx: added the server-level include to $f"; fi
            changed=1
        fi
    done
    rm -f "$tmp"
    if [ "$dry" = "1" ]; then inf "Dry run: no files were changed (nginx -t was not run)."; return 0; fi

    if [ "$changed" -eq 0 ]; then
        warn "No server{} block was found to add the include to; nginx found but nothing was changed. Add the rule by hand (see 'rules')."
        return 2
    fi

    if nginx_test; then
        ok "nginx -t accepts the new configuration."
        if [ "${RELOAD:-0}" -ne 1 ]; then
            note "Reload nginx for this to take effect, e.g. 'systemctl reload nginx' or 'nginx -s reload', or rerun with --reload."
        fi
        note "This blocks the one separator this exploit depends on; it is not a substitute for upgrading to $FIXED."
        return 0
    else
        warn "nginx -t rejected the result; rolling back."
        do_rollback
        return 2
    fi
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "$BACKUP_DIR/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0 orig backup
    # read from a process substitution, not a pipe, so a failure is not lost in a subshell
    while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then inf "Dry run: would restore $orig from $backup"; continue; fi
        if cp -a "$backup" "$orig"; then ok "Restored $orig"; else warn "Failed to restore $orig"; failed=1; fi
    done < <(tac "$BACKUP_DIR/.manifest.tsv" 2>/dev/null)
    if [ "$dry" = "1" ]; then inf "Dry run: no files were changed."; return "$failed"; fi
    rm -f "$NGINX_HTTP_SNIPPET" "$NGINX_SERVER_SNIPPET"
    if command -v nginx >/dev/null 2>&1; then
        nginx_test && ok "nginx -t accepts the restored configuration." || warn "nginx -t still fails after rollback; check the config by hand."
    fi
    return "$failed"
}

reload_nginx() {
    [ "${RELOAD:-0}" -eq 1 ] || return 0
    command -v nginx >/dev/null 2>&1 || { note "--reload given but nginx was not found: reload it yourself"; return 0; }
    if command -v systemctl >/dev/null 2>&1 && systemctl list-unit-files 2>/dev/null | grep -q '^nginx\.service'; then
        systemctl reload nginx && inf "reloaded nginx (graceful)" && return 0
    fi
    nginx -s reload && inf "reloaded nginx (graceful, via nginx -s reload)" || note "--reload given but the reload failed: reload it yourself"
}

do_rules() {
    cat <<EOF
CVE-2026-114516 / GHSA-mc8w-wjhw-45x5: Etherpad, CVSS 9.8, unauthenticated
path traversal reachable before the auth middleware runs, able to read any
file the Etherpad process can, including credentials and secrets, which
chains to an admin session and then remote code execution through the
plugin installer.

The fix is upgrading etherpad-lite to 3.3.3. 'mitigate' blocks the one
separator the exploit depends on (a URL-encoded backslash) at the nginx
layer as a stopgap; it covers nginx only. For Apache, add the equivalent
rule by hand in the site's config:

    RewriteEngine On
    RewriteCond %{THE_REQUEST} %5[cC] [NC]
    RewriteRule .* - [F]

A plain reverse proxy with no such rule does not stop this on its own: the
traversal uses '%5C', which is ordinary request-path text and proxies
forward unchanged.
EOF
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
    psf_refuse_change "lock_for_change"
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "mitigate rollback" "$@"

case "${1:-check}" in
    check) do_check; exit $? ;;
    hunt) do_hunt; exit $? ;;
    mitigate)
        shift; RELOAD=0; dry=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                --reload) RELOAD=1 ;;
                *) die "Unknown mitigate option: $a (--dry-run --reload)" ;;
            esac
        done
        do_mitigate "$dry"; rc=$?
        [ "$dry" = "1" ] || [ "$rc" != "0" ] || reload_nginx
        exit "$rc"
        ;;
    rollback)
        shift; RELOAD=0; dry=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                --reload) RELOAD=1 ;;
                *) die "Unknown rollback option: $a (--dry-run --reload)" ;;
            esac
        done
        do_rollback "$dry"; rc=$?
        [ "$dry" = "1" ] || [ "$rc" != "0" ] || reload_nginx
        exit "$rc"
        ;;
    rules) do_rules; exit 0 ;;
    version) echo "etherpad-static-traversal-check.sh $SCRIPT_VERSION ($SCRIPT_DATE)"; exit 0 ;;
    *) die "Usage: $0 {check|hunt|mitigate [--dry-run] [--reload]|rollback [--dry-run] [--reload]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
