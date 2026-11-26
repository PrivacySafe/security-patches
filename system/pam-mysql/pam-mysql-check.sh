#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# pam-mysql inverted empty-password check, November 2026: check and hunt (v1)
# CVE-2026-124749 (CVSS 8.1 to 9.8 depending on the setup; demonstrated, no public exploit)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# pam-mysql checks Linux logins against a MySQL table. When a service asks PAM to refuse
# accounts with no password (PAM_DISALLOW_NULL_AUTHTOK, which sshd sets with its default
# PermitEmptyPasswords no), pam-mysql does the opposite: anyone can log in, typing any password,
# as an account whose stored password is NULL (0.8.x) or NULL or empty (the 1.0.0 betas). Every
# release is affected. Debian fixed it on 19 November 2026 (Debian 12: 0.8.2-2+deb12u1, DLA-4919-1;
# Debian 13: 0.8.2-2.1+deb13u1, DSA-6643-1), adding a nullok option that is off by default.
# Ubuntu, Fedora, Gentoo and Debian testing had no fix on 21 November. Do NOT set
# PermitEmptyPasswords yes as a fix: that opens a different hole.
#
# Usage:
#   ./pam-mysql-check.sh [command]
#
#   check (default)  Read-only. Finds the PAM services that use pam_mysql,
#                    reads sshd's PermitEmptyPasswords, judges the installed
#                    package, and reads the table and column pam-mysql checks
#                    from its PAM arguments or config_file. With QUERY_DB=1 it
#                    also asks the database how many rows have no password,
#                    using pam-mysql's own read credentials (count only; add
#                    LIST_USERS=1 to list the names). Exit 0 = not in use or
#                    fixed, 1 = in use and not fixed, 2 = something could not
#                    be read.
#   hunt             Read-only. Lists "Accepted password" logins from the auth
#                    log and the journal. With QUERY_DB=1, a login by an account
#                    that has no stored password now is marked: that login was
#                    a bypass (the table now may not show what it held then: a
#                    backup or the binary log does). Exit 0 = nothing found,
#                    1 = leads, 2 = no log could be read.
#   version          Prints the script version.
#
# Until a fixed package is installed: give every row in the login table a password or lock it,
# then make the password column NOT NULL with no empty default (see the README).
#
# Env overrides:
#   PAM_DIR=/etc/pam.d   SSHD_CONFIG=/etc/ssh/sshd_config   SSHD_T_OUTPUT (testing only)
#   QUERY_DB=0           1 asks the database (needs the mysql or mariadb client)
#   LIST_USERS=0         1 lists the names of rows with no password
#   HUNT_LOG_FILES       instead of /var/log/auth.log* /var/log/secure*
#   PKG_VERSION, OS_RELEASE_FILE   (testing only)
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="pam-mysql-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
CVE="CVE-2026-124749"
PAM_DIR="${PAM_DIR:-/etc/pam.d}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
QUERY_DB="${QUERY_DB:-0}"
LIST_USERS="${LIST_USERS:-0}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

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
have()    { command -v "$1" >/dev/null 2>&1; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}

# ---------- where pam-mysql is used, and how -----------------------------------
pam_lines() { grep -HnE '^[[:space:]]*[^#].*pam_mysql\.so' "$PAM_DIR"/* 2>/dev/null; }
# DB settings: from the PAM arguments, overridden by a config_file (keys users.table and so on)
declare -A DB=()
read_db_settings() {
    local line arg k v cf=""
    line="$(pam_lines | grep -E '[[:space:]]auth[[:space:]]' | head -n1)"
    [[ -n "$line" ]] || line="$(pam_lines | head -n1)"
    for arg in ${line#*pam_mysql.so}; do
        k="${arg%%=*}"; v="${arg#*=}"; [[ "$arg" == *=* ]] || continue
        case "$k" in user|passwd|host|db|table|usercolumn|passwdcolumn|where|crypt) DB[$k]="$v" ;; config_file) cf="$v" ;; esac
    done
    if [[ -n "$cf" && -r "$cf" ]]; then
        while IFS='=' read -r k v; do
            k="$(echo "$k" | tr -d '[:space:]')"; v="$(echo "$v" | sed -E 's/^[[:space:]]+|[[:space:]]+$//g')"
            case "$k" in users.host) DB[host]="$v" ;; users.database) DB[db]="$v" ;; users.db_user) DB[user]="$v" ;; users.db_passwd) DB[passwd]="$v" ;;
                         users.table) DB[table]="$v" ;; users.user_column) DB[usercolumn]="$v" ;; users.password_column) DB[passwdcolumn]="$v" ;; esac
        done < <(grep -E '^[[:space:]]*users\.' "$cf")
    elif [[ -n "$cf" ]]; then caution "config_file ${cf} cannot be read (run as root)"; fi
}
permit_empty() {   # -> yes | no | unknown
    local v=""
    if [[ -n "${SSHD_T_OUTPUT:-}" ]]; then v="$(grep -i '^permitemptypasswords ' "$SSHD_T_OUTPUT" | awk '{print tolower($2)}')"
    elif is_root && have sshd; then v="$(sshd -T 2>/dev/null | awk 'tolower($1)=="permitemptypasswords" {print tolower($2)}')"; fi
    [[ -n "$v" ]] || v="$(grep -iE '^[[:space:]]*PermitEmptyPasswords[[:space:]]' "$SSHD_CONFIG" 2>/dev/null | head -n1 | awk '{print tolower($2)}')"
    [[ -n "$v" ]] || { [[ -r "$SSHD_CONFIG" ]] && v=no; }
    echo "${v:-unknown}"
}
pkg_state() {   # -> "<rc>|<text>": 0 fixed, 1 not fixed, 2 unknown
    local v="${PKG_VERSION:-}" codename fixed
    if [[ -z "$v" ]] && have dpkg-query; then v="$(dpkg-query -W -f='${Version}' libpam-mysql 2>/dev/null)"; fi
    if [[ -n "$v" ]]; then
        codename="$(sed -nE 's/^VERSION_CODENAME=//p' "$OS_RELEASE_FILE" 2>/dev/null)"
        case "$codename" in bookworm) fixed="0.8.2-2+deb12u1" ;; trixie) fixed="0.8.2-2.1+deb13u1" ;; *) fixed="" ;; esac
        if [[ -n "$fixed" ]] && have dpkg && dpkg --compare-versions "$v" ge "$fixed"; then echo "0|libpam-mysql ${v} (fixed: ${fixed} or later, with the new nullok option off)"; return; fi
        if [[ -z "$fixed" ]]; then echo "1|libpam-mysql ${v}: ${codename:-this release} has no fixed package as of 21 November 2026"; return; fi
        echo "1|libpam-mysql ${v} is before ${fixed}"; return
    fi
    if have rpm && rpm -q pam_mysql >/dev/null 2>&1; then echo "1|$(rpm -q pam_mysql): no fixed Fedora or RHEL package as of 21 November 2026"; return; fi
    echo "2|the pam-mysql package version could not be read (built from source?): every released version is affected"
}
mysql_client() { if have mysql; then echo mysql; elif have mariadb; then echo mariadb; fi; }
db_query() {   # <sql> -> rows, using pam-mysql's own credentials; the password goes through the environment
    local c; c="$(mysql_client)"; [[ -n "$c" ]] || return 3
    MYSQL_PWD="${DB[passwd]:-}" "$c" --batch --skip-column-names -h "${DB[host]:-localhost}" -u "${DB[user]:-}" "${DB[db]:-}" -e "$1" 2>/dev/null
}
ident_ok() { [[ "$1" =~ ^[A-Za-z0-9_.]+$ ]]; }
EMPTY_USERS=()
query_empty() {   # fills EMPTY_USERS; returns 0 ok, 1 could not ask
    local t="${DB[table]:-}" uc="${DB[usercolumn]:-}" pc="${DB[passwdcolumn]:-}"
    ident_ok "$t" && ident_ok "$uc" && ident_ok "$pc" || { caution "table or column names missing or unusual (table='${t}' usercolumn='${uc}' passwdcolumn='${pc}'): not asking"; return 1; }
    local out
    out="$(db_query "SELECT ${uc} FROM ${t} WHERE ${pc} IS NULL OR ${pc} = ''")" || { caution "the database did not answer with pam-mysql's credentials"; return 1; }
    mapfile -t EMPTY_USERS < <(printf '%s\n' "$out" | sed '/^$/d')
    return 0
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments"
    limited_view "PAM and sshd configuration"
    local lines svc pe rc why
    step "PAM services that use pam_mysql"
    lines="$(pam_lines)"
    if [[ -z "$lines" ]]; then
        [[ -d "$PAM_DIR" ]] || die "cannot read ${PAM_DIR}"
        info "No PAM service uses pam_mysql: not affected."; return 0
    fi
    while IFS= read -r svc; do inf "${svc}"; done <<<"$lines"
    step "sshd"
    pe="$(permit_empty)"
    case "$pe" in
        no) bad "PermitEmptyPasswords no (the default): sshd asks pam-mysql to refuse accounts with no password, and an affected pam-mysql lets them in instead" ;;
        yes) caution "PermitEmptyPasswords yes: not the trigger for this flaw, but accounts with no password can log in anyway. Set it to no once pam-mysql is fixed" ;;
        *) caution "PermitEmptyPasswords could not be read (run as root): assumed no, the default" ;;
    esac
    step "Package"
    IFS='|' read -r rc why <<<"$(pkg_state)"
    case "$rc" in 0) info "$why" ;; 1) bad "$why" ;; *) caution "$why" ;; esac
    step "Login table"
    read_db_settings
    inf "table ${DB[table]:-?}, user column ${DB[usercolumn]:-?}, password column ${DB[passwdcolumn]:-?} (database ${DB[db]:-?} on ${DB[host]:-localhost})"
    local nempty=-1
    if [[ "$QUERY_DB" == 1 ]]; then
        if [[ -z "$(mysql_client)" ]]; then caution "no mysql or mariadb client: cannot ask"
        elif query_empty; then
            nempty=${#EMPTY_USERS[@]}
            if [[ $nempty -gt 0 ]]; then
                bad "${nempty} row(s) have no stored password: on an affected pam-mysql, anyone can log in as these accounts with any password"
                [[ "$LIST_USERS" == 1 ]] && for u in "${EMPTY_USERS[@]}"; do inf "  ${u}"; done
            else info "no row has a NULL or empty password"; fi
        fi
    else
        inf "to count rows with no password, run with QUERY_DB=1 (as root, to read pam-mysql's credentials), or ask yourself: SELECT ${DB[usercolumn]:-user} FROM ${DB[table]:-users} WHERE ${DB[passwdcolumn]:-password} IS NULL OR ${DB[passwdcolumn]:-password} = '';"
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "pam-mysql is fixed. Leave nullok off."; return 0; fi
    if [[ $nempty -eq 0 ]]; then
        warn "pam-mysql is in use and not fixed, but no row has an empty password now: nobody can use the flaw until one does. Make the column NOT NULL with no empty default so it stays that way, and install the fix when your distribution ships it."
        return 1
    fi
    warn "pam-mysql is in use and not fixed (${CVE}). Install the fixed package (Debian 12 and 13), or until one exists give every row in ${DB[table]:-the login table} a password or lock it, then make ${DB[passwdcolumn]:-the password column} NOT NULL with no empty default. Do NOT set PermitEmptyPasswords yes. Then run hunt."
    return 1
}

cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments"
    limited_view "the auth log"
    local files="${HUNT_LOG_FILES:-/var/log/auth.log* /var/log/secure*}" f n_read=0 line user leads=0 tmp
    tmp="$(mktemp)" || die "Cannot make a temporary file."; PSF_TMP+=("$tmp")
    for f in $files; do [[ -r "$f" ]] || continue; n_read=$((n_read + 1)); zcat -f "$f" 2>/dev/null | grep -a 'sshd.*Accepted password for' >> "$tmp"; done
    if have journalctl && [[ -z "${HUNT_LOG_FILES:-}" ]]; then n_read=$((n_read + 1)); journalctl --no-pager -q -o short-iso _COMM=sshd 2>/dev/null | grep -a 'Accepted password for' >> "$tmp"; fi
    [[ $n_read -gt 0 ]] || { warn "No auth log could be read. Set HUNT_LOG_FILES, or run as root."; return 2; }
    if [[ "$QUERY_DB" == 1 ]]; then read_db_settings; query_empty || true; fi
    step "Password logins over SSH"
    local total; total="$(sort -u "$tmp" | wc -l)"
    inf "${total} password login(s) in the logs read"
    while IFS= read -r line; do
        user="$(sed -nE 's/.*Accepted password for (invalid user )?([^ ]+) from.*/\2/p' <<<"$line")"
        for u in ${EMPTY_USERS[@]+"${EMPTY_USERS[@]}"}; do
            [[ "$u" == "$user" ]] && { leads=$((leads + 1)); bad "${line:0:220}  (${user} has no stored password now: this login was a bypass unless the password was set then)"; }
        done
    done < <(sort -u "$tmp")
    [[ ${#EMPTY_USERS[@]} -gt 0 || "$QUERY_DB" == 1 ]] || inf "run with QUERY_DB=1 to mark logins by accounts that have no stored password; the busiest accounts:"
    if [[ ${#EMPTY_USERS[@]} -eq 0 && "$QUERY_DB" != 1 ]]; then
        sed -nE 's/.*Accepted password for (invalid user )?([^ ]+) from.*/\2/p' "$tmp" | sort | uniq -c | sort -rn | head -n 10 | while read -r c u; do inf "  ${u}: ${c}"; done
    fi
    step "Verdict"
    if [[ $leads -gt 0 ]]; then warn "${leads} login(s) by accounts with no stored password. Treat them as break-ins: lock the accounts, look at what they did, and check a backup or the binary log for what the table held at the time."; return 1; fi
    info "No login by an account with no stored password was found."
    return 0
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}: pam-mysql lets accounts with no stored password in when the service asks it not to"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
