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
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
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
