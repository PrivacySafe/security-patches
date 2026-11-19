#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# OpenSSH password authentication bypass on musl Linux without PAM: check, hunt
# and a reversible mitigation  (v1)
# No CVE at time of writing (reported 5 November 2026 by Ozgun Kultekin of
# Wakefield; advisories from Alpine Linux and the OpenSSH project the same day.
# The README spells the name with its proper Turkish diacritics: Ozgun here is
# ASCII only, because this comment becomes the manual page and groff's default
# encoding cannot render them)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# When sshd is built against musl libc without PAM (or built with PAM but run
# with UsePAM no), it checks a password itself: it hashes the attempt with
# crypt() and compares the result to the account's stored field in /etc/shadow.
# For an account whose stored field is too short to contain a salt, sshd
# borrows another account's salt to hash the attempt, a fix for CVE-2016-6210
# (timing-based user enumeration). musl's crypt() returns the literal string
# "*" as an error indicator for a key (password) over 256 bytes; confirmed
# against musl's own source and a real musl build for this release: a 256 byte
# password hashes normally, a 257 byte one returns exactly "*". "*" is also
# the stored field of every account with no password set, so a 257 to 1024
# byte password makes the comparison match and the login succeeds, for any
# account whose shadow field is "*", as long as some other local account has a
# $5$ or $6$ password hash to lend its salt. An account locked with "!" is not
# reachable this way: "!" cannot appear as a crypt() error return, so the
# strings never match.
#
# This needs ALL of: an sshd linked against musl, UsePAM no (Alpine's
# openssh-server package is built this way by default; openssh-server-pam is
# not, but is exposed too if UsePAM no is set), PasswordAuthentication yes
# (OpenSSH's own default), an account whose shadow field is exactly "*" (root
# on Alpine since about 3.16, a key-only user made with adduser and no
# password or usermod -p '*', a directory-service user with no shadow entry,
# or the "alpine" user that Alpine's official cloud images ship), and at least
# one other local account with a $5$ or $6$ hash. On Alpine's own tiny-cloud
# AWS and Azure images the "alpine" user has passwordless doas, so reaching it
# reaches root even though OpenSSH's own PermitRootLogin default blocks root
# directly. A system using PAM with UsePAM yes, or glibc, or any non-Linux
# system, is not affected: the bug is in musl's crypt(), not in OpenSSH.
#
# The fix is OpenSSH 10.6p2 (released 5 November 2026), which stops relying on
# the comparison in sshd itself and is safe even on an unpatched musl. Alpine
# has published fixed openssh packages for every release still receiving
# updates and several that no longer do (3.16 through edge; see the README).
# Until you can update: set PasswordAuthentication no, which closes this
# entirely, on any libc.
#
# "check" and "hunt" are read-only. "mitigate" and "rollback" are the only
# commands that change anything. "check" finds sshd (PATH, the usual
# locations, a running process), reads its ELF interpreter and dynamic
# section to judge musl and PAM linkage without executing it, reads the
# effective configuration with "sshd -T" and scans for a Match block that
# re-enables PasswordAuthentication for specific connections even when the
# global setting is "no" (verified: a Match block does exactly this, and a
# drop-in alone would miss it), and reads /etc/shadow for the two kinds of
# account the attack needs. It never executes sshd with attacker-controlled
# input and never attempts a login.
#
# Usage:
#   ./openssh-musl-check.sh [command]
#
#   check (default)  Read-only. Exit 0 = not affected or no account is
#                    reachable this way, 1 = affected, 2 = it could not be
#                    judged (sshd or /etc/shadow could not be read).
#   hunt             Read-only. Reads the auth log (the journal's sshd
#                    messages, and /var/log/auth.log, /var/log/secure and
#                    /var/log/messages where they exist) for "Accepted
#                    password" lines naming an account whose shadow field is
#                    "*" right now. This can only check the account's CURRENT
#                    field, not what it was at the time of a login in an old
#                    log line. Exit 0 = nothing found, 1 = a lead, 2 = no log
#                    could be read.
#   mitigate [--dry-run] [--restart]   (root) changes the host. Sets
#                    PasswordAuthentication no two ways, matching Alpine's own
#                    advisory: writes a drop-in file in sshd_config's Include
#                    directory when one exists, or the top of sshd_config
#                    itself otherwise; and changes every other
#                    "PasswordAuthentication ... yes" line already in
#                    sshd_config to "no", including one inside a Match block,
#                    because a Match block can re-enable it even under a
#                    global "no" (this script confirmed that against a real
#                    sshd). Every file it touches is copied first, the result
#                    is checked with "sshd -t", and the originals are put back
#                    at once if that check fails. Nothing is restarted unless
#                    you add --restart: a mitigation that is written but not
#                    yet loaded does not protect you.
#   rollback [--dry-run] [--restart]   Puts back every file mitigate changed.
#   version          Prints the script version.
#
# Env overrides, mainly for testing:
#      SSHD_BIN           the sshd binary to read, instead of discovery
#      SSHD_CONFIG         the main sshd_config file (default /etc/ssh/sshd_config)
#      SSHD_CONFIG_D       the Include directory (default /etc/ssh/sshd_config.d)
#      SHADOW_FILE         instead of /etc/shadow
#      SSHD_T_OUTPUT       a file whose content stands in for "sshd -T" (testing only)
#      SSHD_T_MATCH_OUTPUT a file whose content stands in for "sshd -T -C ..." per Match
#                          block (testing only; see the script for the exact form)
#      OS_RELEASE_FILE     instead of /etc/os-release
#      APT_PKG_VERSION, APK_PKG_VERSION  the installed package version, instead of apk/dpkg
#      HUNT_LOG_FILES      the log files hunt reads, instead of the defaults
#      STATE_DIR           where mitigate keeps its backups and manifest
#                          (default /var/lib/psf-security-patches/openssh-musl)
#      PSF_LOCK_WAIT       seconds a run that changes the host waits for another
#                          one that is already changing it (default 30)
# =============================================================================
set -uo pipefail
SELF="$0"
SCRIPT_NAME="openssh-musl-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-05"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/openssh-musl}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SSHD_CONFIG_D="${SSHD_CONFIG_D:-/etc/ssh/sshd_config.d}"
SHADOW_FILE="${SHADOW_FILE:-/etc/shadow}"
OS_RELEASE_FILE="${OS_RELEASE_FILE:-/etc/os-release}"
DROPIN_NAME="00-psf-openssh-musl-no-passwords.conf"
DROPIN_MARK="# Written by openssh-musl-check.sh (PrivacySafe Security Patches) for the musl crypt() password bypass."

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how=", or add --dry-run to see what it would do" msg
    if is_root; then root_note; return 0; fi
    if have sudo; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    have sudo && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- discovery ----------------------------------------------------------------------------
find_sshd() {
    [[ -n "${SSHD_BIN:-}" ]] && { echo "$SSHD_BIN"; return 0; }
    local c
    for c in /usr/sbin/sshd /usr/local/sbin/sshd /sbin/sshd; do [[ -x "$c" ]] && { echo "$c"; return 0; }; done
    have sshd && { command -v sshd; return 0; }
    c="$(pgrep -x sshd 2>/dev/null | head -n1)"
    [[ -n "$c" ]] && [[ -r "/proc/$c/exe" ]] && { readlink -f "/proc/$c/exe"; return 0; }
    return 1
}
# interp_of FILE: the ELF interpreter path, from the program headers, read without executing the file
interp_of() {
    if have readelf; then readelf -l "$1" 2>/dev/null | awk -F'[][]' '/Requesting program interpreter/{print $2}'
    elif have file; then file -b "$1" 2>/dev/null | grep -oE 'interpreter [^,]+' | awk '{print $2}'
    fi
}
is_musl_binary() { [[ "$(interp_of "$1")" == *ld-musl* ]]; }
# needed_libs FILE: the libraries in the ELF dynamic section's NEEDED entries, one per line
needed_libs() {
    if have readelf; then readelf -d "$1" 2>/dev/null | grep -oE '\[[A-Za-z0-9_.+-]+\.so[0-9.]*\]' | tr -d '[]'
    elif have objdump; then objdump -p "$1" 2>/dev/null | awk '/NEEDED/{print $2}'
    fi
}
links_pam() { needed_libs "$1" | grep -qi '^libpam\.so'; }

# effective_sshd_t: the output of "sshd -T" for the global config, or a test stand-in
effective_sshd_t() {
    if [[ -n "${SSHD_T_OUTPUT:-}" ]]; then
        [[ -r "$SSHD_T_OUTPUT" ]] || return 1
        cat "$SSHD_T_OUTPUT"
        return 0
    fi
    local b; b="$(find_sshd)" || return 1
    mkdir -p /run/sshd 2>/dev/null || true
    "$b" -T -f "$SSHD_CONFIG" 2>/dev/null
}
usepam_value() { effective_sshd_t | awk '/^usepam /{print $2; found=1} END{if(!found) print "unknown"}'; }
passwordauth_value() { effective_sshd_t | awk '/^passwordauthentication /{print $2; found=1} END{if(!found) print "unknown"}'; }

# match_blocks_enabling_passwordauth: Match blocks in SSHD_CONFIG (and SSHD_CONFIG_D/*.conf) whose own
# criteria line is printed for any block that sets PasswordAuthentication yes directly inside it; a
# global "no" does not stop these from re-enabling it for the connections they match (verified against
# a real sshd: a Match block's own value wins over the global one for a matching connection).
match_blocks_enabling_passwordauth() {
    local f
    for f in "$SSHD_CONFIG" "$SSHD_CONFIG_D"/*.conf; do
        [[ -r "$f" ]] || continue
        awk '
            BEGIN{incrit=""}
            /^[[:space:]]*#/{next}
            /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/{ incrit=$0; sub(/^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+/,"",incrit); next }
            incrit != "" && /^[[:space:]]*[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][Aa][Uu][Tt][Hh][Ee][Nn][Tt][Ii][Cc][Aa][Tt][Ii][Oo][Nn][[:space:]]+[Yy][Ee][Ss][[:space:]]*$/{ print incrit }
            incrit != "" && /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]/{ incrit=$0; sub(/^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+/,"",incrit) }
        ' "$f"
    done
}

# shadow_class: prints "locked" (field is !), "nopass" (field is exactly *), "hashed" (a $N$ hash) or
# "other" for each readable /etc/shadow line, tab-separated with the username
shadow_classify() {
    [[ -r "$SHADOW_FILE" ]] || return 1
    awk -F: '
        $2 == "!" || $2 ~ /^!/ { print $1 "\tlocked"; next }
        $2 == "*" { print $1 "\tnopass"; next }
        $2 ~ /^\$[0-9]+\$/ { print $1 "\thashed"; next }
        { print $1 "\tother" }
    ' "$SHADOW_FILE"
}

sshd_version() {
    local b v; b="$(find_sshd)" || return 1
    v="$("$b" -V 2>&1 | head -n1)"
    echo "$v" | grep -oE 'OpenSSH_[0-9]+\.[0-9]+(p[0-9]+)?' | head -n1
}
# fixed_alpine_version BRANCH: the Alpine package version that first carries the fix, or empty
fixed_alpine_version() {
    case "$1" in
        edge) echo "10.6_p2-r0" ;; 3.24) echo "10.3_p1-r2" ;; 3.23) echo "10.2_p1-r1" ;;
        3.22) echo "10.0_p1-r11" ;; 3.21) echo "9.9_p2-r1" ;; 3.20) echo "9.7_p1-r6" ;;
        3.19) echo "9.6_p1-r3" ;; 3.18) echo "9.3_p2-r4" ;; 3.17) echo "9.1_p1-r7" ;;
        3.16) echo "9.0_p1-r6" ;; *) echo "" ;;
    esac
}
is_alpine() { [[ -r "$OS_RELEASE_FILE" ]] && grep -qiE '^ID=alpine$' "$OS_RELEASE_FILE"; }
alpine_branch() { [[ -r "$OS_RELEASE_FILE" ]] && grep -oE '^VERSION_ID=[0-9]+\.[0-9]+' "$OS_RELEASE_FILE" | cut -d= -f2; }
apk_pkg_version() {   # PKG -> installed version, or empty
    [[ -n "${APK_PKG_VERSION:-}" ]] && { echo "$APK_PKG_VERSION"; return 0; }
    have apk || return 1
    apk info -e "$1" >/dev/null 2>&1 || return 1
    apk info -v "$1" 2>/dev/null | sed -n "s/^${1}-//p" | head -n1
}
apk_ver_lt() { have apk || return 1; [[ "$(apk version -t "$1" "$2" 2>/dev/null)" == "<" ]]; }

cmd_check() {
    local sb rc=0 pam_note="" musl=0 pam=0 usepam pwa
    step "OpenSSH musl password bypass: check"
    if ! sb="$(find_sshd)"; then
        inf "sshd was not found on this host, so the two conditions that need it cannot be judged."
        return 2
    fi
    inf "sshd binary: ${sb}"
    if is_musl_binary "$sb"; then ok "sshd is linked against musl libc"; musl=1
    elif [[ -n "$(interp_of "$sb")" ]]; then ok "sshd is not linked against musl ($(interp_of "$sb")): this flaw does not apply here"
    else caution "could not read sshd's ELF interpreter (readelf or file is needed): musl could not be confirmed either way"; fi
    if links_pam "$sb"; then pam=1; fi
    usepam="$(usepam_value)"; pwa="$(passwordauth_value)"
    if [[ "$usepam" == unknown || "$pwa" == unknown ]]; then
        caution "could not read sshd's effective configuration (sshd -T): judging from the files instead is less certain"
    fi
    if [[ $pam -eq 1 && "$usepam" != "no" ]]; then
        ok "sshd links libpam, and UsePAM is not set to no (${usepam}): PAM, not musl's crypt(), checks the password here"
    else
        [[ $pam -eq 1 ]] && pam_note=" (sshd links libpam, but UsePAM is ${usepam})"
        inf "sshd checks passwords itself (no PAM in effect)${pam_note}"
    fi
    inf "PasswordAuthentication (effective): ${pwa}"
    local mb; mb="$(match_blocks_enabling_passwordauth)"
    if [[ -n "$mb" ]]; then
        bad "a Match block re-enables PasswordAuthentication yes for: $(tr '\n' ';' <<<"$mb" | sed 's/;$//; s/;/; /g'). A global PasswordAuthentication no does not stop this for a matching connection."
    fi
    local nopass_users hashed_users locked_users n_nopass n_hashed
    local shadow_tmp
    shadow_tmp="$(mktemp "${TMPDIR:-/tmp}/psf-om-shadow.XXXXXX" 2>/dev/null)" && PSF_TMP+=("$shadow_tmp")
    if [[ -n "$shadow_tmp" ]] && shadow_classify >"$shadow_tmp" 2>/dev/null; then
        nopass_users="$(awk -F'\t' '$2=="nopass"{print $1}' "$shadow_tmp")"
        hashed_users="$(awk -F'\t' '$2=="hashed"{print $1}' "$shadow_tmp")"
        locked_users="$(awk -F'\t' '$2=="locked"{print $1}' "$shadow_tmp")"
        n_nopass=$(wc -l <<<"${nopass_users:-}"); [[ -z "$nopass_users" ]] && n_nopass=0
        n_hashed=$(wc -l <<<"${hashed_users:-}"); [[ -z "$hashed_users" ]] && n_hashed=0
        rm -f "$shadow_tmp"
        if [[ $n_nopass -gt 0 ]]; then
            bad "${n_nopass} account(s) with no password set (field is exactly \"*\", reachable this way): $(tr '\n' ',' <<<"$nopass_users" | sed 's/,$//; s/,/, /g')"
        else
            ok "no account has a bare \"*\" password field. Locked accounts (\"!\") are not reachable this way$([[ -n "$locked_users" ]] && echo ": $(tr '\n' ',' <<<"$locked_users" | sed 's/,$//; s/,/, /g')")"
        fi
        if [[ $n_hashed -gt 0 ]]; then
            inf "${n_hashed} other account(s) have a usable salt to borrow (\$5\$ or \$6\$ hash)"
        else
            ok "no account on this host has a \$5\$ or \$6\$ password hash for sshd to borrow a salt from"
        fi
    else
        caution "${SHADOW_FILE} could not be read (root is needed): the two account conditions could not be checked"
        rc=2
    fi
    step "Version"
    local ver branch fixed
    ver="$(sshd_version 2>/dev/null)"
    if [[ -z "$ver" ]]; then caution "could not read the OpenSSH version"
    else
        inf "OpenSSH version: ${ver}"
        if is_alpine; then
            branch="$(alpine_branch)"
            fixed="$(fixed_alpine_version "${branch:-}")"
            local pkgver=""
            for pkg in openssh openssh-server openssh-server-pam; do
                pkgver="$(apk_pkg_version "$pkg" 2>/dev/null)" && [[ -n "$pkgver" ]] && break
            done
            if [[ -n "$fixed" && -n "$pkgver" ]]; then
                if apk_ver_lt "$pkgver" "$fixed"; then bad "openssh ${pkgver} on Alpine ${branch} is below the fixed ${fixed}"
                else ok "openssh ${pkgver} on Alpine ${branch} is at or past the fixed ${fixed}"; fi
            elif [[ -n "$fixed" ]]; then inf "Alpine ${branch:-unknown}'s fixed package version is ${fixed:-unknown}; the installed package version could not be read (apk)"
            else inf "Alpine branch could not be read; compare your installed openssh against the table in the README"
            fi
        else
            if [[ "$ver" =~ OpenSSH_([0-9]+)\.([0-9]+)(p([0-9]+))? ]]; then
                local maj="${BASH_REMATCH[1]}" min="${BASH_REMATCH[2]}" pat="${BASH_REMATCH[4]:-0}"
                if (( maj > 10 || (maj == 10 && min > 6) || (maj == 10 && min == 6 && pat >= 2) )); then ok "OpenSSH ${ver} is 10.6p2 or later (portable's own fix)"
                else bad "OpenSSH ${ver} is below 10.6p2 (portable's fix). A distribution may have backported it under this version number: check your vendor's advisory, and your package manager's changelog, before trusting the version number alone."; fi
            else caution "could not parse the OpenSSH version number from '${ver}'"
            fi
        fi
    fi
    step "Verdict"
    if [[ $musl -eq 1 && ( $pam -eq 0 || "$usepam" == "no" ) && "$pwa" == "yes" && ${n_nopass:-0} -gt 0 && ${n_hashed:-0} -gt 0 ]]; then
        bad "This host is affected: musl sshd, no PAM in effect, password authentication on, an account with no password set, and another account to borrow a salt from. Update OpenSSH, or run mitigate as a stopgap."
        return 1
    fi
    if [[ -n "$mb" ]]; then
        bad "A Match block can still re-enable password authentication for some connections even though the global check above is not fully exposed. Review it."
        return 1
    fi
    [[ $rc -eq 2 ]] && { inf "Not enough could be read to give a verdict."; return 2; }
    ok "Not exposed, by what this check can see."
    return 0
}

cmd_hunt() {
    step "OpenSSH musl password bypass: hunt"
    local nopass_users
    if ! nopass_users="$(shadow_classify 2>/dev/null | awk -F'\t' '$2=="nopass"{print $1}')"; then
        inf "${SHADOW_FILE} could not be read, so a successful login cannot be matched to a no-password account."
        return 2
    fi
    if [[ -z "$nopass_users" ]]; then
        ok "No account on this host has a bare \"*\" password field right now, so there is nothing this hunt can match. This does not rule out a login before the field was last changed."
        return 0
    fi
    inf "accounts with no password set right now: $(tr '\n' ',' <<<"$nopass_users" | sed 's/,$//; s/,/, /g')"
    local files=() f nlead=0 read_any=0
    if [[ -n "${HUNT_LOG_FILES:-}" ]]; then IFS=' ' read -r -a files <<<"$HUNT_LOG_FILES"
    else
        for f in /var/log/auth.log /var/log/secure /var/log/messages; do [[ -r "$f" ]] && files+=("$f"); done
    fi
    local pat
    pat="$(tr '\n' '|' <<<"$nopass_users" | sed 's/|$//')"
    for f in "${files[@]+"${files[@]}"}"; do
        [[ -r "$f" ]] || continue
        read_any=1
        while IFS= read -r line; do
            bad "${f}: ${line}"
            nlead=$((nlead + 1))
        done < <(grep -E "sshd.*Accepted password for (${pat}) " "$f" 2>/dev/null)
    done
    if have journalctl; then
        read_any=1
        while IFS= read -r line; do
            bad "journal: ${line}"
            nlead=$((nlead + 1))
        done < <(journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep -E "Accepted password for (${pat}) ")
    fi
    if [[ $read_any -eq 0 ]]; then
        inf "no log file could be read, and journalctl found nothing readable either."
        return 2
    fi
    if [[ $nlead -gt 0 ]]; then
        bad "${nlead} lead(s) found. Each line is a password login accepted for an account with no password set. Treat the host as compromised: check doas/sudo use, new administrator accounts, authorized_keys and crontabs, then update OpenSSH and rotate anything the account could reach."
        return 1
    fi
    ok "Nothing found. This is not clearance: it only means the logs this hunt could read show no accepted password for a currently no-password account."
    return 0
}

# ---------- mitigate and rollback -----------------------------------------------------------
manifest_add() { mkdir -p "$STATE_DIR" && printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$STATE_DIR/manifest"; }
# backup_once FILE: keeps the first original of FILE and records it in the manifest exactly once, even
# across several calls in the same run (mitigate backs up sshd_config before each of its two edits).
backup_once() {
    local f="$1" b
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    [[ -f "$b" ]] && return 0
    mkdir -p "$STATE_DIR" || return 1
    cp -p "$f" "$b" 2>/dev/null || return 1
    manifest_add conf "$f"
}
sshd_config_has_include() { [[ -r "$SSHD_CONFIG" ]] && grep -qiE '^[[:space:]]*Include[[:space:]].*sshd_config\.d' "$SSHD_CONFIG"; }
test_sshd_config() { local b; b="$(find_sshd)" || return 1; mkdir -p /run/sshd 2>/dev/null || true; "$b" -t -f "$SSHD_CONFIG" >/dev/null 2>&1; }
maybe_restart() {
    [[ "${RESTART:-0}" -eq 1 ]] || { inf "Not restarted: add --restart, or restart sshd yourself, for this to take effect."; return 0; }
    if have rc-service; then rc-service sshd restart && ok "sshd restarted (OpenRC)"
    elif have systemctl; then systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; ok "sshd restarted (systemd)"
    else caution "no known service manager found: restart sshd by hand"; fi
}

cmd_mitigate() {
    local dry=0
    RESTART=0
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (mitigate [--dry-run] [--restart])" ;; esac; done
    [[ $dry -eq 1 ]] || need_root "mitigate changes ${SSHD_CONFIG} and ${SSHD_CONFIG_D}"
    step "Setting PasswordAuthentication no"
    if [[ ! -r "$SSHD_CONFIG" ]]; then die "${SSHD_CONFIG} does not exist or is not readable."; fi
    local content="${DROPIN_MARK}\nPasswordAuthentication no\n" path="${SSHD_CONFIG_D}/${DROPIN_NAME}"
    if sshd_config_has_include; then
        if [[ $dry -eq 1 ]]; then echo "  would write ${path}"
        elif [[ -f "$path" ]] && grep -qF "$DROPIN_MARK" "$path" && [[ "$(cat "$path")" == "$(printf '%b' "$content" | sed '$ { /^$/d }')" ]]; then
            ok "${path} is already in place"
        else
            mkdir -p "$SSHD_CONFIG_D" || die "could not create ${SSHD_CONFIG_D}"
            printf '%b' "$content" > "$path" || die "could not write ${path}"
            manifest_add dropin "$path"
            ok "wrote ${path}"
        fi
    else
        caution "${SSHD_CONFIG} has no Include line for ${SSHD_CONFIG_D}: a drop-in there would not be read. Patching ${SSHD_CONFIG} directly instead."
        backup_once "$SSHD_CONFIG"
        if [[ $dry -eq 0 ]]; then
            if ! grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+no[[:space:]]*$' "$SSHD_CONFIG"; then
                { printf 'PasswordAuthentication no\n'; cat "$SSHD_CONFIG"; } > "${SSHD_CONFIG}.psf-new" && mv "${SSHD_CONFIG}.psf-new" "$SSHD_CONFIG"
                ok "added PasswordAuthentication no at the top of ${SSHD_CONFIG}"
            fi
        else echo "  would add PasswordAuthentication no at the top of ${SSHD_CONFIG}"
        fi
    fi
    # every explicit "PasswordAuthentication ... yes" in the main config, including inside a Match
    # block, is changed to "no": a Match block can re-enable it even under a global "no" (see the
    # header), so the drop-in alone is not enough. "#" starts a comment; the pattern mirrors Alpine's
    # own published sed line for this advisory.
    local hits; hits="$(grep -ciE '^[[:space:]]*PasswordAuthentication[^y#]*yes[[:space:]]*$' "$SSHD_CONFIG" 2>/dev/null)"; [[ -n "$hits" ]] || hits=0
    if [[ "$hits" -gt 0 ]]; then
        if [[ $dry -eq 1 ]]; then echo "  would change ${hits} explicit 'PasswordAuthentication ... yes' line(s) in ${SSHD_CONFIG} to 'no'"
        else
            backup_once "$SSHD_CONFIG"
            sed -i -E 's/^([[:space:]]*PasswordAuthentication[^y#]*)yes([[:space:]]*)$/\1no\2/I' "$SSHD_CONFIG" \
                || die "could not edit ${SSHD_CONFIG}"
            ok "changed ${hits} explicit line(s) in ${SSHD_CONFIG} (including any inside a Match block) to 'no'"
        fi
    fi
    if [[ $dry -eq 1 ]]; then inf "Dry run: nothing was changed."; return 0; fi
    if ! test_sshd_config; then
        bad "the result does not pass 'sshd -t': putting the original files back"
        cmd_rollback --no-restart-note 2>/dev/null
        return 1
    fi
    ok "sshd -t accepts the new configuration"
    maybe_restart
    return 0
}

cmd_rollback() {
    local dry=0
    RESTART=0
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; --no-restart-note) ;; *) die "Unknown option: $a (rollback [--dry-run] [--restart])" ;; esac; done
    local manifest="${STATE_DIR}/manifest"
    [[ -s "$manifest" ]] || { inf "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    local kind path b rc=0
    while IFS=$'\t' read -r _ kind path; do
        case "$kind" in
            dropin)
                if [[ $dry -eq 1 ]]; then echo "  would remove ${path}"
                elif [[ -f "$path" ]]; then rm -f "$path" && ok "removed ${path}"
                else inf "${path} is already gone"; fi
                ;;
            conf)
                b="${STATE_DIR}/$(printf '%s' "$path" | sed 's#/#_#g').orig"
                if [[ ! -r "$b" ]]; then bad "${path}: backup ${b} is missing, left alone"; rc=1
                elif [[ $dry -eq 1 ]]; then echo "  would restore ${path} from ${b}"
                else cp -p "$b" "$path" && ok "restored ${path}"; fi
                ;;
        esac
    done < "$manifest"
    if [[ $dry -eq 0 && $rc -eq 0 ]]; then
        mv "$manifest" "${manifest}.rolled-back-$(date +%s)" 2>/dev/null || true
        inf "Rolled back."
    fi
    maybe_restart
    return "$rc"
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
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "OpenSSH password authentication bypass on musl Linux without PAM (no CVE at time of writing)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5
