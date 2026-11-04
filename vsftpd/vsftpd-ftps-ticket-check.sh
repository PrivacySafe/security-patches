#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# vsftpd FTPS data channel hijack (require_ssl_reuse bypass): checker  (v1)
# CVE-2026-119568
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# vsftpd through 3.0.5, built with SSL support and run with ssl_enable=YES,
# decides that an FTPS data connection belongs to the logged-in user by asking
# OpenSSL one question: was a session ticket resumed (SSL_session_reused)? It
# does not compare the data session with the control session. A client that
# shares the victim's source IP address can run AUTH TLS on its own control
# connection (no USER or PASS needed), keep the ticket it receives, connect to
# the victim's passive (PASV) port first and resume that ticket. The server then
# serves or accepts the victim's transfer on the attacker's TLS session.
# Impact: the file the victim downloads can be read, or an upload can be
# supplied, by someone who is not the user. It is not a login bypass and not
# code execution.
#
# SOURCES AND WHAT IS NOT SETTLED.
#   - CVE-2026-119568 was published on 30 October 2026. The VulnCheck advisory
#     scores it 9.1 Critical (CVSS v4, attack complexity high). The researcher
#     (Abraxas Labs, 12 October 2026) scored it 7.4 High (CVSS v3.1) and reproduced
#     it on the official 3.0.5 tarball in a lab. The CVE text names
#     ssl_data_accept(); the researcher's write-up names ssl_accept() in ssl.c.
#     They describe the same missing check.
#   - The affected
#     range given is "through 3.0.5". A version above 3.0.5 is reported as
#     outside that range, with a reminder to confirm against the vendor page.
#   - The researcher's conditions for exposure are: SSL compiled in (the stock
#     tarball has it off, most distribution packages turn it on), ssl_enable=YES,
#     a standalone listener (listen=YES, or listen_ipv6=YES), and the default
#     require_ssl_reuse=YES. The attacker must share the victim's source IP
#     (shared NAT, the same host) because passive connections must come from the
#     control connection's address unless pasv_promiscuous=YES.
#   - The researcher reports that require_cert=YES, with clients that present a
#     certificate, binds the data connection to the control connection and
#     closes this path, and that a per-connection (inetd or xinetd) server does
#     not share ticket keys between connections. Those two points come from the
#     write-up's reading of the code.
#   - require_ssl_reuse=NO removes the ticket requirement altogether. It is a
#     documented setting and not the vulnerable default, but a data connection
#     is then not tied to the control connection at all. It is reported as
#     exposed for that reason (our reading, not the advisory's).
#
# "check" is read-only; "mitigate" and "rollback" are the only commands that change
# anything. "check" finds vsftpd binaries (PATH, usual locations and
# running processes), reads the version from "vsftpd -v" (falling back to the
# package manager), checks whether the binary links OpenSSL, reads each
# configuration file and reports exposure for each one. It sends no network
# traffic and never starts, reloads or restarts anything.
#
# Usage:
#   ./vsftpd-ftps-ticket-check.sh [command] [PATH-TO-vsftpd ...]
#
#   check (default)  read-only. Exit 0 = nothing exposed, 1 = an exposed vsftpd (or
#                    one that cannot be judged) was found, 2 = bad usage.
#   mitigate [options]   (root) changes the host. Protective measures only: there is
#                    no vendor fix. Every file it edits is copied first and
#                    "rollback" puts it back. Nothing is restarted unless you add
#                    --restart (vsftpd reads its configuration at start, and a
#                    restart ends transfers in progress). Options:
#                      (no option)      sets pasv_promiscuous=NO in each FTPS
#                                       configuration that has it on. That setting
#                                       removes the same-IP precondition of the
#                                       attack, and turning it off is safe unless
#                                       you rely on FXP transfers.
#                      --require-cert   also sets require_cert=YES and
#                                       ssl_request_cert=YES: every client must
#                                       present a certificate, and the data
#                                       connection is matched against it. The
#                                       researcher reports this closes the path
#                                       It REFUSES clients that
#                                       have no certificate, which is most FTPS
#                                       clients, so use it only if yours have one.
#                      --allow LIST     firewall (nftables, else iptables): only the
#                                       comma separated addresses or CIDRs in LIST,
#                                       plus loopback, may reach the FTP control
#                                       port (listen_port, default 21) and the
#                                       passive range if pasv_min_port and
#                                       pasv_max_port are set. Does not survive a
#                                       reboot. It cannot stop an attacker who
#                                       shares an allowed address.
#                      --dry-run        print what would change and change nothing
#                      --restart        restart vsftpd afterwards (systemd)
#   harden [options]   (root) OPTIONAL baseline hardening, separate from the two CVEs.
#                    Nothing is hardened unless you choose
#                    it, because every item can break something. Each directive is
#                    set only if the installed vsftpd build knows it (an unknown
#                    directive stops vsftpd from starting), limits are never
#                    loosened, and every file is copied first (rollback restores it).
#                    Options (the first six come from the common vsftpd hardening
#                    guides):
#                      --baseline       --logging, --limits and --tls together
#                      --logging        xferlog_enable=YES
#                      --limits         standalone only: max_clients=50 and
#                                       max_per_ip=5 (a generic suggestion from a
#                                       third-party summary of CVE-2025-14242, not
#                                       Red Hat's: it caps how many sessions one
#                                       address can hold, it does not remove the bug,
#                                       and max_per_ip can lock out many users behind
#                                       one NAT address); everywhere:
#                                       idle_session_timeout=300 and
#                                       data_connection_timeout=120
#                      --tls            where ssl_enable=YES: ssl_ciphers=HIGH, SSLv2,
#                                       SSLv3, TLSv1 and TLSv1.1 off, TLSv1.2 on
#                      --force-tls      where ssl_enable=YES: force_local_logins_ssl
#                                       and force_local_data_ssl (vsftpd's default is
#                                       already YES for both, so this makes it
#                                       explicit), and, where allow_anon_ssl=YES,
#                                       force_anon_logins_ssl and force_anon_data_ssl,
#                                       so plain FTP is refused for anonymous users
#                                       too (breaks clients without FTPS)
#                      --no-anon        anonymous_enable=NO (vsftpd's default is YES)
#                      --chroot         where local_enable=YES: chroot_local_user=YES.
#                                       vsftpd then refuses logins for users whose
#                                       home directory is writable; this script does
#                                       not set allow_writeable_chroot
#                      --pasv-range A-B pasv_min_port and pasv_max_port. Your firewall
#                                       must allow the range (mitigate --allow does)
#                      --dry-run        print what would change and change nothing
#                      --restart        restart vsftpd afterwards (systemd)
#   rollback [--dry-run] [--restart]   put back every file mitigate or harden changed
#                    and remove the firewall rules.
#   version          print the script version.
#
# Env overrides:
#   VSFTPD_CONF="/etc/vsftpd.conf /etc/vsftpd/other.conf"   configuration files
#                    (space separated) instead of discovery
#   STATE_DIR=/var/lib/psf-security-patches/vsftpd           where mitigate keeps its
#                    backups and manifest
# Two CVEs are covered. CVE-2026-119568 (FTPS data channel hijack, through 3.0.5, no
# fixed upstream release; CISA SSVC on 30 October 2026: exploitation none, automatable
# no, technical impact total; not in the KEV catalog). CVE-2025-14242 (authenticated
# denial of service, integer overflow in ls parameter parsing reached through STAT,
# CVSS 6.5): Red Hat lists its own vsftpd packages as affected and fixed them in
# RHSA-2026:0605, 0606 and 0608 and later errata (for example 3.0.3-36.el8_10.3 on
# RHEL 8, 3.0.5-6.el9_7.2 on RHEL 9, 3.0.5-10.el10_1.1 on RHEL 10). A Red Hat Bugzilla
# comment asks whether it comes from a Red Hat-only patch; that is not confirmed, so
# the check reports it only for Red Hat family packages whose changelog does not name
# the CVE, and says plainly that other builds are not listed.
# Containers are not scanned. Run the script inside a container, or pass the
# binary and set VSFTPD_CONF to a copy of its configuration.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="vsftpd-ftps-ticket-check.sh"
SCRIPT_VERSION="1.1.1"
SCRIPT_DATE="2026-11-02"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/vsftpd}"
CVE="CVE-2026-119568"
CVE2="CVE-2025-14242"
DOS_EXPOSED=0

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}

norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

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

print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- discovery --------------------------------------------------------
bin_version() {   # binary -> "3.0.5"; "vsftpd -v" prints "vsftpd: version 3.0.5"
    local v=""
    if have timeout; then v="$(timeout 10 "$1" -v 2>&1 | head -n1)"; else v="$("$1" -v 2>&1 | head -n1)"; fi
    v="$(sed -n 's/.*[Vv]ersion \([0-9][0-9A-Za-z.+~-]*\).*/\1/p' <<<"$v" | head -n1)"
    if [[ -z "$v" ]]; then
        local real pkg=""
        real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
        if have dpkg; then
            pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
            [[ -n "$pkg" ]] && v="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null | sed -E 's/^[0-9]+://')"
        fi
        if [[ -z "$v" ]] && have rpm; then
            v="$(rpm -qf --qf '%{VERSION}' "$real" 2>/dev/null)"
            [[ "$v" == *"not owned"* ]] && v=""
        fi
    fi
    [[ "$v" =~ ^[0-9]+(\.[0-9]+)+ ]] || v=""   # a tool that prints junk must not become the version
    echo "$v"
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v vsftpd 2>/dev/null)" /usr/sbin/vsftpd /usr/local/sbin/vsftpd /usr/bin/vsftpd /usr/local/bin/vsftpd; do
        [[ -n "$b" && -x "$b" ]] && out+=("$(readlink -f "$b")")
    done
    shopt -s nullglob
    for b in /opt/vsftpd*/sbin/vsftpd /opt/vsftpd*/bin/vsftpd /opt/*/sbin/vsftpd; do
        [[ -x "$b" ]] && out+=("$(readlink -f "$b")")
    done
    shopt -u nullglob
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2=="vsftpd"{print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

config_files() {   # -> readable configuration files
    local -a paths=()
    local f p
    if have ps; then
        while read -r p; do paths+=("$p"); done < <(ps -eo args= 2>/dev/null \
            | awk '$1 ~ /(^|\/)vsftpd$/ {for (i=2;i<=NF;i++) if ($i ~ /^\//) {print $i; break}}')
    fi
    [[ -z "${VSFTPD_CONF:-}" ]] || read -r -a paths <<<"$VSFTPD_CONF"
    if [[ ${#paths[@]} -eq 0 ]]; then
        paths=(/etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /usr/local/etc/vsftpd.conf)
        shopt -s nullglob; for f in /etc/vsftpd/*.conf; do paths+=("$f"); done; shopt -u nullglob
    fi
    for p in "${paths[@]}"; do [[ -r "$p" && -f "$p" ]] && echo "$p"; done | awk '!s[$0]++'
}

# conf_get FILE KEY DEFAULT -> last value of KEY (vsftpd lets a later line win), upper-cased
conf_get() {
    local v
    v="$(tr -d '\r' <"$1" 2>/dev/null | awk -F= -v k="$2" '
        /^[[:space:]]*#/ {next}
        { key=$1; gsub(/^[[:space:]]+|[[:space:]]+$/,"",key)
          if (key==k) { val=substr($0, index($0,"=")+1); gsub(/^[[:space:]]+|[[:space:]]+$/,"",val); last=val; seen=1 } }
        END { if (seen) print last }')"
    [[ -n "$v" ]] || v="$3"
    echo "$v" | tr '[:lower:]' '[:upper:]'
}
is_yes() { [[ "$1" == "YES" || "$1" == "TRUE" || "$1" == "1" ]]; }

# ---------- CVE-2025-14242 and build knowledge -------------------------------
# does the installed build know this directive? vsftpd stops at start on an unknown one,
# and the directive names are plain strings inside the binary.
knows_directive() {   # BINARY KEY
    [[ -n "${1:-}" && -r "$1" ]] || return 0
    grep -aqE "(^|[^a-z0-9_])${2}([^a-z0-9_]|\$)" "$1" 2>/dev/null
}

# CVE-2025-14242: reported against Red Hat's packages. Decided by the package, not the version number.
dos_check() {   # BINARY
    local b="$1" vendor owned=0
    distro_mentions "$b" "$CVE2"
    case $? in
        0) ok "package ${DISTRO_PKG} changelog mentions ${CVE2}: the authenticated denial of service is fixed in this build"; return 0 ;;
        1) owned=1 ;;
    esac
    if [[ $owned -eq 1 ]] && have rpm && rpm -q "$DISTRO_PKG" >/dev/null 2>&1; then
        vendor="$(rpm -q --qf '%{VENDOR}' "$DISTRO_PKG" 2>/dev/null)"
        case "${vendor,,}" in
            *"red hat"*|*almalinux*|*rocky*|*centos*|*oracle*)
                if [[ "$DISTRO_PKG" == *.el7* ]]; then
                    inf "${CVE2}: Red Hat does not list RHEL 7 builds (end of life): not reported for ${DISTRO_PKG}"
                    return 0
                fi
                bad "package ${DISTRO_PKG} (${vendor}) is a Red Hat family build whose changelog does not name ${CVE2}: it has the authenticated denial of service (CVSS 6.5)"
                DOS_EXPOSED=1; return 1 ;;
        esac
    fi
    inf "${CVE2} (authenticated denial of service): Red Hat lists its own vsftpd packages as affected; this build is not a Red Hat family package, so it is not reported. Whether the upstream code is affected is unconfirmed."
    return 0
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local -a bins=()
    local rc=0 found=0 b raw n affected ssl_linked f sslen listen listen6 reuse cert pasvp standalone nconf nrun
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for vsftpd"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No vsftpd found on this host"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        found=$((found+1))
        raw="$(bin_version "$b")"
        step "vsftpd at ${b}"
        inf "version ${raw:-unknown}"
        dos_check "$b"
        affected=1
        if [[ -z "$raw" ]]; then
            caution "could not read a version: treating it as affected so that you review it"
        elif ! is_semver "$raw"; then
            caution "cannot parse version '${raw}': treating it as affected"
        else
            n="$(norm_ver "$raw")"
            if ver_lt "$n" "3.0.6"; then
                bad "vsftpd ${raw} is in the affected range of ${CVE} (through 3.0.5)"
            else
                ok "vsftpd ${raw} is newer than 3.0.5, outside the range of ${CVE} as published on 30 October 2026"
                inf "install the upstream release that fixes it when it is published: https://security.appspot.com/vsftpd.html"
                affected=0
            fi
        fi
        if [[ $affected -eq 0 ]]; then continue; fi
        if distro_mentions "$b" "$CVE"; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported a fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention the CVE yet"
        fi
        if grep -aqE 'libssl\.so|libssl3|libcrypto\.so' "$b" 2>/dev/null; then ssl_linked=1; else ssl_linked=0; fi
        if [[ $ssl_linked -eq 0 ]]; then
            ok "this build does not link OpenSSL (the stock tarball has SSL compiled out): FTPS is not available, not exposed"
            continue
        fi
        inf "this build links OpenSSL, so FTPS can be enabled in configuration"
        nrun="$(ps -eo comm= 2>/dev/null | grep -cx vsftpd || true)"
        [[ "${nrun:-0}" -gt 0 ]] && inf "${nrun} vsftpd process(es) running now"
        nconf=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            nconf=$((nconf+1))
            inf "reading ${f}"
            sslen="$(conf_get "$f" ssl_enable NO)"
            listen="$(conf_get "$f" listen NO)"
            listen6="$(conf_get "$f" listen_ipv6 NO)"
            reuse="$(conf_get "$f" require_ssl_reuse YES)"
            cert="$(conf_get "$f" require_cert NO)"
            pasvp="$(conf_get "$f" pasv_promiscuous NO)"
            if ! is_yes "$sslen"; then ok "${f}: ssl_enable is not YES, FTPS is off: not exposed"; continue; fi
            standalone=0; is_yes "$listen" && standalone=1; is_yes "$listen6" && standalone=1
            if [[ $standalone -eq 0 ]]; then
                ok "${f}: neither listen nor listen_ipv6 is YES: vsftpd runs once per connection (inetd style). The researcher's reading is that ticket keys are not shared then: not exposed"
                inf "if a supervisor such as systemd keeps a standalone vsftpd running with these settings, set listen=YES to see it reported"
                continue
            fi
            if is_yes "$cert"; then
                ok "${f}: require_cert=YES: clients must present a certificate and the data connection is matched against it. Mitigated by configuration (it needs a certificate on every client)"
                continue
            fi
            bad "${f}: FTPS on a standalone listener with no certificate binding: exposed to ${CVE} for users who share a source IP address with an attacker"
            if is_yes "$pasvp"; then
                bad "${f}: pasv_promiscuous=YES: passive connections are not tied to the control connection's address, so the attacker does not need to share the victim's IP address"
            fi
            if ! is_yes "$reuse"; then
                inf "require_ssl_reuse is NO: the data connection needs no ticket at all, which is the same exposure by an easier route"
            fi
            rc=1
        done < <(config_files)
        if [[ $nconf -eq 0 ]]; then
            caution "no readable vsftpd configuration found (looked at /etc/vsftpd.conf, /etc/vsftpd/*.conf, running process arguments): exposure cannot be decided, treating as exposed. Set VSFTPD_CONF to the file."
            rc=1
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No usable vsftpd binary found"
    elif [[ $rc -eq 0 && $DOS_EXPOSED -eq 0 ]]; then
        info "No exposed vsftpd found (${found} checked)"
    fi
    if [[ $found -gt 0 && $rc -ne 0 ]]; then
        warn "Exposed or unverifiable vsftpd found. No upstream fix is named for ${CVE} yet."
        inf "Apply the protective measures with:  $0 mitigate --dry-run   (then without --dry-run; add --require-cert if your clients present certificates, or --allow CIDR,CIDR to limit who can reach the port)."
        inf "Also from the researcher: run vsftpd per connection from xinetd or a systemd socket."
        inf "PrivacySafe recommendation: limit who can reach the FTPS port (a shared NAT address is what makes the attack possible), or move transfers to SFTP."
        inf "Advisory: https://www.vulncheck.com/advisories/vsftpd-through-3.0.5-require-ssl-reuse-bypass-via-ftps-data-channel-hijacking"
        inf "Write-up:  https://abraxaslabs.tech/research/vsftpd-ssl-data-any-ticket"
    fi
    if [[ $DOS_EXPOSED -eq 1 ]]; then
        warn "A Red Hat family vsftpd without the ${CVE2} fix was found. Update vsftpd from your distribution (RHSA-2026:0605, 0606 and 0608 and later errata for RHEL 8, 9 and 10)."
        inf "Until then (ours, not Red Hat's): limit who can reach the FTP port ($0 mitigate --allow CIDR,CIDR) and remove accounts that do not need FTP, because the attacker needs a valid login. $0 harden --limits caps sessions per address but does not remove the bug."
        inf "Look for it: repeated vsftpd crashes or restarts in the system log, and very long STAT arguments in the FTP log."
    fi
    [[ $found -eq 0 ]] || inf "Optional baseline hardening (separate from both CVEs): $0 harden --dry-run --baseline"
    [[ $DOS_EXPOSED -eq 0 ]] || rc=1
    return "$rc"
}


# ---------- mitigate and rollback --------------------------------------------
MANIFEST=""
run_or_say() {   # honors DRY
    if [[ "${DRY:-0}" -eq 1 ]]; then echo "  would run: $*"; return 0; fi
    "$@"
}

# conf_set FILE KEY VALUE: drop every uncommented KEY= line, append KEY=VALUE
conf_set() {
    local f="$1" k="$2" v="$3" tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/vsftpd-psf.XXXXXX")" || return 1
    PSF_TMP+=("$tmp")
    awk -v k="$k" '
        { line=$0; sub(/\r$/,"",line)
          if (line ~ /^[[:space:]]*#/) { print $0; next }
          key=line; sub(/=.*/,"",key); gsub(/^[[:space:]]+|[[:space:]]+$/,"",key)
          if (key==k) next
          print $0 }' "$f" >"$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -s "$tmp" && -n "$(tail -c1 "$tmp")" ]]; then printf '\n' >>"$tmp"; fi
    printf '%s=%s\n' "$k" "$v" >>"$tmp"
    cat "$tmp" >"$f" || { rm -f "$tmp"; return 1; }
    rm -f "$tmp"
}

backup_conf() {   # keep the FIRST original of each file, so rollback restores the real original
    local f="$1" b
    grep -qF "conf|${f}|" "$MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$MANIFEST"
}

valid_cidr() {
    local c="$1"
    [[ "$c" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] && return 0
    [[ "$c" == *:* && "$c" =~ ^[0-9A-Fa-f:]+(/[0-9]{1,3})?$ ]] && return 0
    return 1
}

fw_apply() {   # ports v4list v6list  (comma separated; lists may be empty)
    local ports="$1" v4="$2" v6="$3" mp
    if have nft; then
        run_or_say nft delete table inet psf_vsftpd 2>/dev/null || true
        run_or_say nft add table inet psf_vsftpd || return 1
        run_or_say nft add chain inet psf_vsftpd input '{ type filter hook input priority -5 ; policy accept ; }' || return 1
        run_or_say nft add rule inet psf_vsftpd input iifname lo accept || return 1
        if [[ -n "$v4" ]]; then
            run_or_say nft add rule inet psf_vsftpd input meta nfproto ipv4 tcp dport "{ ${ports} }" ip saddr != "{ ${v4} }" drop || return 1
        else
            run_or_say nft add rule inet psf_vsftpd input meta nfproto ipv4 tcp dport "{ ${ports} }" drop || return 1
        fi
        if [[ -n "$v6" ]]; then
            run_or_say nft add rule inet psf_vsftpd input meta nfproto ipv6 tcp dport "{ ${ports} }" ip6 saddr != "{ ${v6} }" drop || return 1
        else
            run_or_say nft add rule inet psf_vsftpd input meta nfproto ipv6 tcp dport "{ ${ports} }" drop || return 1
        fi
        [[ "${DRY:-0}" -eq 1 ]] || echo "fw|nft" >>"$MANIFEST"
        return 0
    fi
    if have iptables; then
        mp="${ports//-/:}"
        local tool c
        for tool in iptables ip6tables; do
            have "$tool" || continue
            run_or_say "$tool" -N PSF_VSFTPD 2>/dev/null || run_or_say "$tool" -F PSF_VSFTPD || return 1
            run_or_say "$tool" -A PSF_VSFTPD -i lo -j ACCEPT || return 1
            if [[ "$tool" == iptables ]]; then
                for c in ${v4//,/ }; do run_or_say "$tool" -A PSF_VSFTPD -s "$c" -j ACCEPT || return 1; done
            else
                for c in ${v6//,/ }; do run_or_say "$tool" -A PSF_VSFTPD -s "$c" -j ACCEPT || return 1; done
            fi
            run_or_say "$tool" -A PSF_VSFTPD -j DROP || return 1
            if ! "$tool" -C INPUT -p tcp -m multiport --dports "$mp" -j PSF_VSFTPD 2>/dev/null; then
                run_or_say "$tool" -I INPUT -p tcp -m multiport --dports "$mp" -j PSF_VSFTPD || return 1
            fi
        done
        [[ "${DRY:-0}" -eq 1 ]] || echo "fw|iptables|${mp}" >>"$MANIFEST"
        return 0
    fi
    caution "neither nft nor iptables found: no firewall rule added"
    return 1
}

fw_remove() {
    local line kind mp tool
    while IFS= read -r line; do
        kind="${line#fw|}"; kind="${kind%%|*}"
        if [[ "$kind" == nft ]] && have nft; then
            run_or_say nft delete table inet psf_vsftpd 2>/dev/null || true
            inf "removed the nftables table psf_vsftpd"
        elif [[ "$kind" == iptables ]]; then
            mp="${line##*|}"
            for tool in iptables ip6tables; do
                have "$tool" || continue
                run_or_say "$tool" -D INPUT -p tcp -m multiport --dports "$mp" -j PSF_VSFTPD 2>/dev/null || true
                run_or_say "$tool" -F PSF_VSFTPD 2>/dev/null || true
                run_or_say "$tool" -X PSF_VSFTPD 2>/dev/null || true
            done
            inf "removed the PSF_VSFTPD iptables chain"
        fi
    done < <(grep '^fw|' "$MANIFEST" 2>/dev/null)
}

maybe_restart() {
    [[ "${RESTART:-0}" -eq 1 ]] || return 0
    if have systemctl && grep -q '^vsftpd' <<<"$(systemctl list-unit-files 2>/dev/null)"; then
        run_or_say systemctl restart vsftpd && inf "restarted vsftpd"
    else
        caution "--restart given but no vsftpd systemd unit found: restart it yourself"
    fi
}

cmd_mitigate() {
    local reqcert=0 allow="" f ssl pasvp cert req changed=0 rc=0 c v4="" v6="" port pmin pmax ports="" nconf=0 first=1
    DRY=0; RESTART=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY=1 ;;
            --require-cert) reqcert=1 ;;
            --restart) RESTART=1 ;;
            --allow) shift; [[ -n "${1:-}" ]] || die "--allow needs a comma separated list of addresses or CIDRs"; allow="$1" ;;
            *) die "Unknown mitigate option: $1 (--require-cert --allow LIST --dry-run --restart)" ;;
        esac
        shift
    done
    [[ $DRY -eq 1 ]] || need_root "mitigate changes the host"
    if [[ -n "$allow" ]]; then
        for c in ${allow//,/ }; do
            valid_cidr "$c" || die "not an address or CIDR: ${c}"
            if [[ "$c" == *:* ]]; then v6+="${v6:+,}${c}"; else v4+="${v4:+,}${c}"; fi
        done
    fi
    if [[ -z "${VSFTPD_CONF:-}" && -z "$(discover_bins)" ]]; then info "No vsftpd found on this host: nothing to do"; return 0; fi
    if [[ $DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        MANIFEST="${STATE_DIR}/manifest.txt"; touch "$MANIFEST"
    else
        MANIFEST=/dev/null; step "Dry run: nothing will be changed"
    fi
    step "Configuration changes"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        nconf=$((nconf+1))
        ssl="$(conf_get "$f" ssl_enable NO)"
        if ! is_yes "$ssl"; then inf "${f}: ssl_enable is not YES, left alone"; continue; fi
        if [[ $first -eq 1 ]]; then
            first=0
            port="$(conf_get "$f" listen_port 21)"; pmin="$(conf_get "$f" pasv_min_port 0)"; pmax="$(conf_get "$f" pasv_max_port 0)"
            ports="$port"
            [[ "$pmin" =~ ^[0-9]+$ && "$pmax" =~ ^[0-9]+$ && "$pmin" -gt 0 && "$pmax" -ge "$pmin" ]] && ports+=",${pmin}-${pmax}"
        fi
        pasvp="$(conf_get "$f" pasv_promiscuous NO)"; cert="$(conf_get "$f" require_cert NO)"
        req="$(conf_get "$f" ssl_request_cert YES)"
        local need_pasv=0 need_cert=0
        is_yes "$pasvp" && need_pasv=1
        if [[ $reqcert -eq 1 ]]; then { is_yes "$cert" && is_yes "$req"; } || need_cert=1; fi
        if [[ $need_pasv -eq 0 && $need_cert -eq 0 ]]; then inf "${f}: nothing to change"; continue; fi
        if [[ $DRY -eq 0 ]]; then
            backup_conf "$f" || { bad "${f}: could not back it up, left alone"; rc=1; continue; }
            if ! grep -qF 'psf-security-patches: CVE-2026-119568' "$f"; then
                printf '\n# psf-security-patches: CVE-2026-119568 mitigation (vsftpd-ftps-ticket-check.sh mitigate). Undo with: rollback\n' >>"$f"
            fi
        fi
        if [[ $need_pasv -eq 1 ]]; then
            if [[ $DRY -eq 1 ]]; then echo "  would set pasv_promiscuous=NO in ${f}"; else conf_set "$f" pasv_promiscuous NO && ok "${f}: set pasv_promiscuous=NO"; fi
        fi
        if [[ $need_cert -eq 1 ]]; then
            if [[ $DRY -eq 1 ]]; then echo "  would set require_cert=YES and ssl_request_cert=YES in ${f}"
            else conf_set "$f" ssl_request_cert YES && conf_set "$f" require_cert YES && ok "${f}: set require_cert=YES and ssl_request_cert=YES (clients without a certificate are now refused)"; fi
        fi
        changed=1
    done < <(config_files)
    [[ $nconf -gt 0 ]] || { caution "no readable vsftpd configuration found: set VSFTPD_CONF to the file"; rc=1; }
    if [[ -n "$allow" ]]; then
        step "Firewall"
        [[ -n "$ports" ]] || { ports="21"; inf "no FTPS configuration to read ports from: using the control port 21 only"; }
        inf "only ${allow} (and loopback) may reach TCP ${ports}"
        if fw_apply "$ports" "$v4" "$v6"; then
            [[ $DRY -eq 1 ]] || ok "firewall rule installed (it does not survive a reboot)"
            changed=1
        else bad "firewall rule could not be installed"; rc=1; fi
    fi
    maybe_restart
    step "Result"
    if [[ $DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $changed -eq 1 ]]; then
        info "Mitigation applied. Backups and manifest are in ${STATE_DIR}. Undo with: $0 rollback"
        [[ $RESTART -eq 1 ]] || inf "restart vsftpd for the configuration changes to take effect (or re-run with --restart)"
    else info "Nothing needed changing"; fi
    inf "This reduces exposure. Run check again, and watch https://security.appspot.com/vsftpd.html for the fixed release."
    return "$rc"
}

cmd_rollback() {
    local line f b rc=0
    DRY=0; RESTART=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) DRY=1 ;; --restart) RESTART=1 ;; *) die "Unknown rollback option: $1 (--dry-run --restart)" ;; esac
        shift
    done
    MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $DRY -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
        if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
        if [[ $DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi
    done <"$MANIFEST"
    fw_remove
    if [[ $DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$MANIFEST" "${MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Restart vsftpd for restored configuration to take effect."
    fi
    maybe_restart
    return "$rc"
}


# ---------- optional hardening -----------------------------------------------
HSETS=(); HBIN=""
# h_add FILE KEY VALUE [le]: queue KEY=VALUE unless the build does not know KEY or the file already satisfies it.
# "le" means never loosen a numeric limit that is already set and at least as strict.
h_add() {
    local f="$1" k="$2" v="$3" mode="${4:-eq}" cur
    if ! knows_directive "$HBIN" "$k"; then caution "${f}: this vsftpd build does not know ${k}: skipped (setting it would stop vsftpd from starting)"; return 0; fi
    cur="$(conf_get "$f" "$k" "")"
    if [[ "$mode" == le ]]; then
        [[ "$cur" =~ ^[0-9]+$ && "$cur" -gt 0 && "$cur" -le "$v" ]] && return 0
    else
        [[ "$cur" == "${v^^}" ]] && return 0
    fi
    HSETS+=("${k}=${v}")
}

cmd_harden() {
    local do_log=0 do_lim=0 do_tls=0 do_ftls=0 do_anon=0 do_chroot=0 prange="" pmin="" pmax="" f nconf=0 changed=0 rc=0 kv standalone sslon localen
    DRY=0; RESTART=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --baseline) do_log=1; do_lim=1; do_tls=1 ;;
            --logging) do_log=1 ;; --limits) do_lim=1 ;; --tls) do_tls=1 ;; --force-tls) do_ftls=1 ;;
            --no-anon) do_anon=1 ;; --chroot) do_chroot=1 ;;
            --pasv-range) shift; prange="${1:-}" ;;
            --dry-run) DRY=1 ;; --restart) RESTART=1 ;;
            *) die "Unknown harden option: $1 (--baseline --logging --limits --tls --force-tls --no-anon --chroot --pasv-range A-B --dry-run --restart)" ;;
        esac
        shift
    done
    if [[ -n "$prange" ]]; then
        [[ "$prange" =~ ^([0-9]+)-([0-9]+)$ ]] || die "--pasv-range needs MIN-MAX, for example 40000-40100"
        pmin="${BASH_REMATCH[1]}"; pmax="${BASH_REMATCH[2]}"
        (( pmin >= 1024 && pmax <= 65535 && pmax >= pmin )) || die "--pasv-range must lie between 1024 and 65535 with MIN not above MAX"
    fi
    [[ $do_log -eq 1 || $do_lim -eq 1 || $do_tls -eq 1 || $do_ftls -eq 1 || $do_anon -eq 1 || $do_chroot -eq 1 || -n "$prange" ]] \
        || die "harden needs at least one measure (--baseline or one of the options in --help), because every item can break something. Nothing was changed."
    [[ $DRY -eq 1 ]] || need_root "harden changes the host"
    HBIN="$(discover_bins | head -n1)"
    if [[ -z "$HBIN" && -z "${VSFTPD_CONF:-}" ]]; then info "No vsftpd found on this host: nothing to do"; return 0; fi
    [[ -n "$HBIN" ]] || caution "no vsftpd binary found to ask which directives this build knows: every directive will be written as given"
    if [[ $DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        MANIFEST="${STATE_DIR}/manifest.txt"; touch "$MANIFEST"
    else MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    [[ $do_ftls -eq 0 ]] || caution "--force-tls: plain FTP logins and transfers will be refused: every client must speak FTPS (for local users vsftpd already does this by default when ssl_enable=YES)"
    [[ $do_chroot -eq 0 ]] || caution "--chroot: vsftpd refuses a login when the user's home directory is writable (500 OOPS: refusing to run with writable root inside chroot): fix the layout, or set allow_writeable_chroot yourself knowing it weakens the jail"
    [[ $do_anon -eq 0 ]] || caution "--no-anon: anonymous FTP stops working"
    [[ -z "$prange" ]] || caution "--pasv-range ${prange}: your firewall and NAT must allow TCP ${prange}, or passive transfers will hang"
    step "Configuration changes"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        nconf=$((nconf+1)); HSETS=()
        standalone=0; is_yes "$(conf_get "$f" listen NO)" && standalone=1; is_yes "$(conf_get "$f" listen_ipv6 NO)" && standalone=1
        sslon=0; is_yes "$(conf_get "$f" ssl_enable NO)" && sslon=1
        localen=0; is_yes "$(conf_get "$f" local_enable NO)" && localen=1
        if [[ $do_log -eq 1 ]]; then h_add "$f" xferlog_enable YES; fi
        if [[ $do_lim -eq 1 ]]; then
            if [[ $standalone -eq 1 ]]; then h_add "$f" max_clients 50 le; h_add "$f" max_per_ip 5 le
            else inf "${f}: not a standalone listener: max_clients and max_per_ip are ignored per connection, left alone"; fi
            h_add "$f" idle_session_timeout 300 le; h_add "$f" data_connection_timeout 120 le
        fi
        if [[ $do_tls -eq 1 ]]; then
            if [[ $sslon -eq 1 ]]; then
                h_add "$f" ssl_ciphers HIGH; h_add "$f" ssl_sslv2 NO; h_add "$f" ssl_sslv3 NO
                h_add "$f" ssl_tlsv1 NO; h_add "$f" ssl_tlsv1_1 NO; h_add "$f" ssl_tlsv1_2 YES
            else inf "${f}: ssl_enable is not YES: the TLS settings do not apply, left alone"; fi
        fi
        if [[ $do_ftls -eq 1 ]]; then
            if [[ $sslon -eq 1 ]]; then
                h_add "$f" force_local_logins_ssl YES; h_add "$f" force_local_data_ssl YES
                if is_yes "$(conf_get "$f" allow_anon_ssl NO)"; then h_add "$f" force_anon_logins_ssl YES; h_add "$f" force_anon_data_ssl YES
                else inf "${f}: allow_anon_ssl is not YES, so anonymous users cannot use TLS at all: not forcing it for them (use --no-anon to remove anonymous access)"; fi
            else caution "${f}: ssl_enable is not YES, so forcing TLS would lock every user out: left alone"; fi
        fi
        if [[ $do_anon -eq 1 ]]; then h_add "$f" anonymous_enable NO; fi
        if [[ $do_chroot -eq 1 ]]; then
            if [[ $localen -eq 1 ]]; then h_add "$f" chroot_local_user YES
            else inf "${f}: local_enable is not YES: there are no local users to jail, left alone"; fi
        fi
        if [[ -n "$prange" ]]; then h_add "$f" pasv_min_port "$pmin"; h_add "$f" pasv_max_port "$pmax"; fi
        if [[ ${#HSETS[@]} -eq 0 ]]; then inf "${f}: nothing to change"; continue; fi
        if [[ $DRY -eq 1 ]]; then
            for kv in "${HSETS[@]}"; do echo "  would set ${kv} in ${f}"; done
        else
            backup_conf "$f" || { bad "${f}: could not back it up, left alone"; rc=1; continue; }
            if ! grep -qF 'psf-security-patches: hardening' "$f"; then
                printf '\n# psf-security-patches: hardening (vsftpd-ftps-ticket-check.sh harden). Undo with: rollback\n' >>"$f"
            fi
            for kv in "${HSETS[@]}"; do conf_set "$f" "${kv%%=*}" "${kv#*=}" || rc=1; done
            ok "${f}: set ${HSETS[*]}"
        fi
        changed=1
    done < <(config_files)
    [[ $nconf -gt 0 ]] || { caution "no readable vsftpd configuration found: set VSFTPD_CONF to the file"; rc=1; }
    maybe_restart
    step "Result"
    if [[ $DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $changed -eq 1 ]]; then
        info "Hardening applied. Backups and manifest are in ${STATE_DIR}. Undo with: $0 rollback"
        [[ $RESTART -eq 1 ]] || inf "restart vsftpd for the configuration changes to take effect (or re-run with --restart), then try a login from each kind of client you have"
    else info "Nothing needed changing"; fi
    inf "This is baseline hardening, separate from ${CVE} and ${CVE2}."
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE} (vsftpd through 3.0.5) and ${CVE2} (authenticated DoS, Red Hat family packages)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        harden) cmd_harden "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|harden|rollback|version)" ;;
    esac
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
lock_for_change "mitigate rollback harden" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
