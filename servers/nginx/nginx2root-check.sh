#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# nginx2root: ten nginx HTTP/2, HTTP/3, resolver, mail-proxy and TLS flaws  (v1)
# CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425
# CVE-2026-118899 CVE-2026-120967 CVE-2026-120993 CVE-2026-125283 CVE-2026-123640
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# nginx 1.30.7 (stable) and 1.31.9 (mainline), released 18 November 2026, fix
# ten flaws in all. Five are the ones this script actively audits for,
# detailed below. The other five, fixed by the exact same two releases, are
# not separately audited: CVE-2026-118899 (high: a TLS 1.3 worker can hang in
# a loop reading a request body on any "listen ... ssl;" server that allows
# TLS 1.3, a denial of service rather than code execution, with no F5
# workaround published); CVE-2026-120967 (medium); and CVE-2026-120993,
# CVE-2026-125283, CVE-2026-123640 (low, opt-in features or limited impact).
# Upgrading to the fixed releases closes all ten at once; an unpatched
# version is exposed to CVE-2026-118899 on nothing more than an ordinary TLS
# 1.3-enabled server block, the same way CVE-2026-123007 needs nothing but
# HTTP/2, so treat it the same way in your own risk accounting even though
# this script's audit output doesn't name it directive-by-directive.
#
# The five this script does audit: F5 and nginx both rate two of them 9.2
# (CVSS 4.0) critical. Two were independently found by five separate teams
# (Wiz Research, Xint, Metnir, Rapid7 and Ikotas Labs, who also call it
# NGINX2Shell; it is the same two bugs, not a sixth): CVE-2026-123007, an
# HTTP/2 flow-control integer underflow exploitable even on a plain
# static-file server with no backend, and CVE-2026-123633, a use-after-free
# reachable when HTTP/2 is proxied to an upstream and the worker is short of
# connection slots. Xint found three more on its own as part of research it
# names nginx2root: CVE-2026-123634 (a resolver use-after-free, reachable
# through "mirror" plus a request-derived proxy_pass target), CVE-2026-121810
# (the same shape of bug over HTTP/3 instead of HTTP/2), and CVE-2026-113425
# (a use-after-free in the mail proxy's auth_http path). Xint also chained
# CVE-2026-123007 with a Linux kernel SCTP use-after-free in ASCONF handling,
# since assigned CVE-2026-64564 (Red Hat CVSS 3.1 7.8, present since 4.15),
# to get root on the host, including out of a Docker
# container; that kernel bug is a different, newer issue from three
# already-fixed 2026 SCTP flaws in the kernel's own advisory history, one of
# them nicknamed "SCTPhantom", and this script cannot check for it, only
# help you block the module that carries it. As of 22 November 2026, the fix
# for that kernel bug has merged into mainline (net-7.4-rc4, 19 Nov) but no
# stable kernel release carries it yet, and Docker's default seccomp profile
# does not block SCTP sockets, so blocking the module remains the only
# stopgap for anyone who can't run that unreleased kernel.
#
# CVE-2026-123007 affects nginx 1.9.5 through 1.31.8 and needs nothing but
# HTTP/2 turned on; it was present in every official release for more than a
# decade. The other four each need a more specific setup, shown below. Rapid7
# published a working proof of concept; it needs about 128 GB of HTTP/2
# traffic over one connection and a glibc memcpy implementation chosen at
# runtime on CPUs with AVX-512 (Xint's own writeup and demo instead walk
# through a build that resolves to the AVX2 memcpy path; both are real,
# CPU-dependent variants of the same bug, not a disagreement between them).
# As of 19 November 2026 this is a complete, public, unauthenticated RCE:
# Rapid7's repository includes a runnable client that negotiates the attack
# over real TLS and HTTP/2 and demonstrates arbitrary command execution
# against a freshly started nginx container, with no backend and no
# authentication; it targets a single, lightly loaded container and may not
# succeed as reliably against a busy production server with a "messy" heap
# or multiple concurrent clients, which is a property of this specific
# demonstration, not a reason an unpatched server is safe.
#
# CVE | Needs, besides an unpatched version | First affected | http2/http3 off helps?
# CVE-2026-123007 | HTTP/2 on, nothing else | 1.9.5 | yes
# CVE-2026-123633 | HTTP/2 on, proxied to an upstream | 1.19.7 | yes
# CVE-2026-123634 | resolver, a request-derived proxy_pass, and mirror | 0.6.18 | no
# CVE-2026-121810 | HTTP/3 (quic) on, proxied to an upstream | 1.25.0 | no (http3 off helps)
# CVE-2026-113425 | a mail block with "proxy on" and auth_http | 0.5.33 | no
#
# "check" and "hunt" are read-only and change nothing. "check" reports the
# nginx version (host and containers) and audits the running configuration
# (nginx -T) for each flaw's trigger directives, the same approach and the
# same caveat as our nginx-oct2026-check.sh: a match shows the ingredients
# are present, not a guarantee, and matches are not confirmed to share a
# server or location block. "hunt" looks for signs in the logs that match
# what Xint's own write-up says an attack leaves: sustained one-way traffic,
# requests that stay small while received bytes climb, and abnormal worker
# exits. None of it can see the WINDOW_UPDATE and RST_STREAM frames the
# attack itself sends: those are control frames, not logged requests, and
# TLS hides them from a packet capture at the host. "mitigate" edits
# nginx.conf for three of the five flaws (http2-off also covers the one
# chained with the kernel bug), backs up every file it touches, and rolls
# back automatically if nginx rejects the result. The fourth, the resolver
# and mirror flaw, needs a fixed upstream address only you know, so "rules"
# explains it instead of editing anything (as our wordpress-upgrade and
# openssh-musl tools do for what they can't automate either). The kernel
# flaw has its own mitigate option, since it is not an nginx.conf change.
#
# Usage:
#   ./nginx2root-check.sh [command] [options]
#
#   check (default)  nginx version on the host and in containers, and a
#                    configuration audit for the five flaws' trigger
#                    directives. Root optional, but nginx -T usually needs
#                    root to read the full config. Exit 0 = nothing exposed,
#                    1 = a vulnerable nginx is present, 2 = something
#                    couldn't be read.
#   hunt             read-only: connection and log signals from Section 3.2
#                    of Xint's write-up (long-lived connections with far more
#                    received than sent, HTTP/2 requests whose logged length
#                    stays small while bytes_received climbs, and abnormal
#                    nginx worker exits in the logs). None of this proves an
#                    attack; Xint's own guidance is to weigh several signs
#                    together. Exit 0 = nothing found, 1 = a lead.
#   mitigate [options]   (root) changes the host. With no option, applies
#                    --http2-off, the single broadest fix (covers the two
#                    multiply-discovered flaws and removes the path used to
#                    reach host root in Xint's demo). Options:
#                      --http2-off    CVE-2026-123007, CVE-2026-123633: sets
#                                     "http2 off;" (nginx >= 1.25.1) or drops
#                                     the http2 listen parameter (older),
#                                     per F5's own workaround. Breaks anything
#                                     that specifically needs HTTP/2, such as
#                                     native gRPC.
#                      --http3-off    CVE-2026-121810: removes "quic" listen
#                                     parameters, sets "http3 off;", and
#                                     clears any Alt-Svc header advertising
#                                     HTTP/3.
#                      --mail-loopback  CVE-2026-113425: binds every mail
#                                     proxy listen directive to 127.0.0.1, so
#                                     only this host can reach it. Only use
#                                     this if the mail proxy does not need
#                                     outside access; otherwise restrict it
#                                     with a firewall instead and skip this.
#                      --block-sctp   the kernel flaw (CVE-2026-64564): adds
#                                     "install sctp /bin/false" under
#                                     /etc/modprobe.d/, so modprobe refuses to
#                                     load the sctp module from now on. Does
#                                     not unload a copy already loaded, and
#                                     does nothing to a kernel with SCTP
#                                     compiled in rather than as a module.
#                                     Skip this on a host that uses SCTP.
#                      --force        apply a chosen measure even if the
#                                     audit does not report that flaw exposed
#                      --dry-run, --reload   show only; graceful reload after
#                    Every nginx.conf file is copied first and checked with
#                    nginx -t before and after; if nginx rejects the result
#                    the originals are put back at once. CVE-2026-123634 is
#                    not automated: see "rules".
#   rollback [--dry-run] [--reload]   put back every file mitigate changed,
#                    nginx.conf and the modprobe.d drop-in alike.
#   rules            prints the manual fix for CVE-2026-123634 (a fixed
#                    upstream group instead of a request-derived proxy_pass
#                    target) and the modprobe.d line "mitigate --block-sctp"
#                    writes, for anyone who would rather add it by hand.
#   version          print the script version.
#
# Env overrides:
#   NGINX_STABLE_FIXED=1.30.7     first fixed stable release
#   NGINX_MAINLINE_FIXED=1.31.9   first fixed mainline release
#   FIXED_BUILDS="1.24.0-2ubuntu7.99"   distro nginx builds known to carry a
#                                  backported fix, space-separated full
#                                  versions (checked for dpkg-owned nginx).
#                                  As of 18 November 2026, no distro had
#                                  shipped a backport yet: Debian's and
#                                  Ubuntu's own trackers both still marked
#                                  every supported release vulnerable.
#   SCAN_CONTAINERS=1             1 = read nginx inside running containers
#   STATE_DIR (default /var/lib/psf-security-patches/nginx2root) holds the
#                                  backups and manifest, including the
#                                  modprobe.d drop-in's own backup record
#   NGINX_BIN, NGINX_MAIN_CONF, NGINX_CONF_FILES   for mitigate: the binary,
#                                  a non-default main configuration file, and
#                                  the files to edit
#   NGINX_T=1                     1 = run "nginx -T" for the config audit
#   HUNT_LOGS="/var/log/nginx/*.log"   extra log globs for hunt
#   HUNT_ACCESS_LOG=/var/log/nginx/access.log   the access log hunt reads for
#                                  per-request sizes, if it uses a custom path
#   PSF_LOCK_WAIT    seconds a run that changes the host waits for another one
#                     already changing it (default 30), then stops with exit
#                     2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES="CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425 CVE-2026-118899 CVE-2026-120967 CVE-2026-120993 CVE-2026-125283 CVE-2026-123640"
NGINX_STABLE_FIXED="${NGINX_STABLE_FIXED:-1.30.7}"
NGINX_MAINLINE_FIXED="${NGINX_MAINLINE_FIXED:-1.31.9}"
FIXED_BUILDS="${FIXED_BUILDS:-}"
FIXED_BUILDS_KNOWN=""   # no confirmed distro backport build baked in yet (see README)
CHANGELOG_MARKERS=(CVE-2026-123007 CVE-2026-123633 CVE-2026-123634 CVE-2026-121810 CVE-2026-113425 CVE-2026-118899 CVE-2026-120967 CVE-2026-120993 CVE-2026-125283 CVE-2026-123640)
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
NGINX_T="${NGINX_T:-1}"
HUNT_LOGS="${HUNT_LOGS:-}"
HUNT_ACCESS_LOG="${HUNT_ACCESS_LOG:-/var/log/nginx/access.log}"
SCRIPT_NAME="nginx2root-check.sh"
SCRIPT_VERSION="1.1.1"
SCRIPT_DATE="2026-11-22"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/nginx2root}"
ADVISORY="https://nginx.org/en/security_advisories.html"
WRITEUP="https://nginx2root.com/"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: files and logs that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: files and logs that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
in_range() { ver_ge "$1" "$2" && ver_ge "$3" "$1"; }   # lo <= v <= hi
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- version judgment --------------------------------------------------
# All five flaws are fixed on the same two current branches: 1.30.7 (stable)
# and 1.31.9 (mainline). Older branches (1.28, 1.26, ...) upgrade to a
# current branch or take a distro backport.
nginx_upstream_state() {   # <X.Y.Z> -> rc|why
    local v="$1"
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if ver_ge "$v" "1.32.0"; then echo "0|${v} is newer than the fixed releases"; return; fi
    if ver_ge "$v" "1.31.0"; then
        if ver_ge "$v" "$NGINX_MAINLINE_FIXED"; then echo "0|${v} >= ${NGINX_MAINLINE_FIXED} (mainline)"
        else echo "1|${v} < ${NGINX_MAINLINE_FIXED} (mainline fix)"; fi
        return
    fi
    if ver_ge "$v" "$NGINX_STABLE_FIXED"; then echo "0|${v} >= ${NGINX_STABLE_FIXED} (stable)"; return; fi
    if ver_ge "$v" "1.30.0"; then echo "1|${v} < ${NGINX_STABLE_FIXED} (stable fix)"; return; fi
    echo "1|${v}: branch is older than 1.30; upgrade to ${NGINX_STABLE_FIXED} or ${NGINX_MAINLINE_FIXED}"
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

nginx_pkg_state() {   # <X.Y.Z> <binary path> -> rc|why
    local v="$1" p="${2:-}" pkg full f cl m rc why
    if [[ -n "$p" ]]; then
        pkg="$(owner_pkg "$p")"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            for f in $FIXED_BUILDS_KNOWN $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            cl="/usr/share/doc/${pkg}/changelog.Debian.gz"
            if [[ -f "$cl" && "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]]; then
                for m in "${CHANGELOG_MARKERS[@]}"; do
                    if zgrep -q "$m" "$cl" 2>/dev/null; then echo "0|${pkg} ${full}: changelog lists ${m}"; return; fi
                done
            fi
            IFS='|' read -r rc why <<<"$(nginx_upstream_state "$v")"
            case $rc in
                0) echo "0|${pkg} ${full} (${why})" ;;
                1) echo "1|${pkg} ${full} (upstream ${why}). As of 18 November 2026 no distro had a backport yet; check your distro's own advisory, then add any backport build to FIXED_BUILDS" ;;
                *) echo "2|${pkg} ${full} (version unreadable)" ;;
            esac
            return
        fi
    fi
    nginx_upstream_state "$v"
}

# ---------- discovery ----------------------------------------------------------
nginx_binaries() {
    { type -a -P nginx 2>/dev/null || true
      shopt -s nullglob
      local c
      for c in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx /opt/*/sbin/nginx; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u
}
nginx_version_of() { "$1" -v 2>&1 | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2 || true; }
nginx_is_plus() { "$1" -v 2>&1 | grep -qi 'nginx-plus'; }

# ---------- config audit --------------------------------------------------------
# Each flaw needs a directive combination. These are greps over the dumped
# config (nginx -T); they report the ingredients, not a guarantee, and do not
# confirm the directives share a server/location block.
audit_config() {   # <version> <vfixed 0/1> <config-text-file> <is_plus 0/1>
    local v="$1" vfixed="$2" cfg="$3" exposed_local=0
    rok() { [[ "$vfixed" == 1 ]] && { echo 0; return; }; in_range "$1" "$2" "$3" && echo 1 || echo 0; }

    _flag() {   # <cve> <range-ok 0/1> <present 0/1> <desc> <workaround>
        local cve="$1" rok="$2" present="$3" desc="$4" wrk="$5"
        if [[ "$present" == 1 && "$rok" == 1 ]]; then
            bad "${cve}: ${desc}  [exposed]"; inf "    workaround: ${wrk}"; exposed_local=1
        elif [[ "$present" == 1 ]]; then
            caution "${cve}: ${desc} is configured, but ${v} is outside this flaw's affected range"
        else
            ok "${cve}: not configured (${desc})"
        fi
    }

    local has_http2=0 has_http3=0 has_proxy_pass=0 has_resolver=0 has_mirror=0 has_mirror_body_on=0
    grep -qE 'listen[^;]*\bhttp2\b|^[[:space:]]*http2[[:space:]]+on[[:space:]]*;' "$cfg" && has_http2=1
    grep -qE 'listen[^;]*\bquic\b|^[[:space:]]*http3[[:space:]]+on[[:space:]]*;' "$cfg" && has_http3=1
    grep -qE '^[[:space:]]*proxy_pass[[:space:]]' "$cfg" && has_proxy_pass=1
    grep -qE '^[[:space:]]*resolver[[:space:]]' "$cfg" && has_resolver=1
    # nginx's mirror directive takes a URI (always starts with /) or the literal keyword "off"; this
    # checks for the URI form specifically, rather than excluding "off" (which also missed "OFF" or
    # any other value that isn't a URI, however unlikely in practice).
    grep -qE '^[[:space:]]*mirror[[:space:]]+/' "$cfg" && has_mirror=1
    grep -qE '^[[:space:]]*mirror_request_body[[:space:]]+on[[:space:]]*;' "$cfg" && has_mirror_body_on=1

    # CVE-2026-123007: HTTP/2 enabled, nothing else needed  (1.9.5 - 1.31.8)
    _flag "CVE-2026-123007" "$(rok "$v" 1.9.5 1.31.8)" "$has_http2" \
        "HTTP/2 enabled (works even with no backend, serving only static files)" \
        "set http2 off (or drop the http2 listen parameter on nginx < 1.25.1), then reload"

    # CVE-2026-123633: HTTP/2 enabled AND proxying to an upstream  (1.19.7 - 1.31.8)
    local p633=0; [[ "$has_http2" == 1 && "$has_proxy_pass" == 1 ]] && p633=1
    _flag "CVE-2026-123633" "$(rok "$v" 1.19.7 1.31.8)" "$p633" \
        "HTTP/2 enabled together with proxy_pass to an upstream" \
        "set http2 off (same workaround as CVE-2026-123007), then reload"

    # CVE-2026-123634: resolver + a request-derived proxy_pass + mirror  (0.6.18 - 1.31.8)
    # mirror_request_body on stops Xint's specific proof of concept but is not a fix for the
    # underlying use-after-free (their own write-up says so), so it is not treated as clearing this.
    local p634=0 proxy_has_var=0
    grep -qE '^[[:space:]]*proxy_pass[[:space:]]+[^;]*\$' "$cfg" && proxy_has_var=1
    [[ "$has_resolver" == 1 && "$proxy_has_var" == 1 && "$has_mirror" == 1 ]] && p634=1
    if [[ "$p634" == 1 && "$has_mirror_body_on" == 1 ]]; then
        inf "    mirror_request_body on is set: it stopped Xint's own proof of concept but is not a fix for the underlying bug"
    fi
    _flag "CVE-2026-123634" "$(rok "$v" 0.6.18 1.31.8)" "$p634" \
        "resolver with a request-derived proxy_pass target (contains a variable) and mirror" \
        "point proxy_pass at a fixed upstream group for both the main request and any mirror (see 'rules'); this one is not automated"

    # CVE-2026-121810: HTTP/3 (quic) enabled AND proxying to an upstream  (1.25.0 - 1.31.8)
    local p121=0; [[ "$has_http3" == 1 && "$has_proxy_pass" == 1 ]] && p121=1
    _flag "CVE-2026-121810" "$(rok "$v" 1.25.0 1.31.8)" "$p121" \
        "HTTP/3 (quic) enabled together with proxy_pass to an upstream" \
        "remove the quic listen parameter, set http3 off, and clear any Alt-Svc header, then reload"

    # CVE-2026-113425: a mail block using proxy on and auth_http, reachable from outside  (0.5.33 - 1.31.8)
    # A loopback-only mail listener is not practically exposed, so a mail proxy on the standard
    # mail ports bound to anything else (or with no address, which means every address) still
    # counts; this does not confirm the listen line is inside the same mail block as proxy/auth_http,
    # the same whole-config approximation the other checks above make.
    local p113=0 mail_remote=0 listen_line
    if grep -qE '^[[:space:]]*mail[[:space:]]*\{' "$cfg" || grep -qE '^[[:space:]]*(imap|pop3|smtp)[[:space:]]*\{' "$cfg"; then
        if grep -qE '^[[:space:]]*proxy[[:space:]]+on[[:space:]]*;' "$cfg" && grep -qE '^[[:space:]]*auth_http[[:space:]]' "$cfg"; then
            # Any single mail-port listen line that is not loopback-bound counts, so this checks
            # each matching line on its own rather than a single existence test (which could not
            # tell "all loopback" from "one loopback, one public" on separate listen lines).
            while IFS= read -r listen_line; do
                printf '%s\n' "$listen_line" | grep -qE '(127\.0\.0\.1|localhost|\[?::1\]?)' || mail_remote=1
            done < <(grep -E '^[[:space:]]*listen[[:space:]]+(([^[:space:];]*:)?(25|110|143|465|587|993|995)\b)' "$cfg" 2>/dev/null)
            [[ "$mail_remote" == 1 ]] && p113=1
        fi
    fi
    _flag "CVE-2026-113425" "$(rok "$v" 0.5.33 1.31.8)" "$p113" \
        "a mail proxy block using proxy on with auth_http, listening on more than loopback" \
        "bind the mail listeners to 127.0.0.1, or restrict them with a firewall (see mitigate --mail-loopback)"

    if [[ "$4" == 1 ]]; then
        inf "this is an NGINX Plus build: Plus fixes land on different numbers (R33 and later get 37.0.8.1 / 37.3.0.1 for CVE-2026-123007, 37.0.7.1 / 37.2.0.1 for CVE-2026-123633; see the README). The version compared above is the open-source base it reports and may not reflect the Plus-specific fix"
    fi
    return "$exposed_local"
}

# ---------- containers -----------------------------------------------------------
container_nginx() {   # "runtime|ref|version"
    [[ "$SCAN_CONTAINERS" == 1 ]] || return 0
    local rt id name v
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'nginx -v 2>&1' 2>/dev/null | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2 || true)"
            [[ -n "$v" ]] && echo "${rt}|${name:-$id}|${v}"
        done
    done
}

# ---------- check -----------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 b v st how any=0 primary="" is_plus=0
    step "nginx on the host"
    while read -r b; do
        [[ -n "$b" ]] || continue
        any=1; [[ -z "$primary" ]] && primary="$b"
        v="$(nginx_version_of "$b")"
        nginx_is_plus "$b" && is_plus=1
        IFS='|' read -r st how <<<"$(nginx_pkg_state "$v" "$b")"
        case $st in
            0) ok "${b}  nginx ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "${b}  nginx ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "${b}  nginx ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
        esac
    done < <(nginx_binaries)
    [[ $any -eq 1 ]] || inf "no nginx binary found on PATH or the usual locations"

    step "Configuration audit (which flaws your nginx is configured to reach)"
    if [[ "$NGINX_T" != 1 ]]; then inf "config audit disabled (NGINX_T=0)"
    elif [[ -z "$primary" ]]; then inf "no nginx binary to run 'nginx -T' with"
    else
        local cfg; cfg="$(mktemp)"
        # shellcheck disable=SC2064
        trap "rm -f '$cfg'" RETURN
        if "$primary" -T >"$cfg" 2>/dev/null && [[ -s "$cfg" ]]; then
            v="$(nginx_version_of "$primary")"
            local pst vfixed=0
            IFS='|' read -r pst _ <<<"$(nginx_pkg_state "$v" "$primary")"
            [[ "$pst" == 0 ]] && vfixed=1
            inf "auditing the running config of ${primary} (nginx ${v:-?}$([[ $vfixed -eq 1 ]] && echo ', patched'))"
            if audit_config "$v" "$vfixed" "$cfg" "$is_plus"; then :; else exposed=1; fi
            inf "these matches cover the whole config; confirm the directives share a server/location before acting"
        else
            caution "could not run 'nginx -T' (needs root and a valid config); skipping the config audit"
            unknownz=1
        fi
    fi

    step "Linux kernel SCTP module (used to chain CVE-2026-123007 to host root in Xint's demo)"
    if [[ -r /proc/modules ]] && grep -qw sctp /proc/modules 2>/dev/null; then
        caution "the sctp module is currently loaded. The kernel flaw Xint used is CVE-2026-64564; its fix is in mainline (19 November 2026) but in no stable kernel release as of 22 November, and this script cannot detect it, only reduce exposure. Check your distribution's kernel advisory, not the upstream version number. If this host does not use SCTP, see 'mitigate --block-sctp' (loading it again needs a reboot or manual unload, which this script does not do)"
    elif have modprobe && modprobe -n sctp >/dev/null 2>&1; then
        caution "the sctp module is not currently loaded, but it would load automatically the first time something opens an SCTP socket. If this host does not use SCTP, see 'mitigate --block-sctp'"
    else
        ok "sctp module not available to load (or modprobe could not be checked)"
    fi

    step "nginx inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt ref cv any_c=0
        while IFS='|' read -r rt ref cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r st how <<<"$(nginx_upstream_state "$cv")"
            case $st in
                0) ok "${rt} ${ref}  nginx ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${ref}  nginx ${cv}  $(state_word 1)  (${how}); rebuild the image on a fixed base"; exposed=1 ;;
                *) caution "${rt} ${ref}  nginx ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_nginx)
        [[ $any_c -eq 1 ]] || inf "no running container reports an nginx version (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable nginx found, or none configured to reach any of the five flaws" ;;
        1) warn "A vulnerable nginx is present. Upgrade to 1.30.7 (stable) or 1.31.9 (mainline), or your distribution's backport, then reload: this closes all ten flaws these releases fix, not only the five this script audits. CVE-2026-123007 needs nothing but HTTP/2 turned on, and CVE-2026-118899 (high, a TLS 1.3 worker hang) needs nothing but an ordinary TLS 1.3 server block, so treat an unpatched version as exposed to both even without a config audit; for the other three this script does audit, see whether the audit above found their trigger directives, and apply the matching workaround shown there, or 'mitigate', if you can't upgrade yet. Advisory: ${ADVISORY} ; write-up: ${WRITEUP}" ;;
        *) warn "Some things couldn't be read. Run as root so 'nginx -T' and the package checks work" ;;
    esac
    return "$rc"
}

# ---------- hunt ---------------------------------------------------------------
# These are the read-only signals from Xint's own write-up (Section 3.2): sustained
# one-way traffic on long-lived connections (3.2.1, needs a live "ss" snapshot, so hunt
# instead looks at access-log entries whose logged length cannot explain a long
# request_time), small logged request lengths next to large received byte counts where
# the custom h2_hunt log format has been added (3.2.2), and abnormal worker exits
# (3.2.4). It cannot see the control frames the attack itself sends (3.2.1's live ss
# comparison and 3.2.3's auditd rule need to be set up and watched in real time, which a
# single read-only run cannot do; the README explains how to add them).
cmd_hunt() {
    step "Hunting for nginx2root attack signals"
    limited_view
    local found=0 g f
    local -a files=()
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in "$HUNT_ACCESS_LOG" /var/log/nginx/*error*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable nginx logs (try as root, or set HUNT_LOGS / HUNT_ACCESS_LOG)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    step "Abnormal worker exits (Section 3.2.4: a failed exploit attempt can crash a worker)"
    local n
    n="$( { grep -hEc 'worker process.*exited|signal 11|segfault' "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
    if [[ "${n:-0}" -gt 0 ]]; then
        found=1; caution "abnormal worker exits / segfaults found: ${n}"
        grep -hE 'worker process.*exited|signal 11|segfault' "${files[@]}" 2>/dev/null | tail -3 | cut -c1-200 | sed 's/^/      /'
    else ok "abnormal worker exits / segfaults: none"; fi
    if have coredumpctl; then
        local cd; cd="$(coredumpctl list nginx 2>/dev/null | tail -n +2 | wc -l || echo 0)"
        [[ "${cd:-0}" -gt 0 ]] && { caution "coredumpctl also lists ${cd} nginx core dump(s)"; found=1; }
    fi

    step "Request-vs-connection-size mismatch (Section 3.2.2: needs the h2_hunt log format)"
    if grep -qE '\bconn=[0-9]+\b' "$HUNT_ACCESS_LOG" 2>/dev/null; then
        inf "the access log already has a connection id (conn=): this is set up. Compare request_length totals per conn against 'ss -tinp' bytes_received by the same source IP, as the README describes; this script cannot capture that live state by itself."
    else
        caution "the access log has no connection id (conn=) field: the custom log_format from Section 3.2.2 of Xint's write-up is not configured, so this signal is not available yet. See the README to add it; it needs only a config reload, not a restart."
    fi

    step "Sustained one-way HTTP/2 traffic (Section 3.2.1: needs a live 'ss' snapshot)"
    if have ss; then
        local est; est="$(ss -tinp state established '( sport = :443 )' 2>/dev/null | grep -c '^ESTAB' || true)"
        inf "established TLS connections on :443 right now: ${est:-0}. A single snapshot cannot show the pattern Xint describes (bytes_received growing fast while bytes_sent stays small, over several minutes); run 'ss -tinp state established' twice, a short interval apart, and compare, or watch it continuously while investigating a specific source IP."
    else
        caution "'ss' is not available; cannot even take a snapshot of connection byte counts"
    fi

    echo
    echo "  None of these on their own proves an attack: Xint's own guidance is to treat several"
    echo "  of them together, with no ordinary explanation, as worth investigating. The clearest"
    echo "  sign, a program started by an nginx worker, needs the auditd rule from Section 3.2.3"
    echo "  of their write-up (the README has the exact command); this script does not install it."
    return "$found"
}

# ---------- mitigate and rollback -----------------------------------------------
NG_MANIFEST=""; NG_DRY=0; NG_RELOAD=0; NGB=""
ng_nginx() { "$NGB" ${NGINX_MAIN_CONF:+-c "$NGINX_MAIN_CONF"} "$@"; }
ng_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$NG_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$NG_MANIFEST"
}
ng_restore_all() {
    local line f
    while IFS= read -r line; do
        case "$line" in
            conf\|*) f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f" ;;
        esac
    done <"$NG_MANIFEST"
}
ng_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    ng_nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p' | awk '!s[$0]++' | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done
}
ng_exposed() {
    local cfg v pst vfixed=0 isp=0
    cfg="$(mktemp)" || return 1
    if ! ng_nginx -T >"$cfg" 2>/dev/null || [[ ! -s "$cfg" ]]; then rm -f "$cfg"; return 1; fi
    v="$(nginx_version_of "$NGB")"
    nginx_is_plus "$NGB" && isp=1
    IFS='|' read -r pst _ <<<"$(nginx_pkg_state "$v" "$NGB")"
    [[ "$pst" == 0 ]] && vfixed=1
    audit_config "$v" "$vfixed" "$cfg" "$isp" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -F '[exposed]' | grep -oE 'CVE-[0-9]+-[0-9]+' | sort -u
    rm -f "$cfg"
}

read -r -d '' NG_AWK_HTTP2 <<'AWKEOF' || true
# Plain mawk has no \b word-boundary extension, so "http2" is matched and removed as a whole
# whitespace-separated token (split/rejoin), not with a regex boundary assertion. newsyn is 1
# only when the running nginx is >= 1.25.1, where "http2 off;" is a directive on its own; on
# older nginx that line is an unknown-directive error, so it is only emitted when newsyn=1, and
# then once per modified listen line (not once per file), since each one needs its own override
# in case something at an outer context still sets "http2 on;".
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*listen[ \t]/ && code ~ /(^|[ \t])http2([ \t]|;|$)/) {
        n = split(line, parts, /[ \t]+/); out = ""; had_semi = 0
        for (i = 1; i <= n; i++) {
            tok = parts[i]; bare = tok; semi = 0
            if (bare ~ /;$/) { semi = 1; sub(/;$/, "", bare) }
            if (bare == "http2") { if (semi) had_semi = 1; continue }
            if (semi) tok = bare ";"
            out = (out == "" ? tok : out " " tok)
        }
        if (had_semi && out !~ /;[ \t]*$/) out = out ";"
        print out
        if (newsyn) { match(line, /^[ \t]*/); print substr(line, 1, RLENGTH) "http2 off;" }
        next
    }
    if (code ~ /^[ \t]*http2[ \t]+on[ \t]*;/) { sub(/http2[ \t]+on/, "http2 off", line); print line; next }
    print line
}
AWKEOF
read -r -d '' NG_AWK_HTTP3 <<'AWKEOF' || true
# An existing Alt-Svc header is replaced with the clear value in place, not deleted outright
# (deleting it without a replacement would leave no Alt-Svc header at all, which is not the same
# as clearing it). ins is only used to insert a new line right after "server {" when the whole
# file had no add_header Alt-Svc line anywhere; a file with one block that has an existing header
# and another that doesn't still only gets the in-place replacement for the one that has it, the
# same whole-file approximation the rest of this script's config checks already make.
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*listen[ \t]/ && code ~ /(^|[ \t])quic([ \t]|;|$)/) { print "#" line; next }
    if (code ~ /^[ \t]*http3[ \t]+on[ \t]*;/) { sub(/http3[ \t]+on/, "http3 off", line); print line; next }
    if (code ~ /^[ \t]*add_header[ \t]+Alt-Svc[ \t]/) {
        match(line, /^[ \t]*/); print substr(line, 1, RLENGTH) "add_header Alt-Svc \x27clear\x27 always;"; next
    }
    print line
    if (ins && !done && code ~ /^[ \t]*server[ \t]*\{/) { print "    add_header Alt-Svc \x27clear\x27 always;"; done = 1 }
}
AWKEOF
read -r -d '' NG_AWK_MAIL <<'AWKEOF' || true
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*listen[ \t]/ && inmail) {
        n = split(line, parts, /[ \t]+/)
        for (i = 1; i <= n; i++) {
            if (parts[i] ~ /^[0-9.]*:[0-9]+;?$/ || parts[i] ~ /^[0-9]+;?$/) {
                had_semi = (parts[i] ~ /;$/) ? ";" : ""
                port = parts[i]; sub(/;$/, "", port); sub(/^.*:/, "", port)
                parts[i] = "127.0.0.1:" port had_semi
            }
        }
        line = parts[1]; for (i = 2; i <= n; i++) line = line " " parts[i]
    }
    if (code ~ /^[ \t]*mail[ \t]*\{/) inmail = 1
    print line
}
AWKEOF
# ng_apply LABEL FILE AWK [awk -v args...]  -> 0 changed, 1 unchanged, 2 failed
ng_apply() {
    local label="$1" f="$2" prog="$3" tmp n; shift 3
    tmp="$(mktemp "${TMPDIR:-/tmp}/ngmit.XXXXXX")" || return 2
    awk "$@" "$prog" "$f" >"$tmp" || { rm -f "$tmp"; return 2; }
    if cmp -s "$f" "$tmp"; then rm -f "$tmp"; return 1; fi
    n=$(diff "$f" "$tmp" | grep -c '^>')
    if [[ "$NG_DRY" -eq 1 ]]; then echo "  would change ${n} line(s) in ${f} (${label})"; diff "$f" "$tmp" | grep '^>' | sed 's/^/      /' | cut -c1-120
    else
        if ! ng_backup "$f"; then bad "${f}: could not back it up, left alone"; rm -f "$tmp"; return 2; fi
        cat "$tmp" >"$f" || { rm -f "$tmp"; return 2; }
        ok "${f}: ${label} (${n} line(s))"
    fi
    rm -f "$tmp"; return 0
}

ng_block_sctp() {   # -> 0 written, 1 already there, 2 failed
    local dropin="/etc/modprobe.d/psf-nginx2root-block-sctp.conf"
    if [[ -f "$dropin" ]] && grep -qE '^\s*install\s+sctp\s+/bin/false\s*$' "$dropin" 2>/dev/null; then
        return 1
    fi
    if [[ "$NG_DRY" -eq 1 ]]; then echo "  would create ${dropin} with: install sctp /bin/false"; return 0; fi
    mkdir -p /etc/modprobe.d || return 2
    echo "install sctp /bin/false" >"$dropin" || return 2
    echo "modprobe|${dropin}|" >>"$NG_MANIFEST"
    ok "${dropin}: created (install sctp /bin/false)"
    return 0
}
ng_unblock_sctp() {
    local dropin="/etc/modprobe.d/psf-nginx2root-block-sctp.conf"
    [[ -f "$dropin" ]] || return 0
    if [[ "$NG_DRY" -eq 1 ]]; then echo "  would remove ${dropin}"; return 0; fi
    rm -f "$dropin" && ok "removed ${dropin}"
}

cmd_mitigate() {
    local http2=0 http3=0 mail=0 sctp=0 force=0 rc=0 changed=0 f exposed newsyn ins
    local -a files=()
    set +e   # this script runs with -e; several normal steps below return non-zero (for example "nothing to change")
    NG_DRY=0; NG_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --http2-off) http2=1 ;; --http3-off) http3=1 ;; --mail-loopback) mail=1 ;; --block-sctp) sctp=1 ;;
            --force) force=1 ;; --dry-run) NG_DRY=1 ;; --reload) NG_RELOAD=1 ;;
            *) die "Unknown mitigate option: $1 (--http2-off --http3-off --mail-loopback --block-sctp --force --dry-run --reload)" ;;
        esac
        shift
    done
    local defaulted=0
    if [[ $http2 -eq 0 && $http3 -eq 0 && $mail -eq 0 && $sctp -eq 0 ]]; then http2=1; defaulted=1; fi
    [[ $NG_DRY -eq 1 ]] || need_root "mitigate changes the host"
    if [[ $NG_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        NG_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$NG_MANIFEST"
    else NG_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi

    if [[ $sctp -eq 1 ]]; then
        step "Kernel SCTP module"
        ng_block_sctp; r=$?
        case $r in
            0) : ;;
            1) ok "the block is already in place" ;;
            2) bad "could not write the modprobe.d drop-in"; rc=1 ;;
        esac
    fi

    if [[ $http2 -eq 0 && $http3 -eq 0 && $mail -eq 0 ]]; then
        [[ $defaulted -eq 0 && $sctp -eq 1 ]] && { step "Result"; info "Only --block-sctp was requested; nginx.conf was not touched."; return "$rc"; }
    fi
    [[ $defaulted -eq 0 ]] || info "No option given: applying --http2-off, the broadest of the four nginx.conf fixes."

    NGB="${NGINX_BIN:-$(nginx_binaries | head -n1)}"
    if [[ -z "$NGB" || ! -x "$NGB" ]]; then
        if [[ $http2 -eq 1 || $http3 -eq 1 || $mail -eq 1 ]]; then info "No nginx found on this host: nothing more to do"; fi
        return "$rc"
    fi
    step "Which flaws is this nginx exposed to?"
    exposed="$(ng_exposed)" || { bad "could not run nginx -T (needs root and a valid configuration): not touching nginx.conf"; return 1; }
    if [[ -n "$exposed" ]]; then inf "exposed: $(tr '\n' ' ' <<<"$exposed")"; else ok "the audit reports no exposed flaw"; fi
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(ng_files)
    [[ ${#files[@]} -gt 0 ]] || { caution "no readable configuration file found"; return 1; }
    if ! ng_nginx -t >/dev/null 2>&1; then bad "nginx -t rejects the configuration as it is now: not touching it (fix that first)"; return 1; fi
    ok "nginx -t accepts the current configuration (${#files[@]} file(s))"
    step "Configuration changes"
    hit() { [[ $force -eq 1 ]] || grep -qxF "$1" <<<"$exposed"; }
    if [[ $http2 -eq 1 ]]; then
        if hit CVE-2026-123007 || hit CVE-2026-123633; then
            newsyn=0; ver_ge "$(nginx_version_of "$NGB")" "1.25.1" && newsyn=1
            for f in "${files[@]}"; do
                ng_apply "CVE-2026-123007 / CVE-2026-123633: http2 off" "$f" "$NG_AWK_HTTP2" -v newsyn="$newsyn"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "neither CVE-2026-123007 nor CVE-2026-123633 is reported as exposed: --http2-off left alone (--force overrides)"; fi
    fi
    if [[ $http3 -eq 1 ]]; then
        if hit CVE-2026-121810; then
            for f in "${files[@]}"; do
                ins=0; grep -qE '^[[:space:]]*add_header[[:space:]]+Alt-Svc\b' "$f" || ins=1
                ng_apply "CVE-2026-121810: http3 off, quic listener removed, Alt-Svc cleared" "$f" "$NG_AWK_HTTP3" -v ins="$ins"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "CVE-2026-121810 is not reported as exposed: --http3-off left alone (--force overrides)"; fi
    fi
    if [[ $mail -eq 1 ]]; then
        if hit CVE-2026-113425; then
            for f in "${files[@]}"; do
                ng_apply "CVE-2026-113425: mail listeners bound to 127.0.0.1" "$f" "$NG_AWK_MAIL"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "CVE-2026-113425 is not reported as exposed: --mail-loopback left alone (--force overrides)"; fi
    fi
    if [[ $NG_DRY -eq 0 && $changed -eq 1 ]]; then
        step "Checking the new configuration"
        if ng_nginx -t >/dev/null 2>&1; then ok "nginx -t accepts the new configuration"
        else
            bad "nginx -t REJECTS the new configuration: restoring the originals now"
            ng_restore_all; : >"$NG_MANIFEST"; bad "originals restored, nothing was changed"; return 1
        fi
        if [[ $NG_RELOAD -eq 1 ]]; then
            if grep -q '^nginx' <<<"$(systemctl list-unit-files 2>/dev/null)"; then systemctl reload nginx && inf "reloaded nginx (graceful)"
            else caution "--reload given but no nginx systemd unit found: reload it yourself"; fi
        fi
        exposed="$(ng_exposed || true)"
        if [[ -n "$exposed" ]]; then inf "still exposed after the change: $(tr '\n' ' ' <<<"$exposed")"; else ok "the audit now reports no exposed flaw"; fi
    fi
    if grep -qxF CVE-2026-123634 <<<"$exposed"; then inf "CVE-2026-123634 is not automated: see 'rules' for the fix"; fi
    step "Result"
    if [[ $NG_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $changed -eq 1 ]]; then
        info "Applied. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $NG_RELOAD -eq 1 ]] || inf "reload nginx for it to take effect (or re-run with --reload)"
    else info "Nothing needed changing"; fi
    inf "These are F5's and Xint's own workarounds; the permanent fix is to upgrade to 1.30.7 (stable) or 1.31.9 (mainline), or your distribution's backport."
    return "$rc"
}

cmd_rollback() {
    local line f b rc=0
    set +e
    NG_DRY=0; NG_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) NG_DRY=1 ;; --reload) NG_RELOAD=1 ;; *) die "Unknown rollback option: $1 (--dry-run --reload)" ;; esac
        shift
    done
    NG_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$NG_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $NG_DRY -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS= read -r line; do
        case "$line" in
            conf\|*)
                f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
                if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
                if [[ $NG_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi
                ;;
            modprobe\|*)
                f="${line#modprobe|}"; f="${f%%|*}"
                if [[ $NG_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi
                ;;
        esac
    done <"$NG_MANIFEST"
    if [[ $NG_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$NG_MANIFEST" "${NG_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload nginx for a restored nginx.conf to take effect; the sctp block, if any, takes effect on a module load attempt, with no reload needed."
        if [[ $NG_RELOAD -eq 1 ]] && grep -q '^nginx' <<<"$(systemctl list-unit-files 2>/dev/null)"; then systemctl reload nginx && inf "reloaded nginx (graceful)"; fi
    fi
    return "$rc"
}

cmd_rules() {
    step "CVE-2026-123634: fixed upstream groups instead of a request-derived proxy_pass target"
    cat <<'EOF'
This flaw needs a resolver, a proxy_pass target built from the request (such as
proxy_pass http://$host;), and mirror together. It is not automated here because the
fix needs your actual backend address, which this script cannot know.

If you don't need mirroring, turn it off in the affected location and point proxy_pass
at a fixed upstream group. Replace {BACKEND_IP} with your backend's address:

    upstream backend_hotfix {
        server {BACKEND_IP}:8080;
    }
    location / {
        mirror off;
        proxy_pass http://backend_hotfix;
    }

If you need mirroring, use fixed upstream groups for both the main request and the
mirror:

    upstream backend_main_hotfix {
        server {MAIN_SERVER_IP}:8080;
    }
    upstream backend_mirror_hotfix {
        server {MIRROR_SERVER_IP}:8080;
    }
    location / {
        mirror /mirror;
        proxy_pass http://backend_main_hotfix;
    }
    location = /mirror {
        internal;
        proxy_pass http://backend_mirror_hotfix;
    }

Setting mirror_request_body on also stopped Xint's own proof of concept, but it is not
a fix for the underlying resolver use-after-free; do not rely on it alone.

Validate and reload afterwards:

    sudo nginx -t && sudo nginx -s reload
EOF
    step "The kernel SCTP block mitigate --block-sctp writes"
    cat <<'EOF'
/etc/modprobe.d/psf-nginx2root-block-sctp.conf:

    install sctp /bin/false

This stops modprobe from loading the sctp module from now on. It does not unload a
copy that is already loaded (check with: lsmod | grep sctp), and it does nothing on a
kernel that has SCTP compiled in rather than built as a loadable module. Skip this on
a host that uses SCTP.
EOF
}

main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
case "$CMD" in mitigate|rollback) ;; *) [[ $# -eq 0 ]] || die "Unknown option: $1" ;; esac
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "nginx2root: ${CVES}; advisory: ${ADVISORY} ; write-up: ${WRITEUP}"
case "$CMD" in
    check|hunt|rules) "cmd_${CMD}" ;;
    mitigate|rollback) "cmd_${CMD}" "$@" ;;
    *) die "Unknown command: $CMD (check|hunt|mitigate|rollback|rules|version)" ;;
esac
}
# ---------- one change at a time ---------------------------------------------------------------------
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_words=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
        case "$lk_arg" in -*) ;; *) lk_words=$((lk_words + 1)) ;; esac
    done
    [[ $lk_words -eq 0 && "$lk_cmds" == *" * "* ]] && lk_hit=1
    [[ $lk_hit -eq 1 ]] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "mitigate rollback" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5
