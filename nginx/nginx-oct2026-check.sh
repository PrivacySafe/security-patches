#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# nginx October 2026 security release: checker with optional workarounds  (v1)
# CVE-2026-15176 CVE-2026-93479 CVE-2026-97205 CVE-2026-95101 CVE-2026-97629
# njs: CVE-2026-101019 CVE-2026-101025
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# nginx 1.30.6 (stable) and 1.31.7 (mainline), 14 October 2026, fix five flaws.
# Three are heap/use-after-free memory bugs in worker processes (a crash, and
# possibly code execution): CVE-2026-15176 (alias with a rewrite),
# CVE-2026-93479 (a regex map's captures used by root or log_format), and
# CVE-2026-97205 (AIO with SSI). One forges a TLS session that can bypass
# client-certificate checks (CVE-2026-97629, automatic session-ticket-key
# rotation). One slips extra bytes into a proxied request (CVE-2026-95101,
# HTTP/3). nginx rates all five medium; F5 scores the three memory bugs 9.2
# critical, the TLS flaw 8.3, the HTTP/3 flaw 6.9. None was reported exploited
# as of mid-October 2026. njs 1.0.2 separately fixes two XML-module flaws in
# the JavaScript module (CVE-2026-101019, CVE-2026-101025).
#
# Each flaw needs a specific directive in your configuration, so a vulnerable
# nginx version is not necessarily reachable. "check" and "hunt" are read-only: "check"
# reports the nginx and njs versions on the host (and in containers), and audits the
# running configuration (nginx -T) for the directive combination each flaw
# needs, with F5's workaround for the ones you are exposed to; it
# changes nothing. The fix is to upgrade to 1.30.6 / 1.31.7 (or your distro's
# backport) and reload. "mitigate" is the only command that edits nginx.conf, and only
# for the three simple workarounds you choose, with a copy of every file and an
# automatic undo if nginx rejects the result; the others need an administrator.
#
# Usage:
#   ./nginx-oct2026-check.sh [command]
#
#   check (default)  nginx and njs versions on the host and in containers, and
#                    a configuration audit of the running nginx for the five
#                    flaws' trigger directives. Root optional, but nginx -T
#                    usually needs root to read the full config. Exit 0 =
#                    nothing exposed, 1 = a vulnerable nginx/njs is present,
#                    2 = something couldn't be read.
#   mitigate [options]   (root) changes the host. Applies F5's own workarounds for
#                    the flaws your running configuration is exposed to (the same audit as
#                    check, so a patched build or an unexposed flaw is left alone). You must
#                    choose among these; with no option it applies --tickets-off and --aio-off,
#                    the two low-impact measures. Options:
#                      --tickets-off          CVE-2026-97629: where ssl_session_cache is
#                                             shared, adds ssl_session_tickets off (TLS
#                                             session resumption through the shared cache
#                                             still works; ticket resumption stops)
#                      --aio-off              CVE-2026-97205: replaces "aio on" and "aio
#                                             threads" with "aio off" (slower file serving
#                                             under load; nothing breaks)
#                      --proxy-buffering-off  CVE-2026-95101: sets proxy_request_buffering
#                                             off at the http level (request bodies are
#                                             streamed to the upstream: retries stop, and
#                                             an upstream that needs Content-Length may
#                                             fail), only when the config sets it nowhere
#                      --force                apply a chosen measure even if the audit does
#                                             not report that flaw as exposed
#                      --dry-run, --reload    show only; graceful reload afterwards
#                    Every file is copied first and checked with nginx -t before and after;
#                    if nginx rejects the result the originals are put back at once. Not
#                    automated, because they need a person to read the configuration:
#                    CVE-2026-15176 (alias with a rewrite and $request_filename) and
#                    CVE-2026-93479 (a regex map whose captures feed root or log_format).
#                    These are F5's workarounds; the permanent fix is to upgrade.
#   rollback [--dry-run] [--reload]   put back every file mitigate changed.
#   hunt             read-only: the journal and logs for nginx worker crashes
#                    (segfaults, aborts), the likely symptom of the memory
#                    bugs. Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   FIXED_BUILDS="1.30.1-1~deb13u2"   distro nginx builds known to carry the
#                                     backported fix, space-separated full
#                                     versions (checked for dpkg-owned nginx)
#   NGINX_STABLE_FIXED=1.30.6         first fixed stable release
#   NGINX_MAINLINE_FIXED=1.31.7       first fixed mainline release
#   NJS_FIXED=1.0.2                   first fixed njs release
#   SCAN_CONTAINERS=1                 1 = read nginx inside running containers
#   STATE_DIR (default /var/lib/psf-security-patches/nginx) holds the backups and manifest
#   NGINX_BIN, NGINX_MAIN_CONF, NGINX_CONF_FILES   for mitigate: the binary, a non-default
#                                     main configuration file, and the files to edit
#   NGINX_T=1                         1 = run "nginx -T" for the config audit
#                                     (0 to skip it)
#   HUNT_SINCE="2026-10-01"           how far back hunt reads the journal
#   HUNT_LOGS="/var/log/nginx/*.log"  extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES="CVE-2026-15176 CVE-2026-93479 CVE-2026-97205 CVE-2026-95101 CVE-2026-97629"
NGINX_STABLE_FIXED="${NGINX_STABLE_FIXED:-1.30.6}"
NGINX_MAINLINE_FIXED="${NGINX_MAINLINE_FIXED:-1.31.7}"
NJS_FIXED="${NJS_FIXED:-1.0.2}"
FIXED_BUILDS="${FIXED_BUILDS:-}"
FIXED_BUILDS_KNOWN=""   # no confirmed distro backport build baked in yet
CHANGELOG_MARKERS=(CVE-2026-15176 CVE-2026-93479 CVE-2026-97205 CVE-2026-95101 CVE-2026-97629)
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
NGINX_T="${NGINX_T:-1}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCRIPT_NAME="nginx-oct2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/nginx}"
ADVISORY="https://nginx.org/en/security_advisories.html"

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
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
in_range() { ver_ge "$1" "$2" && ver_ge "$3" "$1"; }   # lo <= v <= hi
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- version judgment ------------------------------------------------
# nginx fixes land on the two current branches only: 1.30.6 (stable) and
# 1.31.7 (mainline). Older branches (1.28, 1.26, ...) upgrade to a current
# branch or take a distro backport.
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

# A distro can backport the fix under an older upstream number, so judge a
# dpkg-owned nginx on its package build/changelog first.
nginx_pkg_state() {   # <X.Y.Z> <binary path> -> rc|why
    local v="$1" p="${2:-}" pkg full f m cl rc why
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
                1) echo "1|${pkg} ${full} (upstream ${why}). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS" ;;
                *) echo "2|${pkg} ${full} (version unreadable)" ;;
            esac
            return
        fi
    fi
    nginx_upstream_state "$v"
}

# ---------- discovery --------------------------------------------------------
nginx_binaries() {
    { type -a -P nginx 2>/dev/null || true
      shopt -s nullglob
      local c
      for c in /usr/sbin/nginx /usr/local/sbin/nginx /usr/local/nginx/sbin/nginx /opt/*/sbin/nginx; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u
}
nginx_version_of() { "$1" -v 2>&1 | grep -oE 'nginx/[0-9]+\.[0-9]+\.[0-9]+' | head -1 | cut -d/ -f2 || true; }

# ---------- config audit -----------------------------------------------------
# Each flaw needs a directive combination. These are greps over the
# dumped config (nginx -T); they report the ingredients, not a guarantee.
audit_config() {   # <version> <vfixed 0/1> <config-text-file>
    local v="$1" vfixed="$2" cfg="$3" exposed_local=0
    # A patched nginx is not reachable regardless of config; fold that into the
    # per-flaw range test so a fixed build never reports "exposed".
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

    # CVE-2026-15176: alias + rewrite + $request_filename  (0.1.29 - 1.31.6)
    local p15=0
    grep -qE '^\s*alias\s' "$cfg" && grep -qE '^\s*rewrite\s' "$cfg" && grep -qE '\$request_filename' "$cfg" && p15=1
    _flag "CVE-2026-15176" "$(rok "$v" 0.1.29 1.31.6)" "$p15" \
        "alias with a rewrite and \$request_filename" \
        "do not use alias in that location, or do not read \$request_filename there"

    # CVE-2026-93479: regex map captures used by root/log_format  (1.30.0-1.30.5, 1.31.2-1.31.6)
    local p93=0
    if grep -qE '^\s*map\s' "$cfg" && grep -qE '~' "$cfg" && { grep -qE '^\s*root\s' "$cfg" || grep -qE '^\s*log_format\s' "$cfg"; }; then p93=1; fi
    local r93=0; [[ "$vfixed" != 1 ]] && { in_range "$v" 1.30.0 1.30.5 || in_range "$v" 1.31.2 1.31.6; } && r93=1
    _flag "CVE-2026-93479" "$r93" "$p93" \
        "a regex map whose captures feed root or log_format" \
        "use named captures, only inside the block with the regex match"

    # CVE-2026-97205: aio + ssi  (0.8.11 - 1.31.6)
    local p97=0
    grep -qE '^\s*aio\s+(on|threads)' "$cfg" && grep -qE '^\s*ssi\s+on' "$cfg" && p97=1
    _flag "CVE-2026-97205" "$(rok "$v" 0.8.11 1.31.6)" "$p97" \
        "AIO enabled together with SSI pages" \
        "turn aio off, or do not serve SSI pages"

    # CVE-2026-95101: HTTP/3 + proxy_request_buffering on (default)  (1.25.0 - 1.31.6)
    local p95=0
    if { grep -qE 'listen[^;]*quic' "$cfg" || grep -qE '^\s*http3\s+on' "$cfg"; } && ! grep -qE '^\s*proxy_request_buffering\s+off' "$cfg"; then p95=1; fi
    _flag "CVE-2026-95101" "$(rok "$v" 1.25.0 1.31.6)" "$p95" \
        "HTTP/3 (quic) with proxy_request_buffering on (the default)" \
        "set proxy_request_buffering off"

    # CVE-2026-97629: shared TLS session cache with automatic ticket-key rotation  (1.23.2 - 1.31.6)
    local p976=0
    if grep -qE '^\s*ssl_session_cache\s+shared' "$cfg" && ! grep -qE '^\s*ssl_session_ticket_key' "$cfg" && ! grep -qE '^\s*ssl_session_tickets\s+off' "$cfg"; then p976=1; fi
    _flag "CVE-2026-97629" "$(rok "$v" 1.23.2 1.31.6)" "$p976" \
        "ssl_session_cache shared without ssl_session_ticket_key (automatic key rotation)" \
        "load keys with ssl_session_ticket_key, remove the shared cache, or set ssl_session_tickets off"

    return "$exposed_local"
}

# ---------- containers -------------------------------------------------------
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

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 b v st how any=0 primary=""
    step "nginx on the host"
    while read -r b; do
        [[ -n "$b" ]] || continue
        any=1; [[ -z "$primary" ]] && primary="$b"
        v="$(nginx_version_of "$b")"
        IFS='|' read -r st how <<<"$(nginx_pkg_state "$v" "$b")"
        case $st in
            0) ok "${b}  nginx ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "${b}  nginx ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "${b}  nginx ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
        esac
    done < <(nginx_binaries)
    [[ $any -eq 1 ]] || inf "no nginx binary found on PATH or the usual locations"

    step "njs (nginx JavaScript module)"
    if have njs; then
        v="$(njs -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        if [[ -z "$v" ]]; then caution "njs present but version unreadable"; unknownz=1
        elif ver_ge "$v" "$NJS_FIXED"; then ok "njs ${v}  $(state_word 0)  (>= ${NJS_FIXED})"
        else bad "njs ${v}  $(state_word 1)  (< ${NJS_FIXED}; CVE-2026-101019 / CVE-2026-101025 in the XML module); upgrade njs to ${NJS_FIXED}"; exposed=1; fi
    elif [[ -n "$primary" ]] && "$primary" -V 2>&1 | grep 'js_module\|njs' >/dev/null; then
        caution "nginx is built with the njs module but the njs CLI is not on PATH; confirm njs >= ${NJS_FIXED} (CVE-2026-101019 / CVE-2026-101025)"; unknownz=1
    else inf "njs not detected"; fi

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
            if audit_config "$v" "$vfixed" "$cfg"; then :; else exposed=1; fi
            inf "these matches cover the whole config; confirm the directives share a server/location before acting"
        else
            caution "could not run 'nginx -T' (needs root and a valid config); skipping the config audit"
            unknownz=1
        fi
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
        0) info "No vulnerable nginx/njs found, or none configured to reach the flaws" ;;
        1) warn "A vulnerable nginx or njs is present. Upgrade to 1.30.6 (stable) or 1.31.7 (mainline), and njs to ${NJS_FIXED}, or your distribution's backport, then reload. For a flaw you can't upgrade away yet, apply the per-flaw workaround shown above. Advisory: ${ADVISORY}" ;;
        *) warn "Some things couldn't be read. Run as root so 'nginx -T' and the package checks work" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for nginx worker crashes since ${HUNT_SINCE}"
    local jr; jr="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$jr'" RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >"$jr" || true; fi
    local -a files=()
    [[ -s "$jr" ]] && files+=("$jr")
    local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/nginx/*error*.log /var/log/nginx/*.log /var/log/syslog /var/log/syslog.1 \
             /var/log/kern.log /var/log/messages $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "nginx worker crash (signal) in the error log|worker process [0-9]+ exited on signal (11|6|7)"
        "nginx segfault or protection fault in the kernel log|nginx\[[0-9]+\]: segfault|nginx.*(general protection|trap invalid opcode)"
        "use-after-free or heap corruption abort|(use-after-free|double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned))"
        "service killed by SIGSEGV/SIGABRT/SIGBUS|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1; caution "${name}: ${n}"
            { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-220 | sed 's/^/      /'
        else ok "${name}: none"; fi
    done
    echo
    echo "  A hit tells you where to look: workers crash for many reasons. Repeated worker"
    echo "  crashes on a vulnerable build, on a server whose config reaches one of these"
    echo "  flaws, are worth treating as an incident while you upgrade."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------

# ---------- mitigate and rollback --------------------------------------------
NG_MANIFEST=""; NG_DRY=0; NG_RELOAD=0; NGB=""
ng_nginx() { "$NGB" ${NGINX_MAIN_CONF:+-c "$NGINX_MAIN_CONF"} "$@"; }
ng_note() { [[ "$NG_DRY" -eq 1 ]] || echo "$1" >>"$NG_MANIFEST"; }
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
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f"
    done <"$NG_MANIFEST"
}
ng_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    ng_nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p' | awk '!s[$0]++' | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done
}
# prints the CVE ids this nginx is exposed to, using the same audit as "check"
ng_exposed() {
    local cfg v pst vfixed=0
    cfg="$(mktemp)" || return 1
    if ! ng_nginx -T >"$cfg" 2>/dev/null || [[ ! -s "$cfg" ]]; then rm -f "$cfg"; return 1; fi
    v="$(nginx_version_of "$NGB")"
    IFS='|' read -r pst _ <<<"$(nginx_pkg_state "$v" "$NGB")"
    [[ "$pst" == 0 ]] && vfixed=1
    audit_config "$v" "$vfixed" "$cfg" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -F '[exposed]' | grep -oE 'CVE-[0-9]+-[0-9]+' | sort -u
    rm -f "$cfg"
}
read -r -d '' NG_AWK_TICKETS <<'AWKEOF' || true
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*ssl_session_tickets[ \t]+on[ \t]*;/) { sub(/ssl_session_tickets[ \t]+on/, "ssl_session_tickets off", line); print line; next }
    print line
    if (!hastick && code ~ /^[ \t]*ssl_session_cache[ \t]+shared/) { match(line, /^[ \t]*/); print substr(line, 1, RLENGTH) "ssl_session_tickets off;" }
}
AWKEOF
read -r -d '' NG_AWK_AIO <<'AWKEOF' || true
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*aio[ \t]+(on|threads)/) { match(line, /^[ \t]*/); print substr(line, 1, RLENGTH) "aio off;"; next }
    print line
}
AWKEOF
read -r -d '' NG_AWK_PBUF <<'AWKEOF' || true
{
    line = $0; code = line; sub(/#.*/, "", code)
    if (code ~ /^[ \t]*proxy_request_buffering[ \t]+on[ \t]*;/) { sub(/proxy_request_buffering[ \t]+on/, "proxy_request_buffering off", line); print line; next }
    print line
    if (ins && !done && code ~ /^[ \t]*http[ \t]*\{/) { print "    proxy_request_buffering off;"; done = 1 }
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

cmd_mitigate() {
    local tickets=0 aio=0 pbuf=0 force=0 rc=0 changed=0 f exposed anyp=0 r hastick ins
    local -a files=()
    set +e   # this script runs with -e; several normal steps below return non-zero (for example "nothing to change")
    NG_DRY=0; NG_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tickets-off) tickets=1 ;; --aio-off) aio=1 ;; --proxy-buffering-off) pbuf=1 ;;
            --force) force=1 ;; --dry-run) NG_DRY=1 ;; --reload) NG_RELOAD=1 ;;
            *) die "Unknown mitigate option: $1 (--tickets-off --aio-off --proxy-buffering-off --force --dry-run --reload)" ;;
        esac
        shift
    done
    local defaulted=0
    if [[ $tickets -eq 0 && $aio -eq 0 && $pbuf -eq 0 ]]; then tickets=1; aio=1; defaulted=1; fi
    [[ $NG_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "mitigate changes the host: run it as root, or add --dry-run to see what it would do"
    NGB="${NGINX_BIN:-$(nginx_binaries | head -n1)}"
    if [[ -z "$NGB" || ! -x "$NGB" ]]; then info "No nginx found on this host: nothing to do"; return 0; fi
    [[ $defaulted -eq 0 ]] || info "No option given: applying the two low-impact measures, --tickets-off and --aio-off. Add --proxy-buffering-off for HTTP/3 request buffering."
    step "Which flaws is this nginx exposed to?"
    exposed="$(ng_exposed)" || { bad "could not run nginx -T (needs root and a valid configuration): not touching anything"; return 1; }
    if [[ -n "$exposed" ]]; then inf "exposed: $(tr '\n' ' ' <<<"$exposed")"; else ok "the audit reports no exposed flaw"; fi
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(ng_files)
    [[ ${#files[@]} -gt 0 ]] || { caution "no readable configuration file found"; return 1; }
    if ! ng_nginx -t >/dev/null 2>&1; then bad "nginx -t rejects the configuration as it is now: not touching it (fix that first)"; return 1; fi
    ok "nginx -t accepts the current configuration (${#files[@]} file(s))"
    if [[ $NG_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        NG_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$NG_MANIFEST"
    else NG_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    step "Configuration changes"
    hit() { [[ $force -eq 1 ]] || grep -qxF "$1" <<<"$exposed"; }
    if [[ $tickets -eq 1 ]]; then
        if hit CVE-2026-97629; then
            for f in "${files[@]}"; do
                hastick=0; grep -qE '^[[:space:]]*ssl_session_tickets' "$f" && hastick=1
                ng_apply "CVE-2026-97629: ssl_session_tickets off" "$f" "$NG_AWK_TICKETS" -v hastick="$hastick"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "CVE-2026-97629 is not reported as exposed: --tickets-off left alone (--force overrides)"; fi
    fi
    if [[ $aio -eq 1 ]]; then
        if hit CVE-2026-97205; then
            for f in "${files[@]}"; do
                ng_apply "CVE-2026-97205: aio off" "$f" "$NG_AWK_AIO"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "CVE-2026-97205 is not reported as exposed: --aio-off left alone (--force overrides)"; fi
    fi
    if [[ $pbuf -eq 1 ]]; then
        if hit CVE-2026-95101; then
            for f in "${files[@]}"; do grep -qE '^[[:space:]]*proxy_request_buffering' "$f" && anyp=1; done
            for f in "${files[@]}"; do
                ins=0
                if [[ $anyp -eq 0 ]] && grep -qE '^[[:space:]]*http[[:space:]]*\{' "$f"; then ins=1; anyp=1; fi
                ng_apply "CVE-2026-95101: proxy_request_buffering off" "$f" "$NG_AWK_PBUF" -v ins="$ins"; r=$?
                [[ $r -eq 0 ]] && changed=1; [[ $r -eq 2 ]] && rc=1
            done
        else ok "CVE-2026-95101 is not reported as exposed: --proxy-buffering-off left alone (--force overrides)"; fi
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
    if grep -qxF CVE-2026-15176 <<<"$exposed"; then inf "CVE-2026-15176 is not automated: do not use alias in that location, or do not read \$request_filename there"; fi
    if grep -qxF CVE-2026-93479 <<<"$exposed"; then inf "CVE-2026-93479 is not automated: use named captures, only inside the block with the regex match"; fi
    step "Result"
    if [[ $NG_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $changed -eq 1 ]]; then
        info "Applied. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $NG_RELOAD -eq 1 ]] || inf "reload nginx for it to take effect (or re-run with --reload)"
    else info "Nothing needed changing"; fi
    inf "These are F5's workarounds; the permanent fix is to upgrade to 1.30.6 (stable) or 1.31.7 (mainline) or your distribution's backport."
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
    [[ $NG_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "rollback changes the host: run it as root, or add --dry-run"
    step "Rolling back"
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
        if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
        if [[ $NG_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi
    done <"$NG_MANIFEST"
    if [[ $NG_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$NG_MANIFEST" "${NG_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload nginx for the restored configuration to take effect."
        if [[ $NG_RELOAD -eq 1 ]] && grep -q '^nginx' <<<"$(systemctl list-unit-files 2>/dev/null)"; then systemctl reload nginx && inf "reloaded nginx (graceful)"; fi
    fi
    return "$rc"
}

main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
case "$CMD" in mitigate|rollback) ;; *) [[ $# -eq 0 ]] || die "Unknown option: $1" ;; esac
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "nginx: ${CVES}; njs: CVE-2026-101019 CVE-2026-101025; advisory: ${ADVISORY}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    mitigate|rollback) "cmd_${CMD}" "$@" ;;
    *) die "Unknown command: $CMD (check|hunt|mitigate|rollback|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
