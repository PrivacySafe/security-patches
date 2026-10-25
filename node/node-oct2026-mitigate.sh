#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Node.js October 2026 interim mitigation  (v1)
# CVE-2026-111497 (Brotli decoder out-of-bounds write, RCE) and the nine other
# CVEs fixed in Node.js 22.23.4 / 24.22.1 / 26.12.1 on 21 Oct 2026
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Usage:
#   ./node-oct2026-mitigate.sh [command] [--unit NAME]... [--force]
#
#   check (default)  read-only report: every Node runtime on the host (PATH,
#                    nvm, n, fnm, volta, asdf, /opt, running processes,
#                    container images), whether each is fixed, which running
#                    processes still need a restart or a guard. Root optional
#                    (root sees every process). Exit 0 = nothing exposed,
#                    1 = unfixed runtime in use, 2 = something couldn't be read.
#   scan             read-only: find application code and dependencies that
#                    decode Brotli, Node single executable applications (SEAs)
#                    and startup snapshots that must be rebuilt
#                    (CVE-2026-106074). Exit 0 = none, 1 = findings.
#   guard --unit U   load brotli-guard.cjs into systemd unit U through a
#                    drop-in that adds --require to NODE_OPTIONS, restart it,
#                    and prove the guard is live. Rolls back if U won't start.
#   unguard --unit U remove that drop-in and restart U.
#   status           guarded units, their runtime, and what the guard blocked.
#   hunt             read-only: scan the journal and logs for Node crashes
#                    (segfaults, V8 fatal errors, Brotli decoder frames) and
#                    guard events. Exit 0 = clean, 1 = findings.
#
#   --unit NAME      systemd unit for guard/unguard (repeatable; .service
#                    is added if missing)
#   --force          guard: install even if the guard's self-test fails on
#                    the unit's runtime, or the runtime is already fixed
#
# This script never executes a Node binary as root unless root owns it and
# nobody else can write it. Versions are read from the binary's contents, so
# a binary planted in a user's ~/.nvm or inside a container is never run with
# root's privileges.
#
# Env overrides:
#   NODE_FIXED_22=22.23.4 NODE_FIXED_24=24.22.1 NODE_FIXED_26=26.12.1
#                                      first fixed release per line
#   FIXED_BUILDS="20.19.2+dfsg-1+deb13u2"  distro builds known to carry the
#                                      fix (Debian/Ubuntu backport to an
#                                      upstream-EOL line)
#   SCAN_PATHS="/srv /opt /var/www /home /usr/local/lib /usr/lib/node_modules"
#   SCAN_DEPTH=8                       how deep scan descends
#   GUARD_DST=/usr/local/lib/privacysafe/brotli-guard.cjs
#   HUNT_SINCE="2026-10-14"            how far back hunt reads the journal
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES=(CVE-2026-111497 CVE-2026-105482 CVE-2026-105483 CVE-2026-106069 CVE-2026-105481
      CVE-2026-106072 CVE-2026-106074 CVE-2026-106070 CVE-2026-106071 CVE-2026-106073)
KEY_CVE="CVE-2026-111497"
declare -A FIXED_DEFAULT=([22]=22.23.4 [24]=24.22.1 [26]=26.12.1)
fixed_for() { local n="NODE_FIXED_$1"; echo "${!n:-${FIXED_DEFAULT[$1]:-}}"; }
FIXED_BUILDS="${FIXED_BUILDS:-}"
SCAN_PATHS="${SCAN_PATHS:-/srv /opt /var/www /home /usr/local/lib /usr/lib/node_modules}"
SCAN_DEPTH="${SCAN_DEPTH:-8}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-14}"
SCRIPT_NAME="node-oct2026-mitigate.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-23"
SELF="$0"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD_SRC="${GUARD_SRC:-${SELF_DIR}/brotli-guard.cjs}"
GUARD_DST="${GUARD_DST:-/usr/local/lib/privacysafe/brotli-guard.cjs}"
DROPIN_NAME="50-privacysafe-brotli-guard.conf"
MARKER="# managed-by: privacysafe node-oct2026-mitigate"
SEA_FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1"

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
section() { echo -e "\n  ${CYAN}$*${NC}"; }

is_root() { [[ $EUID -eq 0 ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
have_systemd() { [[ -d /run/systemd/system ]] && have systemctl; }

# ---------- versions ---------------------------------------------------------
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# Release builds embed their own version in the headers/source URLs
# ("node-v24.22.0-headers.tar.gz"). Reading it costs a grep and runs nothing.
static_version() {
    local v
    v="$(grep -aoE -m1 'node-v[0-9]+\.[0-9]+\.[0-9]+' "$1" 2>/dev/null | head -1 || true)"
    [[ -n "$v" ]] && echo "${v#node-}"
}

# Executing is the fallback, and only for a binary root could trust anyway.
safe_to_exec() {
    local f="$1" d
    [[ -x "$f" ]] || return 1
    [[ "$(stat -Lc %u "$f" 2>/dev/null)" == 0 ]] || return 1
    [[ $(( 8#$(stat -Lc %a "$f") & 8#022 )) -eq 0 ]] || return 1
    d="$(dirname "$(readlink -f "$f")")"
    while [[ "$d" != / ]]; do
        [[ "$(stat -c %u "$d")" == 0 && $(( 8#$(stat -c %a "$d") & 8#022 )) -eq 0 ]] || return 1
        d="$(dirname "$d")"
    done
}

node_version() {   # <binary> -> vX.Y.Z or empty
    local v; v="$(static_version "$1")"
    if [[ -z "$v" ]] && { ! is_root || safe_to_exec "$1"; }; then
        v="$(timeout 5 "$1" --version 2>/dev/null | head -1 || true)"
    fi
    [[ "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]] && echo "${BASH_REMATCH[0]}"
}

# "<rc>|<explanation>": rc 0 = fixed, 1 = not fixed, 2 = unknown
patch_state() {   # <vX.Y.Z> [binary path]
    local v="${1#v}" bin="${2:-}" major fixed pkg full cl
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    major="${v%%.*}"; fixed="$(fixed_for "$major")"

    # A distro package can carry the fix under the old upstream version, so a
    # dpkg-owned binary is judged on its package first.
    if [[ -n "$bin" ]] && have dpkg-query; then
        pkg="$(dpkg -S "$(readlink -f "$bin")" 2>/dev/null | head -1 | cut -d: -f1 || true)"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            local f
            for f in $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            # Debian splits the runtime into nodejs + libnodeNNN; either changelog counts
            shopt -s nullglob
            for cl in "/usr/share/doc/${pkg}/changelog.Debian.gz" /usr/share/doc/libnode[0-9]*/changelog.Debian.gz; do
                [[ -f "$cl" ]] || continue
                # Only trust a changelog whose newest entry is the installed build
                [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]] || continue
                if zgrep -q "$KEY_CVE" "$cl"; then shopt -u nullglob; echo "0|${pkg} ${full}: changelog lists ${KEY_CVE}"; return; fi
            done
            shopt -u nullglob
        fi
    fi
    if [[ -n "$fixed" ]]; then
        if ver_ge "$v" "$fixed"; then echo "0|v${v} >= ${fixed}"; else echo "1|v${v} < ${fixed}"; fi
        return
    fi
    if [[ -n "${pkg:-}" ]]; then
        echo "1|v${v} (${pkg} ${full}): Node ${major} is end-of-life upstream and the package changelog doesn't list ${KEY_CVE}"
    else
        echo "1|v${v}: Node ${major} is end-of-life upstream; no fix will ship. Move to 22.23.4, 24.22.1 or 26.12.1"
    fi
}

state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}NOT fixed${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- discovery --------------------------------------------------------
# Installed runtimes: PATH, the usual system prefixes, and per-user version
# managers. Prints one resolved path per line.
find_runtimes() {
    local c
    {
        command -v -a node nodejs 2>/dev/null || true
        shopt -s nullglob
        for c in /usr/bin/node /usr/bin/nodejs /usr/local/bin/node /opt/*/bin/node /opt/*/*/bin/node \
                 /usr/local/n/versions/node/*/bin/node /snap/node/current/bin/node \
                 /root/.nvm/versions/node/*/bin/node /home/*/.nvm/versions/node/*/bin/node \
                 /root/.volta/tools/image/node/*/bin/node /home/*/.volta/tools/image/node/*/bin/node \
                 /root/.local/share/fnm/node-versions/*/installation/bin/node \
                 /home/*/.local/share/fnm/node-versions/*/installation/bin/node \
                 /home/*/.fnm/node-versions/*/installation/bin/node \
                 /root/.asdf/installs/nodejs/*/bin/node /home/*/.asdf/installs/nodejs/*/bin/node \
                 /home/*/.local/share/mise/installs/node/*/bin/node; do
            echo "$c"
        done
        shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u
}

# Running Node processes: "pid|exe|user|unit|guarded|snapshot"
find_procs() {
    local p pid exe base user unit guarded snap env cmd
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        exe="$(readlink "$p/exe" 2>/dev/null)" || continue
        base="$(basename "${exe% (deleted)}")"
        [[ "$base" == node* ]] || continue
        # node, nodejs, node22... or a renamed copy that carries a Node version
        # string (node_exporter and friends don't)
        [[ "$base" =~ ^(node|nodejs)[0-9.]*$ ]] || [[ -n "$(static_version "$p/exe")" ]] || continue
        user="$(stat -c %U "$p" 2>/dev/null || echo '?')"
        unit="$(grep -oE '[^/]+\.(service|scope)' "$p/cgroup" 2>/dev/null | tail -1 || true)"
        env="$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^NODE_OPTIONS=' || true)"
        cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
        guarded=0; [[ "$env$cmd" == *brotli-guard* ]] && guarded=1
        snap=0;    [[ "$cmd" == *--snapshot-blob* || "$cmd" == *--build-snapshot* ]] && snap=1
        echo "${pid}|${exe}|${user}|${unit}|${guarded}|${snap}"
    done
}

# Container images that declare NODE_VERSION (the official node images and
# most images built on them). Read from image metadata; nothing is started.
find_images() {
    local rt img env
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' >/dev/null 2>&1 || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u | while read -r img; do
            env="$("$rt" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$img" 2>/dev/null \
                   | sed -n 's/^NODE_VERSION=//p' | head -1)"
            [[ -n "$env" ]] && echo "${rt}|${img}|v${env#v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc_all=0 bin v ps how n
    step "Node.js runtimes on disk"
    is_root || caution "not root: other users' version managers and processes may be hidden"
    local found=0 disk_bad=0
    while read -r bin; do
        [[ -n "$bin" ]] || continue
        found=1
        v="$(node_version "$bin")"
        IFS='|' read -r ps how <<<"$(patch_state "$v" "$bin")"
        if [[ -z "$v" ]]; then
            caution "${bin}: version unreadable (not executed: owner $(stat -Lc %U "$bin"))"
            [[ $rc_all -eq 0 ]] && rc_all=2
            continue
        fi
        if [[ $ps -eq 0 ]]; then ok "${bin}  ${v}  $(state_word 0)  (${how})"
        else bad "${bin}  ${v}  $(state_word "$ps")  (${how})"; disk_bad=$((disk_bad + 1)); fi
    done < <(find_runtimes)
    [[ $found -eq 1 ]] || inf "no Node.js runtime found in the usual places"

    step "Running Node.js processes"
    local pid exe user unit guarded snap vers stale running=0 exposed=0
    while IFS='|' read -r pid exe user unit guarded snap; do
        [[ -n "$pid" ]] || continue
        running=1
        vers="$(node_version "/proc/${pid}/exe")"
        IFS='|' read -r ps how <<<"$(patch_state "$vers" "${exe% (deleted)}")"
        stale=""; [[ "$exe" == *"(deleted)" ]] && stale=" binary replaced on disk since start"
        local where="pid ${pid} (${user}${unit:+, ${unit}})"
        if [[ $ps -eq 0 && -z "$stale" ]]; then
            ok "${where}  ${vers}  $(state_word 0)"
        elif [[ $ps -eq 0 ]]; then
            caution "${where}  ${vers}  fixed, but${stale}: restart it to run the new code"
        elif [[ $guarded -eq 1 ]]; then
            caution "${where}  ${vers:-?}  $(state_word "$ps"), brotli-guard loaded (interim)${stale:+;${stale}}"
        else
            bad "${where}  ${vers:-?}  $(state_word "$ps"), no guard${stale:+,${stale}}"
            exposed=1
            if [[ "$unit" == *.service ]]; then
                echo "      fix: upgrade Node, then restart ${unit}. Interim: sudo ${SELF} guard --unit ${unit}"
            else
                echo "      fix: upgrade Node and restart it. Interim: start it with --require=${GUARD_DST}"
            fi
        fi
        [[ $snap -eq 1 ]] && caution "    pid ${pid} uses a startup snapshot: rebuild it with the fixed Node (CVE-2026-106074)"
    done < <(find_procs)
    [[ $running -eq 1 ]] || inf "no running Node.js processes"
    [[ $exposed -eq 1 ]] && rc_all=1

    step "Container images"
    local rt img iv any=0
    if ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        while IFS='|' read -r rt img iv; do
            [[ -n "$img" ]] || continue
            any=1
            IFS='|' read -r ps how <<<"$(patch_state "$iv")"
            if [[ $ps -eq 0 ]]; then ok "${rt} ${img}  ${iv}  $(state_word 0)"
            else bad "${rt} ${img}  ${iv}  $(state_word "$ps"): rebuild on a fixed base image (node:22.23.4 / 24.22.1 / 26.12.1 or later)"; fi
        done < <(find_images)
        [[ $any -eq 1 ]] || inf "no images declaring NODE_VERSION (or no permission to list images). Images that install Node another way aren't detected"
    fi

    step "Other places Node hides"
    inf "Electron apps bundle their own Node: update them through their vendor"
    inf "Single executable applications and startup snapshots: run '${SELF} scan'"
    inf "The fixed releases also update Node's bundled CA store (eMudhra): see pki/emudhra-mitigate.sh"

    step "Verdict"
    n=${#CVES[@]}
    case $rc_all in
        0) info "Nothing running is exposed to the ${n} CVEs fixed on 21 Oct 2026"
           [[ $disk_bad -eq 0 ]] || warn "...but ${disk_bad} installed runtime(s) are unfixed. Upgrade them before something starts them" ;;
        1) warn "Unfixed Node is running without a guard. Upgrade first; guard what you can't upgrade today" ;;
        *) warn "Some versions couldn't be read; rerun as root" ;;
    esac
    return "$rc_all"
}

# ---------- scan -------------------------------------------------------------
existing_scan_paths() { local p; for p in $SCAN_PATHS; do [[ -d "$p" ]] && echo "$p"; done; }

cmd_scan() {
    local findings=0
    mapfile -t roots < <(existing_scan_paths)
    [[ ${#roots[@]} -gt 0 ]] || { warn "None of SCAN_PATHS exist: $SCAN_PATHS"; return 0; }

    step "Code that decodes Brotli (CVE-2026-111497 reachability)"
    echo "  Every fetch() on an unfixed runtime is reachable; this finds the other paths."
    local hits
    hits="$(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" -type f \
              \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' -o -name '*.ts' \) \
              ! -name '*.d.ts' ! -path '*/.git/*' -size -5M -print0 2>/dev/null \
            | xargs -0 -r grep -lE '\b(createBrotliDecompress|brotliDecompress(Sync)?|BrotliDecompress)\b' 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "no direct use of the Brotli decoder found under ${roots[*]}"
    else
        findings=1
        # Group by application: own code vs. the dependency that does it
        awk '
            {
                f = $0
                if (match(f, /\/node_modules\//)) {
                    n = split(f, a, "/node_modules/")
                    app = a[1]; rest = a[n]
                    split(rest, b, "/")
                    pkg = (substr(b[1],1,1) == "@") ? b[1] "/" b[2] : b[1]
                    if (!seen[app SUBSEP pkg]++) deps[app] = deps[app] (deps[app] ? ", " : "") pkg
                    apps[app] = 1
                } else {
                    own[f] = 1
                }
            }
            END {
                for (ap in apps) printf "  ! app %s\n      dependencies that decode Brotli: %s\n", ap, deps[ap]
                for (f in own) printf "  ! own code: %s\n", f
            }' <<<"$hits"
        echo "      These decode attacker-controlled bytes if they handle request bodies or fetched"
        echo "      responses. brotli-guard makes them fail safely until Node is upgraded."
    fi

    step "Single executable applications (CVE-2026-106074)"
    local sea seav ps how any=0
    while IFS= read -r -d '' sea; do
        grep -qaF "$SEA_FUSE" "$sea" 2>/dev/null || continue
        any=1; findings=1
        seav="$(static_version "$sea")"
        IFS='|' read -r ps how <<<"$(patch_state "$seav")"
        caution "${sea}  built on ${seav:-unknown Node}  $(state_word "$ps")"
        echo "      Rebuild it with a fixed Node. Its crypto.randomUUID()/randomInt() output may repeat"
        echo "      across runs: rotate any IDs or tokens it generated if they need to be unguessable."
    done < <(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" -type f -perm -u+x -size +20M -print0 2>/dev/null)
    [[ $any -eq 1 ]] || ok "no SEA binaries found"

    step "Startup snapshots (CVE-2026-106074)"
    local snaps=""
    if [[ -d /etc/systemd/system ]]; then
        snaps="$(grep -rlE -- '--(snapshot-blob|build-snapshot)' /etc/systemd/system /lib/systemd/system 2>/dev/null || true)"
    fi
    local pid exe user unit guarded snap
    while IFS='|' read -r pid exe user unit guarded snap; do
        [[ "$snap" == 1 ]] && snaps+=$'\n'"pid ${pid} (${unit})"
    done < <(find_procs)
    snaps="$(sed '/^$/d' <<<"$snaps")"
    if [[ -n "$snaps" ]]; then
        findings=1
        while read -r s; do caution "$s uses --snapshot-blob/--build-snapshot: rebuild the blob with a fixed Node"; done <<<"$snaps"
    else
        ok "no startup snapshots in units or running processes"
    fi
    return "$findings"
}

# ---------- guard ------------------------------------------------------------
need_root_systemd() {
    is_root || die "$CMD needs root"
    have_systemd || die "$CMD needs systemd. Without it, add --require=${GUARD_DST} to NODE_OPTIONS in the service's own startup script"
}

unit_name() { [[ "$1" == *.* ]] && echo "$1" || echo "$1.service"; }
dropin_path() { echo "/etc/systemd/system/$1.d/${DROPIN_NAME}"; }
main_pid() { systemctl show -p MainPID --value "$1" 2>/dev/null || echo 0; }

# systemd's Environment= as one value per line, quotes resolved
unit_env() {
    systemctl show -p Environment --value "$1" 2>/dev/null | xargs -r -n1 printf '%s\n' 2>/dev/null || true
}

# Escape a value for Environment="..." in a unit file
unit_quote() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//%/%%}"; printf '%s' "$s"; }

unit_node_bin() {   # best guess at the node binary the unit runs
    local pid exe c
    pid="$(main_pid "$1")"
    if [[ "$pid" != 0 ]]; then
        exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "$(basename "${exe% (deleted)}")" =~ ^node ]] && { echo "${exe% (deleted)}"; return; }
        # a wrapper (npm, pm2, sh): look at its children
        for c in $(pgrep -P "$pid" 2>/dev/null); do
            exe="$(readlink "/proc/${c}/exe" 2>/dev/null || true)"
            [[ "$(basename "${exe% (deleted)}")" =~ ^node ]] && { echo "${exe% (deleted)}"; return; }
        done
    fi
    exe="$(systemctl show -p ExecStart --value "$1" 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)"
    [[ "$(basename "$exe")" =~ ^node ]] && { echo "$exe"; return; }
    command -v node 2>/dev/null || true
}

guard_live() {   # <unit> <since> : guard announced itself, or a process carries it
    local u="$1" since="$2" pid c
    journalctl -u "$u" --since "$since" --no-pager -o cat 2>/dev/null | grep -qF '[brotli-guard] active' && return 0
    journalctl -u "$u" --since "$since" --no-pager -o cat 2>/dev/null | grep -qF '[brotli-guard] Node' && return 0
    pid="$(main_pid "$u")"
    for c in "$pid" $(pgrep -P "$pid" 2>/dev/null); do
        [[ "$c" != 0 ]] || continue
        tr '\0' '\n' < "/proc/${c}/environ" 2>/dev/null | grep -qE '^NODE_OPTIONS=.*brotli-guard' && return 0
    done
    return 1
}

wait_active() {   # <unit> : active and not restart-looping for ~5s
    local u="$1" i n0 n1
    n0="$(systemctl show -p NRestarts --value "$u" 2>/dev/null || echo 0)"
    for i in $(seq 1 20); do
        systemctl is-active --quiet "$u" && break
        sleep 1
        [[ $i -eq 20 ]] && return 1
    done
    sleep 5
    n1="$(systemctl show -p NRestarts --value "$u" 2>/dev/null || echo 0)"
    systemctl is-active --quiet "$u" && [[ "${n1:-0}" == "${n0:-0}" ]]
}

install_guard_file() {
    [[ -f "$GUARD_SRC" ]] || die "brotli-guard.cjs not found next to this script (${GUARD_SRC}). Download it from the same place."
    if [[ -f "$GUARD_DST" ]] && cmp -s "$GUARD_SRC" "$GUARD_DST"; then
        info "Guard already installed: $GUARD_DST"
    else
        install -d -m 0755 -o root -g root "$(dirname "$GUARD_DST")"
        install -m 0644 -o root -g root "$GUARD_SRC" "$GUARD_DST"
        info "Installed $GUARD_DST ($(sha256sum "$GUARD_DST" | cut -c1-16)...)"
    fi
}

guard_one() {
    local u="$1" dp node_bin v ps how uu existing="" e f since
    systemctl cat "$u" >/dev/null 2>&1 || die "unit $u not found"
    dp="$(dropin_path "$u")"
    step "guard $u"

    node_bin="$(unit_node_bin "$u")"
    v=""; [[ -z "$node_bin" ]] || v="$(node_version "$node_bin")"
    IFS='|' read -r ps how <<<"$(patch_state "$v" "$node_bin")"
    info "Runtime: ${node_bin:-unknown} ${v:-?} ($(state_word "$ps"): ${how})"
    if [[ $ps -eq 0 && -z "$FORCE" ]]; then
        info "Already fixed - no guard needed. Restart $u if it predates the upgrade. (--force to guard anyway)"
        return 0
    fi

    # EnvironmentFile= wins over Environment=, so a NODE_OPTIONS there would
    # silently discard ours. Don't pretend to have guarded it.
    for f in $(systemctl show -p EnvironmentFiles --value "$u" 2>/dev/null | grep -oE '^/[^ ]+|[[:space:]]/[^ ]+' | tr -d ' '); do
        if [[ -f "$f" ]] && grep -qE '^[[:space:]]*(export[[:space:]]+)?NODE_OPTIONS=' "$f"; then
            die "$f (an EnvironmentFile of $u) sets NODE_OPTIONS, which would override this drop-in. Add --require=${GUARD_DST} to NODE_OPTIONS in that file and restart $u yourself."
        fi
    done

    install_guard_file

    # Self-test on the unit's own runtime, as the unit's user, before touching it
    uu="$(systemctl show -p User --value "$u" 2>/dev/null)"; uu="${uu:-root}"
    if [[ -n "$node_bin" && -x "$node_bin" ]] && id "$uu" >/dev/null 2>&1; then
        if [[ "$uu" == root ]] && ! safe_to_exec "$node_bin"; then
            caution "Not running the self-test: $node_bin isn't root-owned, and $u runs as root (that is worth fixing on its own)"
        else
            local out; out="$(mktemp)"
            if timeout 30 runuser -u "$uu" -- env -u NODE_OPTIONS "$node_bin" "$GUARD_DST" --self-test >"$out" 2>&1; then
                info "Guard self-test passed on ${v} as ${uu}"
                rm -f "$out"
            else
                sed 's/^/      /' "$out"; rm -f "$out"
                [[ -n "$FORCE" ]] || die "Guard self-test failed on $node_bin. Not installing (--force to install anyway)"
                warn "--force: installing despite the failed self-test"
            fi
        fi
    fi

    while IFS= read -r e; do
        [[ "$e" == NODE_OPTIONS=* ]] && existing="${e#NODE_OPTIONS=}"
    done < <(unit_env "$u")
    if [[ -f "$dp" ]] && grep -qF "$MARKER" "$dp"; then
        # our own earlier drop-in: rebuild from what's underneath it
        existing="${existing//--require=${GUARD_DST}/}"
        existing="$(sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' <<<"$existing")"
    elif [[ "$existing" == *brotli-guard* ]]; then
        info "$u already loads a brotli-guard through NODE_OPTIONS; leaving it"
        return 0
    fi
    local want="${existing:+${existing} }--require=${GUARD_DST}"

    mkdir -p "$(dirname "$dp")"
    local prev=""; [[ -f "$dp" ]] && prev="$(cat "$dp")"
    printf '%s\n' "$MARKER" \
        "# Interim guard for ${KEY_CVE}, written by ${SCRIPT_NAME} ${SCRIPT_VERSION}." \
        "# Remove with: ${SELF} unguard --unit ${u}" \
        "[Service]" \
        "Environment=\"NODE_OPTIONS=$(unit_quote "$want")\"" > "$dp"
    systemctl daemon-reload
    info "Wrote $dp"

    # Don't start a service the admin had stopped
    if ! systemctl is-active --quiet "$u"; then
        info "$u isn't running; the guard loads the next time it starts"
        return 0
    fi
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    systemctl restart "$u" || true
    if ! wait_active "$u"; then
        warn "$u didn't come up cleanly with the guard - rolling back"
        journalctl -u "$u" --since "$since" --no-pager -n 15 2>/dev/null | sed 's/^/      /' || true
        if [[ -n "$prev" ]]; then printf '%s\n' "$prev" > "$dp"; else rm -f "$dp"; fi
        systemctl daemon-reload; systemctl restart "$u" || true
        if wait_active "$u"; then die "Rolled back; $u is running without the guard"; fi
        die "Rolled back, but $u still isn't healthy: journalctl -xeu $u"
    fi
    if guard_live "$u" "$since"; then
        info "$u is running with brotli-guard"
    else
        warn "$u is up, but the guard didn't announce itself and no process carries it."
        echo "      The service may reset NODE_OPTIONS (a wrapper script, pm2, docker). Check: journalctl -u $u | grep brotli-guard"
    fi
    echo "  Watch for blocked callers: ${SELF} status   (each one names the code that tried to decode Brotli)"
}

unguard_one() {
    local u="$1" dp since
    dp="$(dropin_path "$u")"
    step "unguard $u"
    if [[ ! -f "$dp" ]]; then info "No guard drop-in for $u"; return 0; fi
    grep -qF "$MARKER" "$dp" || die "$dp wasn't written by this script; leaving it"
    rm -f "$dp"; rmdir --ignore-fail-on-non-empty "$(dirname "$dp")" 2>/dev/null || true
    systemctl daemon-reload
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    systemctl restart "$u" || true
    wait_active "$u" || die "$u isn't healthy after removing the guard: journalctl -xeu $u"
    if guard_live "$u" "$since"; then warn "$u still loads a guard (NODE_OPTIONS set elsewhere)"
    else info "Guard removed from $u"; fi
    local others; others="$(find /etc/systemd/system -name "$DROPIN_NAME" 2>/dev/null | head -1)"
    [[ -n "$others" ]] || inf "No other unit uses $GUARD_DST; you can delete it"
}

cmd_guard()   { need_root_systemd; [[ ${#UNITS[@]} -gt 0 ]] || die "guard needs --unit NAME"; local u; for u in "${UNITS[@]}"; do guard_one "$(unit_name "$u")"; done; }
cmd_unguard() { need_root_systemd; [[ ${#UNITS[@]} -gt 0 ]] || die "unguard needs --unit NAME"; local u; for u in "${UNITS[@]}"; do unguard_one "$(unit_name "$u")"; done; }

# ---------- status -----------------------------------------------------------
cmd_status() {
    step "Guarded units"
    local dp u node_bin v ps how n any=0
    shopt -s nullglob
    for dp in /etc/systemd/system/*.d/"$DROPIN_NAME"; do
        any=1
        u="$(basename "$(dirname "$dp")")"; u="${u%.d}"
        node_bin="$(unit_node_bin "$u")"; v=""; [[ -z "$node_bin" ]] || v="$(node_version "$node_bin")"
        IFS='|' read -r ps how <<<"$(patch_state "$v" "$node_bin")"
        n="$(journalctl -u "$u" --since "-7d" --no-pager -o cat 2>/dev/null | grep -cF '[brotli-guard] blocked' || true)"
        echo -e "  ${u}: $(systemctl is-active "$u" 2>/dev/null || true), Node ${v:-?} $(state_word "$ps"), ${n:-0} blocked call site(s) in 7 days"
        journalctl -u "$u" --since "-7d" --no-pager -o cat 2>/dev/null | grep -F '[brotli-guard] blocked' | sort | uniq -c | sort -rn | head -5 | sed 's/^/      /' || true
        [[ $ps -eq 0 ]] && echo "      runtime is fixed: ${SELF} unguard --unit ${u}"
    done
    shopt -u nullglob
    [[ $any -eq 1 ]] || inf "no units guarded by this script"
    if [[ -f "$GUARD_DST" ]]; then
        inf "guard file: $GUARD_DST v$(grep -oE "GUARD_VERSION = '[^']+'" "$GUARD_DST" | cut -d"'" -f2)"
        [[ -f "$GUARD_SRC" ]] && ! cmp -s "$GUARD_SRC" "$GUARD_DST" && caution "differs from ${GUARD_SRC}; rerun guard to update it"
    fi
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for Node.js crashes and guard events since ${HUNT_SINCE}"
    local tmp; tmp="$(mktemp)"; trap 'rm -f "$tmp"' RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >>"$tmp" || true; fi
    local f
    shopt -s nullglob
    for f in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /root/.pm2/logs/*.log /home/*/.pm2/logs/*.log; do
        [[ -r "$f" ]] && cat "$f" >>"$tmp"
    done
    shopt -u nullglob
    [[ -s "$tmp" ]] || { warn "No readable journal or logs (try as root)"; return 0; }

    local found=0 name re c
    local -a checks=(
        "kernel: node segfault/GPF|(node|nodejs|MainThread)\[[0-9]+\]: (segfault at|general protection|trap invalid opcode)"
        "V8 fatal error|FATAL ERROR: |Fatal error in .*v8|Check failed: "
        "Brotli decoder in a crash or backtrace|BrotliDecoder(DecompressStream|Decompress|State)|brotli/c/dec/"
        "unit killed by SIGSEGV/SIGABRT (any service; check which run Node)|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
        "brotli-guard blocked a decode|\[brotli-guard\] blocked|ERR_BROTLI_GUARD_BLOCKED"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        local n; n="$(grep -cE "$re" "$tmp" || true)"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            grep -E "$re" "$tmp" | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit is a lead, not proof. A crash in the Brotli decoder on an unfixed runtime is"
    echo "  worth treating as an incident: check what the process could reach (env secrets, DB"
    echo "  credentials, tokens) and rotate them. Guard blocks show what tried to decode Brotli;"
    echo "  from an attacker-reachable route, that's the request to look at."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
UNITS=(); FORCE=""
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; --*) set -- "$CMD" "$@"; CMD=check ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)   UNITS+=("${2:?--unit needs a unit name}"); shift 2 ;;
        --unit=*) UNITS+=("${1#*=}"); shift ;;
        --force)  FORCE=1; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}), brotli-guard $(grep -oE "GUARD_VERSION = '[^']+'" "$GUARD_SRC" 2>/dev/null | cut -d"'" -f2 || echo '?') - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
case "$CMD" in
    check|scan|guard|unguard|status|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|scan|guard|unguard|status|hunt)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
