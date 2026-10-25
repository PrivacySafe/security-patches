#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Brotli decoder out-of-bounds write, October 2026: read-only checker  (v1)
# CVE-2026-111497
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Brotli decoder (Google's libbrotli / libbrotlidec) does not propagate an
# invalid block-switch when a stream declares only one block type, so a crafted
# Brotli stream writes past the decoder's output buffer: a crash, a memory
# disclosure, or remote code execution. The flaw is in the upstream C library,
# and the same CVE has advisories across everything that bundles it: Node.js,
# Bun, Envoy, Istio, the Python brotli and brotlicffi bindings, and OS
# packages. Some people are calling the broadened picture "HTTP2Shell", since
# any HTTP path that decodes untrusted Brotli can be a route to it.
#
# Fixed upstream in Brotli 1.0.10, 1.1.1 and 1.2.1. Distributions backport the
# fix into their own libbrotli builds, sometimes under an older version number.
#
# This is read-only: it finds what needs updating and judges each against the
# fixes. It does NOT change anything. The fix is to update the library or the
# runtime. There is no host-wide switch to turn Brotli off; where no fix is
# available yet, disabling Brotli decoding is application-specific (reject
# Content-Encoding: br before it is decompressed, turn off automatic Brotli in
# HTTP clients, disable the Brotli decompressor filter in Envoy/Istio). See
# the repository README and https://patchtheplanet.org/brotli
#
# For the Node.js interim guard (loading a require-hook that refuses to decode),
# use node/node-oct2026-mitigate.sh and node/brotli-guard.cjs instead. This
# script only reports Node's version.
#
# Usage:
#   ./brotli-oct2026-check.sh [command]
#
#   check (default)  every libbrotli on the host, the runtimes that bundle
#                    their own Brotli (Node.js, Bun, Python's brotli and
#                    brotlicffi, Envoy, Istio, cdxgen), and libbrotli inside
#                    running containers, with whether each carries the fix.
#                    Root optional. Exit 0 =
#                    nothing exposed, 1 = a vulnerable Brotli is present, 2 =
#                    something couldn't be read.
#   hunt             read-only: the journal and logs for process crashes that
#                    look like a Brotli decoder overflow (segfaults with
#                    brotli/BrotliDecoder frames, heap corruption aborts).
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   FIXED_BUILDS="1.0.9-2+deb12u2 1.1.0-2ubuntu0.1"
#                                     extra distro libbrotli builds known to
#                                     carry the fix, space-separated full
#                                     versions. Checked alongside a built-in
#                                     list of known builds (Debian 13's
#                                     1.1.0-2+deb13u1), which a value here does
#                                     not replace.
#   BRANCH_FIXED="1.0:1.0.10 1.1:1.1.1 1.2:1.2.1"
#                                     first fixed upstream release per branch
#   SCAN_CONTAINERS=1                 1 = read libbrotli inside running
#                                     containers (default 1; 0 to skip)
#   HUNT_SINCE="2026-10-01"           how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVE="CVE-2026-111497"
# First fixed upstream release for each minor branch.
declare -A BRANCH_FIXED_DEFAULT=([1.0]=1.0.10 [1.1]=1.1.1 [1.2]=1.2.1)
FIXED_BUILDS="${FIXED_BUILDS:-}"
# Distro builds known to carry the fix under an older-looking upstream number.
# Checked alongside any user-supplied FIXED_BUILDS, so a user override does not
# drop these. Debian 13 (trixie): brotli 1.1.0-2+deb13u1, 23 Oct 2026.
FIXED_BUILDS_KNOWN="1.1.0-2+deb13u1"
CHANGELOG_MARKERS=(CVE-2026-111497)
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
# Fixed runtime releases (first fixed per line), for things that bundle Brotli.
NODE_FIXED="${NODE_FIXED:-22.23.4 24.22.1 26.12.1}"
BUN_FIXED="${BUN_FIXED:-1.4.4}"
PYBROTLICFFI_FIXED="${PYBROTLICFFI_FIXED:-1.2.1.0}"
ENVOY_FIXED="${ENVOY_FIXED:-1.40.0 1.39.3 1.38.6 1.37.8 1.36.12}"
ISTIO_FIXED="${ISTIO_FIXED:-1.29.9 1.30.6 1.31.2}"
CDXGEN_FIXED="${CDXGEN_FIXED:-13.5.0 12.8.9}"
SCRIPT_NAME="brotli-oct2026-check.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-10-24"
SELF="$0"
UPSTREAM="https://github.com/google/brotli"

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
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }
branch_fixed_for() { local n="${BRANCH_FIXED:-}"; if [[ -n "$n" ]]; then for p in $n; do [[ "${p%%:*}" == "$1" ]] && { echo "${p#*:}"; return; }; done; fi; echo "${BRANCH_FIXED_DEFAULT[$1]:-}"; }

# ---------- libbrotli discovery and versioning -------------------------------
find_libs() {   # <soname-stem> -> resolved paths
    local stem="$1" c
    {
        shopt -s nullglob
        for c in /usr/lib/*/"${stem}".so* /usr/lib/"${stem}".so* /usr/lib64/"${stem}".so* \
                 /usr/local/lib/*/"${stem}".so* /usr/local/lib/"${stem}".so* /lib/*/"${stem}".so* \
                 /opt/*/lib/"${stem}".so* /opt/*/*/lib/"${stem}".so*; do
            echo "$c"
        done
        shopt -u nullglob
        have ldconfig && ldconfig -p 2>/dev/null | grep -oE "/[^ ]*${stem}\.so[^ ]*" || true
    } | while read -r c; do [[ -e "$c" ]] && readlink -f "$c"; done | sort -u
}

# The soname carries the library version (libbrotlidec.so.1.0.9 is 1.0.9). A
# shared object also holds unrelated X.Y.Z strings, so the filename is the
# reliable source. Reading it runs nothing.
lib_version() {   # <path> -> X.Y.Z or empty
    local real base v
    real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
    base="$(basename "$real")"
    v="$(grep -oE '\.so\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$base" | sed 's/^\.so\.//' || true)"
    [[ -n "$v" ]] || v="$(grep -aoE '^[0-9]+\.[0-9]+\.[0-9]+$' "$real" 2>/dev/null | head -1 || true)"
    echo "$v"
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# Judge an upstream X.Y.Z against the per-branch fix. "<rc>|<why>"
upstream_state() {   # <X.Y.Z>
    local v="$1" mm fixed
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    mm="${v%.*}"; fixed="$(branch_fixed_for "$mm")"
    if [[ -n "$fixed" ]]; then
        if ver_ge "$v" "$fixed"; then echo "0|${v} >= ${fixed}"; else echo "1|${v} < ${fixed} (branch ${mm})"; fi
        return
    fi
    # A branch newer than 1.2 shipped after the fixes; older than 1.0 predates them.
    if ver_ge "$v" "1.3.0"; then echo "0|${v} is newer than the fixed releases"
    else echo "1|${v}: branch ${mm} has no fixed release in this list; treat as vulnerable and move to 1.0.10, 1.1.1 or 1.2.1"; fi
}

# A distro package can carry the fix under an older upstream number, so judge a
# dpkg-owned library on its package build first, then on the branch fix.
lib_state() {   # <X.Y.Z> <path>
    local v="$1" p="${2:-}" pkg full f m cl
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
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
            local rc why; IFS='|' read -r rc why <<<"$(upstream_state "$v")"
            if [[ $rc -eq 0 ]]; then
                # Upstream number is already fixed; a distro at this number is fixed too.
                echo "0|${pkg} ${full} (upstream ${why})"
            else
                echo "1|${pkg} ${full} (upstream ${v} is vulnerable, changelog doesn't name ${CVE}). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS"
            fi
            return
        fi
    fi
    upstream_state "$v"   # self-built or bundled: branch fix only
}

# ---------- runtimes that bundle their own Brotli ----------------------------
# Compare "X.Y.Z" against a space list of first-fixed-per-line releases. The
# release model differs: Node.js and Bun cut a line per MAJOR, Envoy and Istio
# per MAJOR.MINOR. Pass "major" or "minor" so the right fix is matched.
line_key() { [[ "$2" == major ]] && echo "${1%%.*}" || echo "${1%.*}"; }
line_state() {   # <ver> "<fixed...>" [major|minor]
    local v="$1" list="$2" gran="${3:-minor}" key f
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    key="$(line_key "$v" "$gran")"
    for f in $list; do
        if [[ "$(line_key "$f" "$gran")" == "$key" ]]; then
            if ver_ge "$v" "$f"; then echo "0|${v} >= ${f}"; else echo "1|${v} < ${f}"; fi
            return
        fi
    done
    # Newer than every listed fix is fixed; otherwise no fix for this line.
    local newest; newest="$(printf '%s\n' $list | sort -V | tail -1)"
    if ver_ge "$v" "$newest"; then echo "0|${v} is newer than ${newest}"
    else echo "1|${v}: line ${key} has no fixed release in this list; move to a fixed line"; fi
}

runtime_report() {   # <label> <version> "<fixed list>" <major|minor> <extra note>
    local label="$1" v="$2" list="$3" gran="${4:-minor}" note="${5:-}" rc why
    [[ -n "$v" ]] || { inf "${label}: not found"; return; }
    IFS='|' read -r rc why <<<"$(line_state "$v" "$list" "$gran")"
    case $rc in
        0) ok "${label} ${v}  $(state_word 0)  (${why})${note:+  ${note}}" ;;
        1) bad "${label} ${v}  $(state_word 1)  (${why})${note:+  ${note}}"; return 1 ;;
        *) caution "${label} ${v}  $(state_word 2)  (${why})" ;;
    esac
    return 0
}

node_versions() {   # prints each node binary's version, one per line
    local c
    { command -v -a node 2>/dev/null || true
      shopt -s nullglob
      for c in /usr/bin/node /usr/local/bin/node /opt/*/bin/node \
               /root/.nvm/versions/node/*/bin/node /home/*/.nvm/versions/node/*/bin/node; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u | while read -r b; do
        [[ -n "$b" ]] || continue
        v="$("$b" --version 2>/dev/null | tr -d 'v' || true)"
        [[ -n "$v" ]] && echo "$v"
    done | sort -uV
}

py_brotli_modules() {   # prints "<module>|<version>" for each importable Python Brotli binding
    have python3 || return 0
    python3 - <<'PY' 2>/dev/null || true
import sys
try:
    from importlib.metadata import version as dist_version
except Exception:
    dist_version = None
for mod, dist in (("brotli", "Brotli"), ("brotlicffi", "brotlicffi")):
    try:
        m = __import__(mod)
    except Exception:
        continue
    # Only the real Brotli codec bindings expose decompress(); skip an
    # unrelated or namespace module that merely shares the name.
    if not hasattr(m, "decompress"):
        continue
    v = getattr(m, "__version__", "") or getattr(m, "version", "")
    if not v and dist_version:
        try:
            v = dist_version(dist)
        except Exception:
            v = ""
    sys.stdout.write("%s|%s\n" % (mod, str(v)))
PY
}

# ---------- containers -------------------------------------------------------
container_libs() {   # "runtime|ref|version"
    [[ "$SCAN_CONTAINERS" == 1 ]] || return 0
    local rt id name v
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'for p in /usr/lib/*/libbrotlidec.so* /usr/lib/libbrotlidec.so* /usr/local/lib/libbrotlidec.so*; do [ -e "$p" ] && { echo "${p##*/libbrotlidec.so.}"; break; }; done' 2>/dev/null | head -1 || true)"
            [[ -n "$v" && "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${rt}|${name:-$id}|${v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 p v ps how any

    step "libbrotli on the host"
    any=0
    local stem
    for stem in libbrotlidec libbrotlienc libbrotlicommon; do
        while read -r p; do
            [[ -n "$p" ]] || continue
            any=1
            v="$(lib_version "$p")"
            IFS='|' read -r ps how <<<"$(lib_state "$v" "$p")"
            case $ps in
                0) ok "${p}  ${v:-?}  $(state_word 0)  (${how})" ;;
                1) bad "${p}  ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
                *) caution "${p}  ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(find_libs "$stem")
    done
    if [[ $any -eq 0 ]]; then
        inf "no libbrotli found on the host (it may live only inside a runtime or container, checked below)"
    else
        inf "the decoder (libbrotlidec) is the vulnerable path; libbrotlienc and libbrotlicommon ship from the same package and are shown for completeness"
    fi

    step "Runtimes that bundle their own Brotli"
    local nv had_node=0
    while read -r nv; do
        [[ -n "$nv" ]] || continue
        had_node=1
        runtime_report "Node.js" "$nv" "$NODE_FIXED" major "interim guard available: see node/node-oct2026-mitigate.sh in this repo" || exposed=1
    done < <(node_versions)
    [[ $had_node -eq 1 ]] || inf "Node.js: not found"

    if have bun; then runtime_report "Bun" "$(bun --version 2>/dev/null | head -1 || true)" "$BUN_FIXED" major || exposed=1; else inf "Bun: not found"; fi

    # Python Brotli bindings. The "brotli" package is versioned per upstream
    # branch; "brotlicffi" carries its own four-part version, fixed at 1.2.1.0.
    # An HTTP client such as urllib3 or requests decodes Content-Encoding: br
    # on its own whenever either binding is importable, so a present binding is
    # a live decode path, not dormant code.
    local dist pv pstate pwhy had_py=0
    while IFS='|' read -r dist pv; do
        [[ -n "$dist" ]] || continue
        had_py=1
        if [[ "$dist" == brotlicffi ]]; then
            if [[ -z "$pv" ]]; then caution "Python brotlicffi (version unreadable)  $(state_word 2)"; unknownz=1
            elif ver_ge "$pv" "$PYBROTLICFFI_FIXED"; then ok "Python brotlicffi ${pv}  $(state_word 0)  (>= ${PYBROTLICFFI_FIXED})"
            else bad "Python brotlicffi ${pv}  $(state_word 1)  (< ${PYBROTLICFFI_FIXED}); upgrade the brotlicffi wheel to ${PYBROTLICFFI_FIXED}"; exposed=1; fi
        else
            IFS='|' read -r pstate pwhy <<<"$(upstream_state "$pv")"
            case $pstate in
                0) ok "Python brotli ${pv}  $(state_word 0)  (${pwhy})" ;;
                1) bad "Python brotli ${pv}  $(state_word 1)  (${pwhy}); upgrade the brotli wheel to 1.2.1"; exposed=1 ;;
                *) caution "Python brotli ${pv}  $(state_word 2)  (${pwhy})"; unknownz=1 ;;
            esac
        fi
    done < <(py_brotli_modules)
    [[ $had_py -eq 1 ]] || inf "Python Brotli bindings (brotli, brotlicffi): not found (or not importable)"

    if have envoy; then runtime_report "Envoy" "$(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$ENVOY_FIXED" minor "disable the Brotli decompressor filter if you can't upgrade" || exposed=1; else inf "Envoy: not found"; fi
    if have istioctl; then runtime_report "Istio (istioctl)" "$(istioctl version --remote=false 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$ISTIO_FIXED" minor || exposed=1; else inf "Istio (istioctl): not found"; fi
    if have cdxgen; then runtime_report "cdxgen" "$(cdxgen --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$CDXGEN_FIXED" major "standalone binaries and images bundle Brotli; rebuild them, a version bump alone is not enough" || exposed=1; else inf "cdxgen: not found on PATH"; fi

    inf "Bun, Envoy, Istio and cdxgen bundle Brotli; upgrading the runtime is the fix. This script reads only the versions it can reach from the command line"

    step "libbrotli inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then
        inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        local rt ref cv any_c=0
        while IFS='|' read -r rt ref cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r ps how <<<"$(upstream_state "$cv")"
            case $ps in
                0) ok "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 1)  (${how}); rebuild the image, a restart won't change the library"; exposed=1 ;;
                *) caution "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_libs)
        [[ $any_c -eq 1 ]] || inf "no running container exposes a readable libbrotlidec (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable Brotli found where this could read one" ;;
        1) warn "A vulnerable Brotli is present. Update libbrotli (and the runtimes that bundle it), rebuild anything that bundles it, and restart. Upstream: ${UPSTREAM} (update your distro/package, don't vendor it). Where no fix is available yet, disable Brotli decoding of untrusted data" ;;
        *) warn "Some builds couldn't be judged. For a dpkg build, confirm against the distro advisory and add it to FIXED_BUILDS. Rerun as root to read more" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for Brotli decoder crashes since ${HUNT_SINCE}"
    local jr; jr="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$jr'" RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >"$jr" || true; fi
    local -a files=()
    [[ -s "$jr" ]] && files+=("$jr")
    local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /var/log/nginx/*.log /var/log/apache2/*.log /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "Brotli decoder frames in a crash/backtrace|(libbrotlidec|BrotliDecoder|brotli_decode|BrotliDecompress|ProcessCommands|SafeDecodeInternal)"
        "process segfault or protection fault|(segfault at|general protection|trap invalid opcode)"
        "heap corruption abort|(double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned)|corrupted size vs\. prev_size|stack smashing detected)"
        "service killed by SIGSEGV/SIGABRT/SIGBUS|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit is a lead, not proof: plenty of things segfault. A crash with Brotli decoder frames"
    echo "  on a vulnerable build, especially on a service that decompresses untrusted Brotli, is worth"
    echo "  treating as an incident: check what the process could reach (secrets, database credentials,"
    echo "  tokens) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "${CVE}; upstream: ${UPSTREAM}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
