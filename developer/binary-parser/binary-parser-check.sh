#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# binary-parser code injection, January and November 2026: read-only checker (v1)
# CVE-2026-134814, CVE-2026-1245
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# binary-parser (npm) compiles each parser definition into JavaScript with the
# Function constructor. Values from the definition were pasted into that code
# without validation, so whoever controls a parser definition can run
# JavaScript in the Node.js process when the parser is compiled:
#   CVE-2026-1245    field names and encodings, every release before 2.3.0
#   CVE-2026-134814  the length, lengthInBytes, key, tag and offset options
#                    and the namely() alias, every release before 2.3.1
# Parsing untrusted binary data with a trusted, hard-coded definition is not
# affected. Applications that build definitions from a schema, a JSON file, a
# database or a request are. The fix is binary-parser 2.3.1; there is no
# configuration switch that closes it on an older copy.
#
# Usage:
#   ./binary-parser-check.sh [command] [arguments]
#
#   check (default)  find binary-parser in package.json files, lockfiles,
#                    installed copies (nested node_modules and Debian or
#                    Ubuntu node-binary-parser too) and bundles that carry
#                    its parser compiler. Each copy is judged by its version
#                    and by the checks its code carries, so a copy patched
#                    in place reads as fixed. Exit 0 = none affected found, 1 = an affected
#                    copy, or a version that can't be confirmed as 2.3.1 or
#                    newer, 2 = bad arguments.
#   audit DIR...     list the source files under each DIR that use
#                    binary-parser and the lines that pass a non-literal value
#                    as a name, an encoding, one of the options above or a
#                    namely() alias. Those are where an untrusted definition
#                    could get in. Exit 0 = none, 1 = lines to review,
#                    2 = bad argument.
#   version          print the script version.
#
# Env overrides:
#   ROOTS="/home /root /srv /var/www /opt /usr/local /usr/lib/node_modules
#          /usr/share/nodejs /usr/lib/nodejs"
#                         where check looks (default shown; the last two hold
#                         Debian and Ubuntu node-* packages). A directory
#                         that does not exist is skipped.
#   MAX_DEPTH=9           how deep check descends under each root
#   BUNDLES=1             also look for bundled copies (0 skips that step,
#                         the slowest one)
# Containers: with no argument and ROOTS unset, the check also looks in running docker and podman
# containers (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies the
# package.json and lockfiles that mention binary-parser, and each installed copy's package.json,
# into a private temporary directory, and this script runs once per container in isolation against
# that copy. Bundled copies are not searched inside containers. Paths shown as .../docker_NAME/...
# are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

CVE_NEW="CVE-2026-134814"
CVE_OLD="CVE-2026-1245"
PKG="binary-parser"
FIXED="2.3.1"        # fixes both
FIXED_OLD="2.3.0"    # fixes CVE-2026-1245 only
ROOTS_GIVEN="${ROOTS:+1}"   # ROOTS set by the user means they chose where to look: running containers are then skipped
ROOTS="${ROOTS:-/home /root /srv /var/www /opt /usr/local /usr/lib/node_modules /usr/share/nodejs /usr/lib/nodejs}"
MAX_DEPTH="${MAX_DEPTH:-9}"
BUNDLES="${BUNDLES:-1}"
SCRIPT_NAME="binary-parser-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
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
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

ver_lt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }

# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
# Paths the container reports are validated before use, a symlink is never kept (docker cp copies the
# link itself, and the check would then read whatever it points to on the host), and the number of
# copied files is capped. It runs once, in the main shell (a subshell's exit would delete the copies).
STAGE=""
declare -a STAGED_DIRS=()
stage_probe() {   # <probe script, run with sh -s inside each running container>
    local probe="$1" rt id name out kind p rest s nf
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        command -v "$rt" >/dev/null 2>&1 || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            out="$(printf '%s\n' "$probe" | "$rt" exec -i "$id" sh -s 2>/dev/null | head -n 6000)" || continue
            [[ -n "$out" ]] || continue
            s=""; nf=0
            while read -r kind p rest; do
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
                if [[ -z "$s" ]]; then
                    if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; trap 'rm -rf "${STAGE:-}"' EXIT; fi
                    s="$STAGE/${rt}_${name:-$id}"; mkdir -p "$s"
                fi
                case "$kind" in
                    F) nf=$((nf + 1)); [[ $nf -le 400 ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       "$rt" cp "${id}:${p}" "$s$p" >/dev/null 2>&1 || rm -f "$s$p"
                       [[ -L "$s$p" ]] && rm -f "$s$p" ;;
                    D) mkdir -p "$s$p" ;;
                    E) mkdir -p "$s$(dirname "$p")"; : > "$s$p" ;;
                    L) [[ "$rest" =~ ^[A-Za-z0-9_=.,:/@-]{0,120}$ ]] || continue
                       mkdir -p "$s$(dirname "$p")"; printf '%s\n' "$rest" > "$s$p" ;;
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

# ---------- check ------------------------------------------------------------
existing_roots() { local r; for r in $ROOTS; do [[ -d "$r" ]] && echo "$r"; done; }

# Judge one resolved version. Returns 0 fixed, 1 affected or not confirmed.
# A pre-release of 2.3.1 is not confirmed as carrying the fix.
judge() {   # <version-or-empty> -> "<rc>|<text>"
    local v="${1#v}" base
    base="${v%%[-+]*}"
    if [[ ! "$base" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "1|version '${1:-?}' can't be read, so it isn't confirmed as ${FIXED} or newer"; return
    fi
    if ver_lt "$base" "$FIXED_OLD"; then
        echo "1|before ${FIXED_OLD}: affected by ${CVE_OLD} and ${CVE_NEW}"
    elif ver_lt "$base" "$FIXED"; then
        echo "1|${base}: fixed for ${CVE_OLD}, affected by ${CVE_NEW}"
    elif [[ "$base" == "$FIXED" && "$v" != "$base" ]]; then
        echo "1|${v} is a pre-release of ${FIXED}, not confirmed fixed"
    else
        echo "0|${FIXED} or newer"
    fi
}

N_AFFECTED=0; N_FIXED=0

# The fixes leave fixed strings in the shipped code that survive bundling and minification:
# 2.3.0 added the "Invalid field name:" and "Invalid encoding:" errors, 2.3.1 the "Invalid reference:"
# error. So the code itself says which fix it carries, with or without a package.json, and a copy
# patched in place reads as fixed whatever its version says.
code_level() {   # <file...> -> 2.3.1 | 2.3.0 | old | none
    local f any=0
    for f in "$@"; do [[ -r "$f" ]] && any=1; done
    [[ $any -eq 1 ]] || { echo none; return; }
    if grep -qsF 'Invalid reference: ' "$@"; then echo "$FIXED"
    elif grep -qsF 'Invalid field name: ' "$@"; then echo "$FIXED_OLD"
    else echo old; fi
}
report_version() {   # <where> <version>
    local rc why; IFS='|' read -r rc why <<<"$(judge "$2")"
    if [[ $rc -eq 0 ]]; then inf "$1  ${2}  fixed (${why})"; N_FIXED=$((N_FIXED + 1))
    else bad "$1  ${2:-?}  ${RED}affected${NC}  (${why})"; N_AFFECTED=$((N_AFFECTED + 1)); fi
}

# A range in package.json does not say what is installed; the lockfile and node_modules do.
# Only an exact pin is judged here. A range that can't reach 2.3.1 is named, so the next
# install does not quietly keep an affected copy.
report_range() {   # <file> <range>
    local f="$1" r="$2"
    if [[ "$r" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+([-+].*)?$ ]]; then
        report_version "${f} (pinned)" "$r"; return
    fi
    if [[ "$r" =~ ^~[0-9]+\.[0-9]+ ]]; then
        local mm="${r#\~}"; mm="${mm%.*}"
        if ver_lt "$mm" "2.3" ; then
            bad "${f}  range ${r} can't reach ${FIXED}: widen it, then reinstall"; N_AFFECTED=$((N_AFFECTED + 1)); return
        fi
    fi
    if [[ "$r" =~ ^\^?(0|1)\. || "$r" =~ ^(0|1)\.x ]]; then
        bad "${f}  range ${r} can't reach ${FIXED}: move to ^${FIXED}, then reinstall"; N_AFFECTED=$((N_AFFECTED + 1)); return
    fi
    inf "${f}  range ${r}: the lockfile or the installed copy below says which version is in use"
}

BP_PROBE="$(cat <<'EOS'
R="/home /root /srv /var/www /opt /usr/local /usr/lib/node_modules /app"
PKG="binary-parser"
find $R -maxdepth 9 -type d -name node_modules -prune -o -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -print 2>/dev/null | head -n 4000 | while read -r f; do
  grep -q "\"$PKG\|$PKG@\|/$PKG/" "$f" 2>/dev/null && echo "F $f"
done
find $R -maxdepth 14 -type f -path "*/node_modules/$PKG/package.json" 2>/dev/null | head -n 60 | while read -r f; do echo "F $f"; done
exit 0
EOS
)"

container_run() {   # <staged directory>
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "binary-parser in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 BUNDLES=0 ROOTS="$s" bash "$SELF" check 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ -z "${ROOTS_GIVEN:-}" && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$BP_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

lock_versions() {   # <lockfile> -> one resolved version per line
    local f="$1"
    case "${f##*/}" in
        package-lock.json|npm-shrinkwrap.json)
            # v2/v3: "node_modules/.../binary-parser": { "version": ... }; v1: "binary-parser": { "version": ... }
            grep -A4 -E "\"(node_modules/([^\"]*/)?)?${PKG}\"[[:space:]]*:[[:space:]]*\\{" "$f" 2>/dev/null \
              | grep '"version"' | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/' ;;
        yarn.lock)
            awk -v p="$PKG" '
                /^[^ \t]/ { inblk = ($0 ~ ("(^|[\" ,])" p "@")) ; next }
                inblk && /^[ \t]+version:?[ \t]/ { v=$2; gsub(/"/, "", v); print v; inblk=0 }' "$f" 2>/dev/null ;;
        pnpm-lock.yaml)
            grep -oE "(^|[[:space:]/'\"])${PKG}[@/][0-9][0-9A-Za-z.+-]*" "$f" 2>/dev/null \
              | sed -E "s/.*${PKG}[@/]//" ;;
    esac | sort -u
}

cmd_check_host() {
    local f v roots n
    roots="$(existing_roots)"
    [[ -n "$roots" ]] || die "None of the ROOTS exist: ${ROOTS}"

    step "Projects that depend on ${PKG}"
    limited_view "project folders"
    n=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        case "${f##*/}" in
            package.json)
                v="$(grep -oE "\"${PKG}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$f" 2>/dev/null | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')"
                [[ -n "$v" ]] || continue
                n=$((n + 1)); report_range "$f" "$v" ;;
            *)
                local found=0
                while IFS= read -r v; do
                    [[ -n "$v" ]] || continue
                    found=1; report_version "$f (lockfile)" "$v"
                done < <(lock_versions "$f")
                [[ $found -eq 1 ]] && n=$((n + 1)) ;;
        esac
    done < <(while IFS= read -r r; do
                find "$r" -maxdepth "$MAX_DEPTH" -type d -name node_modules -prune -o \
                     -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json \
                                -o -name yarn.lock -o -name pnpm-lock.yaml \) -print 2>/dev/null
             done <<<"$roots")
    [[ $n -gt 0 ]] || inf "no package.json or lockfile under ${roots//$'\n'/ } names ${PKG}"

    step "Installed copies"
    n=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        grep -qE "\"name\"[[:space:]]*:[[:space:]]*\"${PKG}\"" "$f" 2>/dev/null || continue
        n=$((n + 1))
        v="$(grep -m1 '"version"' "$f" 2>/dev/null | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
        local d="${f%/package.json}" lvl rc why; local -a code
        mapfile -t code < <(find "$d" -maxdepth 3 -path "$d/node_modules" -prune -o -type f -name '*.js' -print 2>/dev/null | head -n 40)
        lvl="$(code_level ${code[@]:+"${code[@]}"})"
        IFS='|' read -r rc why <<<"$(judge "$v")"
        if [[ $rc -ne 0 && "$lvl" == "$FIXED" ]]; then
            inf "${d}  ${v:-?}  fixed in place (its code carries the ${FIXED} checks, so the fix was backported)"; N_FIXED=$((N_FIXED + 1))
        elif [[ $rc -eq 0 && ( "$lvl" == old || "$lvl" == "$FIXED_OLD" ) ]]; then
            bad "${d}  ${v}  ${RED}affected${NC}  (package.json says ${v}, but the code lacks the ${FIXED} checks)"; N_AFFECTED=$((N_AFFECTED + 1))
        else
            report_version "$d" "$v"
        fi
    done < <(while IFS= read -r r; do
                find "$r" -maxdepth "$((MAX_DEPTH + 5))" -type f \( -path "*/node_modules/${PKG}/package.json" \
                     -o -path "*/nodejs/${PKG}/package.json" \) 2>/dev/null
             done <<<"$roots")
    [[ $n -gt 0 ]] || inf "no installed copy under node_modules"

    if [[ "$BUNDLES" == 1 ]]; then
        step "Bundled copies"
        # A bundler (webpack, esbuild, rollup) can carry the parser compiler inside another file, with
        # no package.json to say which version it is. Its Context class keeps these method names, and
        # the error strings above say which fix it carries.
        n=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            n=$((n + 1))
            case "$(code_level "$f")" in
                "$FIXED")     inf "${f}  bundled copy with the ${FIXED} checks: fixed"; N_FIXED=$((N_FIXED + 1)) ;;
                "$FIXED_OLD") bad "${f}  bundled copy at the ${FIXED_OLD} level: ${RED}affected${NC} by ${CVE_NEW}. Rebuild it against ${PKG} ${FIXED} or newer"; N_AFFECTED=$((N_AFFECTED + 1)) ;;
                *)            bad "${f}  bundled copy older than ${FIXED_OLD}: ${RED}affected${NC} by ${CVE_OLD} and ${CVE_NEW}. Rebuild it against ${PKG} ${FIXED} or newer"; N_AFFECTED=$((N_AFFECTED + 1)) ;;
            esac
        done < <(while IFS= read -r r; do
                    find "$r" -maxdepth "$MAX_DEPTH" \( -path "*/node_modules/${PKG}" -o -path "*/nodejs/${PKG}" \) -prune -o -type f \
                         \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -size -20M -print 2>/dev/null
                 done <<<"$roots" | xargs -r -d '\n' grep -lF 'generateTmpVariable' 2>/dev/null \
                 | xargs -r -d '\n' grep -lF 'generateOption' 2>/dev/null | head -n 200)
        [[ $n -gt 0 ]] || inf "no bundled copy found"
    fi

    step "Verdict"
    if [[ $N_AFFECTED -gt 0 ]]; then
        warn "${N_AFFECTED} affected or unconfirmed copy(ies). Upgrade with 'npm install ${PKG}@^${FIXED}' (or yarn/pnpm), commit the lockfile, rebuild and redeploy. Until then, never build a parser definition from data someone else controls. Run '${SELF} audit DIR' on your source to see where definitions come from"
        return 1
    fi
    if [[ $N_FIXED -gt 0 ]]; then info "every copy found is ${FIXED} or newer"
    else info "${PKG} was not found where this could read"; fi
    return 0
}

# ---------- audit ------------------------------------------------------------
# An option value written as a quoted literal, a number or a function is fixed in the source. A
# value taken from a variable, an object or a template with ${...} may come from outside; those
# are the lines to read. This is a pointer for a reviewer, not a verdict on the code.
OPT_KEYS='(length|lengthInBytes|key|tag|offset|encoding)'
NONLIT="(^|[^A-Za-z0-9_\$])${OPT_KEYS}[[:space:]]*:[[:space:]]*([A-Za-z_\$][A-Za-z0-9_\$.]*[[:space:]]*([,}]|\$|\\[)|\`[^\`]*\\\$\\{)"
NAMELY='\.namely[[:space:]]*\([[:space:]]*([^"'"'"'[:space:]]|`[^`]*\$\{)'
METHOD_NAME='\.(u?int(8|16|32|64)(le|be)?|bit[0-9]+|(float|double)(le|be)?|string|buffer|array|choice|nest|pointer|saveOffset|wrapped)[[:space:]]*\([[:space:]]*([A-Za-z_$][A-Za-z0-9_$.]*|`[^`]*\$\{)[[:space:]]*[,)]'

cmd_audit() {
    [[ $# -gt 0 ]] || die "audit needs at least one directory"
    local d f files=0 lines=0 hit
    for d in "$@"; do [[ -d "$d" ]] || die "Not a directory: ${d}"; done
    step "Source that uses ${PKG} (read only, never run)"
    for d in "$@"; do
        while IFS= read -r f; do
            files=$((files + 1))
            inf "$f"
            grep -qE 'JSON\.parse|readFileSync|req\.(body|query)|request\.(body|query)' "$f" 2>/dev/null \
                && caution "  this file also reads JSON, files or request data: check whether any of it reaches a parser definition"
            while IFS= read -r hit; do
                [[ -n "$hit" ]] || continue
                lines=$((lines + 1))
                bad "  ${f}:${hit:0:200}"
            done < <( { grep -nE "$NONLIT" "$f"; grep -nE "$NAMELY" "$f"; grep -nE "$METHOD_NAME" "$f"; } 2>/dev/null | sort -t: -k1,1n -u )
        done < <(find "$d" -type d \( -name node_modules -o -name .git \) -prune -o -type f \
                      \( -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name '*.mts' -o -name '*.cts' \) -print0 2>/dev/null \
                 | xargs -r -0 grep -lE "(require\\(|from[[:space:]]+|import\\()[[:space:]]*['\"]${PKG}['\"]" 2>/dev/null | sort)
    done
    step "Verdict"
    inf "${files} file(s) use ${PKG}"
    if [[ $lines -eq 0 ]]; then
        info "Every name, encoding, length, key, tag, offset and alias found is written in the source"
        inf "This reads the source as text. A definition assembled some other way (a helper that builds parsers in a loop, options passed as one object) is not followed: read those by hand"
        return 0
    fi
    warn "${lines} line(s) take a name, an encoding, an option or an alias from a variable. Trace each back: if any part can come from a user, a file, a database or the network, an affected ${PKG} runs it as code when the parser compiles. Upgrading to ${FIXED} rejects such values"
    return 1
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE_NEW} (fixed in ${FIXED}) and ${CVE_OLD} (fixed in ${FIXED_OLD})"
    case "$CMD" in
        check) [[ $# -eq 0 ]] || die "check takes no arguments (set ROOTS to choose where it looks)"; cmd_check ;;
        audit) cmd_audit "$@" ;;
        *) die "Unknown command: ${CMD} (check|audit|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
