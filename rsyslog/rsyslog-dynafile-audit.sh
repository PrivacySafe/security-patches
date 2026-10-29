#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# rsyslog dynaFile path traversal: read-only configuration audit  (v1)
# CVE-2026-92709 (GHSA-xmp9-244p-5ggv)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# rsyslog's omfile dynaFile feature builds an output file name from a template.
# When a template puts a value that an outside party can influence (the HOSTNAME
# or program name of an incoming message, the message text, structured data...)
# into a path component WITHOUT explicit secure-path handling, the rendered path
# can escape the intended log directory. rsyslog usually runs as root or with
# broad write access to /var/log, so the result is an arbitrary file write, which
# the advisory title and several trackers escalate to code execution. Rated High,
# CVSS 8.1. The flaw is not limited to the RFC 5424 HOSTNAME field: any untrusted
# value that reaches a path component creates the condition. A PoC reference is
# listed by one aggregator; the page we saw held only the advisory text.
#
#   Affected: rsyslog 1.15.0 through 8.2610.0, WHEN a dynaFile template uses an
#             untrusted value in a path component without secure-path handling
#   Fixed:    NO RELEASE IS LISTED AS FULLY PATCHED (27 October 2026). Debian,
#             Cyberus and nixpkgs trackers show it as open. The daily stable
#             documentation describes new dynaFile controls and a rule that the
#             path must stay under a fixed leading prefix, which hints that a fix
#             is on the way; no release carries it yet, so do not wait for it.
#
# The documented, recommended defence, which works on every version, is explicit
# secure-path handling for each untrusted value in a dynaFile path:
#     string templates:   %HOSTNAME:::secpath-replace%     (or secpath-drop)
#     list templates:     property(name="hostname" securePath="replace")
# Both forms were validated with rsyslogd -N1 on 8.2312.0.
#
#   CAUTION: global(compatibility.defaults.secure="strict"), which defaults
#   unprotected dynaFile fields to secpath-replace, is only known to newer
#   rsyslog. On 8.2312.0 it is a configuration ERROR ("parameter ... not known").
#   Test any change with rsyslogd -N1 before you restart.
#
# This script is read-only. It reads the rsyslog version, the main configuration
# and everything it includes, finds the templates used by dynaFile, and lists any
# path component that comes from an untrusted property without secure-path
# handling. It reports whether remote input modules are configured and which
# user rsyslogd runs as. It does not restart rsyslog and does not send any
# message. It is a text search over the configuration, not a full parser.
#
# Usage:
#   ./rsyslog-dynafile-audit.sh [command]
#
#   audit (default)  Exit 0 = no unprotected untrusted value in a dynaFile path,
#                    1 = at least one was found or could not be judged.
#   version          print the script version.
#
# Environment: RSYSLOG_CONF (space separated files) replaces configuration discovery.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="rsyslog-dynafile-audit.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"
SELF="$0"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Version helpers: strip a leading v and any -prerelease or +build suffix, then compare with
# sort -V. A pre-release of the boundary itself (6.3.0-rc2 against 6.3.0) is below it, as in
# semantic versioning, so a pre-release of a fixed release is never reported as the release.
norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
ver_ge() { ! ver_lt "$1" "$2"; }
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
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

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- the template parser (portable awk: works with mawk and gawk) -----
# Emits one record per template: TPL <TAB> file <TAB> name <TAB> specs
# and one per dynaFile reference:  REF <TAB> file <TAB> name
# A spec is  property|secpath-flag  and specs are joined by the ASCII record separator.
read -r -d '' AWK_PARSE <<'AWKEOF'
function lc(s) { return tolower(s) }
function scan_close(s, start, op, cl,    i, c, depth, inq) {
    depth = 1; inq = 0
    for (i = start; i <= length(s); i++) {
        c = substr(s, i, 1)
        if (inq) { if (c == "\\") { i++; continue } if (c == "\"") inq = 0; continue }
        if (c == "\"") { inq = 1; continue }
        if (c == op) depth++
        else if (c == cl) { depth--; if (depth == 0) return i }
    }
    return 0
}
function getattr(s, key,    re, seg, l) {
    l = lc(s); re = "(^|[ \t\n])" key "[ \t\n]*=[ \t\n]*\"[^\"]*\""
    if (match(l, re)) {
        seg = substr(s, RSTART, RLENGTH)
        sub(/^[^"]*"/, "", seg); sub(/"$/, "", seg)
        return seg
    }
    return ""
}
function specs_from_string(s,    out, expr, a, n, i, opts, flag) {
    out = ""
    while (match(s, /%[^%]*%/)) {
        expr = substr(s, RSTART + 1, RLENGTH - 2)
        s = substr(s, RSTART + RLENGTH)
        if (expr == "") continue
        n = split(expr, a, ":")
        opts = ""
        for (i = 4; i <= n; i++) opts = opts (i > 4 ? ":" : "") a[i]
        flag = (lc(opts) ~ /secpath|securepath/) ? "secpath" : ""
        out = out (out == "" ? "" : "\036") lc(a[1]) "|" flag
    }
    return out
}
{ txt = txt $0 "\n" }
END {
    n = split(txt, L, "\n")
    for (i = 1; i <= n; i++) {
        line = L[i]; l = lc(line)
        # legacy: $template NAME,"string"[,options]
        if (match(l, /^[ \t]*\$template[ \t]+/)) {
            rest = substr(line, RSTART + RLENGTH)
            c = index(rest, ",")
            if (c > 0) {
                nm = substr(rest, 1, c - 1); gsub(/[ \t]/, "", nm)
                r2 = substr(rest, c + 1)
                q1 = index(r2, "\"")
                if (q1 > 0) {
                    r3 = substr(r2, q1 + 1); q2 = 0
                    for (k = length(r3); k >= 1; k--) if (substr(r3, k, 1) == "\"") { q2 = k; break }
                    if (q2 > 0) printf "TPL\t%s\t%s\t%s\n", FILENAME, nm, specs_from_string(substr(r3, 1, q2 - 1))
                }
            }
            continue
        }
        # legacy action reference: ?Name or -?Name (not on $-directive lines)
        if (line !~ /^[ \t]*\$/ && match(line, /[ \t:]-?\?[A-Za-z_][A-Za-z0-9_.-]*/)) {
            ref = substr(line, RSTART, RLENGTH); sub(/^[^?]*\?/, "", ref)
            printf "REF\t%s\t%s\n", FILENAME, ref
        }
    }
    # RainerScript: template( ... ) and dynaFile="..."
    lt = lc(txt); pos = 1
    while (pos <= length(txt) && match(substr(lt, pos), /(^|[^a-z0-9_$])template[ \t\n]*\(/)) {
        op = pos + RSTART - 1 + RLENGTH - 1
        cl = scan_close(txt, op + 1, "(", ")")
        if (cl == 0) break
        args = substr(txt, op + 1, cl - op - 1)
        pos = cl + 1
        nm = getattr(args, "name"); ty = lc(getattr(args, "type")); st = getattr(args, "string")
        if (nm == "") continue
        if (ty == "list") {
            j = cl + 1
            while (j <= length(txt) && substr(txt, j, 1) ~ /[ \t\n]/) j++
            if (substr(txt, j, 1) == "{") {
                e = scan_close(txt, j + 1, "{", "}")
                if (e > 0) {
                    blk = substr(txt, j + 1, e - j - 1); lb = lc(blk); bp = 1; sp = ""
                    while (bp <= length(blk) && match(substr(lb, bp), /(^|[^a-z0-9_])property[ \t\n]*\(/)) {
                        po = bp + RSTART - 1 + RLENGTH - 1
                        pc = scan_close(blk, po + 1, "(", ")")
                        if (pc == 0) break
                        pa = substr(blk, po + 1, pc - po - 1); bp = pc + 1
                        fl = (lc(pa) ~ /securepath|secpath/) ? "secpath" : ""
                        sp = sp (sp == "" ? "" : "\036") lc(getattr(pa, "name")) "|" fl
                    }
                    printf "TPL\t%s\t%s\t%s\n", FILENAME, nm, sp
                    pos = e + 1
                }
            }
        } else if (st != "" || ty == "string") {
            printf "TPL\t%s\t%s\t%s\n", FILENAME, nm, specs_from_string(st)
        } else {
            printf "TPL\t%s\t%s\t%s\n", FILENAME, nm, "?unanalyzable|"
        }
    }
    p2 = 1
    while (p2 <= length(txt) && match(substr(lt, p2), /dynafile[ \t\n]*=[ \t\n]*"[^"]+"/)) {
        seg = substr(txt, p2 + RSTART - 1, RLENGTH); p2 = p2 + RSTART - 1 + RLENGTH
        sub(/^[^"]*"/, "", seg); sub(/"$/, "", seg)
        printf "REF\t%s\t%s\n", FILENAME, seg
    }
}
AWKEOF

# ---------- helpers ----------------------------------------------------------
# property class: safe | sender | unknown
prop_class() {
    local p; p="$(tr 'A-Z' 'a-z' <<<"$1")"
    case "$p" in
        fromhost-ip|inputname|timegenerated|timereported|timestamp|now|year|month|day|hour|minute|pri|pri-text|syslogfacility|syslogfacility-text|syslogseverity|syslogseverity-text|iut) echo safe ;;
        '$now'|'$year'|'$month'|'$day'|'$hour'|'$minute'|'$myhostname'|'$now-utc'|'$year-utc'|'$month-utc'|'$day-utc'|'$hour-utc'|'$minute-utc') echo safe ;;
        hostname|source|fromhost|programname|app-name|syslogtag|msg|rawmsg|rawmsg-after-pri|procid|msgid|structured-data|protocol-version) echo sender ;;
        '$!'*) echo sender ;;
        *) echo unknown ;;
    esac
}

# resolve the configuration files: main file, then $IncludeConfig / include(file=)
collect_conf() {   # file depth
    local f="$1" depth="$2" inc g
    [[ -r "$f" && -f "$f" ]] || return 0
    case " ${SEEN_CONF:-} " in *" $f "*) return 0 ;; esac
    SEEN_CONF="${SEEN_CONF:-} $f"
    echo "$f"
    (( depth >= 5 )) && return 0
    while IFS= read -r inc; do
        [[ -n "$inc" ]] || continue
        if [[ -d "$inc" ]]; then
            for g in "$inc"/*; do [[ -f "$g" ]] && collect_conf "$g" $((depth+1)); done
        else
            # shellcheck disable=SC2086
            for g in $inc; do collect_conf "$g" $((depth+1)); done
        fi
    done < <( {
        sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -iE '^[[:space:]]*\$includeconfig[[:space:]]+' | sed -E 's/^[[:space:]]*\$[Ii]nclude[Cc]onfig[[:space:]]+//; s/[[:space:]]+$//'
        sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -ioE 'include[[:space:]]*\([^)]*file[[:space:]]*=[[:space:]]*"[^"]+"' | sed -E 's/.*file[[:space:]]*=[[:space:]]*"([^"]+)"/\1/I'
    } )
}

config_files() {
    local f
    SEEN_CONF=""
    if [[ -n "${RSYSLOG_CONF:-}" ]]; then for f in $RSYSLOG_CONF; do collect_conf "$f" 0; done; return 0; fi
    collect_conf /etc/rsyslog.conf 0
}

# ---------- audit ------------------------------------------------------------
cmd_audit() {
    local rc=0 f raw v b files=() tmp kind file name specs ref t sp p flag cls
    local -A TPL_SPECS=() TPL_FILE=() REFS=()
    local unsafe=0 dyn=0 strict=0 remote="" user

    step "rsyslog version"
    b="$(command -v rsyslogd 2>/dev/null)"; [[ -z "$b" && -x /usr/sbin/rsyslogd ]] && b=/usr/sbin/rsyslogd
    if [[ -n "$b" ]]; then
        raw="$("$b" -v 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]{4}\.[0-9]+' | head -n1)"
        if [[ -n "$raw" ]]; then
            if ver_lt "$raw" "8.2610.1"; then
                caution "rsyslog ${raw} is in the affected range (1.15.0 through 8.2610.0) and no release is listed as fully patched: the configuration audit below decides your exposure"
            else
                inf "rsyslog ${raw} is newer than the last affected release (8.2610.0). Check its release notes for the dynaFile fix; the audit below still applies."
            fi
            if distro_mentions "$b" CVE-2026-92709; then
                ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have shipped a mitigation"
            elif [[ $? -eq 1 ]]; then
                inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention the CVE yet"
            fi
        else
            inf "could not read a version from ${b} -v"
        fi
        user="$(ps -o user= -C rsyslogd 2>/dev/null | head -n1 | tr -d ' ')"
        if [[ -n "$user" ]]; then
            if [[ "$user" == "root" ]]; then caution "rsyslogd is running as root: a path escape writes as root"
            else inf "rsyslogd is running as user '${user}': a path escape writes with that user's permissions"; fi
        else
            inf "rsyslogd is not running (or its process is not visible): the user it runs as was not checked"
        fi
    else
        inf "rsyslogd not found on PATH or in /usr/sbin: the version was not checked"
    fi

    step "Configuration files"
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(config_files)
    if [[ ${#files[@]} -eq 0 ]]; then
        caution "no readable rsyslog configuration found (looked at /etc/rsyslog.conf): exposure cannot be judged, treating as exposed"
        return 1
    fi
    for f in "${files[@]}"; do inf "read ${f}"; done

    AUDIT_TMP="$(mktemp -d 2>/dev/null || mktemp -d -t rsyslogaudit)"; tmp="$AUDIT_TMP"
    for f in "${files[@]}"; do
        sed -E 's/^[[:space:]]*#.*$//; s/\r$//' "$f" | sed -e ':a' -e '/\\$/N; s/\\\n//; ta' > "$tmp/$(basename "$f").$$.flat"
        # awk reads the flattened copy but reports the original file name
        awk -v FILENAME_OVERRIDE="$f" "$AWK_PARSE" "$tmp/$(basename "$f").$$.flat" | sed "s#$tmp/[^	]*\\.flat#$f#"
    done > "$tmp/records.tsv"

    strict=0
    for f in "${files[@]}"; do grep -qiE 'compatibility\.defaults\.secure[[:space:]]*=[[:space:]]*"strict"' "$f" && strict=1; done
    remote="$(for f in "${files[@]}"; do sed -E 's/^[[:space:]]*#.*$//' "$f"; done | grep -ioE 'imudp|imtcp|imrelp|imptcp|imhttp|imgssapi|imkafka|UDPServerRun|InputTCPServerRun|InputRELPServerRun' | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ')"

    while IFS=$'\t' read -r kind file name specs; do
        case "$kind" in
            TPL) TPL_SPECS["$name"]="$specs"; TPL_FILE["$name"]="$file" ;;
            REF) REFS["$name"]="$file" ;;
        esac
    done < "$tmp/records.tsv"

    step "dynaFile templates"
    dyn=${#REFS[@]}
    if [[ $dyn -eq 0 ]]; then
        ok "no omfile dynaFile (and no ?Template action) was found in the configuration: nothing here builds a path from message data"
    else
        for ref in "${!REFS[@]}"; do
            if [[ -z "${TPL_FILE[$ref]+x}" ]]; then
                caution "dynaFile template '${ref}' (used in ${REFS[$ref]}) is not defined in the files read: review it by hand"
                unsafe=$((unsafe+1)); continue
            fi
            inf "template '${ref}' defined in ${TPL_FILE[$ref]}, used by dynaFile in ${REFS[$ref]}"
            specs="${TPL_SPECS[$ref]}"
            if [[ -z "$specs" ]]; then ok "template '${ref}' has no property in its path"; continue; fi
            local bad_here=0 strict_used=0
            IFS=$'\036' read -r -a sp <<<"$specs"
            for t in "${sp[@]}"; do
                p="${t%%|*}"; flag="${t#*|}"
                if [[ "$p" == "?unanalyzable" ]]; then
                    caution "template '${ref}' is a subtree or plugin template that this script cannot analyse: review it by hand"; bad_here=1; continue
                fi
                cls="$(prop_class "$p")"
                if [[ -n "$flag" ]]; then
                    inf "  ${p}: secure-path handling present"
                elif [[ "$cls" == "safe" ]]; then
                    inf "  ${p}: not controllable by a sender"
                elif [[ $strict -eq 1 ]]; then
                    inf "  ${p}: no explicit handling, covered only by global strict mode"
                    strict_used=1
                elif [[ "$cls" == "sender" ]]; then
                    bad "template '${ref}': property '${p}' comes from the message and has NO secure-path handling"; bad_here=1
                else
                    caution "template '${ref}': property '${p}' is unrecognised and has no secure-path handling: if a sender can influence it, treat it as unsafe"; bad_here=1
                fi
            done
            if [[ $bad_here -eq 1 ]]; then unsafe=$((unsafe+1))
            elif [[ $strict_used -eq 1 ]]; then caution "template '${ref}': protected only by global strict mode: confirm with rsyslogd -N1 that your rsyslog accepts it (8.2312.0 does not), or add explicit secpath-replace"
            else ok "template '${ref}': every untrusted component is protected"; fi
        done
    fi

    step "Input and global settings"
    if [[ -n "$remote" ]]; then caution "remote or network input is configured (${remote% }): senders you do not control can reach these templates"
    else inf "no network input module found in these files (local sources such as imuxsock and imjournal can still carry attacker-chosen program names)"; fi
    [[ $strict -eq 1 ]] && inf "global(compatibility.defaults.secure=\"strict\") is set"

    step "Verdict"
    if [[ $unsafe -eq 0 ]]; then
        info "No unprotected untrusted value found in a dynaFile path (${dyn} dynaFile template(s) checked)"
        return 0
    fi
    warn "${unsafe} dynaFile template(s) are unsafe or could not be shown safe (untrusted data in a path without secure-path handling, an undefined template, or one this script cannot analyse)."
    inf "Fix each untrusted property: %HOSTNAME% becomes %HOSTNAME:::secpath-replace% (or secpath-drop); in list templates add securePath=\"replace\" to the property()."
    inf "Test the result with: rsyslogd -N1   before you restart rsyslog."
    inf "global(compatibility.defaults.secure=\"strict\") is only known to newer rsyslog; on older versions such as 8.2312.0 it is a configuration error, so test before relying on it."
    inf "Also run rsyslogd as an unprivileged user and keep its writable area to the log directories."
    inf "Advisory: https://github.com/rsyslog/rsyslog/security/advisories/GHSA-xmp9-244p-5ggv"
    return 1
}

# ---------- dispatch ---------------------------------------------------------
AUDIT_TMP=""
trap 'rm -rf "${AUDIT_TMP:-}"' EXIT
main() {
    CMD="${1:-audit}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-92709; no release is listed as fully patched; secure-path handling is the defence"
    case "$CMD" in
        audit) cmd_audit "$@" ;;
        *) die "Unknown command: ${CMD} (audit|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
