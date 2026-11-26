#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Jenkins plugin security advisory of 16 September 2026 (20 CVEs): read-only checker  (v1)
# CVE-2026-92122 to CVE-2026-92141
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Jenkins published a security advisory on 16 September 2026 covering 20 vulnerabilities
# in 13 widely deployed plugins. Eight are High-severity flaws in Script Security, the
# plugin that sandboxes Groovy for Pipelines and is present on nearly every Jenkins
# server: ways around the sandbox (interface coercion, calls on a null receiver,
# collection casts, AST transformations, @Builder at compile time, dynamic methods, a
# classpath approval bypass, and a time-of-check to time-of-use race on approved remote
# JARs) that let a user who may define Pipeline scripts run code in the controller's JVM.
#
#   Plugin (short name)                 Fixed in                   CVE          Severity
#   script-security                     1422.v06869826dd9b_        92122-92129  High (8 issues)
#   workflow-multibranch                842.v3a_b_59b_57b_e6e      92130        Low
#   pipeline-groovy-lib                 806.v408277b_33d1d         92131        Medium
#   gradle                              2.20.1253.vc116f0763a_eb_  92132        Medium
#   gitlab-plugin                       1.2152.veec0897048b_0      92133        Medium
#   warnings-ng                         13.10259.v80f407cb_03a_e   92134        High
#   coverage                            3.3361.v0626103a_67e6      92135        High
#   dependency-check-jenkins-plugin     5.6.5                      92136        High
#   robot                               6.3.0                      92137        High
#   atlassian-bitbucket-server-integration  6.0.2                  92138        Medium
#   bitbucket-push-and-pull-request     4.1.0                      92139        Medium
#   gitee                               1304.v2702f1d71cde         92140        High
#   keycloak                            2.4.2                      92141        Medium
#
# What the High ones allow: Script Security, sandbox bypass and code execution in the
# controller JVM; Robot Framework (92137), arbitrary file creation or replacement on the
# controller, which can lead to code execution; Warnings, Coverage, Dependency-Check and
# Gitee, stored cross-site scripting. Credentials can leak through Pipeline: Multibranch
# (System-scoped credentials), GitLab (API tokens), Gradle (the Develocity access key),
# and Bitbucket Push and Pull Request (Bitbucket credentials, by SSRF).
#
# How this script reads an install. A plugin's version is the Plugin-Version line of its
# META-INF/MANIFEST.MF, in the expanded plugin directory or inside the .jpi or .hpi file
# under $JENKINS_HOME/plugins. Versions are compared by their leading dotted number; two
# builds with the same number but different build hashes cannot be ordered, and are
# reported as such. A plugin that is disabled does not run and is reported as such.
# The 13 short names were checked against each plugin's own project file.
#
# This script is read-only.
#
# Usage:
#   ./jenkins-check.sh [command] [JENKINS_HOME ...]
#   check (default)  Exit 0 = nothing exposed, 1 = a plugin below its fixed version.
#   version          print the script version.
#
# Env: JENKINS_HOME  the Jenkins home directory (default /var/lib/jenkins, /var/jenkins_home)
#      SCAN_CONTAINERS=1 (the default) also reads the advisory plugins' manifests inside running
#      docker and podman containers (JENKINS_HOME there, default /var/jenkins_home); 0 skips them.
#      It is skipped when you name the home directories yourself.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="jenkins-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }
# short name | fixed version | CVEs | severity | what it allows
PLUGINS=(
 "script-security|1422.v06869826dd9b_|CVE-2026-92122 CVE-2026-92123 CVE-2026-92124 CVE-2026-92125 CVE-2026-92126 CVE-2026-92127 CVE-2026-92128 CVE-2026-92129|High|sandbox bypass: code execution in the controller JVM"
 "workflow-multibranch|842.v3a_b_59b_57b_e6e|CVE-2026-92130|Low|System-scoped credential exposure"
 "pipeline-groovy-lib|806.v408277b_33d1d|CVE-2026-92131|Medium|path traversal: file read and deletion"
 "gradle|2.20.1253.vc116f0763a_eb_|CVE-2026-92132|Medium|SSRF: Develocity access key theft"
 "gitlab-plugin|1.2152.veec0897048b_0|CVE-2026-92133|Medium|GitLab API token exposure"
 "warnings-ng|13.10259.v80f407cb_03a_e|CVE-2026-92134|High|stored XSS"
 "coverage|3.3361.v0626103a_67e6|CVE-2026-92135|High|stored XSS"
 "dependency-check-jenkins-plugin|5.6.5|CVE-2026-92136|High|stored XSS"
 "robot|6.3.0|CVE-2026-92137|High|arbitrary file write on the controller, potentially code execution"
 "atlassian-bitbucket-server-integration|6.0.2|CVE-2026-92138|Medium|OAuth access token hijacking"
 "bitbucket-push-and-pull-request|4.1.0|CVE-2026-92139|Medium|SSRF: Bitbucket credential theft"
 "gitee|1304.v2702f1d71cde|CVE-2026-92140|High|stored XSS"
 "keycloak|2.4.2|CVE-2026-92141|Medium|open redirect"
)

# the Plugin-Version of a plugin: expanded directory first, then the packaged archive.
# A manifest wraps long lines: a line that starts with one space continues the line before.
manifest_of() {   # plugins-dir short-name -> manifest text
    local pd="$1" n="$2" a
    if [[ -r "$pd/$n/META-INF/MANIFEST.MF" ]]; then cat "$pd/$n/META-INF/MANIFEST.MF"; return; fi
    for a in "$pd/$n.jpi" "$pd/$n.hpi"; do
        [[ -r "$a" ]] || continue
        if have unzip; then unzip -p "$a" META-INF/MANIFEST.MF 2>/dev/null && return
        elif have python3; then python3 -c 'import sys,zipfile; sys.stdout.write(zipfile.ZipFile(sys.argv[1]).read("META-INF/MANIFEST.MF").decode("utf-8","replace"))' "$a" 2>/dev/null && return; fi
    done
    return 1
}
plugin_version() {
    local m; m="$(manifest_of "$1" "$2")" || return 1
    printf '%s' "$m" | tr -d '\r' | sed ':a;N;$!ba;s/\n //g' | sed -nE 's/^Plugin-Version:[[:space:]]*//p' | head -n1 | sed -E 's/[[:space:]]+$//'
}
# prints: fixed | affected | unordered
#   unordered = the same leading number with different build hashes: the order is not knowable
jver_status() {
    local inst="$1" fix="$2" pi pf
    [[ "$inst" == "$fix" ]] && { echo fixed; return; }
    pi="$(sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/' <<<"$inst")"; pf="$(sed -E 's/^([0-9]+(\.[0-9]+)*).*/\1/' <<<"$fix")"
    [[ "$pi" =~ ^[0-9]+(\.[0-9]+)*$ ]] || { echo unordered; return; }
    if ver_lt "$pi" "$pf"; then echo affected
    elif ver_lt "$pf" "$pi"; then echo fixed
    else echo unordered; fi
}

# ---------- running containers -----------------------------------------------
# A Jenkins home inside a container is not on the host. For each running container, copy out the
# manifests of the advisory plugins into a staging directory laid out like a plugins directory,
# so the same checks (disabled plugins, unreadable versions, build-hash ordering) judge it.
JK_STAGE=""
declare -a JK_STAGED=()
declare -A JK_LABEL=()
stage_containers() {
    local rt id name h list entry n x s
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            h="$("$rt" exec "$id" sh -c 'printf %s "${JENKINS_HOME:-/var/jenkins_home}"' 2>/dev/null)" || continue
            [[ "$h" =~ ^/[A-Za-z0-9._/-]+$ ]] || continue
            list="$("$rt" exec "$id" sh -c "ls -1 '${h}/plugins' 2>/dev/null" 2>/dev/null)" || continue
            [[ -n "$list" ]] || continue
            if [[ -z "$JK_STAGE" ]]; then
                JK_STAGE="$(mktemp -d)" || return 0
                trap 'rm -rf "${JK_STAGE:-}"' EXIT
            fi
            s="$JK_STAGE/${rt}_${id}"; mkdir -p "$s/plugins"
            for entry in "${PLUGINS[@]}"; do
                n="${entry%%|*}"
                if grep -Fx -- "$n" <<<"$list" >/dev/null; then
                    mkdir -p "$s/plugins/$n/META-INF"
                    "$rt" exec "$id" cat "${h}/plugins/${n}/META-INF/MANIFEST.MF" > "$s/plugins/$n/META-INF/MANIFEST.MF" 2>/dev/null || rm -f "$s/plugins/$n/META-INF/MANIFEST.MF"
                fi
                for x in jpi hpi; do
                    if grep -Fx -- "$n.$x" <<<"$list" >/dev/null; then
                        "$rt" cp "${id}:${h}/plugins/${n}.${x}" "$s/plugins/${n}.${x}" >/dev/null 2>&1 || : > "$s/plugins/${n}.${x}"
                    fi
                    if grep -Fx -- "$n.$x.disabled" <<<"$list" >/dev/null; then : > "$s/plugins/${n}.${x}.disabled"; fi
                done
            done
            JK_STAGED+=("$s"); JK_LABEL["$s"]="${rt} container ${name:-$id} (${h})"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

cmd_check() {
    local -a homes=(); local rc=0 h pd entry n fix cves sev what v st disabled found=0 present=0 exposed=0
    if [[ $# -gt 0 ]]; then homes=("$@")
    else
        [[ -n "${JENKINS_HOME:-}" ]] && homes+=("$JENKINS_HOME")
        for h in /var/lib/jenkins /var/jenkins_home; do [[ -d "$h/plugins" && "$h" != "${JENKINS_HOME:-}" ]] && homes+=("$h"); done
    fi
    step "Looking for Jenkins"
    local -a real=(); for h in "${homes[@]:-}"; do [[ -n "$h" && -d "$h/plugins" ]] && real+=("$h"); done
    # running containers, unless the homes to check were named on the command line
    if [[ $# -eq 0 ]]; then
        stage_containers
        for h in "${JK_STAGED[@]:-}"; do [[ -n "$h" ]] && real+=("$h"); done
    fi
    if [[ ${#real[@]} -eq 0 ]]; then info "No Jenkins plugins directory found on the host or in a running container (set JENKINS_HOME, or pass the home directory)"; return 0; fi
    for h in "${real[@]}"; do
        found=$((found+1)); pd="$h/plugins"
        step "Jenkins home ${JK_LABEL[$h]:-$h}"
        for entry in "${PLUGINS[@]}"; do
            IFS='|' read -r n fix cves sev what <<<"$entry"
            v="$(plugin_version "$pd" "$n")" || v=""
            if [[ -z "$v" ]]; then
                # listed in the advisory and installed, but its version cannot be read: do not skip it
                if [[ -e "$pd/$n" || -e "$pd/$n.jpi" || -e "$pd/$n.hpi" || -e "$pd/$n.jpi.disabled" || -e "$pd/$n.hpi.disabled" ]]; then
                    present=$((present+1)); caution "${n} is installed but its version could not be read (no Plugin-Version in its manifest): confirm it is at least ${fix} in the Plugin Manager"; rc=1
                fi
                continue
            fi
            present=$((present+1))
            disabled=""; [[ -e "$pd/$n.jpi.disabled" || -e "$pd/$n.hpi.disabled" ]] && disabled=1
            st="$(jver_status "$v" "$fix")"
            case "$st" in
                fixed)     ok "${n} ${v}" ;;
                affected)
                    if [[ -n "$disabled" ]]; then inf "${n} ${v} is below ${fix} (${sev}: ${what}) but is DISABLED, so it does not run: update or remove it anyway"
                    else bad "${n} ${v} is below the fixed ${fix}: ${sev}, ${what} (${cves})"; rc=1; exposed=$((exposed+1)); fi ;;
                unordered) caution "${n} ${v}: same build number as the fixed ${fix} but a different build: cannot order them, confirm in the Plugin Manager"; rc=1 ;;
            esac
        done
    done
    inf "${present} affected-list plugin(s) installed across ${found} Jenkins home(s)"
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No plugin below its fixed version."
    else
        warn "${exposed} plugin(s) below their fixed version. Update them in Manage Jenkins, Plugins, then restart Jenkins."
        inf "If an affected Script Security, GitLab, Gradle or Bitbucket plugin was installed while users you do not fully trust could define Pipelines or edit jobs, treat the credentials those plugins could reach as possibly exposed and rotate them"
        inf "Until then (the project's suggestion, not Jenkins's): limit who holds Pipeline authoring and Item/Configure permissions"
        inf "Advisory: https://www.jenkins.io/security/advisory/2026-09-16/"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Jenkins plugin advisory of 16 September 2026 (CVE-2026-92122 to CVE-2026-92141)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
