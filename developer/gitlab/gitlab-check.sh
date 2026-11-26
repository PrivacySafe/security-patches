#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# GitLab security releases of October 2026: read-only checker  (v5)
# CVE-2026-16301, CVE-2026-92883, CVE-2026-14814, CVE-2026-81839, CVE-2026-96893,
# CVE-2026-15723, CVE-2026-112212
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# GitLab's critical patch release of 12 October 2026 (19.4.2, 19.3.5, 19.2.8) fixed 24
# vulnerabilities in Community Edition (CE) and Enterprise Edition (EE). Five of them are
# rated High and are covered here, with the affected ranges GitLab published for each:
#
#   CVE-2026-92883  8.7  CE/EE  stored cross-site scripting in syntax highlighting, through
#                              a crafted repository. From 19.1 before 19.2.8, 19.3 before
#                              19.3.5, 19.4 before 19.4.2.
#   CVE-2026-16301  8.5  CE/EE  a user with the Developer role can run CI/CD pipelines on
#                              protected branches without authorization. From 18.7 before
#                              19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-14814  8.2  CE/EE  a permissive regular expression in repository file access
#                              lets a user poison the cache of raw repository files, so
#                              other users' pipelines run crafted content and protected
#                              variables can be exposed. Every version before 19.2.8, 19.3
#                              before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-81839  7.7  EE only  after a project is transferred, scheduled pipeline
#                              execution policy records are not cleaned up, so pipelines
#                              run with the new group's privileges. From 18.1 before
#                              19.2.8, 19.3 before 19.3.5, 19.4 before 19.4.2.
#   CVE-2026-96893  7.3  EE only  prompt injection in the GitLab Duo Agent Platform: crafted
#                              content in the AI conversation context can cause unintended
#                              commands attributed to other users. From 19.1 before 19.2.8,
#                              19.3 before 19.3.5, 19.4 before 19.4.2. (GitLab rates it High.)
#
# GitLab published fixes for those three lines only. Every line below 19.2 (19.1, 19.0 and
# all 18.x) is affected by the ones whose range reaches it: the fix there is to move to a
# fixed release of a supported line. 19.5 is not listed as affected.
#
# The critical patch release of 21 October 2026 (19.5.1, 19.4.3, 19.3.6, plus backports of its
# critical fix to 19.2.9, 19.1.9, 19.0.10 and 18.11.13) added two more High flaws:
#
#   CVE-2026-15723   8.2  CE/EE  account takeover: when OmniAuth SAML and LDAP auto-linking are
#                              both enabled, an authenticated user can take over an existing
#                              LDAP-backed account, because the LDAP email lookup used during
#                              identity linking does not sanitize its input. From 10.1 before
#                              19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1.
#   CVE-2026-112212  7.5  CE/EE  cache poisoning of the OAuth and OpenID Connect discovery
#                              document, so an attacker without an account can point some
#                              sign-in flows at a server they control (it needs a shared cache).
#                              From 18.3 before 19.3.6, 19.4 before 19.4.3, 19.5 before 19.5.1.
#
# Those two are fixed on 19.3.6, 19.4.3 and 19.5.1 only. The backports of 19.2.9 and older carry
# the regular-expression fix alone, so 19.2.9 is NOT a full fix for this set. The Medium and Low
# flaws of both releases are not checked here.
#
# The two regular-expression flaws of October (CVE-2026-97229 and CVE-2026-110264) are
# covered by the runtimes/ruby/ checker in this collection; run both. Each flaw has its own fixed
# versions, so being current for one says nothing about the other.
#
# The version is read from GitLab's own VERSION file (Omnibus: <root>/embedded/service/
# gitlab-rails/VERSION, or version-manifest.txt; source installs: /home/git/gitlab/VERSION)
# and from the tags of gitlab/gitlab-ce and gitlab/gitlab-ee images known to docker or
# podman. The edition (Community or Enterprise) matters for CVE-2026-81839 and CVE-2026-96893
# and is read from the package or image marker (-ee, -ce), the manifest's product name, or the
# presence of GitLab's ee directory. If it cannot be read, the script says those flaws apply
# only to Enterprise Edition rather than skipping them.
#
# GitLab published no indicators of exploitation for these flaws, so there is no hunt.
# This script is read-only.
#
# Usage:
#   ./gitlab-check.sh [command]
#   check (default)  Exit 0 = nothing exposed, 1 = an install without a fix.
#   version          print the script version.
#
# Env: GITLAB_ROOT         Omnibus root (default /opt/gitlab)
#      GITLAB_SOURCE_DIRS  source install directories (default /home/git/gitlab)
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="gitlab-check.sh"
SCRIPT_VERSION="5.1.0"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }
# ---------- version rules ----------------------------------------------------
# One row per flaw: id|cvss|edition|introduced|fixed patch per branch|what
# "introduced" is the first affected release line (0.0 = every version). A line below the
# highest fixed line that has no fixed patch listed is affected with no fix available.
GL_CVES=(
"CVE-2026-92883|8.7|any|19.1|19.2:8 19.3:5 19.4:2|stored cross-site scripting in syntax highlighting"
"CVE-2026-16301|8.5|any|18.7|19.2:8 19.3:5 19.4:2|a Developer can run pipelines on protected branches"
"CVE-2026-14814|8.2|any|0.0|19.2:8 19.3:5 19.4:2|poisoned raw-file cache runs crafted content in pipelines"
"CVE-2026-81839|7.7|ee|18.1|19.2:8 19.3:5 19.4:2|pipelines run with a new group's privileges after a transfer"
"CVE-2026-96893|7.3|ee|19.1|19.2:8 19.3:5 19.4:2|prompt injection in the Duo Agent Platform: crafted content in the AI conversation context can cause unintended commands attributed to other users"
"CVE-2026-15723|8.2|any|10.1|19.3:6 19.4:3 19.5:1|account takeover when SAML and LDAP auto-linking are both enabled"
"CVE-2026-112212|7.5|any|18.3|19.3:6 19.4:3 19.5:1|OAuth and OpenID Connect discovery cache poisoning, redirecting sign-in flows"
)

# gitlab_state <X.Y.Z> <introduced X.Y> "<fixed list>"  ->  notaffected | affected | nofix | fixed | unknown
gitlab_state() {
    local v="$1" intro="$2" fixed="$3" maj min pat imaj imin key top=0 want="" ent
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    imaj="${intro%%.*}"; imin="${intro##*.}"
    (( maj < imaj || (maj == imaj && min < imin) )) && { echo notaffected; return; }
    key=$(( maj * 1000 + min ))
    for ent in $fixed; do
        local b="${ent%%:*}" p="${ent##*:}" bk
        bk=$(( ${b%%.*} * 1000 + ${b##*.} )); (( bk > top )) && top=$bk
        (( bk == key )) && want="$p"
    done
    if [[ -n "$want" ]]; then (( pat >= want )) && echo fixed || echo affected; return; fi
    (( key > top )) && echo fixed || echo nofix
}

# the fixed patch release for this line, or empty
gitlab_fix_for() { local v="$1" fixed="$2" ent; for ent in $fixed; do [[ "${v%.*}" == "${ent%%:*}" ]] && { echo "${ent%%:*}.${ent##*:}"; return; }; done; }

# edition from a marker: ee | ce | unknown
gitlab_edition_of() {
    case "$1" in
        *gitlab-ee*|*-ee|*-ee.*|*"-ee "*) echo ee ;;
        *gitlab-ce*|*-ce|*-ce.*|*"-ce "*) echo ce ;;
        *) echo unknown ;;
    esac
}

# "<kind>|<where>|<version>|<edition>" for each install found
gitlab_installs() {
    local root="${GITLAB_ROOT:-/opt/gitlab}" f v d rt img ed man
    f="$root/embedded/service/gitlab-rails/VERSION"; man="$root/version-manifest.txt"
    if [[ -r "$f" || -r "$man" ]]; then
        v=""; ed=unknown
        if [[ -r "$f" ]]; then v="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -n1)"; head -n1 "$f" 2>/dev/null | grep -qiE '^[0-9]+\.[0-9]+\.[0-9]+-(pre|rc)' && [[ -n "$v" ]] && v="${v}-pre"; ed="$(gitlab_edition_of "$(head -n1 "$f" 2>/dev/null)")"; fi
        if [[ -r "$man" ]]; then
            [[ -n "$v" ]] || v="$(head -n1 "$man" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
            [[ "$ed" != unknown ]] || ed="$(gitlab_edition_of "$(head -n1 "$man" 2>/dev/null)")"
        fi
        [[ "$ed" != unknown ]] || { [[ -d "$root/embedded/service/gitlab-rails/ee" ]] && ed=ee; }
        echo "omnibus|${root}|${v}|${ed}"
    fi
    # shellcheck disable=SC2086
    for d in ${GITLAB_SOURCE_DIRS:-/home/git/gitlab}; do
        [[ -r "$d/VERSION" ]] || continue
        v="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$d/VERSION" 2>/dev/null | head -n1)"
        head -n1 "$d/VERSION" 2>/dev/null | grep -qiE '^[0-9]+\.[0-9]+\.[0-9]+-(pre|rc)' && [[ -n "$v" ]] && v="${v}-pre"
        ed="$(gitlab_edition_of "$(head -n1 "$d/VERSION" 2>/dev/null)")"
        [[ "$ed" != unknown ]] || { [[ -d "$d/ee" ]] && ed=ee; }
        echo "source|${d}|${v}|${ed}"
    done
    for rt in docker podman; do
        have "$rt" || continue
        while IFS= read -r img; do
            [[ -n "$img" ]] || continue
            v="$(grep -oE ':[0-9]+\.[0-9]+\.[0-9]+' <<<"$img" | tr -d ':' | head -n1)"
            case "$img" in *gitlab-ee*) ed=ee ;; *gitlab-ce*) ed=ce ;; *) ed=unknown ;; esac
            echo "${rt} image|${img}|${v}|${ed}"
        done < <("$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)gitlab/gitlab-(ce|ee):' | sort -u)
    done
}

cmd_check() {
    local rc=0 found=0 line kind where v ed row id cvss need intro fixed what st fx nbad
    step "Looking for GitLab"
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        found=$((found+1)); IFS='|' read -r kind where v ed <<<"$line"
        step "GitLab ${v:-unknown}, edition ${ed:-unknown} (${kind}: ${where})"
        [[ -n "$v" ]] || { caution "could not read a version"; rc=1; continue; }
        nbad=0
        for row in "${GL_CVES[@]}"; do
            IFS='|' read -r id cvss need intro fixed what <<<"$row"
            st="$(gitlab_state "$v" "$intro" "$fixed")"
            if [[ "$st" == unknown ]]; then
                if [[ "$v" == *-pre ]]; then caution "${v} is a pre-release build, not a release: it may not have the fixes. Upgrade to a released version"
                else caution "cannot interpret version '${v}'"; fi
                nbad=$((nbad+1)); rc=1; break
            fi
            [[ "$st" == fixed || "$st" == notaffected ]] && continue
            if [[ "$need" == ee && "$ed" == ce ]]; then inf "${id} (${cvss}) applies to Enterprise Edition only; this is Community Edition"; continue; fi
            nbad=$((nbad+1)); fx="$(gitlab_fix_for "$v" "$fixed")"
            local sev="CVSS ${cvss}"
            if [[ "$need" == ee && "$ed" != ee ]]; then
                caution "${id} (${sev}): ${what}. Applies to Enterprise Edition only and the edition could not be read: if this is EE it is exposed"; rc=1; continue
            fi
            if [[ "$st" == affected ]]; then bad "${id} (${sev}): ${what}. Fixed in ${fx}"
            else bad "${id} (${sev}): ${what}. the ${v%.*} line moves to a fixed GitLab release"; fi
            rc=1
        done
        [[ $nbad -eq 0 ]] && ok "no flaw in this set applies to ${v}"
        case "$kind" in *image*) [[ $nbad -eq 0 ]] || inf "this is an image on disk, not necessarily a running container: pull a fixed tag and recreate the container" ;; esac
    done < <(gitlab_installs)
    [[ $found -eq 0 ]] && info "No GitLab found (Omnibus under ${GITLAB_ROOT:-/opt/gitlab}, source under ${GITLAB_SOURCE_DIRS:-/home/git/gitlab}, or gitlab/gitlab-ce and gitlab-ee images)"
    step "Verdict"
    if [[ $found -gt 0 && $rc -eq 0 ]]; then info "No exposed GitLab found (${found} checked)."
    elif [[ $rc -ne 0 ]]; then
        warn "Exposed GitLab found. Upgrade to 19.5.1, 19.4.3 or 19.3.6."
        inf "Move to 19.5.1, 19.4.3 or 19.3.6: only these carry every fix in this set and the October regular-expression fixes. 19.2.9 and the older backports (19.1.9, 19.0.10, 18.11.13) carry only the regular-expression fix, so they leave the flaws above open"
        inf "If CVE-2026-14814 applied, CI/CD variables that pipelines could read may have been exposed too: rotate protected variables"
        inf "If CVE-2026-15723 applied (SAML and LDAP auto-linking both on), review LDAP-backed accounts for sign-ins you do not recognize"
        inf "Until you can upgrade (the project's suggestion, not GitLab's): take the instance off the public internet, or restrict it at the reverse proxy or firewall to trusted networks"
        inf "The October regular-expression flaws are a separate problem: run the runtimes/ruby/ checker as well"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "GitLab: CVE-2026-16301, -92883, -14814, -81839, -96893, -15723, -112212"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
