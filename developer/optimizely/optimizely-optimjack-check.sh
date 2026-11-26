#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# psf-run: manual (check needs the site: --url URL or --file PATH)
# =============================================================================
# Optimizely Web Experimentation supply-chain compromise ("OPTIMJACK"): checker  (v1)
# CVE-2026-132224 (published 18 Nov 2026; disclosed 16-17 Nov 2026 by Scott Helme / Report URI); on CISA's KEV list since 24 Nov 2026
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On 16 November 2026 an attacker got write access to many unrelated customer
# projects on Optimizely's Web Experimentation platform and injected a loader
# into each project's "Project JavaScript" field, the one piece of custom code
# that runs on every page of every experiment in that project. The file is
# still served from cdn.optimizely.com with Optimizely's own certificate, so
# nothing about where it comes from looks wrong: detection has to look at what
# the file actually contains. Report URI found 188 infected snippets across
# 178 organisations (Zoom, the BBC, CNN, Salesforce, GitLab, IKEA, HSBC and
# many others); Optimizely has since fixed the vulnerability and removed the
# injected code, and by 16 Nov 23:11 UTC Report URI found every snippet clean.
# The main command-and-control domain, 1688360.cc, was put on clientHold at
# 17 Nov 00:37 UTC and no longer resolves; this incident is winding down, not
# live, but a site that was compromised still needs to check what was taken
# and whether write access to its Optimizely account is still open.
#
# What the injected code did: swapped cryptocurrency addresses in page text,
# the clipboard and outgoing requests; skimmed payment card fields eMudhra's
# hosted payment frames (Stripe, Adyen) were out of its reach, a site's own
# form fields were not; sent cookies and page screenshots to the attacker;
# and on iPhones and iPads loaded the Coruna (iOS 13-17) or DarkSword (iOS 18.x)
# exploit kit through a hidden iframe. Three variants were seen: a plain
# <script src> to the attacker's domain, the same URL hidden in base64 behind
# atob() specifically so a text search for the domain would miss it, and a
# full inline copy run through eval() as a fallback when the domain was
# blocked. A restrictive script-src defeated the first and third; allowing
# 'unsafe-eval' or 'strict-dynamic' let either straight through, which is why
# Report URI found only 24 of 256 sites they checked were fully protected.
#
# "check" and "hunt" are read-only and make no changes. "check" reads one
# Optimizely snippet (by URL or a local file you've already saved) and looks
# for all three variants: the literal attacker domains, any atob() argument
# that decodes to one of them, the known markers and telemetry channel codes
# the payload set, and the two published SHA-256 builds of the payload file
# itself. "hunt" does the same search across a directory of saved pages, JS
# files or a CDN cache, for finding a copy you already have on disk. Nothing
# here mitigates anything: there is no local fix, because the compromise was
# on Optimizely's side and Optimizely has already removed the injected code.
# What is left to do is site-side: see "What to do now" in the README.
#
# Usage:
#   ./optimizely-optimjack-check.sh [command] [options]
#
#   check (default)  read-only. --url URL fetches and scans one snippet (needs
#                    curl); --file PATH scans a file already saved to disk.
#                    Exactly one of the two is required. Exit 0 = nothing
#                    found, 1 = a known indicator found, 2 = could not be
#                    fetched or read.
#   hunt PATH ...     read-only. Scans each PATH (a file, or a directory
#                    searched recursively) for the same indicators. Useful for
#                    a saved CDN cache, a static export or a backup. Exit 0 =
#                    nothing found, 1 = a lead, 2 = nothing readable at any PATH.
#   csp              read-only. --header VALUE checks a Content-Security-Policy
#                    header value you supply; --url URL fetches the header
#                    from a live response instead. Reports whether it would
#                    have blocked, partly blocked, or let through this
#                    payload, the same four categories Report URI used.
#   rules            prints a starting Content-Security-Policy line that would
#                    have blocked every part of this payload.
#   version          print the script version and exit
#
# Env overrides:
#   IOC_DOMAINS   space-separated, replaces the embedded attacker domain list
#                 (testing only; the built-in list is what this script checks
#                 by default and should not normally need replacing)
# =============================================================================
set -uo pipefail
SELF="$0"
SCRIPT_NAME="optimizely-optimjack-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
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
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- indicators ---------------------------------------------------------------------------
# Domains the attacker controlled. Confirmed independently by Report URI and corroborated by The
# Register and other coverage. 1688360.cc was the main C2 (track.js, card.php, hit.php); the .icu
# domains served the iOS router and exploit chains; webshell.lol and linkforge.cc belong to an
# earlier wave by the same actor. All are reported taken down or unresponsive as of 17 Nov 2026,
# which does not change whether a cached copy of the payload on your own disk still names them.
declare -a IOC_DOMAIN_LIST=(
    "1688360.cc" "5vobauua3ojpklx.icu" "eil786npto9u5bq.icu" "l7bcsnwc7nzr3uo.icu"
    "webshell.lol" "linkforge.cc" "je4ft3gn8vxudum.icu" "q1ls1ho9x7wsxlu.icu" "ios-hack.icu"
    "p55abnw2pnsz0bo.icu" "1y69gy2mdzaltz1.icu" "gm38duxoihbmy5o.icu"
)
if [[ -n "${IOC_DOMAINS:-}" ]]; then read -r -a IOC_DOMAIN_LIST <<<"$IOC_DOMAINS"; fi

# Global variables and attributes the payload set on an infected page, keyed by the regex that
# finds them with a plain label for the person reading the output.
declare -A IOC_MARKERS=(
    ["window\\._k7\\b"]="the global window._k7"
    ["window\\.__k7b\\b"]="the global window.__k7b"
    ['data-channel-code="02111110"']="the iOS-loader script attribute data-channel-code=\"02111110\""
    ["BIGNIAO"]="the Coruna telemetry channel code BIGNIAO"
)

# The attacker's own wallet addresses, published by Report URI. A clipper has to carry the address
# it swaps *to* somewhere in its own code, so these are as specific an indicator as the domains,
# and worth checking even where the domain itself has been further hidden beyond the atob() case
# already handled above.
declare -A IOC_WALLETS=(
    [19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW]="BTC"
    [0xC4026b06D82b0F0B363eda0642D61CfbDc17884e]="ETH/EVM (also used on BSC)"
    [THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa]="TRON"
    [FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n]="Solana"
    [UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p]="TON"
    [ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5]="Litecoin"
    [qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58]="Bitcoin Cash"
    [DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5]="Dogecoin"
)

# SHA-256 of two published builds of the payload file itself (the attacker rebuilt it 26 times
# during the day; these two are the ones Report URI published a hash for).
declare -A IOC_HASHES=(
    [814A963C0DA480E2449D9B6664480156E1CD6D731014117401BF635BADEC3A0F]="track.js build, 17:13 UTC 16 Nov"
    [F7B84B9A94F749F8CED3F0112D0A66894E8BBC3B4AA5592021D1B8976A9BAD40]="track.js build, 17:57 UTC 16 Nov (latest)"
)

# scan_text FILE LABEL: prints CRIT/ok lines for FILE, returns 0 if clean, 1 if something matched
scan_text() {
    local f="$1" label="$2" hit=0 d m w got hash
    [[ -r "$f" ]] || { caution "$label: could not read it"; return 2; }

    for d in "${IOC_DOMAIN_LIST[@]}"; do
        if grep -qF "$d" "$f" 2>/dev/null; then
            bad "$label: names the attacker domain $d"
            hit=1
        fi
    done

    # The base64/atob() evasion: decode every atob('...') or atob("...") argument found and check
    # the result for an attacker domain. A plain string search for the domain would miss this.
    while IFS= read -r m; do
        [[ -n "$m" ]] || continue
        got="$(printf '%s' "$m" | base64 -d 2>/dev/null || true)"
        for d in "${IOC_DOMAIN_LIST[@]}"; do
            if [[ "$got" == *"$d"* ]]; then
                bad "$label: an atob() argument decodes to the attacker domain $d (base64-hidden variant)"
                hit=1
            fi
        done
    done < <(grep -oE "atob\\(['\"][A-Za-z0-9+/=]+['\"]\\)" "$f" 2>/dev/null \
              | sed -E "s/^atob\\(['\"]//; s/['\"]\\)\$//")

    for m in "${!IOC_MARKERS[@]}"; do
        if grep -qE "$m" "$f" 2>/dev/null; then
            bad "$label: carries ${IOC_MARKERS[$m]}"
            hit=1
        fi
    done

    for w in "${!IOC_WALLETS[@]}"; do
        if grep -qF "$w" "$f" 2>/dev/null; then
            bad "$label: carries the attacker's published ${IOC_WALLETS[$w]} wallet address"
            hit=1
        fi
    done

    if have sha256sum; then
        hash="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1 | tr '[:lower:]' '[:upper:]')"
        if [[ -n "${IOC_HASHES[$hash]:-}" ]]; then
            bad "$label: matches a published payload build exactly (${IOC_HASHES[$hash]})"
            hit=1
        fi
    fi

    [[ $hit -eq 0 ]] && ok "$label: no known indicator found"
    return "$hit"
}

cmd_check() {
    local url="" file="" tmp rc
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --url) [[ $# -ge 2 ]] || die "--url needs a value"; url="$2"; shift 2 ;;
            --file) [[ $# -ge 2 ]] || die "--file needs a value"; file="$2"; shift 2 ;;
            *) die "Unknown option: $1 (check --url URL | --file PATH)" ;;
        esac
    done
    [[ -n "$url" || -n "$file" ]] || die "check needs --url URL or --file PATH"
    [[ -z "$url" || -z "$file" ]] || die "check takes --url or --file, not both"

    step "Optimizely snippet check"
    if [[ -n "$url" ]]; then
        have curl || die "curl is needed for --url (or save the file yourself and use --file)"
        tmp="$(mktemp "${TMPDIR:-/tmp}/psf-optimjack.XXXXXX" 2>/dev/null)" && PSF_TMP+=("$tmp")
        [[ -n "$tmp" ]] || die "could not create a temporary file"
        inf "fetching $url"
        if ! curl -fsSL --max-time 20 -o "$tmp" "$url" 2>/dev/null; then
            caution "could not fetch $url"
            return 2
        fi
        scan_text "$tmp" "$url"; rc=$?
    else
        scan_text "$file" "$file"; rc=$?
    fi
    if [[ $rc -eq 0 ]]; then
        inf "a clean result here does not prove your Optimizely project was never affected: Report URI"
        inf "found the injected code was removed from every snippet by 16 Nov 23:11 UTC, so a check run"
        inf "after that time will not see it even on a project that was compromised earlier that day."
        inf "Check your project's change history (Settings > History) for the 16th regardless."
    fi
    return "$rc"
}

cmd_hunt() {
    [[ $# -gt 0 ]] || die "hunt needs at least one PATH (a file, or a directory to search)"
    step "Hunting for OPTIMJACK indicators"
    local p f any_readable=0 lead=0 degraded=0 rc file_count finderr
    for p in "$@"; do
        if [[ -f "$p" ]]; then
            any_readable=1
            scan_text "$p" "$p"; rc=$?
            [[ $rc -eq 1 ]] && lead=1
            [[ $rc -eq 2 ]] && degraded=1
        elif [[ -d "$p" ]]; then
            if [[ ! -r "$p" || ! -x "$p" ]]; then
                caution "$p: cannot be searched (permission denied)"
                degraded=1
                continue
            fi
            file_count=0
            finderr="$(mktemp "${TMPDIR:-/tmp}/psf-optimjack-finderr.XXXXXX" 2>/dev/null)" && PSF_TMP+=("$finderr")
            while IFS= read -r -d '' f; do
                file_count=$((file_count+1))
                any_readable=1
                scan_text "$f" "$f"; rc=$?
                [[ $rc -eq 1 ]] && lead=1
                [[ $rc -eq 2 ]] && degraded=1
            done < <(find "$p" -type f \( -iname '*.js' -o -iname '*.html' -o -iname '*.htm' \) -print0 2>"$finderr")
            # A permission-denied subdirectory under $p makes find skip it and write a line to
            # stderr rather than failing outright, which is the only sign that the search of $p
            # was not complete.
            [[ -n "$finderr" && -s "$finderr" ]] && { degraded=1; caution "$p: $(head -n1 "$finderr")"; }
            [[ $file_count -eq 0 ]] && inf "$p: no .js, .html or .htm file found under it"
        else
            caution "$p: not a file or directory"
            degraded=1
        fi
    done
    if [[ $any_readable -eq 0 && $lead -eq 0 ]]; then
        inf "nothing readable was found under any of the given paths."
        return 2
    fi
    if [[ $lead -eq 1 ]]; then
        bad "found at least one known indicator. Treat the matching file's project as compromised:"
        bad "check its Optimizely change history, rotate account credentials and API tokens, and"
        bad "treat cards or secrets handled by the matching page on 16 November as exposed."
        return 1
    fi
    if [[ $degraded -eq 1 ]]; then
        caution "not everything given could be read or searched; this is not a confirmed clean result."
        return 2
    fi
    ok "no known indicator found in anything readable."
    return 0
}

cmd_csp() {
    local header="" url="" got_header=0 got_url=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --header) [[ $# -ge 2 ]] || die "--header needs a value (an empty policy is --header '')"; header="$2"; got_header=1; shift 2 ;;
            --url) [[ $# -ge 2 ]] || die "--url needs a value"; url="$2"; got_url=1; shift 2 ;;
            *) die "Unknown option: $1 (csp --header VALUE | --url URL)" ;;
        esac
    done
    [[ $got_header -eq 1 || $got_url -eq 1 ]] || die "csp needs --header VALUE or --url URL"
    [[ $got_header -eq 0 || $got_url -eq 0 ]] || die "csp takes --header or --url, not both"

    step "CSP evaluation against this payload"
    if [[ -n "$url" ]]; then
        have curl || die "curl is needed for --url"
        local headers
        if ! headers="$(curl -fsSI --max-time 20 "$url" 2>/dev/null)"; then
            caution "could not fetch $url"
            return 2
        fi
        inf "fetched from $url"
        local cspcount roheader
        cspcount="$(grep -ci '^content-security-policy:' <<<"$headers")"
        if [[ "$cspcount" -gt 1 ]]; then
            caution "this response sends $cspcount Content-Security-Policy headers; a browser enforces the intersection of all of them (the strictest reading wins), but this command only evaluates the first one below. The real effective policy may already be stricter than this result suggests."
        fi
        header="$(grep -i '^content-security-policy:' <<<"$headers" | head -n1 | cut -d: -f2-)"
        header="$(echo "$header" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/\r$//')"
        roheader="$(grep -i '^content-security-policy-report-only:' <<<"$headers" | head -n1)"
        if [[ -z "$header" && -n "$roheader" ]]; then
            caution "no enforcing Content-Security-Policy, only Content-Security-Policy-Report-Only, which reports violations but blocks nothing"
        fi
    fi
    if [[ -z "$header" ]]; then
        bad "no enforcing Content-Security-Policy header: nothing here would have blocked any part of this payload"
        return 1
    fi
    inf "header: $header"
    local rc=0
    if echo "$header" | grep -qE "strict-dynamic|'unsafe-eval'"; then
        bad "allows 'strict-dynamic' or 'unsafe-eval': the loader and the eval() inline fallback both run anyway"
        rc=1
    else
        ok "no 'strict-dynamic' or 'unsafe-eval': the loader script tag and the eval() fallback are both blocked"
    fi
    if ! echo "$header" | grep -qiE 'connect-src|default-src'; then
        caution "no connect-src (or default-src) restriction found: card, cookie and screenshot exfiltration would reach the attacker uncontrolled"
        rc=1
    else
        ok "connect-src or default-src present: exfiltration to an undeclared host should be blocked"
    fi
    if ! echo "$header" | grep -qiE 'frame-src|child-src|default-src'; then
        caution "no frame-src (or default-src) restriction found: the iOS exploit-kit iframe is not blocked"
        rc=1
    fi
    [[ $rc -eq 0 ]] && ok "this policy would have blocked every part of this payload"
    return "$rc"
}

cmd_rules() {
    step "A starting CSP against this payload"
    cat <<'EOF'
Content-Security-Policy:
    default-src 'self';
    script-src 'self' cdn.optimizely.com;
    connect-src 'self';
    frame-src 'none';
    report-uri /csp-reports;

This blocks the loader <script> tag, the eval() inline fallback ('unsafe-eval' is not listed), the
exfiltration of card, cookie and screenshot data (connect-src), and the iOS exploit-kit iframe
(frame-src). It does not stop clipboard or page-text cryptocurrency address swapping: that happens
inside the already-trusted Optimizely script's own execution, which a CSP has no way to distinguish
from any other code that script runs. Replace cdn.optimizely.com with your own domain if you serve
your snippet from it (README has examples). Start with Content-Security-Policy-Report-Only to see
what would have broken before you enforce it.
EOF
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Optimizely Web Experimentation supply-chain compromise, OPTIMJACK (CVE-2026-132224)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        csp) cmd_csp "$@" ;;
        rules) cmd_rules "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|csp|rules|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5
