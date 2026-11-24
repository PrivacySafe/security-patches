#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# iTerm2 terminal-reply command execution, November 2026: check and file scan (v1)
# No CVE at time of writing (researcher ii4gsp; fixed in iTerm2 3.7.9, 20 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The rest of this collection is for GNU/Linux. iTerm2 is a macOS terminal, and this flaw
# reaches the machines administrators use to run everything else, so this tool checks Macs.
# Its scan command runs on GNU/Linux as well, to look through repositories and downloads.
#
# iTerm2 3.6.1 to 3.7.8 answer a Kitty graphics file-transfer request with an error reply
# that keeps the control characters from the request. A file that carries such a request,
# shown with "cat README.md", makes iTerm2 type the attacker's text into your shell, which
# runs it: in bash, zsh and fish, on a default install. All you see is a few shell errors.
# The setting "Disable potentially insecure escape sequences" does not cover it. 3.7.9 (macOS
# 13 or later) strips control characters from every reply; macOS 12.4 to 12.x has no fixed
# release, because its newest iTerm2 is 3.6.11.
#
# Usage:
#   ./iterm2-kitty-check.sh [command] [arguments]
#
#   check (default)  Read-only. Finds every iTerm2 copy (/Applications, each
#                    user's ~/Applications, Homebrew's Caskroom, and Spotlight
#                    where it answers), reads its version and judges it
#                    against 3.6.1 to 3.7.8, and says whether this macOS can
#                    run the fix. Exit 0 = no affected copy, 1 = an affected
#                    copy, 2 = a copy whose version could not be read.
#   scan PATH...     Read-only. Looks through files under each PATH for the
#                    Kitty graphics escape sequence the attack hides in text
#                    (ESC _ G), and lists files with other escape sequences
#                    that make a terminal answer (APC, DCS, device status
#                    requests) for a look by hand. Runs on macOS and GNU/Linux.
#                    Exit 0 = nothing found, 1 = files found, 2 = bad argument.
#   version          Prints the script version.
#
# The fix is iTerm2 3.7.9 or later (iTerm2 > Check for Updates), then quit and reopen it:
# a window that is still open runs the old code. Until then, read files from others with
# "less" (which shows escape characters as ^[ instead of sending them to the terminal) or in
# an editor, not with cat, head or tail.
#
# Env overrides:
#   APP_DIRS="/Applications /Users/*/Applications"   where to look for iTerm.app
#   MACOS_VERSION      the macOS version, instead of sw_vers (testing only)
#   SCAN_MAX_SIZE=20   largest file scan reads, in MB
# Works with the bash 3.2 that macOS ships.
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="iterm2-kitty-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"
FIRST_AFFECTED="3.6.1"   # Kitty image file transfer arrived in 3.6.1; 3.6.0 answers "Unimplemented"
FIXED="3.7.9"
APP_DIRS="${APP_DIRS:-/Applications /Users/*/Applications /opt/homebrew/Caskroom/iterm2 /usr/local/Caskroom/iterm2}"
SCAN_MAX_SIZE="${SCAN_MAX_SIZE:-20}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
bad()     { echo -e "  ${RED}x${NC} $*"; }
inf()     { echo -e "  - $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# ver_cmp A B: prints -1, 0 or 1. Numeric, dot by dot, so it works without sort -V (bash 3.2, BSD sort).
ver_cmp() {
    awk -v a="$1" -v b="$2" 'BEGIN { na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb ? na : nb)
        for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p < q) { print -1; exit } if (p > q) { print 1; exit } } print 0 }'
}

# The version in an app bundle's Info.plist, binary or XML, without needing the app to run.
plist_version() {
    local p="$1/Contents/Info.plist" v=""
    [[ -f "$p" && -r "$p" ]] || return 0   # -f: never read a link to a FIFO or a device
    if have plutil; then v="$(plutil -extract CFBundleShortVersionString raw -o - "$p" 2>/dev/null)"; fi
    if [[ -z "$v" ]] && have defaults; then v="$(defaults read "${p%.plist}" CFBundleShortVersionString 2>/dev/null)"; fi
    if [[ -z "$v" ]]; then
        v="$(tr -d '\r' < "$p" | awk '/<key>CFBundleShortVersionString<\/key>/ { getline; gsub(/.*<string>|<\/string>.*/, ""); print; exit }')"
    fi
    printf '%s' "$v"
}

find_apps() {
    local d a
    for d in $APP_DIRS; do
        [[ -d "$d" ]] || continue
        for a in "$d"/iTerm.app "$d"/iTerm2.app "$d"/*/iTerm.app "$d"/*/iTerm2.app; do
            [[ -d "$a" ]] && echo "$a"
        done
    done
    if have mdfind && [[ -z "${APP_DIRS_ONLY:-}" ]]; then
        mdfind "kMDItemCFBundleIdentifier == 'com.googlecode.iterm2'" 2>/dev/null
    fi
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments"
    local os app v n=0 affected=0 unknown=0 old_os=0 seen=" "
    os="${MACOS_VERSION:-}"
    if [[ -z "$os" ]] && have sw_vers; then os="$(sw_vers -productVersion 2>/dev/null)"; fi
    step "This Mac"
    if [[ -z "$os" ]]; then
        inf "not macOS: iTerm2 runs only on macOS. Use 'scan' here to look through files"
    else
        inf "macOS ${os}"
        [[ "$(ver_cmp "$os" 13)" -lt 0 ]] && old_os=1
    fi
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || caution "not running as root: other users' ~/Applications may not be readable. Run it with sudo to check every account"

    step "iTerm2 copies"
    while IFS= read -r app; do
        [[ -n "$app" ]] || continue
        case "$seen" in *" $app "*) continue ;; esac
        seen="${seen}${app} "
        n=$((n + 1))
        v="$(plist_version "$app")"
        if [[ ! "$v" =~ ^[0-9]+(\.[0-9]+)+ ]]; then
            unknown=$((unknown + 1)); caution "${app}: version '${v:-?}' could not be read"
        elif [[ "$(ver_cmp "$v" "$FIRST_AFFECTED")" -lt 0 ]]; then
            inf "${app}: ${v}, older than ${FIRST_AFFECTED}, which has no Kitty file transfer: not affected by this flaw (update anyway: older releases have other fixes missing)"
        elif [[ "$(ver_cmp "$v" "$FIXED")" -lt 0 ]]; then
            affected=$((affected + 1)); bad "${app}: ${v}, ${RED}affected${NC} (${FIRST_AFFECTED} to 3.7.8)"
        else
            inf "${app}: ${v}, fixed"
        fi
    done < <(find_apps)
    [[ $n -gt 0 ]] || inf "no iTerm2 found in ${APP_DIRS}"

    step "Verdict"
    if [[ $affected -gt 0 ]]; then
        if [[ $old_os -eq 1 ]]; then
            warn "${affected} affected copy(ies), and macOS ${os} cannot run the fixed ${FIXED} (it needs macOS 13 or later; the newest iTerm2 for macOS 12, 3.6.11, is affected). Upgrade macOS if you can, or use another terminal (Terminal.app) for files from others."
        else
            warn "${affected} affected copy(ies). Update: iTerm2 > Check for Updates, to ${FIXED} or later, then quit and reopen iTerm2 (open windows run the old code). Until then, do not cat, head or tail files from others in iTerm2: use less or an editor. The 'Disable potentially insecure escape sequences' setting does not cover this."
        fi
        return 1
    fi
    if [[ $unknown -gt 0 ]]; then warn "${unknown} copy(ies) could not be judged: read the version in iTerm2 > About iTerm2."; return 2; fi
    info "No affected iTerm2 found."
    return 0
}

# ---------- scan -------------------------------------------------------------
# The attack hides a Kitty graphics command in text: ESC _ G ... ESC \ (an APC string). A file
# with one has no business being shown in a terminal. Other strings that make a terminal answer
# (any other APC, a DCS such as DECRQSS, a device status or attribute request) are listed for a
# look by hand: they appear in some legitimate captures and test files too.
cmd_scan() {
    [[ $# -gt 0 ]] || die "scan needs at least one file or folder"
    local p f hits=0 review=0 esc kitty apc dcs maxkb
    for p in "$@"; do [[ -e "$p" ]] || die "Not found: ${p}"; done
    esc="$(printf '\033')"; kitty="${esc}_G"; apc="${esc}_"; dcs="${esc}P"
    maxkb=$((SCAN_MAX_SIZE * 1024))
    step "Files with escape sequences that make a terminal answer"
    while IFS= read -r f; do
        if LC_ALL=C grep -qF -- "$kitty" "$f" 2>/dev/null; then
            hits=$((hits + 1)); bad "${f}: a Kitty graphics command (ESC _ G): do not show this file in iTerm2 before ${FIXED}"
        elif LC_ALL=C grep -qF -- "$apc" "$f" 2>/dev/null || LC_ALL=C grep -qF -- "$dcs" "$f" 2>/dev/null \
             || LC_ALL=C grep -qE -- "${esc}\\[[0-9;]*[56]n|${esc}\\[[>=]?c" "$f" 2>/dev/null; then
            review=$((review + 1)); caution "${f}: escape sequences that ask the terminal for a reply (APC, DCS or a status request): look at it with less before showing it in a terminal"
        fi
    done < <(for p in "$@"; do find "$p" -type d -name .git -prune -o -type f -size -"${maxkb}"k -print 2>/dev/null; done \
             | while IFS= read -r f; do LC_ALL=C grep -lF -- "$esc" "$f" 2>/dev/null; done)
    step "Verdict"
    if [[ $hits -gt 0 ]]; then warn "${hits} file(s) carry the escape sequence this attack uses. Find where each came from."; return 1; fi
    if [[ $review -gt 0 ]]; then warn "${review} file(s) ask a terminal for replies (above): read them with less, not cat."; return 1; fi
    info "No file asks the terminal for a reply."
    return 0
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "iTerm2 3.6.1 to 3.7.8: a file shown in the terminal can type commands into your shell; fixed in ${FIXED}"
    case "$CMD" in
        check) cmd_check "$@" ;;
        scan) cmd_scan "$@" ;;
        *) die "Unknown command: ${CMD} (check|scan|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
