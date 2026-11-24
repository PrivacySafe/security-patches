#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Optimizely Web Experimentation supply-chain compromise ("OPTIMJACK"): checker  (v1)
# No CVE at time of writing (disclosed 16-17 Nov 2026 by Scott Helme / Report URI)
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
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-17"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
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
    echo "Optimizely Web Experimentation supply-chain compromise, OPTIMJACK (no CVE at time of writing)"
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
