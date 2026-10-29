#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PHP2Shell edge guard tester  (v1)
# CVE-2026-109618 / CVE-2026-109619
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Checks that an edge guard from this folder (the Apache .conf, the Apache
# .htaccess or the nginx snippets) behaves the way you think it does on a given
# URL. It sends a handful of small, benign requests (a form field named "a"
# with the value "b", never exploit content) and reads the status codes. It
# needs only bash and curl, and nothing on the server being tested.
#
# A pass here shows the tested URL behaves as described. It does not show a
# server is safe from either CVE, does not cover other paths or virtual hosts,
# and cannot tell which component refused a request. Patching PHP is the fix.
#
# Usage:
#   ./php2shell-edge-test.sh [options] URL
#
#   --expect MODE    block     (default) the guard is enforcing: a multipart
#                              POST to URL must get 403
#                    dry-run   the .htaccess dry run: a multipart POST must NOT
#                              get 403 and must carry X-PHP2Shell-Guard
#                    log-only  the .conf or nginx log-only mode: a multipart
#                              POST must NOT get 403 (add --log FILE to also
#                              confirm the guard logged it)
#   --allow PATH     a path on your allowlist (for example /wp-admin/async-
#                    upload.php). A multipart POST to it must NOT get 403, and
#                    one to PATH.bak must get 403 when enforcing
#   --log FILE       a log the guard writes to; used with --expect log-only
#   --host NAME      send this Host header (the URL may be 127.0.0.1)
#   --insecure       do not verify a TLS certificate
#   -h, --help, version
#
# Exit codes: 0 every check passed, 1 at least one failed, 2 usage error or
# the server could not be reached.
#
# Content-Type variants: PHP parses a body as multipart for the plain value, any
# letter case, a comma instead of a semicolon, and a space before the
# semicolon, all of which start with "multipart/form-data". It does not treat a
# value with leading whitespace as multipart (as parsed by PHP 8.3). The checks
# below send exactly the variants PHP does parse.
# =============================================================================
set -uo pipefail

SCRIPT_NAME="php2shell-edge-test.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; NC=''; }
pass() { echo -e "  ${GREEN}PASS${NC}  $*"; PASSES=$((PASSES + 1)); }
fail() { echo -e "  ${RED}FAIL${NC}  $*"; FAILS=$((FAILS + 1)); }
note() { echo -e "  ${YELLOW}note${NC}  $*"; }
die()  { echo "$*" >&2; exit 2; }

usage() { sed -n '/^# Usage:/,/^# Exit codes/p' "$0" | sed '$d;s/^# \{0,1\}//'; }

EXPECT="block"; ALLOW=""; LOGFILE=""; HOSTHDR=""; INSECURE=""; URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --expect)   EXPECT="${2:?--expect needs block, dry-run or log-only}"; shift 2 ;;
        --allow)    ALLOW="${2:?--allow needs a path}"; shift 2 ;;
        --log)      LOGFILE="${2:?--log needs a file}"; shift 2 ;;
        --host)     HOSTHDR="${2:?--host needs a name}"; shift 2 ;;
        --insecure) INSECURE="-k"; shift ;;
        -h|--help|help) usage; exit 0 ;;
        -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
        -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)  [[ -z "$URL" ]] || die "Only one URL, please"; URL="$1"; shift ;;
    esac
done
[[ -n "$URL" ]] || { usage >&2; exit 2; }
case "$EXPECT" in block|dry-run|log-only) ;; *) die "--expect must be block, dry-run or log-only" ;; esac
command -v curl >/dev/null 2>&1 || die "curl is required"
[[ "$URL" =~ ^https?://[^/]+(/.*)?$ ]] || die "URL must start with http:// or https://"

ORIGIN="$(sed -E 's#^(https?://[^/]+).*#\1#' <<<"$URL")"
PASSES=0; FAILS=0
BODY=$'--x\r\nContent-Disposition: form-data; name="a"\r\n\r\nb\r\n--x--\r\n'

# curl wrapper: prints "<status>|<guard header present 0/1>"; "000|0" if unreachable.
send() {   # <url> <curl args...>
    local u="$1"; shift
    local hargs=(); [[ -n "$HOSTHDR" ]] && hargs=(-H "Host: ${HOSTHDR}")
    local out
    out="$(curl -s ${INSECURE} -m 15 --max-redirs 0 -D - -o /dev/null -w 'STATUS:%{http_code}\n' \
            "${hargs[@]}" "$@" "$u" 2>/dev/null | tr -d '\r')" || true
    local code; code="$(sed -n 's/^STATUS://p' <<<"$out" | tail -1)"
    local mark=0; grep -qi '^x-php2shell-guard:' <<<"$out" && mark=1
    echo "${code:-000}|${mark}"
}
code_of() { echo "${1%%|*}"; }
mark_of() { echo "${1##*|}"; }

echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${URL}, expecting: ${EXPECT}"
probe="$(send "$URL" -d a=b)"
[[ "$(code_of "$probe")" != "000" ]] || die "Could not reach ${URL}"

echo
echo "Control"
c="$(code_of "$probe")"
if [[ "$c" != "403" ]]; then pass "urlencoded POST was not refused (HTTP ${c})"
else fail "urlencoded POST got 403: something other than the guard refuses it, or the guard is too broad"; fi

echo
echo "Multipart POST to ${URL}"
check_multipart() {   # <label> <curl args...>
    local label="$1"; shift
    local r c m; r="$(send "$URL" "$@")"; c="$(code_of "$r")"; m="$(mark_of "$r")"
    case "$EXPECT" in
        block)
            if [[ "$c" == "403" ]]; then pass "${label}: refused (403)"
            else fail "${label}: HTTP ${c}, expected 403"; fi ;;
        dry-run)
            if [[ "$c" != "403" && "$m" == "1" ]]; then pass "${label}: passed through and marked would-block (HTTP ${c})"
            elif [[ "$c" == "403" ]]; then fail "${label}: refused (403), but this should be the dry run"
            else fail "${label}: HTTP ${c} with no X-PHP2Shell-Guard header: the dry run is not active on this URL"; fi ;;
        log-only)
            if [[ "$c" != "403" ]]; then pass "${label}: passed through (HTTP ${c})"
            else fail "${label}: refused (403), but this should be log-only"; fi ;;
    esac
}
check_multipart "plain form (curl -F)" -F a=b
check_multipart "upper case type"   -H 'Content-Type: MULTIPART/FORM-DATA; boundary=x' --data-binary "$BODY"
check_multipart "comma separator"   -H 'Content-Type: multipart/form-data, boundary=x' --data-binary "$BODY"
check_multipart "space before ;"    -H 'Content-Type: multipart/form-data ; boundary=x' --data-binary "$BODY"
check_multipart "chunked encoding"  -H 'Transfer-Encoding: chunked' -F a=b

if [[ "$EXPECT" == "log-only" && -n "$LOGFILE" ]]; then
    [[ -r "$LOGFILE" ]] || { note "cannot read ${LOGFILE}; skipping the log check"; LOGFILE=""; }
fi
if [[ "$EXPECT" == "log-only" && -n "$LOGFILE" ]]; then
    before="$(grep -c 'php2shell-guard\|ct="' "$LOGFILE" 2>/dev/null || true)"
    send "$URL" -F a=b >/dev/null; sleep 1
    after="$(grep -c 'php2shell-guard\|ct="' "$LOGFILE" 2>/dev/null || true)"
    if [[ "${after:-0}" -gt "${before:-0}" ]]; then pass "the guard logged a multipart POST to ${LOGFILE}"
    else fail "no new guard line in ${LOGFILE}: the guard may not cover this host, or logs elsewhere"; fi
fi

echo
echo "Other requests that must not be refused"
r="$(send "$URL" -X GET -H 'Content-Type: multipart/form-data; boundary=x')"
if [[ "$(code_of "$r")" != "403" ]]; then pass "GET carrying a multipart header was not refused (HTTP $(code_of "$r"))"
else fail "GET carrying a multipart header got 403"; fi
r="$(send "$URL" -H 'Content-Type: text/plain' --data-binary x)"
if [[ "$(code_of "$r")" != "403" ]]; then pass "text/plain POST was not refused (HTTP $(code_of "$r"))"
else fail "text/plain POST got 403"; fi

if [[ -n "$ALLOW" ]]; then
    echo
    echo "Allowlist: ${ALLOW}"
    r="$(send "${ORIGIN}${ALLOW}" -F a=b)"; c="$(code_of "$r")"
    if [[ "$c" != "403" ]]; then pass "multipart POST to the allowlisted path was not refused (HTTP ${c})"
    else fail "multipart POST to the allowlisted path got 403: the allowlist does not match it"; fi
    if [[ "$EXPECT" == "block" ]]; then
        for variant in "${ALLOW}.bak" "${ALLOW}/extra" "/?x=${ALLOW}"; do
            r="$(send "${ORIGIN}${variant}" -F a=b)"; c="$(code_of "$r")"
            if [[ "$c" == "403" ]]; then pass "look-alike ${variant} refused (403)"
            else fail "look-alike ${variant} got HTTP ${c}, expected 403"; fi
        done
    fi
fi

echo
echo "${PASSES} passed, ${FAILS} failed"
[[ "$FAILS" -eq 0 ]]

# Assisted-by: Claude Sonnet 5.5
