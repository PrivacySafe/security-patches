#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: manual page checker  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Checks that the manual pages and the info manual work on Debian, Ubuntu, Red Hat
# and the distributions built on them, which all read manuals with man-db, and on
# systems that use mandoc. It uses whichever of these tools it finds and says which it
# skipped:
#
#   always    every page has a name line that whatis and apropos can read, no page has
#             a character outside ASCII (so none shows as <U+...> in the C locale),
#             and hyphenation is off (so a command or a setting name is never split)
#   groff     no warnings from groff -ww
#   mandoc    no warnings from mandoc -T lint (the stricter checker BSD and Alpine use)
#   man-db    every page renders through man, with groff warnings on; mandb builds an
#             index with no complaints and whatis finds every page
#   info      the info manual opens, has a directory entry, and install-info accepts it
#
# Usage:
#   packaging/check-manuals.sh MANDIR
#
# MANDIR holds man7/ and man8/ (plain or gzipped pages). It can be the folder gen-docs.py
# wrote, or usr/share/man of an extracted .deb or .rpm. The info manual is taken from
# MANDIR/psf-security-patches.info, or from ../info beside an installed man folder.
# Nothing in MANDIR is changed: the checks that write an index work on a copy.
#
# Exit code: 0 everything that could be checked passed, 1 something failed.
#
# =============================================================================
set -uo pipefail

[ $# -eq 1 ] && [ -d "$1" ] || { sed -n '/^# Usage:/,/^# Exit code/p' "$0" | sed '$d;s/^# \{0,1\}//'; exit 2; }
SRC="$(cd "$1" && pwd)"
FAIL=0
pass() { echo "  ok    $*"; }
fail() { echo "  FAIL  $*"; FAIL=$((FAIL + 1)); }
skip() { echo "  skip  $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# Work on a plain copy, so gzipped and plain pages are treated alike and nothing in the input changes.
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/man/man7" "$WORK/man/man8" "$WORK/info"
for sec in 7 8; do
    for f in "$SRC"/man$sec/*.$sec "$SRC"/man$sec/*.$sec.gz; do
        [ -f "$f" ] || continue
        b="$(basename "$f" .gz)"
        case "$f" in *.gz) gzip -dc "$f" > "$WORK/man/man$sec/$b" ;; *) cp "$f" "$WORK/man/man$sec/$b" ;; esac
    done
done
INFO=""
for c in "$SRC/psf-security-patches.info" "$SRC/psf-security-patches.info.gz" "$SRC/../info/psf-security-patches.info.gz" "$SRC/../info/psf-security-patches.info"; do
    [ -f "$c" ] && { INFO="$c"; break; }
done
if [ -n "$INFO" ]; then
    case "$INFO" in *.gz) gzip -dc "$INFO" > "$WORK/info/psf-security-patches.info" ;; *) cp "$INFO" "$WORK/info/psf-security-patches.info" ;; esac
    gzip -9n < "$WORK/info/psf-security-patches.info" > "$WORK/info/psf-security-patches.info.gz"
fi
PAGES=( "$WORK"/man/man8/*.8 "$WORK"/man/man7/*.7 )
[ -f "${PAGES[0]}" ] || { echo "no manual pages found under $SRC"; exit 1; }
echo "Checking ${#PAGES[@]} manual pages from $SRC"

# man-db's own binary. On a minimized container image "man" is a stub and the real one is man.REAL.
MAN=""
for c in man.REAL man; do
    have "$c" || continue
    "$c" --version 2>/dev/null | grep -q 'man-db' && { MAN="$c"; break; }
done

echo "Always:"
bad=0
for p in "${PAGES[@]}"; do
    l="$(awk '/^\.SH NAME/{f=1; next} f && /^\./{next} f{print; exit}' "$p")"
    echo "$l" | grep -qE '^[A-Za-z0-9\\.-]+ \\- .{8,}' || { bad=$((bad + 1)); fail "$(basename "$p"): the line after .SH NAME is not 'name \\- description' ($l)"; }
done
[ $bad -eq 0 ] && pass "every page has a name line that whatis and apropos can read"
bad=0; for p in "${PAGES[@]}"; do LC_ALL=C grep -q -P '[^\x00-\x7F]' "$p" && { bad=$((bad + 1)); fail "$(basename "$p") has a character outside ASCII"; }; done
[ $bad -eq 0 ] && pass "every page is plain ASCII"
bad=0; for p in "${PAGES[@]}"; do grep -q '^\.nh' "$p" || { bad=$((bad + 1)); fail "$(basename "$p") does not turn hyphenation off"; }; done
[ $bad -eq 0 ] && pass "hyphenation is off in every page"
bad=0; for p in "${PAGES[@]}"; do grep -qE '^\.TH [^ ]+ [78] "[0-9]{4}-[0-9]{2}-[0-9]{2}" ' "$p" || { bad=$((bad + 1)); fail "$(basename "$p"): the .TH line has no ISO date"; }; done
[ $bad -eq 0 ] && pass "every .TH line has an ISO date"

echo "groff:"
if have groff; then
    bad=0; for p in "${PAGES[@]}"; do w="$(groff -man -Tutf8 -ww -z "$p" 2>&1 | head -2)"; [ -n "$w" ] && { bad=$((bad + 1)); fail "$(basename "$p"): $w"; }; done
    [ $bad -eq 0 ] && pass "no warnings from groff -ww"
else skip "groff is not installed"; fi

echo "mandoc:"
if have mandoc; then
    bad=0; for p in "${PAGES[@]}"; do w="$(mandoc -T lint -W warning "$p" 2>&1 | head -2)"; [ -n "$w" ] && { bad=$((bad + 1)); fail "$(basename "$p"): $w"; }; done
    [ $bad -eq 0 ] && pass "no warnings from mandoc -T lint"
else skip "mandoc is not installed"; fi

echo "man-db:"
if [ -n "$MAN" ] && have mandb && have whatis; then
    bad=0
    for p in "${PAGES[@]}"; do
        b="$(basename "$p")"; name="${b%.*}"; sec="${b##*.}"
        out="$(MANWIDTH=80 LC_ALL=C "$MAN" --warnings -M "$WORK/man" "$sec" "$name" 2>&1 >/dev/null | head -2)"
        [ -n "$out" ] && { bad=$((bad + 1)); fail "man $sec $name: $out"; continue; }
        MANWIDTH=80 LC_ALL=C "$MAN" -M "$WORK/man" "$sec" "$name" 2>/dev/null | col -bx | grep -q . || { bad=$((bad + 1)); fail "man $sec $name printed nothing"; }
    done
    [ $bad -eq 0 ] && pass "every page renders through man-db, with warnings on, in the C locale"
    err="$(mandb -q -c -C /dev/null "$WORK/man" 2>&1 | head -3)"
    [ -z "$err" ] && pass "mandb builds an index with no complaint" || fail "mandb: $err"
    n="$(whatis -w -l -M "$WORK/man" 'psf-*' 2>/dev/null | grep -vciE 'unknown subject| - *$')"
    [ "$n" -eq "${#PAGES[@]}" ] && pass "whatis finds all $n pages, each with a description" || fail "whatis finds $n of ${#PAGES[@]} pages with a description"
else skip "man-db (man, mandb, whatis) is not installed"; fi

echo "info:"
if [ -z "$INFO" ]; then skip "no info manual found next to the man pages"
else
    grep -q 'START-INFO-DIR-ENTRY' "$WORK/info/psf-security-patches.info" && pass "the info manual has a directory entry" || fail "the info manual has no directory entry"
    if have info; then
        n="$(INFOPATH="$WORK/info" info psf-security-patches --subnodes -o - 2>/dev/null | grep -c '^File: psf-security-patches.info,  Node:')"
        [ "$n" -gt 10 ] && pass "info opens it by name from the gzipped file ($n nodes)" || fail "info could not open psf-security-patches (found $n nodes)"
    else skip "info is not installed"; fi
    if have install-info; then
        install-info --dir-file="$WORK/info/dir" "$WORK/info/psf-security-patches.info.gz" >/dev/null 2>&1 && grep -q '(psf-security-patches)' "$WORK/info/dir" && pass "install-info accepts it" || fail "install-info does not accept the info manual"
    else skip "install-info is not installed"; fi
fi

echo
if [ $FAIL -eq 0 ]; then echo "manual pages: all checks that could run passed"; exit 0; fi
echo "manual pages: $FAIL check(s) failed"; exit 1

# Assisted-by: Claude Sonnet 5.5
