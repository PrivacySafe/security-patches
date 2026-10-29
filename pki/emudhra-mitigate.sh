#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# eMudhra intermediate CA compromise, interim mitigation  (v1)
# Disclosed 20 Oct 2026: https://emudhra.we-have-a-problem.com/
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The private keys of eight eMudhra intermediate CAs can be recovered from
# their certificates. Browsers block them through OneCRL, CRLite and CRLSets,
# but the system CA store, and everything that reads it (OpenSSL, GnuTLS, curl,
# wget, apt, git, Python, PHP, Go, Ruby, Java via ca-certificates-java), keeps
# trusting them until ca-certificates is updated. This script distrusts the
# roots that anchor them and then proves the store rejects all of them.
#
# Usage:
#   ./emudhra-mitigate.sh [command] [--force] [--ignore-env]
#
#   check            environment report only; changes nothing, root optional
#                    (exit 0 = ok, 1 = hard blocker, 2 = needs --ignore-env)
#   apply (default)  distrust the affected certificates in the system store,
#                    rebuild it, fix the Java keystore, and verify
#   status           mitigation state, store tests and stale processes
#   restore          undo everything this script distrusted (re-exposes you
#                    if ca-certificates isn't patched)
#   cleanup          once ca-certificates is patched: remove this script's
#                    distrust, but only if the store still rejects every
#                    compromised intermediate afterwards (--force skips the
#                    patch check, never the store test)
#   version          print the script version and exit
#
#   --ignore-env     proceed past soft environment blockers (a running
#                    process or system-wide override uses a CA store this run
#                    can't fix). Hard blockers (non-Debian, no
#                    update-ca-certificates, no openssl, not root) can't be
#                    overridden.
#
# Every command first checks, in order: OS (Debian, Ubuntu, Trisquel and
# popular derivatives), the system CA store and its package, other CA stores
# (Java, Python certifi and other bundles, Node.js, NSS, overrides), then system
# (root, container, tools). The system store's patch state is reported from
# three signals: the fixed build for your release, extra FIXED_BUILDS, and the
# package changelog. The verdict that matters is functional: every command
# tests each store against the 16 published intermediate certificates, which
# are embedded below and checked against their published SHA-256 fingerprints.
#
# Env overrides:
#   FIXED_BUILDS="20250419~deb12u2"   extra fixed ca-certificates builds
#   SCAN_PATHS="/opt /srv ..."         where to look for bundled CA files;
#                                      empty disables the scan
#   SCAN_DEPTH=9                       find -maxdepth for that scan
#   TEST_HOSTS="api.example.com:443"   hosts to TLS-test before and after
#                                      apply, to catch collateral breakage
#   JAVA_STOREPASS=changeit            Java keystore password
#
# Debian/Ubuntu/Trisquel layout: /etc/ca-certificates.conf and
# update-ca-certificates. A "!" line in that file survives package upgrades
# (the ca-certificates postinst and debconf config keep deselected entries).
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
# Fixed ca-certificates builds per release, from the disclosure page (20 Oct 2026)
declare -A FIXED_BY_RELEASE=(
    [debian:12]="20250419~deb12u2"
    [debian:13]="20250419+deb13u1"
    [debian:testing]="20260816+nmu1"
    [debian:unstable]="20260816+nmu1"
    [ubuntu:22.04]="20260816ubuntu0.22.04.1"
    [ubuntu:24.04]="20260816ubuntu0.24.04.1"
    [ubuntu:26.04]="20260816ubuntu0.26.04.1"
    [ubuntu:26.10]="20260816ubuntu0.26.10.1"
)
FIXED_BUILDS="${FIXED_BUILDS:-}"
# A ca-certificates changelog that names either of these bug numbers (from the
# disclosure page) carries the fix. Note CVE-2026-111943 is NOT used here: that
# CVE is the Go standard library's own crypto/x509 denylist (fixed in Go
# 1.26.10 / 1.27.3), not the ca-certificates fix, so a ca-certificates
# changelog won't cite it. Chainguard reused that CVE id for its own
# ca-certificates package, but Debian/Ubuntu track this by the bug numbers.
CHANGELOG_RE='LP: ?#2171507|#1151413'
# Builds of ca-certificates and ca-certificates-java dated on or after this
# day count as updated. The date is the newest changelog entry's, and only
# when that entry is the installed build. Override with MIN_PKG_DATE.
MIN_PKG_DATE="${MIN_PKG_DATE:-2026-08-30}"
# Fixed releases of software that ships its own roots (report only)
declare -A NODE_FIXED=([22]=22.23.4 [24]=24.22.1 [26]=26.12.1)
NSS_FIXED=3.131.1
CERTIFI_FIXED=2026.10.19
PIP_FIXED=26.2.2

SCAN_PATHS="${SCAN_PATHS-/opt /srv /usr/local /usr/lib /usr/share /home /root /var/www}"
SCAN_DEPTH="${SCAN_DEPTH:-9}"
TEST_HOSTS="${TEST_HOSTS:-}"
JAVA_STOREPASS="${JAVA_STOREPASS:-changeit}"

CERTS_CONF=/etc/ca-certificates.conf
SHARE_DIR=/usr/share/ca-certificates
LOCAL_DIR=/usr/local/share/ca-certificates
CERTS_DIR=/etc/ssl/certs
SYS_BUNDLE=/etc/ssl/certs/ca-certificates.crt
JAVA_KS=/etc/ssl/certs/java/cacerts
STATE_DIR=/var/lib/emudhra-mitigation
STATE="${STATE_DIR}/state"
BACKUP_BASE=/var/backups/emudhra-mitigation
# the process id keeps two runs in the same second from sharing a directory and overwriting the first backup
BACKUP_DIR="${BACKUP_BASE}/$(date +%Y%m%d-%H%M%S)-$$"
MARKER="# managed-by: emudhra-mitigation"
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"   # testing hook
# All verification runs at this instant (2026-09-21 UTC), inside the validity
# of every test certificate, so expiry can never pass for distrust
ATTIME=1790000000
SELF="$0"
SCRIPT_NAME="emudhra-mitigate.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"

# Every certificate in the trust path, keyed by SHA-256 of its
# SubjectPublicKeyInfo. Matching on the key catches every certificate for it:
# self-signed roots, cross-signs and copies added by hand. The two cross-
# signers' keys aren't compromised; distrusting them is the collateral cost
# until the patched package arrives (see README).
declare -A AFFECTED_SPKI=(
    [EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105]="EM DV TLS CA - G3B - compromised key"
    [43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B]="EM OV TLS CA - G3B - compromised key"
    [E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41]="EM EV TLS CA - G3B - compromised key"
    [49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F]="EM DV TLS CA - G3C - compromised key"
    [63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8]="EM OV TLS CA - G3C - compromised key"
    [5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0]="EM EV TLS CA - G3C - compromised key"
    [EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6]="EM OV CS CA - G3B - compromised key"
    [92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30]="EM OV CS CA - G3C - compromised key"
    [C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9]="emSign Root TLS CA - G3 - issues the compromised TLS intermediates"
    [0A6C2B2CA5B364207954171987AC9D2178561569D8205457E77CA90C32EDE282]="emSign Root CS CA - G3 - issues the compromised code-signing intermediates"
    [BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3]="AAA Certificate Services - Sectigo root that cross-signs all eight"
    [8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782]="emSign ECC Root CA - G3 - cross-signs emSign Root TLS CA - G3"
)
declare -A AFFECTED_SHA256=(
    [42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493]="EM DV TLS CA - G3B - issued by emSign Root TLS CA - G3"
    [45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE]="EM DV TLS CA - G3B - issued by AAA Certificate Services"
    [98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B]="EM OV TLS CA - G3B - issued by emSign Root TLS CA - G3"
    [5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699]="EM OV TLS CA - G3B - issued by AAA Certificate Services"
    [E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838]="EM EV TLS CA - G3B - issued by emSign Root TLS CA - G3"
    [579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512]="EM EV TLS CA - G3B - issued by AAA Certificate Services"
    [0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19]="EM DV TLS CA - G3C - issued by emSign Root TLS CA - G3"
    [62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72]="EM DV TLS CA - G3C - issued by AAA Certificate Services"
    [CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F]="EM OV TLS CA - G3C - issued by emSign Root TLS CA - G3"
    [7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489]="EM OV TLS CA - G3C - issued by AAA Certificate Services"
    [432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3]="EM EV TLS CA - G3C - issued by emSign Root TLS CA - G3"
    [FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F]="EM EV TLS CA - G3C - issued by AAA Certificate Services"
    [9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4]="EM OV CS CA - G3B - issued by emSign Root CS CA - G3"
    [A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8]="EM OV CS CA - G3B - issued by AAA Certificate Services"
    [4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1]="EM OV CS CA - G3C - issued by emSign Root CS CA - G3"
    [84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD]="EM OV CS CA - G3C - issued by AAA Certificate Services"
    [7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D]="emSign Root TLS CA - G3 - root"
    [F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5]="emSign Root CS CA - G3 - root"
    [D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4]="AAA Certificate Services - root"
    [86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B]="emSign ECC Root CA - G3 - root"
    [3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD]="emSign Root TLS CA - G3 - cross-signed by emSign ECC Root CA - G3"
)

# The leaked private keys, keyed by SPKI-SHA256: each intermediate's private
# key is this small integer d, so its public key is d·G on P-384. The check
# recomputes d·G with OpenSSL and compares, so the compromise is proven on
# your machine rather than taken on trust.
# Source: the emudhra-verification project, after
# https://mastodon.catgirl.cloud/@49016/117474217042191790
declare -A LEAKED_D=(
    [63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8]=4     # EM OV TLS CA - G3C
    [5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0]=56    # EM EV TLS CA - G3C
    [EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6]=66    # EM OV CS CA - G3B
    [E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41]=115   # EM EV TLS CA - G3B
    [43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B]=155   # EM OV TLS CA - G3B
    [EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105]=156   # EM DV TLS CA - G3B
    [49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F]=230   # EM DV TLS CA - G3C
    [92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30]=237   # EM OV CS CA - G3C
)

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
step()  { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()   { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }

have_systemd() { [[ -d /run/systemd/system ]]; }
svc_hint() { if have_systemd; then echo "systemctl $1 $2"; else echo "service $2 $1"; fi; }
in_list() { [[ " $2 " == *" $1 "* ]]; }

# ---------- test certificates ------------------------------------------------
# Writes the embedded certificates to $TDIR/test and checks each against its
# published SHA-256. A mismatch means the script was damaged in transit.
TDIR=""; TEST_NAMES=(); TEST_FILES=(); SELFTEST_ERR=""
setup_tests() {
    TDIR="$(mktemp -d /tmp/emudhra.XXXXXX)"
    trap 'rm -rf "${TDIR:-/nonexistent}"' EXIT
    mkdir -p "$TDIR/test" "$TDIR/empty"
    test_cert_blob | awk -v d="$TDIR/test" '
        /^-----BEGIN/ { inside = 1 }
        !inside && NF == 2 { name = $1; want[name] = $2; next }
        inside { print > (d "/" name ".pem") }
        /^-----END/ { inside = 0; close(d "/" name ".pem") }
        END { for (n in want) print n, want[n] > (d "/SHA256SUMS") }'
    local n want got
    while read -r n want; do
        got="$(openssl x509 -in "$TDIR/test/$n.pem" -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
        [[ "${got^^}" == "$want" ]] || SELFTEST_ERR+="$n "
    done < "$TDIR/test/SHA256SUMS"
    mv "$TDIR/test/cross.pem" "$TDIR/cross.pem"
    while read -r n; do
        TEST_NAMES+=("$n"); TEST_FILES+=("$TDIR/test/$n.pem")
    done < <(cut -d' ' -f1 "$TDIR/test/SHA256SUMS" | grep -vx cross | sort)
}

# Proves the compromise locally: rebuilds each intermediate's public key from
# its leaked d and compares it with the certificate. The DER is an RFC 5915
# ECPrivateKey on secp384r1 with no public key; OpenSSL computes d·G itself.
# Sets PROOF_OK (count) and PROOF_ERR (names that didn't reproduce).
PROOF_OK=0; PROOF_ERR=""
prove_keys() {
    PROOF_OK=0; PROOF_ERR=""
    local n spki d hex got
    for n in "${TEST_NAMES[@]}"; do
        [[ "$n" == *.em ]] || continue
        spki="$(openssl x509 -in "$TDIR/test/$n.pem" -noout -pubkey 2>/dev/null \
                | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
        d="${LEAKED_D[${spki^^}]:-}"
        [[ -n "$d" ]] || { PROOF_ERR+="${n%.em} "; continue; }
        hex="303e0201010430$(printf '%096x' "$d")a00706052b81040022"
        got="$(printf '%b' "$(sed 's/../\\x&/g' <<<"$hex")" \
               | openssl ec -inform DER -pubout -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
        if [[ "$got" == "$spki" ]]; then PROOF_OK=$((PROOF_OK + 1)); else PROOF_ERR+="${n%.em} "; fi
    done
}

# One test certificate against one store, isolated from every other store.
# OpenSSL loads its default file and directory unless told otherwise, even
# with -CAfile, so the defaults are pointed at an empty directory.
verify_test() {   # file|dir|default <store> <cert>  ->  OK | REJECT | ERR:<code>
    local -a envs=() args=(verify -attime "$ATTIME" -untrusted "$TDIR/cross.pem")
    local out code
    case "$1" in
        file)    envs=("SSL_CERT_DIR=$TDIR/empty" "SSL_CERT_FILE=$TDIR/empty/none"); args+=(-CAfile "$2") ;;
        dir)     envs=("SSL_CERT_DIR=$TDIR/empty" "SSL_CERT_FILE=$TDIR/empty/none"); args+=(-CApath "$2") ;;
        default) ;;
    esac
    if out="$(env "${envs[@]+"${envs[@]}"}" openssl "${args[@]}" "$3" 2>&1)" && [[ "$out" == *": OK"* ]]; then
        echo OK; return
    fi
    code="$(sed -nE 's/^error ([0-9]+) at .*/\1/p' <<<"$out" | head -1)"
    # 2/20: issuer not trusted. 23: revoked. 28: rejected by trust settings.
    case "$code" in 2|20|23|28) echo REJECT ;; *) echo "ERR:${code:-load}" ;; esac
}

# Tests all 16. Sets FT_OK (names trusted) and FT_ERR. Returns 0 if the store
# rejects every one, 1 if it trusts any, 2 if some results are inconclusive.
FT_OK=(); FT_ERR=()
store_check() {
    FT_OK=(); FT_ERR=()
    local n r
    for n in "${TEST_NAMES[@]}"; do
        r="$(verify_test "$1" "$2" "$TDIR/test/$n.pem")"
        case "$r" in OK) FT_OK+=("$n") ;; REJECT) ;; *) FT_ERR+=("$n:${r#ERR:}") ;; esac
    done
    [[ ${#FT_OK[@]} -eq 0 ]] || return 1
    [[ ${#FT_ERR[@]} -eq 0 ]] || return 2
    return 0
}

ft_summary() {
    local em=0 aaa=0 n
    for n in "${FT_OK[@]+"${FT_OK[@]}"}"; do [[ "$n" == *.aaa ]] && aaa=$((aaa + 1)) || em=$((em + 1)); done
    if [[ ${#FT_OK[@]} -gt 0 ]]; then
        echo "TRUSTS ${#FT_OK[@]} of ${#TEST_NAMES[@]} compromised intermediates (via emSign: ${em}, via AAA: ${aaa})"
    elif [[ ${#FT_ERR[@]} -gt 0 ]]; then
        echo "inconclusive for ${#FT_ERR[@]} of ${#TEST_NAMES[@]} (${FT_ERR[*]})"
    else
        echo "rejects all ${#TEST_NAMES[@]} compromised intermediates"
    fi
}

# Batched test of a PEM bundle: prints how many it trusts, or "?" if OpenSSL
# can't read it as a bundle
bundle_ok_count() {
    local out
    grep -q 'BEGIN CERTIFICATE' "$1" 2>/dev/null || { echo "?"; return; }
    out="$(SSL_CERT_DIR="$TDIR/empty" SSL_CERT_FILE="$TDIR/empty/none" \
           openssl verify -attime "$ATTIME" -CAfile "$1" -untrusted "$TDIR/cross.pem" "${TEST_FILES[@]}" 2>&1 || true)"
    if grep -qiE 'error loading file|unable to load' <<<"$out"; then echo "?"; return; fi
    grep -cE ': OK$' <<<"$out" || true
}

# ---------- certificate identity ---------------------------------------------
cert_ids() {   # <file>  ->  "<SHA256> <SPKI-SHA256>" of its first certificate
    local out fp spki
    out="$(openssl x509 -in "$1" -noout -fingerprint -sha256 -pubkey 2>/dev/null)" || return 1
    fp="$(sed -n 's/^.*Fingerprint=//p' <<<"$out" | tr -d ':')"
    spki="$(sed -n '/BEGIN PUBLIC KEY/,/END PUBLIC KEY/p' <<<"$out" \
            | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | cut -d' ' -f1 || true)"
    echo "${fp^^} ${spki^^}"
}

affected_label() {   # <sha256> <spki> -> label, or nothing
    local l="${AFFECTED_SPKI[$2]:-}"
    [[ -n "$l" ]] || l="${AFFECTED_SHA256[$1]:-}"
    echo "$l"
}

count_certs() { grep -c 'BEGIN CERTIFICATE' "$1" 2>/dev/null || echo 0; }

# Affected certificates inside a PEM bundle, by key, one label per line.
# This catches what a path test can't: Go and GnuTLS accept a non-self-signed
# certificate in the store as an anchor, OpenSSL by default doesn't.
bundle_affected() {   # <bundle>
    local d="$TDIR/split" f ids label
    rm -rf "$d"; mkdir -p "$d"
    awk -v d="$d" '/BEGIN CERTIFICATE/ { n++; out = d "/" n ".pem" } out { print > out }
                   /END CERTIFICATE/ { close(out); out = "" }' "$1" 2>/dev/null || return 0
    for f in "$d"/*.pem; do
        [[ -e "$f" ]] || continue
        ids="$(cert_ids "$f")" || continue
        label="$(affected_label "${ids% *}" "${ids#* }")"
        if [[ -n "$label" ]]; then echo "$label"; fi
    done
}

# Affected certificates the system store can pick up. Fills:
#   M_CONF   "rel|label"  under /usr/share/ca-certificates, selected in the conf
#   M_OFF    "rel|label"  same, already deselected ("!") in the conf
#   M_UNSEL  "rel|label"  same, not listed in the conf (not trusted)
#   M_LOCAL  "path|label" under /usr/local/share/ca-certificates (always trusted)
#   M_LOOSE  "path|label" in /etc/ssl/certs but not from either directory
M_CONF=(); M_OFF=(); M_UNSEL=(); M_LOCAL=(); M_LOOSE=()
scan_sources() {
    M_CONF=(); M_OFF=(); M_UNSEL=(); M_LOCAL=(); M_LOOSE=()
    local f rel ids label t
    while IFS= read -r -d '' f; do
        ids="$(cert_ids "$f")" || continue
        label="$(affected_label "${ids% *}" "${ids#* }")"; [[ -n "$label" ]] || continue
        rel="${f#"${SHARE_DIR}"/}"
        if grep -qxF "!${rel}" "$CERTS_CONF" 2>/dev/null; then M_OFF+=("${rel}|${label}")
        elif grep -qxF "$rel" "$CERTS_CONF" 2>/dev/null; then M_CONF+=("${rel}|${label}")
        else M_UNSEL+=("${rel}|${label}"); fi
    done < <(find "$SHARE_DIR" -type f -name '*.crt' -print0 2>/dev/null)
    while IFS= read -r -d '' f; do
        ids="$(cert_ids "$f")" || continue
        label="$(affected_label "${ids% *}" "${ids#* }")"
        if [[ -n "$label" ]]; then M_LOCAL+=("${f}|${label}"); fi
    done < <(find "$LOCAL_DIR" -name '*.crt' \( -type f -o -type l \) -print0 2>/dev/null)
    # Files dropped straight into /etc/ssl/certs, or links to elsewhere
    while IFS= read -r -d '' f; do
        [[ "$f" == "$SYS_BUNDLE" ]] && continue
        t="$(readlink -f "$f" 2>/dev/null || true)"
        [[ -n "$t" && -f "$t" ]] || continue
        case "$t" in "$SHARE_DIR"/*|"$LOCAL_DIR"/*|"$SYS_BUNDLE") continue ;; esac
        # Links to another entry here (rehash's <hash>.0 links) follow that
        # entry, which this loop examines itself; rehash removes them with it
        if [[ -L "$f" && "$t" == "$CERTS_DIR"/* ]]; then continue; fi
        ids="$(cert_ids "$f")" || continue
        label="$(affected_label "${ids% *}" "${ids#* }")"
        if [[ -n "$label" ]]; then M_LOOSE+=("${f}|${label}"); fi
    done < <(find "$CERTS_DIR" -maxdepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
    return 0
}

# ---------- patch detection --------------------------------------------------
# Returns 0 if the newest changelog entry is the installed build and the
# changelog names this incident, 1 if it doesn't, 2 if there's no usable
# changelog. Like php2shell: a changelog only counts if it's current.
changelog_lists() {   # <package> <installed version>
    local cl rc=2
    for cl in "/usr/share/doc/$1/changelog.Debian.gz" "/usr/share/doc/$1/changelog.gz"; do
        [[ -f "$cl" ]] || continue
        [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"($2)"* ]] || continue
        if zgrep -qE "$CHANGELOG_RE" "$cl"; then return 0; fi
        rc=1
    done
    return $rc
}

# Build date of the installed package: the trailer of the newest changelog
# entry, only when that entry is the installed version (a stale changelog left
# by a docs-stripped image can't vouch for anything). Prints YYYY-MM-DD.
pkg_build_date() {   # <package> <installed version>
    local cl line
    for cl in "/usr/share/doc/$1/changelog.Debian.gz" "/usr/share/doc/$1/changelog.gz"; do
        [[ -f "$cl" ]] || continue
        [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"($2)"* ]] || continue
        line="$(zcat "$cl" 2>/dev/null | grep -m1 '^ -- ' || true)"
        line="${line##*>  }"
        date -u -d "$line" +%F 2>/dev/null && return 0
    done
    return 1
}

# When dpkg last installed or upgraded the package on this machine
pkg_install_date() {   # <package>
    local f
    for f in "/var/lib/dpkg/info/$1.list" "/var/lib/dpkg/info/$1:all.list"; do
        [[ -f "$f" ]] && { date -u -d "@$(stat -c %Y "$f")" +%F; return 0; }
    done
    return 1
}

# Is the installed build dated on or after MIN_PKG_DATE? Sets DATE_HOW;
# returns 0 yes, 1 no, 2 no usable changelog (docs stripped)
pkg_date_status() {   # <package> <installed version>
    local built inst
    inst="$(pkg_install_date "$1" || true)"
    if ! built="$(pkg_build_date "$1" "$2")"; then
        DATE_HOW="no changelog to date it${inst:+, installed ${inst}}"; return 2
    fi
    DATE_HOW="built ${built}${inst:+, installed ${inst}}"
    if [[ ! "$built" < "$MIN_PKG_DATE" ]]; then DATE_HOW+=", on or after ${MIN_PKG_DATE}"; return 0; fi
    DATE_HOW+=", before ${MIN_PKG_DATE}"; return 1
}

# ca-certificates. Sets PATCH_HOW and DATE_HOW; returns 0 patched, 1 not,
# 2 can't tell. Signals, strongest first:
#   1. installed build >= the fixed build for this release (or FIXED_BUILDS)
#   2. the changelog names this incident
#   3. the build is dated on or after MIN_PKG_DATE, when no fixed build is
#      known for this release (a known fixed build always outranks a date)
# Whatever this says, the store tests decide, and cleanup re-tests.
REL_KEY=""
ca_patch_status() {
    local full v f x below="" clrc=0 drc=0
    PATCH_HOW=""; DATE_HOW=""
    full="$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null || true)"
    [[ -n "$full" ]] || { PATCH_HOW="ca-certificates isn't installed"; return 2; }
    v="${full#*:}"
    pkg_date_status ca-certificates "$v" || drc=$?
    f="${FIXED_BY_RELEASE[$REL_KEY]:-}"
    if [[ -n "$f" ]]; then
        if dpkg --compare-versions "$v" ge "$f" 2>/dev/null; then PATCH_HOW="${v} >= fixed build ${f} (${REL_KEY}); ${DATE_HOW}"; return 0; fi
        below="$f"
    fi
    for x in $FIXED_BUILDS; do
        # same upstream date, so a build for another release can't vouch for this one
        [[ "${x%%[!0-9]*}" == "${v%%[!0-9]*}" ]] || continue
        if dpkg --compare-versions "$v" ge "$x" 2>/dev/null; then PATCH_HOW="${v} >= fixed build ${x} (FIXED_BUILDS); ${DATE_HOW}"; return 0; fi
    done
    changelog_lists ca-certificates "$v" || clrc=$?
    if [[ $clrc -eq 0 ]]; then PATCH_HOW="${v}: changelog names this incident; ${DATE_HOW}"; return 0; fi
    if [[ -n "$below" ]]; then PATCH_HOW="${v} is older than fixed build ${below}; ${DATE_HOW}"; return 1; fi
    if [[ $drc -eq 0 ]]; then PATCH_HOW="${v}: no known fixed build for ${REL_KEY:-this release}; ${DATE_HOW}"; return 0; fi
    if [[ $drc -eq 1 ]]; then PATCH_HOW="${v}: no known fixed build for ${REL_KEY:-this release}; ${DATE_HOW}"; return 1; fi
    PATCH_HOW="${v}: no known fixed build for ${REL_KEY:-this release}; ${DATE_HOW}"; return 2
}

# ca-certificates-java. It ships no roots of its own: its jks-keystore hook
# rebuilds /etc/ssl/certs/java/cacerts from the system store whenever
# update-ca-certificates runs. Sets JPKG_HOW; returns 0 updated on or after
# MIN_PKG_DATE (or its changelog names this incident), 1 older, 2 can't
# tell, 3 not installed. The keystore test decides either way.
cajava_status() {
    local full v drc=0
    JPKG_HOW=""
    full="$(dpkg-query -W -f='${Version}' ca-certificates-java 2>/dev/null || true)"
    [[ -n "$full" ]] || { JPKG_HOW="not installed"; return 3; }
    v="${full#*:}"
    if changelog_lists ca-certificates-java "$v"; then
        pkg_date_status ca-certificates-java "$v" || true
        JPKG_HOW="${v}: changelog names this incident; ${DATE_HOW}"; return 0
    fi
    pkg_date_status ca-certificates-java "$v" || drc=$?
    JPKG_HOW="${v}: ${DATE_HOW}"
    return $drc
}

# ---------- other stores -----------------------------------------------------
# Java keystore entries for affected certificates: "alias|sha256|label"
java_matches() {   # <keystore> [keytool]
    local kt="${2:-keytool}" out
    out="$("$kt" -list -v -keystore "$1" -storepass "$JAVA_STOREPASS" 2>/dev/null)" || return 2
    awk '/^Alias name:/ { sub(/^Alias name: */, ""); a = $0 }
         /^[[:space:]]*SHA256:/ { fp = $2; gsub(":", "", fp); print a "|" fp }' <<<"$out" \
      | while IFS='|' read -r a fp; do
            if [[ -n "${AFFECTED_SHA256[$fp]:-}" ]]; then echo "${a}|${fp}|${AFFECTED_SHA256[$fp]}"; fi
        done
    return 0
}

# Node.js binaries on PATH and in the usual version-manager locations
node_bins() {
    local b
    shopt -s nullglob
    {
        command -v node nodejs 2>/dev/null || true
        for b in /usr/local/bin/node /opt/*/bin/node /home/*/.nvm/versions/node/*/bin/node \
                 /root/.nvm/versions/node/*/bin/node /usr/local/n/versions/node/*/bin/node; do
            [[ -x "$b" ]] && echo "$b"
        done
    } | while read -r b; do readlink -f "$b"; done | sort -u
    shopt -u nullglob
}

# Bundled roots of one Node.js binary -> trusted count or "?"
NODE_EXPOSED=" "
node_bundled() {
    local out="$TDIR/node-$RANDOM.pem"
    timeout 20 "$1" -e 'process.stdout.write(require("tls").rootCertificates.join("\n")+"\n")' > "$out" 2>/dev/null \
        || { echo "?"; return; }
    bundle_ok_count "$out"
}

# Candidate CA bundle files outside the system store
scan_bundles() {
    local p
    [[ -n "$SCAN_PATHS" ]] || return 0
    for p in $SCAN_PATHS; do
        [[ -d "$p" ]] || continue
        find "$p" -xdev -maxdepth "$SCAN_DEPTH" \
            \( -name .cache -o -path /var/lib/docker -o -path /var/lib/containers \
               -o -path "$BACKUP_BASE" -o -path "$SHARE_DIR" -o -path /usr/share/doc \) -prune \
            -o \( -type f -o -type l \) \( -name cacert.pem -o -name ca-bundle.crt -o -name ca-bundle.pem \
               -o -name ca-certificates.crt -o -name tls-ca-bundle.pem \) -print 2>/dev/null || true
    done
    [[ -f /home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem ]] && echo /home/linuxbrew/.linuxbrew/etc/ca-certificates/cert.pem
    return 0
}

bundle_fix_hint() {   # <path>
    local f="$1" owner prefix pyver
    owner="$(dpkg-query -S "$f" 2>/dev/null | head -1 | cut -d: -f1 || true)"
    if [[ -n "$owner" ]]; then echo "apt-get install --only-upgrade ${owner}"; return; fi
    case "$f" in
        */pip/_vendor/certifi/*)
            echo "upgrade that pip to ${PIP_FIXED}+ (python -m pip install -U pip)" ;;
        */lib/python3*/site-packages/certifi/*|*/lib/python3*/dist-packages/certifi/*)
            prefix="${f%/lib/python3*}"; pyver="${f#"${prefix}"/lib/}"; pyver="${pyver%%/*}"
            if [[ -x "${prefix}/bin/python" ]]; then echo "${prefix}/bin/python -m pip install -U 'certifi>=${CERTIFI_FIXED}'"
            elif [[ "$prefix" == /usr/local || "$prefix" == /usr ]] && command -v "$pyver" >/dev/null; then
                echo "${pyver} -m pip install -U 'certifi>=${CERTIFI_FIXED}' (add --break-system-packages if pip refuses)"
            else echo "pip install -U 'certifi>=${CERTIFI_FIXED}' for the Python that owns this path"; fi ;;
        /home/linuxbrew/*) echo "brew upgrade ca-certificates" ;;
        *) echo "update the software that ships it, or point it at ${SYS_BUNDLE}" ;;
    esac
}

# Processes that loaded a TLS library or a JVM, or are Node.js, before <epoch>: they may still
# hold the old trust in memory. One-shot tools (curl, apt, git) are fine.
stale_tls() {   # <epoch>
    local since="$1" btime hz p line rest st unit exe out=() seen=" "
    btime="$(awk '/^btime/ {print $2}' /proc/stat)"; hz="$(getconf CLK_TCK)"
    for p in /proc/[0-9]*; do
        [[ "${p#/proc/}" == "$$" || "${p#/proc/}" == 1 ]] && continue
        read -r line < "$p/stat" 2>/dev/null || continue
        rest="${line##*) }"; read -ra st <<<"$rest"
        [[ $(( btime + ${st[19]:-0} / hz )) -lt "$since" ]] || continue
        exe="$(readlink "$p/exe" 2>/dev/null || true)"; [[ -n "$exe" ]] || continue
        # Node.js often links OpenSSL statically, so match it by name
        if [[ "${exe% (deleted)}" != */node && "${exe% (deleted)}" != */nodejs ]]; then
            grep -qE '/lib(ssl|gnutls|nss3)\.so|/libjvm\.so' "$p/maps" 2>/dev/null || continue
        fi
        unit="$(sed -nE 's#.*/([^/]+\.service)$#\1#p' "$p/cgroup" 2>/dev/null | tail -1)"
        local key="${unit:-${exe% (deleted)}}"
        in_list "$key" "$seen" && continue
        seen+="$key "; out+=("$key")
    done
    printf '%s\n' "${out[@]+"${out[@]}"}"
}

host_ok() {   # host[:port] -> 0 if it verifies against the system bundle
    local h="${1%%:*}" port="${1##*:}"
    [[ "$port" == "$1" ]] && port=443
    timeout 15 env SSL_CERT_DIR="$TDIR/empty" SSL_CERT_FILE="$TDIR/empty/none" \
        openssl s_client -connect "${h}:${port}" -servername "$h" -CAfile "$SYS_BUNDLE" \
        -verify_return_error </dev/null 2>&1 | grep 'Verify return code: 0 (ok)' >/dev/null
}

# ---------- state ------------------------------------------------------------
# One line per change, tab-separated: kind, path or alias, backup, label
state_add() { mkdir -p "$STATE_DIR"; printf '%s\t%s\t%s\t%s\n' "$@" >> "$STATE"; }
backup() { mkdir -p "$BACKUP_DIR"; cp -a "$1" "$BACKUP_DIR/"; info "Backed up $1 -> $BACKUP_DIR/"; }

rebuild_store() {   # [--fresh]
    local out
    out="$(update-ca-certificates "$@" 2>&1)" || { echo "$out" | tail -5; return 1; }
    echo "$out" | grep -E 'added|removed|^W:' | sed 's/^/  /' || true
}

# Checks the rebuilt bundle is a sane store, not just that the bad certs
# left: only affected certificates may go. <affected> counts those in the
# bundle before the rebuild, so changes left pending by an interrupted run
# are expected too.
store_sane() {   # <count before> <affected before>
    local now; now="$(count_certs "$SYS_BUNDLE")"
    [[ -s "$SYS_BUNDLE" && "$now" -gt 0 ]] || { warn "$SYS_BUNDLE is empty"; return 1; }
    if [[ "$now" -lt $(( $1 - $2 )) ]]; then
        warn "$SYS_BUNDLE went from $1 to $now certificates, but only $2 of them were affected. Other changes may have been pending in $CERTS_CONF."
        return 1
    fi
    compgen -G "${CERTS_DIR}/*.0" >/dev/null || { warn "No hash links in $CERTS_DIR"; return 1; }
}

# ---------- commands ---------------------------------------------------------
# The three ways programs read the store: the bundle file (GnuTLS, Go, curl,
# Python), the hash directory, and OpenSSL's compiled-in defaults; then the
# bundle's contents, for clients that accept intermediates as anchors.
# Returns 1 if any trusts a compromised intermediate, else 2 if any test was
# inconclusive, else 0.
system_tests() {
    local trusted=0 unsure=0 r mode store label
    for mode in file dir default; do
        case $mode in
            file)    store="$SYS_BUNDLE"; label="bundle  ${SYS_BUNDLE}" ;;
            dir)     store="$CERTS_DIR";  label="hashdir ${CERTS_DIR}/" ;;
            default) store="";            label="OpenSSL defaults ($(openssl version -d 2>/dev/null | sed 's/^OPENSSLDIR: //'))" ;;
        esac
        r=0; store_check "$mode" "$store" || r=$?
        echo "  ${label}: $(ft_summary)"
        if [[ $r -eq 1 ]]; then trusted=1; elif [[ $r -eq 2 ]]; then unsure=1; fi
    done
    local inb; inb="$(bundle_affected "$SYS_BUNDLE")"
    if [[ -n "$inb" ]]; then
        echo "  bundle contents: HOLDS $(wc -l <<<"$inb") affected certificate(s): $(paste -sd';' <<<"$inb")"
        trusted=1
    else
        echo "  bundle contents: no affected certificates"
    fi
    if [[ $trusted -eq 1 ]]; then return 1; fi
    if [[ $unsure -eq 1 ]]; then return 2; fi
    return 0
}

java_fix() {
    [[ -f "$JAVA_KS" ]] || { info "No system Java keystore ($JAVA_KS)"; return 0; }
    command -v keytool >/dev/null || { warn "$JAVA_KS exists but keytool isn't installed; can't check it"; return 0; }
    local m a fp label rc=0
    m="$(java_matches "$JAVA_KS")" || rc=$?
    if [[ $rc -ne 0 ]]; then warn "Can't read $JAVA_KS (wrong JAVA_STOREPASS?)"; return 0; fi
    if [[ -z "$m" ]]; then info "Java keystore $JAVA_KS has no affected entries"; return 0; fi
    # The ca-certificates-java hook normally removed them; it can be deferred
    # (dpkg lock held, cacerts_updates=no in /etc/default/cacerts)
    warn "The ca-certificates-java hook left affected entries; removing them with keytool"
    backup "$JAVA_KS"
    while IFS='|' read -r a fp label; do
        if keytool -delete -alias "$a" -keystore "$JAVA_KS" -storepass "$JAVA_STOREPASS" >/dev/null 2>&1; then
            state_add java "$a" "$BACKUP_DIR/${JAVA_KS##*/}" "$label"; info "Removed Java alias ${a} (${label})"
        else
            warn "Could not remove Java alias ${a}"
        fi
    done <<<"$m"
    m="$(java_matches "$JAVA_KS" || true)"
    if [[ -n "$m" ]]; then warn "Java keystore still has: $(cut -d'|' -f1 <<<"$m" | xargs)"; return 1; fi
    info "Java keystore clean"
}

STATE_BEFORE=0
cmd_apply() {
    step "1/4  System CA store"
    STATE_BEFORE=0; if [[ -f "$STATE" ]]; then STATE_BEFORE="$(wc -l < "$STATE")"; fi
    scan_sources
    local e rel label before need_cross=1
    # The two cross-signing roots are distrusted only when the store actually
    # trusts a compromised intermediate. If a patched package already cut the
    # path, distrusting them would only break unrelated sites.
    if store_check file "$SYS_BUNDLE"; then
        need_cross=0; info "The store already rejects every compromised intermediate; cross-signing roots stay trusted"
    else
        info "Before: $(ft_summary)"
    fi
    for e in "${M_OFF[@]+"${M_OFF[@]}"}";   do info "Already distrusted: ${e#*|} (${e%%|*})"; done
    for e in "${M_UNSEL[@]+"${M_UNSEL[@]}"}"; do info "Present but not selected (not trusted): ${e#*|} (${e%%|*})"; done

    local -a pre_ok=()
    if [[ -n "$TEST_HOSTS" ]]; then
        for e in $TEST_HOSTS; do
            if host_ok "$e"; then pre_ok+=("$e"); else warn "TEST_HOSTS: $e fails before any change; it won't count as a regression"; fi
        done
    fi

    if [[ ${#M_CONF[@]} -eq 0 && ${#M_LOCAL[@]} -eq 0 && ${#M_LOOSE[@]} -eq 0 ]]; then
        info "No trusted copies of affected certificates in the system store"
    else
        backup "$CERTS_CONF"
        local stamp; stamp="$(date -u +%FT%TZ)"
        for e in "${M_CONF[@]+"${M_CONF[@]}"}"; do
            rel="${e%%|*}"; label="${e#*|}"
            if [[ $need_cross -eq 0 && "$label" == *cross-signs* ]]; then
                info "Leaving ${label} trusted (not needed)"; continue
            fi
            # In place, with a marker comment above; the postinst keeps both
            awk -v r="$rel" -v m="${MARKER} ${stamp}: ${label}; undo with ${SELF} restore" \
                '$0 == r { print m; print "!" r; next } { print }' "$CERTS_CONF" > "$TDIR/conf"
            cat "$TDIR/conf" > "$CERTS_CONF"
            state_add conf "$rel" "-" "$label"
            info "Distrusted ${label} (${rel})"
        done
        local p kind bn nmoved=0
        for e in "${M_LOCAL[@]+"${M_LOCAL[@]}"}" "${M_LOOSE[@]+"${M_LOOSE[@]}"}"; do
            [[ -n "$e" ]] || continue
            p="${e%%|*}"; kind=local
            [[ "$p" == "$CERTS_DIR"/* ]] && kind=loose
            # numbered, because two files with the same name from different directories would
            # overwrite each other, and restore would then put the wrong certificate back
            nmoved=$((nmoved + 1)); bn="$(printf '%02d' "$nmoved")-${p##*/}"
            mkdir -p "$BACKUP_DIR/$kind"
            mv "$p" "$BACKUP_DIR/$kind/$bn"
            state_add "$kind" "$p" "$BACKUP_DIR/$kind/$bn" "${e#*|}"
            warn "Moved hand-added ${e#*|} out of the store: $p -> $BACKUP_DIR/$kind/$bn"
        done
    fi

    step "2/4  Rebuild"
    before="$(count_certs "$SYS_BUNDLE")"
    local affected_before; affected_before="$(bundle_affected "$SYS_BUNDLE" | wc -l)"
    if ! rebuild_store || ! store_sane "$before" "$affected_before"; then
        warn "Store rebuild failed or produced an unexpected store; rolling back"
        rollback
        die "Rolled back to the store as it was before this run. Check update-ca-certificates by hand."
    fi
    info "Store rebuilt: $(count_certs "$SYS_BUNDLE") certificates (was ${before})"

    step "3/4  Java"
    java_fix || true

    step "4/4  Verify"
    local vrc=0
    system_tests || vrc=$?
    if [[ $vrc -eq 1 ]]; then
        warn "Still trusted after an incremental rebuild; retrying with update-ca-certificates --fresh"
        rebuild_store --fresh || true
        vrc=0; system_tests || vrc=$?
    fi
    if [[ -n "$TEST_HOSTS" ]]; then
        for e in "${pre_ok[@]+"${pre_ok[@]}"}"; do
            if host_ok "$e"; then info "TEST_HOSTS: $e still verifies"
            else warn "TEST_HOSTS: $e verified before and FAILS now. Its chain likely anchors at AAA Certificate Services or emSign ECC Root CA - G3. The distrust stays in place; to undo it: ${SELF} restore"; vrc=3; fi
        done
    fi
    report_patch_line
    report_stale "$(stat -c %Y "$SYS_BUNDLE")"
    case $vrc in
        0) info "The system store rejects every compromised intermediate" ;;
        1) die "The system store still trusts compromised intermediates through a path this script doesn't know. Report it, with the output above." ;;
        2) warn "Some tests were inconclusive (see above)"; return 1 ;;
        3) return 1 ;;
    esac
}

# Undo this run's changes after a mechanical failure: restore the conf, put
# back moved files, and drop the state lines this run added
rollback() {
    local k p b
    if [[ -f "$BACKUP_DIR/${CERTS_CONF##*/}" ]]; then cp -a "$BACKUP_DIR/${CERTS_CONF##*/}" "$CERTS_CONF"; fi
    if [[ -f "$STATE" ]]; then
        while IFS=$'\t' read -r k p b _; do
            case "$k" in
                local|loose) if [[ -e "$b" && ! -e "$p" ]]; then mv "$b" "$p"; fi ;;
            esac
        done < <(tail -n +$((STATE_BEFORE + 1)) "$STATE")
        head -n "$STATE_BEFORE" "$STATE" > "$TDIR/state"
        cat "$TDIR/state" > "$STATE"
    fi
    rebuild_store --fresh >/dev/null 2>&1 || true
    info "Store restored ($(count_certs "$SYS_BUNDLE") certificates)"
}

do_restore() {
    [[ -s "$STATE" ]] || { info "Nothing to restore: this script hasn't distrusted anything here"; return 0; }
    backup "$CERTS_CONF"; backup "$STATE"
    local k p b label
    while IFS=$'\t' read -r k p b label; do
        case "$k" in
            conf)
                if [[ ! -f "${SHARE_DIR}/${p}" ]]; then
                    info "${label}: ${p} is no longer shipped; leaving it deselected"
                elif grep -qxF "!${p}" "$CERTS_CONF"; then
                    awk -v r="$p" '$0 == "!" r { print r; next } { print }' "$CERTS_CONF" > "$TDIR/conf"
                    cat "$TDIR/conf" > "$CERTS_CONF"; warn "Re-trusted ${label} (${p})"
                fi ;;
            local|loose)
                if [[ -e "$p" ]]; then warn "$p exists again; not overwriting (backup kept at $b)"
                elif [[ -e "$b" ]]; then mv "$b" "$p"; warn "Put back ${label}: $p"
                else warn "Backup $b is gone; can't put back $p"; fi ;;
            java) : ;;   # the ca-certificates-java hook re-adds certificates the store gains
        esac
    done < "$STATE"
    grep -vF "$MARKER" "$CERTS_CONF" > "$TDIR/conf" || true
    cat "$TDIR/conf" > "$CERTS_CONF"
    rm -f "$STATE"
    rebuild_store || die "update-ca-certificates failed during restore; conf backup in $BACKUP_DIR"
    java_restore_check
}

# The ca-certificates-java hook re-adds what the store regains; report it
java_restore_check() {
    if [[ ! -f "$JAVA_KS" ]] || ! command -v keytool >/dev/null; then return 0; fi
    local m; m="$(java_matches "$JAVA_KS" || true)"
    if [[ -n "$m" ]]; then info "Java keystore has the restored entries back ($(wc -l <<<"$m"))"; fi
}

cmd_restore() {
    warn "Restoring trust in the distrusted certificates"
    do_restore
    local rc=0; system_tests || rc=$?
    report_patch_line
    if [[ $rc -eq 1 ]]; then
        warn "The system store TRUSTS compromised intermediates again. Re-apply with: ${SELF} apply"
    else
        info "The store still rejects every compromised intermediate (the package fix holds on its own)"
    fi
}

cmd_cleanup() {
    local prc=0; ca_patch_status || prc=$?
    if [[ $prc -ne 0 && -z "$FORCE" ]]; then
        die "ca-certificates doesn't look patched (${PATCH_HOW}). Target: $(patch_target). Or add --force"
    fi
    [[ -s "$STATE" ]] || { info "Nothing to clean up"; return 0; }
    info "ca-certificates: ${PATCH_HOW}"
    do_restore
    local rc=0; system_tests || rc=$?
    if [[ $rc -ne 0 ]]; then
        warn "Without this script's distrust the store is not clean; putting it back"
        BACKUP_DIR="${BACKUP_DIR}-reapply"
        cmd_apply
        die "Kept the distrust: the installed ca-certificates doesn't remove these paths on its own."
    fi
    info "The patched package holds on its own. This script's changes are gone; backups stay in ${BACKUP_BASE}/"
}

cmd_status() {
    step "Managed by this script"
    if [[ -s "$STATE" ]]; then
        local k p b label
        while IFS=$'\t' read -r k p b label; do
            case "$k" in
                conf)  if grep -qxF "!${p}" "$CERTS_CONF"; then info "distrusted: ${label} (${p})"
                       else warn "RE-TRUSTED since apply: ${label} (${p}). Rerun: ${SELF} apply"; fi ;;
                local|loose) if [[ -e "$p" ]]; then warn "BACK in the store: $p. Rerun: ${SELF} apply"
                             else info "moved out: ${label} ($p -> $b)"; fi ;;
                java)  info "removed from Java keystore: ${p} (${label})" ;;
            esac
        done < "$STATE"
    else
        info "Nothing (not applied, restored, or cleaned up)"
    fi
    step "Store tests"
    local rc=0; system_tests || rc=$?
    report_cajava
    if [[ -f "$JAVA_KS" ]] && command -v keytool >/dev/null; then
        local m; m="$(java_matches "$JAVA_KS" || true)"
        if [[ -z "$m" ]]; then echo "  Java ${JAVA_KS}: no affected entries"
        else echo "  Java ${JAVA_KS}: HAS $(wc -l <<<"$m") affected entries ($(cut -d'|' -f3 <<<"$m" | paste -sd, -))"; fi
    fi
    report_patch_line
    report_stale "$(stat -c %Y "$SYS_BUNDLE" 2>/dev/null || echo 0)"
    [[ $rc -ne 1 ]]
}

patch_target() {
    local f="${FIXED_BY_RELEASE[$REL_KEY]:-}"
    if [[ -n "$f" ]]; then echo "ca-certificates ${f}+ or a build whose changelog names the fix"
    else echo "a ca-certificates build dated ${MIN_PKG_DATE} or later, or whose changelog names the fix (no known fixed build for ${REL_KEY:-this release}; add it with FIXED_BUILDS)"; fi
}

report_cajava() {
    local jrc=0; cajava_status || jrc=$?
    case $jrc in
        0) ok "ca-certificates-java ${JPKG_HOW}" ;;
        1) caution "ca-certificates-java ${JPKG_HOW}. Upgrade when available: apt-get install --only-upgrade ca-certificates-java. Until then its hook still rebuilds ${JAVA_KS} from the system store, and the keystore test below is what counts" ;;
        2) caution "ca-certificates-java ${JPKG_HOW}" ;;
        3) if [[ -f "$JAVA_KS" ]]; then caution "ca-certificates-java isn't installed, but ${JAVA_KS} exists: nothing keeps it in step with the system store"
           else inf "ca-certificates-java isn't installed (no system Java keystore)"; fi ;;
    esac
    if [[ $jrc -ne 3 && ! -x /etc/ca-certificates/update.d/jks-keystore ]]; then
        caution "ca-certificates-java is installed but its hook /etc/ca-certificates/update.d/jks-keystore is missing: ${JAVA_KS} won't follow the store"
    fi
    return 0
}

report_patch_line() {
    local prc=0; ca_patch_status || prc=$?
    case $prc in
        0) info "ca-certificates patched (${PATCH_HOW})"
           if [[ -s "$STATE" ]]; then echo "  The mitigation can go: ${SELF} cleanup (it re-tests before keeping the change)"; fi ;;
        1) warn "ca-certificates NOT patched (${PATCH_HOW}). Target: $(patch_target)" ;;
        *) warn "ca-certificates patch status unknown (${PATCH_HOW}). Target: $(patch_target)" ;;
    esac
}

report_stale() {   # <epoch>
    local s; s="$(stale_tls "$1")"
    [[ -n "$s" ]] || { info "No long-running TLS processes predate the current store"; return 0; }
    warn "These started before the current store and may still hold the old trust. Restart them:"
    head -20 <<<"$s" | while read -r u; do
        if [[ "$u" == *.service ]]; then echo "    $(svc_hint restart "${u%.service}")"; else echo "    $u"; fi
    done
    [[ $(wc -l <<<"$s") -le 20 ]] || echo "    ... and $(( $(wc -l <<<"$s") - 20 )) more"
    [[ $EUID -eq 0 ]] || echo "    (not root: other users' processes weren't checked)"
    command -v needrestart >/dev/null && echo "    needrestart can do this for you: needrestart -r l"
    return 0
}

# ---------- environment check ------------------------------------------------
# Runs before anything is changed, in this order: OS, system store, other
# stores, system. Hard blockers always stop the run. Soft blockers stop it
# unless --ignore-env is given. Cautions are reported but never stop it.
OS_SUPPORTED="debian ubuntu trisquel"
OS_DERIVATIVES="linuxmint pop elementary zorin neon kali raspbian pureos parrot deepin tuxedo devuan mx antix sparky q4os peppermint bunsenlabs siduction"
declare -A TRISQUEL_BASE=([etiona]=bionic [nabia]=focal [aramo]=jammy [ecne]=noble)
declare -A DEBIAN_MAJOR=([10]=buster [11]=bullseye [12]=bookworm [13]=trixie)
declare -A DEBIAN_VER=([buster]=10 [bullseye]=11 [bookworm]=12 [trixie]=13 [forky]=testing [sid]=unstable)
declare -A UBUNTU_VER=([bionic]=18.04 [focal]=20.04 [jammy]=22.04 [noble]=24.04 [resolute]=26.04)
ENV_HARD=(); ENV_SOFT=(); MUTATES=0

ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
soft()    { ENV_SOFT+=("$1"); echo -e "  ${YELLOW}✗${NC} $1 ${YELLOW}[stops; --ignore-env overrides]${NC}"; [[ -z "${2:-}" ]] || echo -e "      $2"; }
hard()    { ENV_HARD+=("$1"); echo -e "  ${RED}✗${NC} $1 ${RED}[stops]${NC}"; [[ -z "${2:-}" ]] || echo -e "      $2"; }
section() { echo -e "\n  ${CYAN}$*${NC}"; }

other_os_hint() {   # <id> <id_like>
    local s=" $1 $2 " page="https://emudhra.we-have-a-problem.com/"
    case "$s" in
        *" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" amzn "*)
            echo "Fedora/RHEL family: p11-kit blocklist + update-ca-trust. See ${page}#linux" ;;
        *" suse "*|*" opensuse"*|*" sles "*) echo "openSUSE/SLES: p11-kit blocklist + update-ca-certificates. See ${page}#linux" ;;
        *" arch "*)   echo "Arch: p11-kit blocklist + update-ca-trust, or ca-certificates-mozilla 3.131.1-1. See ${page}#linux" ;;
        *" alpine "*) echo "Alpine: ca-certificates 20261020-r0, or the /etc/ca-certificates.conf workaround. See ${page}#linux" ;;
        *" nixos "*)  echo "NixOS: security.pki.caCertificateBlacklist. See ${page}#linux" ;;
        *) echo "See ${page} for other platforms" ;;
    esac
}

check_os() {
    section "1/4  Operating system"
    if [[ ! -r "$OS_RELEASE" ]]; then
        hard "$OS_RELEASE missing - can't identify the distribution"; return 1
    fi
    local kv id like pretty code ubu deb ver
    # shellcheck source=/dev/null
    kv="$(. "$OS_RELEASE"; printf '%s\x1f' "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-unknown}" \
          "${VERSION_CODENAME:-}" "${UBUNTU_CODENAME:-}" "${DEBIAN_CODENAME:-}" "${VERSION_ID:-}")"
    IFS=$'\x1f' read -r id like pretty code ubu deb ver <<<"$kv"

    if in_list "$id" "$OS_SUPPORTED"; then
        ok "$pretty (supported)"
    elif in_list "$id" "$OS_DERIVATIVES"; then
        ok "$pretty (known derivative, ID=$id)"
    elif in_list ubuntu "$like" || in_list debian "$like"; then
        ok "$pretty (Debian/Ubuntu derivative, ID=$id, ID_LIKE=$like)"
    elif [[ "$OS_RELEASE" == /etc/os-release && -r /etc/debian_version ]]; then
        ok "$pretty (Debian-based: /etc/debian_version present, ID=$id)"
    else
        hard "$pretty is not Debian, Ubuntu, Trisquel or a derivative (ID=$id)" "$(other_os_hint "$id" "$like")"
        return 1
    fi

    # Base release: picks the fixed ca-certificates build to compare against
    local base="" fam=debian
    if [[ "$id" == ubuntu || "$id" == trisquel || -n "$ubu" ]] || in_list ubuntu "$like"; then fam=ubuntu; fi
    if [[ $fam == ubuntu ]]; then
        if [[ "$id" == ubuntu ]]; then REL_KEY="ubuntu:${ver}"; base="$code"
        else
            base="$ubu"; [[ -n "$base" || "$id" != trisquel ]] || base="${TRISQUEL_BASE[$code]:-}"
            [[ -z "$base" || -z "${UBUNTU_VER[$base]:-}" ]] || REL_KEY="ubuntu:${UBUNTU_VER[$base]}"
        fi
    else
        base="$deb"
        [[ -n "$base" ]] || { [[ "$id" =~ ^(debian|raspbian)$ ]] && base="$code"; } || true
        if [[ -z "$base" && -r /etc/debian_version ]]; then
            local dv; dv="$(cut -d. -f1 /etc/debian_version)"
            base="${DEBIAN_MAJOR[$dv]:-}"
            [[ -n "$base" ]] || case "$(cat /etc/debian_version)" in *sid*) base=sid ;; esac
        fi
        [[ -z "$base" || -z "${DEBIAN_VER[$base]:-}" ]] || REL_KEY="debian:${DEBIAN_VER[$base]}"
    fi
    if [[ -n "$REL_KEY" ]]; then
        local f="${FIXED_BY_RELEASE[$REL_KEY]:-}"
        inf "Base: ${fam^} ${base:-$ver} (${REL_KEY})${f:+, fixed ca-certificates build ${f}}"
        [[ -n "$f" ]] || caution "No published fixed ca-certificates build for ${REL_KEY} yet; patch detection relies on the changelog and FIXED_BUILDS"
    else
        caution "Couldn't determine the Debian/Ubuntu base release; patch detection relies on the changelog and FIXED_BUILDS"
    fi
    command -v dpkg-query >/dev/null || { hard "dpkg-query not found - Debian package layout required"; return 1; }
    return 0
}

check_store() {
    section "2/4  System CA store"
    local pv; pv="$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null || true)"
    if [[ -z "$pv" ]]; then
        hard "ca-certificates isn't installed" "Without it there's no system store to fix. Programs here ship their own roots; see section 3."
        return 1
    fi
    if [[ ! -f "$CERTS_CONF" ]] || ! command -v update-ca-certificates >/dev/null; then
        hard "ca-certificates ${pv} is installed but $CERTS_CONF or update-ca-certificates is missing"
        return 1
    fi
    local prc=0; ca_patch_status || prc=$?
    case $prc in
        0) ok "ca-certificates ${pv}: patched (${PATCH_HOW})" ;;
        1) caution "ca-certificates ${pv}: NOT patched (${PATCH_HOW}). Upgrade when available: apt-get install --only-upgrade ca-certificates" ;;
        *) caution "ca-certificates ${pv}: patch status unknown (${PATCH_HOW})" ;;
    esac
    local drc=0; pkg_date_status ca-certificates "${pv#*:}" || drc=$?
    case $drc in
        0) ok "ca-certificates build date: ${DATE_HOW}" ;;
        1) caution "ca-certificates build date: ${DATE_HOW}. No update since then: apt-get update && apt-get install --only-upgrade ca-certificates" ;;
        *) caution "ca-certificates build date: unknown (${DATE_HOW})" ;;
    esac

    scan_sources
    local e
    for e in "${M_CONF[@]+"${M_CONF[@]}"}";   do inf "trusted: ${e#*|} (${e%%|*}) - apply distrusts it"; done
    for e in "${M_OFF[@]+"${M_OFF[@]}"}";     do ok "distrusted: ${e#*|} (${e%%|*})"; done
    for e in "${M_UNSEL[@]+"${M_UNSEL[@]}"}"; do inf "shipped, not selected: ${e#*|} (${e%%|*})"; done
    for e in "${M_LOCAL[@]+"${M_LOCAL[@]}"}" "${M_LOOSE[@]+"${M_LOOSE[@]}"}"; do
        [[ -n "$e" ]] && caution "hand-added: ${e#*|} at ${e%%|*} - apply moves it to the backup directory"
    done
    [[ ${#M_CONF[@]} -gt 0 || ${#M_OFF[@]} -gt 0 || ${#M_UNSEL[@]} -gt 0 || ${#M_LOCAL[@]} -gt 0 || ${#M_LOOSE[@]} -gt 0 ]] \
        || inf "No affected certificates found in ${SHARE_DIR}, ${LOCAL_DIR} or ${CERTS_DIR}"

    if store_check file "$SYS_BUNDLE"; then ok "Store test, ${SYS_BUNDLE}: $(ft_summary)"
    else caution "Store test, ${SYS_BUNDLE}: $(ft_summary)"; fi
    return 0
}

check_other() {
    section "3/4  Other CA stores"
    local p e n k f v pv

    # Java: the system keystore follows the store through ca-certificates-java
    report_cajava
    if [[ -f "$JAVA_KS" ]]; then
        if command -v keytool >/dev/null; then
            local m rc=0; m="$(java_matches "$JAVA_KS")" || rc=$?
            if [[ $rc -ne 0 ]]; then caution "Java ${JAVA_KS}: can't read it (set JAVA_STOREPASS)"
            elif [[ -n "$m" ]]; then inf "Java ${JAVA_KS}: $(wc -l <<<"$m") affected entries - apply removes them with the store"
            else ok "Java ${JAVA_KS}: no affected entries"; fi
        else
            caution "Java ${JAVA_KS} exists but keytool isn't installed; can't check it"
        fi
    fi
    # Other JDKs with their own cacerts
    local -A jdk_exposed=()
    shopt -s nullglob
    for f in /usr/lib/jvm/*/lib/security/cacerts /usr/lib/jvm/*/jre/lib/security/cacerts \
             /opt/*/lib/security/cacerts /opt/*/jre/lib/security/cacerts /opt/*/*/lib/security/cacerts \
             /usr/local/*/lib/security/cacerts; do
        [[ "$(readlink -f "$f")" == "$(readlink -f "$JAVA_KS" 2>/dev/null)" ]] && continue
        local kt="${f%/lib/security/cacerts}/bin/keytool"; kt="${kt/\/jre\/bin/\/bin}"
        [[ -x "$kt" ]] || kt="$(command -v keytool || true)"
        [[ -n "$kt" ]] || { caution "JDK store $f: no keytool to check it"; continue; }
        local m2; m2="$(java_matches "$f" "$kt" 2>/dev/null || true)"
        if [[ -n "$m2" ]]; then
            caution "JDK store $f has $(wc -l <<<"$m2") affected entries - NOT covered. Update that JDK, or: ${kt} -delete -cacerts -alias <alias>"
            jdk_exposed["${f%/lib/security/cacerts}"]=1
        else
            ok "JDK store $f: no affected entries"
        fi
    done
    shopt -u nullglob

    # Bundled PEM stores (certifi, pip, Homebrew, vendored bundles)
    local found=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=1
        local real; real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
        [[ "$real" == "$SYS_BUNDLE" ]] && { inf "$f → system store"; continue; }
        if [[ -f "$(dirname "$f")/core.py" ]] && grep -qF "$SYS_BUNDLE" "$(dirname "$f")/core.py" 2>/dev/null; then
            ok "$f: Debian's certifi, reads the system store instead"; continue
        fi
        n="$(bundle_ok_count "$f")"
        if [[ "$n" == "?" ]]; then inf "$f: not a PEM bundle OpenSSL can read; skipped"
        elif [[ "$n" -eq 0 ]]; then ok "$f: rejects all"
        else caution "$f TRUSTS ${n} of ${#TEST_NAMES[@]} - NOT covered. Fix: $(bundle_fix_hint "$f")"; fi
    done < <(scan_bundles | sort -u)
    [[ $found -eq 1 || -z "$SCAN_PATHS" ]] || inf "No bundled CA files under ${SCAN_PATHS}"
    [[ -n "$SCAN_PATHS" ]] || inf "Bundle scan disabled (SCAN_PATHS is empty)"

    # Node.js ships its own roots unless started with --use-openssl-ca/--use-system-ca
    local b maj fixed
    while IFS= read -r b; do
        [[ -n "$b" ]] || continue
        v="$(timeout 10 "$b" --version 2>/dev/null || true)"; v="${v#v}"; maj="${v%%.*}"
        fixed="${NODE_FIXED[$maj]:-}"
        n="$(node_bundled "$b")"
        if [[ "$n" == "?" ]]; then caution "Node.js ${v:-?} ($b): couldn't read its bundled roots"
        elif [[ "$n" -gt 0 ]]; then
            NODE_EXPOSED+="$b "
            caution "Node.js ${v} ($b): bundled roots TRUST ${n} - NOT covered. Upgrade to ${fixed:-a fixed release}${fixed:++}, or run it with --use-openssl-ca"
        else ok "Node.js ${v} ($b): bundled roots reject all"; fi
    done < <(node_bins)

    # Running processes this run can't protect
    for p in /proc/[0-9]*; do
        e="$(readlink "$p/exe" 2>/dev/null || true)"; e="${e% (deleted)}"
        [[ -n "$e" ]] || continue
        local cmd envs; cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
        envs="$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^NODE_OPTIONS=' || true)"
        if [[ "$e" == */node || "$e" == */nodejs ]] && in_list "$e" "$NODE_EXPOSED"; then
            [[ "$cmd $envs" == *--use-openssl-ca* || "$cmd $envs" == *--use-system-ca* ]] && continue
            [[ $CMD =~ ^(apply|check)$ ]] && soft "Running Node.js (PID ${p#/proc/}) uses its bundled roots, which trust the compromised intermediates" \
                "Upgrade Node.js, or restart it with NODE_OPTIONS=--use-openssl-ca so it reads the system store this script fixes."
        elif [[ "$e" == */bin/java ]]; then
            local home="${e%/bin/java}"; home="${home%/jre}"
            if [[ -n "${jdk_exposed[$home]:-}" && "$cmd" != *javax.net.ssl.trustStore=* ]]; then
                [[ $CMD =~ ^(apply|check)$ ]] && soft "Running Java (PID ${p#/proc/}) uses ${home}/lib/security/cacerts, which this run won't fix"
            fi
            if [[ "$cmd" =~ javax\.net\.ssl\.trustStore=([^ ]+) ]]; then
                caution "Java PID ${p#/proc/} uses its own trustStore ${BASH_REMATCH[1]}; check it with keytool"
            fi
        fi
    done

    # System-wide overrides: programs following these won't read the system store
    for f in /etc/environment /etc/profile.d/*.sh; do
        [[ -r "$f" ]] || continue
        while IFS='=' read -r k v; do
            v="${v//\"/}"; v="${v//\'/}"; k="${k##* }"
            case "$k" in
                SSL_CERT_FILE) [[ "$v" == "$SYS_BUNDLE" ]] && continue
                    n="$(bundle_ok_count "$v")"
                    if [[ "$n" != "?" && "$n" -gt 0 && $CMD =~ ^(apply|check)$ ]]; then
                        soft "$f sets SSL_CERT_FILE=$v, which TRUSTS ${n}" "Programs that inherit it skip the system store. Fix that bundle or drop the override."
                    else inf "$f sets SSL_CERT_FILE=$v (${n} trusted)"; fi ;;
                SSL_CERT_DIR) [[ "$v" == "$CERTS_DIR" || "$v" == "$CERTS_DIR/" ]] && continue
                    local drc=0; store_check dir "$v" || drc=$?
                    if [[ $drc -eq 1 && $CMD =~ ^(apply|check)$ ]]; then soft "$f sets SSL_CERT_DIR=$v, which $(ft_summary)"
                    else inf "$f sets SSL_CERT_DIR=$v: $(ft_summary)"; fi ;;
            esac
        done < <(grep -hE '^[[:space:]]*(export[[:space:]]+)?SSL_CERT_(FILE|DIR)=' "$f" 2>/dev/null || true)
    done

    # NSS builtin roots (libnssckbi), used by NSS applications with their own trust
    pv="$(dpkg-query -W -f='${Version}' libnss3 2>/dev/null || true)"
    if [[ -n "$pv" ]]; then
        local nv="${pv#*:}" up ckbi="" via=""
        up="${nv%%-*}"
        for ckbi in /usr/lib/*/nss/libnssckbi.so /usr/lib/*/libnssckbi.so; do [[ -e "$ckbi" ]] && break; done
        [[ -e "$ckbi" && "$(readlink -f "$ckbi")" == *p11-kit* ]] && via=" (libnssckbi is p11-kit: follows the system store)"
        if [[ -n "$via" ]]; then ok "NSS ${nv}${via}"
        elif dpkg --compare-versions "$up" ge "$NSS_FIXED" || changelog_lists libnss3 "$nv"; then ok "NSS ${nv}: patched builtin roots"
        else caution "NSS ${nv}: builtin roots predate NSS ${NSS_FIXED}. NSS programs not using p11-kit stay exposed until libnss3 is updated"; fi
    fi

    # Things that carry their own store entirely
    local ct; ct="$(systemd-detect-virt --container 2>/dev/null || true)"
    [[ -z "$ct" || "$ct" == none ]] || caution "Running inside a container (${ct}): this fixes this container only. Rebuild the image on a patched base."
    { command -v docker >/dev/null || command -v podman >/dev/null; } \
        && caution "Container images carry their own ca-certificates. Rebuild them on patched bases; this host's fix doesn't reach them."
    { command -v snap >/dev/null && compgen -G '/snap/*/current' >/dev/null; } \
        && caution "Snaps run on their own base and may carry their own CA store; refresh them once fixed."
    command -v flatpak >/dev/null && caution "Flatpak runtimes may carry their own CA store; update them once fixed."

    # Go binaries: a CGO build reads the system store this script fixes, but a
    # pure-Go build carries its own verifier with a built-in denylist, fixed in
    # Go 1.26.10 / 1.27.3 (CVE-2026-111943). Those binaries can't be detected
    # from their file, so this is a reminder, not a per-binary check.
    if command -v go >/dev/null; then
        local gov; gov="$(go version 2>/dev/null | sed -nE 's/.*go([0-9.]+).*/\1/p')"
        caution "Go toolchain ${gov:-found}: rebuild pure-Go binaries with Go 1.26.10 / 1.27.3+ (CVE-2026-111943). Existing Go binaries that don't use CGO keep their own trust and aren't fixed by this script."
    fi
    return 0
}

check_system() {
    section "4/4  System"
    if [[ $EUID -ne 0 ]]; then
        if [[ $MUTATES -eq 0 ]]; then caution "Not root - some results may be incomplete"
        else hard "Must run as root (sudo $SELF $CMD)"; fi
    else
        ok "Running as root"
    fi
    if command -v openssl >/dev/null; then
        ok "$(openssl version 2>/dev/null | cut -d' ' -f1-2)"
    else
        hard "openssl not found - needed to identify certificates and test stores" "apt-get install openssl"
    fi
    if [[ -n "$SELFTEST_ERR" ]]; then
        hard "Embedded test certificates fail their SHA-256 check: ${SELFTEST_ERR}" "The script is damaged. Download it again and compare checksums."
    elif [[ ${#TEST_NAMES[@]} -eq 16 ]]; then
        ok "Embedded test certificates match their published SHA-256 (16 + 1 cross-sign)"
    else
        hard "Expected 16 embedded test certificates, found ${#TEST_NAMES[@]}"
    fi
    if [[ -z "$SELFTEST_ERR" && ${#TEST_NAMES[@]} -eq 16 ]]; then
        prove_keys
        if [[ $PROOF_OK -eq 8 ]]; then
            ok "Compromise reproduced: all 8 public keys equal d·G for d = $(printf '%s\n' "${LEAKED_D[@]}" | sort -n | paste -sd, - | sed 's/,/, /g')"
        else
            caution "Only ${PROOF_OK} of 8 leaked keys reproduced (${PROOF_ERR% }); the store tests still apply"
        fi
    fi
    if have_systemd; then ok "systemd is PID 1"; else inf "No systemd (PID 1 is $(cat /proc/1/comm 2>/dev/null || echo unknown)); restart hints use service(8)"; fi
    local t missing=()
    for t in awk sed grep zgrep sha256sum mktemp readlink find timeout stat getconf cut sort; do
        command -v "$t" >/dev/null || missing+=("$t")
    done
    [[ ${#missing[@]} -eq 0 ]] || hard "Missing tools: ${missing[*]}"
}

env_check() {
    [[ "$CMD" =~ ^(apply|restore|cleanup)$ ]] && MUTATES=1
    step "Environment check"
    if check_os; then
        if command -v openssl >/dev/null && [[ -z "$SELFTEST_ERR" ]]; then
            check_store || true
            check_other
        else
            echo "      (skipping store checks: openssl or the test certificates are unavailable)"
        fi
    else
        echo "      (skipping store checks)"
    fi
    check_system

    step "Verdict"
    local r
    if [[ ${#ENV_HARD[@]} -gt 0 ]]; then
        echo -e "${RED}Not starting.${NC} ${#ENV_HARD[@]} blocking problem(s):"
        for r in "${ENV_HARD[@]}"; do echo "  - $r"; done
        if [[ ${#ENV_SOFT[@]} -gt 0 ]]; then
            echo "Also (overridable):"; for r in "${ENV_SOFT[@]}"; do echo "  - $r"; done
        fi
        echo "Nothing was changed."
        exit 1
    fi
    if [[ ${#ENV_SOFT[@]} -gt 0 ]]; then
        if [[ -n "$IGNORE_ENV" && $CMD != check ]]; then
            warn "--ignore-env: proceeding despite ${#ENV_SOFT[@]} problem(s):"
            for r in "${ENV_SOFT[@]}"; do echo "  - $r"; done
            return 0
        fi
        echo -e "${YELLOW}Not starting.${NC} ${#ENV_SOFT[@]} problem(s) need a decision:"
        for r in "${ENV_SOFT[@]}"; do echo "  - $r"; done
        [[ $CMD == check ]] || echo "Review the report above. To proceed anyway: ${SELF} ${CMD} --ignore-env"
        echo "Nothing was changed."
        exit 2
    fi
    if [[ $CMD == check ]]; then info "Environment OK - nothing blocks apply"; exit 0; fi
    info "Environment OK - starting ${CMD}"
}

# ---------- embedded test certificates ---------------------------------------
# The 16 intermediates from impacted-intermediates.json and the emSign Root TLS
# CA - G3 cross-sign served by the test hosts, each with its published SHA-256.
# Source: https://github.com/galadran/we-have-a-problem.com
test_cert_blob() {
cat <<'CERTS'
EM-DV-TLS-CA-G3B.em 42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIQAKSu5njyM2K0wORgt3LyFDAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTU1
NDA4WhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11
ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAE557ZwEqXc8RzXlERHahawr1eZKs3S4DhLLwgOOweTw47gS/J
hZ4eZ6+wTi+LyX90hbplqpEe6KTkW2LVzAPVa+Z4s8OMtNyTfKJGDiOEU8iSk10p
1E+R4VYGtjzO2rRoo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFOIeL+ccGTkOVUtiwSAkVzUkiiUUMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYi5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQi5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIwLmsGXi6oFMJ2klkcEMXMug6gvxQWZWkewiDWVzQyl2L6z6DuQfPO
Ibh1grvdULDCAjEAxZvLlxUavG69J6wnSjC8XBbqNIQsJ6CE2QdNOe84Ptxb6VG8
gt2TlfJbHii+KNvK
-----END CERTIFICATE-----
EM-DV-TLS-CA-G3B.aaa 45A883F349AEDFD5F3A649B5498FFB121712BA8B448F3F2A91DBC5A766FCDDBE
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAKAk/fS6Zlx4XOSgIEg4WLcwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBEViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAATnntnASpdzxHNeUREdqFrCvV5kqzdLgOEsvCA47B5PDjuBL8mFnh5nr7BO
L4vJf3SFumWqkR7opORbYtXMA9Vr5nizw4y03JN8okYOI4RTyJKTXSnUT5HhVga2
PM7atGijggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQU4h4v5xwZOQ5VS2LBICRXNSSKJRQwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQIBMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJkMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQBzQ1IoqpdotM6gFrR4Q3YrKifOLeaj5XXunldpVE/vZn2TxC2y0s8oYiLR5ICE
wqVXSB7N6BM1Mp+Nif7Jbhb2IswAfSR4Iik8+B0iRmi7lYoNlycCgHjmsjOmZaxM
QkPmjXAJbG5f4V41OsvJZmS7lI3r0IuvEDVX3GAZ13on6IImSs9ybNpHQ7NCqkMQ
7wH4uAO1dtpFycgJSdHaCOhHjrox2BTYGLdpUrYwY3EOAjlZ8UGgsxs7mG+xquMl
bN1LFURwfnkVMP3T/DBIZ/ys2+lNFyxK3FlArrV4/000uTnVB1lO8oGORYdXoT5V
GUyRCEIDhF5TBUuKF4E3kf1h
-----END CERTIFICATE-----
EM-OV-TLS-CA-G3B.em 98B896625C0C230ADEEC3EB2CF6AAD5001ECF9156A68644E82374CE5833BC25B
-----BEGIN CERTIFICATE-----
MIIDZjCCAu2gAwIBAgIPbK2jZ/scEACIEg6iAtVoMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNjAw
MTJaFw00MDA0MjgxODMwMDBaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVk
aHJhIEJWMRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIB
BgUrgQQAIgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK
56Ks1xwyKo42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDft
DIVOTMEvTPhkbQ2jggGWMIIBkjAfBgNVHSMEGDAWgBThOqshfPHjTVSu1HK3/YtZ
QiCQVDAdBgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowHQYDVR0lBBYwFAYI
KwYBBQUHAwEGCCsGAQUFBwMCMF0GA1UdIARWMFQwOQYLKwYBBAGDjiEBAAEwKjAo
BggrBgEFBQcCARYcaHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTANBgsrBgEE
AYOOIQECbjAIBgZngQwBAgIwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBv
c2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1PVlRMU0NBRzNCLnA3YzA3BgNVHR8E
MDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNy
bDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQD
AwNnADBkAjBAk+5BizdJhrED3wb7F2Gm7bWI60dlNd075nghT2TrR4NWKZtJZcbc
28xxIY/NONICMF6mPdsjosaqmvEMWqKcBh4vsIvXSKnQj5o8zrFB4oKS+accjYTe
8Dz3bQjauvy9uw==
-----END CERTIFICATE-----
EM-OV-TLS-CA-G3B.aaa 5F1DED4DD590AF74631290CF073B122A2AAC6A1FA479778A0BD43579BD832699
-----BEGIN CERTIFICATE-----
MIIDzjCCAragAwIBAgIRAOlCI73pL5FOWrmsq/2sNxAwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBPViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAARziXqg6zz9yosSQC/68KvE4SErr43ud4rJ7i1tuD+sKAxeBWOK56Ks1xwy
Ko42HN659pxDArndjXPRzGyqsswK7k4hbOl53VGKSvS2JuVoTN1lgDftDIVOTMEv
TPhkbQ2jggE1MIIBMTAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUm9hlUa/n5yw3rQjuaRnZvzeErgowDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDEGA1UdIAQqMCgwCAYGZ4EMAQICMA0GCysGAQQBg44hAQABMA0GCysGAQQBg44h
AQJuMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FB
QUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEF
BQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IB
AQALRoOSvkzRa+tN5Rje9W5GiXd/qsicd9N6Gnh0SWC7VyWH+HycIqAnFCMYZznj
CeGusomFYHE42SHWr85JDIbgzy6y3dO4i9n9w0Bx7yrXWBbDzFS8VgA3+EY4Cg7y
mtoC3RPOJVtaXXPZ+68X804g1Mj+3vCSHj2lNPVgco0OzSIOJ/KMg1R9MLBkiKzb
bERAGZHejY0HBhYd76IINZN8z6bBNah2UdFYxsOisLynPQUkol6gRLum024/FzVl
CCDfnUusrkr+mAfPAvD/Vb8bhpA7jYtepuU+2mIdShj5lLlvAwZphn+ypWycuo2x
0k9mldz2dqI9nhCiY+TTIOOR
-----END CERTIFICATE-----
EM-EV-TLS-CA-G3B.em E7568FE6E12331F4FD7DE61DA4C7559D0F8EB192A218D4741A3BA75184333838
-----BEGIN CERTIFICATE-----
MIIDaDCCAu2gAwIBAgIQAMfEHv6S2CXwXq6EGkqCwTAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTYw
MzMxWhcNNDAwNDI4MTgzMDAwWjA/MQswCQYDVQQGEwJOTDETMBEGA1UECgwKZU11
ZGhyYSBCVjEbMBkGA1UEAwwSRU0gRVYgVExTIENBIC0gRzNCMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEJduoWmTTl9oLEFLp6lRuSHvv6pydnWigxerc/u91ppu11vwB
9Cv7ym60C81kwHZ+Nv/QXZeoE8WqDGyVMOec9fCGZGjxOAZCCqXIUYQLHiUlQOeQ
5LZUw4Uu1krx6GV9o4IBlTCCAZEwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFD7cINmJRpiHe4c/2IFHslwV2EcGMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBcBgNVHSAEVTBTMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAngwBwYFZ4EMAQEwdQYIKwYBBQUHAQEEaTBnMCQGCCsGAQUFBzABhhho
dHRwOi8vb2NzcC1iLmVtc2lnbi5jb20wPwYIKwYBBQUHMAKGM2h0dHA6Ly9yZXBv
c2l0b3J5LmVtc2lnbi5jb20vY2VydHMvRU1FVlRMU0NBRzNCLnA3YzA3BgNVHR8E
MDAuMCygKqAohiZodHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3R0bHNjYWczLmNy
bDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQD
AwNpADBmAjEA9Jq999oaOUKhFwopw33iCmt0OHIn3gjT43GfuOHR/YckXdwoNdDA
lIEhz0NgRO3/AjEAvY/a3OMvktIZLYjn+WLKmp0QhrIMV+e6EpS7j4GVeOKouNp6
MN/P+ByGeiRMghzB
-----END CERTIFICATE-----
EM-EV-TLS-CA-G3B.aaa 579480AEA166290BD3C643589E795FC0D0E54E86505D180F1DFF99EFD3199512
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIRANj4aF5PK9nYJAKoWhwetzEwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAk5MMRMwEQYDVQQKDAplTXVkaHJhIEJW
MRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0IwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQl26haZNOX2gsQUunqVG5Ie+/qnJ2daKDF6tz+73Wmm7XW/AH0K/vKbrQL
zWTAdn42/9Bdl6gTxaoMbJUw55z18IZkaPE4BkIKpchRhAseJSVA55DktlTDhS7W
SvHoZX2jggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUPtwg2YlGmId7hz/YgUeyXBXYRwYwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEB
AngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFB
Q2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUF
BzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEB
AJNFuAFW9Gnw/8+kCO4KIlZdnM1Sh2u+8cK0EYAHhXpb5FlGvYkcARigo5oS7VoM
7FOYlTueV6yICZKNAYawZPJPhNCGK+rp3cQBEz6d0n8OZEYZov9lb3ll8ORgSDuf
FVIW6Gagg/UnOamLBTOR8eD5V73SCme/B2cHUDw+m5E8cc+0Ujzz3Cn3ex5JrhXk
2T3s8PoVzEmhTgGboFfcWO1EYhPPrYwdxPYRQIXAXUXhLEOVNL9ASbZJLFI8E1IM
m7NwxVN2s38jWpaCUaaF0tg7hfiy7oe13rzJfHsdqldJVTTUTPWVx8TC4ju0VLet
bAlwhwFT6AP8uIVMGUHNw24=
-----END CERTIFICATE-----
EM-DV-TLS-CA-G3C.em 0164D7CEAE5BB909C272AF151FF44B1177AE9B47D9424B94F1D9558C30934D19
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPWIsuPCu4zaE+GhIJJUMhMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM1
MDlaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFy
pDPjYw8CvRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpV
bMyLpQVh3xsqRB0Bo4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAmQwCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRFZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMEN2HWMocbuWdy1d33pH6JpMvP/V/DIS5PtZbv1Q7TXEbxrcyxg
yuddOJscYDJJlAIwB4sH1BpbScDzkdD4tJBSwrG/1Mx82vb8YaySehNuu1+1oXNd
AEKwaJ0mVzScy2+6
-----END CERTIFICATE-----
EM-DV-TLS-CA-G3C.aaa 62B7F9868263F72F6911FC78CEAF72C1979158B7368BF648683BB2AA39B02E72
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAJHzR/Glt9OZYrleDuTimdEwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gRFYgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEOnp4YsjETTJN3WkDOmeCwO/u/kBV5ooSP6A3G6O9kZRRTuFypDPjYw8C
vRiAN9nlFJ+bd9uUooHfmHsv6oiLdL3+j9pMEJnubKGVZv4+8OX2sJpVbMyLpQVh
3xsqRB0Bo4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFK5+EFw8KZbBqEcnBVnx4D3U5QrzMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECATANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECZDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAr7b6Mx11TIJgVzHt6EH5qGNWeiiqoMrp8E5/k8s+jvupx1n083pZ5XOzUzND
wEUe0W4C4FIGUHNQ4XDwqOw0yK42xqm2dvCKgsko2UvDlT0haZVtTCeWMQOe5J/J
ziaMfZwsZNfZ3aaI6XPtWDZtwY8AaNfyaeCpbtm5GcGnyNWk4jSNpbtpo6NjfXuP
CFOm3rTjJ4zytP7Tso6iMm0L01cYFOlTmoPv4515R2r3SPnKDtijoB/D/vgxzojv
DafgyG9afX8+laO9NbMMz4sqC1vZx3984i/sBNFiugm3Vvdq5OdJRjuGC1QILIs6
dg/K3i8VQqRpbfaM9kIlMzZ3dQ==
-----END CERTIFICATE-----
EM-OV-TLS-CA-G3C.em CB6E15165AC802E9B3F993F16C25D41F4E81C21EBDE71AE1B012AC00BF9C7C3F
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIPKWkmwiejoVJjkrGUgqUEMAoGCCqGSM49BAMDMFYxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MSAwHgYDVQQDDBdlbVNpZ24gUm9vdCBUTFMgQ0EgLSBHMzAeFw0yNTA0MzAxNTM3
NDFaFw00MDA0MjgxODMwMDBaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVk
aHJhIEluYzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0C
AQYFK4EEACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZ
fjpRIOHv1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+
N7ulaVSfHAKycO1no4IBljCCAZIwHwYDVR0jBBgwFoAU4TqrIXzx401UrtRyt/2L
WUIgkFQwHQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjBdBgNVHSAEVjBUMDkGCysGAQQBg44hAQABMCow
KAYIKwYBBQUHAgEWHGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDQYLKwYB
BAGDjiEBAm4wCAYGZ4EMAQICMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNT1ZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIxAMSZt2xsPeumRdeSMSQ3CbzIZeQ/q7GDCWfeE1Pq+mhgA6gRM44c
NVF3xJ+wsxJk+wIwFJbaDMokD8Ei6eNOiA8yUMYvfzQyngmrhZQMdPCK1SewrR79
4rSb9vGqxZzelQth
-----END CERTIFICATE-----
EM-OV-TLS-CA-G3C.aaa 7485B51C0ED192878FA1D2F948FB529AE1842CC5086C4B67F7BE5B2039DE9489
-----BEGIN CERTIFICATE-----
MIIDzzCCAregAwIBAgIRAI1aSBGTnvRH13ERzdmEmukwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMEAxCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEbMBkGA1UEAwwSRU0gT1YgVExTIENBIC0gRzNDMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEE4JRzVKskpjByKrZdzId65fnCb0LTKCspV3IrVHc/J0ViaFZfjpRIOHv
1jHGPhg1ysrimGmmLhYx6KKBgatWYW3EXZGKvAnzqw5jz3kqpNztc4e+N7ulaVSf
HAKycO1no4IBNTCCATEwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQw
HQYDVR0OBBYEFDTq6gzryQra+dDF4u2beMmHnhtsMA4GA1UdDwEB/wQEAwIBBjAS
BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
AjAxBgNVHSAEKjAoMAgGBmeBDAECAjANBgsrBgEEAYOOIQEAATANBgsrBgEEAYOO
IQECbjBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9B
QUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYB
BQUHMAGGGGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOC
AQEAHlbhZpjhkPEAQVhPHRtBDaHqiisVD20pQ1TUeSx3l62Qe7NQ0b7vWQy7DN0i
KOu7BGpP5EnIjvXbz9FhpfPJ4FhKEt3tQ51rqXz2oD8vRaryvExWPobDUz3j7HN6
OzBsVMIe3PD7AAkpky0x8zMSi/ep5R9OMzybmNptbtppyuB5ytgq+h7lQdRIP+CQ
TaJX3qTgfMqzntYre5GljmEB5hU2/rSn8zoSU2APkJidlZFpghtgbD4I2VRHZvCw
FFr/SrFM9pwrgbJNZ1MtyTSVgI5NlNb0aMfLR+/r6jJt3ROeY2yh2QQ2dx+Yqgdb
uL5ChFWOQU+ErSDnUq7yr+pjBQ==
-----END CERTIFICATE-----
EM-EV-TLS-CA-G3C.em 432EC25F0D28DE9006D97BF752F17BBB2CD41F669933FCB072D9A1148D0261F3
-----BEGIN CERTIFICATE-----
MIIDaDCCAu6gAwIBAgIQAIAJkopkEHYBrwX6LxnxCTAKBggqhkjOPQQDAzBWMQsw
CQYDVQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRl
ZDEgMB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwHhcNMjUwNDMwMTUz
OTMxWhcNNDAwNDI4MTgzMDAwWjBAMQswCQYDVQQGEwJVUzEUMBIGA1UECgwLZU11
ZGhyYSBJbmMxGzAZBgNVBAMMEkVNIEVWIFRMUyBDQSAtIEczQzB2MBAGByqGSM49
AgEGBSuBBAAiA2IABC1W6Cmm+4LGSkaX2WCvlR6QZ66R+SbTQwbaSKiq63hptqZ+
bSdCbgRCqgOzbhmI3/Y2UU7hzwf1uks/8qBmRa59MdWGatMao9JG6wsxd+6Zy3Vm
xRbOdICKZo+R8MR/yqOCAZUwggGRMB8GA1UdIwQYMBaAFOE6qyF88eNNVK7Ucrf9
i1lCIJBUMB0GA1UdDgQWBBSmJV6AqU2385Z8G8eR35K87kvrXzAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwXAYDVR0gBFUwUzA5BgsrBgEEAYOOIQEAATAq
MCgGCCsGAQUFBwIBFhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMA0GCysG
AQQBg44hAQJ4MAcGBWeBDAEBMHUGCCsGAQUFBwEBBGkwZzAkBggrBgEFBQcwAYYY
aHR0cDovL29jc3AtYy5lbXNpZ24uY29tMD8GCCsGAQUFBzAChjNodHRwOi8vcmVw
b3NpdG9yeS5lbXNpZ24uY29tL2NlcnRzL0VNRVZUTFNDQUczQy5wN2MwNwYDVR0f
BDAwLjAsoCqgKIYmaHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290dGxzY2FnMy5j
cmwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwCgYIKoZIzj0E
AwMDaAAwZQIwBy1wTnzH4lXDTy2PD91ysLjvnlVN3JbJmc1BIMEU8TOLkYVHibMc
9HeyonikFSfmAjEA6uE3QRxlrZTz/1/lXPTEMUhoauAtycagtlNFp79kjhvNa2/f
Aal1GNxsOutLnr0Y
-----END CERTIFICATE-----
EM-EV-TLS-CA-G3C.aaa FD9D5C2DBBD4995AB69B8D50C439D9527B00529199C2FD01B2174EB58F07021F
-----BEGIN CERTIFICATE-----
MIIDzTCCArWgAwIBAgIQBfB4dS3s56G7hZXTAxZxcTANBgkqhkiG9w0BAQsFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTI1MDUxNDAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowQDELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRocmEgSW5j
MRswGQYDVQQDDBJFTSBFViBUTFMgQ0EgLSBHM0MwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAQtVugppvuCxkpGl9lgr5UekGeukfkm00MG2kioqut4abamfm0nQm4EQqoD
s24ZiN/2NlFO4c8H9bpLP/KgZkWufTHVhmrTGqPSRusLMXfumct1ZsUWznSAimaP
kfDEf8qjggE0MIIBMDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQUpiVegKlNt/OWfBvHkd+SvO5L618wDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MDAGA1UdIAQpMCcwBwYFZ4EMAQEwDQYLKwYBBAGDjiEBAAEwDQYLKwYBBAGDjiEB
AngwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFB
Q2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUF
BzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZIhvcNAQELBQADggEB
AIFfHiaMSjnrdZygRYV4ekRBmG7ybcFk4hGQWMMyMFi0cAEk2+dGfz5bl8IaIbLq
z+uVJzhOgVEX7WqIfgbWfFsfPYHYjPHBmy7SlZ3BwA86IQ6qF/etpX2/qL9A5yRN
N3nVowUpaqV6H3aCpkAh3wR2ZNkvAbLDvPz3J0l+sEWjWv+ZISOV4R+hXDTdPXV0
1lKxnbwqEsdo/sE2QkCDKwFrZh/0uKjWspydJj+jSaDLTrGNx50Dgmn7VEcD1ZI5
FXjknVUiO25YlmS1dtVZSBbyUKSjlrP/yDwPcZunoAsmCAAtCKsFLviLaymzvsKI
eSSDGxpSySp2VCxompGDk8g=
-----END CERTIFICATE-----
EM-OV-CS-CA-G3B.em 9E39DE2881273ACC225A149C72BA3E0F51424963669AB633EE1DC7DF5DB067B4
-----BEGIN CERTIFICATE-----
MIIDWzCCAuCgAwIBAgIPeBiTP4+FtGGaKzX7qD0KMAoGCCqGSM49BAMDMFUxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MR8wHQYDVQQDDBZlbVNpZ24gUm9vdCBDUyBDQSAtIEczMB4XDTI1MDQzMDE2MDgy
N1oXDTQwMDQyODE4MzAwMFowPjELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRo
cmEgQlYxGjAYBgNVBAMMEUVNIE9WIENTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUOb
NKBDHK/+W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jord
d7EAZPKr5eBQo4IBizCCAYcwHwYDVR0jBBgwFoAUaHQD+IXKjVRQVx0W4MjeRQ2r
zS0wHQYDVR0OBBYEFHn66OzP2w11jaRY1p+27dx8Sd7mMBMGA1UdJQQMMAoGCCsG
AQUFBwMDMF4GA1UdIARXMFUwOQYLKwYBBAGDjiEBAAEwKjAoBggrBgEFBQcCARYc
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbTAOBgwrBgEEAYOOIQECgUgwCAYG
Z4EMAQQBMHQGCCsGAQUFBwEBBGgwZjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3At
Yi5lbXNpZ24uY29tMD4GCCsGAQUFBzAChjJodHRwOi8vcmVwb3NpdG9yeS5lbXNp
Z24uY29tL2NlcnRzL0VNT1ZDU0NBRzNCLnA3YzA2BgNVHR8ELzAtMCugKaAnhiVo
dHRwOi8vY3JsLmVtc2lnbi5jb20vP3Jvb3Rjc2NhZzMuY3JsMA4GA1UdDwEB/wQE
AwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMDA2kAMGYCMQC/zr03
YEELsNKqzUtH2dVFi4BaKFdyrr/6G1dIWp8KAVgsw2/u4lyyboUDaC9jDvICMQC9
HTxku84tNX9dmHOtH7aC2Nu/JM0jTf6KjZAvovCJzzv1IFWSZpVLZibynMLXOrM=
-----END CERTIFICATE-----
EM-OV-CS-CA-G3B.aaa A496E23AC0CAB8155FC9B117B97EAE368EFCBB9041AEC8804D5A308D2D01C2D8
-----BEGIN CERTIFICATE-----
MIIDwzCCAqugAwIBAgIQQeMrc6wYXWzg10gLrPhOaTANBgkqhkiG9w0BAQsFADB7
MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYD
VQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UE
AwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTI1MDUxNDAwMDAwMFoXDTI4
MTIzMTIzNTk1OVowPjELMAkGA1UEBhMCTkwxEzARBgNVBAoMCmVNdWRocmEgQlYx
GjAYBgNVBAMMEUVNIE9WIENTIENBIC0gRzNCMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAEqrsPsGZqz88B+tUr/P1MK/LLPDSX3nOVDlgZth/mlQmHQcjEkUObNKBDHK/+
W/m0wcjorgAB+fTcitgsWfNjnpbNbD1NsM7+wmw9YlF7N3YTcnQ/jordd7EAZPKr
5eBQo4IBLDCCASgwHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
VR0OBBYEFHn66OzP2w11jaRY1p+27dx8Sd7mMA4GA1UdDwEB/wQEAwIBBjASBgNV
HRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMDIGA1UdIAQrMCkw
CAYGZ4EMAQQBMA0GCysGAQQBg44hAQABMA4GDCsGAQQBg44hAQKBSDBDBgNVHR8E
PDA6MDigNqA0hjJodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0
ZVNlcnZpY2VzLmNybDA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6
Ly9vY3NwLmNvbW9kb2NhLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAIh0OzWsdBYhY
7+yxPGyosRL+uUSN6/Mrd30fBuougs5FVWQ3cRgLhImnUUgXADY9buugWhMmfT3c
yU5T1MFXZXClCILm5mfg+oqm/ikUWJl3Ayf2GvYf2O++6vzqvkn418nI5Lpdt0O7
Li524YS/3CZHDA+zZQ7rrHpZXgQ9Hmp8AUQ4FneaGjNanFoYxiZxwCyW5z4u7AoK
0bmOVqKtcDFoVNz5++G9TYDJdhWOXmKKgzqRo1MK0PjazNT7MGHqknP93SqMVJ1g
mX/qNWxYteAjlvFanQxBNX/+TRxDjuFsEHO/7BvqSpIIck0UEEfizhN8zNpWLbcl
EqVgl0g39A==
-----END CERTIFICATE-----
EM-OV-CS-CA-G3C.em 4B2460A466F95FD40113BCDCCA2CEB29B3B093921DE45474DA7DF48874C630B1
-----BEGIN CERTIFICATE-----
MIIDWzCCAuGgAwIBAgIPVEt/kiwxriIKSpIpFvbmMAoGCCqGSM49BAMDMFUxCzAJ
BgNVBAYTAklOMSUwIwYDVQQKDBxlTXVkaHJhIFRlY2hub2xvZ2llcyBMaW1pdGVk
MR8wHQYDVQQDDBZlbVNpZ24gUm9vdCBDUyBDQSAtIEczMB4XDTI1MDQzMDE2Mzg0
MFoXDTQwMDQyODE4MzAwMFowPzELMAkGA1UEBhMCVVMxFDASBgNVBAoMC2VNdWRo
cmEgSW5jMRowGAYDVQQDDBFFTSBPViBDUyBDQSAtIEczQzB2MBAGByqGSM49AgEG
BSuBBAAiA2IABLnw4GNHAqacpqrdRDz9YsQbm6SyCSRpfXl052kaEm+5avs+NML9
O8X0gwYfJl3CpYQ2NHMjUQQ2so8E84YjYwZ5gOJQPgJTLWVGI1pxZaJZoe9Jb3Qb
X97neHII5Lj676OCAYswggGHMB8GA1UdIwQYMBaAFGh0A/iFyo1UUFcdFuDI3kUN
q80tMB0GA1UdDgQWBBTub3MpjW+/p7Mbw5U09hVWRHhmtzATBgNVHSUEDDAKBggr
BgEFBQcDAzBeBgNVHSAEVzBVMDkGCysGAQQBg44hAQABMCowKAYIKwYBBQUHAgEW
HGh0dHA6Ly9yZXBvc2l0b3J5LmVtc2lnbi5jb20wDgYMKwYBBAGDjiEBAoFIMAgG
BmeBDAEEATB0BggrBgEFBQcBAQRoMGYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
LWMuZW1zaWduLmNvbTA+BggrBgEFBQcwAoYyaHR0cDovL3JlcG9zaXRvcnkuZW1z
aWduLmNvbS9jZXJ0cy9FTU9WQ1NDQUczQy5wN2MwNgYDVR0fBC8wLTAroCmgJ4Yl
aHR0cDovL2NybC5lbXNpZ24uY29tLz9yb290Y3NjYWczLmNybDAOBgNVHQ8BAf8E
BAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADAKBggqhkjOPQQDAwNoADBlAjEA8yPg
8sntOhLwV2QXJ5LEaKSpo/fnE3uOgTadK73fDhyjiqr0Io9GVuQTYqBPbQ2TAjBg
euApmBS486+iei03lRrp139dPw6k28jjGNvWsAU7A1N86J1zPJVDEyVH+nMAWC0=
-----END CERTIFICATE-----
EM-OV-CS-CA-G3C.aaa 84112972B8E59D14560AE7E7119654474AAD119990CF3722BFC1E3B91615E1FD
-----BEGIN CERTIFICATE-----
MIIDxTCCAq2gAwIBAgIRANal72E7OQ8y75zfNJ93KEEwDQYJKoZIhvcNAQELBQAw
ezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
A1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNV
BAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczAeFw0yNTA1MTQwMDAwMDBaFw0y
ODEyMzEyMzU5NTlaMD8xCzAJBgNVBAYTAlVTMRQwEgYDVQQKDAtlTXVkaHJhIElu
YzEaMBgGA1UEAwwRRU0gT1YgQ1MgQ0EgLSBHM0MwdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAS58OBjRwKmnKaq3UQ8/WLEG5uksgkkaX15dOdpGhJvuWr7PjTC/TvF9IMG
HyZdwqWENjRzI1EENrKPBPOGI2MGeYDiUD4CUy1lRiNacWWiWaHvSW90G1/e53hy
COS4+u+jggEsMIIBKDAfBgNVHSMEGDAWgBSgEQojPpbxB+zirynvgqV/0DCktDAd
BgNVHQ4EFgQU7m9zKY1vv6ezG8OVNPYVVkR4ZrcwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwMgYDVR0gBCsw
KTAIBgZngQwBBAEwDQYLKwYBBAGDjiEBAAEwDgYMKwYBBAGDjiEBAoFIMEMGA1Ud
HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBgGbZ+NDkn
2Fr5dCVs/51+6cT5iEPP1stglX4TI2UaNh9LmPdltxXw3crV8gK5L8i+d+ScGibF
y0obtBHNTldXDgLnAHIzY3n+pceyKj7O2ae9CYnyuu5RBifeI3XYKowWE+oXnVGF
Oy0CvCJ/JsdP6aYgoCa9hGnAYicYQQL6MOMQZ5PuhcSM8t4giIzrpgrEkUP93GYE
emDG5Z8BYwKs80lLeQNBnwg/VHJ3iEF/o84RXYwrlrKqJ+33C094o6LNikMJCqOK
/WYHZSR8Xyhf8GXFAj5pZuI6Bcpug2V/E7i42j8OBhc25aNYDqK+B0qmb90sjNUB
g3tJeSIb/599
-----END CERTIFICATE-----
cross 3094025792039A68AF6E553686410BDAB7C0D4A36B9084CBA64202E35D6EBBDD
-----BEGIN CERTIFICATE-----
MIIDdDCCAvmgAwIBAgIQAJYaPvsTWVdu0EAFtGhKWzAKBggqhkjOPQQDAzBrMQsw
CQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhy
YSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290
IENBIC0gRzMwHhcNMjQwNzExMTU0MzM2WhcNMzkwNzA5MTgzMDAwWjBWMQswCQYD
VQQGEwJJTjElMCMGA1UECgwcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEg
MB4GA1UEAwwXZW1TaWduIFJvb3QgVExTIENBIC0gRzMwdjAQBgcqhkjOPQIBBgUr
gQQAIgNiAARfD9w/q1cWxL6D9bMGH6CQ4u+gAV6GN9s+PwQx9Bl4hC+0iU8QOk8m
WO/RwXQy10DCSxT8vSIJClHKp+Ao4qJKdYeV0SwZ7LMQziyLfxIUOY6Grja/sQFw
LKYf8EdDXAyjggF1MIIBcTAfBgNVHSMEGDAWgBR8XQKEE9TMipuBzhccLikenEhj
QjAdBgNVHQ4EFgQU4TqrIXzx401UrtRyt/2LWUIgkFQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMD0GA1UdIAQ2MDQwMgYEVR0gADAqMCgGCCsGAQUFBwIB
FhxodHRwOi8vcmVwb3NpdG9yeS5lbXNpZ24uY29tMHgGCCsGAQUFBwEBBGwwajAi
BggrBgEFBQcwAYYWaHR0cDovL29jc3AuZW1zaWduLmNvbTBEBggrBgEFBQcwAoY4
aHR0cDovL3JlcG9zaXRvcnkuZW1zaWduLmNvbS9jZXJ0cy9lbVNpZ25FQ0NSb290
Q0FHMy5jcnQwMwYDVR0fBCwwKjAooCagJIYiaHR0cDovL2NybC5lbXNpZ24uY29t
P1Jvb3RDQUczLmNybDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIB
ATAKBggqhkjOPQQDAwNpADBmAjEAt9CIpRGp46QHQYDUBnLKw+vvK0/h9vmilEAg
TroUl/anH4x2rXHqiCtBTBfgKDegAjEA8WpG1LTZdAIL0FSYqxXeREaeTSxEofM0
1jJH3jGvCXC79LU9UPJ2o3TU+UIj2gMV
-----END CERTIFICATE-----
CERTS
}

# ---------- dispatch ---------------------------------------------------------
# Wrapped in main and ended with exit on the same line: bash parses all of
# main before running it, so re-downloading or editing this file while a run
# is in progress can't make bash read the rest from a shifted offset.
main() {
CMD="${1:-apply}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
FORCE=""; IGNORE_ENV=""
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; --*) set -- "$CMD" "$@"; CMD=apply ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --force) FORCE=1; shift ;;
        --ignore-env) IGNORE_ENV=1; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$CMD" in check|apply|status|restore|cleanup) ;; *) die "Unknown command: $CMD (check|apply|status|restore|cleanup|version)" ;; esac
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"

command -v openssl >/dev/null && setup_tests
env_check      # exits here for "check", or if the environment blocks the run

step "${CMD}"
"cmd_${CMD}"
if [[ "$CMD" == apply ]]; then
    echo -e "\n${YELLOW}REMINDER:${NC} this distrusts all of emSign ECC Root CA - G3 and AAA Certificate Services, not just the"
    echo "eight intermediates. Once ca-certificates is patched: ${SELF} cleanup"
fi
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
# Assisted-by: Claude Sonnet 5.5
