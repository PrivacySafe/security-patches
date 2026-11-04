#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# APT: a package download can be swapped after APT has verified it  (v1)
# CVE-2026-109518
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# APT, the package manager of Debian, Ubuntu and their derivatives, can merge two
# different package downloads when an HTTP redirect gives them the same address, and
# it reuses a file through a hard link when it retries a download. Someone who can
# alter the HTTP traffic between the host and the archive (an attacker on the network
# path, a malicious mirror or a proxy) can use redirects and ordinary temporary server
# errors to make APT retry, and replace a package after APT has checked it. The
# replaced package is installed as root. CWE-62 (hard link) and CWE-367 (a time of check
# to time of use race), CVSS 4.0 score 7.7 (High); the APT developers call it critical. Reported by Max Justicz, disclosed on 4 November 2026.
#
# The attack needs both of these at once: APT follows redirects (it does by default)
# and Acquire::Retries is above 0. The default is 3 on Debian 12 and Ubuntu 22.04 and
# later, so Debian 11, Ubuntu 20.04 and older are not exposed in their default
# configuration, unless a script or an image turned retries on.
#
#   Fixed APT releases (the CVE record), by release line:
#     3.3.6, 3.2.1, 3.0.4, 2.8.4, 2.6.2, 2.4.15, 2.2.5, 2.0.12, 1.8.2.4, 1.6.19,
#     1.4.12 and 1.2.36. APT 1.8.3 through 1.8.5 are affected and have no fixed 1.8
#     release.
#   Debian:  13 (trixie) 3.0.4, DSA-6607-1. 12 (bookworm) 2.6.2, DLA-4880-1. 11
#            (bullseye) 2.2.5, published by the APT developers after its long term
#            support ended on 31 August 2026. Unstable has 3.3.6; testing (forky) was
#            still on the affected 3.3.5 in Debian's security tracker.
#   Ubuntu:  26.10 3.3.3ubuntu0.1, 26.04 LTS 3.2.1ubuntu0.1, 24.04 LTS 2.8.4ubuntu0.1,
#            22.04 LTS 2.4.15ubuntu0.1, Ubuntu Pro 20.04 2.0.12+esm1.
#
# No workaround is published by the advisories. The stopgap that follows from the
# description is Acquire::Retries "0", which removes one of the two conditions (APT
# then does not retry a failed download, which can make updates less reliable on a
# poor connection). Updating APT is the fix.
#
# Usage:
#   ./apt-nov2026-check.sh [command]
#
#   check (default)  read-only. Reads the installed APT version, judges it against the
#                    fixed releases, reads the effective Acquire::Retries and redirect
#                    settings, and lists where this host downloads from. Exit 0 = APT is
#                    fixed, or it is not fixed but a condition of the attack is off (a
#                    warning says so), or APT is not installed. 1 = vulnerable and both
#                    conditions are on. 2 = it could not be judged (a development
#                    version between the published ranges, or APT would not answer).
#   hunt             read-only. APT's published advisories name no indicator, so this
#                    looks for what the flaw would leave: a cached package whose
#                    SHA-256 differs from the one in the index for the same name,
#                    version and architecture, and files in the package and list
#                    caches that have more than one hard link (a healthy cache has
#                    none). A clean hunt is not clearance. Exit 0 = nothing found, 1 =
#                    a lead, 2 = it could not read what it needs.
#   mitigate [--dry-run]   (root) changes the host. Writes the file
#                    /etc/apt/apt.conf.d/99psf-cve-2026-109518-retries with
#                    Acquire::Retries "0", then asks apt-config for the effective value.
#                    If another file or setting overrides it, the new file is removed
#                    again and the command says which one. Nothing else is touched. This
#                    is a stopgap, not the fix: update APT, then run rollback.
#   rollback [--dry-run]   (root) removes the file that mitigate wrote (and only that
#                    file; --force removes it even if someone edited it).
#   version          print the script version.
#
# Update first, with retries off for the update itself:
#   sudo apt-get -o Acquire::Retries=0 update
#   sudo apt-get -o Acquire::Retries=0 install --only-upgrade apt
#
# Environment: STATE_DIR (default /var/lib/psf-security-patches/apt) holds the manifest.
#              APT_CONF_DIR (default /etc/apt/apt.conf.d) is where mitigate writes.
#              ARCHIVES_DIR and LISTS_DIR replace APT's package and list folders for
#              hunt. APT_HELPER (default /usr/lib/apt/apt-helper) reads compressed
#              index files. OS_RELEASE (default /etc/os-release) names the release.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="apt-nov2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-04"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/apt}"
APT_CONF_DIR="${APT_CONF_DIR:-/etc/apt/apt.conf.d}"
APT_HELPER="${APT_HELPER:-/usr/lib/apt/apt-helper}"
OS_RELEASE="${OS_RELEASE:-/etc/os-release}"
DROPIN="99psf-cve-2026-109518-retries"
DROPIN_MARK="# Written by apt-nov2026-check.sh (PrivacySafe Security Patches) for CVE-2026-109518."

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
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- what the CVE record says --------------------------------------------------------
# release line | first affected | fixed (upstream) | the Ubuntu build that fixes a line below that
# These are the ranges of the CVE record. The README shows the same table, and a test compares them.
APT_LINES=(
    "1.2|0|1.2.36|"
    "1.4|1.4.0|1.4.12|"
    "1.6|1.6.0|1.6.19|"
    "1.8|1.8.0|1.8.2.4|"
    "2.0|2.0.0|2.0.12|2.0.12+esm1"
    "2.2|2.2.0|2.2.5|"
    "2.4|2.4.0|2.4.15|2.4.15ubuntu0.1"
    "2.6|2.6.0|2.6.2|"
    "2.8|2.8.0|2.8.4|2.8.4ubuntu0.1"
    "3.0|3.0.0|3.0.4|"
    "3.2|3.2.0|3.2.1|3.2.1ubuntu0.1"
    "3.3|3.3.0|3.3.6|3.3.3ubuntu0.1"
)
NEWEST_FIXED="3.3.6"      # any version at or above this is fixed
FIRST_FIXED="1.2.36"      # anything below this is affected
RETRIES_DEFAULT_FROM="2.4.0"   # the default Acquire::Retries is 3 from here on (Debian 12, Ubuntu 22.04)

vcmp() { dpkg --compare-versions "$1" "$2" "$3"; }
cfg_get() {   # KEY: the effective value from APT's own configuration, empty when it is not set
    apt-config dump "$1" 2>/dev/null | sed -n 's/^[^ ]* "\(.*\)";$/\1/p' | tail -n 1
}
is_false() { case "$(tr '[:upper:]' '[:lower:]' <<<"${1:-}")" in 0|false|no|off|disable|disabled) return 0 ;; *) return 1 ;; esac; }
release_field() { sed -n "s/^$1=//p" "$OS_RELEASE" 2>/dev/null | head -n 1 | tr -d '"'; }

# judge_apt VERSION: prints fixed, vulnerable or unknown
judge_apt() {
    local v="$1" bare series line s fixed ubu
    bare="${v#*:}"; v="$bare"      # the thresholds have no epoch; an epoch must not make a version look newer
    vcmp "$v" lt "$FIRST_FIXED" && { echo vulnerable; return; }
    vcmp "$v" ge "$NEWEST_FIXED" && { echo fixed; return; }
    [[ "$bare" =~ ^([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    series="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
    for line in "${APT_LINES[@]}"; do
        IFS='|' read -r s _ fixed ubu <<<"$line"
        [[ "$s" == "$series" ]] || continue
        # 1.8.3 through 1.8.5 are affected and the 1.8 line has no later fix
        if [[ "$series" == 1.8 ]] && vcmp "$v" ge 1.8.3; then echo vulnerable; return; fi
        if vcmp "$v" ge "$fixed"; then echo fixed; return; fi
        if [[ -n "$ubu" && "$v" == *ubuntu* ]] && vcmp "$v" ge "$ubu"; then echo fixed; return; fi
        echo vulnerable; return
    done
    echo unknown     # a development series (2.5, 2.7, 3.1 ...) between the published ranges
}

# fix_target ID VERSION_ID: the APT version that fixes this release, as far as the advisories say
fix_target() {
    case "$1:$2" in
        debian:13) echo "3.0.4 (DSA-6607-1)" ;;
        debian:12) echo "2.6.2 (DLA-4880-1)" ;;
        debian:11) echo "2.2.5, published by the APT developers (Debian 11 long term support ended on 31 August 2026)" ;;
        ubuntu:26.10) echo "3.3.3ubuntu0.1" ;;
        ubuntu:26.04) echo "3.2.1ubuntu0.1" ;;
        ubuntu:24.04) echo "2.8.4ubuntu0.1" ;;
        ubuntu:22.04) echo "2.4.15ubuntu0.1" ;;
        ubuntu:20.04) echo "2.0.12+esm1 (Ubuntu Pro)" ;;
        ubuntu:*) echo "an Ubuntu Pro update, if your release is still covered" ;;
        debian:*) echo "3.3.6 or later (unstable has it; testing was still on 3.3.5 in the security tracker)" ;;
        *) echo "" ;;
    esac
}

# ---------- reading the host ----------------------------------------------------------------
APT_VER=""; RETRIES=""; RETRIES_FROM=""; REDIRECT_ON=1; REDIRECT_NOTE=""
read_apt() {
    have apt-config && have dpkg-query && have dpkg || return 1
    APT_VER="$(dpkg-query -W -f='${Version}' apt 2>/dev/null || true)"
    [[ -n "$APT_VER" ]] || return 1
    local raw
    raw="$(cfg_get Acquire::Retries)"
    if [[ -n "$raw" ]]; then RETRIES="$raw"; RETRIES_FROM="set in the APT configuration"
    elif vcmp "$APT_VER" ge "$RETRIES_DEFAULT_FROM"; then RETRIES=3; RETRIES_FROM="the default of this APT"
    else RETRIES=0; RETRIES_FROM="the default of this APT"; fi
    [[ "$RETRIES" =~ ^[0-9]+$ ]] || RETRIES=0
    local rh rs
    rh="$(cfg_get Acquire::http::AllowRedirect)"; rs="$(cfg_get Acquire::https::AllowRedirect)"
    if [[ -n "$rh" ]] && is_false "$rh" && [[ -n "$rs" ]] && is_false "$rs"; then REDIRECT_ON=0; REDIRECT_NOTE="turned off for http and https"
    elif [[ -n "$rh" ]] && is_false "$rh"; then REDIRECT_NOTE="turned off for http, still on for https"
    else REDIRECT_NOTE="on (the default)"; fi
    return 0
}

list_sources() {   # prints one repository address per line
    have apt-get || return 0
    apt-get indextargets --format "\$(REPO_URI)" 2>/dev/null | sort -u
}

# ---------- check ---------------------------------------------------------------------------
cmd_check() {
    local state exposed=0 rc=0 id vid pretty target
    if ! read_apt; then
        step "APT"
        inf "APT is not installed here, so there is nothing to check."
        step "Verdict"; ok "Not applicable: this host does not use APT."
        return 0
    fi
    id="$(release_field ID)"; vid="$(release_field VERSION_ID)"; pretty="$(release_field PRETTY_NAME)"
    step "APT version"
    inf "apt ${APT_VER}${pretty:+ on ${pretty}}"
    state="$(judge_apt "$APT_VER")"
    case "$state" in
        fixed)      ok "apt ${APT_VER} has the fix for CVE-2026-109518." ;;
        vulnerable) bad "apt ${APT_VER} is older than the fixed release of its line (CVE-2026-109518)." ;;
        *)          caution "apt ${APT_VER} is a development version between the published ranges; it cannot be judged." ; rc=2 ;;
    esac
    step "What the attack needs"
    if [[ "$RETRIES" -gt 0 ]]; then
        if [[ "$state" == fixed ]]; then inf "Acquire::Retries is ${RETRIES} (${RETRIES_FROM})."
        else bad "Acquire::Retries is ${RETRIES} (${RETRIES_FROM}): APT retries a failed download, which the attack needs."; fi
    else
        ok "Acquire::Retries is 0 (${RETRIES_FROM}): APT does not retry a download, so the attack cannot work."
    fi
    if [[ $REDIRECT_ON -eq 1 ]]; then inf "Redirects: ${REDIRECT_NOTE}."
    else ok "Redirects: ${REDIRECT_NOTE}, so the attack cannot work."; fi
    local ex
    ex="$(apt-config dump 2>/dev/null | grep -iE '^Acquire::[A-Za-z0-9:_-]*Retries ' | grep -v '^Acquire::Retries ' || true)"
    [[ -z "$ex" ]] || inf "Other retry settings: $(tr '\n' ' ' <<<"$ex")"
    [[ "$RETRIES" -gt 0 && $REDIRECT_ON -eq 1 ]] && exposed=1

    step "Where this host downloads from"
    local src nhttp=0 nhttps=0 nother=0
    src="$(list_sources)"
    if [[ -z "$src" ]]; then inf "The package sources could not be read."
    else
        while IFS= read -r u; do
            case "$u" in http://*|mirror+http://*) nhttp=$((nhttp + 1)) ;; https://*|mirror+https://*) nhttps=$((nhttps + 1)) ;; *) nother=$((nother + 1)) ;; esac
        done <<<"$src"
        inf "${nhttp} source(s) over http, ${nhttps} over https, ${nother} other (file, cdrom)."
        if [[ $nhttp -gt 0 ]]; then caution "A source over http can be altered by anyone on the network path: $(grep -E '^(mirror\+)?http://' <<<"$src" | head -n 3 | tr '\n' ' ')"; fi
        [[ $nhttps -eq 0 || $nhttp -gt 0 ]] || inf "Every source is https. The advisories do not say whether https sources are exposed; a malicious mirror or a proxy that inspects TLS is in scope."
    fi
    local px
    px="$(apt-config dump 2>/dev/null | grep -iE '^Acquire::https?::Proxy ' | grep -v '""' || true)"
    [[ -z "$px" ]] || inf "A proxy is configured: $(tr '\n' ' ' <<<"$px")"

    step "Verdict"
    target="$(fix_target "$id" "$vid")"
    if [[ "$state" == fixed ]]; then
        ok "apt ${APT_VER} is fixed."
    elif [[ "$state" == unknown ]]; then
        caution "This version is not covered by the published ranges. Update APT to a release line that lists a fix."
        rc=2
    elif [[ $exposed -eq 1 ]]; then
        bad "Vulnerable, and both conditions are on: a download that an attacker redirects and makes APT retry can be replaced after verification."
        [[ -z "$target" ]] || inf "For this release the fixed APT is ${target}."
        inf "Update: sudo apt-get -o Acquire::Retries=0 update && sudo apt-get -o Acquire::Retries=0 install --only-upgrade apt"
        inf "Until the update is available: ${SELF} mitigate"
        rc=1
    else
        caution "apt ${APT_VER} has the flaw, but a condition of the attack is off here. Update APT anyway: a script, an image or a command line can turn retries back on."
        [[ -z "$target" ]] || inf "For this release the fixed APT is ${target}."
        rc=0
    fi
    return "$rc"
}

# ---------- hunt ----------------------------------------------------------------------------
cmd_hunt() {
    read_apt || { step "APT"; inf "APT is not installed here, so there is nothing to look at."; return 0; }
    local arch lists nlead=0 ndeb=0 hl idx key sha want f tmp
    arch="${ARCHIVES_DIR:-$(apt-config shell A Dir::Cache::archives/d 2>/dev/null | sed -n "s/^A='\(.*\)'$/\1/p")}"
    lists="${LISTS_DIR:-$(apt-config shell L Dir::State::lists/d 2>/dev/null | sed -n "s/^L='\(.*\)'$/\1/p")}"
    [[ -n "$arch" ]] || arch=/var/cache/apt/archives/
    [[ -n "$lists" ]] || lists=/var/lib/apt/lists/
    step "Files with more than one hard link"
    hl="$(find "$arch" "$lists" -xdev -type f -links +1 2>/dev/null || true)"
    if [[ -z "$hl" ]]; then ok "No file in ${arch} or ${lists} has more than one hard link."
    else
        while IFS= read -r f; do bad "${f} has $(stat -c %h "$f" 2>/dev/null || echo '?') hard links (APT does not normally leave any)"; nlead=$((nlead + 1)); done <<<"$hl"
    fi

    step "Cached packages against the index"
    local debs
    debs="$(find "$arch" -maxdepth 1 -type f -name '*.deb' 2>/dev/null | sort || true)"
    if [[ -z "$debs" ]]; then inf "There are no cached packages to compare (APT removes them after an install on many systems)."
    elif ! have dpkg-deb || ! have sha256sum; then inf "dpkg-deb or sha256sum is missing, so the packages cannot be compared."
    else
        tmp="$(mktemp "${TMPDIR:-/tmp}/apt-psf.XXXXXX")" || { inf "No temporary file; skipped."; tmp=""; }
        if [[ -n "$tmp" ]]; then
            PSF_TMP+=("$tmp")
            local files nread=0
            files="$(apt-get indextargets --format "\$(FILENAME)|\$(CREATED_BY)" 2>/dev/null | sed -n 's/|Packages$//p' || true)"
            while IFS= read -r idx; do
                [[ -r "$idx" ]] || continue
                nread=$((nread + 1))
                if [[ "$idx" == *Packages ]]; then cat "$idx"
                elif [[ -x "$APT_HELPER" ]]; then "$APT_HELPER" cat-file "$idx" 2>/dev/null
                else :; fi
            done <<<"$files" | awk '
                /^Package: /{p=$2} /^Version: /{v=$2} /^Architecture: /{a=$2} /^SHA256: /{s=$2}
                /^$/ { if (p != "" && s != "") print p "|" v "|" a "\t" s; p=v=a=s="" }
                END  { if (p != "" && s != "") print p "|" v "|" a "\t" s }' > "$tmp"
            if [[ ! -s "$tmp" ]]; then inf "No package index could be read, so the cached packages cannot be compared."
            else
                while IFS= read -r f; do
                    ndeb=$((ndeb + 1))
                    key="$(dpkg-deb -f "$f" Package Version Architecture 2>/dev/null | awk -F': ' '{print $2}' | paste -sd'|' || true)"
                    sha="$(sha256sum "$f" | cut -d' ' -f1)"
                    want="$(awk -F'\t' -v k="$key" '$1 == k {print $2; exit}' "$tmp")"
                    if [[ -z "$want" ]]; then inf "$(basename "$f"): the index no longer lists this version, so it cannot be compared."
                    elif [[ "$want" == "$sha" ]]; then ok "$(basename "$f") matches the SHA-256 in the index."
                    else bad "$(basename "$f") has SHA-256 ${sha}, but the index lists ${want} for the same package, version and architecture"; nlead=$((nlead + 1)); fi
                done <<<"$debs"
            fi
        fi
    fi

    step "Verdict"
    if [[ $nlead -gt 0 ]]; then
        bad "${nlead} lead(s). Treat the host as possibly altered if the package was installed over http: reinstall it from a trusted source and check what it put on disk."
        return 1
    fi
    ok "Nothing found. APT's advisories name no indicator, so this is not clearance: it only means the two things this hunt can see are in order."
    return 0
}

# ---------- mitigate and rollback -----------------------------------------------------------
manifest_add() { mkdir -p "$STATE_DIR" && printf '%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" >> "$STATE_DIR/manifest"; }

cmd_mitigate() {
    local dry=0 a path content tmp eff
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (mitigate [--dry-run])" ;; esac; done
    read_apt || die "APT is not installed here (apt-config and dpkg-query are needed)."
    path="${APT_CONF_DIR}/${DROPIN}"
    step "Stopgap: Acquire::Retries \"0\""
    if [[ "$(judge_apt "$APT_VER")" == fixed ]]; then ok "apt ${APT_VER} is already fixed: nothing to do."; return 0; fi
    if [[ "$RETRIES" -eq 0 && ! -f "$path" ]]; then ok "Acquire::Retries is already 0 (${RETRIES_FROM}): nothing to do. Update APT anyway."; return 0; fi
    content="${DROPIN_MARK}
# Stopgap: APT does not retry a failed download, which removes one of the two conditions of the attack.
# Update APT, then remove this file with: ${SCRIPT_NAME} rollback
Acquire::Retries \"0\";
"
    if [[ $dry -eq 1 ]]; then
        inf "would write ${path}:"
        while IFS= read -r a; do echo "        ${a}"; done <<<"${content%$'\n'}"
        inf "would then check the effective value with apt-config dump Acquire::Retries"
        return 0
    fi
    need_root "mitigate changes ${APT_CONF_DIR}"
    [[ -d "$APT_CONF_DIR" ]] || die "${APT_CONF_DIR} does not exist."
    if [[ -f "$path" ]] && grep -qF "$DROPIN_MARK" "$path" && [[ "$(cat "$path")" == "${content%$'\n'}" ]]; then
        ok "${path} is already in place."
    else
        tmp="$(mktemp "${APT_CONF_DIR}/.psf-apt.XXXXXX")" || die "cannot create a file in ${APT_CONF_DIR}"
        PSF_TMP+=("$tmp")
        if ! { printf '%s' "$content" > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$path"; }; then die "could not write ${path}"; fi
        info "Wrote ${path}"
        manifest_add dropin "$path"
    fi
    eff="$(cfg_get Acquire::Retries)"
    if [[ "$eff" == 0 ]]; then
        ok "apt-config reports Acquire::Retries \"0\": APT no longer retries a download on this host."
        inf "A command line such as apt-get -o Acquire::Retries=3 still overrides it, and so does a setting in /etc/apt/apt.conf if it has one."
        inf "This is a stopgap. Update APT, then run: ${SCRIPT_NAME} rollback"
        return 0
    fi
    rm -f "$path"
    bad "apt-config still reports Acquire::Retries \"${eff:-unset}\" after the file was written, so another setting wins. The new file was removed again."
    grep -rnE 'Retries' /etc/apt/apt.conf "$APT_CONF_DIR" 2>/dev/null | grep -v "$DROPIN" | head -n 5 | sed 's/^/        /'
    return 1
}

cmd_rollback() {
    local dry=0 force=0 a path
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --force) force=1 ;; *) die "Unknown option: $a (rollback [--dry-run] [--force])" ;; esac; done
    path="${APT_CONF_DIR}/${DROPIN}"
    step "Roll back the stopgap"
    if [[ ! -e "$path" ]]; then ok "${path} is not there: nothing to roll back."; return 0; fi
    if ! grep -qF "$DROPIN_MARK" "$path" && [[ $force -eq 0 ]]; then
        die "${path} was not written by this script, or it was edited. Look at it, or add --force to remove it."
    fi
    if [[ $dry -eq 1 ]]; then inf "would remove ${path}"; return 0; fi
    need_root "rollback changes ${APT_CONF_DIR}"
    rm -f "$path" && info "Removed ${path}" && manifest_add removed "$path"
    ok "APT's retry setting is back to what the rest of the configuration says."
    return 0
}

# ---------- main ----------------------------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-109518; fixed in APT 3.3.6, 3.2.1, 3.0.4, 2.8.4, 2.6.2, 2.4.15, 2.2.5 and older lines; needs retries and redirects"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
# ---------- one change at a time ---------------------------------------------------------------------
# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a dry run
# (a * in CMDS stands for the default command, for a tool whose default changes the host),
# run the script again under flock(1), so two runs cannot interleave their changes. The second run waits
# PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. flock -o leaves the lock with the waiting
# flock process, so a service this script starts does not inherit it and hold it. The lock file is
# STATE_DIR/.lock, or /var/lib/psf-security-patches/<script>/.lock. Without flock (macOS) nothing is locked.
# PSF_LOCK_HELD marks the re-run so it does not lock again: the script sets it, leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_words=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
        case "$lk_arg" in -*) ;; *) lk_words=$((lk_words + 1)) ;; esac
    done
    [[ $lk_words -eq 0 && "$lk_cmds" == *" * "* ]] && lk_hit=1      # no command named, and the default command changes the host
    [[ $lk_hit -eq 1 ]] || return 0
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "mitigate rollback" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
