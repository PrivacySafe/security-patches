#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Claude Code extension SSH backdoor (Cursor marketplace, 29 October 2026): check, hunt, update, keys, clean  (v1)
# No CVE (supply-chain compromise of an editor extension)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Cursor reports that between about 2:27am and 1:35pm Pacific time on 29 October
# 2026 a maliciously modified copy of the Claude Code extension for VS Code
# (versions 2.1.312 and 2.1.313) was served from the Cursor extension
# marketplace, to up to 5,000 developer machines. Anthropic says it was not
# involved in building, publishing or hosting the tampered build. A prefix added
# to extension.js runs the moment the editor loads the extension. It:
#   - appends the attacker's ed25519 key (comment "svc-telemetry") to
#     ~/.ssh/authorized_keys;
#   - writes ~/.config/.smt (a retry loop) and ~/.config/.smtk (the tunnel key),
#     and a copy of the tunnel key as .stk_<10 hex> in the temp directory;
#   - opens a reverse SSH tunnel (ssh -N -R '*:0:localhost:22') to
#     tunnel@134.209.82.225 and retries it about every 60 seconds, kept alive
#     across reboots by a LaunchAgent (~/Library/LaunchAgents/
#     com.apple.sysmond.plist) on macOS or an @reboot crontab entry on GNU/Linux
#     (a scheduled task named SysMon on Windows);
#   - tries to switch the local SSH server on (this fails without admin rights
#     on most machines, so the inbound path is often closed, but the key and
#     the persistence are still planted);
#   - POSTs the hostname, user name, OS, public IP, git email and the NAMES of
#     environment variables that look like secrets (not their values) to
#     http://134.209.82.225:8099/beacon.
# Cursor says it has had the attacker's server taken offline. Treat that as a
# reason the damage may be smaller, not as a reason to skip the cleanup.
#
# Updating or uninstalling the extension does NOT remove any of that. A
# replacement build, 2.1.314, was published on 30 October; it swaps the
# extension's files and leaves the key, the scripts and the persistence in
# place. This script checks for each piece separately.
#
# One detail matters when judging versions: a legitimate 2.1.312 exists (it is
# on npm and Open VSX, published 27 October). Only the copy served by Cursor's
# marketplace was modified. So 2.1.312 is judged by the content of its
# extension.js, not by its number. 2.1.313 was never published legitimately
# anywhere and is reported on sight.
#
# Get the vendor's fix FIRST, then clean. Anthropic replaced the bad build with
# Claude Code 2.1.314 (published 30 October 2026); 2.1.314 or newer is the fix. Every
# run of check, hunt, clean and update says so up front. The "update" command below
# installs it through your editor, but only after it shows you the state of the
# machine and asks. Installing the fix is half of the job: it does not remove an
# SSH key, implant files or persistence that already got planted.
#
# Usage:
#   ./claude-code-vsx-oct2026-check.sh [command] [options]
#
#   check (default)  read-only. Looks for: an installed Claude Code extension
#                    that is 2.1.313 or carries the backdoored extension.js
#                    (known SHA-256, the C2 address or the svc-telemetry key
#                    comment); a downloaded or cached extension package with a
#                    known bad hash; the attacker's key in authorized_keys
#                    (matched by key, by fingerprint and by comment), with an
#                    inventory of every other key so an unknown one stands out;
#                    the implant files; the crontab entry or LaunchAgent;
#                    running tunnel processes; a connection to the C2; and
#                    whether this machine's SSH server is reachable on the
#                    loopback address, which is the door the tunnel opens.
#                    Exit 0 = nothing found, 1 = exposure or compromise found,
#                    2 = could not read what it needed to.
#   hunt             read-only. Searches the SSH server logs for a login with
#                    the attacker's key (a login through the tunnel arrives
#                    from 127.0.0.1 or ::1), and lists recent changes under
#                    ~/.ssh, ~/.config and the LaunchAgents folder for review.
#                    Exit 0 = no login evidence, 1 = evidence found.
#   update           the vendor's fix, with questions first. (1) a read-only check, as
#                    above. (2) for each editor command line (code, cursor, codium,
#                    windsurf) whose extensions folder holds Claude Code, it shows the
#                    command it would run (<editor> --install-extension
#                    anthropic.claude-code --force; the editor downloads the extension
#                    from its own marketplace, this script downloads nothing) and asks
#                    before running it. An editor that does not have the extension is
#                    not offered one. (3) it checks again, says whether Claude Code
#                    2.1.314 or newer is now installed, and, if the machine shows the
#                    backdoor, asks whether to run 'clean' now. It needs a terminal to
#                    ask on, or --yes (install without asking). --yes never answers the
#                    clean question: that needs an answer at the terminal, or --and-clean. As root it checks and cleans but does not
#                    install, because editors are per user. Close the editor first.
#                    --dry-run shows the commands and runs none.
#   keys             read-only. Lists the private keys in each account's ~/.ssh with
#                    their type, fingerprint, last change and whether a passphrase
#                    protects the file, and counts the agent sockets in ~/.ssh/agent.
#                    It prints no key material. A private key file that no passphrase
#                    protects can be used by anything that can read it, which is what
#                    a file-reading flaw in an editor or assistant gets; keys loaded in
#                    an ssh-agent are not in those files. OpenSSH 10.1 and later keep
#                    the agent's socket in ~/.ssh/agent (older versions use /tmp):
#                    that folder holds sockets, not keys, so there is nothing in it to
#                    block. Exit 0, or 2 if something could not be read.
#   clean            containment and cleanup. Stops the tunnel processes,
#                    unloads and removes the persistence, removes the
#                    attacker's key line from authorized_keys, and moves the
#                    implant files and the bad extension folders into a
#                    backup folder (nothing is deleted). Add --reinstall to
#                    install the extension again through any editor command
#                    line it finds (code, cursor, codium, windsurf). Close the
#                    editor first. Re-checks afterwards and exits 1 if anything
#                    remains. --dry-run shows what it would do. Before it changes anything
#                    it keeps a record of each account's ~/.ssh in the backup folder:
#                    authorized_keys, config and known_hosts with their times, an
#                    inventory of the private keys (no key material), and the names of
#                    the agent sockets. --copy-keys also copies the private key files
#                    into the backup folder (0600), which is one more copy of a secret:
#                    delete it once you have rotated the keys. --drop-agent-keys empties
#                    the ssh-agents that belong to you (ssh-add -D) after the record is
#                    kept; the keys must be added again afterwards. It is not a cure:
#                    it does not help against key files that were already copied.
#   block            GNU/Linux, as root: drop outbound traffic to the C2
#                    address with nftables or iptables. Defense in depth only;
#                    rules do not survive a reboot. On macOS it prints how to
#                    do the same. --dry-run shows the command.
#   unblock          remove the rule that block added.
#   version          print the script version.
#
# Options: --dry-run (clean, block, unblock, update)   --reinstall (clean)   --yes, --and-clean (update)
#          --copy-keys, --drop-agent-keys (clean, and the clean step of update)
#
# Run it as your own user to check your own account. Run it as root to check
# every account on the machine. It works on GNU/Linux and macOS. It does not
# cover Windows: use the remediation script in Cursor's notice there.
#
# Env overrides:
#   NO_NOTICE=1                       leave out the upfront notice about the vendor's fix
#   ANSWERS_FILE=/path                answers for update, one per line (y or n), read
#                                     instead of the terminal (for automation)
#   HOMES="/home/a:/home/b"           accounts to check, colon separated (default:
#                                     you; as root: every account)
#   BACKUP_ROOT=/var/backups/claude-code-vsx-oct2026   where clean puts files
#                                     (default for a normal user:
#                                     ~/claude-code-vsx-oct2026-backup)
#   TMP_DIRS="/tmp:/var/tmp"          where to look for .stk_ key copies (colon separated)
#   EXT_ROOTS_EXTRA="/opt/ide/extensions"   more folders that hold extensions (colon separated)
#   EXTRA_KEY_BLOBS, EXTRA_FPRS, EXTRA_SHA256   more indicators, space separated,
#                                     for when the vendors publish updates
#   HUNT_LOGS="/var/log/ssh/*.log"    extra log files for hunt
#   HUNT_LOG_DAYS=4                   how many days of macOS log to search
#   LOOPBACK_PORT=22                  port to probe on 127.0.0.1
#   PLATFORM=Linux|Darwin             override the detected platform
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

SCRIPT_NAME="claude-code-vsx-oct2026-check.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
REF="https://cursor.com/blog/claude-code-extension-security-notice"
FIXED_VER="2.1.314"

PLATFORM="${PLATFORM:-$(uname -s 2>/dev/null || echo Linux)}"
HOMES="${HOMES:-}"
BACKUP_ROOT="${BACKUP_ROOT:-}"
TMP_DIRS="${TMP_DIRS:-}"
EXT_ROOTS_EXTRA="${EXT_ROOTS_EXTRA:-}"
EXTRA_KEY_BLOBS="${EXTRA_KEY_BLOBS:-}"
EXTRA_FPRS="${EXTRA_FPRS:-}"
EXTRA_SHA256="${EXTRA_SHA256:-}"
HUNT_LOGS="${HUNT_LOGS:-}"
HUNT_LOG_DAYS="${HUNT_LOG_DAYS:-4}"
LOOPBACK_PORT="${LOOPBACK_PORT:-22}"

# ---------- indicators (Cursor and Phorion, 29 and 30 October 2026) ----------
C2_IP="134.209.82.225"
KEY_BLOBS="AAAAC3NzaC1lZDI1NTE5AAAAIDdvylCEJ/k2TpezcTfedrkHyFSK9IZ3vmP6vhY4Ss0P ${EXTRA_KEY_BLOBS}"
# fingerprint of the key planted in authorized_keys, and of the tunnel key
FPRS="SHA256:0Z6R+DF64Do2nwQic8a7kkfDLNNk4IiK+2U2Rci4htk SHA256:KOAU57+ZG6u3MG4WwzPzPX2O5YEe9qdOC1Bl+6MVyDQ ${EXTRA_FPRS}"
# the backdoored extension.js
JS_SHA256="ecb58cb29078d9646ad1dcdbe51526f2d9cfea06be5fb2ab183e8ecc3ab6bf15 ${EXTRA_SHA256}"
# the backdoored packages (2.1.312 and 2.1.313; darwin-arm64 and win32-x64)
# The last hash, 432ccdee..., is a darwin-arm64 package that one secondary report (Rescana) lists and
# Cursor's own list does not. It is included because a wrong hash can never match a good file.
VSIX_SHA256="fcbb327e38e61c4fec795e0d0591f52cd1014b813d20a5912104953c3a17c364 3de1722901165769893bef57c72594e9a54459faa23f3091b136b79966edd081 80402fdcad8799285fd93044976973ca000da7995fb93363f819bb8e4f84ee6c 6786ec90cbd45949695bd7805c9fbb26cfc91bc5fc897de0183d9bcb9cb21731 432ccdee3801f99e52b8fe31f69ea9870118e96ea7ef9ecabed1479621b5ab62 ${EXTRA_SHA256}"

# folders under a home that hold editor extensions
EXT_REL=".vscode/extensions .vscode-insiders/extensions .vscode-oss/extensions .cursor/extensions .windsurf/extensions .kiro/extensions .trae/extensions .antigravity/extensions .vscode-server/extensions .vscode-server-insiders/extensions .cursor-server/extensions .windsurf-server/extensions .local/share/code-server/extensions .openvscode-server/extensions .theia/deployedPlugins .theia/plugins"
# folders under a home where an editor caches downloaded extension packages
VSIX_REL=(".config/Code/CachedExtensionVSIXs" ".config/Cursor/CachedExtensionVSIXs" ".config/VSCodium/CachedExtensionVSIXs" ".config/Windsurf/CachedExtensionVSIXs" "Library/Application Support/Code/CachedExtensionVSIXs" "Library/Application Support/Cursor/CachedExtensionVSIXs" "Library/Application Support/VSCodium/CachedExtensionVSIXs" "Library/Application Support/Windsurf/CachedExtensionVSIXs" "Downloads")

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
QUIET=0
say()     { [[ "$QUIET" -eq 1 ]] || echo -e "$*"; }
info()    { say "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { say "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { say "  ${GREEN}✓${NC} $*"; }
bad()     { say "  ${RED}✗${NC} $*"; }
inf()     { say "  • $*"; }
caution() { say "  ${YELLOW}!${NC} $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------- findings ---------------------------------------------------------
N_EXPOSED=0      # a bad extension is or was on disk
N_COMP=0         # the implant, the key, the tunnel or a login was found
N_UNREAD=0       # something could not be read
N_REVIEW=0       # looks related but is not proven
R_EXT=(); R_FILES=(); R_PLISTS=(); R_AK=(); R_PIDS=(); R_CRON=(); EXT_VERS=()
reset_records() {
    N_EXPOSED=0; N_COMP=0; N_UNREAD=0; N_REVIEW=0
    R_EXT=(); R_FILES=(); R_PLISTS=(); R_AK=(); R_PIDS=(); R_CRON=(); EXT_VERS=()
}

# ---------- small helpers ----------------------------------------------------
# print the items of a colon-separated list, one per line (items may contain spaces)
split_list() { local IFS=:; local x; for x in $1; do [[ -n "$x" ]] && printf '%s\n' "$x"; done; return 0; }
lc() { printf '%s' "$1" | tr 'A-Z' 'a-z'; }

sha256_of() {
    if have sha256sum; then sha256sum "$1" 2>/dev/null | awk '{print $1}' || true
    elif have shasum; then shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' || true
    elif have openssl; then openssl dgst -sha256 "$1" 2>/dev/null | awk '{print $NF}' || true
    fi
}
in_list() { local x needle="$1"; shift; for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done; return 1; }

# fingerprint of the public key on one authorized_keys line (empty if unknown)
key_fpr() {
    have ssh-keygen || return 0
    local t out
    t="$(mktemp "${TMPDIR:-/tmp}/vsxkey.XXXXXX" 2>/dev/null)" || return 0
    printf '%s\n' "$1" >"$t"
    out="$(ssh-keygen -l -f "$t" </dev/null 2>/dev/null | awk 'NR==1 {print $2}' || true)"
    rm -f "$t"
    printf '%s' "$out"
}
# fingerprint of a key file (public or private; the public half of a modern private key is stored in the clear)
file_fpr() {
    have ssh-keygen || return 0
    ssh-keygen -l -f "$1" </dev/null 2>/dev/null | awk 'NR==1 {print $2}' || true
}
fpr_is_ioc() { [[ -n "$1" ]] && in_list "$1" $FPRS; }

# true if the line is the attacker's key, by key text, comment or fingerprint
ioc_key_line() {
    local line="$1" b fp
    case "$line" in *svc-telemetry*) return 0 ;; esac
    for b in $KEY_BLOBS; do case "$line" in *"$b"*) return 0 ;; esac; done
    fp="$(key_fpr "$line")"
    fpr_is_ioc "$fp"
}

home_owner() { ls -ld "$1" 2>/dev/null | awk '{print $3}' || true; }

list_homes() {
    local h
    if [[ -n "$HOMES" ]]; then split_list "$HOMES"; return 0; fi
    if [[ "$(id -u)" -eq 0 ]]; then
        for h in /home/* /Users/* /root /var/root; do
            [[ -d "$h" ]] || continue
            case "$h" in /Users/Shared|/Users/Guest|/home/lost+found) continue ;; esac
            echo "$h"
        done
    else
        echo "${HOME:-}"
    fi
}

tmp_dirs() {
    local d
    if [[ -n "$TMP_DIRS" ]]; then split_list "$TMP_DIRS"; return 0; fi
    for d in /tmp /var/tmp /private/tmp "${TMPDIR:-}" /private/var/folders/*/*/T; do
        [[ -n "$d" && -d "$d" ]] && echo "$d"
    done
    if have getconf; then d="$(getconf DARWIN_USER_TEMP_DIR 2>/dev/null || true)"; [[ -n "$d" && -d "$d" ]] && echo "$d"; fi
    return 0
}

# ---------- scan: editor extensions ------------------------------------------
# Folder names look like anthropic.claude-code-2.1.313-darwin-arm64 (VS Code family)
# or anthropic.claude-code@2.1.313 (Theia).
scan_extensions() {
    local home="$1" rel root d base l rest ver f hit reason js_ok n_js sha
    local roots=()
    for rel in $EXT_REL; do [[ -d "$home/$rel" ]] && roots+=("$home/$rel"); done
    while IFS= read -r rel; do
        [[ -n "$rel" && -d "$rel" ]] && roots+=("$rel")
    done < <(split_list "$EXT_ROOTS_EXTRA")
    for d in /Applications/*-portable-data/extensions; do [[ -d "$d" ]] && roots+=("$d"); done
    local i=0 found=0
    while [[ $i -lt ${#roots[@]} ]]; do
        root="${roots[$i]}"; i=$((i + 1))
        for d in "$root"/*; do
            [[ -d "$d" ]] || continue
            base="$(basename "$d")"; l="$(lc "$base")"
            case "$l" in
                anthropic.claude-code-*) rest="${l#anthropic.claude-code-}" ;;
                anthropic.claude-code@*) rest="${l#anthropic.claude-code@}" ;;
                *) continue ;;
            esac
            found=$((found + 1))
            ver="${rest%%-*}"
            EXT_VERS+=("$ver")
            hit=""; reason=""; js_ok=0; n_js=0
            while IFS= read -r f; do
                [[ -n "$f" ]] || continue
                n_js=$((n_js + 1))
                if [[ ! -r "$f" ]]; then N_UNREAD=$((N_UNREAD + 1)); caution "cannot read ${f}"; continue; fi
                js_ok=1
                sha="$(sha256_of "$f")"
                if [[ -n "$sha" ]] && in_list "$sha" $JS_SHA256; then hit=1; reason="extension.js has the known backdoored SHA-256"; break; fi
                if grep -qF "$C2_IP" "$f" 2>/dev/null; then hit=1; reason="extension.js contains the C2 address ${C2_IP}"; break; fi
                if grep -qF "svc-telemetry" "$f" 2>/dev/null; then hit=1; reason="extension.js contains the svc-telemetry key comment"; break; fi
            done < <(find "$d" -maxdepth 3 -type f -name extension.js 2>/dev/null)
            if [[ -n "$hit" ]]; then
                bad "backdoored extension: ${d} (${reason})"
                N_EXPOSED=$((N_EXPOSED + 1)); R_EXT+=("$d")
            elif [[ "$ver" == "2.1.313" ]]; then
                bad "version 2.1.313 is on disk: ${d} (never a legitimate release; Cursor lists it as malicious)"
                N_EXPOSED=$((N_EXPOSED + 1)); R_EXT+=("$d")
            elif [[ "$ver" == "2.1.312" ]]; then
                if [[ $js_ok -eq 1 ]]; then
                    inf "version 2.1.312: ${d}; its extension.js has none of the indicators (a legitimate 2.1.312 exists on npm and Open VSX, only Cursor's marketplace copy was modified)"
                else
                    caution "version 2.1.312 with no readable extension.js: ${d}; cannot tell the legitimate build from the modified one"
                    N_REVIEW=$((N_REVIEW + 1))
                fi
            else
                ok "Claude Code ${ver} in ${d}: not an affected version"
            fi
        done
    done
    [[ $found -gt 0 ]] || inf "no Claude Code extension folders under ${home}"
}

# ---------- scan: downloaded or cached extension packages --------------------
scan_packages() {
    local home="$1" d f sha i=0
    while [[ $i -lt ${#VSIX_REL[@]} ]]; do
        d="$home/${VSIX_REL[$i]}"; i=$((i + 1))
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            [[ -n "$f" && -r "$f" ]] || continue
            sha="$(sha256_of "$f")"
            if [[ -n "$sha" ]] && in_list "$sha" $VSIX_SHA256; then
                bad "extension package with a known bad hash: ${f}"
                N_EXPOSED=$((N_EXPOSED + 1)); R_FILES+=("$f")
            fi
        done < <(find "$d" -maxdepth 2 -type f -iname '*claude-code*' 2>/dev/null)
    done
}

# ---------- scan: SSH keys ---------------------------------------------------
scan_keys() {
    local home="$1" f line t n fp bad_here
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
        [[ -e "$f" ]] || continue
        if [[ ! -r "$f" ]]; then N_UNREAD=$((N_UNREAD + 1)); caution "cannot read ${f}"; continue; fi
        n=0; bad_here=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            t="${line#"${line%%[![:space:]]*}"}"
            [[ -z "$t" || "${t:0:1}" == "#" ]] && continue
            n=$((n + 1))
            if ioc_key_line "$t"; then
                bad_here=1
                bad "the attacker's key is in ${f}: $(printf '%s' "$t" | awk '{print substr($0,1,60)}')..."
            else
                fp="$(key_fpr "$t")"
                inf "key in ${f}: ${fp:-fingerprint unavailable} $(printf '%s' "$t" | awk '{print substr($NF,1,40)}')"
            fi
        done <"$f"
        if [[ $bad_here -eq 1 ]]; then N_COMP=$((N_COMP + 1)); R_AK+=("$f"); fi
        [[ $n -gt 0 ]] || inf "${f} has no keys"
        if [[ -n "$(find "$f" -newermt 2026-10-29 2>/dev/null)" ]]; then
            caution "${f} was modified on or after 29 October 2026: check that every key above is one you added"
        fi
    done
}

# ---------- scan: implant files and persistence ------------------------------
# kind is sh, key or plist
implant_confirmed() {
    local f="$1" kind="$2" fp
    case "$kind" in
        sh)    grep -qF "$C2_IP" "$f" 2>/dev/null || grep -qF '.smtk' "$f" 2>/dev/null ;;
        plist) grep -qF '.config/.smt' "$f" 2>/dev/null ;;
        key)
            fp="$(file_fpr "$f")"
            if [[ -n "$fp" ]]; then fpr_is_ioc "$fp"
            else head -c 60 "$f" 2>/dev/null | grep -q 'PRIVATE KEY'; fi ;;
    esac
}
note_implant() {
    local f="$1" kind="$2"
    if [[ ! -r "$f" ]]; then N_UNREAD=$((N_UNREAD + 1)); caution "cannot read ${f}"; return 0; fi
    if implant_confirmed "$f" "$kind"; then
        bad "implant file: ${f}"
        N_COMP=$((N_COMP + 1)); R_FILES+=("$f")
        [[ "$kind" == "plist" ]] && R_PLISTS+=("$f")
    else
        caution "${f} has the implant's name but not its content: review it by hand (left alone)"
        N_REVIEW=$((N_REVIEW + 1))
    fi
    return 0
}

scan_implants_home() {
    local home="$1" f
    f="$home/.config/.smt";  [[ -e "$f" ]] && note_implant "$f" sh
    f="$home/.config/.smtk"; [[ -e "$f" ]] && note_implant "$f" key
    f="$home/Library/LaunchAgents/com.apple.sysmond.plist"; [[ -e "$f" ]] && note_implant "$f" plist
    return 0
}
scan_implants_system() {
    local f d b re='^\.stk_[0-9a-f]{10}$'
    for f in /Library/LaunchAgents/com.apple.sysmond.plist /Library/LaunchDaemons/com.apple.sysmond.plist; do
        [[ -e "$f" ]] && note_implant "$f" plist
    done
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        for f in "$d"/.stk_*; do
            [[ -e "$f" ]] || continue
            b="$(basename "$f")"
            [[ "$b" =~ $re ]] || continue
            note_implant "$f" key
        done
    done < <(tmp_dirs | sort -u)
    # a crontab or cron.d entry that runs the loop
    for f in /etc/cron.d/*; do
        [[ -f "$f" && -r "$f" ]] || continue
        if grep -qF '.config/.smt' "$f" 2>/dev/null; then
            bad "cron entry runs the implant loop: ${f} (remove the line by hand)"
            N_COMP=$((N_COMP + 1))
        fi
    done
    return 0
}

scan_cron_home() {
    local home="$1" owner ct
    have crontab || return 0
    owner="$(home_owner "$home")"
    if [[ "$(id -u)" -eq 0 && -n "$owner" && "$owner" != "root" ]]; then
        ct="$(crontab -u "$owner" -l 2>/dev/null || true)"
    elif [[ "$(id -u)" -eq 0 ]]; then
        ct="$(crontab -l 2>/dev/null || true)"
    else
        [[ "$home" == "${HOME:-}" ]] || return 0
        owner="$(id -un 2>/dev/null || echo me)"
        ct="$(crontab -l 2>/dev/null || true)"
    fi
    if grep -qF '.config/.smt' <<<"$ct"; then
        bad "crontab of ${owner:-root} runs the implant loop (@reboot ... .config/.smt)"
        N_COMP=$((N_COMP + 1)); R_CRON+=("${owner:-root}")
    fi
    return 0
}

# ---------- scan: processes and network --------------------------------------
PS_OUT=""
scan_processes() {
    local l pid args role
    PS_OUT="$(ps -axww -o pid=,args= 2>/dev/null || ps -ax -o pid=,args= 2>/dev/null || true)"
    if [[ -z "$PS_OUT" ]]; then N_UNREAD=$((N_UNREAD + 1)); caution "could not list processes (ps failed)"; return 0; fi
    local found=0
    while IFS= read -r l; do
        l="${l#"${l%%[![:space:]]*}"}"
        [[ -n "$l" ]] || continue
        pid="${l%% *}"; args="${l#* }"
        [[ "$pid" =~ ^[0-9]+$ ]] || continue
        [[ "$pid" == "$$" || "$pid" == "${PPID:-0}" ]] && continue
        case "$args" in *"$SCRIPT_NAME"*) continue ;; esac
        role=""
        case "$args" in
            *"$C2_IP"*) role="ssh" ;;
        esac
        if [[ -z "$role" ]]; then
            case "$args" in
                *ssh*.stk_*|*ssh*.smtk*) role="ssh" ;;
                *"sh "*/.config/.smt|*"sh "*/.config/.smt\ *|*"sh "*/.config/.smt\"*) role="loop" ;;
            esac
        fi
        if [[ -n "$role" ]]; then
            found=$((found + 1))
            bad "tunnel or persistence process ${pid}: $(printf '%s' "$args" | awk '{print substr($0,1,110)}')"
            N_COMP=$((N_COMP + 1)); R_PIDS+=("${role}:${pid}")
        fi
    done <<<"$PS_OUT"
    [[ $found -gt 0 ]] || ok "no tunnel or retry-loop process is running"
    return 0
}

scan_network() {
    local conns=""
    if have ss; then conns="$(ss -tn 2>/dev/null || true)"
    elif have lsof; then conns="$(lsof -nP -iTCP 2>/dev/null || true)"
    elif have netstat; then conns="$(netstat -an 2>/dev/null || true)"
    else N_UNREAD=$((N_UNREAD + 1)); caution "none of ss, lsof or netstat is available: cannot look for a connection to the C2"; return 0; fi
    if grep -qF "$C2_IP" <<<"$conns"; then
        bad "a connection to the C2 ${C2_IP} is open or being retried"
        N_COMP=$((N_COMP + 1))
    else
        ok "no connection to ${C2_IP}"
    fi
    return 0
}

# Can something reach this machine's SSH server on the loopback address? That is
# where the reverse tunnel delivers the attacker. A successful probe sends no data.
LOOPBACK_OPEN=0
scan_loopback() {
    local rc=0
    if have timeout; then timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/${LOOPBACK_PORT}" 2>/dev/null || rc=$?
    else bash -c "exec 3<>/dev/tcp/127.0.0.1/${LOOPBACK_PORT}" 2>/dev/null || rc=$?; fi
    if [[ $rc -eq 0 ]]; then
        LOOPBACK_OPEN=1
        caution "127.0.0.1:${LOOPBACK_PORT} accepts connections: this machine runs an SSH server (Remote Login on macOS). If the key was planted and the tunnel connected, this is the door it opens"
    else
        ok "127.0.0.1:${LOOPBACK_PORT} is closed: nothing listens there, so a connection forwarded through the tunnel would be refused"
    fi
    return 0
}

scan_launchd_loaded() {
    [[ "$PLATFORM" == "Darwin" ]] || return 0
    have launchctl || return 0
    if grep -qF 'com.apple.sysmond' <<<"$(launchctl list 2>/dev/null)"; then
        bad "launchd has com.apple.sysmond loaded (not a real Apple label)"
        N_COMP=$((N_COMP + 1))
    fi
    return 0
}

# ---------- driver -----------------------------------------------------------
HOME_LIST=""
scan_all() {
    local h n=0
    reset_records
    HOME_LIST="$(list_homes)"
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        if [[ ! -d "$h" ]]; then inf "home does not exist, skipped: ${h}"; continue; fi
        if [[ ! -r "$h" || ! -x "$h" ]]; then N_UNREAD=$((N_UNREAD + 1)); caution "cannot read ${h}"; continue; fi
        n=$((n + 1))
        step "Account: ${h}"
        step_extensions_msg
        scan_extensions "$h"
        scan_packages "$h"
        step_keys_msg
        scan_keys "$h"
        step_implants_msg
        scan_implants_home "$h"
        scan_cron_home "$h"
    done <<<"$HOME_LIST"
    [[ $n -gt 0 ]] || die "none of the accounts to check can be read (${HOME_LIST:-none}): nothing was checked"
    step "Machine-wide: key copies in temp folders, cron.d, launchd"
    scan_implants_system
    scan_launchd_loaded
    step "Running processes and network"
    scan_processes
    scan_network
    scan_loopback
    return 0
}
step_extensions_msg() { inf "editor extensions:"; }
step_keys_msg()       { inf "SSH authorized keys:"; }
step_implants_msg()   { inf "implant files and persistence:"; }

verdict() {
    echo
    if [[ $N_COMP -gt 0 ]]; then
        warn "COMPROMISED: ${N_COMP} sign(s) that the backdoor ran on this machine."
        [[ $LOOPBACK_OPEN -eq 1 ]] && warn "This machine runs an SSH server, so a login through the tunnel was possible while the C2 was up. Run 'hunt' to look for one."
        warn "Next: close the editor, run 'clean', then rotate every credential this account could reach, from a different, trusted machine. Updating the extension alone does not remove the backdoor."
    elif [[ $N_EXPOSED -gt 0 ]]; then
        warn "EXPOSED: a bad extension build is on disk, but no key, implant or tunnel was found. It may never have been loaded, or it may already have been cleaned. Run 'clean' to remove it and reinstall the extension."
    elif [[ $N_UNREAD -gt 0 ]]; then
        warn "No indicator found, but ${N_UNREAD} thing(s) could not be read, so this is not a clean result."
    else
        info "No indicator of the Claude Code extension backdoor was found."
    fi
    if [[ $N_COMP -gt 0 || $N_EXPOSED -gt 0 ]]; then
        warn "Also install the vendor's fix: Claude Code ${FIXED_VER} or newer ('${SELF} update' asks first). Do not stop there: it does not remove the backdoor."
        inf "Your own SSH private keys: '${SELF} keys' lists which are not protected by a passphrase."
    fi
    [[ $N_REVIEW -eq 0 ]] || warn "${N_REVIEW} item(s) look related and need a look by hand (marked above)."
    inf "This checks this operating system only. On Windows, use Cursor's remediation script (${REF})."
}

cmd_check() {
    scan_all
    verdict
    if [[ $N_COMP -gt 0 || $N_EXPOSED -gt 0 ]]; then exit 1; fi
    if [[ $N_UNREAD -gt 0 ]]; then exit 2; fi
    exit 0
}


# ---------- SSH private keys: inventory, a record before cleaning, agent sockets
# Nothing here prints or copies key material unless --copy-keys is given.
COPY_KEYS=0; DROP_AGENT=0
mtime_of() {   # file -> YYYY-MM-DD
    local t
    if [[ "$PLATFORM" == "Darwin" ]]; then t="$(stat -f %Sm -t %Y-%m-%d "$1" 2>/dev/null || true)"
    else t="$(stat -c %y "$1" 2>/dev/null | awk '{print $1}' || true)"; fi
    printf '%s' "${t:-unknown}"
}
is_private_key_file() {   # 0 when the first line is a PEM or OpenSSH private key header
    local first
    [[ -f "$1" && -r "$1" ]] || return 1
    first="$(head -n 1 "$1" 2>/dev/null | tr -d '\r' || true)"
    case "$first" in "-----BEGIN "*"PRIVATE KEY-----") return 0 ;; esac
    return 1
}
# protected: a passphrase is needed. unprotected: none is. hardware: a security key handle
# (useless without the token). too-open: ssh-keygen refuses the file, fix its permissions first. unknown.
key_protection() {
    local info out rc
    have ssh-keygen || { echo unknown; return 0; }
    info="$(ssh-keygen -l -f "$1" </dev/null 2>/dev/null || true)"
    case "$info" in *"-SK)"*) echo hardware; return 0 ;; esac
    out="$(ssh-keygen -y -P '' -f "$1" 2>&1 </dev/null)" && rc=0 || rc=$?
    if [[ $rc -eq 0 ]]; then echo unprotected
    elif [[ "$out" == *"UNPROTECTED PRIVATE KEY FILE"* || "$out" == *"bad permissions"* ]]; then echo too-open
    elif [[ "$out" == *"passphrase"* ]]; then echo protected
    else echo unknown; fi
}
list_private_keys() {   # home -> one path per line, from ~/.ssh only (never the agent folder)
    local f
    for f in "$1"/.ssh/*; do
        [[ -f "$f" ]] || continue
        case "$f" in *.pub) continue ;; esac
        if is_private_key_file "$f"; then printf '%s\n' "$f"; fi
    done
    return 0
}
list_agent_sockets() {   # home -> sockets under ~/.ssh/agent (OpenSSH 10.1 and later)
    local s
    for s in "$1"/.ssh/agent/*; do
        if [[ -S "$s" ]]; then printf '%s\n' "$s"; fi
    done
    return 0
}
key_hosts() {   # home keyfile -> the Host entries in ~/.ssh/config that name this key
    local home="$1" key="$2" cfg line host="" out="" id
    cfg="$home/.ssh/config"
    [[ -r "$cfg" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line#"${line%%[![:space:]]*}"}"
        case "$line" in
            [Hh]ost\ *|[Hh]ost=*) host="${line#*[ =]}"; host="${host#"${host%%[![:space:]]*}"}" ;;
            [Ii]dentity[Ff]ile\ *|[Ii]dentity[Ff]ile=*)
                id="${line#*[ =]}"; id="${id#"${id%%[![:space:]]*}"}"; id="${id%\"}"; id="${id#\"}"
                # shellcheck disable=SC2088
                case "$id" in "~/"*) id="${home}/${id#\~/}" ;; esac
                id="${id//%d/$home}"
                if [[ "$id" == "$key" && -n "$host" ]]; then out="${out:+${out}, }${host}"; fi ;;
        esac
    done <"$cfg"
    printf '%s' "$out"
    return 0
}
key_inventory() {   # home -> lines: path|type|fingerprint|protection|modified
    local f info typ fp prot
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        info="$(ssh-keygen -l -f "$f" </dev/null 2>/dev/null || true)"
        if [[ -z "$info" && -r "${f}.pub" ]]; then info="$(ssh-keygen -l -f "${f}.pub" </dev/null 2>/dev/null || true)"; fi
        fp="$(printf '%s' "$info" | awk 'NR==1 {print $2}')"
        typ="$(printf '%s' "$info" | awk 'NR==1 {gsub(/[()]/, "", $NF); print $NF}')"
        prot="$(key_protection "$f")"
        printf '%s|%s|%s|%s|%s\n' "$f" "${typ:-unknown}" "${fp:-unavailable}" "$prot" "$(mtime_of "$f")"
    done < <(list_private_keys "$1")
    return 0
}

cmd_keys() {
    local h line path typ fp prot mt n=0 unprot=0 nsock s unread=0 accounts=0
    while IFS= read -r h; do
        [[ -n "$h" && -d "$h" ]] || continue
        if [[ ! -d "$h/.ssh" ]]; then inf "${h}: no .ssh folder"; continue; fi
        if [[ ! -r "$h/.ssh" || ! -x "$h/.ssh" ]]; then unread=$((unread + 1)); caution "cannot read ${h}/.ssh"; continue; fi
        accounts=$((accounts + 1))
        step "Account: ${h}"
        nsock=0
        while IFS= read -r s; do [[ -n "$s" ]] && nsock=$((nsock + 1)); done < <(list_agent_sockets "$h")
        if [[ -d "$h/.ssh/agent" ]]; then
            inf "${h}/.ssh/agent holds ${nsock} agent socket(s). OpenSSH 10.1 and later keep the agent's socket there (older versions use /tmp). A socket is not a key: the keys an agent holds are in its memory, and this folder has nothing in it to block or copy."
        fi
        while IFS='|' read -r path typ fp prot mt; do
            [[ -n "$path" ]] || continue
            n=$((n + 1))
            used="$(key_hosts "$h" "$path")"; [[ -z "$used" ]] || used="  used for: ${used}"
            case "$prot" in
                unprotected) unprot=$((unprot + 1)); caution "$(basename "$path")  ${typ}  ${fp}  NOT protected by a passphrase  changed ${mt}${used}" ;;
                too-open)    unprot=$((unprot + 1)); caution "$(basename "$path")  ${typ}  ${fp}  permissions too open, ssh-keygen refuses it: run chmod 600 on it, then check again  changed ${mt}${used}" ;;
                hardware)    inf "$(basename "$path")  ${typ}  ${fp}  hardware-backed: the file alone cannot sign  changed ${mt}${used}" ;;
                protected)   ok "$(basename "$path")  ${typ}  ${fp}  protected by a passphrase  changed ${mt}${used}" ;;
                *)           caution "$(basename "$path")  ${typ}  ${fp}  could not tell whether a passphrase protects it  changed ${mt}${used}" ;;
            esac
        done < <(key_inventory "$h")
    done < <(list_homes)
    echo
    if [[ $n -eq 0 ]]; then info "No private key files found in the ~/.ssh of ${accounts} account(s)."
    else
        info "${n} private key file(s); ${unprot} not protected by a passphrase."
    fi
    if [[ $unprot -gt 0 ]]; then
        warn "Anything that can read an unprotected key file can use it at once, for example the editor and assistant flaws reported on 29 October 2026 that let a local file read the rest of the disk, or a backdoor like this one."
        inf "If one of those could have run on this machine, treat the unprotected keys as exposed: make new keys, add each new public key where the old one was accepted, remove the old one there, then delete the old key files. Do it from a machine you trust."
        inf "A passphrase (ssh-keygen -p -f FILE) protects a file from now on. It does not undo a copy that was already taken."
    fi
    inf "Keys that are only loaded in an agent are not in these files. Dropping them from an agent does not help against key files that were already copied."
    [[ $unread -eq 0 ]] || exit 2
    exit 0
}

snapshot_ssh() {   # home -> a record of ~/.ssh in the backup folder, taken before anything is changed
    local h="$1" d f n inv key
    [[ -d "$h/.ssh" ]] || return 0
    qdir_init
    d="${QDIR}/ssh-record/$(printf '%s' "$h" | tr '/ ' '__')"
    if [[ "$DRY" -eq 1 ]]; then
        inf "would record ${h}/.ssh in ${d}: authorized_keys, config and known_hosts with their times, an inventory of the private keys (no key material) and the agent socket names"
        [[ "$COPY_KEYS" -eq 0 ]] || inf "would also copy the private key files there (0600)"
        return 0
    fi
    (umask 077; mkdir -p "$d") || { caution "could not create ${d}"; return 0; }
    for n in authorized_keys authorized_keys2 config known_hosts known_hosts.old; do
        f="$h/.ssh/$n"
        if [[ -f "$f" && -r "$f" ]]; then cp -p "$f" "$d/$n" 2>/dev/null || caution "could not copy ${f}"; fi
    done
    inv="$(key_inventory "$h")"
    { echo "# path|type|fingerprint|protection|modified (no key material)"; printf '%s\n' "$inv"; } >"$d/private-keys.txt"
    list_agent_sockets "$h" >"$d/agent-sockets.txt"
    if [[ "$COPY_KEYS" -eq 1 ]]; then
        (umask 077; mkdir -p "$d/private-keys") || true
        while IFS= read -r key; do
            [[ -n "$key" ]] || continue
            cp -p "$key" "$d/private-keys/$(basename "$key")" 2>/dev/null && chmod 600 "$d/private-keys/$(basename "$key")" 2>/dev/null || caution "could not copy ${key}"
        done < <(list_private_keys "$h")
        caution "the private key files are copied into ${d}/private-keys: that is one more copy of a secret. Delete it once you have rotated the keys."
    fi
    info "recorded ${h}/.ssh in ${d}"
}

drop_agent_keys() {   # the current user's own agents only
    local s seen=" " n
    if [[ "$(id -u)" -eq 0 ]]; then caution "not touching agents as root: run 'clean --drop-agent-keys' as the account that owns them"; return 0; fi
    have ssh-add || { inf "ssh-add not found: nothing to drop"; return 0; }
    n=0
    for s in "${SSH_AUTH_SOCK:-}" "${HOME:-}"/.ssh/agent/* /tmp/ssh-*/agent.*; do
        [[ -n "$s" && -S "$s" && -O "$s" ]] || continue
        case "$seen" in *" $s "*) continue ;; esac
        seen="${seen}${s} "; n=$((n + 1))
        if [[ "$DRY" -eq 1 ]]; then inf "would run: SSH_AUTH_SOCK=${s} ssh-add -D"; continue; fi
        if SSH_AUTH_SOCK="$s" ssh-add -D </dev/null >/dev/null 2>&1; then ok "dropped the keys loaded in the agent at ${s} (add them again when you are ready)"
        else caution "could not talk to the agent at ${s} (a stale socket?)"; fi
    done
    [[ $n -gt 0 ]] || inf "no running ssh-agent of yours was found"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0 f out fp h logs=() i=0 hits
    step "SSH server logs: a login with the attacker's key"
    inf "a login through the reverse tunnel arrives from 127.0.0.1 or ::1 and names the key's fingerprint"
    for f in /var/log/auth.log* /var/log/secure* /var/log/messages* /var/log/syslog*; do [[ -f "$f" ]] && logs+=("$f"); done
    if [[ -n "$HUNT_LOGS" ]]; then for f in $HUNT_LOGS; do [[ -f "$f" ]] && logs+=("$f"); done; fi
    local searched=0
    while [[ $i -lt ${#logs[@]} ]]; do
        f="${logs[$i]}"; i=$((i + 1))
        [[ -r "$f" ]] || { caution "cannot read ${f}"; continue; }
        searched=$((searched + 1))
        for fp in $FPRS; do
            if have zgrep; then hits="$(zgrep -hF "$fp" "$f" 2>/dev/null || true)"
            else hits="$(grep -hF "$fp" "$f" 2>/dev/null || true)"; fi
            if [[ -n "$hits" ]]; then
                found=$((found + 1))
                bad "login evidence for ${fp} in ${f}:"
                printf '%s\n' "$hits" | head -n 10 | sed 's/^/      /'
            fi
        done
    done
    if have journalctl; then
        searched=$((searched + 1))
        out="$(journalctl --no-pager --since 2026-10-29 -t sshd -t sshd-session -t ssh 2>/dev/null || true)"
        for fp in $FPRS; do
            hits="$(grep -F "$fp" <<<"$out" || true)"
            if [[ -n "$hits" ]]; then
                found=$((found + 1)); bad "login evidence for ${fp} in the journal:"
                printf '%s\n' "$hits" | head -n 10 | sed 's/^/      /'
            fi
        done
    fi
    if [[ "$PLATFORM" == "Darwin" ]] && have log; then
        searched=$((searched + 1))
        inf "searching the last ${HUNT_LOG_DAYS} days of the macOS unified log (this can take a few minutes)"
        out="$(log show --last "${HUNT_LOG_DAYS}d" --style compact --predicate 'process == "sshd" OR process == "sshd-session"' 2>/dev/null || true)"
        for fp in $FPRS; do
            hits="$(grep -F "$fp" <<<"$out" || true)"
            if [[ -n "$hits" ]]; then
                found=$((found + 1)); bad "login evidence for ${fp} in the unified log:"
                printf '%s\n' "$hits" | head -n 10 | sed 's/^/      /'
            fi
        done
    fi
    if [[ $searched -eq 0 ]]; then
        caution "no SSH log was readable here (try as root, or point HUNT_LOGS at the log)"
    elif [[ $found -eq 0 ]]; then
        ok "no login with the attacker's key in ${searched} log source(s). Logs rotate and a quiet LogLevel records no fingerprint, so this covers the log lines that remain"
    fi

    step "Recent changes to review (since 29 October 2026)"
    while IFS= read -r h; do
        [[ -d "$h" ]] || continue
        for f in "$h/.ssh" "$h/.config" "$h/Library/LaunchAgents"; do
            [[ -d "$f" ]] || continue
            out="$(find "$f" -maxdepth 1 -newermt 2026-10-29 -not -path "$f" 2>/dev/null || true)"
            [[ -z "$out" ]] || { inf "changed under ${f}:"; printf '%s\n' "$out" | head -n 20 | awk '/\/\.ssh\/agent$/ {print $0 "   (agent socket folder: OpenSSH 10.1 and later put the agent socket here, so it changes whenever an agent starts; it holds sockets, not keys)"; next} {print}' | sed 's/^/      /'; }
        done
    done < <(list_homes)

    echo
    if [[ $found -gt 0 ]]; then
        warn "The attacker's key was used to log in here. Treat this account and anything it could reach as compromised: rotate credentials from a trusted machine and consider rebuilding the host."
        exit 1
    fi
    exit 0
}

# ---------- clean ------------------------------------------------------------
DRY=0; REINSTALL=0; QDIR=""
run() { if [[ "$DRY" -eq 1 ]]; then inf "would run: $*"; return 0; fi; "$@"; }

qdir_init() {
    [[ -n "$QDIR" ]] && return 0
    local root stamp
    if [[ -n "$BACKUP_ROOT" ]]; then root="$BACKUP_ROOT"
    elif [[ "$(id -u)" -eq 0 ]]; then root="/var/backups/claude-code-vsx-oct2026"
    else root="${HOME:-/tmp}/claude-code-vsx-oct2026-backup"; fi
    stamp="$(date +%Y%m%d-%H%M%S)-$$"
    QDIR="${root}/${stamp}"
    if [[ "$DRY" -eq 1 ]]; then return 0; fi
    (umask 077; mkdir -p "${QDIR}/items") || die "cannot create the backup folder ${QDIR}"
    chmod 700 "$QDIR" 2>/dev/null || true
    : >"${QDIR}/MANIFEST.txt"
}
quarantine_item() {
    local src="$1" name dest
    qdir_init
    name="$(printf '%s' "$src" | tr '/ ' '__')"
    dest="${QDIR}/items/${name}"
    if [[ "$DRY" -eq 1 ]]; then inf "would move ${src} to ${dest}"; return 0; fi
    [[ -e "$dest" ]] && dest="${dest}.${RANDOM}"
    if mv -- "$src" "$dest" 2>/dev/null; then
        printf '%s -> %s\n' "$src" "$dest" >>"${QDIR}/MANIFEST.txt"
        info "moved ${src} to ${dest}"
    else
        caution "could not move ${src} (permissions?)"
    fi
}

clean_keys() {
    local f="$1" tmp line t removed=0 name
    qdir_init
    if [[ "$DRY" -eq 1 ]]; then inf "would remove the attacker's key line(s) from ${f} (backup kept)"; return 0; fi
    name="$(printf '%s' "$f" | tr '/ ' '__')"
    cp -p "$f" "${QDIR}/items/${name}.bak" 2>/dev/null || { caution "could not back up ${f}; leaving it alone"; return 0; }
    tmp="$(mktemp "${TMPDIR:-/tmp}/vsxkeys.XXXXXX")" || { caution "no temp file; leaving ${f} alone"; return 0; }
    while IFS= read -r line || [[ -n "$line" ]]; do
        t="${line#"${line%%[![:space:]]*}"}"
        if [[ -n "$t" && "${t:0:1}" != "#" ]] && ioc_key_line "$t"; then removed=$((removed + 1)); continue; fi
        printf '%s\n' "$line"
    done <"$f" >"$tmp"
    # write back through the original file so its owner and mode stay as they were
    if cat "$tmp" >"$f" 2>/dev/null; then info "removed ${removed} key line(s) from ${f}; original kept as ${QDIR}/items/${name}.bak"
    else caution "could not write ${f} (permissions?); the original is untouched and a copy is in ${QDIR}/items/${name}.bak"; fi
    rm -f "$tmp"
}

clean_cron() {
    local owner="$1" ct tmp name
    have crontab || { caution "no crontab command: remove the @reboot line for ${owner} by hand"; return 0; }
    qdir_init
    if [[ "$(id -u)" -eq 0 && "$owner" != "root" ]]; then ct="$(crontab -u "$owner" -l 2>/dev/null || true)"
    else ct="$(crontab -l 2>/dev/null || true)"; fi
    if [[ "$DRY" -eq 1 ]]; then inf "would remove the implant lines from the crontab of ${owner}"; return 0; fi
    name="crontab-${owner}.bak"
    printf '%s\n' "$ct" >"${QDIR}/items/${name}"
    tmp="$(grep -vF '.config/.smt' <<<"$ct" || true)"
    if [[ -z "$(printf '%s' "$tmp" | tr -d '[:space:]')" ]]; then
        if [[ "$(id -u)" -eq 0 && "$owner" != "root" ]]; then crontab -u "$owner" -r 2>/dev/null || true; else crontab -r 2>/dev/null || true; fi
    else
        if [[ "$(id -u)" -eq 0 && "$owner" != "root" ]]; then printf '%s\n' "$tmp" | crontab -u "$owner" - ; else printf '%s\n' "$tmp" | crontab - ; fi
    fi
    info "removed the implant line from the crontab of ${owner}; original saved as ${QDIR}/items/${name}"
}

kill_all_pids() {
    local role e pid i
    [[ ${#R_PIDS[@]} -gt 0 ]] || { inf "no tunnel or retry-loop process is running"; return 0; }
    for role in loop ssh; do
        i=0
        while [[ $i -lt ${#R_PIDS[@]} ]]; do
            e="${R_PIDS[$i]}"; i=$((i + 1))
            [[ "${e%%:*}" == "$role" ]] || continue
            pid="${e#*:}"
            if [[ "$DRY" -eq 1 ]]; then inf "would stop process ${pid} (${role})"; continue; fi
            kill "$pid" 2>/dev/null && info "stopped process ${pid} (${role})" || caution "could not stop process ${pid} (owned by another user? run as root)"
        done
    done
    [[ "$DRY" -eq 1 ]] && return 0
    sleep 1
    i=0
    while [[ $i -lt ${#R_PIDS[@]} ]]; do
        pid="${R_PIDS[$i]#*:}"; i=$((i + 1))
        if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid" 2>/dev/null || true; fi
    done
}

unload_plist() {
    local p="$1" owner uid
    [[ "$PLATFORM" == "Darwin" ]] && have launchctl || return 0
    if [[ "$DRY" -eq 1 ]]; then inf "would unload ${p} from launchd"; return 0; fi
    owner="$(home_owner "$(dirname "$(dirname "$p")")")"
    uid=""; [[ -n "$owner" ]] && uid="$(id -u "$owner" 2>/dev/null || true)"
    if [[ -n "$uid" && "$(id -u)" -eq 0 ]]; then
        launchctl bootout "gui/${uid}/com.apple.sysmond" 2>/dev/null || launchctl unload "$p" 2>/dev/null || true
    else
        launchctl bootout "gui/$(id -u)/com.apple.sysmond" 2>/dev/null || launchctl unload "$p" 2>/dev/null || true
    fi
}

reinstall_extension() {
    local cli done_any=0
    if [[ "$(id -u)" -eq 0 ]]; then
        caution "not reinstalling as root: run 'clean --reinstall' as the account that uses the editor"; return 0
    fi
    for cli in code cursor codium windsurf; do
        have "$cli" || continue
        done_any=1
        if [[ "$DRY" -eq 1 ]]; then inf "would run: ${cli} --install-extension anthropic.claude-code --force"; continue; fi
        inf "reinstalling through ${cli} (needs network)"
        "$cli" --install-extension anthropic.claude-code --force 2>&1 | sed 's/^/      /' || caution "${cli} could not reinstall it"
    done
    [[ $done_any -eq 1 ]] || inf "no editor command line found (code, cursor, codium, windsurf): reinstall Claude Code from the editor's extensions view, and make sure it shows 2.1.314 or newer"
    inf "after reinstalling, restart the editor and confirm the Claude Code version"
}

cmd_clean() {
    local i e total
    umask 077
    QUIET=1; scan_all; QUIET=0
    total=$(( ${#R_EXT[@]} + ${#R_FILES[@]} + ${#R_AK[@]} + ${#R_PIDS[@]} + ${#R_CRON[@]} ))
    echo
    if [[ $total -eq 0 ]]; then
        info "nothing to clean: no bad extension, implant file, key, cron entry or process was found"
        if [[ $DROP_AGENT -eq 1 ]]; then step "Drop the keys loaded in your ssh-agents"; drop_agent_keys; fi
        [[ $REINSTALL -eq 1 ]] && reinstall_extension
        exit 0
    fi
    warn "Close the editor first if you have not: it can reload the extension."
    [[ "$DRY" -eq 0 ]] || inf "dry run: nothing will change"
    step "0. Keep a record of ~/.ssh first"
    while IFS= read -r i; do [[ -n "$i" ]] && snapshot_ssh "$i"; done < <(list_homes)
    inf "your private keys are not touched by clean; the record has an inventory of them (run '${SELF} keys' to see which are not protected by a passphrase)"
    step "1. Stop the tunnel and retry loop"
    kill_all_pids
    step "2. Remove persistence"
    [[ $(( ${#R_PLISTS[@]} + ${#R_CRON[@]} )) -gt 0 ]] || inf "no LaunchAgent or crontab entry found"
    i=0; while [[ $i -lt ${#R_PLISTS[@]} ]]; do unload_plist "${R_PLISTS[$i]}"; i=$((i + 1)); done
    i=0; while [[ $i -lt ${#R_CRON[@]} ]]; do clean_cron "${R_CRON[$i]}"; i=$((i + 1)); done
    step "3. Remove the attacker's key"
    [[ ${#R_AK[@]} -gt 0 ]] || inf "the attacker's key is not in any authorized_keys file"
    i=0; while [[ $i -lt ${#R_AK[@]} ]]; do clean_keys "${R_AK[$i]}"; i=$((i + 1)); done
    step "4. Move the implant files and bad extensions to the backup folder"
    [[ $(( ${#R_FILES[@]} + ${#R_EXT[@]} )) -gt 0 ]] || inf "no implant file or bad extension folder found"
    i=0; while [[ $i -lt ${#R_FILES[@]} ]]; do e="${R_FILES[$i]}"; [[ -e "$e" ]] && quarantine_item "$e"; i=$((i + 1)); done
    i=0; while [[ $i -lt ${#R_EXT[@]} ]]; do e="${R_EXT[$i]}"; [[ -e "$e" ]] && quarantine_item "$e"; i=$((i + 1)); done
    if [[ $DROP_AGENT -eq 1 ]]; then step "Drop the keys loaded in your ssh-agents"; drop_agent_keys; fi
    if [[ $REINSTALL -eq 1 ]]; then step "5. Reinstall the extension"; reinstall_extension; fi
    [[ "$DRY" -eq 1 ]] && { echo; info "dry run finished; nothing was changed"; exit 0; }

    step "Re-check"
    QUIET=1; scan_all; QUIET=0
    echo
    if [[ $((N_COMP + N_EXPOSED)) -eq 0 ]]; then
        info "clean: no indicator remains. Everything removed was moved to ${QDIR}"
    else
        warn "${N_COMP} compromise sign(s) and ${N_EXPOSED} exposure(s) remain. Run 'check' to see them (a process owned by another user or a system-wide cron file needs root)."
    fi
    inf "To see which of your own SSH private keys are not protected by a passphrase: ${SELF} keys"
    warn "Cleaning does not undo what the backdoor could already have done. From a different, trusted machine: rotate the credentials and sessions this account could reach (cloud keys, tokens, SSH keys, API keys, password-manager sessions, anything in environment variables), review recent activity on them, and consider rebuilding the machine if 'hunt' found a login. If your crontab or other files look emptier than you expect, the backdoor's installer is reported to be able to wipe an existing crontab: see ${QDIR}/items for what was there before this script ran."
    [[ $((N_COMP + N_EXPOSED)) -eq 0 ]] || exit 1
    exit 0
}


# ---------- update: get the vendor's fix, with questions first ---------------
ASSUME_YES=0; AND_CLEAN=0; ASK_N=0
notice() {
    [[ "${NO_NOTICE:-0}" == "1" ]] && return 0
    echo
    warn "FIRST, get the vendor's fix: Anthropic's Claude Code extension ${FIXED_VER} or newer replaced the bad 2.1.313 on 30 October 2026."
    inf "Install it from your editor's Extensions view, or run:  ${SELF} update   (it asks before it installs anything)."
    warn "But updating alone does NOT remove the backdoor: the attacker's SSH key, the implant files and the persistence stay. After updating run 'check', then 'clean', then rotate credentials from a trusted machine."
    return 0
}
# dotted version a >= b (numbers only, up to three parts; works in bash 3.2)
ver_ge() {
    local a="${1%%[!0-9.]*}" b="${2%%[!0-9.]*}" a1 a2 a3 b1 b2 b3
    local IFS=.
    set -- $a; a1="${1:-0}"; a2="${2:-0}"; a3="${3:-0}"
    set -- $b; b1="${1:-0}"; b2="${2:-0}"; b3="${3:-0}"
    [[ "$a1" -gt "$b1" ]] && return 0; [[ "$a1" -lt "$b1" ]] && return 1
    [[ "$a2" -gt "$b2" ]] && return 0; [[ "$a2" -lt "$b2" ]] && return 1
    [[ "$a3" -ge "$b3" ]]
}
cli_root() { case "$1" in code) echo ".vscode/extensions" ;; cursor) echo ".cursor/extensions" ;; codium) echo ".vscode-oss/extensions" ;; windsurf) echo ".windsurf/extensions" ;; esac; }
cli_has_ext() {   # does any account's folder for this editor hold Claude Code?
    local h rel d
    rel="$(cli_root "$1")"
    [[ -n "$rel" ]] || return 1
    while IFS= read -r h; do
        [[ -n "$h" ]] || continue
        for d in "$h/$rel"/[Aa]nthropic.[Cc]laude-[Cc]ode-*; do [[ -d "$d" ]] && return 0; done
    done < <(list_homes)
    return 1
}
can_ask() { [[ "$ASSUME_YES" -eq 1 || -n "${ANSWERS_FILE:-}" ]] && return 0; { : </dev/tty; } 2>/dev/null; }
can_ask_for_real() { [[ -n "${ANSWERS_FILE:-}" ]] && return 0; { : </dev/tty; } 2>/dev/null; }   # --yes does not count
ask() {   # QUESTION [strict] -> 0 yes, 1 no. Enter means yes. "strict" means --yes does not answer it.
    local q="$1" strict="${2:-}" ans="" raw=""
    if [[ "$ASSUME_YES" -eq 1 && -z "$strict" ]]; then echo "  ${q} yes (--yes)"; return 0; fi
    if [[ -n "${ANSWERS_FILE:-}" ]]; then
        ASK_N=$((ASK_N + 1)); raw="$(awk -v n="$ASK_N" 'NR==n {print "x" $0}' "$ANSWERS_FILE" 2>/dev/null || true)"
        if [[ -n "$raw" ]]; then ans="${raw#x}"; else ans="n"; fi
        echo "  ${q} [Y/n] ${ans:-y}"
    else
        printf '  %s [Y/n] ' "$q"
        if ! { read -r ans </dev/tty; } 2>/dev/null; then ans="n"; echo; fi
    fi
    case "$ans" in n|N|no|NO|No) return 1 ;; *) return 0 ;; esac
}
best_ext_version() {   # highest version among the installed copies, empty if none
    local v best=""
    for v in ${EXT_VERS[@]+"${EXT_VERS[@]}"}; do
        if [[ -z "$best" ]] || { ver_ge "$v" "$best" && ! ver_ge "$best" "$v"; }; then best="$v"; fi
    done
    echo "$best"
}

cmd_update() {
    local cli offered=0 installed=0 best i bad_ver=0
    if [[ "$DRY" -eq 0 ]] && ! can_ask; then
        die "update asks before it installs anything, and there is no terminal to ask on: run it from a terminal, or add --yes (and --and-clean to clean afterwards)"
    fi
    step "1. Where things stand (read-only check)"
    scan_all
    verdict
    step "2. The vendor's fix: Claude Code ${FIXED_VER} or newer"
    if [[ ${#EXT_VERS[@]} -eq 0 ]]; then
        inf "no Claude Code extension was found on this account: there is nothing to update here. If you use it in another editor or account, run this from there."
    elif [[ "$(id -u)" -eq 0 ]]; then
        caution "not installing as root: editors and their extensions belong to a user. Run '${SELF} update' as the account that uses the editor."
    else
        for cli in code cursor codium windsurf; do
            have "$cli" || continue
            cli_has_ext "$cli" || { inf "${cli}: its extensions folder has no Claude Code: not offering to install one"; continue; }
            offered=$((offered + 1))
            inf "${cli}: would run   ${cli} --install-extension anthropic.claude-code --force"
            inf "(the editor downloads it from its own marketplace; this script downloads nothing)"
            if [[ "$DRY" -eq 1 ]]; then continue; fi
            if ask "Install the latest Claude Code extension through ${cli} now? Close the editor first."; then
                inf "installing through ${cli} (needs network)"
                if "$cli" --install-extension anthropic.claude-code --force 2>&1 | sed 's/^/      /'; then installed=$((installed + 1)); else caution "${cli} could not install it"; fi
            else
                inf "skipped ${cli}"
            fi
        done
        if [[ $offered -eq 0 ]]; then
            inf "no editor command line found for the editors that hold Claude Code (code, cursor, codium, windsurf): open the editor's Extensions view, find Claude Code by Anthropic, update or reinstall it, and make sure it shows ${FIXED_VER} or newer"
        fi
    fi
    if [[ "$DRY" -eq 1 ]]; then echo; info "dry run finished; nothing was installed or changed"; exit 0; fi
    step "3. Check again"
    scan_all
    best="$(best_ext_version)"
    echo
    if [[ -z "$best" ]]; then
        inf "no Claude Code extension found: nothing to compare with ${FIXED_VER}"
    elif ver_ge "$best" "$FIXED_VER"; then
        info "Claude Code ${best} is installed (the vendor's fix is ${FIXED_VER} or newer). Restart the editor so it loads it."
    else
        bad_ver=1
        warn "the newest Claude Code found is ${best}, not ${FIXED_VER} or newer yet: restart the editor, or install it from the Extensions view"
    fi
    verdict
    echo
    warn "Updating the extension does NOT remove an existing backdoor: the attacker's SSH key, the implant files and the persistence stay until 'clean' removes them."
    if [[ $N_COMP -gt 0 || $N_EXPOSED -gt 0 ]]; then
        step "4. Clean up"
        if [[ "$AND_CLEAN" -eq 1 ]] || { can_ask_for_real && ask "Run 'clean' now? (stops the tunnel, removes the attacker's key and persistence; moves the implant files and bad extensions to a backup folder, deletes nothing)" strict; }; then
            REINSTALL=0
            cmd_clean
        fi
        inf "not cleaned yet: run  ${SELF} clean  (close the editor first), then rotate credentials from a trusted machine"
        exit 1
    fi
    [[ $N_UNREAD -eq 0 ]] || exit 2
    [[ $bad_ver -eq 0 ]] || exit 1
    exit 0
}

# ---------- block and unblock ------------------------------------------------
NFT_TABLE="psf_claude_vsx"
cmd_block() {
    if [[ "$PLATFORM" != "Linux" ]]; then
        warn "block only applies rules on GNU/Linux. On macOS, block ${C2_IP} with your firewall (for example Little Snitch, LuLu, or a rule on your router or MDM), or in pf:"
        echo "      echo 'block drop out quick to ${C2_IP}' | sudo pfctl -a com.apple/psf_claude_vsx -f -   # then: sudo pfctl -e"
        exit 0
    fi
    [[ "$DRY" -eq 1 || "$(id -u)" -eq 0 ]] || die "block needs root (run it with sudo)"
    if have nft; then
        if [[ "$DRY" -eq 0 ]] && nft list table inet "$NFT_TABLE" >/dev/null 2>&1; then info "the nftables rule is already in place"; exit 0; fi
        run nft add table inet "$NFT_TABLE"
        run nft add chain inet "$NFT_TABLE" output '{ type filter hook output priority 0 ; policy accept ; }'
        run nft add rule inet "$NFT_TABLE" output ip daddr "$C2_IP" drop
        info "outbound traffic to ${C2_IP} is dropped (nftables table inet ${NFT_TABLE}); this does not survive a reboot"
    elif have iptables; then
        if [[ "$DRY" -eq 0 ]] && iptables -C OUTPUT -d "$C2_IP" -j DROP 2>/dev/null; then info "the iptables rule is already in place"; exit 0; fi
        run iptables -I OUTPUT 1 -d "$C2_IP" -j DROP
        info "outbound traffic to ${C2_IP} is dropped (iptables OUTPUT); this does not survive a reboot"
    else
        die "neither nft nor iptables was found"
    fi
    inf "Cursor says the attacker's server is already offline: this protects you if it comes back on the same address"
    exit 0
}
cmd_unblock() {
    [[ "$PLATFORM" == "Linux" ]] || { warn "nothing to remove: block applies no rules on ${PLATFORM}"; exit 0; }
    [[ "$DRY" -eq 1 || "$(id -u)" -eq 0 ]] || die "unblock needs root (run it with sudo)"
    if have nft && { [[ "$DRY" -eq 1 ]] || nft list table inet "$NFT_TABLE" >/dev/null 2>&1; }; then run nft delete table inet "$NFT_TABLE"; info "removed the nftables rule"
    elif have iptables && { [[ "$DRY" -eq 1 ]] || iptables -C OUTPUT -d "$C2_IP" -j DROP 2>/dev/null; }; then run iptables -D OUTPUT -d "$C2_IP" -j DROP; info "removed the iptables rule"
    else info "no rule from this script was found"; fi
    exit 0
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY=1 ;;
        --reinstall) REINSTALL=1 ;;
        --yes) ASSUME_YES=1 ;;
        --and-clean) AND_CLEAN=1 ;;
        --copy-keys) COPY_KEYS=1 ;;
        --drop-agent-keys) DROP_AGENT=1 ;;
        *) die "Unknown option: $1 (--dry-run, --reinstall, --yes, --and-clean, --copy-keys, --drop-agent-keys)" ;;
    esac
    shift
done
[[ "$CMD" == "clean" || "$CMD" == "block" || "$CMD" == "unblock" || "$CMD" == "update" ]] || [[ $DRY -eq 0 ]] || die "--dry-run applies to clean, block, unblock and update"
[[ "$CMD" == "update" ]] || [[ $ASSUME_YES -eq 0 && $AND_CLEAN -eq 0 ]] || die "--yes and --and-clean apply to update"
[[ "$CMD" == "clean" || "$CMD" == "update" ]] || [[ $COPY_KEYS -eq 0 && $DROP_AGENT -eq 0 ]] || die "--copy-keys and --drop-agent-keys apply to clean and update"
[[ "$CMD" == "clean" ]] || [[ $REINSTALL -eq 0 ]] || die "--reinstall applies to clean"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "Claude Code extension backdoor, 29 October 2026 (no CVE); context: ${REF}"
case "$CMD" in check|hunt|clean|update) notice ;; esac
case "$CMD" in
    check|hunt|clean|update|keys|block|unblock) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|update|keys|clean|block|unblock|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
