#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# BTCPay Server November 2026: check, recover, preserve, hunt, harden, tor  (v1)
# No CVE (hot wallet thefts on BTCPay Server 2.4.1 and earlier, 1 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On 1 November 2026 the BTCPay Server project reported Bitcoin and Litecoin
# stolen from hot wallets on servers running 2.4.1 or earlier. It says the
# attackers used a different method against the flaw that 2.4.2 fixed in
# August, and that it has seen no impact on servers that were already on
# 2.4.2 or later when it warned operators. It has not published the method,
# and this script does not claim one.
#
# The fix for an affected host is not an update. The project's advice is a
# fresh server and a new wallet. This script's first job is to tell you
# whether that applies to you and to walk you through it. Hardening is second.
#
#   check     finds BTCPay Server (containers, compose and env files, builds, or
#             a server reached with --url) and judges its version: 2.4.1 and
#             earlier, and any 2.4.2 release candidate, are exposed.
#   recover   check, then signs on the host, then the recovery plan for this
#             host, step by step, with a pre-filled report for the project.
#   preserve  saves logs and records into one archive before you take the old
#             server offline. Secrets are redacted. Writes only that archive.
#   hunt      reads web server and container logs for the published indicators.
#   harden    check, then reachable ports, higher-exposure fragments, enabled
#             LND routes, the IPv4 options filter, SSH settings, root's
#             authorized_keys, custom fragments, the btcpayserver-docker
#             checkout and the server administrators.
#   tor       reports whether Tor is enabled and explains the choice.
#
# Read-only by default. The only code paths that change anything are
# "preserve" (it writes one new archive) and "tor enable|disable" (it runs the
# project's own btcpay-fragments as root after you confirm; --dry-run shows the plan).
# --strict makes any warning exit 1. --json prints one JSON document.
#
# Exit codes: 0 nothing to act on, 1 a problem was found or a version could not
# be read (or, with --strict, any warning), 2 usage error.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}" and through run_command, which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="btcpayserver-nov2026-check.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-11-03"
NEWEST="2.4.7"                      # newest release at the time of writing
WARNED_AT="2026-11-01T22:25:00Z"    # the project's warning to operators
LOG_TAIL="${LOG_TAIL:-200000}"
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
PROFILE_FILE="${BTCPAY_FRAGMENTS_PROFILE:-/etc/profile.d/btcpay-env.sh}"

# Destination addresses the project lists as "identified in the incident reports" (post of 2 November 2026).
# The project says some activity at them predates the thefts, so they are indicators, not a confirmed total.
IOC_ADDRESSES=(
    "bc1p0f7wmcnesrapznymf9ljdn04pudgmh96sqtrm9vmgqxdh666fh8qvn63r7"
    "ltc1qp49tmfdueyaqrmgrx0uyx4uegyygt8yt02whee"
)

URL_LOCKED="https://docs.btcpayserver.org/FAQ/LightningNetwork/#lnd-wallet-stays-locked-invalid-passphrase-for-master-public-key"

# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 && -z "${NO_COLOR:-}" ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }

JSON=0; STRICT=0
CRITS=0; WARNS=0; UNKNOWN=0; FOUND=0
DOCKER=""; DOCKER_OK=0
LND_PRESENT=0; NGINX_NAMES=(); BTCPAY_NAMES=(); LND_NAMES=()

# --json prints these as tagged lines (CRIT, WARN, ok, info, SECTION) that to_json converts.
info()    { [[ $JSON -eq 1 ]] || printf '%b[+]%b %s\n' "$GREEN" "$NC" "$*"; }
warn()    { [[ $JSON -eq 1 ]] || printf '%b[!]%b %s\n' "$YELLOW" "$NC" "$*"; }
step()    { if [[ $JSON -eq 1 ]]; then printf 'SECTION  %s\n' "$*"; else printf '\n%b=====%b %s %b=====%b\n' "$CYAN" "$NC" "$*" "$CYAN" "$NC"; fi; }
die()     { printf '%b[-] FATAL:%b %s\n' "$RED" "$NC" "$*" >&2; exit 2; }
ok()      { if [[ $JSON -eq 1 ]]; then printf 'ok    %s\n' "$*"; else printf '  %bcheck%b %s\n' "$GREEN" "$NC" "$*"; fi; }
bad()     { CRITS=$((CRITS + 1)); if [[ $JSON -eq 1 ]]; then printf 'CRIT  %s\n' "$*"; else printf '  %bCRIT%b  %s\n' "$RED" "$NC" "$*"; fi; }
caution() { WARNS=$((WARNS + 1)); if [[ $JSON -eq 1 ]]; then printf 'WARN  %s\n' "$*"; else printf '  %bWARN%b  %s\n' "$YELLOW" "$NC" "$*"; fi; }
unknown() { UNKNOWN=$((UNKNOWN + 1)); if [[ $JSON -eq 1 ]]; then printf 'WARN  %s\n' "$*"; else printf '  %bWARN%b  %s\n' "$YELLOW" "$NC" "$*"; fi; }
inf()     { if [[ $JSON -eq 1 ]]; then printf 'info  %s\n' "$*"; else printf '  %binfo%b  %s\n' "$CYAN" "$NC" "$*"; fi; }
tip()     { printf '      Suggest: %s\n' "$*"; }
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

banner() {
    printf '%s %s (%s) - %s on %s at %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$SCRIPT_DATE" "$1" "$(hostname 2>/dev/null || echo '?')" "$(date -u +%FT%TZ)"
    printf 'No CVE (hot wallet thefts on BTCPay Server 2.4.1 and earlier, 1 November 2026)\n'
}

verdict() {
    step "Verdict"
    if [[ $CRITS -gt 0 ]]; then
        warn "Exposed. The project's advice for this host is a fresh server and a new wallet, not an update."
    elif [[ $UNKNOWN -gt 0 ]]; then
        warn "A BTCPay Server version could not be read, so this host cannot be cleared."
    elif [[ $FOUND -eq 0 ]]; then
        info "No BTCPay Server was found."
    elif [[ $WARNS -gt 0 ]]; then
        info "No exposed version was found. $WARNS $(pl "$WARNS" warning warnings) to review above."
    else
        info "No exposed version was found, and nothing above needs a warning."
    fi
}

print_help() {
    cat <<'USAGE'
BTCPay Server November 2026: check, recover, preserve, hunt, harden, tor  (v1)
No CVE (hot wallet thefts on BTCPay Server 2.4.1 and earlier, 1 November 2026)

If this software is helpful, consider a donation to our 501c3 nonprofit:
https://privacysafe.foundation

On 1 November 2026 the BTCPay Server project reported Bitcoin and Litecoin
stolen from hot wallets on servers running 2.4.1 or earlier. It says the
attackers used a different method against the flaw that 2.4.2 fixed in
August, and that it has seen no impact on servers that were already on
2.4.2 or later when it warned operators. It has not published the method.

The project's advice for a server that ran 2.4.1 or earlier is a fresh server
and a new wallet, not an update. This tool is built around that: check finds
out whether it applies, recover gives the plan in order, preserve saves your
evidence before the old server goes. Hardening comes after.

Usage:
  ./btcpayserver-nov2026-check.sh [command] [options]

  check (default)  [--url URL] [DIR ...]
                   Find BTCPay Server on this host (running or stopped
                   containers, compose and env files, unpacked builds, or a
                   server reached with --url) and judge its version. 2.4.1
                   and earlier, and any 2.4.2 release candidate, are
                   reported as exposed. It also reads the update history
                   (when btcpay-update.sh last ran, against the project's
                   warning) and checks the LND version.
                   Exit 0 = nothing to act on, 1 = exposed or a version that
                   cannot be read, 2 = bad arguments.
  recover          [--url URL] [DIR ...]
                   Run check, then print the recovery plan for this host in
                   order: new wallet, evidence, fresh server, credentials,
                   destination addresses, report. It also looks for signs
                   on the host (SSH access, custom fragments, the
                   btcpayserver-docker checkout, server administrators) and
                   includes a report to send the project, partly filled in.
  preserve         [--out FOLDER] [LOGDIR ...]
                   Save logs and records into one archive before the old
                   server goes offline: host and container records, container
                   and web server logs, the update log archives, the
                   deployment profile. Secrets are redacted and wallet files
                   are never included. The archive
                   is written with mode 0600 into FOLDER (default: the
                   current folder) and is never overwritten.
  hunt             [LOGDIR ...]
                   Read web server, container and update log archives for the
                   reported indicators: LND wallet setup and unlock routes,
                   .macaroon requests, and the destination addresses. They
                   come from the August flaw and the 2.4.4 bot reports. The
                   project says the November method was different, so a
                   clean result is not proof of safety. A log it cannot
                   read, or no log at all, is never reported as clean: the
                   hunt exits 2 and names the sudo command.
  harden           [--url URL] [--profile FILE] [DIR ...]
                   Run check, then review exposed ports, optional fragments,
                   LND API routes, the IPv4 options filter, SSH settings, the
                   keys in root's authorized_keys, custom fragments, the
                   btcpayserver-docker checkout and the server
                   administrators, and list the manual steps that cannot be
                   checked from here.
  tor              [status|enable|disable] [--dry-run] [--yes] [--profile FILE]
                   Report whether Tor is enabled and explain the choice.
                   enable and disable change the host: they run the project's
                   btcpay-fragments after you type yes (or pass --yes), as
                   root. --dry-run shows the plan and changes nothing.
  version          print the script version.
  --strict         any command: exit 1 on any warning as well as any CRIT, so
                   a hardening finding fails a scheduled job. Without it only
                   CRIT or an unreadable version exits 1.
  --json           any command: print one JSON document instead of text (tool,
                   version, command, host, exit, summary counts, findings,
                   advice, recovery steps, report lines, manual steps and
                   commands) for monitoring. Not with tor enable or disable unless
                   --dry-run.
Environment: SCAN_CONTAINERS=0 skips docker and podman. LOG_TAIL sets how many
log lines are read per container (default 200000). NO_COLOR turns color off.
BTCPAY_BASE_DIRECTORY names the btcpayserver-docker folder when it is not under /opt, /srv
or the home directory (it is also read from the profile file, which BTCPAY_FRAGMENTS_PROFILE
or --profile can change). TOR_SERVICES_DIR is the folder that holds the Tor service's
hostname files (default: the generated_tor_servicesdir Docker volume).
PSF_LOCK_WAIT=N: a run that changes the host (harden, tor) waits up to N seconds
for another one that is already changing it (default 30), then stops with exit 2.
USAGE
}

# ---------- version handling ----------

# Prints "MAJOR MINOR PATCH SUFFIX" for a tag such as 2.4.7 or v2.4.2-rc4.
parse_ver() {
    local v="${1#v}"
    if [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.*)?$ ]]; then
        printf '%s %s %s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]:-}"
        return 0
    fi
    return 1
}

# Echoes: exposed | behind | current | unreadable
classify() {
    local parts maj min pat suf
    parts=$(parse_ver "$1") || { echo unreadable; return; }
    read -r maj min pat suf <<<"$parts"
    if [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 4 ]; } \
          || { [ "$maj" -eq 2 ] && [ "$min" -eq 4 ] && [ "$pat" -le 1 ]; }; then
        echo exposed; return
    fi
    if [ "$maj" -eq 2 ] && [ "$min" -eq 4 ] && [ "$pat" -eq 2 ] && [[ "$suf" == -rc* ]]; then
        echo exposed; return
    fi
    local nm nn np
    IFS=. read -r nm nn np <<<"$NEWEST"
    if [ "$maj" -gt "$nm" ] || { [ "$maj" -eq "$nm" ] && [ "$min" -gt "$nn" ]; } \
          || { [ "$maj" -eq "$nm" ] && [ "$min" -eq "$nn" ] && [ "$pat" -ge "$np" ]; }; then
        echo current
    else
        echo behind
    fi
}

# Image reference to tag. Handles registry ports, digests and v prefixes.
image_tag() {
    local ref="${1%%@*}" last
    last="${ref##*/}"
    case "$last" in *:*) printf '%s\n' "${last##*:}" ;; *) printf '\n' ;; esac
}

pl() {
    # pl COUNT SINGULAR PLURAL
    if [ "$1" -eq 1 ]; then printf '%s' "$2"; else printf '%s' "$3"; fi
}

rhint() {
    if [ "$IN_RECOVER" -eq 1 ]; then printf 'follow the plan below'; else printf "run '%s recover'" "$SCRIPT_NAME"; fi
}

is_btcpay_image() {
    local base="${1%%@*}"
    case "${base##*/}" in *:*) base="${base%:*}" ;; esac
    [[ "$base" == btcpayserver/btcpayserver || "$base" == */btcpayserver/btcpayserver ]]
}

ADVICE_MSG="Treat a host that ran 2.4.1 or earlier as untrusted, even if no theft was noticed and even if it was updated after the project's 1 November warning: updating cannot remove access an attacker may already have, and an unchanged balance does not rule out an earlier attack. The project's steps: (1) create a NEW wallet with a NEW seed on a trusted device and sweep any remaining hot-wallet funds into it; reusing the old seed leaves funds at risk. (2) Take the old server offline and keep its logs and transaction records. (3) Provision a FRESH server, install the latest release from trusted sources and connect the new wallet; do not restore the whole old server onto it. (4) From a trusted device, replace the credentials the old server could reach: hosting, SSH, application, API and Lightning, and never enter new ones on the old machine. Wallets whose spending keys are held off the server, including hardware wallets, were not affected. If your hosting provider took the instance offline, ask it for help moving to a fresh VM. To report a loss or unauthorized activity: security@btcpayserver.org, with the version you ran, when you noticed, and public transaction IDs and addresses. Never send seeds, keys or passwords. Update the new host to $NEWEST. Run recover for the plan on this host and preserve to save the evidence first."

advice_short() {
    if [ "$JSON" -eq 1 ]; then printf 'ADVICE  %s\n' "This host ran 2.4.1 or earlier. The project's advice is a fresh server and a new wallet, not an update. Run recover for the plan."; return; fi
    printf '\n      The project'"'"'s advice for this host is a fresh server and a new wallet,\n      not an update. Run '"'"'%s recover'"'"' for the plan, then\n      '"'"'%s preserve'"'"' to save the evidence.\n' "$SCRIPT_NAME" "$SCRIPT_NAME"
}

advice_block() {
    if [ "$JSON" -eq 1 ]; then printf 'ADVICE  %s\n' "$ADVICE_MSG"; return; fi
    cat <<ADV

      Treat a host that ran 2.4.1 or earlier as untrusted, even if no theft
      was noticed and even if it was updated after the project's 1 November
      warning. Updating cannot remove access an attacker may already have,
      and an unchanged balance does not rule out an earlier attack.

      The project's steps:
        1. Create a NEW wallet with a NEW seed on a trusted device and
           sweep any remaining hot-wallet funds into it. Reusing the old
           seed leaves funds at risk.
        2. Take the old server offline and keep its logs and records.
        3. Provision a FRESH server, install the latest release from
           trusted sources, and connect the new wallet. Do not restore
           the whole old server onto it.
        4. From a trusted device, replace the credentials the old server
           could reach: hosting, SSH, application, API and Lightning.
           Never enter new ones on the old machine.

      Wallets whose spending keys are held off the server, including
      hardware wallets, were not affected. If your hosting provider took
      the instance offline, ask it for help moving to a fresh VM.

      To report a loss or unauthorized activity, email
      security@btcpayserver.org with the version you ran, when you noticed,
      and public transaction IDs and addresses. Never send seeds, keys or
      passwords. Update the new host to $NEWEST.

      Run '$SCRIPT_NAME recover' for the plan on this host,
      then '$SCRIPT_NAME preserve' to save the evidence.
ADV
}

judge() {
    # judge LABEL VERSION_TAG
    local label="$1" tag="$2" cls
    FOUND=$((FOUND + 1))
    SEEN_LINES+=("$label: ${tag#v}")
    cls=$(classify "$tag")
    case "$cls" in
        exposed)
            bad "$label is BTCPay Server ${tag#v}, which is 2.4.1 or earlier (or a 2.4.2 release candidate)."
            EXPOSED_SEEN=1 ;;
        behind)
            caution "$label is BTCPay Server ${tag#v}, a fixed release, but $NEWEST is the newest. Update."
            tip "Server Settings > Maintenance > Update, or btcpay-update.sh on a Docker host. Confirm the version in the page footer." ;;
        current)
            ok "check  $label is BTCPay Server ${tag#v}" ;;
        *)
            unknown "$label: the version cannot be read (tag '${tag:-none}'). Pin an explicit version tag, or use --url." ;;
    esac
}
EXPOSED_SEEN=0
IN_RECOVER=0
CREATED_AFTER=0
SEEN_LINES=()
OLD_IMAGES=()
CREATED_LINES=()
UPDATE_TIMES=()
UPDATED_AFTER=0
LN_OTHER=()
GIT_HEAD=""

# ---------- docker / podman ----------

setup_docker() {
    DOCKER=""; DOCKER_OK=0
    [ "$SCAN_CONTAINERS" = "0" ] && return
    DOCKER=$(command -v docker 2>/dev/null || command -v podman 2>/dev/null || true)
    [ -n "$DOCKER" ] || return
    if "$DOCKER" ps -a --format '{{.Names}}' >/dev/null 2>&1; then DOCKER_OK=1; fi
}

docker_ps() { "$DOCKER" ps -a --format '{{.Names}}|{{.Image}}|{{.State}}' 2>/dev/null; }

created_note() {
    # created_note NAME SCRIPT_VERSION: warn when a container was created after the warning
    local name="$1" raw s ts warned
    raw=$("$DOCKER" inspect --format '{{.Created}}' "$name" 2>/dev/null | head -n1)
    [ -n "$raw" ] || return
    s=$(printf '%s' "$raw" | sed -E 's/\.[0-9]+//; s/ [A-Z]{2,5}$//')
    ts=$(date -u -d "$s" +%s 2>/dev/null) || return
    warned=$(date -u -d "$WARNED_AT" +%s)
    if [ "$ts" -gt "$warned" ]; then
        CREATED_AFTER=1; CREATED_LINES+=("$name created $(date -u -d "@$ts" +%Y-%m-%dT%H:%M)Z")
        caution "container $name was created $(date -u -d "@$ts" +%Y-%m-%dT%H:%M) UTC, after the project's warning of 1 November. If this host ran 2.4.1 or earlier and was updated after the warning, the project still recommends a fresh server and a new wallet. If it was already on 2.4.2 or later when the warning went out, the project has seen no impact."
        [ "$IN_RECOVER" -eq 1 ] || tip "$SCRIPT_NAME recover"
    fi
}

scan_containers() {
    if [ "$SCAN_CONTAINERS" = "0" ]; then
        inf "Container scan skipped (SCAN_CONTAINERS=0)."; return
    fi
    if [ -z "$DOCKER" ]; then inf "Neither docker nor podman is installed; no container scan."; return; fi
    if [ "$DOCKER_OK" -ne 1 ]; then
        inf "$(basename "$DOCKER") is installed but this user cannot use it. Run as root or join the docker group to scan containers."
        return
    fi
    local rows name image state n=0 tag stopped lbl
    rows=$(docker_ps)
    while IFS='|' read -r name image state; do
        [ -n "$name" ] || continue
        # remember roles for later checks
        case "$image" in
            nginx|nginx:*|*/nginx|*/nginx:*|*nginx-proxy*) NGINX_NAMES+=("$name") ;;
        esac
        case "$name" in nginx|*_nginx_*|*-nginx-*) NGINX_NAMES+=("$name") ;; esac
        if [[ "$image" =~ (^|/)(btcpayserver/lnd|lightninglabs/lnd)(:|@|$) ]]; then
            LND_PRESENT=1; LND_NAMES+=("$name")
            if lnd_tag_old "$(image_tag "$image")"; then
                caution "container $name runs LND $(image_tag "$image" | sed 's/^v//'), which is older than 0.21.1, the version the August advisory called for."
                tip "btcpay-update.sh updates LND together with BTCPay Server. On a host that ran 2.4.1 or earlier, do not update in place: $(rhint)."
            fi
        fi
        if [[ "$image" =~ (^|/)btcpayserver/lightning(:|@|$) ]]; then LN_OTHER+=("Core Lightning"); fi
        if [[ "$image" =~ (^|/)acinq/phoenixd(:|@|$) ]]; then LN_OTHER+=("phoenixd"); fi
        is_btcpay_image "$image" || continue
        n=$((n + 1)); BTCPAY_NAMES+=("$name")
        tag=$(image_tag "$image")
        stopped=""; [ "$state" = "running" ] || stopped="stopped "
        lbl="${stopped}container $name"
        if [ -z "$tag" ] || [ "$(classify "$tag")" = unreadable ]; then
            FOUND=$((FOUND + 1))
            unknown "$lbl runs image $image: the version cannot be read from the tag."
            continue
        fi
        local before=$CRITS
        judge "$lbl" "$tag"
        [ "$CRITS" -eq "$before" ] && created_note "$name"
    done <<<"$rows"
    if [ "$n" -eq 0 ]; then inf "No container from the btcpayserver/btcpayserver image was found."; fi
    # old images still on disk
    local imgs old=()
    imgs=$("$DOCKER" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null)
    while IFS= read -r image; do
        [ -n "$image" ] || continue
        is_btcpay_image "$image" || continue
        tag=$(image_tag "$image"); [ -n "$tag" ] || continue
        [ "$(classify "$tag")" = exposed ] && old+=("$image")
    done <<<"$imgs"
    if [ "${#old[@]}" -gt 0 ]; then
        OLD_IMAGES=("${old[@]}")
        caution "Images of 2.4.1 or earlier are still on this host (${old[*]})."
        tip "Remove them once the host is rebuilt: docker image rm <image>. Never start one again."
    fi
}

# ---------- files, builds and a live server ----------

scan_files() {
    local dir f ref tag d seen
    for dir in "$@"; do
        [ -d "$dir" ] || continue
        while IFS= read -r -d '' f; do
            case "$f" in
                */BTCPayServer.deps.json)
                    d="${f%/*}"
                    tag=$(grep -oE '"BTCPayServer/[0-9][^"]*"' -- "$f" 2>/dev/null | head -n1 | sed -E 's#"BTCPayServer/(.*)"#\1#')
                    if [ -z "$tag" ]; then
                        FOUND=$((FOUND + 1)); unknown "build $d: the version cannot be read from BTCPayServer.deps.json."
                    else judge "build $d" "$tag"; fi ;;
                *)
                    seen=""
                    while IFS= read -r ref; do
                        [ -n "$ref" ] || continue
                        case "$ref" in *btcpayserver/btcpayserver-*) continue ;; esac
                        case "$seen" in *"|$ref|"*) continue ;; esac
                        seen="$seen|$ref|"
                        tag=$(image_tag "$ref")
                        if [ -z "$tag" ] || [ "$(classify "$tag")" = unreadable ]; then
                            FOUND=$((FOUND + 1)); unknown "file $f names $ref: the version cannot be read from the tag."
                        else
                            judge "file $f ($ref)" "$tag"
                        fi
                    done < <(grep -oE '[A-Za-z0-9./:_-]*btcpayserver/btcpayserver(-[A-Za-z0-9_-]+)?(:[A-Za-z0-9._-]+)?(@sha256:[0-9a-f]+)?' -- "$f" 2>/dev/null) ;;
            esac
        done < <(find "$dir" -maxdepth 6 -type f -size -2M \( -name '*.yml' -o -name '*.yaml' -o -name '.env' -o -name '*.env' -o -name 'BTCPayServer.deps.json' \) -print0 2>/dev/null)
    done
}

scan_url() {
    local base="${1%/}" body ver
    if ! command -v curl >/dev/null 2>&1; then unknown "curl is not installed; cannot query $base."; return; fi
    body=$(curl -fsS --max-time 15 "$base/api/v1/server/info" 2>/dev/null) || {
        FOUND=$((FOUND + 1)); unknown "No answer from $base/api/v1/server/info (the server is down, the path is blocked, or this needs a network that can reach it)."; return; }
    ver=$(printf '%s' "$body" | sed -nE 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/p' | head -n1)
    if [ -z "$ver" ]; then FOUND=$((FOUND + 1)); unknown "server $base answered, but the version cannot be read from the reply."; return; fi
    judge "server $base" "$ver"
}

# ---------- LND exposure ----------

listeners() {
    # prints "ADDR PORT" for every listening TCP socket
    local out
    if command -v ss >/dev/null 2>&1; then out=$(ss -H -ltn 2>/dev/null || ss -ltn 2>/dev/null)
    elif command -v netstat >/dev/null 2>&1; then out=$(netstat -ltn 2>/dev/null)
    else return 1; fi
    printf '%s\n' "$out" | awk '$1 ~ /^LISTEN$|^tcp/ { a=$4; if ($1 ~ /^tcp/) a=$4; p=a; sub(/.*:/,"",p); sub(/:[^:]*$/,"",a); print a, p }'
}

is_public_addr() {
    case "$1" in 127.*|"[::1]"|"::1"|localhost) return 1 ;; *) return 0 ;; esac
}

lnd_exposure() {
    local flagged=0 a p
    if [ "$LND_PRESENT" -eq 0 ] && command -v pgrep >/dev/null 2>&1 && pgrep -x lnd >/dev/null 2>&1; then LND_PRESENT=1; fi
    if [ "$FOUND" -eq 0 ] && [ "$LND_PRESENT" -eq 0 ]; then
        inf "LND exposure: nothing to look at (no BTCPay Server or LND found)."; return
    fi
    if [ "$LND_PRESENT" -eq 1 ]; then
        while read -r a p; do
            [ -n "${p:-}" ] || continue
            case "$p" in 8080|10009)
                if is_public_addr "$a"; then
                    flagged=1
                    caution "Port $p ($([ "$p" = 8080 ] && echo 'LND REST' || echo 'LND gRPC')) is listening and reachable from the network. The wallet unlock and setup calls need no macaroon while LND is locked."
                    tip "Publish nothing on $p. Bind to 127.0.0.1 or remove the port mapping, then restart the stack. Use a firewall as a second layer."
                fi ;;
            esac
        done < <(listeners)
    fi
    if [ "$DOCKER_OK" -eq 1 ] && [ "${#NGINX_NAMES[@]}" -gt 0 ]; then
        local n conf
        for n in $(printf '%s\n' "${NGINX_NAMES[@]}" | sort -u); do
            conf=$("$DOCKER" exec "$n" sh -c 'cat /etc/nginx/conf.d/*.conf /etc/nginx/vhost.d/* 2>/dev/null' 2>/dev/null)
            if printf '%s' "$conf" | grep -qE 'lnd-(rest|grpc)|(proxy|grpc)_pass[^;]*lnd'; then
                flagged=1
                caution "The web server ($n) routes to LND (lnd-rest or lnd-grpc), so the LND API is reachable over HTTPS."
                tip "btcpay-routes show ; btcpay-routes remove lnd-rest lnd-grpc  (unless an external wallet needs them)."
            fi
        done
    fi
    [ "$flagged" -eq 0 ] && ok "No LND REST or gRPC route or listener reachable from the network was found."
}

# ---------- check ----------

cmd_check() {
    local url="" dirs=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) [ $# -ge 2 ] || { die "Option --url needs a value."; }; url="$2"; shift 2 ;;
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) [ -d "$1" ] || { die "Not a directory: $1"; }; dirs+=("$1"); shift ;;
        esac
    done
    if [ "${#dirs[@]}" -eq 0 ]; then
        local d; for d in "$HOME" /opt /srv "${BTCPAY_BASE_DIRECTORY:-}"; do [ -n "$d" ] && [ -d "$d" ] && dirs+=("$d"); done
    fi
    step "Version"
    setup_docker
    scan_containers
    scan_files "${dirs[@]}"
    [ -n "$url" ] && scan_url "$url"
    [ "$FOUND" -eq 0 ] && inf "No BTCPay Server found on this host. If it runs elsewhere, use --url or run this on that host."
    update_history_report
    lnd_exposure
    if [ "$EXPOSED_SEEN" -eq 1 ]; then step "What to do"; advice_block; fi
    verdict
    if [ "$EXPOSED_SEEN" -eq 1 ]; then
        inf "Next: '$SCRIPT_NAME recover' for the plan on this host, then '$SCRIPT_NAME preserve'."
    else
        inf "Also: '$SCRIPT_NAME recover' if this host ever ran 2.4.1 or earlier, '$SCRIPT_NAME harden' for exposure and settings, '$SCRIPT_NAME tor' for Tor."
    fi
    if [ "$CRITS" -gt 0 ] || [ "$UNKNOWN" -gt 0 ]; then return 1; fi
    return 0
}

# ---------- hunt ----------

RE_ROUTE='/v[0-9]+/(initwallet|unlockwallet|changepassword|genseed)|lnd-rest/btc/v[0-9]+/state|lnrpc\.(WalletUnlocker/(GenSeed|InitWallet|UnlockWallet|ChangePassword)|State/(GetState|SubscribeState))'
RE_MAC='\.macaroon'

hunt_stream() {
    # hunt_stream LABEL  (reads the stream on stdin, one pass held in memory)
    local label="$1" data m c first
    data=$(LC_ALL=C head -c 400000000)
    m=$(printf '%s\n' "$data" | LC_ALL=C grep -aiE -- "$RE_ROUTE")
    if [ -n "$m" ]; then
        c=$(printf '%s\n' "$m" | wc -l | tr -d ' ')
        first=$(printf '%s\n' "$m" | head -n1 | LC_ALL=C tr -cd '[:print:]' | cut -c1-140)
        bad "$label: $c $(pl "$c" request requests) for an LND wallet setup or unlock route. First: $first"
    fi
    m=$(printf '%s\n' "$data" | LC_ALL=C grep -aE -- "$RE_MAC")
    if [ -n "$m" ]; then
        c=$(printf '%s\n' "$m" | wc -l | tr -d ' ')
        first=$(printf '%s\n' "$m" | head -n1 | LC_ALL=C tr -cd '[:print:]' | cut -c1-140)
        bad "$label: $c $(pl "$c" request requests) for a .macaroon file. First: $first"
    fi
    local ioc
    for ioc in "${IOC_ADDRESSES[@]}"; do
        if printf '%s\n' "$data" | LC_ALL=C grep -aqF -- "$ioc"; then
            bad "$label: contains a destination address reported for the thefts ($ioc)."
            fi
    done
    if [ "${2:-}" = lnd ] && printf '%s\n' "$data" | LC_ALL=C grep -aqi 'invalid passphrase'; then
        caution "$label: LND logged 'invalid passphrase'. The project says some Docker nodes were left locked after updates on 11 to 14 September, so this is often that and not an attack. It can also follow a wrong-password or probe attempt on the unauthenticated routes. Read the LND and web logs around it. Recovery guide: $URL_LOCKED"
    fi
}

hunt_all() {
    local d f nread=0 nunread=0
    local lbl
    for d in "${HUNT_DIRS[@]}"; do
        while IFS= read -r -d '' f; do
            lbl="$f"
            if [ ! -r "$f" ]; then nunread=$((nunread + 1)); continue; fi
            nread=$((nread + 1))
            case "$f" in
                *.gz) gzip -dc -- "$f" 2>/dev/null | hunt_stream "$lbl" ;;
                *)    hunt_stream "$lbl" <"$f" ;;
            esac
        done < <(find "$d" -maxdepth 3 -type f \( -name '*.log' -o -name '*.log.*' -o -name '*.gz' \) -print0 2>/dev/null)
    done
    local ua nua=0
    while IFS= read -r ua; do
        [ -n "$ua" ] || continue
        if [ ! -r "$ua" ]; then nunread=$((nunread + 1)); continue; fi
        nua=$((nua + 1)); nread=$((nread + 1))
        case "$ua" in
            *.gz) gzip -dc -- "$ua" 2>/dev/null | hunt_stream "update log ${ua##*/}" lnd ;;
            *) hunt_stream "update log ${ua##*/}" lnd <"$ua" ;;
        esac
    done < <(update_archives)
    [ "$nua" -gt 0 ] && inf "Read $nua update log $(pl "$nua" file files). They hold the compose logs saved before each update, which outlive the containers."
    setup_docker
    if [ "$SCAN_CONTAINERS" = "0" ]; then
        inf "Container logs skipped (SCAN_CONTAINERS=0)."
    elif [ -z "$DOCKER" ]; then
        inf "Neither docker nor podman is installed; only log files were read."
    elif [ "$DOCKER_OK" -ne 1 ]; then
        inf "$(basename "$DOCKER") is installed but this user cannot use it, so container logs were not read."
    else
        local rows name image state role
        rows=$(docker_ps)
        while IFS='|' read -r name image state; do
            [ -n "$name" ] || continue
            role=""
            if is_btcpay_image "$image"; then role=btcpay
            elif [[ "$image" =~ (^|/)(btcpayserver/lnd|lightninglabs/lnd)(:|@|$) ]]; then role=lnd
            elif [[ "$image" =~ (^|/)nginx(:|@|$) ]] || [[ "$name" =~ nginx ]]; then role=nginx
            fi
            [ -n "$role" ] || continue
            nread=$((nread + 1))
            "$DOCKER" logs --tail "$LOG_TAIL" "$name" 2>&1 | hunt_stream "container $name" "$role"
        done <<<"$rows"
    fi
    if [ "$nunread" -gt 0 ]; then
        caution "$nunread log $(pl "$nunread" file files) exist but cannot be read by this user. Run it with sudo: sudo $SELF_CMD"
    fi
    if [ "$nread" -eq 0 ]; then
        caution "No log source could be read, so nothing was judged. Name a log folder, or run it where the logs are."
    else
        inf "Read $nread log $(pl "$nread" source sources)."
    fi
}

cmd_hunt() {
    HUNT_DIRS=()
    local d
    while [ $# -gt 0 ]; do
        case "$1" in
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) [ -d "$1" ] || { die "Not a directory: $1"; }; HUNT_DIRS+=("$1"); shift ;;
        esac
    done
    if [ "${#HUNT_DIRS[@]}" -eq 0 ]; then
        for d in /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/caddy; do [ -d "$d" ] && HUNT_DIRS+=("$d"); done
    fi
    # The readers run in pipelines, so their findings are counted from the text.
    local out hits partial
    out=$(hunt_all)
    printf '%s\n' "$out"
    hits=$(printf '%s\n' "$out" | grep -cE $'^ {0,2}(\033\\[[0-9;]*m)?CRIT' || true)
    partial=$(printf '%s\n' "$out" | grep -cE 'cannot be read by this user|No log source could be read' || true)
    step "Verdict"
    if [ "$hits" -eq 0 ] && [ "$partial" -gt 0 ]; then
        warn "Nothing was found in the logs that could be read, but not every log could be read, so this is not a clean result. Fix that and run it again."
    elif [ "$hits" -eq 0 ]; then
        info "None of the reported indicators were found in the logs that were read."
        inf "That is not proof the server was not accessed. Logs rotate, attackers can avoid them, and the indicators are only those the project published. They come from the August flaw and the 2.4.4 bot reports. The project says the November attacks used a different method, so a clean result does not clear a host that ran 2.4.1 or earlier."
        inf "On a stack that blocks LND's unlock and wallet routes in nginx (2.4.4 and later), those requests are deliberately not written to the access log, so a clean result for them means little. LND's own container log is the better source."
    else
        warn "Indicators from the reports were found. Treat the host as exposed: run '$SCRIPT_NAME recover', keep these logs, and send the relevant lines to security@btcpayserver.org."
    fi
    [ "$hits" -gt 0 ] && return 1
    [ "$partial" -gt 0 ] && return 2
    return 0
}

# ---------- profile (read, never sourced) ----------

profile_value() {
    # profile_value NAME: the quoted value of an export in the deployment profile
    [ -r "$PROFILE_FILE" ] || return 1
    sed -nE "s/^[[:space:]]*(export[[:space:]]+)?$1=[\"']?([^\"']*)[\"']?[[:space:]]*\$/\\2/p" "$PROFILE_FILE" | tail -n1
}

has_fragment() {
    # has_fragment NAME: 0 yes, 1 no (profile readable), 2 unknown
    local list
    [ -r "$PROFILE_FILE" ] || return 2
    list=$(profile_value BTCPAYGEN_ADDITIONAL_FRAGMENTS)
    printf '%s' "$list" | tr ',' ';' | tr ';' '\n' | sed -E 's/^[[:space:]]+|[[:space:]]+$//g; s/\.yml$//' | grep -qxF "$1"
}

# ---------- harden ----------

port_role() {
    case "$1" in
        22) echo "ssh|info|SSH. Keys only, no root login, and a firewall rule limiting the source if you can." ;;
        80|443) echo "web|ok|HTTP or HTTPS for BTCPay Server." ;;
        9735|9736) echo "lnpeer|ok|Lightning peer port. Expected when Lightning is enabled." ;;
        8333) echo "p2p|warn|Bitcoin P2P is published (opt-expose-unsafe). Upstream limits this to a trusted LAN or firewall rules naming specific hosts, because the node whitelists these peers and a hostile peer can DoS it." ;;
        8332|18332) echo "rpc|warn|Bitcoin RPC is reachable from the network. Nothing should reach it except the stack." ;;
        24444) echo "nbx|warn|NBXplorer is reachable from the network. It should stay on the internal Docker network." ;;
        5432) echo "pg|warn|PostgreSQL is reachable from the network. Keep it internal." ;;
        9050|9051) echo "tor|warn|The Tor SOCKS or control port is reachable from the network. Keep it internal." ;;
        9911) echo "wt|info|LND watchtower (opt-lnd-watchtower). Only needed if you serve watchtower clients." ;;
        9814) echo "teos|info|TEOS watchtower (opt-add-teos)." ;;
        9001) echo "relay|info|Tor relay (opt-add-tor-relay). Needs contact details and legal review." ;;
        53) echo "dns|warn|DNS is published (opt-add-pihole). Upstream intends this for a trusted LAN. An open resolver is abused for amplification." ;;
        50002) echo "electrum|info|Public ElectrumX (opt-add-electrumx)." ;;
        *) echo "other|info|Unrecognised listener. Confirm you meant to publish it." ;;
    esac
}

harden_ports() {
    step "Listening ports reachable from the network"
    local a p seen="" role lvl msg shown=0
    if ! listeners >/dev/null 2>&1; then inf "Neither ss nor netstat is available; ports were not reviewed."; return; fi
    while read -r a p; do
        [ -n "${p:-}" ] || continue
        is_public_addr "$a" || continue
        case "$seen" in *" $p "*) continue ;; esac
        seen="$seen $p "
        shown=$((shown + 1))
        IFS='|' read -r role lvl msg <<<"$(port_role "$p")"
        case "$p" in 8080|10009) continue ;; esac   # reported by the LND check
        case "$lvl" in
            ok)   ok "port $p: $msg" ;;
            info) inf "port $p: $msg" ;;
            warn) caution "port $p: $msg"
                        case "$role" in
                            p2p)   tip "btcpay-fragments remove opt-expose-unsafe   (reapplies setup), or restrict 8333 to named peers in your firewall." ;;
                            dns)   tip "btcpay-fragments remove opt-add-pihole, or firewall 53 to your LAN." ;;
                            *)     tip "Remove the host port mapping or bind it to 127.0.0.1, then reapply setup. Add a default-deny firewall: allow only 22 (source-limited), 80, 443 and the Lightning peer port." ;;
                        esac ;;
        esac
    done < <(listeners)
    [ "$shown" -eq 0 ] && inf "No network-reachable listeners were reported (or this user cannot see them; run as root)."
    inf "The default Docker stack publishes only 80, 443 and the Lightning peer port when Lightning is enabled."
}

harden_fragments() {
    step "Optional fragments"
    if [ ! -r "$PROFILE_FILE" ]; then
        inf "Deployment profile $PROFILE_FILE is not readable here (not a Docker deployment, or run as root). Fragments were not reviewed."
        return
    fi
    local list f flagged=0
    list=$(profile_value BTCPAYGEN_ADDITIONAL_FRAGMENTS)
    inf "Additional fragments: ${list:-none}"
    for f in opt-expose-unsafe opt-add-pihole opt-lnd-watchtower opt-add-tor-relay opt-add-electrumx opt-add-cloudflared; do
        if has_fragment "$f"; then
            flagged=1
            case "$f" in
                opt-expose-unsafe) caution "$f is enabled: Bitcoin P2P port 8333 is published." ; tip "Remove it unless Bisq, Esplora or similar needs it: btcpay-fragments remove $f" ;;
                opt-add-pihole) caution "$f is enabled: DNS on port 53 is published." ; tip "Keep it to a trusted LAN, or remove it: btcpay-fragments remove $f" ;;
                opt-lnd-watchtower) inf "$f is enabled: an extra public port (9911) serves watchtower clients." ;;
                opt-add-tor-relay) inf "$f is enabled: this host relays Tor traffic on 9001. Confirm contact details and legal review." ;;
                opt-add-electrumx) inf "$f is enabled: a public ElectrumX endpoint on 50002 adds attack surface." ;;
                opt-add-cloudflared) inf "$f is enabled: traffic passes through Cloudflare Tunnel, which sees it unencrypted at the edge." ;;
            esac
        fi
    done
    [ "$flagged" -eq 0 ] && ok "None of the higher-exposure fragments is enabled."
}

harden_routes() {
    step "LND API routes in the bundled web server"
    local base dir r found=0
    base=$(profile_value BTCPAY_BASE_DIRECTORY)
    dir="${base:+$base/btcpayserver-docker/nginx/enabled-routes}"
    if [ -z "$dir" ] || [ ! -d "$dir" ]; then
        inf "The enabled-routes directory was not found (not a standard Docker deployment, or not readable). 'btcpay-routes show' lists them."
        return
    fi
    for r in "$dir"/*; do
        [ -e "$r" ] || [ -L "$r" ] || continue
        case "$(basename "$r")" in
            lnd-rest*|lnd-grpc*) found=1; caution "Route $(basename "$r") is enabled, so the LND API is reachable over HTTPS. Macaroons are then the only gate, and wallet unlock and setup calls need none while LND is locked."
                                                      tip "btcpay-routes remove $(basename "$r" | sed -E 's/\.conf$//')   unless an external wallet needs it. Rotate macaroons if it was ever enabled on a version before 2.4.2." ;;
        esac
    done
    [ "$found" -eq 0 ] && ok "No LND API route is enabled."
}

harden_filter() {
    step "Kernel and host"
    if command -v btcpay-ipv4-options-filter >/dev/null 2>&1; then
        local st; st=$(btcpay-ipv4-options-filter status 2>&1 | head -n3)
        if printf '%s' "$st" | grep -qi 'Enabled: yes'; then ok "IPv4 options filter: enabled."
        else caution "IPv4 options filter is not enabled. Until your kernel is patched for CVE-2026-98432 it drops inbound IPv4 TCP packets that carry IP options."
                  tip "btcpay-ipv4-options-filter enable   (needs nftables), and update the host kernel and reboot. This is described in btcpayserver-docker's networking guide."; fi
    else
        inf "btcpay-ipv4-options-filter was not found. Newer btcpayserver-docker installs it; btcpay-update.sh brings it."
    fi
    local f hits=""
    for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do
        [ -r "$f" ] || continue
        grep -qiE '^[[:space:]]*PasswordAuthentication[[:space:]]+yes' "$f" && hits="$hits PasswordAuthentication"
        grep -qiE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' "$f" && hits="$hits PermitRootLogin"
    done
    if [ -n "$hits" ]; then
        caution "sshd_config explicitly sets:$hits to yes."
        tip "Use keys only and PermitRootLogin prohibit-password or no. Confirm the effective values as root with: sshd -T | grep -Ei 'passwordauth|permitroot'"
    else
        ok "sshd_config does not explicitly enable password or root logins (the effective values need 'sshd -T' as root)."
    fi
    if command -v apt-get >/dev/null 2>&1 && [ -f /var/run/reboot-required ]; then
        caution "This host has a pending reboot (kernel or library updates not yet running)."
        tip "Reboot in a maintenance window. Updates do not protect you until the new kernel runs."
    fi
}

harden_tor_summary() {
    step "Tor"
    tor_detect
    case "$TOR_STATE" in
        enabled)  ok "Tor is enabled (hidden services and onion peers). Run '$SCRIPT_NAME tor' for what that means and how to turn it off." ;;
        disabled) ok "Tor is not enabled. Run '$SCRIPT_NAME tor' if you want the reasons to enable it." ;;
        partial)  caution "Tor is half configured: $TOR_NOTE"; tip "$SCRIPT_NAME tor" ;;
        *)        inf "Tor state could not be determined: $TOR_NOTE" ;;
    esac
}

MANUAL_STEPS=(
    "Hot wallet balance. Keep only what the next few days of payouts need. Wallets whose spending keys are held off the server, such as hardware wallets, were not affected by the November thefts, so move the rest to one."
    "Two-factor sign-in for every administrator (Account > Manage account), and a long unique password."
    "Registration. Server Settings > Policies: keep new-user registration off unless you want open sign-ups. The first account becomes the server administrator, so create it before the site is public."
    "API keys and store users. Revoke what you do not use. Give each key only the permissions its integration needs."
    "LND. If the wallet was created before the project's September 2.4.4 image, it may use the old shared default password. Follow the project's guidance to rotate it, and rotate macaroons after any exposure (BTCPay Server 2.4.4 release post)."
    "Backups. Run btcpay-backup.sh (it stops the stack while it runs), keep the archive off the host and encrypted, and test a restore. A static channel backup is not the channel state: read the backup guide before relying on it."
    "Updates. Watch the project's announcements, update promptly, and confirm the version string in the page footer afterwards."
    "Firewall. Default deny inbound. Allow 80 and 443, the Lightning peer port if you use Lightning, and SSH from your own addresses only."
    "Monitoring. Alert on new administrator logins, new API keys, new store users and unexpected outbound transactions."
)

harden_manual() {
    step "Steps that cannot be checked from here"
    local i=0 step
    for step in "${MANUAL_STEPS[@]}"; do
        i=$((i + 1))
        if [ "$JSON" -eq 1 ]; then printf 'MANUAL  %s\n' "$step"
        else printf '%s\n' "$step" | fold -s -w 66 | sed -e "1s/^/      $i. /" -e '2,$s/^/         /'; fi
    done
}

cmd_harden() {
    local url="" dirs=()
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) [ $# -ge 2 ] || { die "Option --url needs a value."; }; url="$2"; shift 2 ;;
            --profile) [ $# -ge 2 ] || { die "Option --profile needs a value."; }; PROFILE_FILE="$2"; shift 2 ;;
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) [ -d "$1" ] || { die "Not a directory: $1"; }; dirs+=("$1"); shift ;;
        esac
    done
    if [ "${#dirs[@]}" -eq 0 ]; then
        local d; for d in "$HOME" /opt /srv "${BTCPAY_BASE_DIRECTORY:-}"; do [ -n "$d" ] && [ -d "$d" ] && dirs+=("$d"); done
    fi
    step "Version"
    setup_docker
    scan_containers
    scan_files "${dirs[@]}"
    [ -n "$url" ] && scan_url "$url"
    [ "$FOUND" -eq 0 ] && inf "No BTCPay Server found on this host."
    update_history_report
    lnd_exposure
    [ "$EXPOSED_SEEN" -eq 1 ] && advice_short
    harden_ports
    harden_fragments
    harden_routes
    harden_filter
    step "Access to this host"
    host_access_ssh
    host_access_stack
    host_access_admins
    harden_tor_summary
    harden_manual
    verdict
    inf "Nothing was changed. Each suggestion is a command for you to review and run."
    if [ "$CRITS" -gt 0 ] || [ "$UNKNOWN" -gt 0 ]; then return 1; fi
    return 0
}

# ---------- tor ----------

TOR_STATE="unknown"; TOR_NOTE=""; TOR_RUNNING=0

tor_detect() {
    local frag running="" rows name image state
    has_fragment opt-add-tor; frag=$?
    TOR_RUNNING=0
    [ -z "$DOCKER" ] && setup_docker
    if [ "$DOCKER_OK" -eq 1 ]; then
        rows=$(docker_ps)
        while IFS='|' read -r name image state; do
            [ -n "$name" ] || continue
            if [[ "$image" =~ (^|/)btcpayserver/tor(:|@|$) ]] || [ "$name" = tor ]; then
                running="$name"; [ "$state" = running ] && TOR_RUNNING=1
            fi
        done <<<"$rows"
    fi
    if [ "$DOCKER_OK" -ne 1 ] && [ "$frag" -eq 2 ]; then
        TOR_STATE=unknown; TOR_NOTE="neither the deployment profile ($PROFILE_FILE) nor docker could be read. Run as root."; return
    fi
    if [ "$DOCKER_OK" -eq 1 ]; then
        if [ "$frag" -eq 0 ] && [ "$TOR_RUNNING" -eq 1 ]; then TOR_STATE=enabled
        elif [ "$frag" -eq 1 ] && [ -z "$running" ]; then TOR_STATE=disabled
        elif [ "$frag" -eq 0 ]; then TOR_STATE=partial; TOR_NOTE="opt-add-tor is in the profile but no running tor container was found. Setup may not have been reapplied, or the container stopped."
        elif [ "$frag" -eq 1 ]; then TOR_STATE=partial; TOR_NOTE="a tor container exists ($running) but opt-add-tor is not in the profile. It may be a custom fragment or a stale container."
        else
            [ "$TOR_RUNNING" -eq 1 ] && TOR_STATE=enabled || TOR_STATE=disabled
            TOR_NOTE="the profile was not readable; judged from docker only."
        fi
    else
        [ "$frag" -eq 0 ] && TOR_STATE=enabled || TOR_STATE=disabled
        TOR_NOTE="docker could not be read; judged from the profile only."
    fi
}

tor_hostnames() {
    local dir="${TOR_SERVICES_DIR:-}" d h
    if [ -z "$dir" ] && [ "$DOCKER_OK" -eq 1 ]; then
        dir=$("$DOCKER" volume inspect generated_tor_servicesdir --format '{{.Mountpoint}}' 2>/dev/null | head -n1)
    fi
    [ -n "$dir" ] || dir=/var/lib/docker/volumes/generated_tor_servicesdir/_data
    [ -d "$dir" ] && [ -r "$dir" ] || { inf "Onion service names were not read ($dir is missing or needs root)."; return; }
    for d in "$dir"/*/; do
        [ -f "${d}hostname" ] || continue
        h=$(basename "$d")
        case "$h" in
            BTCPayServer|WooCommerce) inf "onion service $h: $(head -n1 "${d}hostname")" ;;
            *) inf "onion service $h exists (address not printed: treat it as private)." ;;
        esac
    done
}

tor_explain() {
    [ "$JSON" -eq 1 ] && return
    cat <<'EXP'

What Tor does in this stack (from the project's fragment notes)
  * Publishes BTCPay Server (and WooCommerce, if present) as onion services,
    and a Bitcoin P2P and RPC onion service for the node, and lets the node
    use onion peers.
  * Helps with NAT and firewall problems: a server at home or in an office
    can be reached without opening ports, a fixed IP or a certificate.
  * It is NOT an anonymity tool for the operator. Not all outbound traffic is
    sent through Tor, and the clearnet site stays reachable. The project
    warns it does not protect against a targeted attack on your privacy.

Since BTCPay Server 2.4.5 Tor is opt-in. A deployment that used Tor before
must select it again after its next Docker setup or update to keep its onion
services (existing Tor data is kept in the Tor volumes).

Choose to enable it when
  * the server sits behind NAT or a firewall you cannot change, or
  * you want customers or point-of-sale devices to have an onion path.

Choose to disable it when
  * you have a public domain with HTTPS and no need for onion access, because
    it removes an extra container and the node's onion services, or
  * you do not want the node accepting onion peers.
  Disabling breaks anything that uses the .onion addresses: wallets, webhooks,
  POS devices. Docker normally keeps named volumes, so re-enabling later
  should bring the same onion addresses back.

Hardening notes for either choice
  * Never publish the Tor SOCKS (9050) or control (9051) ports. 'harden' flags
    them if they are reachable.
  * Do not share the BTC-P2P or BTC-RPC onion addresses. The node whitelists
    connections to them.
  * An LND API exposed over a Tor service you set up yourself is exposed like
    any other route: keep it off, or rotate its credentials independently.
EXP
}

tor_commands() {
    if [ "$JSON" -eq 1 ]; then
        printf 'COMMAND  %s\n' "btcpay-fragments add opt-add-tor" "btcpay-fragments remove opt-add-tor" "btcpay-fragments show"
        return
    fi
    cat <<'CMD'

Commands (run as root; each reapplies setup and briefly restarts services,
so run btcpay-backup.sh first and pick a quiet time)
  Enable : btcpay-fragments add opt-add-tor
  Disable: btcpay-fragments remove opt-add-tor
  Verify : btcpay-fragments show ; docker ps --filter name=tor
CMD
}

tor_apply() {
    # tor_apply enable|disable : runs the project's btcpay-fragments after the operator confirms
    local action="$1" fragcmd
    need_root "tor $action changes the host"
    fragcmd=$(command -v btcpay-fragments 2>/dev/null || true)
    [[ -n "$fragcmd" ]] || die "btcpay-fragments was not found in PATH. This is not a standard Docker deployment, or setup has not been run."
    case "$action" in enable) fragcmd="$fragcmd add opt-add-tor" ;; *) fragcmd="$fragcmd remove opt-add-tor" ;; esac
    printf 'About to run: %s\n' "$fragcmd"
    printf 'This reapplies setup and restarts services. Have you taken a backup (btcpay-backup.sh)?\n'
    if [[ "$ASSUME_YES" -ne 1 ]]; then
        local ans=""
        { : </dev/tty; } 2>/dev/null || die "tor $action needs a terminal to ask on, or --yes"
        read -r -p 'Type yes to continue: ' ans </dev/tty
        [[ "$ans" = yes ]] || { inf "Not confirmed. Nothing was changed."; return 1; }
    fi
    # shellcheck disable=SC2086
    $fragcmd
    local rc=$?
    if [[ "$rc" -eq 0 ]]; then inf "Done. Verify with: btcpay-fragments show"; else warn "btcpay-fragments exited with status $rc. Check the output above and 'btcpay-fragments show'." >&2; fi
    return "$rc"
}
cmd_tor() {
    local action="status" dry=0
    ASSUME_YES=0
    while [ $# -gt 0 ]; do
        case "$1" in
            status|enable|disable) action="$1"; shift ;;
            --dry-run) dry=1; shift ;;
            --yes) ASSUME_YES=1; shift ;;
            --profile) [ $# -ge 2 ] || { die "Option --profile needs a value."; }; PROFILE_FILE="$2"; shift 2 ;;
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) die "Unknown argument: $1" ;;
        esac
    done
    if [ "$dry" -eq 1 ] && [ "$action" = status ]; then die "--dry-run needs 'enable' or 'disable'."; fi
    setup_docker
    tor_detect
    case "$TOR_STATE" in
        enabled)  ok "Tor is ENABLED." ;;
        disabled) ok "Tor is DISABLED." ;;
        partial)  caution "Tor is half configured: $TOR_NOTE" ;;
        *)        inf "Tor state could not be determined: $TOR_NOTE" ;;
    esac
    [ -n "$TOR_NOTE" ] && [ "$TOR_STATE" != partial ] && [ "$TOR_STATE" != unknown ] && inf "Note: $TOR_NOTE"
    [ "$TOR_STATE" = enabled ] || [ "$TOR_STATE" = partial ] && tor_hostnames
    tor_explain
    tor_commands
    case "$action" in
        enable|disable)
            step "Plan: $action Tor"
            if [ "$action" = enable ] && [ "$TOR_STATE" = enabled ]; then inf "Tor is already enabled. Nothing to do."; return 0; fi
            if [ "$action" = disable ] && [ "$TOR_STATE" = disabled ]; then inf "Tor is already disabled. Nothing to do."; return 0; fi
            if [ "$dry" -eq 1 ]; then inf "Dry run: nothing was changed. Run it without --dry-run to apply it, or copy the command above."; return 0; fi
            tor_apply "$action"; return $?
            ;;
    esac
    return 0
}

# ---------- update history, SSH access, custom fragments, accounts ----------

SSH_AUTH_KEYS="${SSH_AUTH_KEYS:-/root/.ssh/authorized_keys}"

btcpay_base() {
    # The deployment folder that holds btcpayserver-docker, the update logs and .env.
    local b="${BTCPAY_BASE_DIRECTORY:-}"
    [ -n "$b" ] || b=$(profile_value BTCPAY_BASE_DIRECTORY 2>/dev/null || true)
    if [ -n "$b" ] && [ -d "$b" ]; then printf '%s\n' "$b"; return 0; fi
    return 1
}

update_archives() {
    # btcpay-update.sh saves the compose logs of the running stack to
    # btcpay-update-logs/update-<UTC>.log.gz before it replaces the containers, and
    # keeps the five newest. The web interface writes btcpay-update.log and
    # btcpay-host-<command>.log. These are the only logs that outlive a recreated container.
    local base f
    base=$(btcpay_base) || return 0
    for f in "$base"/btcpay-update-logs/update-*.log.gz "$base"/btcpay-update.log "$base"/btcpay-host-*.log; do
        [ -f "$f" ] && printf '%s\n' "$f"
    done
    return 0
}

update_history() {
    # Sets UPDATE_TIMES (UTC) and UPDATED_AFTER=1 when any update ran after the project's warning.
    local base f name stamp iso e warned
    UPDATE_TIMES=(); UPDATED_AFTER=0
    base=$(btcpay_base) || return 0
    warned=$(date -u -d "$WARNED_AT" +%s)
    for f in "$base"/btcpay-update-logs/update-*.log.gz; do
        [ -f "$f" ] || continue
        name=${f##*/}; stamp=${name#update-}; stamp=${stamp%.log.gz}
        [[ "$stamp" =~ ^([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z$ ]] || continue
        iso="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-${BASH_REMATCH[3]}T${BASH_REMATCH[4]}:${BASH_REMATCH[5]}:${BASH_REMATCH[6]}Z"
        e=$(date -u -d "$iso" +%s 2>/dev/null) || continue
        UPDATE_TIMES+=("$iso")
        if [ "$e" -gt "$warned" ]; then UPDATED_AFTER=1; fi
    done
    for f in "$base/btcpay-update.log" "$base/btcpay-host-update.log"; do
        [ -f "$f" ] || continue
        e=$(stat -c %Y "$f" 2>/dev/null) || continue
        iso=$(date -u -d "@$e" +%Y-%m-%dT%H:%M:%SZ)
        UPDATE_TIMES+=("$iso (modification time of ${f##*/})")
        if [ "$e" -gt "$warned" ]; then UPDATED_AFTER=1; fi
    done
    return 0
}

update_history_report() {
    update_history
    btcpay_base >/dev/null || return 0
    if [ "${#UPDATE_TIMES[@]}" -gt 0 ]; then
        local joined; joined=$(printf '%s, ' "${UPDATE_TIMES[@]}"); joined=${joined%, }
        inf "Updates recorded on this host: $joined."
    else
        inf "No update records were found. btcpay-update.sh keeps its five newest log archives in btcpay-update-logs."
    fi
    if [ "$UPDATED_AFTER" -eq 1 ]; then
        caution "An update ran after the project's warning (22:25 UTC on 1 November). If this host was on 2.4.1 or earlier before it, the project still recommends a fresh server and a new wallet. If it was already on 2.4.2 or later, the project has seen no impact."
        [ "$IN_RECOVER" -eq 1 ] || tip "$SCRIPT_NAME recover"
    fi
}

host_access_ssh() {
    local f="$SSH_AUTH_KEYS" line comment legacy=0 loose=0 tight=0 other=0 oddcmd=0
    if [ ! -r "$f" ]; then inf "root's authorized_keys is not readable here ($f). Run as root to review SSH access."; return 0; fi
    while IFS= read -r line; do
        case "$line" in ''|'#'*) continue ;; esac
        comment=${line##* }
        case "$comment" in
            btcpayserver) legacy=$((legacy + 1)) ;;
            btcpay-host)
                if [[ "$line" == restrict,command=* ]]; then
                    tight=$((tight + 1))
                    [[ "$line" == *'btcpay-host-proxy"'* ]] || oddcmd=$((oddcmd + 1))
                else loose=$((loose + 1)); fi ;;
            *) other=$((other + 1)) ;;
        esac
    done < "$f"
    if [ "$legacy" -gt 0 ]; then
        caution "root's authorized_keys holds $legacy legacy BTCPay Server $(pl "$legacy" key keys) (comment 'btcpayserver') with no command restriction. The BTCPay Server container used that key to log in to this host as root, so on 2.4.1 or earlier an attacker in the application could have had a root shell here."
        tip "Remove the line, then run btcpay-update.sh: it installs the restricted btcpay-host entry. On a host that ran 2.4.1 or earlier, rebuild instead: $(rhint)."
    fi
    if [ "$loose" -gt 0 ]; then
        caution "A btcpay-host key in root's authorized_keys has no 'restrict,command=' prefix, so it allows a full shell and not only the approved host commands."
        tip "Run btcpay-update.sh, which rewrites it as restrict,command=.../Generated/btcpay-host-proxy."
    fi
    if [ "$oddcmd" -gt 0 ]; then
        caution "A restricted btcpay-host key runs a command other than Generated/btcpay-host-proxy. Confirm that you set that up."
    fi
    if [ "$tight" -gt 0 ] && [ "$legacy" -eq 0 ] && [ "$loose" -eq 0 ] && [ "$oddcmd" -eq 0 ]; then
        ok "The BTCPay host key is limited to the project's host command (restrict,command=)."
    fi
    if [ "$other" -gt 0 ]; then
        inf "$other other $(pl "$other" key keys) in root's authorized_keys. Confirm $(pl "$other" it each) $(pl "$other" is is) yours. 'preserve' saves their fingerprints."
    fi
    return 0
}

host_access_stack() {
    local base repo f names="" n=0 dirty remote tok sel
    base=$(btcpay_base) || return 0
    repo="$base/btcpayserver-docker"
    if [ ! -d "$repo" ]; then inf "No btcpayserver-docker folder was found under $base."; return 0; fi
    for f in "$repo"/docker-compose-generator/docker-fragments/*.custom.yml; do
        [ -f "$f" ] || continue
        n=$((n + 1)); names="$names ${f##*/}"
    done
    if [ "$n" -gt 0 ]; then
        caution "Custom $(pl "$n" fragment fragments) in the stack:$names. A custom fragment adds containers and settings on every update, and Git ignores it. Confirm you wrote each one."
        tip "less $repo/docker-compose-generator/docker-fragments/<name>; btcpay-fragments show"
    else
        ok "No custom fragments in the stack."
    fi
    sel=$(profile_value BTCPAYGEN_ADDITIONAL_FRAGMENTS 2>/dev/null || true)
    for tok in $(printf '%s' "$sel" | tr ',;' '  '); do
        case "$tok" in *.custom|*.custom.yml)
            [ -f "$repo/docker-compose-generator/docker-fragments/${tok%.yml}.yml" ] || inf "The profile selects $tok, but that file is not in the fragments folder." ;;
        esac
    done
    if ! command -v git >/dev/null 2>&1; then inf "git is not installed, so the btcpayserver-docker folder was not compared with the project's copy."; return 0; fi
    if ! git -C "$repo" rev-parse --git-dir >/dev/null 2>&1; then inf "$repo is not a readable Git checkout."; return 0; fi
    GIT_HEAD=$(git -C "$repo" rev-parse --short=12 HEAD 2>/dev/null || true)
    dirty=$(git -C "$repo" status --porcelain 2>/dev/null | head -n 5 | sed 's/^ *//' | tr '\n' ';' | sed 's/;$//; s/;/; /g')
    if [ -n "$dirty" ]; then
        caution "The btcpayserver-docker folder has local changes ($dirty). btcpay-update.sh runs these scripts as root, so review them."
        tip "git -C $repo status ; git -C $repo diff"
    else
        ok "The btcpayserver-docker folder has no local changes${GIT_HEAD:+ (commit $GIT_HEAD)}."
    fi
    remote=$(git -C "$repo" remote get-url origin 2>/dev/null || true)
    case "$remote" in
        *github.com/btcpayserver/btcpayserver-docker*|*github.com:btcpayserver/btcpayserver-docker*) ok "Updates are pulled from the project's repository." ;;
        '') inf "The btcpayserver-docker checkout has no 'origin' remote." ;;
        *) caution "The btcpayserver-docker checkout pulls from $remote, not the project's repository. btcpay-update.sh runs what it fetches as root."
              tip "git -C $repo remote -v" ;;
    esac
    return 0
}

host_access_admins() {
    if [ "${DOCKER_OK:-0}" -ne 1 ]; then inf "Server administrators were not listed (docker is not usable here)."; return 0; fi
    local pg="" nm image state net rows email tfa n=0 list="" off=()
    while IFS='|' read -r nm image state; do
        [ -n "$nm" ] || continue
        if [[ "$image" =~ (^|/)postgres(:|@|$) ]]; then pg="$nm"; break; fi
    done < <(docker_ps)
    if [ -z "$pg" ]; then inf "No PostgreSQL container was found, so the server administrators were not listed."; return 0; fi
    net=$(profile_value NBITCOIN_NETWORK 2>/dev/null || true); net=${net:-mainnet}
    rows=$("$DOCKER" exec -e PGOPTIONS='-c default_transaction_read_only=on' "$pg" psql -U postgres -d "btcpayserver${net}" -At -F '|' \
        -c 'SELECT u."Email", u."TwoFactorEnabled" FROM "AspNetUsers" u JOIN "AspNetUserRoles" ur ON ur."UserId" = u."Id" JOIN "AspNetRoles" r ON r."Id" = ur."RoleId" WHERE r."NormalizedName" = '"'SERVERADMIN'"' ORDER BY u."Email"' 2>/dev/null) || {
        inf "The server administrators could not be read from PostgreSQL."; return 0; }
    while IFS='|' read -r email tfa; do
        [ -n "$email" ] || continue
        n=$((n + 1))
        if [ "$tfa" = t ]; then list="$list$email (two-factor on), "; else list="$list$email (two-factor off), "; off+=("$email"); fi
    done <<<"$rows"
    if [ "$n" -eq 0 ]; then inf "The query returned no server administrators."; return 0; fi
    inf "Server administrators ($n): ${list%, }. Confirm each address is someone you know. An address you do not recognize is a sign of unauthorized access."
    for email in "${off[@]+"${off[@]}"}"; do
        caution "Server administrator $email signs in without two-factor authentication."
        tip "Account > Manage account > Two-factor authentication: use an authenticator app or a security key."
    done
    return 0
}

host_access_review() {
    step "Signs on this host"
    host_access_ssh
    host_access_stack
    host_access_admins
}

lnd_tag_old() {
    # 0 when the LND tag is older than 0.21.1, the version the August advisory called for
    local t="${1#v}" mi pa
    [[ "$t" =~ ^0\.([0-9]+)\.([0-9]+) ]] || return 1
    mi=${BASH_REMATCH[1]}; pa=${BASH_REMATCH[2]}
    if [ "$mi" -lt 21 ]; then return 0; fi
    [ "$mi" -eq 21 ] && [ "$pa" -lt 1 ]
}

# ---------- recover ----------

STEP_N=0
plan_step() {
    STEP_N=$((STEP_N + 1))
    if [ "$JSON" -eq 1 ]; then printf 'STEP  %s\n' "$*"
    else printf '%s\n' "$*" | fold -s -w 66 | sed -e 's/[[:space:]]*$//' -e "1s/^/  $STEP_N. /" -e '2,$s/^/     /'; fi
}

rline() {
    if [ "$JSON" -eq 1 ]; then printf 'REPORT  %s\n' "$*"; else printf '      %s\n' "$*"; fi
}

ssh_key_count() {
    local f n=0 c
    local seen=" "
    for f in "$SSH_AUTH_KEYS" /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
        [ -r "$f" ] || continue
        case "$seen" in *" $f "*) continue ;; esac
        seen="$seen$f "
        c=$(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null || true)
        n=$((n + ${c:-0}))
    done
    echo "$n"
}

recovery_steps() {
    # recovery_steps: the project's four steps, with this host's details added
    local keys keys_note=""; keys=$(ssh_key_count)
    if [ "$keys" -gt 0 ]; then keys_note=" (${keys} authorized $(pl "$keys" key keys) found on this host)"; fi
    plan_step "Make a NEW wallet with a NEW seed on a trusted device, not on the old server. Send everything left in the old hot wallet to an address of the new wallet. Never reuse the old seed on the new server. Wallets whose spending keys are held off the server, including hardware wallets, were not drained, but the project still recommends rebuilding the server."
    plan_step "Save the evidence, then take the old server offline. Run: $SCRIPT_NAME preserve  (it writes one archive; copy it off this host). Then stop the stack: docker-compose -f \"\$BTCPAY_DOCKER_COMPOSE\" stop (this keeps the containers and their logs; btcpay-down.sh removes them and btcpay-teardown.sh erases the volumes, so use neither yet). Keep the old disk until the investigation is done."
    plan_step "Provision a FRESH server and install the latest release ($NEWEST or newer) from trusted sources. Connect the NEW wallet. Do not restore the old server, its backup or its volumes onto it."
    plan_step "From a trusted device, replace every credential the old server could reach: your hosting account and its API tokens, SSH keys${keys_note}, BTCPay Server logins, API keys and store users, payment-plugin keys in your shops, SMTP and DNS logins, and Lightning credentials. Never type the new ones on the old machine."
    local ln_kinds=()
    if [ "$LND_PRESENT" -eq 1 ]; then ln_kinds+=("LND"); fi
    if [ "${#LN_OTHER[@]}" -gt 0 ]; then ln_kinds+=("${LN_OTHER[@]}"); fi
    if [ "${#ln_kinds[@]}" -gt 0 ]; then
        plan_step "Lightning runs on this host ($(printf '%s, ' "${ln_kinds[@]}" | sed 's/, $//')). The project's November post covers the BTCPay Server hot wallet and does not address Lightning funds, so treat the node's wallet password, macaroons and keys as exposed, as the August advisory did for LND. Note your channel and on-chain balances, ask the project at security@btcpayserver.org how to move them safely, and never run the old node and a restored copy at the same time: the project's backup guide warns that stale channel state can lose funds."
    fi
    if has_fragment opt-add-tor; then
        plan_step "Tor is enabled here. The new server gets new onion addresses. Tell anyone who used the old ones."
    fi
    plan_step "Check the old hot wallet's transaction history for the destination addresses in the incident reports: ${IOC_ADDRESSES[0]} and ${IOC_ADDRESSES[1]}. The project says some activity at them predates the thefts, so their balances are not a confirmed total of losses."
    plan_step "If you lost funds or saw unauthorized access, email security@btcpayserver.org and report the theft to your local authorities. Never send seeds, keys or passwords, and strip secrets from any log or file before sharing it."
}

report_block() {
    step "What to send the project (fill in the blanks)"
    local l
    if [ "${#SEEN_LINES[@]}" -gt 0 ]; then
        for l in "${SEEN_LINES[@]}"; do rline "Version found, $l"; done
    else
        rline "Version found: (none read on this host)"
    fi
    if [ "${#OLD_IMAGES[@]}" -gt 0 ]; then rline "Older images still on disk: ${OLD_IMAGES[*]}"; fi
    if [ "${#CREATED_LINES[@]}" -gt 0 ]; then for l in "${CREATED_LINES[@]}"; do rline "Container: $l"; done; fi
    if [ "${#UPDATE_TIMES[@]}" -gt 0 ]; then rline "Updates recorded: $(printf '%s, ' "${UPDATE_TIMES[@]}" | sed 's/, $//')"; fi
    if [ -n "$GIT_HEAD" ]; then rline "btcpayserver-docker commit: $GIT_HEAD"; fi
    rline "Report prepared: $(date -u +%Y-%m-%dT%H:%MZ)"
    rline "You fill in: when you last updated and the version before that; when you noticed, with your time zone; public transaction IDs and addresses."
}

cmd_recover() {
    IN_RECOVER=1
    local url="" dirs=() d
    while [ $# -gt 0 ]; do
        case "$1" in
            --url) [ $# -ge 2 ] || { die "Option --url needs a value."; }; url="$2"; shift 2 ;;
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) [ -d "$1" ] || { die "Not a directory: $1"; }; dirs+=("$1"); shift ;;
        esac
    done
    if [ "${#dirs[@]}" -eq 0 ]; then
        for d in "$HOME" /opt /srv "${BTCPAY_BASE_DIRECTORY:-}"; do [ -n "$d" ] && [ -d "$d" ] && dirs+=("$d"); done
    fi
    step "Version"
    setup_docker
    scan_containers
    scan_files "${dirs[@]}"
    [ -n "$url" ] && scan_url "$url"
    [ "$FOUND" -eq 0 ] && inf "No BTCPay Server found on this host. If it runs elsewhere, use --url or run this on that host."
    update_history_report
    step "Verdict"
    if [ "$EXPOSED_SEEN" -eq 1 ]; then
        bad "This host is exposed. The project's advice for 2.4.1 and earlier is a fresh server and a new wallet. Updating in place does not remove access an attacker may already have, and an unchanged balance does not rule out an earlier attack."
        host_access_review
        step "Plan"
        recovery_steps
        report_block
    elif [ "$CREATED_AFTER" -eq 1 ] || [ "$UPDATED_AFTER" -eq 1 ]; then
        caution "The version is fixed, but this host was updated, or a container was created, after the project's warning. Decide which of these is true."
        inf "Already on 2.4.2 or later when the warning went out (22:25 UTC on 1 November): the project has seen no impact on those servers. Update to $NEWEST if you are behind, then run '$SCRIPT_NAME harden'."
        inf "On 2.4.1 or earlier, or you do not know: follow the plan below. This also applies if you updated after the warning."
        host_access_review
        step "Plan"
        recovery_steps
        report_block
    elif [ "$UNKNOWN" -gt 0 ]; then
        caution "A version could not be read, so the host cannot be cleared. Pin an explicit version tag or use --url and run this again. If it may have run 2.4.1 or earlier, follow the plan below."
        host_access_review
        step "Plan"
        recovery_steps
        report_block
    elif [ "$FOUND" -eq 0 ]; then
        inf "Nothing to recover from here: no BTCPay Server was found."
    else
        ok "Nothing in the version data says this host ran 2.4.1 or earlier. The project has seen no impact on servers that were on 2.4.2 or later when it warned."
        inf "An empty list of old images tells you little: btcpay-update.sh removes unused images by default."
        inf "If you ran an older version at any time before 1 November 22:25 UTC and updated after it, treat the host as exposed and follow '$SCRIPT_NAME recover' on a copy of that history, or ask the project."
        inf "Next: update if you are behind, then '$SCRIPT_NAME harden'."
        host_access_review
    fi
    if [ "$CRITS" -gt 0 ] || [ "$UNKNOWN" -gt 0 ]; then return 1; fi
    return 0
}

# ---------- preserve ----------

redact() {
    sed -E \
        -e 's/([Mm]acaroon[A-Za-z_-]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?)[0-9A-Fa-f]{16,}/\1[redacted]/g' \
        -e 's/([Aa]uthorization:[[:space:]]*)[^[:space:]]+([[:space:]]+[^[:space:]]+)?/\1[redacted]/g' \
        -e 's/((pass(word|phrase|wd)?|secret|token|api[_-]?key|seed|mnemonic|private[_-]?key)[A-Za-z0-9_]*["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"']?)[^[:space:]&"'"'"';,]+/\1[redacted]/Ig' \
        -e 's/[0-9A-Fa-f]{100,}/[long hex redacted]/g'
}

strip_colour() { sed -E $'s/\033\\[[0-9;]*m//g'; }

cmd_preserve() {
    local out_dir="." log_dirs=() d
    while [ $# -gt 0 ]; do
        case "$1" in
            --out) [ $# -ge 2 ] || { die "Option --out needs a value."; }; out_dir="$2"; shift 2 ;;
            -h|--help) print_help; exit 0 ;;
            -*) die "Unknown option: $1" ;;
            *) [ -d "$1" ] || { die "Not a directory: $1"; }; log_dirs+=("$1"); shift ;;
        esac
    done
    [ -d "$out_dir" ] && [ -w "$out_dir" ] || { die "Output folder is not writable: $out_dir"; }
    if ! command -v tar >/dev/null 2>&1 || ! command -v gzip >/dev/null 2>&1; then die "tar and gzip are needed."; fi
    if [ "${#log_dirs[@]}" -eq 0 ]; then
        for d in /var/log/nginx /var/log/apache2 /var/log/httpd /var/log/caddy; do [ -d "$d" ] && log_dirs+=("$d"); done
    fi
    umask 077
    local stamp host name arc base f n out role image nm state
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    host=$(hostname 2>/dev/null || echo host); host=${host//[^A-Za-z0-9._-]/_}
    name="btcpay-evidence-${host}-${stamp}"
    arc="${out_dir%/}/${name}.tar.gz"
    [ ! -e "$arc" ] || { die "Refusing to overwrite $arc"; }
    # work is global on purpose: the trap runs after this function has returned.
    work=$(mktemp -d 2>/dev/null) || { die "Cannot make a temporary folder."; }
    trap 'rm -rf "${work:-}"' EXIT
    base="$work/$name"
    mkdir -p "$base/host" "$base/docker" "$base/logs"

    step "Collecting"
    { date -u +'now (UTC): %Y-%m-%dT%H:%M:%SZ'; echo "host: $host"; uname -a 2>/dev/null; uptime 2>/dev/null; id 2>/dev/null; } > "$base/host/time-and-system.txt"
    if command -v last >/dev/null 2>&1; then last -n 100 -F 2>/dev/null > "$base/host/recent-logins.txt" || true; fi
    if command -v ssh-keygen >/dev/null 2>&1; then
        for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
            [ -r "$f" ] || continue
            { echo "== $f (modified $(date -u -r "$f" +%Y-%m-%dT%H:%MZ 2>/dev/null))"; ssh-keygen -lf "$f" 2>&1; } >> "$base/host/ssh-authorized-key-fingerprints.txt"
        done
    fi
    if command -v ss >/dev/null 2>&1; then ss -tlnp 2>/dev/null > "$base/host/listening.txt" || true
    elif command -v netstat >/dev/null 2>&1; then netstat -tlnp 2>/dev/null > "$base/host/listening.txt" || true; fi
    if [ -r "$PROFILE_FILE" ]; then
        sed -E 's/^([[:space:]]*(export[[:space:]]+)?[A-Za-z_]*(PASS|SECRET|TOKEN|KEY|MACAROON|SEED)[A-Za-z_]*=).*/\1[redacted]/I' "$PROFILE_FILE" | redact > "$base/host/deployment-profile.txt"
        ok "Deployment profile (secret-like values removed)"
    else
        inf "No deployment profile at $PROFILE_FILE."
    fi

    setup_docker
    if [ "$SCAN_CONTAINERS" = "0" ]; then
        inf "Containers skipped (SCAN_CONTAINERS=0)."
    elif [ -z "$DOCKER" ]; then
        inf "Neither docker nor podman is installed; no container records."
    elif [ "$DOCKER_OK" -ne 1 ]; then
        caution "$(basename "$DOCKER") is installed but this user cannot use it. Run as root to save container records and logs."
    else
        "$DOCKER" ps -a --no-trunc --format '{{.Names}}\t{{.Image}}\t{{.CreatedAt}}\t{{.Status}}' > "$base/docker/containers.tsv" 2>/dev/null || true
        "$DOCKER" images --digests --format '{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedAt}}' > "$base/docker/images.tsv" 2>/dev/null || true
        n=0
        while IFS='|' read -r nm image state; do
            [ -n "$nm" ] || continue
            "$DOCKER" inspect --format '{{.Name}} created={{.Created}} started={{.State.StartedAt}} image={{.Config.Image}}' "$nm" >> "$base/docker/containers-inspect.txt" 2>/dev/null || true
            role=""
            if is_btcpay_image "$image"; then role=1
            elif [[ "$image" =~ (^|/)(btcpayserver/lnd|lightninglabs/lnd)(:|@|$) ]]; then role=1
            elif [[ "$image" =~ (^|/)nginx(:|@|$) ]] || [[ "$nm" =~ nginx ]]; then role=1
            elif [[ "$image" =~ (^|/)(btcpayserver/lightning|acinq/phoenixd)(:|@|$) ]]; then role=1
            elif [[ "$nm" =~ ^(btcpayserver_|generated_) ]]; then role=1
            fi
            [ -n "$role" ] || continue
            "$DOCKER" logs --tail "$LOG_TAIL" "$nm" 2>&1 | redact > "$base/logs/container-${nm//[^A-Za-z0-9._-]/_}.log"
            n=$((n + 1))
        done < <(docker_ps)
        ok "Container records and $n container $(pl "$n" log logs) (secrets removed)"
    fi

    n=0
    for d in "${log_dirs[@]+"${log_dirs[@]}"}"; do
        while IFS= read -r -d '' f; do
            out="$base/logs/web-$(printf '%s' "$f" | tr '/' '_' | sed 's/^_//')"
            case "$f" in
                *.gz) gzip -dc -- "$f" 2>/dev/null | tail -n "$LOG_TAIL" | redact | gzip -c > "${out%.gz}.gz" ;;
                *) tail -n "$LOG_TAIL" -- "$f" 2>/dev/null | redact > "$out" ;;
            esac
            n=$((n + 1))
        done < <(find "$d" -maxdepth 3 -type f \( -name '*.log' -o -name '*.log.*' -o -name '*.gz' \) -print0 2>/dev/null)
    done
    if [ "$n" -gt 0 ]; then ok "$n web server log $(pl "$n" file files) (secrets removed)"; else inf "No web server logs found. Name a folder to include one: $SCRIPT_NAME preserve /path/to/logs"; fi

    n=0
    while IFS= read -r f; do
        out="$base/logs/update-${f##*/}"
        case "$f" in
            *.gz) gzip -dc -- "$f" 2>/dev/null | tail -n "$LOG_TAIL" | redact | gzip -c > "$out" ;;
            *) tail -n "$LOG_TAIL" -- "$f" 2>/dev/null | redact > "$out" ;;
        esac
        n=$((n + 1))
    done < <(update_archives)
    if [ "$n" -gt 0 ]; then ok "$n update log $(pl "$n" file files) (secrets removed). These outlive the containers."; else inf "No update logs found."; fi

    { setup_docker; scan_containers; scan_files "$HOME" /opt /srv; update_history_report; host_access_ssh; host_access_stack; host_access_admins; } 2>&1 | strip_colour > "$base/check.txt" || true
    ok "Version findings (check.txt)"

    cat > "$base/README.txt" <<'EVREADME'
This archive was written by btcpayserver-nov2026-check.sh preserve.

It holds logs and records so they survive when the old server is replaced:
host time and system, recent logins, SSH key fingerprints, listening ports,
container and image records, container logs, web server logs, the deployment
profile and the version findings.

It never holds wallet files, seeds, keys, macaroon files or databases.
Values after words such as password, token, secret, seed and api key,
authorization headers, macaroon values and very long hex strings were replaced
with [redacted]. Redaction matches common patterns and cannot catch everything: read the files before you share
them, and send them only to people investigating the incident.

Transaction IDs and addresses are kept on purpose.
EVREADME
    (cd "$base" && find . -type f -print0 | sort -z | xargs -0 sha256sum > "$work/manifest.tmp" && mv "$work/manifest.tmp" MANIFEST.sha256) 2>/dev/null || true
    tar -czf "$arc" -C "$work" "$name" || { die "Could not write $arc"; }
    chmod 0600 "$arc" 2>/dev/null || true
    step "Result"
    ok "Evidence saved: $arc"
    inf "Size $(du -h "$arc" 2>/dev/null | cut -f1), SHA-256 $(sha256sum "$arc" 2>/dev/null | cut -d' ' -f1)."
    inf "Docker keeps only a few megabytes of log per container by default, so older lines are already gone. The update archives are the longest record."
    inf "Copy it off this host now. Keep it until the investigation is over. Read it before you share it: it holds IP addresses and request lines."
    inf "Next: once your funds are moved, stop the old stack with docker-compose stop, which keeps its containers and logs. Avoid btcpay-down.sh and btcpay-teardown.sh until the investigation is over."
    return 0
}

# ---------- output modes ----------

# Turn the report text into one JSON document. The report lines carry a level
# prefix (CRIT, WARN, ok, info), SECTION, ADVICE, MANUAL and COMMAND tags, and
# "Suggest:" lines that attach to the finding above them.
read -r -d '' JSON_AWK <<'AWK'
function esc(x,   i, c, o, n) {
  o = ""; n = length(x)
  for (i = 1; i <= n; i++) {
    c = substr(x, i, 1)
    if (c == "\\") o = o "\\\\"
    else if (c == "\"") o = o "\\\""
    else if (c == "\t") o = o "\\t"
    else if (c == "\r") o = o " "
    else if (c in CTL) o = o sprintf("\\u%04x", CTL[c])
    else o = o c
  }
  return o
}
function addf(level, msg) { nf++; L[nf] = level; M[nf] = msg; S[nf] = sec; T[nf] = ""; cnt[level]++ }
function list(arr, n,   i, o) { o = ""; for (i = 1; i <= n; i++) o = o (i > 1 ? "," : "") "\"" esc(arr[i]) "\""; return o }
BEGIN {
  for (i = 1; i < 32; i++) CTL[sprintf("%c", i)] = i
  sec = ""
}
/^CRIT  / { addf("crit", substr($0, 7)); next }
/^WARN  / { addf("warn", substr($0, 7)); next }
/^ok    / { addf("ok", substr($0, 7)); next }
/^info  / { addf("info", substr($0, 7)); next }
/^SECTION  / { sec = substr($0, 10); next }
/^ADVICE  / { na++; A[na] = substr($0, 9); next }
/^MANUAL  / { nm++; MN[nm] = substr($0, 9); next }
/^COMMAND  / { nc++; CM[nc] = substr($0, 10); next }
/^STEP  / { nst++; ST[nst] = substr($0, 7); next }
/^REPORT  / { nr++; RP[nr] = substr($0, 9); next }
/^      Suggest: / { if (nf > 0) { ns[nf]++; SG[nf, ns[nf]] = substr($0, 16) }; next }
END {
  printf "{\"tool\":\"%s\",\"version\":\"%s\",\"command\":\"%s\",\"host\":\"%s\",\"strict\":%s,", esc(tool), esc(ver), esc(cmd), esc(host), (strict == 1 ? "true" : "false")
  printf "\"exit\":%d,\"summary\":{\"crit\":%d,\"warn\":%d,\"ok\":%d,\"info\":%d},\"findings\":[", rc, cnt["crit"], cnt["warn"], cnt["ok"], cnt["info"]
  for (i = 1; i <= nf; i++) {
    printf "%s{\"level\":\"%s\",\"section\":\"%s\",\"message\":\"%s\"", (i > 1 ? "," : ""), L[i], esc(S[i]), esc(M[i])
    if (ns[i] > 0) { printf ",\"suggest\":["; for (j = 1; j <= ns[i]; j++) printf "%s\"%s\"", (j > 1 ? "," : ""), esc(SG[i, j]); printf "]" }
    printf "}"
  }
  printf "],\"advice\":[%s],\"steps\":[%s],\"report\":[%s],\"manual\":[%s],\"commands\":[%s]}\n", list(A, na), list(ST, nst), list(RP, nr), list(MN, nm), list(CM, nc)
}
AWK

to_json() {
    # to_json COMMAND EXITCODE STRICT < report
    awk -v tool="$SCRIPT_NAME" -v ver="$SCRIPT_VERSION" -v cmd="$1" -v rc="$2" -v strict="$3" \
            -v host="$(hostname 2>/dev/null || echo this-host)" "$JSON_AWK"
}

run_command() {
    local cmd="$1"; shift
    case "$cmd" in
        check) cmd_check "$@" ;;
        recover) cmd_recover "$@" ;;
        preserve) cmd_preserve "$@" ;;
        hunt) cmd_hunt "$@" ;;
        harden) cmd_harden "$@" ;;
        tor) cmd_tor "$@" ;;
    esac
}

# ---------- main ----------

main() {
    local cmd="check" arg rest=()
    for arg in "$@"; do
        case "$arg" in
            --json) JSON=1 ;;
            --strict) STRICT=1 ;;
            *) rest+=("$arg") ;;
        esac
    done
    set -- "${rest[@]+"${rest[@]}"}"
    if [[ $# -gt 0 ]]; then
        case "$1" in
            check|recover|preserve|hunt|harden|tor) cmd="$1"; shift ;;
            version|--version|-V) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
            help|-h|--help) print_help; exit 0 ;;
            -*) ;;
            */*|.) ;;
            *) die "Unknown command: $1 (check|recover|preserve|hunt|harden|tor|version)" ;;
        esac
    fi
    if [[ $JSON -eq 1 ]]; then
        RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''
        if [[ "$cmd" = tor && ( " $* " == *" enable "* || " $* " == *" disable "* ) && " $* " != *" --dry-run "* ]]; then
            die "--json cannot be combined with tor enable or disable, which asks for confirmation. Add --dry-run to see the plan."
        fi
    fi
    if [[ $JSON -eq 0 && $STRICT -eq 0 ]]; then
        banner "$cmd"
        run_command "$cmd" "$@"
        exit $?
    fi
    # Buffered: the report is captured so it can be counted and, for --json, converted.
    local out rc warns
    if [[ $JSON -eq 1 ]]; then out=$(run_command "$cmd" "$@"); rc=$?; else out=$(banner "$cmd"; run_command "$cmd" "$@"); rc=$?; fi
    warns=$(printf '%s\n' "$out" | grep -cE $'^ {0,2}(\033\\[[0-9;]*m)?WARN' || true)
    if [[ $rc -eq 2 ]]; then
        if [[ $JSON -eq 1 ]]; then printf '{"tool":"%s","version":"%s","command":"%s","exit":2,"error":"usage error, see stderr"}\n' "$SCRIPT_NAME" "$SCRIPT_VERSION" "$cmd"; fi
        exit 2
    fi
    [[ $STRICT -eq 1 && $warns -gt 0 && $rc -eq 0 ]] && rc=1
    if [[ $JSON -eq 1 ]]; then
        printf '%s\n' "$out" | to_json "$cmd" "$rc" "$STRICT"
    else
        printf '%s\n' "$out"
        [[ $STRICT -eq 1 ]] && info "strict: $warns $(pl "$warns" warning warnings) counted; exit status $rc."
    fi
    exit "$rc"
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
lock_for_change "harden tor" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
