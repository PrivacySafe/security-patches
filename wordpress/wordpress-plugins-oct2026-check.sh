#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# WordPress plugin checks, October 2026: LiteSpeed Cache, Rank Math PRO, OttoKit, SureCart,
# LatePoint, Amelia, Profile Builder, Bricksforge  (v6)
# CVE-2026-113500 (LiteSpeed Cache before 7.9.2, unauthenticated stored XSS)
# CVE-2026-111862 (Rank Math SEO PRO 3.0.123, supply-chain malware, CVSS 9.8)
# CVE-2026-110372 (OttoKit 1.1.40 and earlier, unauthenticated privilege escalation, CVSS 9.8)
# CVE-2026-112241 (SureCart 4.9.5 and earlier, authentication bypass by spoofing, CVSS 9.8)
# CVE-2026-110653 (LatePoint 5.7.4 and earlier, unauthenticated OTP authentication bypass, CVSS 9.1)
# CVE-2026-112327 (Amelia 2.4.11 and earlier, SQL injection, CVSS 9.3)
# CVE-2026-112242 (Profile Builder 4.0.4 and earlier, privilege escalation, CVSS 8.8)
# CVE-2026-85097 (Bricksforge 3.1.8.9 and earlier, unauthenticated file upload to code execution,
#                 CVSS 10.0, exploited since 7 October 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-113500  The LiteSpeed Cache plugin before 7.9.2 has an HTML
#                  optimization routine that is not limited to stylesheet
#                  content. It can delete the markup that closes an attribute in
#                  the rendered page. Combined with unescaped comment author
#                  output, an unauthenticated visitor whose comment is published
#                  can inject event-handler attributes that run JavaScript for
#                  any visitor, including a logged-in administrator.
#                  Fixed: 7.9.2.
# CVE-2026-111862  Some copies of Rank Math SEO PRO 3.0.123 contained malware.
#                  Per Rank Math, the affected copies were downloaded or
#                  updated between 15 October 2026 20:02 UTC and 16 October 2026
#                  07:12 UTC. The genuine 3.0.123 is dated 7 October. Rank Math
#                  removed the files and shipped 3.0.124. The free Rank Math SEO
#                  plugin from WordPress.org is not part of the incident. The
#                  malware reportedly does nothing until the plugin is activated,
#                  then contacts a command server, plants PHP backdoors that
#                  rebuild themselves, creates administrator accounts, adds cron
#                  jobs and can add SSH keys. Updating to 3.0.124 does not
#                  remove any of that. Treat an activated tainted copy as a
#                  full compromise.
# CVE-2026-110372  OttoKit (the plugin formerly called SureTriggers, folder
#                  suretriggers) up to and including 1.1.40 assigns privileges
#                  incorrectly, which lets an unauthenticated visitor escalate
#                  privileges (CWE-266), in practice to administrator. A Nuclei
#                  template for it exists and is tagged as known-exploited by
#                  VulnCheck's list; another tracker says no public proof of
#                  concept exists, so treat exploitation as plausible.
#                  Fixed: 1.1.41.
# CVE-2026-112241  SureCart (the e-commerce plugin from the same vendor, folder
#                  surecart) up to and including 4.9.5 has an authentication
#                  bypass by spoofing (CWE-290): an attacker can present identity
#                  markers that the plugin trusts and be treated as another user,
#                  with no valid credentials. CVSS 9.8. Patchstack rates it high
#                  priority and expects mass exploitation; we found no report of
#                  exploitation. SureCart has had a run of authentication and
#                  account-takeover fixes this autumn, so keep it current.
#                  Fixed: 4.9.6.
# CVE-2026-110653  LatePoint (appointment booking, folder latepoint) up to and
#                  including 5.7.4. The one-time-password check increments its
#                  attempts counter with a stale value and no conditional guard
#                  or row lock, so concurrent requests slip past the 10-attempt
#                  lockout and an unauthenticated visitor can brute-force the
#                  code and log in as a customer. CVSS 9.1. No exploitation has
#                  been reported. The advisory references the 5.7.5 code for the
#                  fixed helper, so 5.7.5 is the first fixed release; the advisory
#                  does not say "fixed in" in so many words.
# CVE-2026-112327  Amelia (booking, folder ameliabooking) up to and including
#                  2.4.11: SQL injection, CVSS 9.3 (a score that implies no
#                  privileges are needed; the advisory does not state the
#                  required role). Patchstack's solution: 2.4.12 or later.
# CVE-2026-112242  Profile Builder (user registration forms and profiles, folder
#                  profile-builder) up to and including 4.0.4: incorrect
#                  privilege assignment (CWE-266), CVSS 8.8. The score implies a
#                  low-privilege account is enough (privileges required: low), so a
#                  registered user may be able to gain a higher role, in the worst
#                  case administrator. Fixed: 4.0.5. Only the free plugin folder
#                  profile-builder is checked; the paid add-on ships separately.
#
# This script is read-only.
#
# CVE-2026-85097   Bricksforge (an add-on for the Bricks site builder, about 6,000 sites)
#                  up to and including 3.1.8.9 trusts file metadata that arrives with a
#                  form submission. An unauthenticated visitor gets a form nonce, uploads
#                  a file that passes the image type check but also holds PHP code, then
#                  submits the form naming a .php file, and the code runs. Patchstack saw
#                  the first attempts on 7 October 2026 at 21:47 UTC, before the advisory
#                  of 8 October, from 63 addresses within days. Attackers used the route
#                  /wp-json/bricksforge/v1/form_submit and filenames matching
#                  login_admin_*.php, sometimes placed straight in the uploads directories.
#                  Sites with Pro Forms active are affected even when no form has an upload
#                  field. CVSS 10.0 (9.8 in one report). Fixed: 3.1.8.10 for the 3.x line.
#                  The vendor changelog says 4.0.0 also has the fix; Patchstack names 4.0.1,
#                  so this script treats 4.0.0 as unconfirmed and 4.0.1 or later as fixed.
#
# Usage:
#   ./wordpress-plugins-oct2026-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /home /opt
#                    /usr/share/wordpress) for WordPress installs and report the
#                    version of LiteSpeed Cache, Rank Math PRO, OttoKit, SureCart, LatePoint,
#                    Amelia, Profile Builder and Bricksforge. For
#                    Rank Math PRO 3.0.123 it compares file change times with the
#                    incident window. Exit 0 = nothing affected, 1 = affected or
#                    to review.
#   hunt             search each WordPress install, and this server, for the
#                    published indicators of the Rank Math PRO malware, and for
#                    signs of OttoKit abuse (new administrator accounts and
#                    requests to its REST routes), for LatePoint OTP requests, and for
#                    Bricksforge upload attacks (login_admin_*.php files, PHP files in the
#                    uploads directories, requests to its form route). Exit 0 = none found,
#                    1 = at least one indicator found.
#   version          print the script version.
#
# The hunt reads database credentials from wp-config.php and runs two SELECT
# queries with the mysql client. It does not use wp-cli, because wp-cli would
# load the site's PHP, and a backdoor could run when it does. If the mysql
# client is missing, the queries are printed for you to run by hand.
#
# Indicators come from public reports of the incident (Rank Math, Wordfence and
# Patchstack, as relayed by several write-ups). A clean hunt does not prove a
# site is clean. If a tainted copy was activated, restore from a backup taken
# before 15 October 2026 20:02 UTC and rotate every credential the server held.
#
# Environment (for testing or unusual layouts):
#   HUNT_CRON_PATHS  default: /var/spool/cron /etc/cron.d /etc/crontab
#   HUNT_LOG_DIRS    default: /var/log
#   HUNT_SSH_DIRS    default: /root/.ssh /home
#   HUNT_WEB_LOGS    extra web server access log paths for the OttoKit request count
#   HUNT_ADMIN_SINCE default: 2026-10-01, administrators created since then are listed
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies only the Plugin Name and
# Version header lines of each covered plugin's main file, and its modification time, into a private
# temporary directory, and this script runs once per container in isolation against that copy. For
# Rank Math PRO 3.0.123 only the modification time is available inside a container, and the output
# says so. The hunt command does not look inside containers. Paths shown as .../docker_NAME/... are
# inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="wordpress-plugins-oct2026-check.sh"
SCRIPT_VERSION="6.0.0"
SCRIPT_DATE="2026-10-28"
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
have()    { command -v "$1" >/dev/null 2>&1; }

# Version helpers: strip a leading v and any -prerelease or +build suffix, then compare with
# sort -V. A pre-release of the boundary itself (6.3.0-rc2 against 6.3.0) is below it, as in
# semantic versioning, so a pre-release of a fixed release is never reported as the release.
norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
ver_ge() { ! ver_lt "$1" "$2"; }
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
DISTRO_PKG=""; DISTRO_HIT=""
distro_mentions() {
    local f real pkg="" cl="" c id
    f="$1"; shift
    real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if have dpkg; then
        pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] && cl+="$(zcat "$c" 2>/dev/null)"
            done
        fi
    fi
    if [[ -z "$pkg" ]] && have rpm; then
        pkg="$(rpm -qf "$real" 2>/dev/null | head -n1)"
        [[ "$pkg" == *"not owned"* ]] && pkg=""
        [[ -n "$pkg" ]] && cl="$(rpm -q --changelog "$pkg" 2>/dev/null)"
    fi
    [[ -n "$pkg" ]] || return 2
    DISTRO_PKG="$pkg"
    for id in "$@"; do
        if grep -qF "$id" <<<"$cl"; then DISTRO_HIT="$id"; return 0; fi
    done
    return 1
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- constants --------------------------------------------------------
WINDOW_START_UTC="2026-10-15 20:02:00"
WINDOW_END_UTC="2026-10-16 07:12:00"
OPTION_IOCS="_uf6qdn2hmm t8krdk990phb _np5pvf754c"

# ---------- helpers ----------------------------------------------------------
plugin_version() {   # plugin directory -> Version header of its main file
    local dir="$1" f v
    for f in "$dir"/*.php; do
        [[ -r "$f" ]] || continue
        head -n 60 "$f" | grep -iE 'Plugin Name:' >/dev/null || continue
        v="$(head -n 60 "$f" | grep -m1 -iE '^[[:space:]/*#@]*Version:' \
             | sed -E 's/^.*[Vv]ersion:[[:space:]]*([0-9][0-9A-Za-z._-]*).*$/\1/' | tr -d '\r')"
        [[ -n "$v" ]] && { echo "$v"; return; }
    done
    return 0
}

main_php() {         # plugin directory -> the file whose header holds Plugin Name
    local dir="$1" f
    for f in "$dir"/*.php; do
        [[ -r "$f" ]] || continue
        head -n 60 "$f" | grep -iE 'Plugin Name:' >/dev/null && { echo "$f"; return; }
    done
    return 0
}

fmt_time() { date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC'; }

# classify_arrival MTIME CTIME WINDOW_START WINDOW_END (all epoch seconds)
#   inside: either time falls in the incident window
#   before: both times are earlier than the window
#   after:  anything else (arrived later, or times were reset by a restore)
classify_arrival() {
    local mt="$1" ct="$2" ws="$3" we="$4"
    if (( (ct >= ws && ct <= we) || (mt >= ws && mt <= we) )); then echo inside
    elif (( ct < ws && mt < ws )); then echo before
    else echo after; fi
}

discover_wp() {      # directories -> WordPress roots (the parent of wp-content)
    find "$@" -maxdepth 7 -type d -path '*/wp-content/plugins' 2>/dev/null \
        | sed 's#/wp-content/plugins$##' | sort -u
}

default_dirs() { echo "/var/www /srv /home /opt /usr/share/wordpress"; }

# ---------- check ------------------------------------------------------------
check_rankmath() {   # plugin dir -> prints findings, returns 1 if affected or to review
    local dir="$1" ver mf mt ct ws we rc=0
    ver="$(plugin_version "$dir")"
    if [[ -z "$ver" ]]; then caution "Rank Math PRO folder found but no version header: ${dir}"; return 0; fi
    inf "Rank Math PRO ${ver} at ${dir}"
    if ver_lt "$ver" "3.0.123"; then
        ok "version ${ver} predates the tainted 3.0.123: update to 3.0.124 in the normal way"; return 0
    fi
    if ver_ge "$ver" "3.0.124"; then
        ok "version ${ver} is the clean replacement or newer"
        inf "if this site ever ran 3.0.123, run: $0 hunt   (an update does not remove what the malware left behind)"
        return 0
    fi
    # exactly 3.0.123: the version alone does not decide; the arrival time does
    mf="$(main_php "$dir")"
    mt="$(stat -c %Y "$mf" 2>/dev/null || echo 0)"
    ct="$(stat -c %Z "$mf" 2>/dev/null || echo 0)"
    # inside a container only the modification time is known: the inode change time of the copy is just
    # the moment it was copied, so it must not be used
    [[ -z "${PSF_CONTAINER_COPY:-}" ]] || { ct="$mt"; inf "read from a container: only the modification time is available"; }
    ws="$(date -u -d "$WINDOW_START_UTC" +%s)"; we="$(date -u -d "$WINDOW_END_UTC" +%s)"
    inf "main file modified $(fmt_time "$mt"), inode changed $(fmt_time "$ct")"
    inf "incident window: ${WINDOW_START_UTC} to ${WINDOW_END_UTC} UTC"
    case "$(classify_arrival "$mt" "$ct" "$ws" "$we")" in
        inside)
            bad "3.0.123 whose files changed INSIDE the incident window: this is likely the tainted package"
            rc=1 ;;
        before)
            ok "3.0.123 that arrived before the window opened: not the tainted package (confirm with Rank Math's notice)" ;;
        *)
            caution "3.0.123 that arrived after the window: Rank Math pulled the bad files, so this is probably clean, but restores and rsync change these times. Update to 3.0.124 and run the hunt."
            rc=1 ;;
    esac
    inf "file times are circumstantial: also check the plugin update history, your backup log and the email Rank Math sent to affected accounts"
    return "$rc"
}

# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   M <path> <epoch>  set the modification time of a staged file (a copy would otherwise carry the copy time)
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
# Paths the container reports are validated before use, a symlink is never kept (docker cp copies the
# link itself, and the check would then read whatever it points to on the host), and the number of
# copied files is capped. It runs once, in the main shell (a subshell's exit would delete the copies).
STAGE=""
declare -a STAGED_DIRS=()
stage_probe() {   # <probe script, run with sh -s inside each running container>
    local probe="$1" rt id name out kind p rest s nf
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        command -v "$rt" >/dev/null 2>&1 || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            out="$(printf '%s\n' "$probe" | "$rt" exec -i "$id" sh -s 2>/dev/null | head -n 6000)" || continue
            [[ -n "$out" ]] || continue
            s=""; nf=0
            while read -r kind p rest; do
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
                if [[ -z "$s" ]]; then
                    if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; trap 'rm -rf "${STAGE:-}"' EXIT; fi
                    s="$STAGE/${rt}_${name:-$id}"; mkdir -p "$s"
                fi
                case "$kind" in
                    F) nf=$((nf + 1)); [[ $nf -le 400 ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       "$rt" cp "${id}:${p}" "$s$p" >/dev/null 2>&1 || rm -f "$s$p"
                       [[ -L "$s$p" ]] && rm -f "$s$p" ;;
                    D) mkdir -p "$s$p" ;;
                    E) mkdir -p "$s$(dirname "$p")"; : > "$s$p" ;;
                    L) [[ "$rest" =~ ^[A-Za-z0-9_=.,:/@-]{0,120}$ ]] || continue
                       mkdir -p "$s$(dirname "$p")"; printf '%s\n' "$rest" > "$s$p" ;;
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                    M) [[ "$rest" =~ ^[0-9]{1,12}$ && -e "$s$p" ]] && touch -d "@$rest" "$s$p" 2>/dev/null ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

WPPLUGINS_PROBE="$(cat <<'EOS'
find /var/www /srv /home /opt /usr/share/wordpress -xdev -maxdepth 7 -type d -path "*/wp-content/plugins" 2>/dev/null | head -n 40 | while read -r pd; do
  echo "D $pd"
  for slug in ameliabooking latepoint litespeed-cache profile-builder surecart suretriggers seo-by-rank-math-pro rank-math-pro; do
    [ -d "$pd/$slug" ] || continue
    echo "D $pd/$slug"
    for f in "$pd/$slug"/*.php; do
      [ -f "$f" ] || continue
      head -n 60 "$f" | grep -qiE "Plugin Name:" || continue
      echo "B $f $(head -n 60 "$f" | grep -iE "Plugin Name:|^[[:space:]/*#@]*Version:" | base64 | tr -d '\n')"
      echo "M $f $(stat -c %Y "$f" 2>/dev/null || echo 0)"
    done
  done
done
exit 0
EOS
)"

container_run() {   # <staged directory> : the WordPress plugins in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "WordPress plugins in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 PSF_CONTAINER_COPY=1 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$WPPLUGINS_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a dirs=() roots=()
    local rc=0 found=0 root p ver have_rm=0 bfd bff
    if [[ $# -gt 0 ]]; then dirs=("$@"); else read -r -a dirs <<<"$(default_dirs)"; fi
    local -a existing=()
    for p in "${dirs[@]}"; do [[ -d "$p" ]] && existing+=("$p"); done
    step "Looking for WordPress installs"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(discover_wp "${existing[@]}")
    if [[ ${#roots[@]} -eq 0 ]]; then info "No WordPress install found under: ${existing[*]}"; return 0; fi
    for root in "${roots[@]}"; do
        found=$((found+1))
        step "WordPress at ${root}"
        local plug="${root}/wp-content/plugins" seen=0
        if [[ -d "${plug}/litespeed-cache" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/litespeed-cache")"
            if [[ -z "$ver" ]]; then caution "LiteSpeed Cache: no version header found"
            elif ver_lt "$ver" "7.9.2"; then
                bad "LiteSpeed Cache ${ver} is affected by CVE-2026-113500 (fixed in 7.9.2)"
                inf "exposure needs the HTML optimization feature on and comments from unauthenticated visitors being published"
                inf "interim, derived from the description and not vendor documented: hold every comment for moderation (Settings > Discussion) until you update"
                rc=1
            else ok "LiteSpeed Cache ${ver} has the fix (7.9.2 or newer)"; fi
        fi
        if [[ -d "${plug}/suretriggers" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/suretriggers")"
            if [[ -z "$ver" ]]; then caution "OttoKit (suretriggers): no version header found"
            elif ver_lt "$ver" "1.1.41"; then
                bad "OttoKit ${ver} is affected by CVE-2026-110372 (fixed in 1.1.41): unauthenticated privilege escalation"
                inf "attackers use this to create administrator accounts: after updating, run: $0 hunt   and review every administrator"
                inf "if you cannot update today, deactivate the plugin: an inactive plugin registers no routes"
                rc=1
            else
                ok "OttoKit ${ver} has the fix (1.1.41 or newer)"
                inf "if this site ran 1.1.40 or earlier in October, run: $0 hunt   (an update does not remove accounts already created)"
            fi
        fi
        if [[ -d "${plug}/surecart" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/surecart")"
            if [[ -z "$ver" ]]; then caution "SureCart: no version header found"
            elif ver_lt "$ver" "4.9.6"; then
                bad "SureCart ${ver} is affected by CVE-2026-112241 (fixed in 4.9.6): authentication bypass by spoofing"
                inf "an attacker can be treated as another user without credentials: after updating, reset administrator passwords and end all sessions (change the AUTH_KEY and SECURE_AUTH_KEY salts in wp-config.php), then run: $0 hunt"
                inf "if you cannot update today, deactivate the plugin: an inactive plugin registers no routes"
                rc=1
            else
                ok "SureCart ${ver} has the fix (4.9.6 or newer)"
                inf "if this site ran 4.9.5 or earlier in October, run: $0 hunt   (an update does not undo account takeovers)"
            fi
        fi
        if [[ -d "${plug}/latepoint" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/latepoint")"
            if [[ -z "$ver" ]]; then caution "LatePoint: no version header found"
            elif ver_lt "$ver" "5.7.5"; then
                bad "LatePoint ${ver} is affected by CVE-2026-110653 (fixed in 5.7.5): unauthenticated OTP authentication bypass"
                inf "an attacker can brute-force the one-time code and log in as a customer: after updating, review recent customer logins and bookings"
                inf "if you cannot update today, deactivate the plugin: an inactive plugin registers no routes"
                rc=1
            else
                ok "LatePoint ${ver} has the fix (5.7.5 or newer)"
            fi
        fi
        if [[ -d "${plug}/ameliabooking" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/ameliabooking")"
            if [[ -z "$ver" ]]; then caution "Amelia: no version header found"
            elif ver_lt "$ver" "2.4.12"; then
                bad "Amelia ${ver} is affected by CVE-2026-112327 (fixed in 2.4.12): SQL injection"
                inf "an SQL injection can expose the whole database, including user password hashes: after updating, rotate administrator passwords and the keys and salts in wp-config.php, then run: $0 hunt"
                inf "if you cannot update today, deactivate the plugin: an inactive plugin registers no routes"
                rc=1
            else
                ok "Amelia ${ver} has the fix (2.4.12 or newer)"
            fi
        fi
        if [[ -d "${plug}/profile-builder" ]]; then
            seen=1
            ver="$(plugin_version "${plug}/profile-builder")"
            if [[ -z "$ver" ]]; then caution "Profile Builder: no version header found"
            elif ver_lt "$ver" "4.0.5"; then
                bad "Profile Builder ${ver} is affected by CVE-2026-112242 (fixed in 4.0.5): privilege escalation by a low-privilege account"
                inf "a registered user may be able to gain a higher role: after updating, review administrator and editor accounts with: $0 hunt"
                inf "if you cannot update today, deactivate the plugin and close public registration: an inactive plugin registers no routes"
                rc=1
            else
                ok "Profile Builder ${ver} has the fix (4.0.5 or newer)"
            fi
        fi
        # Bricksforge: found by the Plugin Name in its main file, whatever its folder is called
        for bfd in "${plug}"/*/; do
            [[ -d "$bfd" ]] || continue
            bff="$(main_php "${bfd%/}")"; [[ -n "$bff" ]] || continue
            head -n 60 "$bff" | grep -iE 'Plugin Name:[[:space:]]*Bricksforge' >/dev/null || continue
            seen=1
            ver="$(plugin_version "${bfd%/}")"
            if [[ -z "$ver" ]]; then caution "Bricksforge: no version header found (affected is 3.1.8.9 and earlier, fixed is 3.1.8.10 or 4.0.1)"; rc=1
            elif ver_lt "$ver" "3.1.8.10"; then
                bad "Bricksforge ${ver} is affected by CVE-2026-85097 (fixed in 3.1.8.10 for 3.x, and in 4.0.1): unauthenticated file upload that runs PHP, exploited since 7 October 2026"
                inf "an attacker uploads a PHP file disguised as an image, then submits a form that names it: after updating, run: $0 hunt   and treat the site as possibly compromised if it was reachable"
                inf "if you cannot update today, deactivate Pro Forms or the whole plugin (the mitigation reported by Patchstack); an inactive plugin registers no routes"
                rc=1
            elif ver_lt "$ver" "4.0.0"; then ok "Bricksforge ${ver} has the fix for the 3.x line (3.1.8.10 or newer)"
            elif ver_lt "$ver" "4.0.1"; then
                caution "Bricksforge ${ver}: the vendor changelog says 4.0.0 has the fix, Patchstack names 4.0.1. Update to 4.0.1 or later to be sure"; rc=1
            else ok "Bricksforge ${ver} has the fix (4.0.1 or newer)"; fi
        done
        for p in seo-by-rank-math-pro rank-math-pro; do
            if [[ -d "${plug}/${p}" ]]; then
                seen=1; have_rm=1
                check_rankmath "${plug}/${p}" || rc=1
            fi
        done
        [[ $seen -eq 0 ]] && inf "none of LiteSpeed Cache, Rank Math PRO, OttoKit, SureCart, LatePoint, Amelia, Profile Builder or Bricksforge is installed here"
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No affected plugin found (${found} WordPress install(s) checked)"
    else
        warn "Affected or unverified plugin found."
        inf "LiteSpeed Cache: update to 7.9.2 or later."
        inf "OttoKit: update to 1.1.41 or later."
        inf "SureCart: update to 4.9.6 or later."
        inf "LatePoint: update to 5.7.5 or later."
        inf "Amelia: update to 2.4.12 or later."
        inf "Profile Builder: update to 4.0.5 or later."
        inf "Bricksforge: update to 3.1.8.10 (3.x) or 4.0.1 or later, then run: $0 hunt"
        inf "Rank Math PRO: see the vendor notice https://rankmath.com/kb/pro-3-0-123-security-incident/ and run: $0 hunt"
    fi
    [[ $have_rm -eq 1 ]] && inf "Rank Math PRO is present: the hunt is quick, run it even when the check above is clean"
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
wp_define() {        # wp-config.php NAME -> string value
    sed -nE "s/^[[:space:]]*define\([[:space:]]*['\"]$2['\"][[:space:]]*,[[:space:]]*['\"]([^'\"]*)['\"].*/\1/p" "$1" | head -n1
}
wp_prefix() {
    sed -nE "s/^[[:space:]]*\\\$table_prefix[[:space:]]*=[[:space:]]*['\"]([^'\"]*)['\"].*/\1/p" "$1" | head -n1
}

db_query() {         # wp-config.php, SQL -> rows on stdout, return 1 if the query could not run
    local cfg="$1" sql="$2" host user pass name port="" sock="" h
    host="$(wp_define "$cfg" DB_HOST)"; user="$(wp_define "$cfg" DB_USER)"
    pass="$(wp_define "$cfg" DB_PASSWORD)"; name="$(wp_define "$cfg" DB_NAME)"
    [[ -n "$user" && -n "$name" ]] || return 1
    have mysql || return 1
    h="${host:-localhost}"
    if [[ "$h" == *:/* ]]; then sock="${h#*:}"; h="${h%%:*}"
    elif [[ "$h" == *:* ]]; then port="${h#*:}"; h="${h%%:*}"; fi
    MYSQL_PWD="$pass" mysql --batch --skip-column-names -h "$h" ${port:+-P "$port"} ${sock:+-S "$sock"} \
        -u "$user" "$name" -e "$sql" 2>/dev/null
}

hunt_site() {        # WordPress root -> returns 1 if any indicator was found
    local root="$1" rc=0 cfg p out f n sql1 sql2 qok
    step "Indicators in WordPress at ${root}"

    if [[ -e "${root}/wp-includes/class-wp-cache-util.php" ]]; then
        bad "wp-includes/class-wp-cache-util.php exists (not a real WordPress file)"; rc=1
    else ok "no wp-includes/class-wp-cache-util.php"; fi

    out="$(find "$root" -xdev -name '*.cache' -type f -size -5M 2>/dev/null | while read -r f; do grep -lI '<?php' "$f" 2>/dev/null; done | head -n10)"
    if [[ -n "$out" ]]; then bad ".cache files that contain PHP:"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no .cache file contains PHP"; fi

    out="$(find "$root" -xdev -name .htaccess -type f 2>/dev/null | while read -r f; do
              awk -v F="$f" '/\.cache/ && /[Pp][Hh][Pp]|[Hh]andler/ {print F ": " $0}' "$f"; done | head -n10)"
    if [[ -n "$out" ]]; then bad ".htaccess rules that mention .cache together with PHP or a handler:"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no .htaccess rule lets .cache files run as PHP"; fi

    out="$(grep -rIl --include='*.php' --include='*.cache' -e 'xmmqhn' -e 'rank1cdn' \
             "${root}/wp-content" "${root}/wp-includes" 2>/dev/null | head -n10)"
    if [[ -n "$out" ]]; then bad "files containing the key xmmqhn or the domain rank1cdn:"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no file contains the key xmmqhn or the command server name"; fi

    out="$(find "${root}/wp-content/mu-plugins" -maxdepth 2 -name '*.php' -type f 2>/dev/null | head -n10)"
    if [[ -n "$out" ]]; then caution "PHP in wp-content/mu-plugins (review each, mu-plugins load without being activated):"; sed 's/^/        /' <<<"$out"
    else ok "no PHP in wp-content/mu-plugins"; fi
    out="$(find "${root}/wp-content/uploads" -name '*.php' -type f 2>/dev/null | head -n10)"
    if [[ -n "$out" ]]; then caution "PHP files under wp-content/uploads (normally none):"; sed 's/^/        /' <<<"$out"
    else ok "no PHP under wp-content/uploads"; fi

    cfg="${root}/wp-config.php"; [[ -r "$cfg" ]] || cfg="$(dirname "$root")/wp-config.php"
    p="wp_"
    if [[ -r "$cfg" ]]; then p="$(wp_prefix "$cfg")"; p="${p:-wp_}"; fi
    sql1="SELECT option_name FROM ${p}options WHERE option_name IN ('_uf6qdn2hmm','t8krdk990phb','_np5pvf754c');"
    sql2="SELECT user_login, user_email FROM ${p}users WHERE user_login LIKE 'wpsupport\\_%' OR user_email LIKE '%@wp-mail.net';"
    sql3="SELECT u.user_login, u.user_email, u.user_registered FROM ${p}users u JOIN ${p}usermeta m ON m.user_id=u.ID WHERE m.meta_key='${p}capabilities' AND m.meta_value LIKE '%administrator%' AND u.user_registered >= '${HUNT_ADMIN_SINCE:-2026-10-01}' ORDER BY u.user_registered;"
    qok=0
    if [[ -r "$cfg" ]]; then
        if out="$(db_query "$cfg" "$sql1")"; then
            qok=1
            if [[ -n "$out" ]]; then bad "wp_options rows from the malware are present:"; sed 's/^/        /' <<<"$out"; rc=1
            else ok "none of the three indicator rows is in ${p}options"; fi
            out="$(db_query "$cfg" "$sql2")"
            if [[ -n "$out" ]]; then bad "rogue accounts (wpsupport_ names or @wp-mail.net addresses):"; sed 's/^/        /' <<<"$out"; rc=1
            else ok "no wpsupport_ account and no @wp-mail.net address"; fi
            out="$(db_query "$cfg" "$sql3")"
            if [[ -n "$out" ]]; then
                caution "administrator accounts created since ${HUNT_ADMIN_SINCE:-2026-10-01} (confirm each one is yours; OttoKit abuse creates administrators):"
                sed 's/^/        /' <<<"$out"
                rc=1
            else ok "no administrator account was created since ${HUNT_ADMIN_SINCE:-2026-10-01}"; fi
        fi
    fi
    if [[ $qok -eq 0 ]]; then
        caution "database not checked (no readable wp-config.php, no mysql client, or login failed). Run these by hand:"
        inf "$sql1"
        inf "$sql2"
        inf "$sql3"
    fi

    # Bricksforge CVE-2026-85097: the attack leaves a PHP file in the uploads tree, sometimes named
    # login_admin_*.php. WordPress uploads should hold no PHP apart from the empty index.php stubs
    # some plugins write, which are not counted.
    out="$(find "${root}/wp-content" -xdev -type f -name 'login_admin_*.php' 2>/dev/null | head -n10)"
    if [[ -n "$out" ]]; then bad "files named login_admin_*.php (the name used in the Bricksforge attacks):"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no login_admin_*.php file under wp-content"; fi
    out="$(find "${root}/wp-content/uploads" -xdev -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.phar' \) ! -name 'index.php' 2>/dev/null | head -n10)"
    if [[ -n "$out" ]]; then bad "PHP files in the uploads directories (WordPress uploads should hold none):"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no PHP file in wp-content/uploads"; fi
    return "$rc"
}

hunt_server() {      # checks that are not tied to one WordPress root
    local rc=0 out f dir
    local cron_paths="${HUNT_CRON_PATHS:-/var/spool/cron /etc/cron.d /etc/crontab}"
    local log_dirs="${HUNT_LOG_DIRS:-/var/log}"
    local ssh_dirs="${HUNT_SSH_DIRS:-/root/.ssh /home}"
    step "Indicators on this server"

    out=""
    for f in $cron_paths; do [[ -e "$f" ]] && out+="$(grep -rsH 'ms6v46' "$f" 2>/dev/null)"$'\n'; done
    out="$(sed '/^$/d' <<<"$out")"
    if [[ -n "$out" ]]; then bad "cron entries tagged #ms6v46:"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no cron entry tagged ms6v46 in the readable crontabs"; fi

    out=""
    for dir in $log_dirs; do
        [[ -d "$dir" ]] && out+="$(grep -rIl --exclude='*.gz' --exclude='*.xz' -e 'rank1cdn' "$dir" 2>/dev/null | head -n10)"$'\n'
    done
    out="$(sed '/^$/d' <<<"$out")"
    if [[ -n "$out" ]]; then bad "log files that mention the command server rank1cdn:"; sed 's/^/        /' <<<"$out"; rc=1
    else ok "no readable log mentions rank1cdn"; fi

    # OttoKit: requests to its REST namespace. OttoKit's own cloud also calls this
    # namespace, so a count alone is not an alarm; unfamiliar source addresses are the lead.
    local -a wl=()
    shopt -s nullglob
    for f in /var/log/apache2/*access*.log /var/log/nginx/*access*.log /var/log/httpd/*access*log \
             /var/log/apache2/other_vhosts_access.log ${HUNT_WEB_LOGS:-}; do
        [[ -r "$f" && -f "$f" ]] && wl+=("$f")
    done
    shopt -u nullglob
    if [[ ${#wl[@]} -gt 0 ]]; then
        out="$(grep -hE 'sure-triggers' "${wl[@]}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -n5)"
        if [[ -n "$out" ]]; then
            caution "requests to OttoKit's REST routes (count and source address; confirm the addresses are OttoKit's service or yours):"
            sed 's/^/        /' <<<"$out"
        else ok "no request to OttoKit's REST routes in the readable web logs"; fi
        out="$(grep -hE 'auth__verify_otp' "${wl[@]}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -n5)"
        if [[ -n "$out" ]]; then
            caution "requests naming LatePoint's OTP route auth__verify_otp (count and source address). Many from one address is a brute-force lead. POST bodies are not normally logged, so a POST-only attack may not show here:"
            sed 's/^/        /' <<<"$out"
        else ok "no request naming LatePoint's OTP route in the readable web logs"; fi
        out="$(grep -hE 'bricksforge/v1/form_submit|bricksforge%2[Ff]v1%2[Ff]form_submit' "${wl[@]}" 2>/dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -n5)"
        if [[ -n "$out" ]]; then
            caution "requests to Bricksforge's form route (count and source address). Real visitors use this route too, so look for addresses you do not know and for many requests from one address. POST bodies are not normally logged:"
            sed 's/^/        /' <<<"$out"
        else ok "no request to Bricksforge's form route in the readable web logs"; fi
    else
        inf "no readable web access logs, so OttoKit REST requests were not counted"
    fi

    out=""
    for dir in $ssh_dirs; do
        [[ -d "$dir" ]] && out+="$(find "$dir" -maxdepth 3 -name 'authorized_keys*' -type f -newermt '2026-10-15 00:00:00' 2>/dev/null)"$'\n'
    done
    out="$(sed '/^$/d' <<<"$out")"
    if [[ -n "$out" ]]; then caution "authorized_keys files changed since 15 October 2026 (confirm every key is yours):"; sed 's/^/        /' <<<"$out"
    else ok "no authorized_keys file changed since 15 October 2026"; fi
    return "$rc"
}

cmd_hunt() {
    local -a dirs=() roots=() existing=()
    local rc=0 p root
    if [[ $# -gt 0 ]]; then dirs=("$@"); else read -r -a dirs <<<"$(default_dirs)"; fi
    for p in "${dirs[@]}"; do [[ -d "$p" ]] && existing+=("$p"); done
    step "Hunting for the Rank Math PRO 3.0.123 malware, OttoKit abuse and Bricksforge uploads"
    if [[ ${#existing[@]} -gt 0 ]]; then
        while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(discover_wp "${existing[@]}")
    fi
    if [[ ${#roots[@]} -eq 0 ]]; then inf "no WordPress install found under: ${dirs[*]}"; fi
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        hunt_site "$root" || rc=1
    done
    hunt_server || rc=1
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "No indicator of the Rank Math PRO malware or of OttoKit abuse found"
        inf "A clean result is not proof: the malware can rebuild or hide, and the published indicator list may be incomplete."
    else
        warn "Indicators found. Treat the server as compromised:"
        inf "  1. delete the whole plugin folder first (deactivating does not stop it), then the database rows"
        inf "  2. block outgoing traffic to rank1cdn[.]com"
        inf "  3. restore files and database from a backup taken before 15 October 2026 20:02 UTC"
        inf "  4. rotate WordPress, database, API, payment, SMTP, hosting and SSH credentials"
        inf "  5. only then install Rank Math PRO 3.0.124, downloaded by typing rankmath.com yourself"
        inf "For OttoKit: update to 1.1.41, remove administrators you did not create, rotate those users' passwords and the site's salts."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-113500, -111862, -110372, -112241, -110653, -112327, -112242, -85097; fixed in LiteSpeed 7.9.2, Rank Math PRO 3.0.124, OttoKit 1.1.41, SureCart 4.9.6, LatePoint 5.7.5, Amelia 2.4.12, Profile Builder 4.0.5, Bricksforge 3.1.8.10 or 4.0.1"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
