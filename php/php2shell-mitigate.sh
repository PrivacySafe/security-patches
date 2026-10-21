#!/usr/bin/env bash
# =============================================================================
# PHP2Shell interim mitigation - PHP-FPM 7.0 through 8.5  (v4)
# CVE-2026-109618 / CVE-2026-109619
#
# If this script is helpful please donate to PrivacySafe Foundation: 
# https://privacysafe.foundation
#
# This script was released ahead of patches for two 0day vulns in php.
#
# Usage (as root):
#   ./php2shell-mitigate.sh [command] [--php X.Y] [--force] [--ignore-env]
#
#   check            environment report only; changes nothing, root optional
#                    (exit 0 = ok, 1 = hard blocker, 2 = needs --ignore-env)
#   apply (default)  drop-in + AppArmor profile, safe-load, per FPM version
#   enforce          switch profile(s) to enforce; refuses if complain mode
#                    logged unhandled accesses (override with --force)
#   complain         switch profile(s) back to complain
#   status           mitigation state and recent AppArmor events
#   hunt             read-only: scan logs for signs of exploitation or the
#                    memory-corruption crashes these bugs cause. Changes
#                    nothing, root optional. Exit 0 = clean, 1 = findings.
#   cleanup          remove the ini drop-in once patched (--force to skip check)
#   remove           remove the AppArmor profile entirely: unload it, delete
#                    the profile, local override and disable symlink, verify.
#                    Leaves the ini drop-in (that's cleanup). No patch needed.
#
#   --php X.Y        act on one version only (default: every installed
#                    version in SUPPORTED_VERS)
#   --ignore-env     proceed past soft environment blockers (live unpatched
#                    mod_php, live sites only on skipped versions). Hard
#                    blockers (non-Debian, no service manager, no AppArmor,
#                    not root, no supported FPM) can't be overridden.
#
# Every command first checks, in order: OS (Debian, Ubuntu, Trisquel and
# popular derivatives), PHP-FPM versions and their package source, web
# servers (Apache/nginx and what PHP they use), then system (root, init
# system, container, AppArmor, tools). It reports, then refuses to start only
# if it can't work safely. Derivatives and non-systemd init (sysvinit/OpenRC)
# are supported. Each version's patch state is reported from three signals:
# upstream version, known distro backport builds, and the package changelog.
#
# Env overrides:
#   SUPPORTED_VERS="7.0 ... 8.5"       versions this script will touch
#   FIXED_BUILDS="7.4.33-1+deb11u9"    extra fixed distro builds (backports)
#   PATCHED_X_Y=<version>              first fixed upstream release for branch
#                                      X.Y, e.g. PATCHED_8_4=8.4.27. Defaults:
#                                      8.2.35 8.3.36 8.4.27 8.5.12 (21 Oct 2026).
#                                      7.0-8.1 get no upstream fix: only a
#                                      distro/PPA changelog listing both CVEs
#                                      counts as patched.
#   WEB_ROOTS="/var/www /srv/www"      read-only docroots
#   WRITABLE_PATHS="..."               rwk paths (uploads, cache)
#
# Debian/Ubuntu/Trisquel layout (distro packages, ondrej/sury PPA). Each version gets
# its own drop-in, profile, local override and backups; a failure on one
# version doesn't stop the others.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
SUPPORTED_VERS="${SUPPORTED_VERS:-7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5}"
CVES=(CVE-2026-109618 CVE-2026-109619)
# Upstream fixed releases, 21 Oct 2026. Override per branch with PATCHED_X_Y.
declare -A PATCHED_DEFAULT=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
patched_ver() { local n="PATCHED_${1/./_}"; echo "${!n:-${PATCHED_DEFAULT[$1]:-}}"; }
# Branches PHP no longer fixes; only a distro or PPA backport can patch them
EOL_VERS="7.0 7.1 7.2 7.3 7.4 8.0 8.1"
# Distro builds that carry the fix without changing the upstream version.
# Ubuntu USN-8948-1/-2 (21 Oct 2026). Debian (DSA-6574-1) and sury ship the new
# upstream release instead, which the PATCHED_DEFAULT check already covers.
declare -A BACKPORT_FIXED=(
    [7.0]="7.0.33-0ubuntu0.16.04.16+esm22"
    [7.2]="7.2.24-0ubuntu0.18.04.17+esm14"
    [7.4]="7.4.3-4ubuntu2.29+esm5"
    [8.1]="8.1.2-1ubuntu2.28"
    [8.3]="8.3.6-0ubuntu0.24.04.13"
    [8.5]="8.5.4-0ubuntu1.5 8.5.9-0ubuntu2.1"
)
# Add fixed builds as they're published, e.g. a Debian LTS/ELTS 7.4 update
FIXED_BUILDS="${FIXED_BUILDS:-}"
MARKER="# managed-by: php2shell-mitigation"
BACKUP_ROOT="/var/backups/php2shell/$(date +%Y%m%d-%H%M%S)"
WEB_ROOTS="${WEB_ROOTS:-/var/www /srv/www}"
WRITABLE_PATHS="${WRITABLE_PATHS:-}"
START_TS="$(date '+%Y-%m-%d %H:%M:%S')"
SELF="$0"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
step()  { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()   { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }

# ---------- service manager --------------------------------------------------
# systemd when it's PID 1; otherwise service(8) + init scripts (sysvinit or
# OpenRC, as on Devuan, MX and antiX). Debian's php-fpm init scripts support
# status, restart and reload.
have_systemd() { [[ -d /run/systemd/system ]]; }
svc_active() {
    if have_systemd; then systemctl is-active --quiet "$1" 2>/dev/null
    else service "$1" status >/dev/null 2>&1; fi
}
svc_enabled() {
    if have_systemd; then systemctl is-enabled --quiet "$1" 2>/dev/null; return; fi
    if command -v rc-update >/dev/null; then rc-update show 2>/dev/null | grep -qE "^[[:space:]]*$1[[:space:]]"; return; fi
    compgen -G "/etc/rc[2-5].d/S*$1" >/dev/null
}
svc_do() {   # restart|reload <service>
    if have_systemd; then systemctl "$1" "$2"; else service "$2" "$1"; fi
}
svc_hint() { if have_systemd; then echo "systemctl $1 $2"; else echo "service $2 $1"; fi; }

# ---------- per-version context ----------------------------------------------
set_ver() {
    PHP_VER="$1"
    FPM_BIN="/usr/sbin/php-fpm${PHP_VER}"
    FPM_ETC="/etc/php/${PHP_VER}/fpm"
    FPM_INI_DIR="${FPM_ETC}/conf.d"
    FPM_SERVICE="php${PHP_VER}-fpm"
    AA_NAME="usr.sbin.php-fpm${PHP_VER}"
    AA_PROFILE="/etc/apparmor.d/${AA_NAME}"
    AA_LOCAL="/etc/apparmor.d/local/${AA_NAME}"
    AA_DISABLE="/etc/apparmor.d/disable/${AA_NAME}"
    DROP_IN_CONF="${FPM_INI_DIR}/99-php2shell-mitigation.ini"
    BACKUP_DIR="${BACKUP_ROOT}/${PHP_VER}"
    PATCHED_VER="$(patched_ver "$PHP_VER")"
    # Fallback only (real value comes from FPM -i): the API dir the package ships
    DEFAULT_EXT_DIR="$(dpkg -L "php${PHP_VER}-common" 2>/dev/null | grep -m1 -E '^/usr/lib/php/[0-9]{8}$' || true)"
    HINT="--php ${PHP_VER}"
    FPM_INFO=""
    # Don't start services the admin had stopped; test config only
    if svc_active "$FPM_SERVICE" || svc_enabled "$FPM_SERVICE"; then
        SVC_LIVE=1
    else
        SVC_LIVE=0
    fi
}

detect_versions() {
    local b v
    shopt -s nullglob
    for b in /usr/sbin/php-fpm[0-9]*; do
        v="${b#/usr/sbin/php-fpm}"
        [[ -x "$b" && "$v" =~ ^[0-9]+\.[0-9]+$ ]] || continue
        # unsupported versions were already reported by env_check
        [[ " $SUPPORTED_VERS " != *" $v "* ]] || echo "$v"
    done | sort -V
    shopt -u nullglob
}

# ---------- helpers ----------------------------------------------------------
backup() {
    mkdir -p "$BACKUP_DIR"
    cp -a "$1" "$BACKUP_DIR/"
    info "Backed up $1 -> $BACKUP_DIR/"
}

refresh_info() { FPM_INFO="$("$FPM_BIN" -i 2>/dev/null || true)"; }

ini_val() { awk -F' => ' -v k="$1" '$1==k {print $2; exit}' <<<"$FPM_INFO"; }

ini_path() {   # absolute path or fallback; strips "N;MODE;" prefixes
    local v; v="$(ini_val "$1")"; v="${v##*;}"
    if [[ "$v" == /* ]]; then echo "${v%/}"; else echo "$2"; fi
}

collect_log_paths() {
    {
        grep -hE '^[[:space:]]*(error_log|slowlog|access\.log|php_(admin_)?value\[error_log\])[[:space:]]*=' \
            "${FPM_ETC}/php-fpm.conf" "${FPM_ETC}"/pool.d/*.conf 2>/dev/null \
          | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*;.*$//; s/^"(.*)"$/\1/; s/\$pool/*/g' || true
        ini_val error_log
    } | grep '^/' | sort -u || true
}

listen_sockets() {
    grep -hE '^[[:space:]]*listen[[:space:]]*=' "${FPM_ETC}"/pool.d/*.conf 2>/dev/null \
      | sed -E 's/^[^=]*=[[:space:]]*//; s/[[:space:]]*;.*$//' | grep '^/' || true
}

# systemd's count of automatic restarts. Units with Restart=on-failure (the
# PHP 8.4+ packaging) can look active between crashes, so health also
# requires this not to grow while we watch.
nrestarts() { have_systemd && systemctl show -p NRestarts --value "$1" 2>/dev/null || echo 0; }

# Config test always; restart + reload (SIGUSR2 self re-exec) only for live services
fpm_health() {
    "$FPM_BIN" -t >/dev/null 2>&1 || return 1
    if [[ $SVC_LIVE -eq 0 ]]; then
        warn "$FPM_SERVICE is stopped and disabled - config tested only, not started"
        return 0
    fi
    local n0 n1
    svc_do restart "$FPM_SERVICE" >/dev/null 2>&1 || return 1
    n0="$(nrestarts "$FPM_SERVICE")"
    sleep 2; svc_active "$FPM_SERVICE" || return 1
    svc_do reload "$FPM_SERVICE" >/dev/null 2>&1 || return 1
    sleep 2; svc_active "$FPM_SERVICE" || return 1
    n1="$(nrestarts "$FPM_SERVICE")"
    if [[ "${n1:-0}" -gt "${n0:-0}" ]]; then
        warn "$FPM_SERVICE restarted itself $(( n1 - n0 )) time(s) during the check (crash loop under Restart=on-failure)"
        return 1
    fi
    local s
    for s in $(listen_sockets); do
        [[ -S "$s" ]] || { warn "Listen socket missing: $s"; return 1; }
    done
}

# Accepts "YYYY-mm-dd HH:MM:SS" or "-24h"
aa_since_epoch() { if [[ "$1" == -24h ]]; then echo $(( $(date +%s) - 86400 )); else date -d "$1" +%s; fi; }

# AppArmor records reach different places: the journal (kernel or audit
# transport), auditd's audit.log when auditd runs, or syslog's kern.log on
# systems without systemd. Read all of them; dedupe on the audit(epoch:serial) id.
aa_raw() {
    local since="$1" f
    if have_systemd && command -v journalctl >/dev/null; then
        journalctl -k --since "@${since}" --no-pager 2>/dev/null | grep -F 'apparmor="' || true
        journalctl _TRANSPORT=audit --since "@${since}" --no-pager 2>/dev/null | grep -F 'apparmor="' || true
    fi
    for f in /var/log/audit/audit.log /var/log/kern.log /var/log/kern.log.1 /var/log/syslog; do
        [[ -r "$f" ]] && { grep -hF 'apparmor="' "$f" 2>/dev/null || true; }
    done
    dmesg 2>/dev/null | grep -F 'apparmor="' || true
}

aa_events() {
    local since; since="$(aa_since_epoch "$1")"
    aa_raw "$since" \
      | grep -E 'apparmor="(DENIED|ALLOWED|AUDIT)"' \
      | grep -F "profile=\"${FPM_BIN}\"" \
      | awk -v s="$since" 'match($0, /audit\([0-9]+\.[0-9]+:[0-9]+\)/) {
            id = substr($0, RSTART + 6, RLENGTH - 7); split(id, t, ".")
            if (t[1] + 0 >= s && !seen[id]++) print }' || true
}

aa_event_summary() {
    aa_events "$1" \
      | sed -nE 's/.*apparmor="([A-Z]+)".*operation="([^"]+)".*name="([^"]+)".*requested_mask="([^"]+)".*/\1 \2 \4 \3/p' \
      | sort | uniq -c | sort -rn || true
}

# Start of the window for "what has this profile logged": the later of 24h
# ago and the profile file's last write (apply regenerates it; enforce and
# complain rewrite its flags). Events logged under an older profile, such as
# one generated by an earlier version of this script, say nothing about the
# rules loaded now.
profile_since() {
    local day p
    day="$(date -d '-24 hours' '+%Y-%m-%d %H:%M:%S')"
    p="$(date -r "$AA_PROFILE" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "$day")"
    if [[ "$(date -d "$p" +%s)" -gt "$(date -d "$day" +%s)" ]]; then echo "$p"; else echo "$day"; fi
}

is_managed() { [[ -f "$AA_PROFILE" ]] && grep -qF "$MARKER" "$AA_PROFILE"; }

current_mode() {
    if grep -qE "^${FPM_BIN} flags=\([^)]*complain" "$AA_PROFILE" 2>/dev/null; then echo complain; else echo enforce; fi
}

set_mode() {   # complain|enforce - written into the file so it survives reloads
    sed -i -E "s|^(${FPM_BIN} flags=)\([^)]*\)|\1(attach_disconnected,$1)|" "$AA_PROFILE"
    sed -i -E "s|^(${FPM_BIN} flags=\(attach_disconnected),enforce\)|\1)|" "$AA_PROFILE"
    apparmor_parser -r "$AA_PROFILE"
    info "Profile now in $(current_mode) mode"
}

unload_profile() {
    apparmor_parser -R "$AA_PROFILE" 2>/dev/null || true
    mkdir -p "$(dirname "$AA_DISABLE")"; ln -sf "$AA_PROFILE" "$AA_DISABLE"
    warn "Profile unloaded and disabled (remove $AA_DISABLE to re-enable)"
}

# Is the installed package fixed? Sets PATCH_HOW. Returns 0 patched,
# 1 not patched, 2 can't tell. Three independent signals, strongest first:
#   1. upstream version >= first fixed release (Debian, sury, upstream builds)
#   2. same upstream version as a known distro backport, and >= that build
#   3. the package changelog names both CVEs (catches backports not listed)
# Package dates aren't used: embargoed fixes are often dated before the public
# release, and a later unrelated rebuild doesn't contain the fix.
patch_status() {   # [package], default php${PHP_VER}-fpm
    local pkg="${1:-php${PHP_VER}-fpm}" full v up f cl c have_cl=0 below=""
    PATCH_HOW=""
    full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    if [[ -z "$full" ]]; then PATCH_HOW="${pkg} isn't an installed dpkg package"; return 2; fi
    v="${full#*:}"; up="${v%%-*}"

    if [[ -n "$PATCHED_VER" ]] && dpkg --compare-versions "$up" ge "$PATCHED_VER"; then
        PATCH_HOW="${v}: upstream ${up} >= ${PATCHED_VER}"; return 0
    fi
    for f in ${BACKPORT_FIXED[$PHP_VER]:-} $FIXED_BUILDS; do
        [[ "${f%%-*}" == "$up" ]] || continue
        if dpkg --compare-versions "$v" ge "$f"; then PATCH_HOW="${v} >= fixed build ${f}"; return 0; fi
        below="$f"
    done
    for cl in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/php${PHP_VER}-common/changelog.Debian.gz"; do
        [[ -f "$cl" ]] || continue
        # Only trust a changelog whose newest entry is the installed build
        [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${v})"* ]] || continue
        have_cl=1
        for c in "${CVES[@]}"; do zgrep -q "$c" "$cl" || continue 2; done
        PATCH_HOW="${v}: changelog lists ${CVES[*]}"; return 0
    done
    if [[ -n "$below" ]]; then PATCH_HOW="${v} is older than fixed build ${below}"; return 1; fi
    # Only Ubuntu fixes these branches without changing the upstream version
    # (8.3.6-0ubuntu...). sury and Debian ship the new upstream release
    # (DSA-6574-1: 8.4.27-1~deb13u1), so for any non-Ubuntu build an older
    # upstream is not fixed. Reached only when no changelog decided it.
    # (sury's Ubuntu builds say "+ubuntu24.04.1+deb.sury.org" but are sury's)
    if [[ -n "$PATCHED_VER" ]] && [[ "$v" == *sury* || "$v" != *ubuntu* ]]; then
        PATCH_HOW="${v}: upstream ${up} < ${PATCHED_VER}; $( [[ "$v" == *sury* ]] && echo "sury ships" || echo "non-Ubuntu builds ship" ) the upstream fix rather than backporting"
        return 1
    fi
    if [[ $have_cl -eq 1 ]]; then PATCH_HOW="${v}: no fixed release, no known backport, changelog doesn't list the CVEs"; return 1; fi
    PATCH_HOW="${v}: no changelog to check (docs stripped?) and no known fixed build"; return 2
}
is_patched() { patch_status; }

# Processes still executing the pre-upgrade binary: dpkg replaced the file, but
# the running FPM keeps the old (deleted) inode until it's restarted.
stale_fpm_pids() {
    local p e out=""
    for p in /proc/[0-9]*; do
        e="$(readlink "$p/exe" 2>/dev/null)" || continue
        [[ "$e" == "${FPM_BIN} (deleted)" ]] && out+="${p#/proc/} "
    done
    echo "${out% }"
}

# For the environment report, outside set_ver: "<rc>|<how>|<stale pids>"
patch_report() {   # <version> [package]
    (
        PHP_VER="$1"; PATCHED_VER="$(patched_ver "$1")"; FPM_BIN="/usr/sbin/php-fpm$1"
        rc=0; patch_status "${2:-}" || rc=$?
        echo "${rc}|${PATCH_HOW}|$( [[ -z "${2:-}" ]] && stale_fpm_pids )"
    )
}

patch_target() {
    local b="${BACKPORT_FIXED[$PHP_VER]:-}"
    if [[ -n "$PATCHED_VER" ]]; then echo "PHP ${PATCHED_VER}+${b:+, Ubuntu build ${b// / or }+,} or a distro build listing ${CVES[*]}"
    elif [[ -n "$b" ]]; then echo "Ubuntu build ${b// / or }+ (ESM/backport), or a distro build listing ${CVES[*]}"
    else echo "a distro/PPA build listing ${CVES[*]} (no upstream fix for ${PHP_VER}; set PATCHED_${PHP_VER/./_} if one appears)"; fi
}

global_preflight() {
    step "Preflight"
    [[ $EUID -eq 0 ]] || die "Must run as root (sudo $SELF)"
    command -v dpkg-query >/dev/null || die "Debian/Ubuntu (dpkg) layout required"
    if ! command -v apparmor_parser >/dev/null && [[ $CMD == apply ]]; then
        apt-get install -y --no-install-recommends apparmor || die "Could not install apparmor"
    fi
    aa-status --enabled 2>/dev/null || warn "AppArmor not enabled in the kernel - profiles will not apply"
}

ver_preflight() {
    [[ -x "$FPM_BIN" ]] || die "$FPM_BIN not found"
    [[ -d "$FPM_INI_DIR" ]] || die "$FPM_INI_DIR missing - unexpected PHP layout"
    if [[ " $EOL_VERS " == *" $PHP_VER "* ]]; then
        warn "PHP ${PHP_VER} is past upstream end of life and PHP won't fix it. Unless your distro (Debian LTS/ELTS, Ubuntu ESM) or the sury PPA backports the fix, this mitigation is permanent. Plan an upgrade to 8.2+."
    fi

    # v1 left backups inside /etc/apparmor.d/, where they load as duplicate profiles
    local f
    shopt -s nullglob
    for f in /etc/apparmor.d/"${AA_NAME}"*.bak*; do
        [[ -e "$f" ]] || continue
        mkdir -p "$BACKUP_DIR"; mv "$f" "$BACKUP_DIR/"
        warn "Moved stale backup out of /etc/apparmor.d: ${f##*/} -> $BACKUP_DIR/"
    done
    shopt -u nullglob

    info "Binary   : $FPM_BIN ($( [[ $SVC_LIVE -eq 1 ]] && echo live || echo stopped/disabled ))"
    info "Drop-in  : $DROP_IN_CONF"
    info "AppArmor : $AA_PROFILE (+ local: $AA_LOCAL)"
}

# ---------- profile generation -----------------------------------------------
write_profile() {   # $1 = output path, $2 = mode
    local out="$1" mode="$2" p r
    refresh_info
    local ext_dir sess_dir upload_dir temp_dir
    ext_dir="$(ini_path extension_dir "$DEFAULT_EXT_DIR")"
    [[ "$ext_dir" == /* ]] || die "Could not determine extension_dir for PHP ${PHP_VER}"
    sess_dir="$(ini_path session.save_path /var/lib/php/sessions)"
    upload_dir="$(ini_path upload_tmp_dir /tmp)"
    temp_dir="$(ini_path sys_temp_dir /tmp)"

    local log_rules="" root_rules="" writable_rules=""
    while IFS= read -r p; do [[ -n "$p" ]] && log_rules+="  ${p} rw,"$'\n'; done < <(collect_log_paths)
    for r in $WEB_ROOTS;      do root_rules+="  ${r%/}/ r,"$'\n'"  ${r%/}/** r,"$'\n'; done
    for r in $WRITABLE_PATHS; do writable_rules+="  ${r%/}/ r,"$'\n'"  ${r%/}/** rwk,"$'\n'; done

    local flags="attach_disconnected"; [[ "$mode" == complain ]] && flags+=",complain"
    # Pin rule semantics where the parser knows ABIs (AppArmor 3.0+). Without
    # it the profile compiles against whatever this release and kernel
    # support, so the same rules can mean different things on Ubuntu and
    # Debian 13. AppArmor 2.13 (Ubuntu 20.04, Debian 11) can't parse it.
    local abi_line=""; [[ -f /etc/apparmor.d/abi/3.0 ]] && abi_line="abi <abi/3.0>,"

    cat > "$out" <<AAEOF
${MARKER}
# AppArmor profile - php-fpm ${PHP_VER} - PHP2Shell interim mitigation
# Generated $(date -u +%FT%TZ) by ${SELF}. Regenerated on every run:
# put site-specific rules in ${AA_LOCAL} (never overwritten).
# Switch modes with: ${SELF} enforce ${HINT} | ${SELF} complain ${HINT}

${abi_line}
include <tunables/global>

${FPM_BIN} flags=(${flags}) {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/openssl>
  include <abstractions/ssl_certs>

  # --- Mitigation core: block shells and other binaries ---------------
  # audit: log every attempt. /usr/sbin is deliberately NOT explicitly
  # denied: deny beats allow, and FPM re-execs itself on reload. Every
  # other sbin binary is still implicitly denied in enforce mode.
  # Note: this also blocks mail() (runs /bin/sh -> sendmail) and
  # ImageMagick delegates. Use SMTP from PHP if mail is needed.
  audit deny /{,usr/}{,local/}bin/** x,
  audit deny /snap/bin/** x,
  ${FPM_BIN} mrix,

  deny /etc/shadow rw,
  deny /etc/gshadow rw,
  deny /etc/sudoers rw,
  deny /etc/sudoers.d/** rw,
  deny /etc/passwd w,
  deny /root/** rw,

  # --- FPM runtime ----------------------------------------------------
  capability chown,
  capability dac_override,
  capability dac_read_search,
  capability fowner,
  capability kill,
  capability net_bind_service,
  capability setgid,
  capability setuid,
  capability sys_resource,

  network inet stream,
  network inet6 stream,
  network inet dgram,
  network inet6 dgram,
  network unix stream,
  network unix dgram,

  signal (send, receive) peer=@{profile_name},
  signal (receive) peer=unconfined,

  # systemd readiness: every Debian/Ubuntu/sury unit is Type=notify. Without
  # this, FPM can't send READY=1 in enforce mode and systemd fails the start
  # after TimeoutStartSec.
  @{run}/systemd/notify w,

  # PHP config, extensions, shared libs and data
  /etc/php/${PHP_VER}/** r,
  ${ext_dir}/** mr,
  /usr/lib/php/** r,
  /usr/lib/@{multiarch}/** mr,
  /usr/share/** r,
  /etc/ImageMagick-*/** r,
  /etc/fonts/** r,
  /etc/{localtime,timezone,mime.types,magic} r,

  # Runtime sockets
  /run/php/** rwk,
  /run/mysqld/mysqld.sock rw,
  /run/postgresql/.s.PGSQL.* rw,
  /run/redis/*.sock rw,

  # Logs - derived from FPM config at generation time
${log_rules}  /var/log/php${PHP_VER}-fpm*.log rw,
  /var/log/php/** rw,

  # Sessions, uploads, temp (k = flock, needed for file sessions)
  ${sess_dir}/ r,
  ${sess_dir}/** rwk,
  ${upload_dir}/ r,
  ${upload_dir}/** rwk,
  ${temp_dir}/ r,
  ${temp_dir}/** rwk,
  /tmp/ r,
  /tmp/** rwk,

  # Web roots (read-only) and writable app paths
${root_rules}${writable_rules}
  # Kernel info read by PHP and extensions
  @{PROC}/@{pid}/{status,stat,cmdline,maps,mounts,mountinfo} r,
  @{PROC}/@{pid}/fd/ r,
  @{PROC}/{meminfo,cpuinfo,loadavg,stat} r,
  @{PROC}/sys/kernel/random/boot_id r,
  /sys/kernel/mm/transparent_hugepage/** r,
  /sys/devices/system/cpu/** r,

  include if exists <local/${AA_NAME}>
}
AAEOF
}

ensure_local() {
    [[ -f "$AA_LOCAL" ]] && return 0
    mkdir -p "$(dirname "$AA_LOCAL")"
    cat > "$AA_LOCAL" <<LOCALEOF
# Site-specific rules for ${FPM_BIN}. Never overwritten by ${SELF}.
# Examples:
#   /var/www/example.com/wp-content/uploads/** rwk,
#   /srv/app/storage/** rwk,
LOCALEOF
    info "Created $AA_LOCAL"
}

# ---------- per-version commands ---------------------------------------------
cmd_apply() {
    ver_preflight

    step "PHP ${PHP_VER} 1/3  session.upload_progress"
    local want
    want=$(printf '%s\n' \
        "; PHP2Shell interim mitigation (${CVES[*]})" \
        "; Remove with: ${SELF} cleanup ${HINT}  (once patched)" \
        "session.upload_progress.enabled = Off")
    if [[ -f "$DROP_IN_CONF" ]] && [[ "$(cat "$DROP_IN_CONF")" == "$want" ]]; then
        info "Drop-in already current"
    else
        [[ -f "$DROP_IN_CONF" ]] && backup "$DROP_IN_CONF"
        printf '%s\n' "$want" > "$DROP_IN_CONF"
        info "Written: $DROP_IN_CONF"
    fi

    step "PHP ${PHP_VER} 2/3  AppArmor"
    local mode=complain
    if is_managed && [[ "$(current_mode)" == enforce ]]; then
        mode=enforce; info "Existing profile is enforcing - keeping enforce mode"
    fi
    if [[ -f "$AA_PROFILE" ]] && ! is_managed; then warn "Replacing unmanaged profile (backed up below)"; fi

    TMP_PROFILE="$(mktemp /tmp/php2shell-aa.XXXXXX)"
    trap 'rm -f "${TMP_PROFILE:-}"' EXIT
    ensure_local
    write_profile "$TMP_PROFILE" "$mode"
    apparmor_parser -QK "$TMP_PROFILE" 2>&1 \
        || die "Generated profile failed to parse - nothing installed. Inspect: $TMP_PROFILE"
    info "Profile syntax OK"

    [[ -f "$AA_PROFILE" ]] && backup "$AA_PROFILE"
    install -m 0644 "$TMP_PROFILE" "$AA_PROFILE"
    info "Installed $AA_PROFILE ($mode)"

    if [[ -e "$AA_DISABLE" ]]; then
        warn "$AA_DISABLE exists - profile written but NOT loaded. Remove it and rerun to activate."
    else
        apparmor_parser -r "$AA_PROFILE"
        info "Profile loaded"
    fi

    step "PHP ${PHP_VER} 3/3  Test and restart $FPM_SERVICE"
    "$FPM_BIN" -t 2>&1 | tail -2 || true
    if ! fpm_health; then
        warn "FPM failed under the new profile"
        aa_event_summary "$START_TS"
        if [[ "$(current_mode)" == enforce ]]; then
            set_mode complain
            fpm_health && die "Fell back to complain mode; FPM is up. Add the paths above to $AA_LOCAL, then: ${SELF} enforce ${HINT}"
        fi
        if "$FPM_BIN" -t >/dev/null 2>&1; then
            unload_profile; fpm_health || true
            die "FPM fails even in complain mode - profile unloaded so the service stays up. Check the $FPM_SERVICE log (journalctl -xeu $FPM_SERVICE, or /var/log/php${PHP_VER}-fpm.log)"
        fi
        die "FPM config test fails independent of AppArmor: $FPM_BIN -t"
    fi
    info "$FPM_SERVICE healthy"

    verify
    if [[ "$(current_mode)" == complain ]]; then
        echo -e "  Next: run real traffic, then ${SELF} status ${HINT}; add legit paths to $AA_LOCAL; then ${SELF} enforce ${HINT}"
    fi
}

verify() {
    refresh_info
    local up; up="$(ini_val session.upload_progress.enabled)"
    if [[ "$up" =~ ^(Off|0)$ ]]; then info "session.upload_progress.enabled = $up"
    else warn "session.upload_progress.enabled = '${up:-unknown}' - drop-in not effective"; fi
    local loaded; loaded="$(aa-status 2>/dev/null | grep -cF "$FPM_BIN" || true)"
    info "AppArmor: $( [[ "$loaded" -gt 0 ]] && echo loaded || echo 'NOT loaded' ), file mode: $(current_mode)"
    if [[ $SVC_LIVE -eq 1 ]]; then
        if svc_active "$FPM_SERVICE"; then info "$FPM_SERVICE active"; else warn "$FPM_SERVICE NOT running"; fi
    else
        info "$FPM_SERVICE stopped/disabled (left as found)"
    fi
    local prc=0 stale; patch_status || prc=$?
    case $prc in
        0)  info "php${PHP_VER}-fpm patched (${PATCH_HOW})"
            stale="$(stale_fpm_pids)"
            if [[ -n "$stale" ]]; then
                warn "...but PIDs ${stale} still run the old binary. Restart: $(svc_hint restart "$FPM_SERVICE")"
            else
                info "Running code is current - the mitigation can go: ${SELF} cleanup ${HINT}"
            fi ;;
        1)  warn "NOT patched (${PATCH_HOW}). Target: $(patch_target)" ;;
        *)  warn "Patch status unknown (${PATCH_HOW}). Target: $(patch_target)" ;;
    esac
}

cmd_enforce() {
    is_managed || die "No managed profile at $AA_PROFILE - run ${SELF} ${HINT} first"
    local win; win="$(profile_since)"
    local seen; seen="$(aa_event_summary "$win" | grep -v ' exec ' || true)"
    if [[ -n "$seen" && -z "$FORCE" ]]; then
        warn "Complain mode logged these accesses since ${win} (would be DENIED in enforce):"
        echo "$seen"
        die "Add legitimate paths to $AA_LOCAL, rerun ${SELF} ${HINT}, then retry. Or add --force"
    fi
    local since; since="$(date '+%Y-%m-%d %H:%M:%S')"
    set_mode enforce
    if ! fpm_health; then
        aa_event_summary "$since"
        set_mode complain; fpm_health || true
        die "FPM failed under enforce - reverted to complain. Add the paths above to $AA_LOCAL."
    fi
    info "$FPM_SERVICE healthy under enforce"
    local ev; ev="$(aa_event_summary "$since")"
    [[ -z "$ev" ]] || { warn "Events since enforcing:"; echo "$ev"; }
}

cmd_complain() {
    is_managed || die "No managed profile at $AA_PROFILE"
    set_mode complain
    fpm_health || die "$FPM_SERVICE failed to restart"
}

cmd_status() {
    if [[ ! -f "$DROP_IN_CONF" ]] && ! is_managed; then
        warn "Mitigation not applied to PHP ${PHP_VER}"; return 0
    fi
    verify
    local win; win="$(profile_since)"
    echo "  AppArmor events since ${win}, when the current profile was written or 24h ago (count verdict op mask path):"
    local ev; ev="$(aa_event_summary "$win")"
    if [[ -n "$ev" ]]; then sed 's/^/    /' <<<"$ev"; else echo "    none"; fi
}

# ---------- hunt: read-only log triage ---------------------------------------
# These bugs execute below the application, so app logs hold little. What they
# leave is memory-corruption crashes and, where exploited, a PHP worker running
# something it shouldn't. hunt reads logs only; it never changes anything and
# doesn't need root (though without it some logs aren't readable). It reports
# counts and recent samples, and names the before/after date so a spike is
# visible. A finding is a lead to investigate, never proof on its own: buggy
# extensions crash workers too, and the upload-progress field is in legitimate
# forms. The signatures were confirmed against real php-fpm 8.4 output.
DISCLOSURE_DATE="2026-10-21"

# Logs worth reading: every version's FPM error_log (from its own config),
# the common defaults, the web servers, and the journal.
hunt_log_files() {
    local v
    for v in $SUPPORTED_VERS; do
        FPM_ETC="/etc/php/${v}/fpm"
        collect_log_paths 2>/dev/null
        echo "/var/log/php${v}-fpm.log"
    done
    printf '%s\n' /var/log/php-fpm.log /var/log/php_errors.log /var/log/php/*.log \
        /var/log/apache2/error.log /var/log/apache2/*error*.log \
        /var/log/httpd/error_log /var/log/nginx/error.log /var/log/syslog /var/log/messages
    # web-server-declared PHP error logs (e.g. php_admin_value[error_log] via .htaccess is out of scope; pool logs already covered)
}

# De-duplicated, readable log files that exist
hunt_logs() {
    hunt_log_files | sort -u | while read -r f; do
        # expand a single trailing * glob safely
        if [[ "$f" == *'*'* ]]; then
            compgen -G "$f" 2>/dev/null || true
        else
            [[ -r "$f" ]] && echo "$f"
        fi
    done | sort -u
}

# grep a set of files, print match count and the last few, with context label.
# $1 = label, $2 = extended regex, rest = files
hunt_grep() {
    local label="$1" re="$2"; shift 2
    # grep exits 1 when nothing matches; under `set -o pipefail` that would
    # abort the whole run, so every grep here is wrapped to swallow it.
    local n; n="$( { grep -hE "$re" "$@" 2>/dev/null || true; } | wc -l | tr -d ' ')"
    if [[ "${n:-0}" -gt 0 ]]; then
        warn "${label}: ${n} line(s)"
        { grep -hE "$re" "$@" 2>/dev/null || true; } | tail -4 | sed 's/^/      /'
        HUNT_FINDINGS=$((HUNT_FINDINGS + 1))
    else
        info "${label}: none"
    fi
}

# Count matches before vs on/after the disclosure date, when lines are dated
# "[DD-Mon-YYYY" (FPM) - a rough spike check, best-effort only.
hunt_spike() {
    local re="$1"; shift
    local d; d="$(date -d "$DISCLOSURE_DATE" +%s 2>/dev/null || echo 0)"
    [[ "$d" -gt 0 ]] || return 0
    local before=0 after=0 line ts
    while IFS= read -r line; do
        if [[ "$line" =~ \[([0-9]{2}-[A-Za-z]{3}-[0-9]{4}) ]]; then
            ts="$(date -d "${BASH_REMATCH[1]//-/ }" +%s 2>/dev/null || echo 0)"
            [[ "$ts" -eq 0 ]] && continue
            if [[ "$ts" -lt "$d" ]]; then before=$((before+1)); else after=$((after+1)); fi
        fi
    done < <(grep -hE "$re" "$@" 2>/dev/null || true)
    [[ $((before+after)) -gt 0 ]] && echo "      dated split: ${before} before ${DISCLOSURE_DATE}, ${after} on/after"
    return 0
}

HUNT_FINDINGS=0
cmd_hunt() {
    step "Log triage (read-only)"
    [[ $EUID -eq 0 ]] || warn "Not root - logs you can't read were skipped"

    mapfile -t LOGS < <(hunt_logs)
    if [[ ${#LOGS[@]} -eq 0 ]]; then
        warn "No readable PHP or web-server logs found. Looked for FPM error_logs, /var/log/php*, Apache and nginx logs."
        echo "  If your logs live elsewhere, point hunt at them: WEB_ROOTS is unrelated; pass paths via the FPM config's error_log, or grep them by hand with the patterns in this function."
        return 0
    fi
    info "Reading ${#LOGS[@]} log file(s)"

    step "1/3  Memory-corruption crashes"
    # FPM master logs a crashed worker as: "child N exited on signal 11 (SIGSEGV)".
    # SIGSEGV(11), SIGABRT(6), SIGBUS(7) are the ones memory corruption produces.
    hunt_grep "PHP-FPM worker crashes (SIGSEGV/SIGABRT/SIGBUS)" \
        'exited on signal (6|7|11)( |\()' "${LOGS[@]}"
    hunt_spike 'exited on signal (6|7|11)( |\()' "${LOGS[@]}"
    # Apache mod_php crash line
    hunt_grep "Apache worker crashes (AH00052 / exit signal)" \
        'AH00052|child pid [0-9]+ exit signal (Segmentation|Bus|Abort)' "${LOGS[@]}"
    # Zend/glibc allocator panics seen on corruption (incl. USE_ZEND_ALLOC=0 staging)
    hunt_grep "Allocator panic (zend_mm heap / glibc double free / malloc)" \
        'zend_mm_heap corrupted|double free detected|free\(\): |malloc\(\): |corrupted (top size|size vs. prev_size)' "${LOGS[@]}"
    # Kernel view of the same crashes
    if [[ $EUID -eq 0 ]] && have_systemd && command -v journalctl >/dev/null; then
        local kre='(php-fpm|php[0-9.]*-fpm|apache2|httpd)[^ ]*.*(segfault|general protection|trap)'
        local kn; kn="$( { journalctl -k --since "-14 days" 2>/dev/null || true; } | { grep -cE "$kre" || true; } )"
        if [[ "${kn:-0}" -gt 0 ]]; then
            warn "Kernel segfault/GPF entries naming php-fpm/apache (last 14d): ${kn}"
            { journalctl -k --since "-14 days" 2>/dev/null || true; } | { grep -E "$kre" || true; } | tail -3 | sed 's/^/      /'
            HUNT_FINDINGS=$((HUNT_FINDINGS + 1))
        else
            info "Kernel segfault/GPF entries naming php-fpm/apache (last 14d): none"
        fi
    fi
    # Core dumps
    if command -v coredumpctl >/dev/null; then
        local cd; cd="$( { coredumpctl list --no-pager 2>/dev/null || true; } | { grep -ciE 'php-fpm|php[0-9.]|apache2|httpd' || true; } )"
        if [[ "${cd:-0}" -gt 0 ]]; then
            warn "Core dumps from php-fpm/apache: ${cd} (coredumpctl list)"; HUNT_FINDINGS=$((HUNT_FINDINGS + 1))
        fi
    fi

    step "2/3  Signs of the attack path"
    # php2shell's OOM producer: a flood of memory_limit fatals, or requests that
    # hit it. One is ordinary; a burst from one client around a crash is not.
    hunt_grep "Out-of-memory / memory_limit fatals" \
        'Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(alloc' "${LOGS[@]}"
    hunt_spike 'Allowed memory size of [0-9]+ bytes exhausted' "${LOGS[@]}"
    # Upload-progress field: part of the 109619 path and of older LFI chains.
    # Appears in access logs / mod_security, not usually error logs.
    hunt_grep "PHP_SESSION_UPLOAD_PROGRESS seen in logs (triage signal, also in legit forms)" \
        'PHP_SESSION_UPLOAD_PROGRESS' "${LOGS[@]}"

    step "3/3  Post-exploitation residue"
    # FPM/Apache executing a shell or tool is what nearly every PHP intrusion
    # shows. If the AppArmor profile is loaded in complain or enforce mode, its
    # own log of exec attempts is the strongest local signal.
    local anyaa=0 v
    for v in $(detect_versions 2>/dev/null); do
        set_ver "$v" 2>/dev/null || continue
        is_managed || continue
        anyaa=1
        local ex; ex="$(aa_event_summary '-7d' 2>/dev/null | grep ' exec ' || true)"
        if [[ -n "$ex" ]]; then
            warn "AppArmor blocked/logged FPM ${v} exec attempts (last 7d) - FPM tried to run a binary:"
            sed 's/^/      /' <<<"$ex"; HUNT_FINDINGS=$((HUNT_FINDINGS + 1))
        else
            info "AppArmor FPM ${v}: no exec attempts logged (last 7d)"
        fi
    done
    [[ $anyaa -eq 1 ]] || inf_hunt "No managed AppArmor profile loaded, so no exec log to check. Applying this script's profile in complain mode turns FPM exec attempts into a signal here."
    # Webshell-shaped writes mentioned in logs (very rough; real check is on disk)
    hunt_grep "Shell/interpreter/tool names in PHP or web logs (context-dependent)" \
        '(php-fpm|php-cgi|apache2|httpd)[^ ]*.*(/bin/(ba)?sh|/dev/tcp/|fsockopen|mkfifo|nc |ncat |wget |curl .*(-o|http)|certutil|whoami|uname -a)' "${LOGS[@]}"

    step "Hunt summary"
    if [[ $HUNT_FINDINGS -eq 0 ]]; then
        info "No signatures matched. This is reassuring, not proof: these bugs can corrupt memory silently, and a patched server is the only real fix."
        return 0
    fi
    warn "${HUNT_FINDINGS} signature group(s) matched. None is proof of compromise on its own."
    echo "  Next steps:"
    echo "    - Compare counts against a quiet period before ${DISCLOSURE_DATE}; a spike is the real signal."
    echo "    - Correlate crashes with memory_limit fatals and multipart POSTs from the same client IP."
    echo "    - Check the web root for new/modified files, and for new cron jobs, scheduled tasks and accounts."
    echo "    - Preserve web-server and PHP logs before they rotate."
    echo "    - Patch: the only complete fix is an updated PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35) or your distro's backport."
    return 1
}
inf_hunt() { echo -e "  ${CYAN}note:${NC} $*"; }

cmd_cleanup() {
    if ! is_patched && [[ -z "$FORCE" ]]; then
        die "php${PHP_VER}-fpm doesn't look patched (${PATCH_HOW}). Target: $(patch_target). Or add --force"
    fi
    if [[ -f "$DROP_IN_CONF" ]]; then
        backup "$DROP_IN_CONF"; rm -f "$DROP_IN_CONF"; info "Removed $DROP_IN_CONF"
    fi
    fpm_health || die "$FPM_SERVICE failed to restart after cleanup"
    info "Drop-in removed. AppArmor profile kept as defense-in-depth."
    echo "  The profile still confines FPM (blocks it running a shell etc.), which the patch doesn't do."
    echo "  Recommended now that you're patched and the app is known-good: ${SELF} enforce ${HINT}"
    echo "  To remove the profile instead (both files, unload, verify): ${SELF} remove ${HINT}"
}

# Fully remove this version's AppArmor profile: unload it from the kernel, then
# delete the generated profile, the local override, and any disable symlink.
# Leaves the ini drop-in alone (that's cleanup's job). Safe to run when the
# profile is already gone. Does not need the package to be patched.
cmd_remove() {
    if [[ ! -f "$AA_PROFILE" && ! -f "$AA_LOCAL" && ! -e "$AA_DISABLE" ]]; then
        info "No AppArmor profile for PHP ${PHP_VER} to remove"
        return 0
    fi
    if [[ -f "$AA_PROFILE" ]] && ! is_managed; then
        die "$AA_PROFILE exists but wasn't created by this script (no '${MARKER}' marker). Leaving it alone; remove it by hand if you're sure."
    fi
    # Unload from the kernel first, so running workers stop being confined.
    if command -v apparmor_parser >/dev/null && [[ -f "$AA_PROFILE" ]]; then
        if apparmor_parser -R "$AA_PROFILE" 2>/dev/null; then
            info "Unloaded profile from the kernel"
        else
            warn "apparmor_parser -R failed (profile may not have been loaded)"
        fi
    fi
    local f
    for f in "$AA_PROFILE" "$AA_LOCAL" "$AA_DISABLE"; do
        if [[ -e "$f" || -L "$f" ]]; then backup "$f" 2>/dev/null || true; rm -f "$f"; info "Removed $f"; fi
    done
    # Verify the kernel no longer confines FPM. Running workers can keep a
    # profile reference until they recycle, so a leftover count isn't fatal:
    # report it and say how to clear it.
    local still
    still="$(aa-status 2>/dev/null | grep -cF "$FPM_BIN" || true)"
    if [[ "${still:-0}" -gt 0 ]]; then
        warn "aa-status still lists ${FPM_BIN} (${still} entr$([[ $still -eq 1 ]] && echo y || echo ies))."
        echo "  Running workers keep the old profile until they recycle. Clear it with:"
        echo "    $(svc_hint restart "$FPM_SERVICE")"
        return 0
    fi
    info "aa-status no longer lists ${FPM_BIN}; profile fully removed"
}

# ---------- environment check ------------------------------------------------
# Runs before anything is changed, in this order: OS, PHP, web servers, system.
# Hard blockers always stop the run. Soft blockers stop it unless --ignore-env
# is given. Cautions are reported but never stop it.
OS_SUPPORTED="debian ubuntu trisquel"
OS_DERIVATIVES="linuxmint pop elementary zorin neon kali raspbian pureos parrot deepin tuxedo devuan mx antix sparky q4os peppermint bunsenlabs siduction"
declare -A DISTRO_PHP=([stretch]=7.0 [buster]=7.3 [bullseye]=7.4 [bookworm]=8.2 [trixie]=8.4
                       [xenial]=7.0 [bionic]=7.2 [focal]=7.4 [jammy]=8.1 [noble]=8.3 [resolute]=8.5)
declare -A TRISQUEL_BASE=([etiona]=bionic [nabia]=focal [aramo]=jammy [ecne]=noble)
declare -A DEBIAN_MAJOR=([9]=stretch [10]=buster [11]=bullseye [12]=bookworm [13]=trixie)
ENV_HARD=(); ENV_SOFT=(); ENV_PHP=(); RUNNING_WIRED=(); MUTATES=0

ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
soft()    { ENV_SOFT+=("$1"); echo -e "  ${YELLOW}✗${NC} $1 ${YELLOW}[stops; --ignore-env overrides]${NC}"; [[ -z "${2:-}" ]] || echo -e "      $2"; }
hard()    { ENV_HARD+=("$1"); echo -e "  ${RED}✗${NC} $1 ${RED}[stops]${NC}"; [[ -z "${2:-}" ]] || echo -e "      $2"; }
section() { echo -e "\n  ${CYAN}$*${NC}"; }
in_list() { [[ " $2 " == *" $1 "* ]]; }

svc_state() {
    if svc_active "$1"; then echo running
    elif svc_enabled "$1"; then echo "enabled, not running"
    else echo stopped; fi
}

fpm_refs() {   # PHP versions a web server config points at, via phpX.Y-fpm.sock or php-fpm.sock
    local alt
    grep -rhoE 'php(-|[0-9]+\.[0-9]+-)fpm\.sock' "$@" 2>/dev/null | sort -u | while read -r s; do
        if [[ "$s" == php-fpm.sock ]]; then   # unversioned alternative -> current target
            alt="$(readlink /etc/alternatives/php-fpm.sock 2>/dev/null || true)"
            [[ "$alt" =~ php([0-9]+\.[0-9]+)-fpm\.sock$ ]] && echo "${BASH_REMATCH[1]}"
        else
            s="${s#php}"; echo "${s%-fpm.sock}"
        fi
    done | sort -uV || true
}

check_os() {
    section "1/4  Operating system"
    if [[ ! -r /etc/os-release ]]; then
        hard "/etc/os-release missing - can't identify the distribution"; return 1
    fi
    local kv id like pretty code ubu deb
    kv="$(. /etc/os-release; printf '%s\x1f' "${ID:-}" "${ID_LIKE:-}" "${PRETTY_NAME:-unknown}" \
          "${VERSION_CODENAME:-}" "${UBUNTU_CODENAME:-}" "${DEBIAN_CODENAME:-}")"
    IFS=$'\x1f' read -r id like pretty code ubu deb <<<"$kv"

    if in_list "$id" "$OS_SUPPORTED"; then
        ok "$pretty (supported)"
    elif in_list "$id" "$OS_DERIVATIVES"; then
        ok "$pretty (known derivative, ID=$id)"
    elif in_list ubuntu "$like" || in_list debian "$like"; then
        ok "$pretty (Debian/Ubuntu derivative, ID=$id, ID_LIKE=$like)"
    elif [[ -r /etc/debian_version ]]; then
        ok "$pretty (Debian-based: /etc/debian_version present, ID=$id)"
    else
        hard "$pretty is not Debian, Ubuntu, Trisquel or a derivative (ID=$id)" \
             "This script assumes dpkg, /etc/php/X.Y and AppArmor. RHEL/Fedora/SUSE/Arch/Alpine need a different approach."
        return 1
    fi

    # Base release, used only to tell the user what PHP their distro ships
    local base="" fam=debian
    if [[ "$id" == ubuntu || "$id" == trisquel || -n "$ubu" ]] || in_list ubuntu "$like"; then fam=ubuntu; fi
    if [[ $fam == ubuntu ]]; then
        base="$ubu"
        [[ -n "$base" || "$id" != ubuntu ]] || base="$code"
        [[ -n "$base" || "$id" != trisquel ]] || base="${TRISQUEL_BASE[$code]:-}"
    else
        base="$deb"
        [[ -n "$base" ]] || { [[ "$id" =~ ^(debian|raspbian)$ ]] && base="$code"; } || true
        if [[ -z "$base" && -r /etc/debian_version ]]; then
            local dv; dv="$(cut -d. -f1 /etc/debian_version)"; base="${DEBIAN_MAJOR[$dv]:-}"
        fi
    fi
    # Derivatives often reuse their base's codename (MX, Kali-style setups)
    [[ -n "$base" || -z "$code" || -z "${DISTRO_PHP[$code]:-}" ]] || base="$code"
    if [[ -n "$base" ]]; then
        local dp="${DISTRO_PHP[$base]:-}"
        inf "Base: ${fam^} ${base}${dp:+, distro PHP ${dp}}"
        if [[ -n "$dp" ]] && ! in_list "$dp" "$SUPPORTED_VERS"; then
            caution "Distro PHP ${dp} isn't in SUPPORTED_VERS (${SUPPORTED_VERS}) and will be skipped"
        fi
    else
        caution "Couldn't determine the Debian/Ubuntu base release"
    fi

    command -v dpkg-query >/dev/null || { hard "dpkg-query not found - Debian package layout required"; return 1; }
    return 0
}

report_patch() {   # <version> <package> <service>
    local rep rc how stale
    rep="$(patch_report "$1" "$2")"; rc="${rep%%|*}"; rep="${rep#*|}"; how="${rep%%|*}"; stale="${rep#*|}"
    case $rc in
        0) ok "  patched: ${how}"
           [[ -z "$stale" ]] || caution "  but PIDs ${stale} still run the old binary - restart: $(svc_hint restart "$3")" ;;
        1) caution "  NOT patched: ${how}. Upgrade: apt-get install --only-upgrade $2" ;;
        *) caution "  patch status unknown: ${how}" ;;
    esac
    return "$rc"
}

check_php() {
    section "2/4  PHP"
    local b v pv src
    shopt -s nullglob
    for b in /usr/sbin/php-fpm[0-9]*; do
        v="${b#/usr/sbin/php-fpm}"
        [[ -x "$b" && "$v" =~ ^[0-9]+\.[0-9]+$ ]] || continue
        pv="$(dpkg-query -W -f='${Version}' "php${v}-fpm" 2>/dev/null || true)"
        if   [[ -z "$pv" ]];       then src="not installed by dpkg"
        elif [[ "$pv" == *sury* ]]; then src="ondrej/sury"
        else src="distro"; fi
        if [[ "$v" == 5.* ]]; then
            caution "php${v}-fpm ${pv:-?} (${src}) - PHP 5.4+ is reported affected, but 5.x isn't covered by this script. Upgrade."
        elif ! in_list "$v" "$SUPPORTED_VERS"; then
            caution "php${v}-fpm ${pv:-?} (${src}) - not in SUPPORTED_VERS, will be skipped. Check whether this branch is affected."
        elif [[ -n "$ONLY_VER" && "$v" != "$ONLY_VER" ]]; then
            inf "php${v}-fpm ${pv:-?} (${src}) - skipped (--php ${ONLY_VER})"
        elif [[ -z "$pv" ]]; then
            soft "php${v}-fpm present but not owned by dpkg - patch detection and backups assume packaged PHP"
            ENV_PHP+=("$v")
        else
            ok "php${v}-fpm ${pv} (${src}), service $(svc_state "php${v}-fpm") - will be handled"
            in_list "$v" "$EOL_VERS" && caution "PHP ${v} is end of life: no upstream fix, only distro/PPA backports"
            report_patch "$v" "php${v}-fpm" "php${v}-fpm" || true   # informational, never stops the run
            ENV_PHP+=("$v")
        fi
    done
    shopt -u nullglob

    local cli; cli="$(readlink -f /usr/bin/php 2>/dev/null || true)"
    [[ "$cli" =~ php([0-9]+\.[0-9]+)$ ]] && inf "Default CLI: PHP ${BASH_REMATCH[1]} (CLI isn't exposed to the web; not touched)"

    # PHP this script cannot see or protect
    local p
    for p in /usr/local/sbin/php-fpm* /usr/local/bin/php-fpm* /opt/*/sbin/php-fpm* /opt/*/bin/php-fpm*; do
        [[ -x "$p" ]] && caution "Non-packaged PHP-FPM at $p - NOT covered by this script"
    done
    [[ -d /usr/local/lsws ]] && caution "LiteSpeed lsphp under /usr/local/lsws - NOT covered (it doesn't use php-fpm)"

    if [[ -n "$ONLY_VER" ]] && ! in_list "$ONLY_VER" "$SUPPORTED_VERS"; then
        hard "--php ${ONLY_VER} is not in SUPPORTED_VERS (${SUPPORTED_VERS})"
    elif [[ ${#ENV_PHP[@]} -eq 0 ]]; then
        hard "No PHP-FPM ${ONLY_VER:-in SUPPORTED_VERS (${SUPPORTED_VERS})} installed under /usr/sbin" \
             "Nothing to mitigate. If PHP runs inside Apache (mod_php) see the web server section."
    fi
}

check_web() {
    section "3/4  Web servers"
    local any=0 st ver v f modphp=()

    if [[ -x /usr/sbin/apache2 ]]; then
        any=1; st="$(svc_state apache2)"
        ver="$(/usr/sbin/apache2 -v 2>/dev/null | sed -n 's/^Server version: //p' || true)"
        local mpm=""
        shopt -s nullglob
        for f in /etc/apache2/mods-enabled/mpm_*.load; do mpm="${f##*/mpm_}"; mpm="${mpm%.load}"; done
        for f in /etc/apache2/mods-enabled/php*.load; do v="${f##*/php}"; modphp+=("${v%.load}"); done
        shopt -u nullglob
        inf "Apache: ${ver:-installed}, ${st}${mpm:+, MPM ${mpm}}"
        local refs; refs="$(fpm_refs /etc/apache2/sites-enabled /etc/apache2/conf-enabled)"
        [[ -z "$refs" ]] || inf "  → php-fpm via proxy_fcgi: $(echo $refs)"
        [[ "$st" == running ]] && for v in $refs; do RUNNING_WIRED+=("$v"); done
        for v in "${modphp[@]+"${modphp[@]}"}"; do
            caution "Apache has mod_php ${v} enabled - PHP inside Apache is not covered by this script"
            local mrc=0; report_patch "$v" "libapache2-mod-php${v}" apache2 || mrc=$?
            if [[ $mrc -eq 0 ]]; then
                if grep -lsF "libphp${v}.so (deleted)" /proc/[0-9]*/maps >/dev/null 2>&1; then
                    caution "  Apache still has the old libphp${v}.so loaded - restart: $(svc_hint restart apache2)"
                fi
            elif [[ "$st" == running && $CMD == apply ]]; then
                soft "Apache is running mod_php ${v}, which isn't patched and isn't covered by this script" \
                     "Upgrade libapache2-mod-php${v} and restart Apache. Interim: echo 'session.upload_progress.enabled = Off' > /etc/php/${v}/apache2/conf.d/99-php2shell-mitigation.ini && $(svc_hint restart apache2)"
            fi
        done
    fi

    if [[ -x /usr/sbin/nginx ]]; then
        any=1; st="$(svc_state nginx)"
        ver="$(/usr/sbin/nginx -v 2>&1 | sed -n 's/^nginx version: //p' || true)"
        inf "nginx: ${ver:-installed}, ${st}"
        local refs; refs="$(fpm_refs /etc/nginx)"
        [[ -z "$refs" ]] || inf "  → php-fpm via fastcgi_pass: $(echo $refs)"
        [[ "$st" == running ]] && for v in $refs; do RUNNING_WIRED+=("$v"); done
        if grep -rqE '^[[:space:]]*fastcgi_pass[[:space:]]+[^;/]+:[0-9]+' /etc/nginx 2>/dev/null; then
            caution "nginx has TCP fastcgi_pass upstream(s) - can't map those to a PHP version; check pool 'listen =' lines"
        fi
    fi

    # Less common servers: report only
    local name bin
    for name in angie lighttpd caddy; do
        bin="$(command -v "$name" 2>/dev/null || true)"; [[ -n "$bin" ]] || continue
        any=1; st="$(svc_state "$name")"
        local refs; refs="$(fpm_refs "/etc/${name}")"
        inf "${name}: ${st}${refs:+ → php-fpm $(echo $refs)}"
        [[ "$st" == running ]] && for v in $refs; do RUNNING_WIRED+=("$v"); done
    done

    [[ $any -eq 1 ]] || caution "No Apache, nginx, angie, lighttpd or caddy found - FPM may be served remotely; mitigation still applies to FPM"

    # Cross-check: what's actually serving traffic vs what we'll touch
    local w covered=0 seen=" "
    for w in "${RUNNING_WIRED[@]+"${RUNNING_WIRED[@]}"}"; do
        in_list "$w" "$seen" && continue; seen+="$w "
        if in_list "$w" "${ENV_PHP[*]:-}"; then covered=1
        elif [[ ! -x "/usr/sbin/php-fpm${w}" ]]; then caution "A running web server points at php${w}-fpm, which isn't installed (stale config?)"
        else caution "A running web server uses php${w}-fpm, which this run will NOT touch"; fi
    done
    if [[ $CMD == apply && ${#RUNNING_WIRED[@]} -gt 0 && $covered -eq 0 ]]; then
        soft "None of the PHP-FPM versions your running web server uses would be mitigated" \
             "Live: $(echo "${RUNNING_WIRED[@]}" | tr ' ' '\n' | sort -uV | xargs). Handled: ${ENV_PHP[*]:-none}."
    fi
}

check_system() {
    section "4/4  System"
    if [[ $EUID -ne 0 ]]; then
        if [[ $CMD == check ]]; then caution "Not root - some results may be incomplete"
        else hard "Must run as root (sudo $SELF $CMD)"; fi
    else
        ok "Running as root"
    fi

    local init; init="$(cat /proc/1/comm 2>/dev/null || echo unknown)"
    if have_systemd; then
        ok "systemd is PID 1"
    elif command -v service >/dev/null; then
        ok "No systemd (PID 1 is ${init}) - using service(8) and init scripts, AppArmor events from audit.log/kern.log/dmesg"
        local v
        for v in "${ENV_PHP[@]+"${ENV_PHP[@]}"}"; do
            [[ -x "/etc/init.d/php${v}-fpm" ]] || hard "No /etc/init.d/php${v}-fpm - can't restart FPM ${v} without systemd"
        done
    else
        hard "Neither systemd nor service(8) available (PID 1 is ${init})" \
             "This script has to restart FPM and confirm it came back."
    fi

    local ct; ct="$(systemd-detect-virt --container 2>/dev/null || true)"
    [[ -z "$ct" || "$ct" == none ]] || caution "Running inside a container (${ct}) - AppArmor profiles usually have to be loaded from the host"

    local aa_on=0
    [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] && aa_on=1
    if [[ $aa_on -eq 1 ]]; then
        ok "AppArmor enabled in the kernel"
    elif [[ $MUTATES -eq 1 ]]; then
        hard "AppArmor isn't enabled in the kernel - the profile can't be loaded" \
             "To apply just the ini layer by hand: echo 'session.upload_progress.enabled = Off' > /etc/php/X.Y/fpm/conf.d/99-php2shell-mitigation.ini && $(svc_hint restart phpX.Y-fpm)"
    else
        caution "AppArmor isn't enabled in the kernel"
    fi
    [[ -e /sys/fs/selinux/enforce ]] && caution "SELinux is active - AppArmor and SELinux don't normally run together here"

    if command -v apparmor_parser >/dev/null; then
        ok "apparmor_parser present"
    elif [[ $CMD == apply ]]; then
        inf "apparmor package not installed - apply will install it"
        [[ -z "$(dpkg --audit 2>/dev/null)" ]] || caution "dpkg reports half-installed packages; installing apparmor may fail (dpkg --audit)"
    elif [[ $MUTATES -eq 1 ]]; then
        hard "apparmor_parser not installed - run apply first"
    fi

    local t missing=()
    for t in awk sed grep zgrep install mktemp readlink date; do
        command -v "$t" >/dev/null || missing+=("$t")
    done
    [[ ${#missing[@]} -eq 0 ]] || hard "Missing tools: ${missing[*]}"
}

env_check() {
    [[ "$CMD" =~ ^(apply|enforce|complain)$ ]] && MUTATES=1
    step "Environment check"
    if check_os; then
        check_php
        check_web
    else
        echo "      (skipping PHP and web server checks)"
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

# ---------- dispatch ---------------------------------------------------------
# Wrapped in main and ended with exit on the same line: bash parses all of
# main before running it, so re-downloading or editing this file while a run
# is in progress can't make bash read the rest from a shifted offset.
main() {
CMD="${1:-apply}"; [[ $# -gt 0 ]] && shift
ONLY_VER="${PHP_VER:-}"; FORCE=""; IGNORE_ENV=""
case "$CMD" in -h|--help) awk 'NR>2 && /^# =+$/ {exit} NR>2 {sub(/^# ?/, ""); print}' "$SELF"; exit 0 ;; --*) set -- "$CMD" "$@"; CMD=apply ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --php)   ONLY_VER="${2:?--php needs a version, e.g. 8.2}"; shift 2 ;;
        --php=*) ONLY_VER="${1#*=}"; shift ;;
        --force) FORCE=1; shift ;;
        --ignore-env) IGNORE_ENV=1; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$CMD" in check|apply|enforce|complain|status|cleanup|remove|hunt) ;; *) die "Unknown command: $CMD (check|apply|enforce|complain|status|cleanup|remove|hunt)" ;; esac

# hunt is global and read-only: it doesn't mitigate a version, it reads logs
# across all of them. Run it on its own, without the apply/enforce environment
# gate, and exit with its own status.
if [[ "$CMD" == hunt ]]; then
    cmd_hunt; exit $?
fi

env_check      # exits here for "check", or if the environment blocks the run
global_preflight

mapfile -t VERS < <(detect_versions)
if [[ -n "$ONLY_VER" ]]; then
    [[ " $SUPPORTED_VERS " == *" $ONLY_VER "* ]] || die "PHP $ONLY_VER not in SUPPORTED_VERS ($SUPPORTED_VERS)"
    [[ " ${VERS[*]} " == *" $ONLY_VER "* ]] || die "php-fpm${ONLY_VER} not installed (found: ${VERS[*]:-none})"
    VERS=("$ONLY_VER")
fi
[[ ${#VERS[@]} -gt 0 ]] || die "No supported php-fpm found (looked for: $SUPPORTED_VERS)"
info "PHP-FPM versions: ${VERS[*]}"

# Each version runs in its own subshell so one failure doesn't stop the rest
FAILED=()
for v in "${VERS[@]}"; do
    step "PHP ${v} - ${CMD}"
    set +e
    ( set -e; set_ver "$v"; "cmd_${CMD}" )
    rc=$?
    set -e
    [[ $rc -eq 0 ]] || FAILED+=("$v")
done

step "Summary"
for v in "${VERS[@]}"; do
    if [[ " ${FAILED[*]:-} " == *" $v "* ]]; then echo -e "  ${RED}✗${NC} PHP $v"; else echo -e "  ${GREEN}✓${NC} PHP $v"; fi
done
if [[ "$CMD" == apply ]]; then
    echo -e "\n${RED}REMINDER:${NC} new profiles start in complain mode (log only) until you run enforce."
fi
[[ ${#FAILED[@]} -eq 0 ]] || exit 1
}
main "$@"; exit
