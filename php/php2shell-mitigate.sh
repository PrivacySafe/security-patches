#!/usr/bin/env bash
# =============================================================================
# PHP2Shell interim mitigation — PHP-FPM 8.1 / 8.2 / 8.3  (v3)
# CVE-2026-109618 / CVE-2026-109619
#
# If this script is helpful please donate to PrivacySafe Foundation: 
# https://privacysafe.foundation
#
# This script was released ahead of patches for two 0day vulns in php.
#
# Usage (as root):
#   ./php2shell-mitigate.sh [command] [--php X.Y] [--force]
#
#   apply (default)  drop-in + AppArmor profile, safe-load, per FPM version
#   enforce          switch profile(s) to enforce; refuses if complain mode
#                    logged unhandled accesses (override with --force)
#   complain         switch profile(s) back to complain
#   status           mitigation state and recent AppArmor events
#   cleanup          remove the ini drop-in once patched (--force to skip check)
#
#   --php X.Y        act on one version only (default: every installed
#                    version in SUPPORTED_VERS)
#
# Env overrides:
#   SUPPORTED_VERS="8.1 8.2 8.3"       versions this script will touch
#   PATCHED_8_1= PATCHED_8_2= PATCHED_8_3=8.3.36
#                                      first fixed upstream release per branch;
#                                      empty = rely on distro changelog CVE check
#   WEB_ROOTS="/var/www /srv/www"      read-only docroots
#   WRITABLE_PATHS="..."               rwk paths (uploads, cache)
#
# Debian/Ubuntu layout (distro packages, ondrej/sury PPA). Each version gets
# its own drop-in, profile, local override and backups; a failure on one
# version doesn't stop the others.
# =============================================================================

set -euo pipefail

# ---------- config -----------------------------------------------------------
SUPPORTED_VERS="${SUPPORTED_VERS:-8.1 8.2 8.3}"
CVES=(CVE-2026-109618 CVE-2026-109619)
declare -A PATCHED=(
    [8.1]="${PATCHED_8_1:-}"
    [8.2]="${PATCHED_8_2:-}"
    [8.3]="${PATCHED_8_3:-8.3.36}"
)
# Zend extension API dirs — fallback only; real value read from FPM
declare -A ABI=([8.1]=20210902 [8.2]=20220829 [8.3]=20230831)
declare -A EOL_NOTE=(
    [8.1]="PHP 8.1 is past upstream end of life; a fix may only arrive as a distro/PPA backport. Plan an upgrade."
)
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
    PATCHED_VER="${PATCHED[$PHP_VER]:-}"
    DEFAULT_EXT_DIR="/usr/lib/php/${ABI[$PHP_VER]:-}"
    HINT="--php ${PHP_VER}"
    FPM_INFO=""
    # Don't start services the admin had stopped; test config only
    if systemctl is-active --quiet "$FPM_SERVICE" || systemctl is-enabled --quiet "$FPM_SERVICE" 2>/dev/null; then
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
        if [[ " $SUPPORTED_VERS " == *" $v "* ]]; then
            echo "$v"
        else
            warn "Found php-fpm${v} — not in SUPPORTED_VERS (${SUPPORTED_VERS}); skipped" >&2
        fi
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

# Config test always; restart + reload (SIGUSR2 self re-exec) only for live services
fpm_health() {
    "$FPM_BIN" -t >/dev/null 2>&1 || return 1
    if [[ $SVC_LIVE -eq 0 ]]; then
        warn "$FPM_SERVICE is stopped and disabled — config tested only, not started"
        return 0
    fi
    systemctl restart "$FPM_SERVICE" >/dev/null 2>&1 || return 1
    sleep 2; systemctl is-active --quiet "$FPM_SERVICE" || return 1
    systemctl reload "$FPM_SERVICE" >/dev/null 2>&1 || return 1
    sleep 2; systemctl is-active --quiet "$FPM_SERVICE" || return 1
    local s
    for s in $(listen_sockets); do
        [[ -S "$s" ]] || { warn "Listen socket missing: $s"; return 1; }
    done
}

aa_events() {
    journalctl -k --since "$1" --no-pager 2>/dev/null \
      | grep -E 'apparmor="(DENIED|ALLOWED|AUDIT)"' \
      | grep -F "profile=\"${FPM_BIN}\"" || true
}

aa_event_summary() {
    aa_events "$1" \
      | sed -nE 's/.*apparmor="([A-Z]+)".*operation="([^"]+)".*name="([^"]+)".*requested_mask="([^"]+)".*/\1 \2 \4 \3/p' \
      | sort | uniq -c | sort -rn || true
}

is_managed() { [[ -f "$AA_PROFILE" ]] && grep -qF "$MARKER" "$AA_PROFILE"; }

current_mode() {
    if grep -qE "^${FPM_BIN} flags=\([^)]*complain" "$AA_PROFILE" 2>/dev/null; then echo complain; else echo enforce; fi
}

set_mode() {   # complain|enforce — written into the file so it survives reloads
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

is_patched() {
    local v; v="$(dpkg-query -W -f='${Version}' "php${PHP_VER}-fpm" 2>/dev/null || true)"
    [[ -n "$v" ]] || return 1
    v="${v#*:}"
    if [[ -n "$PATCHED_VER" ]] && dpkg --compare-versions "${v%%-*}" ge "$PATCHED_VER"; then
        return 0
    fi
    # Distro backport: upstream version unchanged, CVEs listed in changelog
    local cl c
    for cl in /usr/share/doc/php"${PHP_VER}"-fpm/changelog.Debian.gz /usr/share/doc/php"${PHP_VER}"-common/changelog.Debian.gz; do
        [[ -f "$cl" ]] || continue
        for c in "${CVES[@]}"; do zgrep -q "$c" "$cl" || continue 2; done
        return 0
    done
    return 1
}

patch_target() {
    if [[ -n "$PATCHED_VER" ]]; then echo "PHP ${PATCHED_VER}+ or a distro build listing ${CVES[*]}"
    else echo "a distro/PPA build listing ${CVES[*]} (no upstream fixed version set — PATCHED_${PHP_VER/./_})"; fi
}

global_preflight() {
    step "Preflight"
    [[ $EUID -eq 0 ]] || die "Must run as root (sudo $SELF)"
    command -v dpkg-query >/dev/null || die "Debian/Ubuntu (dpkg) layout required"
    if ! command -v apparmor_parser >/dev/null; then
        apt-get install -y --no-install-recommends apparmor || die "Could not install apparmor"
    fi
    aa-status --enabled 2>/dev/null || warn "AppArmor not enabled in the kernel — profiles will not apply"
}

ver_preflight() {
    [[ -x "$FPM_BIN" ]] || die "$FPM_BIN not found"
    [[ -d "$FPM_INI_DIR" ]] || die "$FPM_INI_DIR missing — unexpected PHP layout"
    [[ -z "${EOL_NOTE[$PHP_VER]:-}" ]] || warn "${EOL_NOTE[$PHP_VER]}"

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

    cat > "$out" <<AAEOF
${MARKER}
# AppArmor profile — php-fpm ${PHP_VER} — PHP2Shell interim mitigation
# Generated $(date -u +%FT%TZ) by ${SELF}. Regenerated on every run:
# put site-specific rules in ${AA_LOCAL} (never overwritten).
# Switch modes with: ${SELF} enforce ${HINT} | ${SELF} complain ${HINT}

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

  # Logs — derived from FPM config at generation time
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
  @{PROC}/@{pid}/{status,stat,cmdline,maps,mounts} r,
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
        mode=enforce; info "Existing profile is enforcing — keeping enforce mode"
    fi
    if [[ -f "$AA_PROFILE" ]] && ! is_managed; then warn "Replacing unmanaged profile (backed up below)"; fi

    TMP_PROFILE="$(mktemp /tmp/php2shell-aa.XXXXXX)"
    trap 'rm -f "${TMP_PROFILE:-}"' EXIT
    ensure_local
    write_profile "$TMP_PROFILE" "$mode"
    apparmor_parser -QK "$TMP_PROFILE" 2>&1 \
        || die "Generated profile failed to parse — nothing installed. Inspect: $TMP_PROFILE"
    info "Profile syntax OK"

    [[ -f "$AA_PROFILE" ]] && backup "$AA_PROFILE"
    install -m 0644 "$TMP_PROFILE" "$AA_PROFILE"
    info "Installed $AA_PROFILE ($mode)"

    if [[ -e "$AA_DISABLE" ]]; then
        warn "$AA_DISABLE exists — profile written but NOT loaded. Remove it and rerun to activate."
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
            die "FPM fails even in complain mode — profile unloaded so the service stays up. Check: journalctl -xeu $FPM_SERVICE"
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
    else warn "session.upload_progress.enabled = '${up:-unknown}' — drop-in not effective"; fi
    local loaded; loaded="$(aa-status 2>/dev/null | grep -cF "$FPM_BIN" || true)"
    info "AppArmor: $( [[ "$loaded" -gt 0 ]] && echo loaded || echo 'NOT loaded' ), file mode: $(current_mode)"
    if [[ $SVC_LIVE -eq 1 ]]; then
        systemctl is-active --quiet "$FPM_SERVICE" && info "$FPM_SERVICE active" || warn "$FPM_SERVICE NOT running"
    else
        info "$FPM_SERVICE stopped/disabled (left as found)"
    fi
    if is_patched; then info "php${PHP_VER}-fpm appears patched — run: ${SELF} cleanup ${HINT}"
    else warn "Not yet patched. Target: $(patch_target)"; fi
}

cmd_enforce() {
    is_managed || die "No managed profile at $AA_PROFILE — run ${SELF} ${HINT} first"
    local seen; seen="$(aa_event_summary '-24h' | grep -v ' exec ' || true)"
    if [[ -n "$seen" && -z "$FORCE" ]]; then
        warn "Complain mode logged these accesses in the last 24h (would be DENIED in enforce):"
        echo "$seen"
        die "Add legitimate paths to $AA_LOCAL, rerun ${SELF} ${HINT}, then retry. Or add --force"
    fi
    local since; since="$(date '+%Y-%m-%d %H:%M:%S')"
    set_mode enforce
    if ! fpm_health; then
        aa_event_summary "$since"
        set_mode complain; fpm_health || true
        die "FPM failed under enforce — reverted to complain. Add the paths above to $AA_LOCAL."
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
    echo "  AppArmor events, last 24h (count verdict op mask path):"
    local ev; ev="$(aa_event_summary '-24h')"
    if [[ -n "$ev" ]]; then sed 's/^/    /' <<<"$ev"; else echo "    none"; fi
}

cmd_cleanup() {
    if ! is_patched && [[ -z "$FORCE" ]]; then
        die "php${PHP_VER}-fpm doesn't look patched. Target: $(patch_target). Or add --force"
    fi
    if [[ -f "$DROP_IN_CONF" ]]; then
        backup "$DROP_IN_CONF"; rm -f "$DROP_IN_CONF"; info "Removed $DROP_IN_CONF"
    fi
    fpm_health || die "$FPM_SERVICE failed to restart after cleanup"
    info "Drop-in removed. AppArmor profile kept as defense-in-depth."
    echo "  To remove it too: apparmor_parser -R $AA_PROFILE && rm $AA_PROFILE"
}

# ---------- dispatch ---------------------------------------------------------
CMD="${1:-apply}"; [[ $# -gt 0 ]] && shift
ONLY_VER="${PHP_VER:-}"; FORCE=""
case "$CMD" in -h|--help) sed -n '2,30p' "$SELF"; exit 0 ;; --*) set -- "$CMD" "$@"; CMD=apply ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --php)   ONLY_VER="${2:?--php needs a version, e.g. 8.2}"; shift 2 ;;
        --php=*) ONLY_VER="${1#*=}"; shift ;;
        --force) FORCE=1; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done
case "$CMD" in apply|enforce|complain|status|cleanup) ;; *) die "Unknown command: $CMD (apply|enforce|complain|status|cleanup)" ;; esac

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
    step "PHP ${v} — ${CMD}"
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
