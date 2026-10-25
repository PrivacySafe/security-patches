#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PHP session audit - CVE-2026-115560 preconditions  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Read-only. Changes nothing; root is optional but sees more.
#
# On 23 Oct 2026 PHP announced CVE-2026-115560: remote code execution through
# session upload progress when three things line up:
#
#   1. session.serialize_handler is php_binary or php_serialize in config,
#   2. application code switches it to "php" at runtime before session_start(),
#   3. session.upload_progress.enabled is still on.
#
# The fix ships in the next regular PHP release. Until then turning upload
# progress off (php2shell-mitigate.sh does) closes it. This script tells you
# whether the other two conditions exist on this server, so you know whether
# you were exposed and whether anything else depends on the switch:
#
#   * the configured handler and upload-progress setting for every PHP-FPM
#     version and pool, and for Apache mod_php, from the files PHP reads
#   * per-directory overrides: Apache php_value/php_flag, .htaccess, .user.ini
#   * application code that changes the serializer at runtime, through
#     ini_set('session.serialize_handler', ...) or session_start([...])
#   * pools or SAPIs that share one session.save_path with different
#     serializers (a session written in one format and read in another is the
#     shape of this bug class even without upload progress)
#
# Usage:
#   ./php-session-audit.sh            full report
#   WEB_ROOTS="/var/www /srv" ./php-session-audit.sh
#
# Exit: 0 = no precondition found, 1 = all three conditions met somewhere,
#       2 = partial match or something worth a look
#
# Env overrides:
#   WEB_ROOTS="/var/www /srv/www"   where to look for code and per-dir config
#   SCAN_DEPTH=10                   how deep to look
# =============================================================================
set -euo pipefail

SCRIPT_VERSION="1.0.1"
case "${1:-}" in
  -V|--version|version) echo "php-session-audit.sh ${SCRIPT_VERSION}"; exit 0 ;;
  -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; exit 0 ;;
  "") ;;
  *) echo "php-session-audit.sh: unknown argument: $1 (try --help)" >&2; exit 2 ;;
esac

WEB_ROOTS="${WEB_ROOTS:-/var/www /srv/www}"
SCAN_DEPTH="${SCAN_DEPTH:-10}"
CVE="CVE-2026-115560"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

RESULT=0
echo "php-session-audit.sh ${SCRIPT_VERSION} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
flag_partial() { [[ $RESULT -eq 1 ]] || RESULT=2; }

# Last value wins across php.ini and conf.d/*.ini, like PHP itself.
ini_get() {   # <key> <file>...
    local key="$1"; shift
    awk -v k="$key" '
        /^[[:space:]]*[;#]/ || /^[[:space:]]*\[/ { next }
        {
            line = $0; sub(/[[:space:]];.*$/, "", line)
            n = index(line, "="); if (!n) next
            name = substr(line, 1, n - 1); val = substr(line, n + 1)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", name)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
            gsub(/^"|"$/, "", val)
            if (name == k) v = val
        }
        END { if (v != "") print v }' "$@" 2>/dev/null
}

# Pool overrides: php_value[k] / php_admin_value[k] / *_flag[k]
pool_get() {   # <key> <pool file>
    awk -v k="$1" '
        /^[[:space:]]*;/ { next }
        match($0, /php(_admin)?_(value|flag)\[[^]]+\]/) {
            name = substr($0, RSTART, RLENGTH); sub(/^[^[]*\[/, "", name); sub(/\]$/, "", name)
            if (name != k) next
            val = $0; sub(/^[^=]*=/, "", val); gsub(/^[[:space:]]+|[[:space:]]+$/, "", val); gsub(/^"|"$/, "", val)
            v = val
        }
        END { if (v != "") print v }' "$2" 2>/dev/null
}

is_on() { [[ "${1,,}" =~ ^(1|on|true|yes)$ ]]; }
is_risky_handler() { [[ "$1" == php_binary || "$1" == php_serialize ]]; }

# ---------- configuration ----------------------------------------------------
declare -A SAVEPATH_HANDLERS=()   # save_path -> "handler@where ..."
RISKY_BASE=0; PROGRESS_ON=0; RECORDS=0

record() {   # <where> <handler> <progress> <save_path>
    local where="$1" h="$2" p="$3" sp="$4"
    local hp; if is_on "$p"; then hp="on"; else hp="off"; fi
    if is_risky_handler "$h" && [[ $hp == on ]]; then
        bad "${where}: serialize_handler=${h}, upload_progress=${hp}  (conditions 1 and 3)"
        RISKY_BASE=1; PROGRESS_ON=1
    elif is_risky_handler "$h"; then
        caution "${where}: serialize_handler=${h}, upload_progress=${hp}  (condition 1; 3 is closed)"
        RISKY_BASE=1
    elif [[ $hp == on ]]; then
        caution "${where}: serialize_handler=${h}, upload_progress=${hp}  (turn upload progress off: php2shell-mitigate.sh)"
        PROGRESS_ON=1
    else
        ok "${where}: serialize_handler=${h}, upload_progress=${hp}"
    fi
    SAVEPATH_HANDLERS["${sp:-<default>}"]+="${h}@${where// /+} "
    RECORDS=$((RECORDS + 1))
}

audit_sapi() {   # <version> <sapi dir name>
    local v="$1" sapi="$2" dir="/etc/php/$1/$2" files h p sp
    [[ -f "$dir/php.ini" ]] || return 0
    mapfile -t files < <(printf '%s\n' "$dir/php.ini"; find "$dir/conf.d" -maxdepth 1 -name '*.ini' 2>/dev/null | sort)
    h="$(ini_get session.serialize_handler "${files[@]}")"; h="${h:-php}"
    p="$(ini_get session.upload_progress.enabled "${files[@]}")"; p="${p:-On}"
    sp="$(ini_get session.save_path "${files[@]}")"
    if [[ "$sapi" == fpm ]]; then
        # What the binary actually loaded beats our reading of the files
        local info=""
        [[ -x "/usr/sbin/php-fpm$v" ]] && info="$("/usr/sbin/php-fpm$v" -i 2>/dev/null || true)"
        if [[ -n "$info" ]]; then
            h="$(awk -F' => ' '$1=="session.serialize_handler"{print $2; exit}' <<<"$info")"; h="${h:-php}"
            p="$(awk -F' => ' '$1=="session.upload_progress.enabled"{print $2; exit}' <<<"$info")"; p="${p:-On}"
            sp="$(awk -F' => ' '$1=="session.save_path"{print $2; exit}' <<<"$info")"
            [[ "$sp" == "no value" ]] && sp=""
        fi
        local pool ph pp psp name
        for pool in "/etc/php/$v/fpm/pool.d/"*.conf; do
            [[ -f "$pool" ]] || continue
            name="$(basename "$pool" .conf)"
            ph="$(pool_get session.serialize_handler "$pool")"
            pp="$(pool_get session.upload_progress.enabled "$pool")"
            psp="$(pool_get session.save_path "$pool")"
            record "PHP $v fpm pool ${name}" "${ph:-$h}" "${pp:-$p}" "${psp:-$sp}"
        done
    elif [[ "$sapi" == apache2 ]]; then
        [[ -n "$(compgen -G "/etc/apache2/mods-enabled/php${v}.load")" ]] || return 0
        record "PHP $v mod_php (base config)" "$h" "$p" "$sp"
    fi
}

step "Configured session settings"
shopt -s nullglob
for d in /etc/php/*/; do
    v="$(basename "$d")"
    [[ "$v" =~ ^[0-9]+\.[0-9]+$ ]] || continue
    for sapi in fpm apache2; do audit_sapi "$v" "$sapi"; done
done
shopt -u nullglob
[[ $RECORDS -gt 0 ]] || inf "no PHP-FPM pools or mod_php found under /etc/php"

step "Per-directory overrides"
re_keys='session\.(serialize_handler|upload_progress\.enabled|save_path)'
found_dir=0
if [[ -d /etc/apache2 ]]; then
    while IFS= read -r hit; do
        found_dir=1
        caution "Apache: ${hit}"
    done < <(grep -rnE "php_(admin_)?(value|flag)[[:space:]]+${re_keys}" /etc/apache2 2>/dev/null | cut -c1-200 || true)
fi
mapfile -t roots < <(for r in $WEB_ROOTS; do [[ -d "$r" ]] && echo "$r"; done)
if [[ ${#roots[@]} -gt 0 ]]; then
    while IFS= read -r hit; do
        found_dir=1
        case "$hit" in
            *.user.ini:*) caution ".user.ini: ${hit}  (read after the request body is parsed: it can't turn upload progress on or off, but it does set the base serializer)" ;;
            *) caution ".htaccess: ${hit}  (mod_php applies it before the request is parsed)" ;;
        esac
    done < <(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" \( -name .htaccess -o -name .user.ini \) -type f -print0 2>/dev/null \
             | xargs -0 -r grep -nHE "$re_keys" 2>/dev/null | cut -c1-200 || true)
fi
[[ $found_dir -eq 1 ]] && flag_partial
[[ $found_dir -eq 1 ]] || ok "no per-directory session overrides"

step "Code that switches the serializer at runtime (condition 2)"
SWITCH_TO_PHP=0; switches=""
if [[ ${#roots[@]} -eq 0 ]]; then
    caution "none of WEB_ROOTS exist (${WEB_ROOTS}); set WEB_ROOTS to your document and application roots"
    flag_partial
else
    # ini_set('session.serialize_handler', ...), ini_set("session.serialize_handler"...),
    # and session_start(['serialize_handler' => ...]) on one line
    switches="$(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" -type f \
                  \( -name '*.php' -o -name '*.inc' -o -name '*.phtml' -o -name '*.module' \) \
                  ! -path '*/.git/*' -size -2M -print0 2>/dev/null \
               | xargs -0 -r grep -nHE \
                  "ini_set[[:space:]]*\([[:space:]]*['\"]session\.serialize_handler['\"]|session_start[[:space:]]*\(.*['\"]serialize_handler['\"]" \
                  2>/dev/null | cut -c1-240 || true)"
    if [[ -z "$switches" ]]; then
        ok "no runtime serializer switch found under ${roots[*]}"
    else
        while IFS= read -r hit; do
            if grep -qE "['\"]php['\"][[:space:]]*[),]" <<<"${hit#*:*:}"; then
                bad "switches to \"php\": ${hit}"
                SWITCH_TO_PHP=1
            else
                caution "switches the serializer (value not a literal \"php\"; check it): ${hit}"
            fi
        done <<<"$switches"
        flag_partial
    fi
fi

step "Shared session storage"
shared=0
for sp in "${!SAVEPATH_HANDLERS[@]}"; do
    # distinct handlers writing to the same place
    hs="$(tr ' ' '\n' <<<"${SAVEPATH_HANDLERS[$sp]}" | sed '/^$/d' | cut -d@ -f1 | sort -u | tr '\n' ' ')"
    if [[ $(wc -w <<<"$hs") -gt 1 ]]; then
        shared=1
        caution "save_path ${sp} is shared by different serializers (${hs% }):"
        tr ' ' '\n' <<<"${SAVEPATH_HANDLERS[$sp]}" | sed '/^$/d' | sed 's/@/  ← /; s/+/ /g; s/^/      /'
    fi
done
if [[ $shared -eq 1 ]]; then
    echo "      Give each serializer its own save_path (or one serializer for all), so a session"
    echo "      written in one format is never read in another."
    flag_partial
else
    ok "no session.save_path is shared by different serializers"
fi

step "Verdict"
if [[ $RISKY_BASE -eq 1 && $SWITCH_TO_PHP -eq 1 && $PROGRESS_ON -eq 1 ]]; then
    RESULT=1
    bad "All three ${CVE} conditions are present on this server."
    echo "      Turn upload progress off now in server-level config and restart PHP:"
    echo "        sudo ./php2shell-mitigate.sh            (PHP-FPM; also writes the AppArmor layer)"
    echo "        or session.upload_progress.enabled = Off in php.ini / pool config / Apache, then restart"
    echo "      ini_set() and .user.ini can't do it: upload progress runs before your code."
    echo "      Then check the hunt output of php2shell-mitigate.sh for this host's history."
elif [[ $RISKY_BASE -eq 1 && $SWITCH_TO_PHP -eq 1 ]]; then
    caution "Conditions 1 and 2 are present, and upload progress is off: closed while it stays off."
    echo "      Keep it off until PHP ships the ${CVE} fix (php2shell-mitigate.sh cleanup keeps it off)."
elif [[ $RESULT -eq 0 && $PROGRESS_ON -eq 1 ]]; then
    caution "No ${CVE} precondition found, but upload progress is on. PHP still recommends turning it off."
    RESULT=2
elif [[ $RESULT -eq 0 ]]; then
    ok "No ${CVE} precondition found."
else
    caution "Partial match. Review the items above; none alone is the full ${CVE} chain."
fi
exit "$RESULT"

# Assisted-by: Claude Opus 5.5
