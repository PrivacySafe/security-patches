#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# libheif HEIF/AVIF decoder check  (v1)
# A heap buffer overflow in libheif's HEIF decoding (reached through
# ImageMagick on an attacker-supplied image) was used to get remote code
# execution on a Discourse forum and pivot further. The bug class spans many
# libheif CVEs with no single CVE for the Discourse case; the upstream commit
# shipped without one. Debian fixed a batch in DSA-6417-1 (libheif
# 1.19.8-1+deb13u1, trixie, 8 Aug 2026); other distributions backport under
# their own version strings, and some stable branches stayed vulnerable for a
# while. Upstream security releases have continued (1.21.0, 1.22.0, 1.22.1,
# 1.23.x). See https://www.hacktron.ai/blog/hacking-openai
#
# If this script is helpful please donate to PrivacySafe Foundation:
# https://privacysafe.foundation
#
# This is NOT the Ruby Regexp issue. For Ruby/GitLab, use
# ruby/ruby-regexp-oct2026-check.sh instead.
#
# Usage:
#   ./libheif-oct2026-check.sh [command]
#
#   check (default)  read-only: every libheif and libde265 on the host, the
#                    ImageMagick and libvips that reach them, every Discourse
#                    install (whose image-upload path runs an attacker-supplied
#                    file through ImageMagick into libheif), and container
#                    images, with whether each libheif carries the fixes. For
#                    a Discourse container it says whether a rebuild is needed
#                    rather than a restart. Root optional. Exit 0 = nothing
#                    exposed, 1 = a vulnerable libheif is reachable, 2 =
#                    something couldn't be read.
#   policy           read-only: whether ImageMagick's policy.xml still lets
#                    HEIC/HEIF/AVIF through. Disabling those coders is the
#                    interim fix when you can't patch libheif yet. Exit 0 =
#                    HEIF is blocked everywhere a policy was found, 1 = HEIF
#                    is still allowed, 2 = no policy found.
#   harden           write a managed block into ImageMagick's policy.xml that
#                    refuses the HEIC/HEIF/AVIF coders, so a crafted upload
#                    never reaches libheif through ImageMagick. Backs the file
#                    up first, is reversible with unharden, and is the one
#                    thing this script changes. Needs root. This is defence in
#                    depth, NOT a substitute for updating libheif.
#   unharden         remove that managed block and restore. Needs root. Only
#                    touches a block this script wrote.
#   mw-harden        block HEIF/HEIC/AVIF uploads in every MediaWiki found, by
#                    adding those MIME types to wgMimeTypeExclusions in
#                    LocalSettings.php, so a crafted upload is rejected by its
#                    detected type before the scaler runs. Backs up first,
#                    checks the result still parses as PHP, reversible with
#                    mw-unharden. Needs root. Application-level defence; the
#                    host libheif still needs updating.
#   mw-unharden      remove that MediaWiki block and restore. Needs root.
#   hunt             read-only: the journal and logs for image-processor
#                    crashes (ImageMagick/libheif/libde265 segfaults, HEIF
#                    decoder frames, repeated convert/magick aborts).
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# The real fix is to update libheif (and libde265) and rebuild anything that
# bundles it (Discourse containers especially); this script does not run that
# for you, because a package upgrade or a container rebuild is an operator's
# call to make and time. The only change it will make is the ImageMagick coder
# policy, and only when you ask for it with harden.
#
# Env overrides:
#   HEIF_FIXED_UPSTREAM=1.22.0        upstream floor the heap-write class is
#                                     fixed at (coarse: distro backports under
#                                     older numbers are judged by FIXED_BUILDS
#                                     and the package changelog first)
#   FIXED_BUILDS="1.19.8-1+deb13u1 1.17.6-1ubuntu4.6"
#                                     distro builds known to carry the fixes,
#                                     space-separated full versions
#   DISCOURSE_ROOT="/var/discourse"   where the Docker launcher lives
#   DISCOURSE_APP="/var/www/discourse"  where a bare-metal checkout lives
#   POLICY_PATHS="/etc/ImageMagick-6 /etc/ImageMagick-7 ..."
#                                     where policy looks for policy.xml
#   HUNT_SINCE="2026-07-01"           how far back hunt reads the journal
#   HUNT_LOGS="/var/log/nginx/*.log"  extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
KEY_REF="DSA-6417-1"
HEIF_FIXED_UPSTREAM="${HEIF_FIXED_UPSTREAM:-1.22.0}"
# Changelog entries that prove the fixes, used when a dpkg build is not in
# FIXED_BUILDS. Any one is enough.
CHANGELOG_MARKERS=(DSA-6417-1 CVE-2026-32740 CVE-2026-32741 CVE-2025-68431 CVE-2026-47178)
FIXED_BUILDS="${FIXED_BUILDS:-}"
DISCOURSE_ROOT="${DISCOURSE_ROOT:-/var/discourse}"
DISCOURSE_APP="${DISCOURSE_APP:-/var/www/discourse}"
POLICY_PATHS="${POLICY_PATHS:-/etc/ImageMagick-7 /etc/ImageMagick-6 /etc/ImageMagick /usr/local/etc/ImageMagick-7 /usr/local/etc/ImageMagick-6}"
MW_PATHS="${MW_PATHS:-/var/www/mediawiki /var/www/html /var/www/html/mediawiki /var/www/html/w /var/www/w /srv/mediawiki /srv/www/mediawiki /usr/share/mediawiki}"
# The HEIF-family MIME types MediaWiki detects. Blocking these rejects a
# crafted upload by its detected type, whatever extension it was given.
MW_HEIF_MIMES=("image/heif" "image/heic" "image/avif" "image/heif-sequence" "image/heic-sequence")
HUNT_SINCE="${HUNT_SINCE:-2026-07-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCRIPT_NAME="libheif-oct2026-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-10-23"
SELF="$0"
ADVISORY="https://www.hacktron.ai/blog/hacking-openai"
MARKER="managed-by: libheif-oct2026-check"
# Begin carries the version for humans; detection and stripping key on the
# version-independent MARKER so a block written by any version is recognised.
BLOCK_BEGIN="<!-- BEGIN ${MARKER} (v${SCRIPT_VERSION}) -->"
BLOCK_END="<!-- END ${MARKER} -->"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/libheif-oct2026}"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 1; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

is_root() { [[ $EUID -eq 0 ]]; }
have() { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- libheif discovery and versioning ---------------------------------
# One resolved path per line, for libheif or libde265 shared objects.
find_libs() {   # <soname-stem> -> paths
    local stem="$1" c
    {
        shopt -s nullglob
        for c in /usr/lib/*/"${stem}".so* /usr/lib/"${stem}".so* /usr/lib64/"${stem}".so* \
                 /usr/local/lib/*/"${stem}".so* /usr/local/lib/"${stem}".so* /lib/*/"${stem}".so* \
                 /opt/*/lib/"${stem}".so* /opt/*/*/lib/"${stem}".so*; do
            echo "$c"
        done
        shopt -u nullglob
        have ldconfig && ldconfig -p 2>/dev/null | grep -oE "/[^ ]*${stem}\.so[^ ]*" || true
    } | while read -r c; do [[ -e "$c" ]] && readlink -f "$c"; done | sort -u
}

# The real version is the soname's own version, which the package sets to the
# library version (libheif.so.1.19.7 is libheif 1.19.7). A shared object also
# carries unrelated X.Y.Z build strings from its dependencies, so grabbing the
# first string in the file is wrong. Prefer the resolved filename's trailing
# version; fall back to a standalone X.Y.Z string in the file. Reading either
# runs nothing.
lib_version() {   # <path> -> X.Y.Z or empty
    local real base v
    real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
    # libheif.so.1.19.7  ->  1.19.7 ; the final .so.N.N.N is the version
    base="$(basename "$real")"
    v="$(grep -oE '\.so\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$base" | sed 's/^\.so\.//' || true)"
    if [[ -z "$v" ]]; then
        # Not in the filename (a bare libheif.so symlink target, say): take a
        # standalone version-only string, which is how libheif stores its own.
        v="$(grep -aoE '^[0-9]+\.[0-9]+\.[0-9]+$' "$real" 2>/dev/null | head -1 || true)"
    fi
    echo "$v"
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# "<rc>|<explanation>": rc 0 = fixed, 1 = vulnerable, 2 = unknown
# A distro package can carry the fixes under an older upstream number, so a
# dpkg-owned library is judged on its package build first, then on the
# upstream floor. Nothing is executed.
heif_state() {   # <X.Y.Z> [path]
    local v="$1" p="${2:-}" pkg full f m
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if [[ -n "$p" ]]; then
        pkg="$(owner_pkg "$p")"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            for f in $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            local cl
            cl="/usr/share/doc/${pkg}/changelog.Debian.gz"
            if [[ -f "$cl" && "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]]; then
                for m in "${CHANGELOG_MARKERS[@]}"; do
                    if zgrep -q "$m" "$cl" 2>/dev/null; then echo "0|${pkg} ${full}: changelog lists ${m}"; return; fi
                done
            fi
            # dpkg-owned but no proof of the fix: upstream number can't clear a
            # distro build, because distros backport under old numbers.
            if ver_ge "$v" "$HEIF_FIXED_UPSTREAM"; then
                echo "2|${pkg} ${full} (upstream ${v} >= ${HEIF_FIXED_UPSTREAM} but the package changelog doesn't name the fixes; add the build to FIXED_BUILDS if you know it's patched)"
            else
                echo "1|${pkg} ${full} (upstream ${v} < ${HEIF_FIXED_UPSTREAM}, changelog doesn't name the fixes). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS"
            fi
            return
        fi
    fi
    # Not dpkg-owned (self-built, bundled, another distro): upstream floor only.
    if ver_ge "$v" "$HEIF_FIXED_UPSTREAM"; then echo "0|upstream ${v} >= ${HEIF_FIXED_UPSTREAM}"
    else echo "1|upstream ${v} < ${HEIF_FIXED_UPSTREAM}"; fi
}

# ImageMagick and libvips are how a web app reaches libheif. Report their
# version and whether they can even decode HEIF (no HEIF delegate = not a
# path to this bug through that tool).
tool_report() {
    local magick v heif
    for magick in magick convert; do
        have "$magick" || continue
        v="$("$magick" -version 2>/dev/null | grep -oE 'ImageMagick [0-9][^ ]*' | head -1 || true)"
        heif="$("$magick" -list format 2>/dev/null | grep -iE '^\s*HEIC|^\s*HEIF|^\s*AVIF' | tr -s ' ' | head -3 || true)"
        if [[ -n "$heif" ]]; then
            caution "${magick}: ${v:-present}, HEIF/AVIF decoding ENABLED (reaches libheif). Disable it in policy.xml as defence in depth: ${SELF} policy"
        else
            ok "${magick}: ${v:-present}, no HEIF/AVIF delegate (doesn't reach libheif)"
        fi
        break
    done
    if have vips; then v="$(vips --version 2>/dev/null | head -1 || true)"; inf "libvips present (${v:-?}): also links libheif; the library verdict above applies to it too"; fi
    return 0
}

# ---------- Discourse (an image-upload path into libheif) --------------------
discourse_installs() {   # "kind|where|version"
    local v
    if [[ -x "${DISCOURSE_ROOT}/launcher" || -d "${DISCOURSE_ROOT}/containers" ]]; then
        v=""
        [[ -r "${DISCOURSE_ROOT}/version" ]] && v="$(grep -oE '[0-9a-f]{7,40}|v?[0-9]+\.[0-9]+\.[0-9]+' "${DISCOURSE_ROOT}/version" | head -1 || true)"
        echo "docker|${DISCOURSE_ROOT}|${v}"
    fi
    local app f
    for app in "$DISCOURSE_APP" /home/*/discourse /srv/discourse; do
        f="${app}/lib/version.rb"
        [[ -r "$f" || -r "${app}/VERSION" ]] || continue
        v=""
        [[ -r "$f" ]] && v="$(grep -oE 'STRING *= *"[0-9.]+(\.beta[0-9]*)?"' "$f" | grep -oE '[0-9][0-9.]*' | head -1 || true)"
        [[ -z "$v" && -r "${app}/VERSION" ]] && v="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${app}/VERSION" | head -1 || true)"
        echo "source|${app}|${v}"
    done
    local rt img
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)discourse/(discourse|base):' | sort -u | while read -r img; do
            echo "${rt} image|${img}|"
        done
    done
}

# ---------- MediaWiki (another image-upload path into libheif) ---------------
# MediaWiki is a path to this bug only when it is configured for it: the
# scaler must be ImageMagick (not GD, its default when both exist), and HEIF
# must be an allowed upload type (not a default). So this reads LocalSettings
# rather than assuming. Reading a PHP config file is not executing it.
mw_installs() { for d in $MW_PATHS; do [[ -r "${d}/LocalSettings.php" ]] && echo "${d}/LocalSettings.php"; done; }

# Last assignment wins in PHP, so read the last one. Values are read as text,
# nothing is evaluated.
mw_last() {   # <file> <var-without-$>
    grep -oE "\\\$${2}[[:space:]]*=[^;]*" "$1" 2>/dev/null | tail -1 || true
}

# "uses_im|accepts_heif|version"  (1/0 flags, version may be empty)
mw_profile() {   # <LocalSettings.php>
    local f="$1" uses_im=0 accepts=0 ver="" a dir rl
    a="$(mw_last "$f" wgUseImageMagick)"
    [[ "$a" == *[Tt]rue* ]] && uses_im=1
    # An explicit convert command with ImageMagick not disabled also counts
    a="$(mw_last "$f" wgImageMagickConvertCommand)"
    [[ -n "$a" && "$(mw_last "$f" wgUseImageMagick)" != *[Ff]alse* ]] && uses_im=1
    # HEIF reachable if any heif-family extension is in wgFileExtensions
    if grep -oE '\$wgFileExtensions[^;]*' "$f" 2>/dev/null | grep -qiE "['\"](heif|heic|avif)['\"]"; then accepts=1; fi
    # Version from the sibling install (RELEASE-NOTES or includes/Defines)
    dir="$(dirname "$f")"
    for rl in "${dir}/includes/Defines.php" "${dir}/RELEASE-NOTES-"*; do
        [[ -r "$rl" ]] || continue
        ver="$(grep -oE "MW_VERSION'?,?[[:space:]]*'?[0-9]+\.[0-9]+(\.[0-9]+)?" "$rl" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)"
        [[ -n "$ver" ]] && break
    done
    echo "${uses_im}|${accepts}|${ver}"
}

# ---------- containers -------------------------------------------------------
# Report libheif inside running containers. Reading a file from an image or a
# container is not executing the app, and it is how a Discourse web container
# that still carries the old library gets caught: a web-interface update does
# not replace it, only a rebuild does.
container_libs() {   # "runtime|ref|kind|version"  kind = container|image
    local rt
    for rt in docker podman; do
        have "$rt" || continue
        local id name v
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'for p in /usr/lib/*/libheif.so* /usr/lib/libheif.so* /usr/local/lib/libheif.so*; do [ -e "$p" ] && { strings "$p" 2>/dev/null | grep -aoE "[0-9]+\.[0-9]+\.[0-9]+" | head -1; break; }; done' 2>/dev/null | head -1 || true)"
            [[ -n "$v" ]] && echo "${rt}|${name:-$id}|container|${v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 p v ps how any

    step "libheif on the host"
    any=0
    while read -r p; do
        [[ -n "$p" ]] || continue
        any=1
        v="$(lib_version "$p")"
        IFS='|' read -r ps how <<<"$(heif_state "$v" "$p")"
        case $ps in
            0) ok "${p}  ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "${p}  ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "${p}  ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
        esac
    done < <(find_libs libheif)
    [[ $any -eq 1 ]] || inf "no libheif found on the host (it may still live only inside a container, checked below)"

    # libde265 is the HEVC codec libheif calls for HEIC. It has its own CVE
    # history and its own fixed versions, so this script reports it but does
    # not judge it against the libheif floor. Update it from your distro too.
    local dp dv dpkg dfull
    while read -r dp; do
        [[ -n "$dp" ]] || continue
        dv="$(lib_version "$dp")"
        dpkg="$(owner_pkg "$dp")"
        dfull=""
        [[ -n "$dpkg" ]] && dfull="$(dpkg-query -W -f='${Version}' "$dpkg" 2>/dev/null || true)"
        inf "libde265: ${dp}  ${dv:-?}${dfull:+  (${dpkg} ${dfull})} - update it from your distro; judged by your distro advisory, not by this script"
    done < <(find_libs libde265)

    step "What reaches libheif"
    tool_report

    step "Discourse (image uploads run through ImageMagick into libheif)"
    local dkind dwhere dv n=0
    while IFS='|' read -r dkind dwhere dv; do
        [[ -n "$dkind" ]] || continue
        n=1
        case "$dkind" in
            docker)    caution "${dkind} ${dwhere}${dv:+  ${dv}}: libheif lives inside the web container. A web-interface update does NOT replace it. Rebuild: ${DISCOURSE_ROOT}/launcher rebuild app. The container section below reads the running library" ;;
            *" image") caution "${dkind} ${dwhere}: rebuild on a base image whose libheif carries the fixes" ;;
            *)         caution "${dkind} ${dwhere}${dv:+  Discourse ${dv}}: uses the host libheif above. If that is vulnerable, this forum is a path to it through image uploads" ;;
        esac
    done < <(discourse_installs)
    [[ $n -eq 1 ]] || inf "no Discourse install found (Docker launcher under ${DISCOURSE_ROOT}, checkout under ${DISCOURSE_APP}, or discourse images)"

    step "MediaWiki (image uploads run through ImageMagick into libheif)"
    local mf uses accepts mver mw_n=0
    while read -r mf; do
        [[ -n "$mf" ]] || continue
        mw_n=1
        IFS='|' read -r uses accepts mver <<<"$(mw_profile "$mf")"
        if [[ $uses -eq 1 && $accepts -eq 1 ]]; then
            bad "${mf}${mver:+  MediaWiki ${mver}}: uses ImageMagick AND accepts HEIF/HEIC/AVIF uploads. A crafted upload reaches the host libheif above. Block it at the wiki: sudo ${SELF} mw-harden"
            exposed=1
        elif [[ $uses -eq 1 ]]; then
            ok "${mf}${mver:+  MediaWiki ${mver}}: uses ImageMagick but HEIF/HEIC/AVIF is not in wgFileExtensions, so the wiki won't accept it. Keep it that way, or if you add it run: ${SELF} mw-harden"
        elif [[ $accepts -eq 1 ]]; then
            caution "${mf}${mver:+  MediaWiki ${mver}}: accepts HEIF uploads but ImageMagick isn't enabled (GD doesn't reach libheif). If you switch to ImageMagick, block HEIF first: ${SELF} mw-harden"
        else
            ok "${mf}${mver:+  MediaWiki ${mver}}: not a path to libheif (GD scaler and/or HEIF not accepted)"
        fi
    done < <(mw_installs)
    [[ $mw_n -eq 1 ]] || inf "no MediaWiki install found (looked under ${MW_PATHS}; set MW_PATHS if yours is elsewhere)"

    step "libheif inside running containers"
    local rt ref kind cv any_c=0
    if ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        while IFS='|' read -r rt ref kind cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r ps how <<<"$(heif_state "$cv")"
            case $ps in
                0) ok "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 1)  (${how}); rebuild the image/container, a restart won't change the library"; exposed=1 ;;
                *) caution "${rt} ${kind} ${ref}  libheif ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_libs)
        [[ $any_c -eq 1 ]] || inf "no running container exposes a readable libheif (or no permission to exec in them). Images that install it another way aren't detected"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable libheif found where this could read one" ;;
        1) warn "A vulnerable libheif is reachable. Update libheif and libde265, rebuild anything that bundles them (Discourse: ${DISCOURSE_ROOT}/launcher rebuild app), and disable untrusted HEIF/AVIF in ImageMagick: ${SELF} policy" ;;
        *) warn "Some libheif builds couldn't be judged. For a dpkg build, confirm against the distro advisory and add it to FIXED_BUILDS. Rerun as root to read more" ;;
    esac
    return "$rc"
}

# ---------- policy -----------------------------------------------------------
# HEIC/HEIF/AVIF are disabled when a <policy domain="coder" rights="none" ...>
# line names them (or a pattern that covers them). This is a read of the XML,
# not a parse of ImageMagick's effective policy, so it errs toward caution.
coder_blocked() {   # <file> <CODER> -> 0 if a none-rights policy names it
    local f="$1" coder="$2"
    grep -iE "<policy[^>]*domain=\"coder\"[^>]*rights=\"none\"[^>]*pattern=\"(\\{?(HEIC|HEIF|AVIF)[^\"]*|[*]|\\{[^\"]*(HEIC|HEIF|AVIF)[^\"]*)\"" "$f" 2>/dev/null \
        | grep -iqE "pattern=\"([*]|[^\"]*${coder})" && return 0
    return 1
}

# Every policy.xml this host has, one per line. Shared by policy/harden/unharden.
policy_files() {
    local d p
    {
        for p in $POLICY_PATHS; do
            [[ -d "$p" && -e "$p/policy.xml" ]] && echo "$p/policy.xml"
        done
        if have magick; then
            d="$(magick -list configure 2>/dev/null | awk '/CONFIGURE_PATH/{print $2}' | head -1 || true)"
            [[ -n "$d" && -e "$d/policy.xml" ]] && echo "$d/policy.xml"
        fi
    } | sort -u
}

cmd_policy() {
    step "ImageMagick HEIF/AVIF coder policy"
    local f found=0 allowed=0
    local -a files=()
    mapfile -t files < <(policy_files)
    [[ ${#files[@]} -gt 0 ]] || { caution "no readable policy.xml under ${POLICY_PATHS}. ImageMagick with no coder policy decodes HEIF by default, which is the exposed case"; return 2; }

    local c
    for f in "${files[@]}"; do
        [[ -n "$f" ]] || continue
        found=1
        local blocked=() open=()
        for c in HEIC HEIF AVIF; do
            if coder_blocked "$f" "$c"; then blocked+=("$c"); else open+=("$c"); fi
        done
        if [[ ${#open[@]} -eq 0 ]]; then
            ok "${f}: HEIC, HEIF and AVIF are disabled"
        else
            bad "${f}: still allows ${open[*]}${blocked:+ (blocks ${blocked[*]})}"
            allowed=1
        fi
    done
    echo
    echo "  To block the decode path as defence in depth, add inside <policymap> in policy.xml:"
    echo '      <policy domain="coder" rights="none" pattern="HEIC" />'
    echo '      <policy domain="coder" rights="none" pattern="HEIF" />'
    echo '      <policy domain="coder" rights="none" pattern="AVIF" />'
    echo "  This stops ImageMagick handing HEIF/AVIF to libheif. It is not a substitute for"
    echo "  updating libheif, and it won't help a caller that reaches libheif without ImageMagick."
    [[ $allowed -eq 1 ]] && echo "  To write this block for you (reversible): sudo ${SELF} harden"
    [[ $found -eq 1 ]] || return 2
    return "$allowed"
}

# ---------- harden / unharden (the only writes this script makes) ------------
need_root() { is_root || die "${1} needs root (it edits a config file owned by another user). Re-run with sudo"; }

backup_file() {   # <path> -> prints backup path
    local dst
    dst="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dst"
    cp -a "$1" "$dst/" || die "could not back up $1"
    echo "${dst}/$(basename "$1")"
}

# The managed block, indented to sit inside <policymap>.
managed_block() {
    printf '  %s\n' "$BLOCK_BEGIN"
    printf '  <policy domain="coder" rights="none" pattern="HEIC" />\n'
    printf '  <policy domain="coder" rights="none" pattern="HEIF" />\n'
    printf '  <policy domain="coder" rights="none" pattern="AVIF" />\n'
    printf '  %s\n' "$BLOCK_END"
}

# True if the file carries a managed block from any version of this script.
has_block() { grep -qF "BEGIN ${MARKER}" "$1" 2>/dev/null; }

# Print <file> with every managed block (from any version) removed. Matches
# markers as literal substrings via index(), never as regex, so the version
# in the BEGIN line and the ( ) and . in it can't break the match. A single
# blank line immediately before a BEGIN marker is dropped too, so repeated
# harden/unharden cycles don't accumulate blank lines.
strip_block() {   # <file>
    awk -v bm="BEGIN ${MARKER}" -v em="END ${MARKER}" '
        index($0, bm) {
            if (held != "" ) held = ""   # discard a blank line held before the block
            skip=1; next
        }
        skip && index($0, em) {skip=0; next}
        skip {next}
        # Buffer a blank line: emit it only once we know a BEGIN marker does not follow
        /^[[:space:]]*$/ {
            if (held != "") print held
            held=$0; next
        }
        { if (held != "") { print held; held="" } print }
        END { if (held != "") print held }
    ' "$1"
}

cmd_harden() {
    need_root harden
    step "Hardening ImageMagick against HEIF/AVIF decoding"
    local -a files=()
    mapfile -t files < <(policy_files)
    if [[ ${#files[@]} -eq 0 ]]; then
        # No policy.xml at all: ImageMagick decodes HEIF by default. Create one
        # in the first configured directory that exists.
        local p
        for p in $POLICY_PATHS; do [[ -d "$p" ]] && { files=("$p/policy.xml"); break; }; done
        [[ ${#files[@]} -gt 0 ]] || die "no ImageMagick config directory found under ${POLICY_PATHS}; set POLICY_PATHS"
        caution "no policy.xml found; creating ${files[0]}"
        { echo '<policymap>'; managed_block; echo '</policymap>'; } > "${files[0]}"
        ok "wrote ${files[0]} with the HEIF/AVIF block"
        return 0
    fi

    local f bak changed=0
    for f in "${files[@]}"; do
        [[ -w "$f" ]] || { caution "${f}: not writable, skipping"; continue; }
        if has_block "$f"; then
            # Refresh in place: drop the old managed block, re-insert current one
            inf "${f}: already has a managed block; refreshing it"
        fi
        bak="$(backup_file "$f")"
        local tmp; tmp="$(mktemp)"
        # Strip any existing managed block, then insert a fresh one before
        # </policymap> (or append a policymap if the file has none).
        strip_block "$f" > "$tmp"
        if grep -qiF '</policymap>' "$tmp"; then
            local blk; blk="$(managed_block)"
            awk -v blk="$blk" 'BEGIN{done=0}
                !done && /<\/policymap>/ {print blk; done=1}
                {print}
            ' "$tmp" > "${tmp}.2" && mv "${tmp}.2" "$tmp"
        else
            { echo '<policymap>'; managed_block; echo '</policymap>'; cat "$tmp"; } > "${tmp}.2" && mv "${tmp}.2" "$tmp"
            caution "${f}: had no <policymap>; added one"
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: HEIF/AVIF coders disabled (backup ${bak})"
    done
    echo
    if [[ $changed -eq 1 ]]; then
        info "ImageMagick will now refuse HEIC/HEIF/AVIF. Verify with: ${SELF} policy"
        inf "This is defence in depth. Still update libheif and rebuild anything that bundles it"
        inf "Reverse with: sudo ${SELF} unharden"
    else
        warn "nothing was changed (no writable policy.xml)"
        return 1
    fi
}

cmd_unharden() {
    need_root unharden
    step "Removing the managed HEIF/AVIF block"
    local -a files=()
    mapfile -t files < <(policy_files)
    local f bak changed=0 any=0
    for f in "${files[@]}"; do
        has_block "$f" || continue
        any=1
        [[ -w "$f" ]] || { caution "${f}: has the block but is not writable, skipping"; continue; }
        bak="$(backup_file "$f")"
        local tmp; tmp="$(mktemp)"
        strip_block "$f" > "$tmp"
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: managed block removed (backup ${bak})"
    done
    if [[ $any -eq 0 ]]; then
        inf "no managed block found; nothing of this script's to remove"
        inf "If you added the coder lines by hand, remove them by hand"
        return 0
    fi
    [[ $changed -eq 1 ]] && info "Done. Verify with: ${SELF} policy"
    return 0
}

# ---------- mw-harden / mw-unharden (MediaWiki-level upload block) ------------
# A managed PHP block appended to LocalSettings.php that adds the HEIF-family
# MIME types to wgMimeTypeExclusions (and its pre-1.37 name wgMimeTypeBlacklist),
# so MediaWiki rejects a crafted HEIF upload by its detected type, whatever
# extension it carries, before the scaler ever runs. It also drops heif/heic/
# avif from wgFileExtensions if present. This complements the host libheif
# update; it does not replace it.
mw_managed_block() {
    local m
    printf '\n// %s\n' "$BLOCK_BEGIN"
    printf '// Reject HEIF/HEIC/AVIF uploads: a crafted one can reach a libheif\n'
    printf '// heap overflow through ImageMagick. Remove with the matching unharden.\n'
    printf '$wgMimeTypeExclusions = array_values( array_unique( array_merge(\n'
    printf '\t( $wgMimeTypeExclusions ?? [] ),\n\t[\n'
    for m in "${MW_HEIF_MIMES[@]}"; do printf "\t\t'%s',\n" "$m"; done
    printf '\t]\n) ) );\n'
    # Pre-1.37 fallback name, honoured when the new one is absent
    printf 'if ( isset( $wgMimeTypeBlacklist ) ) {\n'
    printf '\t$wgMimeTypeBlacklist = $wgMimeTypeExclusions;\n}\n'
    # Drop the extensions from the allow-list if they were added
    printf 'if ( isset( $wgFileExtensions ) ) {\n'
    printf "\t\$wgFileExtensions = array_values( array_diff( \$wgFileExtensions, [ 'heif', 'heic', 'avif', 'heifs', 'heics' ] ) );\n}\n"
    printf '// %s\n' "$BLOCK_END"
}

# Insert text before a closing "?>" if the file has one, else append. A
# LocalSettings.php that ends inside PHP (no "?>") is the common case.
mw_insert() {   # <stripped-file> <block-text>  -> writes combined to stdout
    local f="$1" blk="$2"
    if grep -qE '^\s*\?>\s*$' "$f"; then
        awk -v blk="$blk" 'BEGIN{done=0}
            !done && /^[[:space:]]*\?>[[:space:]]*$/ {print blk; done=1}
            {print}
        ' "$f"
    else
        cat "$f"; printf '%s\n' "$blk"
    fi
}

cmd_mw_harden() {
    need_root mw-harden
    step "Blocking HEIF/HEIC/AVIF uploads in MediaWiki"
    local -a files=()
    mapfile -t files < <(mw_installs)
    [[ ${#files[@]} -gt 0 ]] || { warn "no LocalSettings.php found under ${MW_PATHS}; set MW_PATHS"; return 2; }
    local f bak changed=0 uses accepts mver
    for f in "${files[@]}"; do
        [[ -w "$f" ]] || { caution "${f}: not writable, skipping"; continue; }
        IFS='|' read -r uses accepts mver <<<"$(mw_profile "$f")"
        has_block "$f" && inf "${f}: already has a managed block; refreshing it"
        bak="$(backup_file "$f")"
        local tmp blk; tmp="$(mktemp)"; blk="$(mw_managed_block)"
        strip_block "$f" > "$tmp"
        mw_insert "$tmp" "$blk" > "${tmp}.2" && mv "${tmp}.2" "$tmp"
        # Refuse to install a file that no longer parses, if php is available
        if have php && ! php -l "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"; caution "${f}: edit would not parse as PHP; left unchanged (backup ${bak} kept)"; continue
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: HEIF/HEIC/AVIF uploads blocked (backup ${bak})"
        [[ $uses -eq 1 ]] || inf "    note: this wiki uses GD, not ImageMagick, so it wasn't a libheif path anyway; the block is harmless"
    done
    echo
    if [[ $changed -eq 1 ]]; then
        info "MediaWiki will now reject HEIF/HEIC/AVIF uploads by detected type. Verify with: ${SELF} check"
        inf "This is an application-level block. Still update the host libheif"
        inf "Reverse with: sudo ${SELF} mw-unharden"
    else
        warn "nothing was changed (no writable LocalSettings.php, or edits wouldn't parse)"
        return 1
    fi
}

cmd_mw_unharden() {
    need_root mw-unharden
    step "Removing the MediaWiki HEIF upload block"
    local -a files=()
    mapfile -t files < <(mw_installs)
    local f bak changed=0 any=0 tmp
    for f in "${files[@]}"; do
        has_block "$f" || continue
        any=1
        [[ -w "$f" ]] || { caution "${f}: has the block but is not writable, skipping"; continue; }
        bak="$(backup_file "$f")"
        tmp="$(mktemp)"
        strip_block "$f" > "$tmp"
        if have php && ! php -l "$tmp" >/dev/null 2>&1; then
            rm -f "$tmp"; caution "${f}: removal would not parse as PHP; left unchanged (backup ${bak} kept)"; continue
        fi
        cat "$tmp" > "$f"; rm -f "$tmp"
        changed=1
        ok "${f}: managed block removed (backup ${bak})"
    done
    [[ $any -eq 1 ]] || { inf "no managed block found; nothing of this script's to remove"; return 0; }
    [[ $changed -eq 1 ]] && info "Done. Verify with: ${SELF} check"
    return 0
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for image-processor crashes since ${HUNT_SINCE}"
    local jr; jr="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$jr'" RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >"$jr" || true; fi
    local -a files=()
    [[ -s "$jr" ]] && files+=("$jr")
    local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /var/discourse/shared/*/log/rails/production.log /var/www/*/log/*.log \
             /var/log/nginx/*.log /var/log/apache2/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "ImageMagick/convert/magick killed by a crash signal|(convert|magick|MagickCore|identify|mogrify)[^:]*\[[0-9]+\]: (segfault at|general protection|trap invalid opcode)"
        "libheif or libde265 frames in a crash/backtrace|(libheif|libde265|heif_|de265_|UncompressedImageCodec|unc_decoder|HeifPixelImage)"
        "service killed by SIGSEGV/SIGABRT (check which run image processing)|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
        "heap corruption abort near image decode|(double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned))"
        "repeated HEIF/HEIC/AVIF handling errors in app logs|(unable to read image|no decode delegate|corrupt image).*\.(heic|heif|avif)"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit is a lead, not proof: image decoders crash on genuinely broken files too. A"
    echo "  crash with libheif or libde265 frames on a vulnerable build, or a burst of HEIF"
    echo "  decode errors from one source before a worker died, is worth treating as an incident:"
    echo "  check what the process could reach (secrets, database credentials, tokens, and for a"
    echo "  forum its admin and session stores) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "reference: ${KEY_REF}; writeup: ${ADVISORY}"
case "$CMD" in
    check|policy|harden|unharden|hunt) "cmd_${CMD}" ;;
    mw-harden)   cmd_mw_harden ;;
    mw-unharden) cmd_mw_unharden ;;
    *) die "Unknown command: $CMD (check|policy|harden|unharden|mw-harden|mw-unharden|hunt|version)" ;;
esac
}
main "$@"; exit
