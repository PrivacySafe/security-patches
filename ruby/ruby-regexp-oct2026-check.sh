#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Ruby Regexp compilation fixes, October 2026: read-only checker  (v1)
# GitLab CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264
# Fixed in Ruby 4.0.9, 3.4.12 and 3.3.13 (23 Oct 2026) and in GitLab
# 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3 and 19.5.1
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Usage:
#   ./ruby-regexp-oct2026-check.sh [command]
#
#   check (default)  every Ruby runtime on the host (system packages, rbenv,
#                    rvm, chruby, asdf, mise, vendor-bundled Rubies under /opt),
#                    every running Ruby process (Puma, Sidekiq, Unicorn...),
#                    GitLab (Omnibus, source and container installs) and
#                    Discourse (Docker launcher and bare-metal installs),
#                    with whether each is fixed. Root optional (root sees
#                    every process). Exit 0 = nothing exposed, 1 = something
#                    unfixed is running or a bundled app is unfixed, 2 =
#                    something couldn't be read.
#   scan             application code that compiles regexps from strings:
#                    Regexp.new / Regexp.compile / Regexp.union and
#                    interpolated regexp literals, graded by whether the
#                    pattern is a literal, escaped, or worth reviewing.
#                    Exit 0 = nothing to review, 1 = findings.
#   hunt             the journal and Ruby and GitLab logs for Ruby crash
#                    reports, Onigmo frames in backtraces, heap corruption
#                    aborts and services killed by a crash signal.
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Everything here is read-only. Ruby has no in-process switch that blocks
# these bugs: Regexp.timeout doesn't, length limits don't, and interpolated
# literals compile without passing through any method a guard could wrap.
# The fix is the upgrade.
#
# This script never executes a Ruby binary. Versions are read from the
# binary's contents or from the libruby it links.
#
# Env overrides:
#   RUBY_FIXED_33=3.3.13 RUBY_FIXED_34=3.4.12 RUBY_FIXED_40=4.0.9
#   FIXED_BUILDS="3.3.8-2ubuntu1.2"    distro builds known to carry the fixes
#   GITLAB_FIXED="18.11.13 19.0.10 19.1.9 19.2.9 19.3.6 19.4.3 19.5.1"
#   DISCOURSE_ROOT="/var/discourse"   where the Docker launcher lives
#   DISCOURSE_APP="/var/www/discourse"  where a bare-metal checkout lives
#   SCAN_PATHS="/srv /opt /var/www /home /usr/local/lib"
#   SCAN_DEPTH=10                      how deep scan descends
#   SCAN_GEMS=0                        1 = also scan installed gems and
#                                      vendor/bundle (noisy, slow)
#   SCAN_SHOW=5                        findings printed per app and grade
#   HUNT_SINCE="2026-09-01"            how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"     extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES=(CVE-2026-89078 CVE-2026-93577 CVE-2026-97229 CVE-2026-110264)
declare -A RUBY_FIXED_DEFAULT=([3.3]=3.3.13 [3.4]=3.4.12 [4.0]=4.0.9)
ruby_fixed_for() { local n="RUBY_FIXED_${1//./}"; echo "${!n:-${RUBY_FIXED_DEFAULT[$1]:-}}"; }
FIXED_BUILDS="${FIXED_BUILDS:-}"
GITLAB_FIXED="${GITLAB_FIXED:-18.11.13 19.0.10 19.1.9 19.2.9 19.3.6 19.4.3 19.5.1}"
SCAN_PATHS="${SCAN_PATHS:-/srv /opt /var/www /home /usr/local/lib}"
SCAN_DEPTH="${SCAN_DEPTH:-10}"
SCAN_GEMS="${SCAN_GEMS:-0}"
SCAN_SHOW="${SCAN_SHOW:-5}"
HUNT_SINCE="${HUNT_SINCE:-2026-09-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
GITLAB_ROOT="${GITLAB_ROOT:-/opt/gitlab}"
DISCOURSE_ROOT="${DISCOURSE_ROOT:-/var/discourse}"
DISCOURSE_APP="${DISCOURSE_APP:-/var/www/discourse}"
SCRIPT_NAME="ruby-regexp-oct2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-23"
SELF="$0"
RUBY_ADVISORY="https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/"

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
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}NOT fixed${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- Ruby versions ----------------------------------------------------
# Ruby compiles its description ("ruby 3.4.11 (2026-07-14 revision ...)")
# into the binary or into libruby, so reading it runs nothing.
desc_version() {
    local v
    v="$(grep -aoE -m1 'ruby [0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)? \([0-9]{4}-[0-9]{2}-[0-9]{2}' "$1" 2>/dev/null | head -1 || true)"
    [[ -n "$v" ]] || return 0
    v="${v#ruby }"; v="${v%% *}"; echo "${v%%p*}"
}

# A shared build keeps the description in libruby. Find the library the
# binary names, next to it first, then in the system library paths.
libruby_for() {
    local bin="$1" so d c
    so="$(grep -aoE -m1 'libruby[-.0-9a-z]*\.so(\.[0-9]+)*' "$bin" 2>/dev/null | head -1 || true)"
    [[ -n "$so" ]] || return 0
    d="$(dirname "$(readlink -f "$bin")")"
    shopt -s nullglob
    for c in "$d/../lib/$so"* "$d/../lib64/$so"* /usr/lib/*/"$so"* /usr/lib/"$so"* /usr/lib64/"$so"* /usr/local/lib/"$so"*; do
        [[ -f "$c" ]] && { shopt -u nullglob; readlink -f "$c"; return 0; }
    done
    shopt -u nullglob
}

ruby_version() {   # <binary> -> X.Y.Z or empty
    local v lib
    v="$(desc_version "$1")"
    if [[ -z "$v" ]]; then
        lib="$(libruby_for "$1")"
        [[ -n "$lib" ]] && v="$(desc_version "$lib")"
    fi
    echo "$v"
}

# The dpkg package that owns a path, if any
owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# "<rc>|<explanation>": rc 0 = fixed, 1 = not fixed, 2 = unknown
ruby_state() {   # <X.Y.Z> [binary] [libruby]
    local v="$1" bin="${2:-}" lib="${3:-}" mm fixed pkg full f cl p
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    mm="${v%.*}"; fixed="$(ruby_fixed_for "$mm")"

    # A distro package can carry the fixes under the old upstream version, so
    # a dpkg-owned Ruby is judged on its package first. Debian ships the
    # interpreter as rubyX.Y and the engine (Onigmo included) in librubyX.Y.
    for p in "$bin" "$lib"; do
        [[ -n "$p" ]] || continue
        pkg="$(owner_pkg "$p")"; [[ -n "$pkg" ]] || continue
        full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
        for f in $FIXED_BUILDS; do
            if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
               && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                echo "0|${pkg} ${full} >= fixed build ${f}"; return
            fi
        done
        shopt -s nullglob
        for cl in "/usr/share/doc/${pkg}/changelog.Debian.gz" /usr/share/doc/libruby"${mm}"/changelog.Debian.gz; do
            [[ -f "$cl" ]] || continue
            # Only trust a changelog whose newest entry is the installed build
            [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]] || continue
            local c
            for c in "${CVES[@]}"; do
                if zgrep -q "$c" "$cl"; then shopt -u nullglob; echo "0|${pkg} ${full}: changelog lists ${c}"; return; fi
            done
        done
        shopt -u nullglob
        break
    done

    if [[ -n "$fixed" ]]; then
        if ver_ge "$v" "$fixed"; then echo "0|${v} >= ${fixed}"; else echo "1|${v} < ${fixed}${pkg:+ (${pkg} ${full}, changelog does not name the GitLab CVEs)}"; fi
        return
    fi
    if ver_ge "$v" "4.1.0"; then
        echo "2|${v} is newer than the 23 Oct releases: check the build includes ruby/ruby#13332, #19020 and #16801"
    elif [[ -n "${pkg:-}" ]]; then
        echo "1|${v} (${pkg} ${full}): Ruby ${mm} got no fixed release and the changelog doesn't name the GitLab CVEs"
    else
        echo "1|${v}: Ruby ${mm} got no fixed release. Move to 3.3.13, 3.4.12 or 4.0.9"
    fi
}

# Rubies bundled into a vendor's /opt tree get their fixes from that vendor,
# whatever version number they report. GitLab says it patched the Ruby it
# ships, so its embedded Ruby is judged by the GitLab version instead.
vendor_of() {
    case "$1" in
        "${GITLAB_ROOT}"/embedded/*) echo gitlab ;;
        /opt/*/embedded/*|/opt/puppetlabs/*) echo vendor ;;
        *) echo "" ;;
    esac
}

# ---------- discovery --------------------------------------------------------
find_runtimes() {
    local c
    {
        command -v -a ruby 2>/dev/null || true
        shopt -s nullglob
        for c in /usr/bin/ruby /usr/bin/ruby[0-9]* /usr/local/bin/ruby \
                 /opt/*/embedded/bin/ruby /opt/puppetlabs/puppet/bin/ruby \
                 /opt/rubies/*/bin/ruby /usr/local/rvm/rubies/*/bin/ruby \
                 /root/.rubies/*/bin/ruby /home/*/.rubies/*/bin/ruby \
                 /root/.rbenv/versions/*/bin/ruby /home/*/.rbenv/versions/*/bin/ruby \
                 /root/.rvm/rubies/*/bin/ruby /home/*/.rvm/rubies/*/bin/ruby \
                 /root/.asdf/installs/ruby/*/bin/ruby /home/*/.asdf/installs/ruby/*/bin/ruby \
                 /root/.local/share/mise/installs/ruby/*/bin/ruby /home/*/.local/share/mise/installs/ruby/*/bin/ruby; do
            echo "$c"
        done
        shopt -u nullglob
    } | while read -r c; do [[ -x "$c" && ! -d "$c" ]] && readlink -f "$c"; done | sort -u
}

# Running Ruby processes: "pid|exe|libruby|user|unit|stale|name"
find_procs() {
    local p pid exe base lib user unit stale name maps
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        exe="$(readlink "$p/exe" 2>/dev/null)" || continue
        base="$(basename "${exe% (deleted)}")"
        maps="$(grep -m1 'libruby' "$p/maps" 2>/dev/null || true)"
        [[ "$base" =~ ^ruby[0-9.]*$ || -n "$maps" ]] || continue
        lib=""; stale=0
        if [[ -n "$maps" ]]; then
            lib="${maps##* }"
            [[ "$maps" == *"(deleted)"* ]] && { stale=1; lib="$(awk '{print $6}' <<<"$maps")"; }
        fi
        [[ "$exe" == *"(deleted)" ]] && stale=1
        user="$(stat -c %U "$p" 2>/dev/null || echo '?')"
        unit="$(grep -oE '[^/]+\.(service|scope)' "$p/cgroup" 2>/dev/null | tail -1 || true)"
        name="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-60 || true)"
        echo "${pid}|${exe}|${lib}|${user}|${unit}|${stale}|${name}"
    done
}

# GitLab installs: "kind|where|version"
gitlab_installs() {
    local f v
    for f in "${GITLAB_ROOT}/embedded/service/gitlab-rails/VERSION" /home/git/gitlab/VERSION; do
        [[ -r "$f" ]] || continue
        v="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' "$f" | head -1 || true)"
        case "$f" in "${GITLAB_ROOT}"/*) echo "omnibus|${GITLAB_ROOT}|${v}" ;; *) echo "source|$(dirname "$f")|${v}" ;; esac
    done
    if [[ ! -r "${GITLAB_ROOT}/embedded/service/gitlab-rails/VERSION" && -r "${GITLAB_ROOT}/version-manifest.txt" ]]; then
        v="$(head -1 "${GITLAB_ROOT}/version-manifest.txt" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
        echo "omnibus|${GITLAB_ROOT}|${v}"
    fi
    local rt img
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)gitlab/gitlab-(ce|ee):' | sort -u | while read -r img; do
            v="$(grep -oE ':[0-9]+\.[0-9]+\.[0-9]+' <<<"$img" | tr -d ':' || true)"
            echo "${rt} image|${img}|${v}"
        done
    done
}

gitlab_state() {   # <X.Y.Z> -> "<rc>|<explanation>"
    local v="$1" mm f newest=""
    [[ -n "$v" ]] || { echo "2|version unreadable (a 'latest' tag, or no permission)"; return; }
    mm="${v%.*}"
    for f in $GITLAB_FIXED; do
        newest="$f"
        if [[ "${f%.*}" == "$mm" ]]; then
            if ver_ge "$v" "$f"; then echo "0|${v} >= ${f}"; else echo "1|${v} < ${f}"; fi
            return
        fi
    done
    # Lines newer than every fixed release shipped after the fixes
    if ver_ge "$mm.0" "${newest%.*}.1"; then echo "0|${v} is newer than ${newest}"; return; fi
    echo "1|${v}: GitLab ${mm} got no fixed release. CVE-2026-110264 affects every version from 7.0; move to a fixed line"
}

# Discourse installs: "kind|where|version|ruby"
# Discourse has published no Discourse-version fix for these Ruby CVEs: the
# fix is the Ruby it runs. So each install reports the Ruby that judges it,
# never a Discourse cutoff this script doesn't have.
#   docker   the launcher at DISCOURSE_ROOT. The app and its Ruby live inside
#            the web container, out of reach from the host, so ruby is left
#            empty and the running-process step judges it instead.
#   source   a bare-metal checkout at DISCOURSE_APP, judged by the Ruby in
#            its .ruby-version, or the system ruby if none is pinned.
discourse_installs() {
    local v rv
    if [[ -x "${DISCOURSE_ROOT}/launcher" || -d "${DISCOURSE_ROOT}/containers" ]]; then
        v=""
        [[ -r "${DISCOURSE_ROOT}/version" ]] && v="$(grep -oE '[0-9a-f]{7,40}|v?[0-9]+\.[0-9]+\.[0-9]+' "${DISCOURSE_ROOT}/version" | head -1 || true)"
        echo "docker|${DISCOURSE_ROOT}|${v}|"
    fi
    local app f
    for app in "$DISCOURSE_APP" /home/*/discourse /srv/discourse; do
        f="${app}/lib/version.rb"
        [[ -r "$f" || -r "${app}/VERSION" ]] || continue
        v=""
        [[ -r "$f" ]] && v="$(grep -oE 'STRING *= *"[0-9.]+(\.beta[0-9]*)?"' "$f" | grep -oE '[0-9][0-9.]*' | head -1 || true)"
        [[ -z "$v" && -r "${app}/VERSION" ]] && v="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${app}/VERSION" | head -1 || true)"
        rv=""
        [[ -r "${app}/.ruby-version" ]] && rv="$(grep -oE '[0-9]+\.[0-9]+\.[0-9]+' "${app}/.ruby-version" | head -1 || true)"
        echo "source|${app}|${v}|${rv}"
    done
    local rt img
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -E '(^|/)discourse/(discourse|base):' | sort -u | while read -r img; do
            echo "${rt} image|${img}||"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 bin v lib ps how vendor gl_bad=0 exposed=0

    step "GitLab"
    local kind where gv any=0
    while IFS='|' read -r kind where gv; do
        [[ -n "$kind" ]] || continue
        any=1
        IFS='|' read -r ps how <<<"$(gitlab_state "$gv")"
        case $ps in
            0) ok "${kind} ${where}  ${gv}  $(state_word 0)  (${how})" ;;
            1) bad "${kind} ${where}  ${gv}  $(state_word 1)  (${how})"
               echo "      CVE-2026-110264 and CVE-2026-97229 need no login. Upgrade now; there is no setting that turns this off"
               gl_bad=1 ;;
            *) caution "${kind} ${where}  $(state_word 2)  (${how})"; [[ $rc -eq 0 ]] && rc=2 ;;
        esac
    done < <(gitlab_installs)
    [[ $any -eq 1 ]] || inf "no GitLab install found (Omnibus under ${GITLAB_ROOT}, source under /home/git/gitlab, or gitlab/gitlab-ce|ee images)"

    step "Discourse"
    local dkind dwhere dv drv dps dhow
    any=0
    while IFS='|' read -r dkind dwhere dv drv; do
        [[ -n "$dkind" ]] || continue
        any=1
        if [[ -n "$drv" ]]; then
            IFS='|' read -r dps dhow <<<"$(ruby_state "$drv")"
            case $dps in
                0) ok "${dkind} ${dwhere}${dv:+  Discourse ${dv}}  Ruby ${drv}  $(state_word 0)  (${dhow})" ;;
                1) bad "${dkind} ${dwhere}${dv:+  Discourse ${dv}}  Ruby ${drv}  $(state_word 1)  (${dhow})"; exposed=1 ;;
                *) caution "${dkind} ${dwhere}${dv:+  Discourse ${dv}}  Ruby ${drv}  $(state_word 2)  (${dhow})"; [[ $rc -eq 0 ]] && rc=2 ;;
            esac
        else
            case "$dkind" in
                docker)   caution "${dkind} ${dwhere}${dv:+  ${dv}}: app Ruby runs inside the web container. Judged by the running process below, or run this script inside it: ${DISCOURSE_ROOT}/launcher enter app" ;;
                *" image") caution "${dkind} ${dwhere}: rebuild on a base image whose Ruby is 3.3.13, 3.4.12, 4.0.9 or later" ;;
                *)        caution "${dkind} ${dwhere}${dv:+  Discourse ${dv}}: no pinned Ruby found; judged by the system Ruby above and the running process below" ;;
            esac
        fi
    done < <(discourse_installs)
    if [[ $any -eq 1 ]]; then
        [[ $exposed -eq 1 ]] && inf "Discourse compiles patterns from admin and user input (watched words, search, theme and automation settings), so an unfixed Ruby is reachable. Upgrade the Ruby it runs, then restart it"
        inf "Note: this is the Ruby Regexp issue, not the separate Discourse libheif/ImageMagick image-upload RCE. For that, rebuild the container (${DISCOURSE_ROOT}/launcher rebuild app)"
    else
        inf "no Discourse install found (Docker launcher under ${DISCOURSE_ROOT}, checkout under ${DISCOURSE_APP}, or discourse/discourse|base images)"
    fi

    step "Ruby runtimes on disk"
    is_root || caution "not root: other users' version managers and processes may be hidden"
    local found=0 disk_bad=0
    while read -r bin; do
        [[ -n "$bin" ]] || continue
        found=1
        v="$(ruby_version "$bin")"; lib="$(libruby_for "$bin")"; vendor="$(vendor_of "$bin")"
        if [[ -z "$v" ]]; then caution "${bin}: version unreadable"; [[ $rc -eq 0 ]] && rc=2; continue; fi
        case "$vendor" in
            gitlab) inf "${bin}  ${v}  GitLab's own Ruby, patched by GitLab: judged by the GitLab version above"; continue ;;
            vendor) caution "${bin}  ${v}  bundled by a vendor: its fix comes from that vendor's update, not from Ruby's version number"; continue ;;
        esac
        IFS='|' read -r ps how <<<"$(ruby_state "$v" "$bin" "$lib")"
        case $ps in
            0) ok "${bin}  ${v}  $(state_word 0)  (${how})" ;;
            1) bad "${bin}  ${v}  $(state_word 1)  (${how})"; disk_bad=$((disk_bad + 1)) ;;
            *) caution "${bin}  ${v}  $(state_word 2)  (${how})" ;;
        esac
    done < <(find_runtimes)
    [[ $found -eq 1 ]] || inf "no Ruby runtime found in the usual places"

    step "Running Ruby processes"
    local pid exe user unit stale name running=0 where
    while IFS='|' read -r pid exe lib user unit stale name; do
        [[ -n "$pid" ]] || continue
        running=1
        where="pid ${pid} (${user}${unit:+, ${unit}}) ${name}"
        vendor="$(vendor_of "${exe% (deleted)}")"
        v="$(desc_version "/proc/${pid}/exe")"
        [[ -z "$v" && -n "$lib" && -r "$lib" ]] && v="$(desc_version "$lib")"
        if [[ "$vendor" == gitlab ]]; then
            if [[ $stale -eq 1 ]]; then caution "${where}  GitLab, running code replaced on disk since start: gitlab-ctl restart"
            else inf "${where}  GitLab: judged by the GitLab version above"; fi
            continue
        fi
        if [[ "$vendor" == vendor ]]; then caution "${where}  ${v:-?}  vendor-bundled Ruby: check that vendor's update"; continue; fi
        IFS='|' read -r ps how <<<"$(ruby_state "$v" "${exe% (deleted)}" "$lib")"
        if [[ $stale -eq 1 ]]; then
            caution "${where}  Ruby replaced on disk since start: restart it to run the new code${unit:+ (systemctl restart ${unit})}"
            exposed=1
        elif [[ $ps -eq 0 ]]; then
            ok "${where}  ${v}  $(state_word 0)"
        elif [[ $ps -eq 1 ]]; then
            bad "${where}  ${v}  $(state_word 1)  (${how})"; exposed=1
        else
            caution "${where}  ${v:-?}  $(state_word 2)  (${how})"
        fi
    done < <(find_procs)
    [[ $running -eq 1 ]] || inf "no running Ruby processes"

    step "What this check can't see"
    inf "Rubies inside containers: each image carries its own. Rebuild on ruby:3.3.13, 3.4.12, 4.0.9 or later"
    inf "Whether an app compiles attacker-controlled patterns at all: run '${SELF} scan'"
    inf "Ruby requested no CVEs for these fixes, so scanners keyed on Ruby CVEs show nothing. Track the GitLab CVEs"

    step "Verdict"
    [[ $exposed -eq 1 || $gl_bad -eq 1 ]] && rc=1
    case $rc in
        0) info "Nothing running is exposed to ${CVES[*]}"
           [[ $disk_bad -eq 0 ]] || warn "...but ${disk_bad} installed Ruby runtime(s) are unfixed. Upgrade them before something starts them" ;;
        1) [[ $gl_bad -eq 1 ]] && warn "GitLab is unfixed: upgrade it first, it is reachable without a login"
           [[ $exposed -eq 1 ]] && warn "Unfixed Ruby is running. It matters if the app compiles patterns from user input: see '${SELF} scan'" ;;
        *) warn "Some versions couldn't be read; rerun as root" ;;
    esac
    return "$rc"
}

# ---------- scan -------------------------------------------------------------
# Grades, per matched line:
#   review   the pattern comes from a variable or expression: find where it
#            comes from. If a user can set it, that app is exposed until Ruby
#            is upgraded.
#   escaped  the dynamic part goes through Regexp.escape/quote, or is a
#            Regexp.union of strings (union escapes strings). Far smaller
#            surface, still compiled, still worth a look.
# Literal patterns are skipped.
# Regexes live in variables: inside [[ =~ ]] quotes and braces get mangled
RX_LIT="('[^']*'|\"[^\"#]*\"|/[^/#]*/|%r\{[^}#]*\})"
RX_NEW="Regexp\.(new|compile)[[:space:](]+"
RX_NEW_LIT="${RX_NEW}${RX_LIT}[[:space:]]*[,)]"
RX_UNION_LIT="Regexp\.union[[:space:](]*\[?[[:space:]]*${RX_LIT}([[:space:]]*,[[:space:]]*${RX_LIT})*[[:space:]]*\]?[[:space:]]*\)?[[:space:]]*$"
RX_ESC='Regexp\.(escape|quote)'
RX_COMMENT='^[[:space:]]*#'
grade_line() {   # <code line> -> review|escaped|skip
    local l="$1"
    [[ "$l" =~ $RX_COMMENT ]] && { echo skip; return; }
    if [[ "$l" =~ $RX_NEW ]]; then
        [[ "$l" =~ $RX_NEW_LIT ]] && { echo skip; return; }
        if [[ "$l" =~ $RX_ESC ]]; then echo escaped; else echo review; fi
        return
    fi
    if [[ "$l" == *Regexp.union* ]]; then
        [[ "$l" =~ $RX_UNION_LIT ]] && { echo skip; return; }
        echo escaped; return
    fi
    # Interpolated literal: /...#{...}/ or %r{...#{...}}
    if [[ "$l" == *'#{'* ]]; then
        if [[ "$l" =~ $RX_ESC ]]; then echo escaped; else echo review; fi
        return
    fi
    echo skip
}

app_root() {   # nearest directory up from a file holding a Gemfile
    local d; d="$(dirname "$1")"
    while [[ "$d" != / && "$d" != . ]]; do
        [[ -f "$d/Gemfile" || -f "$d/gems.rb" ]] && { echo "$d"; return; }
        d="$(dirname "$d")"
    done
    dirname "$1"
}

cmd_scan() {
    step "Ruby code that compiles regexps from strings"
    local -a roots=() prune=()
    local p
    for p in $SCAN_PATHS; do [[ -d "$p" ]] && roots+=("$p"); done
    [[ ${#roots[@]} -gt 0 ]] || { warn "none of SCAN_PATHS exist (${SCAN_PATHS})"; return 0; }
    # GitLab's own tree is judged by its version; gems are opt-in
    prune=( -path "${GITLAB_ROOT}" -o -name .git -o -name node_modules -o -name tmp -o -name log )
    [[ "$SCAN_GEMS" == 1 ]] || prune+=( -o -path '*/vendor/bundle' -o -path '*/gems/*' -o -path '*/.gem' -o -path '*/.rbenv' -o -path '*/.rvm' -o -path '*/.asdf' -o -path '*/.local/share/mise' )
    local list; list="$(mktemp)"; local hits; hits="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$list' '$hits'" RETURN
    find "${roots[@]}" -maxdepth "$SCAN_DEPTH" \( "${prune[@]}" \) -prune -o -type f \
         \( -name '*.rb' -o -name '*.rake' -o -name '*.erb' -o -name '*.haml' -o -name '*.slim' -o -name '*.ru' \) -print 2>/dev/null >"$list" || true
    [[ -s "$list" ]] || { inf "no Ruby source under ${roots[*]}"; return 0; }
    inf "$(wc -l <"$list") Ruby files under ${roots[*]}$([[ "$SCAN_GEMS" == 1 ]] || echo ', gems skipped (SCAN_GEMS=1 to include)')"

    local f ln code g
    while IFS= read -r f; do
        { grep -nE 'Regexp\.(new|compile|union)|/[^/]*#\{[^}]+\}[^/]*/|%r[{(<\[|!].*#\{' "$f" 2>/dev/null || true; } | while IFS= read -r ln; do
            code="${ln#*:}"
            g="$(grade_line "$code")"
            [[ "$g" == skip ]] && continue
            printf '%s\t%s\t%s:%s\n' "$(app_root "$f")" "$g" "$f" "$(cut -c1-160 <<<"$ln")"
        done
    done <"$list" >"$hits"

    if [[ ! -s "$hits" ]]; then ok "no dynamic regexp compilation found"; return 0; fi
    local app n_r n_e
    cut -f1 "$hits" | sort -u | while read -r app; do
        n_r="$(awk -F'\t' -v a="$app" '$1==a && $2=="review"' "$hits" | wc -l)"
        n_e="$(awk -F'\t' -v a="$app" '$1==a && $2=="escaped"' "$hits" | wc -l)"
        local rv=""; [[ -f "$app/.ruby-version" ]] && rv=" (.ruby-version $(head -1 "$app/.ruby-version"))"
        echo
        if [[ $n_r -gt 0 ]]; then bad "${app}${rv}: ${n_r} to review, ${n_e} escaped"
        else caution "${app}${rv}: ${n_e} escaped, none to review"; fi
        awk -F'\t' -v a="$app" '$1==a && $2=="review"' "$hits" | head -n "$SCAN_SHOW" | cut -f3 | sed 's/^/      review   /'
        awk -F'\t' -v a="$app" '$1==a && $2=="escaped"' "$hits" | head -n "$SCAN_SHOW" | cut -f3 | sed 's/^/      escaped  /'
    done
    echo
    echo "  For each 'review' line, trace where the pattern comes from. If a user can supply it"
    echo "  (params, CI config, saved filters, webhooks, search syntax), that app is exposed until"
    echo "  its Ruby is fixed. The interim fix is in the app: stop compiling the user's text, or"
    echo "  pass it through Regexp.escape so it is matched literally. This is a grep: it misses"
    echo "  patterns built across several lines and can flag interpolated strings that aren't regexps."
    grep -q $'\treview\t' "$hits" && return 1
    return 0
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for Ruby crashes since ${HUNT_SINCE}"
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
             /var/log/gitlab/puma/current /var/log/gitlab/puma/puma_stderr.log /var/log/gitlab/sidekiq/current \
             /var/log/gitlab/gitlab-rails/exceptions_json.log /var/log/gitlab/gitlab-rails/production.log \
             /srv/*/log/*.log /srv/*/shared/log/*.log /var/www/*/log/*.log /var/www/*/shared/log/*.log \
             $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "Ruby crash report ([BUG])|\[BUG\] (Segmentation fault|Bus Error|Illegal instruction|Aborted|.*corrupt)"
        "Onigmo or Regexp frames in a backtrace|(onig_compile|onig_new|onig_reg_init|onig_search|rb_reg_initialize|rb_reg_new_str|rb_reg_prepare_re|regparse\.c|regcomp\.c|parse_exp|compile_tree)"
        "heap corruption abort|(double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned)|corrupted size vs\. prev_size)"
        "kernel: Ruby process segfault/GPF|(ruby|puma|sidekiq|unicorn|bundle|rails)[^:]*\[[0-9]+\]: (segfault at|general protection|trap invalid opcode)"
        "unit killed by SIGSEGV/SIGABRT (any service; check which run Ruby)|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
        "RegexpError in app or GitLab logs (pattern probing leaves these)|RegexpError"
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
    echo "  A hit is a lead, not proof: native gems crash Ruby too, and RegexpError is ordinary when"
    echo "  users type bad patterns. A crash with Onigmo frames on an unfixed Ruby, or a burst of"
    echo "  RegexpError from one source before a worker died, is worth treating as an incident:"
    echo "  check what the process could reach (secrets, database credentials, tokens, GitLab runner"
    echo "  registration and CI variables) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "advisory: ${RUBY_ADVISORY}"
case "$CMD" in
    check|scan|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|scan|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
