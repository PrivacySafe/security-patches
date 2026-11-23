#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Roller XML-RPC unauthenticated deserialization check/mitigate  (v1)
# CVE-2026-129448 CVE-2026-82384
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-129448 (CVSS 3.1 9.8, CWE-502 Deserialization of Untrusted Data),
# published 17 November 2026 by the Apache Software Foundation, found by
# n0mi1k and reported by Matt Raible. It is the same underlying bug as
# CVE-2026-82384 (published September 2026), which named only Roller 6.1.5
# as affected; the November advisory widens the affected range back to
# 4.0.0 and says the flaw is being actively exploited. CISA added it to the
# Known Exploited Vulnerabilities catalog on 20 November 2026.
#
# Roller's XML-RPC endpoint (POST /roller-services/xmlrpc, serving the
# legacy Blogger and MetaWeblog APIs) is configured with the XML-RPC
# library's enabledForExtensions option set to true, which makes it accept
# non-standard vendor value types, including one carrying a base64-encoded
# Java-serialized object. The servlet deserializes that object before any
# authentication check runs, so a suitable class on the server's classpath
# turns one unauthenticated POST into remote code execution. The servlet
# mapping for that path is present in every shipped web.xml regardless of
# any application-level setting; in particular, the per-site "XML-RPC"
# toggle in Roller's own admin UI (webservices.enableXmlRpc) does not gate
# this servlet in affected releases, because the deserialization happens
# before that setting is ever read. Fixed in Apache Roller 6.1.6 (11
# November 2026), which disables the vendor extension types outright and
# adds a servlet filter that rejects the request outright when the admin
# UI's XML-RPC toggle is off, so that toggle finally does what it always
# looked like it did. Roller 6.1.7 (the current release) also fixes
# CVE-2026-123374, an unrelated deserialization bug in weblog update ping
# responses, and 15 further, lower-severity issues; this script does not
# audit for any of those.
#
# Usage:
#   ./apache-roller-xmlrpc-check.sh [command] [...]
#
#   check     - read-only. Finds installed Roller web.xml files by finding
#               every Tomcat instance this host has, the same way this
#               collection's tomcat-oct2026-check.sh does: explicit
#               CATALINA_HOME/CATALINA_BASE, every running Java process's
#               -Dcatalina.home=/-Dcatalina.base= (which also catches an
#               install at a non-default path, and a CATALINA_BASE whose
#               webapps/ does not live under its CATALINA_HOME in a
#               multi-instance setup), then the usual filesystem locations
#               as a fallback for an install that is not currently running;
#               walks each one's webapps/ for a web.xml containing the
#               distinctive XML-RPC servlet mapping, or a path given with
#               ROLLER_WEBXML, and reports, for each one: whether the
#               enabledForExtensions setting is on, whether the
#               /roller-services/xmlrpc mapping is still present, and
#               whether the post-fix XmlRpcEnabledFilter (added in 6.1.6)
#               is there. That filter's presence is the one reliable
#               signal this script has for "patched 6.1.6 or later", since
#               a deployed WAR does not reliably carry its own version
#               number anywhere on disk; its absence does not by itself
#               confirm an old version; it means the signal could not be
#               found, same as a missing install. Exits 1 if any install
#               looks exposed (the mapping present, extensions enabled or
#               unchanged from the shipped default, and the fix filter
#               absent), 0 if every one found looks patched or already
#               worked around, 2 if none was found or the result could not
#               be determined.
#   hunt      - read-only. Greps readable Tomcat/httpd access logs for POST
#               requests to /roller-services/xmlrpc. A match is a strong
#               indicator something tried this endpoint, not proof it
#               carried the malicious payload, since the path is also used
#               for legitimate Blogger/MetaWeblog API clients where those
#               are actually in use; finding none does not prove nothing
#               happened, since a successful attack need not appear in any
#               log this script can reach.
#   mitigate [--remove-mapping] [--restart] [--dry-run] [--force] - edits
#               web.xml to set enabledForExtensions to false (the default
#               action), which is one of the two workarounds Apache's own
#               advisory names and, since it only turns off the dangerous
#               vendor extension type rather than the endpoint itself,
#               has no real cost to legitimate Blogger/MetaWeblog API
#               use; this action always runs. --remove-mapping instead
#               comments out the <servlet-mapping> for
#               /roller-services/xmlrpc, the other named workaround,
#               which does have a real cost: it takes the legitimate API
#               offline entirely. Because of that cost, --remove-mapping
#               by default only acts when 'check' would report a Roller
#               install here as exposed (never found, or a version signal
#               that could not be read, counts as not-yet-confirmed-fixed
#               for this purpose, not as clear); when every install found
#               is already confirmed fixed, it changes nothing and says
#               so, unless --force is given to remove the mapping anyway.
#               Backs up the file first and checks the result is still
#               well-formed XML, rolling back automatically if not.
#               Requires root (or whatever user owns the deployed webapp
#               directory), unless --dry-run is given, which prints a diff
#               of what would change for every web.xml found and writes
#               nothing, so it needs no privilege (and skips the exposure
#               gate on --remove-mapping, so you can preview the change
#               either way). Neither Tomcat nor any
#               other servlet container picks up a web.xml edit on its
#               own: the advisory says to restart Roller, and a context
#               reload is not reliably enough, since the servlet and
#               filter instances this bug involves are created once at
#               context start. --restart tries 'systemctl restart'
#               against a detected Tomcat unit;
#               without it, restart the container yourself once you're
#               satisfied with the result.
#   rollback [--restart] [--dry-run] - restores the web.xml mitigate
#               backed up. --dry-run prints which file would be restored
#               from which backup and writes nothing, so it needs no
#               privilege.
#               Requires root. --restart as above.
#   rules     - prints a short explanation with no side effects.
#   version   - prints this script's version.
#
# Environment: ROLLER_WEBXML, an explicit web.xml path (or space-separated
# list), checked before any discovered Tomcat instance. PSF_BACKUP_DIR,
# where backups and the restore manifest are kept (default
# /var/backups/psf-security-patches/apache-roller-xmlrpc).
#
# What this script cannot do: upgrade Roller. mitigate only closes the one
# path named in the advisory; it does not touch CVE-2026-123374 or the other
# issues 6.1.7 fixes, and it cannot tell you whether a deserialization
# already happened before you ran it.
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="apache-roller-xmlrpc-check.sh"
SCRIPT_VERSION="1.7.1"
SCRIPT_DATE="2026-11-22"
ADVISORY="https://lists.apache.org/thread/cc0jck13nb9vvcmzxzwotr6n16mx28z9"
PSF_TMP=()
trap '[ "${#PSF_TMP[@]}" -eq 0 ] || rm -f "${PSF_TMP[@]}"' EXIT

if [ -t 2 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED=$(tput setaf 1); GRN=$(tput setaf 2); YEL=$(tput setaf 3); BLU=$(tput setaf 4); RST=$(tput sgr0)
else
    RED=""; GRN=""; YEL=""; BLU=""; RST=""
fi
warn() { printf '%s[!]%s %s\n' "$RED" "$RST" "$1" >&2; }
note() { printf '%s[*]%s %s\n' "$YEL" "$RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
inf()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$1"; }
die()  { warn "$1"; exit 2; }

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT: stop unless root, and name the sudo command to run instead.
need_root() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then
        die "${1}: run it as root, for example: sudo ${SELF_CMD}"
    else
        die "${1}: run it as root (sudo is not installed here)"
    fi
}

BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/apache-roller-xmlrpc}"
MARKER='/roller-services/xmlrpc'
FILTER_NAME='XmlRpcEnabledFilter'

print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$0"; }

# catalina_roots: every CATALINA_HOME-or-CATALINA_BASE-shaped directory this
# host has, the same discovery this collection's tomcat-oct2026-check.sh
# uses: explicit CATALINA_HOME/CATALINA_BASE, every running Java process's
# -Dcatalina.home=/-Dcatalina.base= (the only way to find a non-default
# install location, and the only way to find a CATALINA_BASE that doesn't
# share its parent CATALINA_HOME's webapps/ in a multi-instance setup), then
# the usual filesystem locations as a fallback for an install that is not
# currently running.
catalina_roots() {
    local -a out=()
    local d p
    for d in "${CATALINA_HOME:-}" "${CATALINA_BASE:-}"; do [ -n "$d" ] && out+=("$d"); done
    if command -v ps >/dev/null 2>&1; then
        while read -r p; do [ -n "$p" ] && out+=("$p"); done \
            < <(ps -eo args 2>/dev/null | grep -oE -- '-Dcatalina\.(home|base)=[^ ]+' | cut -d= -f2- | sort -u)
    fi
    shopt -s nullglob
    for d in /opt/tomcat* /opt/apache-tomcat* /opt/*/tomcat* /opt/*/apache-tomcat* \
             /usr/share/tomcat* /usr/local/tomcat* /usr/local/apache-tomcat* \
             /srv/tomcat* /srv/apache-tomcat* /var/lib/tomcat* \
             /home/*/apache-tomcat* /home/*/tomcat*; do
        [ -d "$d" ] && out+=("$d")
    done
    shopt -u nullglob
    [ "${#out[@]}" -gt 0 ] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

# roller_webxml_roots: every web.xml under any discovered Tomcat root's
# webapps/ directory, plus an unpacked Apache distribution layout, plus
# anything named in ROLLER_WEBXML (space-separated explicit paths, checked
# first).
roller_webxml_roots() {
    local f root
    if [ -n "${ROLLER_WEBXML:-}" ]; then
        for f in $ROLLER_WEBXML; do [ -f "$f" ] && echo "$f"; done
    fi
    while IFS= read -r root; do
        [ -n "$root" ] || continue
        shopt -s nullglob
        for f in "$root"/webapps/*/WEB-INF/web.xml; do
            [ -f "$f" ] && echo "$f"
        done
        shopt -u nullglob
    done < <(catalina_roots)
    for f in /opt/apache-roller*/webapp/roller/WEB-INF/web.xml; do
        [ -f "$f" ] && echo "$f"
    done
}

# is_roller_webxml FILE: true if this web.xml carries the XML-RPC mapping,
# live or commented out by this script's own --remove-mapping (the one
# reliable, version-independent marker that this is a Roller deployment and
# not some other webapp that happens to live under webapps/).
is_roller_webxml() { grep -q "$MARKER" "$1" 2>/dev/null; }

# live_mapping FILE: true if an UNCOMMENTED <servlet-mapping>...</servlet-mapping>
# block naming MARKER is present. Plain grep cannot tell a live block from
# one this script's own --remove-mapping wrapped in "<!-- line -->" per
# line, so this walks the file and skips any line that is, after trimming,
# entirely an XML comment.
live_mapping() {
    awk -v marker="$MARKER" '
        {
            t=$0; gsub(/^[[:space:]]+|[[:space:]]+$/,"",t)
            iscomment = (t ~ /^<!--.*-->$/)
        }
        !iscomment && /<servlet-mapping>/ { capturing=1; buf=""; }
        capturing { buf = buf $0 "\n" }
        !iscomment && /<\/servlet-mapping>/ {
            if (capturing && buf ~ marker) { found=1 }
            capturing=0
        }
        END { exit (found ? 0 : 1) }
    ' "$1"
}

# xml_param_value FILE PARAM-NAME: the <param-value> of the <context-param>
# or <init-param> whose <param-name> is PARAM-NAME. Returns empty if absent.
xml_param_value() {
    awk -v name="$2" '
        /<(context-param|init-param)>/ { depth=1; pname=""; pval=""; next }
        depth==1 && /<param-name>/ {
            pname=$0; sub(/.*<param-name>/,"",pname); sub(/<\/param-name>.*/,"",pname)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",pname)
        }
        depth==1 && /<param-value>/ {
            pval=$0; sub(/.*<param-value>/,"",pval); sub(/<\/param-value>.*/,"",pval)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",pval)
        }
        /<\/(context-param|init-param)>/ {
            if (depth==1 && pname==name) { print pval; found=1 }
            depth=0
        }
        END { if (!found) exit 1 }
    ' "$1"
}

# xml_wellformed FILE: true if a Python or xmllint parser on this host
# accepts the file as well-formed XML; if neither is available, this check
# is skipped (returns true), same caveat as elsewhere in this collection
# when a verification tool is simply not present.
xml_wellformed() {
    if command -v xmllint >/dev/null 2>&1; then xmllint --noout "$1" 2>/dev/null; return $?; fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$1" 2>/dev/null; return $?
    fi
    return 0
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" 2>/dev/null || die "Could not create $BACKUP_DIR"; }

# check_one FILE: prints a verdict line for one web.xml and returns
# 0 clear, 1 exposed, 2 undetermined.
check_one() {
    local f="$1" ext mapping=0 filter=0
    inf "Roller web.xml: $f"
    if grep -q "<filter-name>${FILTER_NAME}</filter-name>" "$f" 2>/dev/null; then filter=1; fi
    if live_mapping "$f"; then mapping=1; fi
    ext="$(xml_param_value "$f" enabledForExtensions 2>/dev/null || true)"

    if [ "$filter" -eq 1 ]; then
        ok "The post-fix ${FILTER_NAME} is present: this looks like Roller 6.1.6 or later, which rejects the vendor-extension payload and gates the endpoint on the XML-RPC admin setting regardless of enabledForExtensions. Upgrading further, to 6.1.7, still gets you CVE-2026-123374's fix and 15 other issues; see the README."
        return 0
    fi
    if [ "$mapping" -eq 0 ]; then
        ok "No /roller-services/xmlrpc servlet mapping found in this file: the endpoint is not reachable here, whether by the --remove-mapping workaround or a deployment that never had it."
        return 0
    fi
    if [ "$ext" = "false" ]; then
        ok "enabledForExtensions is false: the workaround is applied. The servlet mapping is still present and the admin-UI XML-RPC toggle still does not gate this endpoint in an unpatched build, so this is a stopgap, not a fix; upgrade to 6.1.6 or later (6.1.7 current) when you can."
        return 0
    fi
    warn "Exposed: the /roller-services/xmlrpc mapping is present, enabledForExtensions is ${ext:-unset, which ships as true}, and the post-fix filter is absent. Treat this as CVE-2026-129448/CVE-2026-82384, regardless of what the install reports as its version, since a deployed WAR does not reliably carry a version string this script can read. Upgrade to 6.1.6 or later, or run 'mitigate'. Advisory: ${ADVISORY}"
    return 1
}

do_check() {
    local any=0 worst=0 f rc
    while IFS= read -r f; do
        is_roller_webxml "$f" || continue
        any=1
        check_one "$f"; rc=$?
        [ "$rc" -gt "$worst" ] && worst=$rc
        echo
    done < <(roller_webxml_roots | sort -u)
    if [ "$any" -eq 0 ]; then
        inf "No web.xml with a /roller-services/xmlrpc mapping found under the usual Tomcat webapps directories. If Roller runs from somewhere else, set ROLLER_WEBXML to its web.xml path(s), space-separated."
        return 2
    fi
    return "$worst"
}

do_hunt() {
    local any=0 f logs
    logs="$(ls /var/log/tomcat*/*.log /var/log/tomcat*/localhost_access_log*.txt \
              /var/log/apache2/*access*.log /var/log/httpd/*access*log 2>/dev/null | sort -u)"
    if [ -z "$logs" ]; then
        inf "No readable Tomcat or web-server access logs found in the usual locations."
        return 2
    fi
    for f in $logs; do
        local hit
        hit="$(grep -n 'POST[^"]*/roller-services/xmlrpc' "$f" 2>/dev/null)"
        if [ -n "$hit" ]; then
            any=1
            warn "Match in $f:"
            echo "$hit" | sed 's/^/      /'
        fi
    done
    if [ "$any" -eq 0 ]; then
        ok "No POST requests to /roller-services/xmlrpc found in the logs checked."
        return 0
    fi
    note "A match is not proof of the malicious payload specifically, only that something posted to this endpoint; a legitimate Blogger/MetaWeblog client would log the same way. Finding nothing does not prove nothing happened."
    return 1
}

backup_file() {
    local f="$1" rel base
    rel="$(echo "$f" | tr '/' '_')"
    base="${BACKUP_DIR}/${rel}.orig"
    [ -f "$base" ] || cp -a "$f" "$base" || die "Could not back up $f"
    echo "${f}	${base}" >> "${BACKUP_DIR}/.manifest.tsv"
}

do_mitigate() {
    local remove_mapping="${1:-0}" dry="${2:-0}" force="${3:-0}" changed=0 f
    if [ "$remove_mapping" -eq 1 ] && [ "$force" -ne 1 ] && [ "$dry" != "1" ]; then
        local exprc; do_check >/dev/null 2>&1; exprc=$?
        if [ "$exprc" -eq 0 ]; then
            note "Every Roller install found is already confirmed fixed (or the mapping is already gone), and --remove-mapping has a real cost beyond the default action: it takes the legitimate Blogger/MetaWeblog API offline entirely, not just the dangerous vendor extension type. Not changing anything; pass --force to remove the mapping anyway, or --dry-run to preview it. The default action (enabledForExtensions=false, no such cost) is not affected by this and runs normally without --remove-mapping."
            return 0
        fi
    fi
    [ "$dry" = "1" ] || need_root "mitigate changes the host"
    [ "$dry" = "1" ] || ensure_backup_dir
    while IFS= read -r f; do
        is_roller_webxml "$f" || continue
        local tmp
        tmp="$(mktemp)"; PSF_TMP+=("$tmp")
        if [ "$remove_mapping" -eq 1 ]; then
            awk -v marker="$MARKER" '
                BEGIN{skip=0}
                /<servlet-mapping>/ { buf=$0"\n"; capturing=1; next }
                capturing {
                    buf = buf $0 "\n"
                    if ($0 ~ /<\/servlet-mapping>/) {
                        capturing=0
                        if (buf ~ marker) {
                            n=split(buf, lines, "\n")
                            print "<!-- psf-security-patches CVE-2026-129448/CVE-2026-82384: mapping removed -->"
                            for (i=1;i<=n;i++) { if (lines[i] != "") print "<!-- " lines[i] " -->" }
                        } else {
                            printf "%s", buf
                        }
                        next
                    }
                    next
                }
                { print }
            ' "$f" > "$tmp"
        else
            awk -v marker="$MARKER" '
                BEGIN{depth=0}
                /<(context-param|init-param)>/ { depth=1; buf=$0"\n"; pname=""; next }
                depth==1 {
                    buf = buf $0 "\n"
                    if (/<param-name>/) { t=$0; sub(/.*<param-name>/,"",t); sub(/<\/param-name>.*/,"",t); gsub(/^[[:space:]]+|[[:space:]]+$/,"",t); pname=t }
                    if (/<\/(context-param|init-param)>/) {
                        depth=0
                        if (pname=="enabledForExtensions") {
                            gsub(/<param-value>[^<]*<\/param-value>/, "<param-value>false</param-value>", buf)
                        }
                        printf "%s", buf
                        next
                    }
                    next
                }
                { print }
            ' "$f" > "$tmp"
        fi
        if ! cmp -s "$f" "$tmp"; then
            if [ "$dry" = "1" ]; then
                inf "Would edit $f:"
                diff -u "$f" "$tmp" 2>/dev/null | sed -n '3,$p' | sed 's/^/      /'
                changed=1
                rm -f "$tmp"
                continue
            fi
            backup_file "$f"
            cp "$tmp" "$f"
            if xml_wellformed "$f"; then
                ok "Edited $f"
                changed=1
            else
                warn "$f is not well-formed XML after editing; rolling back this file."
                local base; base="$(grep "^${f}	" "${BACKUP_DIR}/.manifest.tsv" | tail -1 | cut -f2)"
                [ -n "$base" ] && cp -a "$base" "$f"
            fi
        fi
        rm -f "$tmp"
    done < <(roller_webxml_roots | sort -u)
    if [ "$dry" = "1" ]; then
        if [ "$changed" -eq 1 ]; then
            inf "Dry run: no files were changed."
        else
            inf "Dry run: nothing found that mitigate would change."
        fi
        return 0
    fi
    if [ "$changed" -eq 0 ]; then
        note "No change made. Either no Roller web.xml was found, every one found already looks patched or worked around, or the edit would not have changed anything (see 'check')."
        return 0
    fi
    note "web.xml changed on disk. Neither Tomcat nor any other container picks this up by itself for this bug: restart Roller's servlet container (or pass --restart to try it now), then re-run 'check'."
    return 0
}

restart_container() {
    [ "${RESTART:-0}" -eq 1 ] || return 0
    local u did=0
    if command -v systemctl >/dev/null 2>&1; then
        for u in $(systemctl list-unit-files 2>/dev/null | awk '/^tomcat[^ ]*\.service/{print $1}'); do
            systemctl restart "$u" && inf "restarted ${u}"; did=1
        done
    fi
    [ "$did" -eq 1 ] || note "--restart given but no systemd Tomcat unit was found: restart the container yourself."
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "${BACKUP_DIR}/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0
    tac "${BACKUP_DIR}/.manifest.tsv" 2>/dev/null | while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then
            inf "Would restore $orig from $backup"
        else
            cp -a "$backup" "$orig" && ok "Restored $orig" || { warn "Failed to restore $orig"; failed=1; }
        fi
    done
    return "$failed"
}

do_rules() {
    cat <<'RULES'
Apache Roller XML-RPC deserialization (CVE-2026-129448 / CVE-2026-82384)

Fix: upgrade to Apache Roller 6.1.6 or later (6.1.7 is current and also
fixes CVE-2026-123374 and 15 other issues).

If you cannot upgrade yet, Apache's own advisory names two workarounds,
either one sufficient on its own:

  1. In WEB-INF/web.xml, set the XmlRpcServlet's enabledForExtensions
     init-param to false (what this script's 'mitigate' does by default).
  2. Remove (or comment out) the <servlet-mapping> whose <url-pattern> is
     /roller-services/xmlrpc (what 'mitigate --remove-mapping' does).

Either way, restart Roller's servlet container: a context reload is not
reliably enough, since the affected servlet and its handler mapping are
built once when the context starts.

Disabling XML-RPC in Roller's own admin settings UI
(webservices.enableXmlRpc) does NOT help on an unpatched install: the
servlet deserializes the request before that setting is ever read. It is
only effective from 6.1.6 onward, where a new filter checks it first.
RULES
}

case "${1:-check}" in
    --help|-h) print_help; exit 0 ;;
esac

verdict() {
    printf '\n===== Verdict =====\n'
    case "$1" in
        0) ok "Not exposed, by what this check can see." ;;
        1) warn "Exposed: see the findings above. Upgrade, or preview the interim measure with 'mitigate --dry-run'." ;;
        *) note "Undetermined: no install was found, or not enough could be read to decide. See the notes above." ;;
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

case "${1:-check}" in
    check) do_check; rc=$?; verdict "$rc"; exit "$rc" ;;
    hunt) do_hunt; exit $? ;;
    mitigate)
        shift; remove_mapping=0; RESTART=0; dry=0; force=0
        for a in "$@"; do
            case "$a" in
                --remove-mapping) remove_mapping=1 ;;
                --restart) RESTART=1 ;;
                --dry-run) dry=1 ;;
                --force) force=1 ;;
                *) die "Unknown mitigate option: $a (--remove-mapping --restart --dry-run --force)" ;;
            esac
        done
        do_mitigate "$remove_mapping" "$dry" "$force"; rc=$?
        [ "$rc" != "0" ] || [ "$dry" = "1" ] || restart_container
        exit "$rc"
        ;;
    rollback)
        shift; RESTART=0; dry=0
        for a in "$@"; do
            case "$a" in
                --restart) RESTART=1 ;;
                --dry-run) dry=1 ;;
                *) die "Unknown rollback option: $a (--restart --dry-run)" ;;
            esac
        done
        do_rollback "$dry"; rc=$?
        [ "$rc" != "0" ] || [ "$dry" = "1" ] || restart_container
        exit "$rc"
        ;;
    rules) do_rules; exit 0 ;;
    version|--version|-V) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
    *) die "Usage: $0 {check|hunt|mitigate [--remove-mapping] [--restart] [--dry-run] [--force]|rollback [--restart] [--dry-run]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
