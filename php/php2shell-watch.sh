#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# php2shell-watch - follow PHP and web server logs live and flag trouble  (v1)
# CVE-2026-109618 / CVE-2026-109619
#
# If this script was helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Prints one line per hit, and a count summary on stop. A hit is a lead, not
# proof: extensions crash workers too, and the upload-progress field is in
# legit forms. Only patching PHP fixes the bug.
#
# Usage:
#   sudo ./php2shell-watch.sh            # watch here; Ctrl-C to stop
#   sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &   # background
#   tail -f /var/log/php2shell-watch.log # then watch it
#   LOGS="/a.log /b.log" ./php2shell-watch.sh   # watch specific files
# =============================================================================

set -uo pipefail

SCRIPT_VERSION="1.2.0"
case "${1:-}" in -V|--version) echo "php2shell-watch.sh ${SCRIPT_VERSION}"; exit 0 ;; esac

# Log files to follow. Globs; missing ones are skipped. Override with $LOGS.
# Access logs are included so the POST-500 -> worker-crash correlation can fire
# (see CORRELATE). Correlation needs the access log to record the worker PID;
# for Apache that means %P in the LogFormat. With no access log present the
# correlation stays off and the per-line signatures still work.
GLOBS="${LOGS:-/var/log/php*-fpm.log /var/log/php-fpm.log /var/log/php/*.log /var/log/apache2/error.log /var/log/apache2/*error*.log /var/log/httpd/error_log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/*access*.log /var/log/httpd/access_log /var/log/nginx/access.log}"
# Correlate POST-500 with a same-PID worker crash within this many seconds.
CORRELATE_WINDOW="${CORRELATE_WINDOW:-10}"

shopt -s nullglob
# shellcheck disable=SC2206
FILES=($GLOBS)
shopt -u nullglob
[ "${#FILES[@]}" -gt 0 ] || { echo "no log files found; set LOGS=\"file ...\"" >&2; exit 1; }

# Signatures (same as the mitigate script's hunt), with label and severity.
# The last three cover the serialized-object variant seen 2026-10-21: a PHP
# object (a gadget chain ending in system()) is sent in the upload-progress
# field, lands in the session file, and fires on the next page load. The
# payload itself travels in the POST body and sits in the session file, neither
# of which is a log, so these catch the attack only when it surfaces an error:
# the gadget chain spawning a shell, that shell failing, or the object failing
# to deserialize. The campaign marker 'p2s:s' (probe string <!--p2s:s-->) is
# the strongest tell; under bash the broken probe command echoes it into the
# FPM error log.
# The asan/zend-alloc and php-S entries cover the variant seen 2026-10-22: an
# allocator double-free (free -> __zend_free -> _efree, zend_alloc.c) reported by
# AddressSanitizer and reproduced through the built-in CLI server (php -S) with a
# crafted POST body. A sanitizer/debug build phrases the double-free differently
# from the glibc/Zend panic line, and prints its backtrace to the process's
# stderr - redirect php -S / FPM stderr into one of the watched files to see it.
# The CLI server is a dev tool, not the FPM path these CVEs target, and the
# mitigate script's AppArmor profile does not confine the `php` binary; treat a
# php-S hit as "a dev server is crashing / exposed", not as a contained event.
# The "in Unknown on line 0" entry covers a signal ReliaQuest reported from lab
# reproduction of CVE-2026-109618 (2026-10-22): during exploitation PHP reports
# the memory error in "Unknown on line 0" rather than naming an application file
# and line, because the failure happens inside PHP before an app file is in
# scope. A normal out-of-memory in application code names the file, so the
# Unknown-on-line-0 form is a stronger tell than the plain memory_limit fatal.
# Per that report, do not filter on the size of the failed allocation: the final
# one they observed was small.
# Correlation: ReliaQuest's strongest signal is a POST that returns HTTP 500
# followed within seconds by the worker that handled it crashing, tied together
# by the worker PID appearing in both the access and error logs. This script
# does that when an access log is among the watched files and records the PID
# (see CORRELATE below); it is off when no access log is present.
RES=(
  'exited on signal (6|7|11)[ (]'
  'AH00052|child pid [0-9]+ exit signal (Segmentation|Bus|Abort)'
  'zend_mm_heap corrupted|double free detected|free\(\): |malloc\(\): |corrupted (top size|size vs\. prev_size)'
  'AddressSanitizer: (attempting )?(double-free|heap-use-after-free|heap-buffer-overflow)|SUMMARY: AddressSanitizer|in (__zend_free|_efree|_emalloc|_erealloc)( |\()|zend_alloc\.c:[0-9]+'
  'php_cli_server_(dispatch|recv_event_read_request|do_event|poller)|PHP [0-9.]+ Development Server'
  'Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(alloc'
  '(Allowed memory size|Out of memory|Fatal error).*in Unknown on line 0|in Unknown on line 0'
  'PHP_SESSION_UPLOAD_PROGRESS'
  '(php-fpm|php-cgi|apache2|httpd)[^ ]*.*(/bin/(ba)?sh|/dev/tcp/|fsockopen|mkfifo|nc |ncat |wget |curl .*(-o|http)|certutil|whoami|uname -a)'
  'p2s:[a-z]'
  'said into stderr[^"]*"[^"]*(ba)?sh:|(ba)?sh:( [0-9]+:)? .*(cannot (open|create)|No such file|[Ss]yntax error|unexpected (token|end))'
  'unserialize\(\): (Error|Function|Class|Extra)|__PHP_Incomplete_Class|session_decode\(\)|[Ff]ailed to decode session'
)
LBL=("fpm worker crash" "apache worker crash" "allocator panic" "asan/zend-alloc crash backtrace" "php -S dev server crash/exposure" "memory_limit fatal" "memory error in Unknown on line 0" "upload-progress field" "shell/tool from php" "p2s object-injection marker" "shell exec error from php" "php object injection / unserialize")
SEV=("CRASH" "CRASH" "CORRUPT" "CORRUPT" "CRASH" "ATTACK" "ATTACK" "ATTACK" "RESIDUE" "RESIDUE" "RESIDUE" "ATTACK")
CNT=(0 0 0 0 0 0 0 0 0 0 0 0)

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now() { date -u +%s; }

# CORRELATE: a POST returning 500 seen in an access log arms the worker PID for
# CORRELATE_WINDOW seconds; a same-PID crash in an error log within the window
# emits a high-confidence hit. An access log that records the PID (Apache %P) is
# required; without one, POST_PID below never matches and the layer is inert.
declare -A POST_PID_TS=()   # pid -> epoch seconds it returned a POST 500
CORR_CNT=0
# A worker PID from an access-log line: Apache %P, or an FPM "pid NNNN" field.
line_pid() { [[ "$1" =~ (pid[=\ ]|\[pid\ )([0-9]{2,7}) ]] && echo "${BASH_REMATCH[2]}"; }

# Totals on stop; also stop the tailer.
summary() {
  echo "-- php2shell-watch stopped $(ts) --"
  local i
  for i in "${!LBL[@]}"; do printf '   %5d  %-8s %s\n' "${CNT[$i]}" "${SEV[$i]}" "${LBL[$i]}"; done
  printf '   %5d  %-8s %s\n' "$CORR_CNT" "ALERT" "POST-500 correlated with same-PID worker crash"
}
cleanup() { [ -n "${TAILER_PID:-}" ] && kill "$TAILER_PID" 2>/dev/null; summary; exit 0; }
trap cleanup INT TERM

echo "php2shell-watch ${SCRIPT_VERSION} $(ts): following ${#FILES[@]} file(s)" >&2
printf '   %s\n' "${FILES[@]}" >&2

# -q drops the ==> headers, -F survives rotation. exec so TAILER_PID is tail.
coproc TAILER { exec tail -qF "${FILES[@]}" 2>/dev/null; }

while IFS= read -r line <&"${TAILER[0]}"; do
  for i in "${!RES[@]}"; do
    if [[ $line =~ ${RES[$i]} ]]; then
      printf '%s  %-8s %s  |  %s\n' "$(ts)" "${SEV[$i]}" "${LBL[$i]}" "$line"
      CNT[$i]=$(( CNT[$i] + 1 ))
    fi
  done

  # CORRELATE, step 1: an access-log POST that returned 500 arms its PID.
  # Matches a request line with a POST and a 500 status; the PID comes from
  # Apache %P or an "pid NNNN" field on the same line.
  if [[ $line == *POST* && $line =~ \ 500\ |\"[0-9]+\ 500 ]]; then
    cpid="$(line_pid "$line")"
    [[ -n "$cpid" ]] && POST_PID_TS[$cpid]="$(now)"
  fi

  # CORRELATE, step 2: a crash line carrying a PID that armed recently fires.
  if [[ $line =~ (zend_mm_heap\ corrupted|AH00052|exit\ signal\ (Abort|Segmentation|Bus)|exited\ on\ signal\ (6|7|11)|in\ Unknown\ on\ line\ 0) ]]; then
    xpid="$(line_pid "$line")"
    if [[ -n "$xpid" && -n "${POST_PID_TS[$xpid]:-}" ]]; then
      if (( $(now) - POST_PID_TS[$xpid] <= CORRELATE_WINDOW )); then
        printf '%s  %-8s %s  |  pid %s: POST 500 then worker crash within %ss  |  %s\n' \
          "$(ts)" "ALERT" "php2shell POST-500 + same-PID crash" "$xpid" "$CORRELATE_WINDOW" "$line"
        CORR_CNT=$(( CORR_CNT + 1 ))
      fi
      unset 'POST_PID_TS[$xpid]'
    fi
  fi

  # Bound the map: drop armed PIDs older than the window (cheap, runs on crashes
  # and periodically via the access-log branch).
  if (( ${#POST_PID_TS[@]} > 256 )); then
    nows="$(now)"
    for k in "${!POST_PID_TS[@]}"; do
      (( nows - POST_PID_TS[$k] > CORRELATE_WINDOW )) && unset 'POST_PID_TS[$k]'
    done
  fi
done
cleanup

# Assisted-by: Claude Opus 5.5
