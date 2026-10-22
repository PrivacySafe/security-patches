#!/usr/bin/env bash
# php2shell-watch - follow PHP/web logs live and flag php2shell-style trouble.
#
#   sudo ./php2shell-watch.sh            # watch here; Ctrl-C to stop
#   sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &   # background
#   tail -f /var/log/php2shell-watch.log # then watch it
#   LOGS="/a.log /b.log" ./php2shell-watch.sh   # watch specific files
#
# Prints one line per hit, and a count summary on stop.
# A hit is a lead, not proof: extensions crash workers too, and the
# upload-progress field is in legit forms. Only patching PHP fixes the bug.

set -uo pipefail

# Log files to follow. Globs; missing ones are skipped. Override with $LOGS.
GLOBS="${LOGS:-/var/log/php*-fpm.log /var/log/php-fpm.log /var/log/php/*.log /var/log/apache2/error.log /var/log/apache2/*error*.log /var/log/httpd/error_log /var/log/nginx/error.log}"

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
RES=(
  'exited on signal (6|7|11)[ (]'
  'AH00052|child pid [0-9]+ exit signal (Segmentation|Bus|Abort)'
  'zend_mm_heap corrupted|double free detected|free\(\): |malloc\(\): |corrupted (top size|size vs\. prev_size)'
  'AddressSanitizer: (attempting )?(double-free|heap-use-after-free|heap-buffer-overflow)|SUMMARY: AddressSanitizer|in (__zend_free|_efree|_emalloc|_erealloc)( |\()|zend_alloc\.c:[0-9]+'
  'php_cli_server_(dispatch|recv_event_read_request|do_event|poller)|PHP [0-9.]+ Development Server'
  'Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(alloc'
  'PHP_SESSION_UPLOAD_PROGRESS'
  '(php-fpm|php-cgi|apache2|httpd)[^ ]*.*(/bin/(ba)?sh|/dev/tcp/|fsockopen|mkfifo|nc |ncat |wget |curl .*(-o|http)|certutil|whoami|uname -a)'
  'p2s:[a-z]'
  'said into stderr[^"]*"[^"]*(ba)?sh:|(ba)?sh:( [0-9]+:)? .*(cannot (open|create)|No such file|[Ss]yntax error|unexpected (token|end))'
  'unserialize\(\): (Error|Function|Class|Extra)|__PHP_Incomplete_Class|session_decode\(\)|[Ff]ailed to decode session'
)
LBL=("fpm worker crash" "apache worker crash" "allocator panic" "asan/zend-alloc crash backtrace" "php -S dev server crash/exposure" "memory_limit fatal" "upload-progress field" "shell/tool from php" "p2s object-injection marker" "shell exec error from php" "php object injection / unserialize")
SEV=("CRASH" "CRASH" "CORRUPT" "CORRUPT" "CRASH" "ATTACK" "ATTACK" "RESIDUE" "RESIDUE" "RESIDUE" "ATTACK")
CNT=(0 0 0 0 0 0 0 0 0 0 0)

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Totals on stop; also stop the tailer.
summary() {
  echo "-- php2shell-watch stopped $(ts) --"
  local i
  for i in "${!LBL[@]}"; do printf '   %5d  %-8s %s\n' "${CNT[$i]}" "${SEV[$i]}" "${LBL[$i]}"; done
}
cleanup() { [ -n "${TAILER_PID:-}" ] && kill "$TAILER_PID" 2>/dev/null; summary; exit 0; }
trap cleanup INT TERM

echo "php2shell-watch $(ts): following ${#FILES[@]} file(s)" >&2
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
done
cleanup
