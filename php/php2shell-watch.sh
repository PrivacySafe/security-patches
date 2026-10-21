#!/usr/bin/env bash
# php2shell-watch 
# 2026-08-21: follow PHP/web logs live and flag php2shell-style trouble.
#
#   sudo ./php2shell-watch.sh            # watch here; Ctrl-C to stop
#   sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &   # background
#   tail -f /var/log/php2shell-watch.log # then watch it
#   LOGS="/a.log /b.log" ./php2shell-watch.sh   # watch specific files
#

set -uo pipefail

# Log files to follow. Globs; missing ones are skipped. Override with $LOGS.
GLOBS="${LOGS:-/var/log/php*-fpm.log /var/log/php-fpm.log /var/log/php/*.log /var/log/apache2/error.log /var/log/apache2/*error*.log /var/log/httpd/error_log /var/log/nginx/error.log}"

shopt -s nullglob
# shellcheck disable=SC2206
FILES=($GLOBS)
shopt -u nullglob
[ "${#FILES[@]}" -gt 0 ] || { echo "no log files found; set LOGS=\"file ...\"" >&2; exit 1; }

# Signatures (same as the mitigate script's hunt), with label and severity.
RES=(
  'exited on signal (6|7|11)[ (]'
  'AH00052|child pid [0-9]+ exit signal (Segmentation|Bus|Abort)'
  'zend_mm_heap corrupted|double free detected|free\(\): |malloc\(\): |corrupted (top size|size vs\. prev_size)'
  'Allowed memory size of [0-9]+ bytes exhausted|Out of memory \(alloc'
  'PHP_SESSION_UPLOAD_PROGRESS'
  '(php-fpm|php-cgi|apache2|httpd)[^ ]*.*(/bin/(ba)?sh|/dev/tcp/|fsockopen|mkfifo|nc |ncat |wget |curl .*(-o|http)|certutil|whoami|uname -a)'
)
LBL=("fpm worker crash" "apache worker crash" "allocator panic" "memory_limit fatal" "upload-progress field" "shell/tool from php")
SEV=("CRASH" "CRASH" "CORRUPT" "ATTACK" "ATTACK" "RESIDUE")
CNT=(0 0 0 0 0 0)

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
