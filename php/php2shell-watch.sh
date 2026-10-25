#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# php2shell-watch - follow PHP and web server logs live and flag trouble  (v1)
# CVE-2026-109618 / CVE-2026-109619
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Prints one line per hit, and a count summary on stop. A hit is a lead, not
# proof: extensions crash workers too, and the upload-progress field is in
# legit forms. Only patching PHP fixes the bug.
#
# Design notes, from a 24 October 2026 honeypot report by the phpot project
# (35 confirmed shell executions on single-worker Apache mod_php):
# https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md
#   * The stages of that chain answered HTTP 200, and the final request, the
#     one that starts the shell, never reached the access log because the worker
#     died. The POST-500 correlation below cannot see that. The pre-script-OOM
#     then same-worker-crash correlation and the per-client OOM burst can.
#   * The strongest signal in that report was process-level: an Apache worker
#     starting /bin/sh. Logs only show the residue, so this script also polls
#     /proc for shells and tools that appear under a web worker (PROCS=0 to
#     turn off). It is a poller: a process that starts and exits between two
#     samples is missed, and one whose worker has already died is re-parented
#     and no longer links to it. For a guarantee use execve auditing (auditd,
#     eBPF) instead; this is the cheap version.
#   * Request fingerprints and source IPs are weak, fast-aging signals: an
#     attacker changes them. They are here as extra leads, not as protection.
#   * The q-parameter fingerprint matches both the short numbered form
#     (?q0=v&q1=v&q2=v...) and the seven-digit form, because different clients
#     used different ones. A process this script flags shows its TCP peers
#     (the phpot report's shells tried to call out), and a POST with a very
#     large response, or a PHPSESSID value thousands of characters long, is
#     flagged as a LEAD: the disclosure stage returned a PHPSESSID of 819,200
#     bytes decoded (about 2 MB on the wire).
#   * The per-client burst and the same-worker chain alert need the error-log
#     line to carry the worker PID and the client address. Apache's own error
#     log does; PHP's own error_log file format ("[23-Oct-2026 09:08:35 UTC]
#     PHP Fatal error: ...") carries neither, so those two alerts cannot fire
#     from it. The plain per-line signature still does. The first such line
#     prints a one-time NOTE.
#   * nginx's "upstream sent too big header" error is flagged as a LEAD. At
#     default fastcgi buffer sizes nginx refuses a leak-sized Set-Cookie with a
#     502 and that line, so on nginx it is the counterpart of the oversized
#     response size the access log cannot show. Large legitimate headers raise
#     it too.
#
# Usage:
#   sudo ./php2shell-watch.sh            # watch here; Ctrl-C to stop
#   sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &   # background
#   tail -f /var/log/php2shell-watch.log # then watch it
#   LOGS="/a.log /b.log" ./php2shell-watch.sh   # watch specific files
# =============================================================================

set -uo pipefail

SCRIPT_VERSION="1.4.3"
case "${1:-}" in
  -V|--version|version) echo "php2shell-watch.sh ${SCRIPT_VERSION}"; exit 0 ;;
  -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; exit 0 ;;
  "") ;;
  *) echo "php2shell-watch.sh: unknown argument: $1 (try --help; settings are environment variables)" >&2; exit 2 ;;
esac

# Log files to follow. Globs; missing ones are skipped. Override with $LOGS.
# Access logs are included so the POST-500 -> worker-crash correlation can fire
# (see CORRELATE). Correlation needs the access log to record the worker PID;
# for Apache that means %P in the LogFormat. With no access log present the
# correlation stays off and the per-line signatures still work.
GLOBS="${LOGS:-/var/log/php*-fpm.log /var/log/php-fpm.log /var/log/php/*.log /var/log/apache2/error.log /var/log/apache2/*error*.log /var/log/httpd/error_log /var/log/nginx/error.log /var/log/apache2/access.log /var/log/apache2/*access*.log /var/log/httpd/access_log /var/log/nginx/access.log}"
# Correlate POST-500 with a same-PID worker crash within this many seconds.
CORRELATE_WINDOW="${CORRELATE_WINDOW:-10}"
# Pre-script OOM ("Unknown on line 0") followed by a crash of the SAME worker
# within this many seconds fires the chain alert. The confirmed chain took ~7 s
# end to end; retries stretch it, so the default is generous.
CHAIN_WINDOW="${CHAIN_WINDOW:-120}"
# This many pre-script OOMs from one client within OOM_CLIENT_WINDOW seconds
# fires the burst alert. Needs the client address in the error log line (Apache
# "[client IP:port]", nginx "client: IP,").
OOM_CLIENT_THRESHOLD="${OOM_CLIENT_THRESHOLD:-2}"
OOM_CLIENT_WINDOW="${OOM_CLIENT_WINDOW:-60}"
# Source addresses reported in confirmed exploitation (phpot, 2026-10-24).
# Addresses age fast and a hit only means the address touched you; check what
# it sent. Set WATCH_IPS="" to turn the signature off, or add your own.
WATCH_IPS="${WATCH_IPS-15.204.59.70 162.35.99.94}"
# Process watch: report NEW shells and tools that appear under a web worker.
PROCS="${PROCS:-1}"
PROC_INTERVAL="${PROC_INTERVAL:-1}"
# Cmdline characters to print for a flagged process (0 = omit the arguments,
# which can carry secrets on hosts whose apps legitimately shell out).
PROC_CMD_MAX="${PROC_CMD_MAX:-160}"
# Extended regex; a flagged process whose cmdline matches is ignored. Use it
# for apps that legitimately shell out, e.g. PROC_ALLOW='convert|sendmail'.
PROC_ALLOW="${PROC_ALLOW:-}"
# Oversized-response leads. The disclosure stage of the confirmed chain returned
# a PHPSESSID of 819,200 bytes decoded (about 2 MB on the wire). A log line shows that only if it
# records the response cookie, or the response size WITH headers: Apache's %O
# (the default "combined" format on Debian and Ubuntu uses it) or nginx's
# $bytes_sent. Formats that count the body only (Apache %b, nginx's default
# $body_bytes_sent) cannot show it. Do not log the cookie itself to get this:
# it is leaked process memory. COOKIE_MAX is the PHPSESSID length flagged and
# RESP_BYTES_MAX the POST response size flagged; 0 turns a check off.
COOKIE_MAX="${COOKIE_MAX:-4096}"
RESP_BYTES_MAX="${RESP_BYTES_MAX:-500000}"

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
  'said into stderr[^"]*"[^"]*(ba)?sh:|(ba)?sh:( [0-9]+:)? .*(cannot (open|create)|No such file|[Ss]yntax error|unexpected (token|end)|[Rr]ead-only file system)|(ba)?sh:[^"]*(wget|curl|ncat?|php[0-9.]*|python[0-9.]*|perl|whoami|uname|hostname|base64|busybox|mkfifo): (command )?not found'
  'unserialize\(\): (Error|Function|Class|Extra)|__PHP_Incomplete_Class|session_decode\(\)|[Ff]ailed to decode session'
  '[?&]q[0-9]{1,8}=v&q[0-9]{1,8}=v&q[0-9]{1,8}=v'
  'php2shell-guard: oversized Set-Cookie'
  'upstream sent too big header'
)
LBL=("fpm worker crash" "apache worker crash" "allocator panic" "asan/zend-alloc crash backtrace" "php -S dev server crash/exposure" "memory_limit fatal" "memory error in Unknown on line 0" "upload-progress field" "shell/tool from php" "p2s object-injection marker" "shell exec error from php" "php object injection / unserialize" "request fingerprint q<N>=v&q<N>=v&q<N>=v (public PoC family; weak, easy to change)" "edge guard cut a leak-sized Set-Cookie (php/edge/)" "nginx refused an oversized upstream header (a leak-sized Set-Cookie does at default buffer sizes; large legitimate headers do too)")
SEV=("CRASH" "CRASH" "CORRUPT" "CORRUPT" "CRASH" "ATTACK" "ATTACK" "ATTACK" "RESIDUE" "RESIDUE" "RESIDUE" "ATTACK" "ATTACK" "ATTACK" "LEAD")

# Optional signature built from WATCH_IPS (see config). Dots are escaped; the
# address must stand alone (not part of a longer number).
IP_RE=""
for _ip in $WATCH_IPS; do _e="${_ip//./\\.}"; IP_RE+="${IP_RE:+|}${_e}"; done
if [ -n "$IP_RE" ]; then
  RES+=("(^|[^0-9.:])(${IP_RE})([^0-9]|\$)")
  LBL+=("traffic from an address reported in confirmed exploitation")
  SEV+=("ATTACK")
fi
CNT=()
for i in "${!RES[@]}"; do CNT[$i]=0; done

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
now() { date -u +%s; }

# CORRELATE: a POST returning 500 seen in an access log arms the worker PID for
# CORRELATE_WINDOW seconds; a same-PID crash in an error log within the window
# emits a high-confidence hit. An access log that records the PID (Apache %P) is
# required; without one, POST_PID below never matches and the layer is inert.
declare -A POST_PID_TS=()   # pid -> epoch seconds it returned a POST 500
CORR_CNT=0
# Pre-script OOM ("... in Unknown on line 0"): the memory-pressure stages of the
# confirmed chain. Tracked per worker PID (then a crash of that worker fires the
# chain alert) and per client (a burst from one client fires the burst alert).
# Unlike POST_PID_TS this needs no access-log line, which matters because the
# chain's HTTP stages answered 200 and its final request never reached the log.
OOM_RE='(Allowed memory size of [0-9]+ bytes exhausted|Out of memory).*in Unknown on line 0'
CRASH_RE='(zend_mm_heap corrupted|AH00052|exit signal (Abort|Segmentation|Bus)|exited on signal (6|7|11))'
declare -A OOM_PID_TS=() OOM_PID_N=() OOM_CLI_TS=() OOM_CLI_N=()
CHAIN_CNT=0
BURST_CNT=0
NOATTR_NOTED=0
PROC_CNT_FILE=""
PROC_PID=""
# The worker PID on a log line. The crashed child is what matters, and it is
# NOT the first "pid" on an Apache crash line: those start with the parent's
# own "[pid 1234]" and name the child later ("child pid 5678 exit signal ..."),
# so the child form is tried first. FPM crash lines say "child 5678 exited on
# signal 11". Otherwise: Apache error "[pid N]", access-log %P as "pid=N" or
# "pid N".
line_pid() {
  if   [[ "$1" =~ child\ pid\ ([0-9]{2,7}) ]];                  then echo "${BASH_REMATCH[1]}"
  elif [[ "$1" =~ child\ ([0-9]{2,7})\ exited\ on\ signal ]];   then echo "${BASH_REMATCH[1]}"
  elif [[ "$1" =~ (pid[=\ ]|\[pid\ )([0-9]{2,7}) ]];            then echo "${BASH_REMATCH[2]}"
  fi
}
# The client address on an error-log line: Apache "[client IP:port]" (the port
# is stripped) or nginx "client: IP,".
line_client() {
  local c
  if [[ "$1" =~ \[client\ ([0-9a-fA-F:.]+)\] ]]; then c="${BASH_REMATCH[1]}"; echo "${c%:[0-9]*}"
  elif [[ "$1" =~ client:\ ([0-9a-fA-F:.]+), ]]; then echo "${BASH_REMATCH[1]}"
  fi
}

# Oversized-response leads (COOKIE_MAX / RESP_BYTES_MAX above). Sets BL_WHY, and
# BL_SHOW=1 when the start of the line is safe to print. The cookie VALUE is
# never printed: it may be leaked process memory.
BIGRESP_CNT=0
BL_WHY=""; BL_SHOW=0
RE_POST_SIZE='" [0-9]{3} ([0-9]+)( |$)'
big_resp_lead() {
  local l="$1" s n
  BL_WHY=""; BL_SHOW=0
  if [ "$COOKIE_MAX" -gt 0 ] 2>/dev/null && [[ $l == *PHPSESSID=* ]] && (( ${#l} >= COOKIE_MAX )); then
    s="${l#*PHPSESSID=}"; s="${s%%[;\" ]*}"
    if (( ${#s} >= COOKIE_MAX )); then BL_WHY="a PHPSESSID value of ${#s} characters (value not shown)"; return 0; fi
  fi
  if [ "$RESP_BYTES_MAX" -gt 0 ] 2>/dev/null && [[ $l == *'"POST '* ]] && [[ $l =~ $RE_POST_SIZE ]]; then
    n="${BASH_REMATCH[1]}"
    if (( ${#n} <= 12 )) && (( n >= RESP_BYTES_MAX )); then BL_WHY="a POST response of ${n} bytes"; BL_SHOW=1; return 0; fi
  fi
  return 0
}

# Totals on stop; also stop the tailer.
summary() {
  echo "-- php2shell-watch stopped $(ts) --"
  local i
  for i in "${!LBL[@]}"; do printf '   %5d  %-8s %s\n' "${CNT[$i]}" "${SEV[$i]}" "${LBL[$i]}"; done
  printf '   %5d  %-8s %s\n' "$CORR_CNT" "ALERT" "POST-500 correlated with same-PID worker crash"
  printf '   %5d  %-8s %s\n' "$CHAIN_CNT" "ALERT" "pre-script OOM then same-worker crash (confirmed-chain shape)"
  printf '   %5d  %-8s %s\n' "$BURST_CNT" "ALERT" "repeated pre-script OOM from one client"
  printf '   %5d  %-8s %s\n' "$BIGRESP_CNT" "LEAD" "oversized POST response or PHPSESSID (leak-sized)"
  if [ -n "$PROC_CNT_FILE" ] && [ -f "$PROC_CNT_FILE" ]; then
    printf '   %5d  %-8s %s\n' "$(wc -l < "$PROC_CNT_FILE" | tr -d ' ')" "ALERT" "shell/tool spawned under a web worker"
  fi
}
cleanup() {
  [ -n "${TAILER_PID:-}" ] && kill "$TAILER_PID" 2>/dev/null
  [ -n "${PROC_PID:-}" ] && kill "$PROC_PID" 2>/dev/null
  summary
  [ -n "$PROC_CNT_FILE" ] && rm -f "$PROC_CNT_FILE"
  exit 0
}
trap cleanup INT TERM

echo "php2shell-watch ${SCRIPT_VERSION} $(ts): following ${#FILES[@]} file(s)" >&2
printf '   %s\n' "${FILES[@]}" >&2

# Process watch. Reports NEW shells and tools whose ancestry (up to four levels)
# includes a web server or PHP worker. Whatever is already running when the
# script starts is the baseline and is never reported, so long-lived helpers
# such as an Apache piped-log shell do not fire. It samples /proc once per
# PROC_INTERVAL, so it can miss a process that lives less than that, and a
# shell whose worker has already died is re-parented to init and no longer
# links to it (the confirmed chain's worker crashed about 0.7 s after starting
# the shell). Treat it as the cheap version of execve auditing, not a guarantee.
WEB_COMM_RE='^(apache2|httpd|httpd\.(worker|event|prefork)|php-fpm[0-9.]*|php-cgi[0-9.]*|lsphp[0-9]*|frankenphp|nginx)$'
# TCP peers of a pid as STATE->peer, e.g. "SYN-SENT->203.0.113.9:8080". Needs ss
# and, for another user's process, root. Prints nothing when there are none; a
# process caught the instant it starts may not have connected yet.
proc_peers() {
  command -v ss >/dev/null 2>&1 || return 0
  ss -tnapH 2>/dev/null | awk -v pat="pid=$1," 'index($0,pat) { print $1 "->" $5 }' | head -3 | paste -sd, - || true
}
SUSP_COMM_RE='^(sh|dash|bash|ash|zsh|ksh|busybox|curl|wget|nc|ncat|netcat|socat|php[0-9.]*|python[0-9.]*|perl|ruby|openssl|base64|mkfifo|whoami|uname|hostname|id)$'
proc_watch() {
  local -A seen=() comm=() ppid=() cur=()
  local first=1 d p c line rest pp a depth hit cmd full uid peers
  while :; do
    comm=(); ppid=(); cur=()
    for d in /proc/[0-9]*; do
      p="${d#/proc/}"
      { read -r c < "$d/comm"; } 2>/dev/null || continue
      { read -r line < "$d/stat"; } 2>/dev/null || continue
      rest="${line##*) }"; set -- $rest; pp="${2:-0}"
      comm[$p]="$c"; ppid[$p]="$pp"
    done
    for p in "${!comm[@]}"; do
      cur[$p]=1
      [[ -n "${seen[$p]:-}" ]] && continue
      seen[$p]=1
      [[ $first -eq 1 ]] && continue
      [[ "${comm[$p]}" =~ $SUSP_COMM_RE ]] || continue
      a="${ppid[$p]}"; depth=0; hit=""
      while [[ -n "$a" && "$a" != 0 && "$a" != 1 && $depth -lt 4 ]]; do
        if [[ "${comm[$a]:-}" =~ $WEB_COMM_RE ]]; then hit="$a"; break; fi
        a="${ppid[$a]:-0}"; depth=$((depth + 1))
      done
      [[ -n "$hit" ]] || continue
      # PROC_ALLOW always sees the full command line; PROC_CMD_MAX only limits
      # what is printed (so omitting the arguments never disables the allowlist).
      full="$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null)"
      if [ -n "$PROC_ALLOW" ] && [[ "$full" =~ $PROC_ALLOW ]]; then continue; fi
      if [ "$PROC_CMD_MAX" -gt 0 ] 2>/dev/null; then
        cmd="$(printf '%s' "$full" | cut -c1-"$PROC_CMD_MAX")"
        [ -n "$cmd" ] || cmd="(cmdline unavailable, process already gone)"
      else
        cmd="(arguments omitted, PROC_CMD_MAX=0)"
      fi
      uid="$(stat -c %u "/proc/$p" 2>/dev/null || echo '?')"
      peers="$(proc_peers "$p")"
      printf '%s  %-8s %s  |  %s (pid %s, uid %s) under %s (pid %s): %s%s\n' \
        "$(ts)" "ALERT" "web worker spawned shell/tool" "${comm[$p]}" "$p" "$uid" "${comm[$hit]}" "$hit" "$cmd" "${peers:+  [tcp: ${peers}]}"
      echo x >> "$PROC_CNT_FILE"
    done
    for p in "${!seen[@]}"; do [[ -n "${cur[$p]:-}" ]] || unset 'seen[$p]'; done
    first=0
    sleep "$PROC_INTERVAL"
  done
}
if [ "$PROCS" = 1 ] && [ -r /proc/self/stat ]; then
  PROC_CNT_FILE="$(mktemp)"
  proc_watch &
  PROC_PID=$!
  echo "process watch on (new shells/tools under web workers; PROCS=0 to turn off)" >&2
fi

# -q drops the ==> headers, -F survives rotation. exec so TAILER_PID is tail.
coproc TAILER { exec tail -qF "${FILES[@]}" 2>/dev/null; }

while IFS= read -r line <&"${TAILER[0]}"; do
  for i in "${!RES[@]}"; do
    if [[ $line =~ ${RES[$i]} ]]; then
      printf '%s  %-8s %s  |  %s\n' "$(ts)" "${SEV[$i]}" "${LBL[$i]}" "$line"
      CNT[$i]=$(( CNT[$i] + 1 ))
    fi
  done

  # Oversized response or PHPSESSID (leak-sized): a lead, not proof.
  big_resp_lead "$line"
  if [ -n "$BL_WHY" ]; then
    if [ "$BL_SHOW" = 1 ]; then
      printf '%s  %-8s %s  |  %s  |  %s\n' "$(ts)" "LEAD" "oversized response" "$BL_WHY" "${line:0:160}"
    else
      printf '%s  %-8s %s  |  %s  |  (log line of %s characters, not shown)\n' "$(ts)" "LEAD" "oversized response" "$BL_WHY" "${#line}"
    fi
    BIGRESP_CNT=$(( BIGRESP_CNT + 1 ))
  fi

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

  # CHAIN, step 1: a pre-script OOM ("... in Unknown on line 0") is recorded per
  # worker PID and per client. These are the memory-pressure stages of the
  # confirmed chain. A single one is ordinary; see the two alerts below.
  if [[ $line =~ $OOM_RE ]]; then
    opid="$(line_pid "$line")"; ocli="$(line_client "$line")"; onow="$(now)"
    if [[ -z "$opid" && -z "$ocli" && $NOATTR_NOTED -eq 0 ]]; then
      NOATTR_NOTED=1
      echo "$(ts)  NOTE     a pre-script OOM line carries no worker pid or client address (PHP's own error_log format?), so the same-worker chain and per-client burst alerts cannot fire for it; the line itself is still flagged. Under mod_php, leave error_log unset so PHP errors go to Apache's error log" >&2
    fi
    if [[ -n "$opid" ]]; then
      if [[ -n "${OOM_PID_TS[$opid]:-}" ]] && (( onow - OOM_PID_TS[$opid] <= CHAIN_WINDOW )); then
        OOM_PID_N[$opid]=$(( ${OOM_PID_N[$opid]:-0} + 1 ))
      else
        OOM_PID_N[$opid]=1
      fi
      OOM_PID_TS[$opid]="$onow"
    fi
    if [[ -n "$ocli" ]]; then
      if [[ -n "${OOM_CLI_TS[$ocli]:-}" ]] && (( onow - OOM_CLI_TS[$ocli] <= OOM_CLIENT_WINDOW )); then
        on=$(( ${OOM_CLI_N[$ocli]:-0} + 1 ))
      else
        on=1
      fi
      OOM_CLI_N[$ocli]="$on"; OOM_CLI_TS[$ocli]="$onow"
      if (( on >= OOM_CLIENT_THRESHOLD )); then
        printf '%s  %-8s %s  |  client %s: %s pre-script OOMs within %ss  |  %s\n' \
          "$(ts)" "ALERT" "repeated pre-script OOM from one client" "$ocli" "$on" "$OOM_CLIENT_WINDOW" "$line"
        BURST_CNT=$(( BURST_CNT + 1 ))
        OOM_CLI_N[$ocli]=0
      fi
    fi
  fi

  # CHAIN, step 2: a crash of a worker that had pre-script OOMs within the
  # window. This is the shape of the confirmed chain (OOM, OOM, then SIGSEGV on
  # the same worker) and needs neither a 500 nor an access-log line.
  if [[ $line =~ $CRASH_RE ]]; then
    cpid2="$(line_pid "$line")"
    if [[ -n "$cpid2" && -n "${OOM_PID_TS[$cpid2]:-}" ]]; then
      if (( $(now) - OOM_PID_TS[$cpid2] <= CHAIN_WINDOW )); then
        printf '%s  %-8s %s  |  pid %s: %s pre-script OOM(s) then worker crash within %ss  |  %s\n' \
          "$(ts)" "ALERT" "pre-script OOM then same-worker crash" "$cpid2" "${OOM_PID_N[$cpid2]:-1}" "$CHAIN_WINDOW" "$line"
        CHAIN_CNT=$(( CHAIN_CNT + 1 ))
      fi
      unset 'OOM_PID_TS[$cpid2]' 'OOM_PID_N[$cpid2]'
    fi
  fi

  # Bound the maps: drop entries older than their window (cheap; the POST map
  # first, then the OOM maps).
  if (( ${#POST_PID_TS[@]} > 256 )); then
    nows="$(now)"
    for k in "${!POST_PID_TS[@]}"; do
      (( nows - POST_PID_TS[$k] > CORRELATE_WINDOW )) && unset 'POST_PID_TS[$k]'
    done
  fi
  if (( ${#OOM_PID_TS[@]} > 256 || ${#OOM_CLI_TS[@]} > 256 )); then
    nows="$(now)"
    for k in "${!OOM_PID_TS[@]}"; do
      (( nows - OOM_PID_TS[$k] > CHAIN_WINDOW )) && unset 'OOM_PID_TS[$k]' 'OOM_PID_N[$k]'
    done
    for k in "${!OOM_CLI_TS[@]}"; do
      (( nows - OOM_CLI_TS[$k] > OOM_CLIENT_WINDOW )) && unset 'OOM_CLI_TS[$k]' 'OOM_CLI_N[$k]'
    done
  fi
done
cleanup

# Assisted-by: Claude Opus 5.5
