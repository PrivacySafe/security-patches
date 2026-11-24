#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Idunno.AntiCsrf deserialization on GNU/Linux (Mono ASP.NET): check, hunt, mitigation (v1)
# CVE-2026-131914
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Idunno.AntiCsrf (Idunno.AntiCsrf.dll 0.9.1.0, "0.9.1 Beta", last released December
# 2008, no maintainer, no fix) is an ASP.NET WebForms anti-CSRF module. On every POST
# to a page it passes the CSRF form field to an unkeyed ObjectStateFormatter, with no
# MAC and no type restriction, before the page runs: one anonymous request with any
# CSRF cookie and a .NET gadget chain in the form field runs code in the web server.
# Mandiant (MNDT-2026-0048) has seen it exploited on Windows and IIS.
#
# This is the GNU/Linux tool. It covers ASP.NET WebForms under Mono (mod_mono in Apache,
# XSP, fastcgi-mono-server behind nginx), whose System.Web has the same unkeyed
# ObjectStateFormatter, and any folder you point it at: a share, a backup or a deployment
# tree for Windows servers. On Windows and IIS use idunno-anticsrf-check.ps1 from this
# folder.
#
# Usage:
#   ./idunno-anticsrf-check.sh [command] [options]
#
#   check (default)  Read-only. Finds the Mono web applications: mod_mono
#                    MonoApplications and .webapp files, nginx server blocks
#                    that send .aspx to FastCGI, and running XSP and
#                    fastcgi-mono-server processes (read from their own
#                    --applications, --root, --appconfigfile and --appconfigdir
#                    arguments). Searches them and ROOTS for Idunno.AntiCsrf.dll
#                    (by name, by Mandiant's three SHA-256 hashes, and by the
#                    module's code inside any DLL in a bin folder), every
#                    web.config that registers the module or still names it,
#                    Mono's machine-wide web.config, the Mono GAC and ASP.NET
#                    shadow copies. Also looks in running docker and podman
#                    containers. A web.config that is a symbolic link is
#                    reported, never read. Exit 0 = not found, 1 = found,
#                    2 = something could not be read or there was nothing to
#                    search.
#   hunt             Read-only. Reads the web server and Mono logs of the last
#                    HUNT_DAYS days: the module's PotentialCsrfException and
#                    deserialization errors, which every attempt leaves when
#                    errors are logged, and POST requests to .aspx pages
#                    answered with 500 (and, summarized, 302). Lists pages,
#                    scripts and binaries changed in the applications in the
#                    same period, and marks the ones that look like a web
#                    shell. Exit 0 = nothing found, 1 = leads to look at,
#                    2 = no log could be read.
#   mitigate [--dry-run] [--restart]   (root) Removes every registration of
#                    the module from every web.config that has one. Each file
#                    is read without following links and copied first, edited
#                    as text so the rest of the file stays byte for byte, and
#                    checked as XML; only a result that parses and registers
#                    nothing replaces the original, through a new file renamed
#                    over it with the same owner and mode. A symbolic link is
#                    left alone and reported. Needs python3. The DLL and the csrfSettings section stay,
#                    because pages may still refer to them. Mono's System.Web
#                    unloads an application when its web.config changes, so the
#                    next request runs without the module. --restart also
#                    restarts Apache when it hosts mod_mono and every running
#                    service that runs XSP or a Mono FastCGI server.
#   rollback [--dry-run] [--restart]   Puts back every file mitigate changed.
#   version          Prints the script version.
#
# Taking the module out closes the hole and removes its CSRF protection: replace
# it with a supported mechanism (see the README).
#
# Env overrides:
#   ROOTS="/var/www /srv /opt /home /usr/share/nginx"   more folders to search
#                       (default shown), beside the applications found
#   MAX_DEPTH=12        how deep each folder is searched
#   APACHE_CONF_DIRS="/etc/apache2 /etc/httpd"   NGINX_CONF_DIRS="/etc/nginx"
#   WEBAPP_DIRS="/etc/xsp4 /etc/xsp2 /etc/xsp /etc/mono-server4 /etc/mono-server2 /etc/mono-server"
#   MONO_CONF_DIRS="/etc/mono /usr/local/etc/mono"   (machine-wide web.config)
#   MONO_GAC_DIRS="/usr/lib/mono/gac /usr/local/lib/mono/gac"
#   SHADOW_DIRS="/tmp /var/tmp"   where Mono keeps its ASP.NET shadow copies
#   EXTRA_SHA256="h1 h2"  more SHA-256 hashes of the DLL, as they are published
#   HUNT_DAYS=60        how far back hunt reads
#   HUNT_LOG_FILES      the access logs hunt reads, instead of the defaults
#   HUNT_ERROR_LOG_FILES  the error logs hunt reads, instead of the defaults
#   STATE_DIR           where mitigate keeps its copies and manifest
#                       (default /var/lib/psf-security-patches/idunno-anticsrf)
#   PSF_LOCK_WAIT       seconds a run that changes the host waits for another
#                       one that is already changing it (default 30)
#   SCAN_CONTAINERS=1   0 skips running docker and podman containers
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="idunno-anticsrf-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-23"
SELF="$0"
CVE="CVE-2026-131914"
ROOTS_GIVEN="${ROOTS:+1}"
ROOTS="${ROOTS:-/var/www /srv /opt /home /usr/share/nginx}"
MAX_DEPTH="${MAX_DEPTH:-12}"
APACHE_CONF_DIRS="${APACHE_CONF_DIRS:-/etc/apache2 /etc/httpd}"
NGINX_CONF_DIRS="${NGINX_CONF_DIRS:-/etc/nginx}"
WEBAPP_DIRS="${WEBAPP_DIRS:-/etc/xsp4 /etc/xsp2 /etc/xsp /etc/mono-server4 /etc/mono-server2 /etc/mono-server}"
MONO_CONF_DIRS="${MONO_CONF_DIRS:-/etc/mono /usr/local/etc/mono}"
MONO_GAC_DIRS="${MONO_GAC_DIRS:-/usr/lib/mono/gac /usr/local/lib/mono/gac}"
SHADOW_DIRS="${SHADOW_DIRS:-/tmp /var/tmp}"
HUNT_DAYS="${HUNT_DAYS:-60}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/idunno-anticsrf}"
# Mandiant's three known builds of Idunno.AntiCsrf.dll 0.9.1.0: the official 2008 release and the
# release and debug rebuilds of the CodePlex source. A recompiled copy is found by its assembly name.
DLL_SHA256="da1efcfed182597ee946a9ef2895dfdfeab2bdff16855aeef01656d8158ead06 c5c994891783453ae85f3ef8efb48592b7c560aeb56f531ee9ea5736518246eb aa7bbad4a7ebc38519955ac65517716569508ee4f61fc2f1276086940501e9bf ${EXTRA_SHA256:-}"
DLL_SHA256="${DLL_SHA256,,}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how=", or add --dry-run to see what it would do" msg
    if is_root; then root_note; return 0; fi
    if have sudo; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    have sudo && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}

# ---------- web.config as text and XML ---------------------------------------
# A web.config is edited as text, so that everything except the removed elements stays byte for byte,
# and checked as XML before it replaces the original. Python 3 does the counting and all the writing;
# without it, Perl counts (check works) and xmllint, where present, checks well-formedness.
PY_XML="$(cat <<'EOS'
import os, re, stat, sys, secrets
# Every file in a web root may be replaced by its owner at any moment, so nothing here follows a
# symbolic link: files are opened with O_NOFOLLOW and checked to be regular files, a copy is read
# from that same open file, and a change is written to a new file created with O_EXCL next to the
# original and renamed over it. A rename replaces the directory entry, never the target of a link.
mode = sys.argv[1]
path = sys.argv[2]
Q = r'''(?:[^>"']|"[^"]*"|'[^']*')'''
ADD = re.compile(r'[ \t]*<add\b' + Q + r'*?\btype\s*=\s*(["\'])(?:(?!\1).)*?(?:Idunno\.AntiCsrf|AntiCsrfModule)(?:(?!\1).)*?\1' + Q + r'*?(?:/>|>\s*</add\s*>)[ \t]*(?:\r?\n)?', re.I | re.S)
BLOCK = re.compile(r'(<(httpModules|modules)\b[^>]*?(?<!/)>)(.*?)(</\2\s*>)', re.S)
COMMENT = re.compile(r'<!--.*?-->', re.S)
def count(text):
    return sum(len(ADD.findall(m.group(3))) for m in BLOCK.finditer(COMMENT.sub('', text)))
def parses(b):
    import xml.dom.minidom
    try:
        xml.dom.minidom.parseString(b)
        return 'ok'
    except Exception:
        return 'bad'
def read_regular(p):
    try:
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as e:
        return None, ('link' if e.errno == 40 else 'unreadable')
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, 'notreg'
        chunks = []
        while True:
            c = os.read(fd, 1 << 20)
            if not c:
                break
            chunks.append(c)
        return (b''.join(chunks), st), 'ok'
    finally:
        os.close(fd)
def write_new(p, data, mode_bits, uid, gid):
    d = os.path.dirname(os.path.abspath(p))
    tmp = os.path.join(d, '.psf-idunno-' + secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        try:
            os.fchown(fd, uid, gid)
        except PermissionError:
            pass
        os.fchmod(fd, mode_bits)
        os.fsync(fd)
    except Exception:
        os.close(fd); os.unlink(tmp); raise
    os.close(fd)
    os.rename(tmp, p)
if mode == 'count':
    r, why = read_regular(path)
    if r is None:
        print(0, why)
    else:
        print(count(r[0].decode('latin-1')), parses(r[0]))
elif mode == 'change':
    backup = sys.argv[3]
    r, why = read_regular(path)
    if r is None:
        print(1, why, 'unchanged', 0, 0, 0); sys.exit(0)
    data, st = r
    bfd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.write(bfd, data); os.fsync(bfd); os.close(bfd)
    t = data.decode('latin-1')
    new = BLOCK.sub(lambda m: m.group(1) + ADD.sub('', m.group(3)) + m.group(4), t)
    nb = new.encode('latin-1')
    left, q = count(new), parses(nb)
    meta = (oct(stat.S_IMODE(st.st_mode)), st.st_uid, st.st_gid)
    if nb == data or left != 0 or q != 'ok':
        print(left, q, 'unchanged', *meta); sys.exit(0)
    write_new(path, nb, stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid)
    print(left, q, 'changed', *meta)
elif mode == 'restore':
    backup, mode_bits, uid, gid = sys.argv[3], int(sys.argv[4], 8), int(sys.argv[5]), int(sys.argv[6])
    r, why = read_regular(backup)
    if r is None:
        print('missing'); sys.exit(0)
    cur = os.lstat(path) if os.path.lexists(path) else None
    if cur is not None and not stat.S_ISREG(cur.st_mode):
        print('notreg'); sys.exit(0)
    write_new(path, r[0], mode_bits, uid, gid)
    print('ok')
EOS
)"
PL_XML="$(cat <<'EOS'
my ($mode, $path) = @ARGV;
open(my $fh, '<:raw', $path) or exit 3; local $/; my $t = <$fh>; close $fh;
my $Q = q{(?:[^>"']|"[^"]*"|'[^']*')};
my $ADD = qr{[ \t]*<add\b$Q*?\btype\s*=\s*(["'])(?:(?!\1).)*?(?:Idunno\.AntiCsrf|AntiCsrfModule)(?:(?!\1).)*?\1$Q*?(?:/>|>\s*</add\s*>)[ \t]*(?:\r?\n)?}is;
sub count { my $x = shift; $x =~ s/<!--.*?-->//sg; my $n = 0;
  while ($x =~ m{<(httpModules|modules)\b[^>]*?(?<!/)>(.*?)</\1\s*>}sg) { my $b = $2; my @m = ($b =~ /$ADD/g); $n += scalar(@m); }
  return $n; }
print count($t), " unknown\n";
EOS
)"
xml_backend() {
    case "${XML_BACKEND:-}" in python) echo python; return ;; perl) echo perl; return ;; esac
    if have python3; then echo python; elif have perl; then echo perl; else echo none; fi
}
# xml_op count FILE -> "<registrations> <ok|bad|unknown|link|notreg|unreadable>" (read only)
xml_op() {
    local out
    case "$(xml_backend)" in
        python) out="$(python3 -c "$PY_XML" count "$2" 2>/dev/null)" ;;
        perl)   [[ -L "$2" ]] && { echo "0 link"; return; }
                out="$(perl -e "$PL_XML" count "$2" 2>/dev/null)"
                if [[ -n "$out" ]] && have xmllint; then
                    if xmllint --noout --nonet "$2" >/dev/null 2>&1; then out="${out% *} ok"; else out="${out% *} bad"; fi
                fi ;;
        *) out="" ;;
    esac
    # A count the helper cannot give (no Python or Perl) is read from the text: any add element naming it.
    if [[ -z "$out" ]]; then
        if grep -qiE '<add[^>]*(Idunno\.AntiCsrf|AntiCsrfModule)' "$2" 2>/dev/null; then out="1 unknown"; else out="0 unknown"; fi
    fi
    echo "$out"
}

# ---------- finding the Mono web applications --------------------------------
APPS=()        # "path<TAB>where it was found"
add_app() { [[ -n "$1" ]] && APPS+=("${1%/}"$'\t'"$2"); return 0; }
conf_files() { local d; for d in "$@"; do [[ -d "$d" ]] && find "$d" -maxdepth 4 -type f -readable 2>/dev/null; done; }
webapp_paths() {   # <file.webapp>: the <path> of each application
    grep -o '<path>[^<]*</path>' "$1" 2>/dev/null | sed -E 's#</?path>##g'
}
find_mono_apps() {
    local f line val item p d w
    # mod_mono: MonoApplications / AddMonoApplications "vpath:path,vpath:path", and .webapp files
    while IFS= read -r f; do
        while IFS= read -r line; do
            line="${line#"${line%%[![:space:]]*}"}"
            case "$line" in
                MonoApplications\ *|AddMonoApplications\ *|monoapplications\ *|addmonoapplications\ *)
                    val="${line#* }"; val="${val#* }"; val="${val//\"/}"
                    IFS=',' read -ra items <<<"$val"
                    for item in "${items[@]}"; do p="${item#*:}"; [[ "$p" == /* ]] && add_app "$p" "mod_mono in $f"; done ;;
                MonoApplicationsConfigFile\ *)
                    w="${line##* }"; w="${w//\"/}"
                    while IFS= read -r p; do add_app "$p" "$w (mod_mono)"; done < <(webapp_paths "$w") ;;
                MonoApplicationsConfigDir\ *)
                    d="${line##* }"; d="${d//\"/}"
                    for w in "$d"/*.webapp; do [[ -f "$w" ]] || continue
                        while IFS= read -r p; do add_app "$p" "$w (mod_mono)"; done < <(webapp_paths "$w"); done ;;
            esac
        done < <(grep -iE '^[[:space:]]*(Add)?MonoApplications' "$f" 2>/dev/null)
    done < <(conf_files $APACHE_CONF_DIRS)
    # XSP and mono-server .webapp files
    for d in $WEBAPP_DIRS; do
        for w in "$d"/*.webapp "$d"/*/*.webapp; do [[ -f "$w" ]] || continue
            while IFS= read -r p; do add_app "$p" "$w"; done < <(webapp_paths "$w")
        done
    done
    # nginx server blocks that pass .aspx (or anything Mono) to FastCGI
    while IFS= read -r f; do
        grep -qE 'fastcgi_pass' "$f" 2>/dev/null && grep -qiE '\.aspx|mono' "$f" 2>/dev/null || continue
        while IFS= read -r p; do add_app "$p" "nginx $f"; done < <(sed -E 's/#.*//' "$f" | grep -oE '(^|[;{[:space:]])root[[:space:]]+"?[^";[:space:]]+"?[[:space:]]*;' | sed -E 's/.*root[[:space:]]+"?([^";[:space:]]+).*/\1/')
    done < <(conf_files $NGINX_CONF_DIRS)
    # running XSP, mod-mono-server and fastcgi-mono-server processes
    [[ -n "${PSF_IN_COPY:-}" ]] && return 0
    local args a next
    while IFS= read -r args; do
        next=""
        for a in $args; do
            case "$next" in
                apps) IFS=',' read -ra items <<<"$a"; for item in "${items[@]}"; do p="${item#*:}"; [[ "$p" == /* ]] && add_app "$p" "running process"; done; next=""; continue ;;
                root) [[ "$a" == /* ]] && add_app "$a" "running process"; next=""; continue ;;
                cfgfile) while IFS= read -r p; do add_app "$p" "$a (running process)"; done < <(webapp_paths "$a"); next=""; continue ;;
                cfgdir) for w in "$a"/*.webapp; do [[ -f "$w" ]] && while IFS= read -r p; do add_app "$p" "$w (running process)"; done < <(webapp_paths "$w"); done; next=""; continue ;;
            esac
            case "$a" in
                --applications=*) IFS=',' read -ra items <<<"${a#*=}"; for item in "${items[@]}"; do p="${item#*:}"; [[ "$p" == /* ]] && add_app "$p" "running process"; done ;;
                --applications) next=apps ;;
                --root=*) add_app "${a#*=}" "running process" ;;
                --root) next=root ;;
                --appconfigfile=*) while IFS= read -r p; do add_app "$p" "${a#*=} (running process)"; done < <(webapp_paths "${a#*=}") ;;
                --appconfigfile) next=cfgfile ;;
                --appconfigdir=*) for w in "${a#*=}"/*.webapp; do [[ -f "$w" ]] && while IFS= read -r p; do add_app "$p" "$w (running process)"; done < <(webapp_paths "$w"); done ;;
                --appconfigdir) next=cfgdir ;;
            esac
        done
    done < <(ps -eo args= 2>/dev/null | grep -E '(^|/| )(xsp[0-9]?|mod-mono-server[0-9]?|fastcgi-mono-server[0-9]?)(\.exe)?( |$)' | grep -v grep)
}
mono_in_apache() { conf_files $APACHE_CONF_DIRS | xargs -r -d '\n' grep -lisE '^[[:space:]]*(Add)?MonoApplications|^[[:space:]]*LoadModule[[:space:]]+mono_module' 2>/dev/null | head -n1; }

# Every folder to search, nested ones once: the applications found, then ROOTS.
search_roots() {
    local e p
    {
        for e in ${APPS[@]+"${APPS[@]}"}; do p="${e%%$'\t'*}"; [[ -d "$p" ]] && echo "$p"; done
        for p in $ROOTS; do [[ -d "$p" ]] && echo "${p%/}"; done
    } | awk '!seen[$0]++'
}

# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
# Paths the container reports are validated before use, a symlink is never kept (docker cp copies the
# link itself, and the check would then read whatever it points to on the host), and the number of
# copied files is capped. It runs once, in the main shell (a subshell's exit would delete the copies).
STAGE=""
declare -a STAGED_DIRS=()
stage_probe() {   # <probe script, run with sh -s inside each running container>
    local probe="$1" rt id name out kind p rest s nf
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        command -v "$rt" >/dev/null 2>&1 || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            out="$(printf '%s\n' "$probe" | "$rt" exec -i "$id" sh -s 2>/dev/null | head -n 6000)" || continue
            [[ -n "$out" ]] || continue
            s=""; nf=0
            while read -r kind p rest; do
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
                if [[ -z "$s" ]]; then
                    if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; trap 'rm -rf "${STAGE:-}"' EXIT; fi
                    s="$STAGE/${rt}_${name:-$id}"; mkdir -p "$s"
                fi
                case "$kind" in
                    F) nf=$((nf + 1)); [[ $nf -le 400 ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       "$rt" cp "${id}:${p}" "$s$p" >/dev/null 2>&1 || rm -f "$s$p"
                       [[ -L "$s$p" ]] && rm -f "$s$p" ;;
                    D) mkdir -p "$s$p" ;;
                    E) mkdir -p "$s$(dirname "$p")"; : > "$s$p" ;;
                    L) [[ "$rest" =~ ^[A-Za-z0-9_=.,:/@-]{0,120}$ ]] || continue
                       mkdir -p "$s$(dirname "$p")"; printf '%s\n' "$rest" > "$s$p" ;;
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}


# ---------- check ------------------------------------------------------------
N_FOUND=0; N_REVIEW=0; N_UNREAD=0
CONFIG_HITS=()
is_module_dll() {   # the module's own code, not an application that only refers to its attributes
    LC_ALL=C grep -qaF 'AntiCsrfModule' "$1" && LC_ALL=C grep -qaF 'ObjectStateFormatter' "$1" && LC_ALL=C grep -qaF 'PreRequestHandlerExecute' "$1"
}
judge_config() {   # <web.config> [note]
    local f="$1" note="${2:-}" n p
    # A link is reported, never read: it could point at a FIFO or a device that never ends.
    if [[ -L "$f" ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "${f}${note}: a symbolic link or not a regular file: read what it points to by hand"; return; fi
    [[ -f "$f" && -r "$f" ]] || { N_UNREAD=$((N_UNREAD + 1)); caution "cannot read ${f}"; return; }
    grep -qiE 'Idunno\.AntiCsrf|AntiCsrfModule' "$f" 2>/dev/null || return 0
    read -r n p <<<"$(xml_op count "$f")"
    if [[ "$p" == link || "$p" == notreg ]]; then
        N_REVIEW=$((N_REVIEW + 1)); caution "${f}${note}: a symbolic link or not a regular file: read what it points to by hand"
    elif [[ "$p" == bad ]]; then
        N_REVIEW=$((N_REVIEW + 1)); caution "${f}${note}: names Idunno.AntiCsrf but is not well-formed XML: read it by hand"
    elif [[ "${n:-0}" -gt 0 ]]; then
        N_FOUND=$((N_FOUND + 1)); CONFIG_HITS+=("$f")
        bad "${f}${note}: registers Idunno.AntiCsrf.AntiCsrfModule (${n} registration(s)). POST requests to its pages reach the unsafe deserializer"
    else
        N_FOUND=$((N_FOUND + 1))
        caution "${f}${note}: names Idunno.AntiCsrf (a csrfSettings section or an assembly reference) but registers no module. Remove what is left"
    fi
}
judge_dll() {   # <file.dll>
    local f="$1" base h size
    [[ -f "$f" ]] || return 0   # a link to anything but a regular file is not read
    base="${f##*/}"
    if [[ "${base,,}" == idunno.anticsrf.dll ]]; then
        N_FOUND=$((N_FOUND + 1)); h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        if [[ -n "$h" && " $DLL_SHA256 " == *" $h "* ]]; then bad "${f}: Idunno.AntiCsrf.dll, one of the builds Mandiant published"
        else bad "${f}: Idunno.AntiCsrf.dll"; fi
        return
    fi
    size="$(stat -c %s "$f" 2>/dev/null || echo 0)"
    if [[ "$size" -gt 0 && "$size" -lt 2097152 ]]; then
        h="$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"
        if [[ -n "$h" && " $DLL_SHA256 " == *" $h "* ]]; then N_FOUND=$((N_FOUND + 1)); bad "${f}: Idunno.AntiCsrf.dll under another name (its hash is one Mandiant published)"; return; fi
    fi
    [[ "$size" -gt 0 && "$size" -lt 8388608 ]] || return 0
    LC_ALL=C grep -qaF 'Idunno.AntiCsrf' "$f" 2>/dev/null || return 0
    if is_module_dll "$f"; then N_FOUND=$((N_FOUND + 1)); bad "${f}: carries the Idunno.AntiCsrf module under another name or build"
    else inf "${f}: refers to Idunno.AntiCsrf (pages that use its attributes): change those pages when you remove the module"; fi
}

BP_PROBE="$(cat <<'EOS'
R="/var/www /srv /opt /app /home /usr/share/nginx /etc/mono"
find $R -maxdepth 12 -type f -iname web.config 2>/dev/null | head -n 2000 | while read -r f; do
  grep -qiE 'Idunno\.AntiCsrf|AntiCsrfModule' "$f" 2>/dev/null && echo "F $f"
done
find $R -maxdepth 12 -type f -iname 'idunno.anticsrf.dll' 2>/dev/null | head -n 50 | while read -r f; do echo "E $f"; done
exit 0
EOS
)"
container_run() {
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "Idunno.AntiCsrf in a container (${s##*/})"
    out="$(PSF_IN_COPY=1 SCAN_CONTAINERS=0 ROOTS="$s" APACHE_CONF_DIRS=/nonexistent NGINX_CONF_DIRS=/nonexistent WEBAPP_DIRS=/nonexistent \
           MONO_CONF_DIRS="$s/etc/mono" MONO_GAC_DIRS=/nonexistent SHADOW_DIRS=/nonexistent bash "$SELF" check 2>&1)"; rc=$?
    tail -n +3 <<<"$out" | sed '/^===== Verdict/,$d'
    return "$rc"
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments (set ROOTS to choose where it looks)"
    local crc=0 _s
    if [[ -z "${ROOTS_GIVEN:-}" && -z "${PSF_IN_COPY:-}" && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$BP_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do container_run "$_s" || crc=1; done
    fi
    local r f e roots d g
    limited_view "web applications and server configuration"
    if [[ -z "${PSF_IN_COPY:-}" ]]; then
        step "Mono ASP.NET on this host"
        if have mono; then inf "mono: $(mono --version 2>/dev/null | head -n1)"; else inf "the mono runtime is not on PATH"; fi
        f="$(mono_in_apache)"; [[ -n "$f" ]] && inf "Apache hosts Mono applications (mod_mono): ${f}"
    fi
    find_mono_apps
    for e in ${APPS[@]+"${APPS[@]}"}; do inf "application ${e%%$'\t'*}  (${e#*$'\t'})"; done
    [[ ${#APPS[@]} -gt 0 || -n "${PSF_IN_COPY:-}" ]] || inf "no Mono web application found in the server configuration or running processes"

    roots="$(search_roots)"
    [[ -n "$roots" ]] || die "nothing to search: none of the applications or ROOTS (${ROOTS}) exist. Name the folders with ROOTS"
    step "Applications and folders"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        case "${f,,}" in
            */web.config) judge_config "$f" ;;
            *.dll) judge_dll "$f" ;;
        esac
    done < <(while IFS= read -r r; do
                find "$r" -maxdepth "$MAX_DEPTH" \( -type f -o -type l \) \( -iname web.config -o -iname '*.dll' \) 2>/dev/null
             done <<<"$roots" | awk '!seen[$0]++')
    [[ $N_FOUND -gt 0 || $N_REVIEW -gt 0 ]] || inf "no trace of Idunno.AntiCsrf under ${roots//$'\n'/ }"

    step "Machine-wide configuration, GAC and shadow copies"
    for d in $MONO_CONF_DIRS; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do judge_config "$f" " (machine-wide: every Mono application)"; done < <(find "$d" -maxdepth 3 -type f -iname web.config 2>/dev/null)
    done
    for d in $MONO_GAC_DIRS; do
        [[ -d "$d" ]] || continue
        while IFS= read -r g; do N_FOUND=$((N_FOUND + 1)); bad "${g}: Idunno.AntiCsrf is in the Mono GAC, where any application can load it"; done < <(find "$d" -maxdepth 1 -iname 'idunno.anticsrf' 2>/dev/null)
    done
    # Mono copies the assemblies an application loads into <user>-temp-aspnet-* folders: a copy
    # there means an application loaded the module at some point, even if it is gone now.
    for d in $SHADOW_DIRS; do
        [[ -d "$d" ]] || continue
        while IFS= read -r g; do N_REVIEW=$((N_REVIEW + 1)); caution "${g}: an ASP.NET shadow copy (modified $(date -r "$g" '+%F %R' 2>/dev/null)): an application loaded Idunno.AntiCsrf here. Find which, and run hunt"; done \
            < <(find "$d" -maxdepth 8 -path '*temp-aspnet*' -type f -iname 'idunno.anticsrf.dll' 2>/dev/null)
    done
    inf "read ${MONO_CONF_DIRS}, ${MONO_GAC_DIRS} and the shadow copies under ${SHADOW_DIRS}"

    step "Verdict"
    if [[ $N_FOUND -gt 0 ]]; then
        warn "FOUND: ${N_FOUND} trace(s) of Idunno.AntiCsrf (${CVE}, exploited, no fix)."
        if [[ ${#CONFIG_HITS[@]} -gt 0 ]]; then warn "Where a web.config registers it, any anonymous POST to a page can run code on this server. Run '${SELF} mitigate --dry-run', then 'sudo ${SELF} mitigate --restart', then hunt, and replace the module with a supported anti-CSRF mechanism (see the README)."
        else warn "No web.config registers it, so it is not running here. Delete the DLL and the leftover configuration."; fi
        [[ $N_REVIEW -eq 0 ]] || warn "${N_REVIEW} item(s) need a look by hand (marked above)."
        return 1
    fi
    if [[ $N_REVIEW -gt 0 ]]; then warn "${N_REVIEW} item(s) need a look by hand (marked above)."; return 1; fi
    if [[ $crc -ne 0 ]]; then return 1; fi
    if [[ $N_UNREAD -gt 0 ]]; then warn "Not found, but ${N_UNREAD} file(s) could not be read, so this is not a clean result."; return 2; fi
    info "Idunno.AntiCsrf was not found where this could read."
    return 0
}

# ---------- hunt -------------------------------------------------------------
recent_logs() {   # <glob patterns...> -> files changed in the last HUNT_DAYS days
    local p f
    for p in "$@"; do for f in $p; do [[ -f "$f" ]] && find "$f" -maxdepth 0 -mtime "-${HUNT_DAYS}" 2>/dev/null; done; done | awk '!seen[$0]++'
}
cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments (set HUNT_LOG_FILES, HUNT_ERROR_LOG_FILES or ROOTS)"
    limited_view "logs"
    local f n_read=0 leads=0 n500=0 n302=0 line
    local access="${HUNT_LOG_FILES:-/var/log/apache2/*access*.log* /var/log/httpd/*access_log* /var/log/httpd/*access*.log* /var/log/nginx/*access*.log*}"
    local errors="${HUNT_ERROR_LOG_FILES:-/var/log/apache2/*error*.log* /var/log/httpd/*error_log* /var/log/httpd/*error*.log* /var/log/nginx/*error*.log* /var/log/mono*/*.log* /var/log/xsp*/*.log*}"
    # shellcheck disable=SC2086
    step "Errors the module leaves (last ${HUNT_DAYS} days)"
    # Every exploitation attempt ends in the module's PotentialCsrfException (or a redirect to its error
    # page), after the payload has already run; a malformed payload throws inside ObjectStateFormatter.
    local pat='PotentialCsrfException|Idunno\.AntiCsrf|ObjectStateFormatter\.Deserialize'
    local shown=0
    while IFS= read -r f; do
        [[ -r "$f" ]] || continue; n_read=$((n_read + 1))
        while IFS= read -r line; do
            leads=$((leads + 1)); [[ $shown -lt 40 ]] && { bad "${f##*/}: ${line:0:240}"; shown=$((shown + 1)); }
        done < <(zcat -f "$f" 2>/dev/null | grep -aE "$pat")
    done < <(recent_logs $errors)
    if have journalctl && [[ -z "${HUNT_ERROR_LOG_FILES:-}" ]]; then
        n_read=$((n_read + 1))
        while IFS= read -r line; do
            leads=$((leads + 1)); [[ $shown -lt 40 ]] && { bad "journal: ${line:0:240}"; shown=$((shown + 1)); }
        done < <(journalctl --no-pager -q -o short-iso --since "-${HUNT_DAYS}d" 2>/dev/null | grep -aE "$pat")
    fi
    [[ $leads -gt 0 ]] || inf "no PotentialCsrfException or deserialization error in the error logs and the journal"

    step "POST requests to .aspx pages answered with 500 or 302"
    local tmp; tmp="$(mktemp)" || die "Cannot make a temporary file."; PSF_TMP+=("$tmp")
    while IFS= read -r f; do
        [[ -r "$f" ]] || continue; n_read=$((n_read + 1))
        zcat -f "$f" 2>/dev/null | awk -v F="${f##*/}" '
            { l = tolower($0) }
            match(l, /"post [^ "]*\.aspx(\?[^ "]*)? http\/[0-9.]+" (500|302) /) {
                s = substr(l, RSTART, RLENGTH); n = split(s, a, " "); print a[n] "\t" $1 "\t" F "\t" $0 }' >> "$tmp"
    done < <(recent_logs $access)
    n500="$(awk -F'\t' '$1=="500"' "$tmp" | wc -l)"; n302="$(awk -F'\t' '$1=="302"' "$tmp" | wc -l)"
    if [[ $n500 -gt 0 ]]; then
        leads=$((leads + n500))
        awk -F'\t' '$1=="500" {print $3 ": " $4}' "$tmp" | head -n 40 | while IFS= read -r line; do bad "${line:0:240}"; done
    fi
    if [[ $n302 -gt 0 ]]; then
        caution "${n302} POST(s) to .aspx pages answered 302. A normal postback (a login) answers 302 too, so these are listed by client, most first: look at clients you do not know"
        awk -F'\t' '$1=="302" {c[$2]++} END {for (k in c) print c[k] "\t" k}' "$tmp" | sort -rn | head -n 10 | while IFS=$'\t' read -r c ip; do inf "${ip}: ${c}"; done
    fi
    [[ $n500 -gt 0 || $n302 -gt 0 ]] || inf "none in the access logs read"
    inf "access logs record the response size, not the request size: to see payload sizes, add %I (mod_logio) to Apache's LogFormat or \$request_length to nginx's log_format"

    step "Files changed recently in the applications"
    find_mono_apps
    local roots=""; local e
    for e in ${APPS[@]+"${APPS[@]}"}; do roots+="${e%%$'\t'*}"$'\n'; done
    [[ -n "${ROOTS_GIVEN:-}" ]] && for e in $ROOTS; do roots+="$e"$'\n'; done
    if [[ -z "${roots//$'\n'/}" ]]; then inf "no application found and ROOTS not set: skipped"; else
        local shell_like='Process\.Start|ProcessStartInfo|cmd\.exe|/bin/(ba)?sh|Assembly\.Load|eval\(Request|Request\.(Form|QueryString)\[[^]]*\]\)'
        local n=0
        while IFS= read -r f; do
            n=$((n + 1))
            if [[ "${f,,}" =~ \.(aspx|ashx|asmx|ascx)$ ]] && grep -qaE "$shell_like" "$f" 2>/dev/null; then
                leads=$((leads + 1)); bad "$(date -r "$f" '+%F %R')  ${f}  (looks like a web shell: runs commands or loads code from the request)"
            else
                N_REVIEW=$((N_REVIEW + 1)); caution "$(date -r "$f" '+%F %R')  ${f}"
            fi
        done < <(printf '%s' "$roots" | awk 'NF && !seen[$0]++' | while IFS= read -r r; do
                    [[ -d "$r" ]] && find "$r" -maxdepth "$MAX_DEPTH" -type f -mtime "-${HUNT_DAYS}" -regextype posix-extended \
                        -iregex '.*\.(aspx|ashx|asmx|asax|ascx|config|dll|exe|sh|py|pl|php)$' 2>/dev/null
                 done | head -n 60)
        [[ $n -gt 0 ]] || inf "no page, script, binary or configuration file changed in the last ${HUNT_DAYS} days"
    fi

    step "Verdict"
    if [[ $n_read -eq 0 ]]; then warn "No log could be read. Set HUNT_LOG_FILES and HUNT_ERROR_LOG_FILES, or run as root."; return 2; fi
    if [[ $leads -gt 0 ]]; then
        warn "${leads} lead(s) above. Exceptions from Idunno.AntiCsrf or ObjectStateFormatter, POSTs answered 500 and new pages that run commands are what exploitation leaves. If any is not explained by your own traffic, treat the server as compromised: rotate every secret in web.config (the machineKey, encryption keys, database passwords) from another machine and check the applications for files you did not put there."
        return 1
    fi
    [[ $N_REVIEW -eq 0 ]] || warn "No lead, but files changed recently are listed above: check that each change was yours."
    info "Nothing matching the exploitation pattern was found in what this could read."
    return 0
}

# ---------- mitigate and rollback ---------------------------------------------
RESTART=0
manifest_add() { mkdir -p "$STATE_DIR" && printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$STATE_DIR/manifest"; }
restart_units() {
    local u units=()
    have systemctl || { caution "systemctl not found: restart the web server and the Mono servers yourself"; return 0; }
    if [[ -n "$(mono_in_apache)" ]]; then
        for u in apache2 httpd; do systemctl is-active --quiet "$u" 2>/dev/null && units+=("$u"); done
    fi
    while IFS= read -r u; do
        systemctl cat "$u" 2>/dev/null | grep -qE '^ExecStart=.*(xsp[0-9]?|mono-server[0-9]?|fastcgi-mono-server[0-9]?)' && units+=("$u")
    done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{print $1}')
    printf '%s\n' ${units[@]+"${units[@]}"} | awk 'NF && !seen[$0]++'
}
maybe_restart() {
    local u list
    list="$(restart_units)"
    if [[ $RESTART -eq 1 ]]; then
        [[ -n "$list" ]] || { inf "no running Apache with mod_mono, XSP or Mono FastCGI service found to restart"; return 0; }
        while IFS= read -r u; do
            if systemctl restart "$u" 2>/dev/null; then info "restarted ${u}"; else bad "could not restart ${u}: restart it yourself"; fi
        done <<<"$list"
    else
        inf "Nothing was restarted. Mono's System.Web watches web.config and unloads the application when it changes, so the next request runs without the module."
        if [[ -n "$list" ]]; then inf "If a server runs with that watch turned off, restart it: --restart, or yourself: ${list//$'\n'/ }"; fi
    fi
}
cmd_mitigate() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (mitigate [--dry-run] [--restart])" ;; esac; done
    [[ $dry -eq 1 ]] || need_root "mitigate changes web.config files"
    have python3 || die "mitigate needs python3: it edits web.config files without following links and checks the result as XML before it replaces anything"
    find_mono_apps
    local roots f n p todo=() d
    roots="$(search_roots)"
    step "web.config files that register the module"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        grep -qiE 'Idunno\.AntiCsrf|AntiCsrfModule' "$f" 2>/dev/null || continue
        if [[ -L "$f" ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "${f}: a symbolic link, left alone: change the file it points to by hand"; continue; fi
        read -r n p <<<"$(xml_op count "$f")"
        if [[ "$p" == link || "$p" == notreg ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "${f}: not a regular file, left alone"; continue; fi
        if [[ "$p" == bad ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "${f}: not well-formed XML, left alone: fix it by hand"; continue; fi
        [[ "${n:-0}" -gt 0 ]] && { todo+=("$f"); inf "${f}: ${n} registration(s)"; }
    done < <({ [[ -n "$roots" ]] && while IFS= read -r r; do find "$r" -maxdepth "$MAX_DEPTH" \( -type f -o -type l \) -iname web.config 2>/dev/null; done <<<"$roots"
               for d in $MONO_CONF_DIRS; do [[ -d "$d" ]] && find "$d" -maxdepth 3 -type f -iname web.config 2>/dev/null; done; } | awk '!seen[$0]++')
    if [[ ${#todo[@]} -eq 0 ]]; then
        if [[ $N_REVIEW -gt 0 ]]; then warn "No registration was changed; ${N_REVIEW} file(s) could not be parsed (above)."; return 1; fi
        info "No web.config registers Idunno.AntiCsrf: nothing to do."; return 0
    fi
    if [[ $dry -eq 1 ]]; then
        step "Verdict"
        info "DRY RUN: ${#todo[@]} file(s) would be copied under ${STATE_DIR}/backups and changed; nothing was written."
        return 0
    fi
    local stamp bk b failed=0 i=0
    stamp="$(date -u +%Y%m%dT%H%M%SZ)-$$"; bk="${STATE_DIR}/backups/${stamp}"
    mkdir -p "$bk" || die "Cannot create ${bk}"
    chmod 700 "$STATE_DIR" "$STATE_DIR/backups" "$bk" 2>/dev/null || true
    step "Changing"
    for f in "${todo[@]}"; do
        i=$((i + 1)); b="${bk}/$(printf '%03d' "$i")-$(printf '%s' "$f" | sed 's#/#_#g')"
        local q state fmode fuid fgid
        read -r _ q state fmode fuid fgid <<<"$(python3 -c "$PY_XML" change "$f" "$b" 2>/dev/null)"
        if [[ "$state" == changed ]]; then
            manifest_add "$stamp" "$f" "$b" "$fmode" "$fuid" "$fgid"
            info "${f}: module removed (copy: ${b})"
        else
            rm -f "$b"
            case "$q" in
                link|notreg) bad "${f}: became a link or a special file while being read: left alone" ;;
                bad) bad "${f}: the result would not parse: left alone" ;;
                *) bad "${f}: could not be changed (${q:-no answer}): left alone" ;;
            esac
            failed=$((failed + 1))
        fi
    done
    step "Verdict"
    if [[ $failed -gt 0 ]]; then warn "${failed} file(s) could not be changed (above)."; maybe_restart; return 1; fi
    maybe_restart
    if [[ $N_REVIEW -gt 0 ]]; then warn "${N_REVIEW} file(s) could not be parsed and were left alone: check them by hand."; return 1; fi
    warn "Idunno.AntiCsrf no longer runs in those applications, and neither does its CSRF protection. Replace it with a supported mechanism, delete Idunno.AntiCsrf.dll and the csrfSettings section once no page refers to it, and run hunt. To undo: sudo ${SELF} rollback"
    return 0
}
cmd_rollback() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (rollback [--dry-run] [--restart])" ;; esac; done
    local manifest="${STATE_DIR}/manifest"
    [[ -s "$manifest" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes web.config files"
    step "Rolling back"
    have python3 || [[ $dry -eq 1 ]] || die "rollback needs python3, to write without following links"
    local rc=0 stamp path b fmode fuid fgid res
    # Newest first, so where two runs saved the same file, the oldest copy, the true original, is put back last.
    # Each copy is written to a new file next to the target and renamed over it, with its original owner and mode.
    while IFS=$'\t' read -r stamp path b fmode fuid fgid; do
        [[ -n "$path" ]] || continue
        if [[ ! -r "$b" ]]; then bad "${path}: its copy ${b} is missing, left alone"; rc=1; continue; fi
        if [[ $dry -eq 1 ]]; then echo "  would restore ${path} from ${b}"; continue; fi
        res="$(python3 -c "$PY_XML" restore "$path" "$b" "${fmode:-0644}" "${fuid:-0}" "${fgid:-0}" 2>/dev/null)"
        case "$res" in
            ok) info "restored ${path}" ;;
            notreg) bad "${path}: is now a link or a special file: left alone, restore it by hand from ${b}"; rc=1 ;;
            *) bad "${path}: could not be restored from ${b}"; rc=1 ;;
        esac
    done < <(tac "$manifest")
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was written."; return "$rc"; fi
    if [[ $rc -eq 0 ]]; then mv "$manifest" "${manifest}.rolled-back-$(date +%s)" 2>/dev/null || true; fi
    maybe_restart
    [[ $rc -eq 0 ]] && warn "Rolled back: Idunno.AntiCsrf is registered again where it was, and so is the hole."
    return "$rc"
}

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

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}: Idunno.AntiCsrf has no fix; the remedy is to take it out"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
