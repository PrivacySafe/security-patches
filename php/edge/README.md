# PHP2Shell edge guards

Part of the [PHP docs](../README.md) in the [PrivacySafe Security Patches](../../README.md) collection. These are **compensating controls, not a fix**: the only complete fix is a patched PHP (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or your distribution's backport). They narrow what a request can do on the way in and what a leak can do on the way out. They matter most for Apache `mod_php` hosts, which the [AppArmor layer](../README.md#php2shell-interim-mitigation) of `php2shell-mitigate.sh` does not reach (it confines PHP-FPM only). To see an attack rather than limit it, see [`php/detect/`](../detect/README.md).

The behaviour described here was verified on real servers with real PHP handlers (Apache 2.4.58 with `mod_php`, nginx 1.24.0 with PHP-FPM, both PHP 8.3.6), using benign requests only. [Verification](#verification) lists the checks.

## What is here

| File | Server | What it does |
|---|---|---|
| [`apache-php2shell-guard.conf`](apache-php2shell-guard.conf) | Apache httpd (`mod_php` or `proxy_fcgi`) | Multipart guard, cookie guard, and an optional body size limit (commented out) |
| [`nginx-php2shell-guard-http.conf`](nginx-php2shell-guard-http.conf) and [`nginx-php2shell-guard-server.conf`](nginx-php2shell-guard-server.conf) | nginx | Multipart guard, plus notes on nginx's own body size and response header limits |

The two servers do not offer the same controls, and the differences matter:

| Control | Apache | nginx |
|---|---|---|
| Multipart guard (log-only first) | Yes | Yes |
| Cuts an oversized `Set-Cookie` | Yes, with `mod_headers` | No. At default buffer sizes nginx refuses the response instead; see [nginx and oversized response headers](#nginx-and-oversized-response-headers) |
| Request body size limit | None by default; example provided | 1 MiB by default; keep it |

## Install and remove

These steps are for Debian and Ubuntu paths; other distributions keep the same files in different directories.

**Apache**

```bash
sudo cp apache-php2shell-guard.conf /etc/apache2/conf-available/php2shell-guard.conf
sudo a2enmod headers log_debug          # log_debug writes the log-only messages
sudo a2enconf php2shell-guard
sudo apachectl configtest && sudo systemctl reload apache2

# remove
sudo a2disconf php2shell-guard && sudo systemctl reload apache2
```

**nginx**

```bash
sudo cp nginx-php2shell-guard-http.conf /etc/nginx/conf.d/php2shell-guard-http.conf
sudo cp nginx-php2shell-guard-server.conf /etc/nginx/snippets/php2shell-guard.conf
# inside every server { } block you want guarded, add:
#     include snippets/php2shell-guard.conf;
sudo nginx -t && sudo systemctl reload nginx

# remove: delete the include lines and both files, then
sudo nginx -t && sudo systemctl reload nginx
```

## The multipart guard

The chain confirmed in the 24 October 2026 phpot honeypot report ([report](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)) was four `multipart/form-data` POSTs to `/` and `/index.php`. A path that takes no uploads does not need to accept multipart bodies, so the guard refuses a multipart POST unless its path is on your allowlist. It **starts in log-only mode**: nothing is blocked, and each request that would be blocked is logged (Apache: the error log, as `php2shell-guard: multipart POST to a path not on the allowlist`; nginx: `/var/log/nginx/php2shell-guard.log`). Run it that way, add every legitimate upload path to the allowlist, and only then enforce. A wrong allowlist breaks uploads, which is why the default does not block.

To enforce, uncomment `#Define P2S_ENFORCE` in the Apache file, or change the `1       0;` line in the nginx `p2s_deny` map to `1       1;`.

**The allowlist is written differently on each server**, because each tests a different thing:

| | Apache | nginx |
|---|---|---|
| What is tested | The original request line, so a rewrite to `index.php` does not change what the guard sees | The normalized URI path, without the query string. nginx does not re-evaluate it after `try_files` |
| Where it goes | The regular expression in the `<If>` condition | The `p2s_path_allowed` map |
| A longer or look-alike path (`/upload.php/extra`, `/upload.php.bak`) | Refused | Refused |
| A query string that contains an allowed path (`/other?n=/upload.php`) | Refused | Refused |

Examples for a WordPress site that needs media uploads. Apache (replace the default regular expression on the `%{THE_REQUEST}` line):

```text
m#^POST (/wp-admin/(async-upload|media-new)\.php|/wp-json/wp/v2/media)( |\?)#
```

nginx (entries in the `p2s_path_allowed` map):

```text
"~^/wp-admin/(async-upload|media-new)\.php$"  1;
"~^/wp-json/wp/v2/media$"                     1;
```

The Apache allowlist tests the original request line, not `%{REQUEST_URI}`: a per-directory rewrite such as WordPress's `RewriteRule . /index.php [L]` changes `REQUEST_URI` to `/index.php` before the guard runs, which would refuse an allowlisted upload route. Keep the allowlist short: an attacker can send multipart to any path you allow.

## The cookie guard (Apache only)

The disclosure stage of the chain returned a `PHPSESSID` of 819,200 bytes URL-decoded in `Set-Cookie`, which is about 2 MB on the wire once URL-encoded. A browser cannot store a cookie over 4096 bytes anyway, so the guard replaces the value of any `Set-Cookie` longer than that with a short marker. It needs `mod_headers`. It removes the leak from the response; it does not stop the memory read.

Tested with a benign value of the leak's size: 819,200 random bytes, URL-encoded the way PHP encodes a session ID (2,034,988 bytes on the wire), emitted by PHP under `mod_php`. Without the guard the response headers were 2,035,615 bytes and carried the whole value; with it they were 228 bytes, the value was replaced by the marker, and the guard wrote one log line. A plain 819,200-byte value was cut the same way.

Two consequences to know about:

- **The guard hides the leak from the size signal.** Once the cookie is cut, the response size an access log records (Apache `%O`) is small, so the oversized-response lead in `php2shell-watch.sh` and `hunt` can no longer see it. To keep a signal, the guard writes `php2shell-guard: oversized Set-Cookie value removed from a response` to the error log when it fires, and both tools flag that line. Keep the guard on: stopping the leak matters more than the lead.
- **That log line has a limit.** It is written only when the oversized cookie is the first `Set-Cookie` of the response, because Apache's log expression reads only the first value. The leak is emitted during PHP's session startup, before any application code runs, so in practice it is first. In any other position the cookie is still cut; it is just not logged.

## nginx and oversized response headers

nginx cannot cut a cookie by length: that needs a module we do not assume, and hiding `Set-Cookie` entirely would break sessions. It does something different by itself. nginx refuses an upstream response header larger than `fastcgi_buffer_size` (`proxy_buffer_size` when it proxies) with a `502` and `upstream sent too big header` in its error log. We sent a benign value of the leak's size (819,200 random bytes, URL-encoded as PHP encodes a session ID: 2,034,988 bytes on the wire; the encoded size of the real leak depends on its content) from PHP-FPM through nginx at several buffer sizes:

| nginx settings | Response | nginx error log |
|---|---|---|
| Defaults | `502` | `upstream sent too big header` |
| `fastcgi_buffer_size 16k; fastcgi_buffers 8 16k;` | `502` (a normal session page still returned `200` with its cookie) | `upstream sent too big header` |
| `fastcgi_buffer_size 1m; fastcgi_buffers 4 1m; fastcgi_busy_buffers_size 2m;` | `502` | `upstream sent too big header` |
| `fastcgi_buffer_size 4m; fastcgi_buffers 4 4m; fastcgi_busy_buffers_size 8m;` | `200`, the full cookie delivered | None |

`proxy_buffer_size` (nginx reverse-proxying to an HTTP backend such as Apache, rather than FastCGI) was checked the same way, against an Apache `mod_php` backend: defaults and `proxy_buffer_size 1m` both returned `502`, and a several-megabyte pool delivered the cookie. It behaves the same as `fastcgi_buffer_size`.

This is a side effect, not a control. A host whose buffers were enlarged past the size of the leak (about 2 MB for a value this size, which is unusual) delivers it silently, and the refused response only stops delivery: the memory read has already happened. If you run nginx in front of PHP-FPM, keep the buffers modest. When you set `fastcgi_buffer_size`, set `fastcgi_buffers` with it: `fastcgi_buffer_size 16k;` on its own makes nginx refuse to start, because its default busy-buffers value no longer fits the default buffer pool. Set the pool with the size for `proxy_buffer_size` too, for the same reason.

The error-log line is a detection signal: `php2shell-watch.sh` 1.4.3 and `hunt` 5.2.5 flag it as a lead. Large legitimate headers raise it too, so treat it as a reason to look, not as proof.

## Request body size limit

The phpot report gives the size of every stage's body: the first memory-pressure stage 1,060,211 bytes, the disclosure stage 33,128,677 bytes, and the other two 279,369 and 451,384 bytes. A web server refuses an oversized body before PHP sees it, so the table shows what a limit does to bodies of exactly those sizes (zero-filled test bodies, not exploit content; fixed-length and chunked requests gave identical results):

| Setting | 279,369 B | 451,384 B | 1,060,211 B | 33,128,677 B |
|---|---|---|---|---|
| nginx default (`client_max_body_size 1m`) | 200 | 200 | 413 | 413 |
| nginx `client_max_body_size 256k` | 413 | 413 | 413 | 413 |
| nginx `client_max_body_size 64m` | 200 | 200 | 200 | 200 |
| Apache default (no limit) | 200 | 200 | 200 | 200 |
| Apache `LimitRequestBody 1048576` | 200 | 200 | 413 | 413 |
| Apache `LimitRequestBody 262144` | 413 | 413 | 413 | 413 |

A 1 MiB limit refuses the first memory-pressure stage and the disclosure stage, and 256 KiB refuses all four. The phpot report links the leak from the disclosure stage to the address-like values in the final request, so refusing that stage matters most. PHP's advisory explains why the cap belongs at the web server: a multipart request with no usable `Content-Length` can pass `post_max_size`, so PHP's own limit does not stop a chunked body, while tests show nginx and Apache refuse chunked bodies over their limits (the bypass as summarized by the SANS Internet Storm Center and HeroDevs). Apache has no limit by default, which fits the phpot report's Apache targets being exploitable. nginx's default already refuses the two large stages, so a host that raised `client_max_body_size` server-wide for uploads (64m is common) lost that protection.

The limit also applies through real PHP handlers: with `mod_php` and with PHP-FPM, a 200 KB multipart upload to a PHP script succeeded and a 1.1 MB one was refused with `413`, at nginx's default and at `LimitRequestBody 1048576`.

This is the one control here that **cannot run log-only**: a limit that is too low refuses legitimate uploads with `413`, and there is no dry run. Set it low for the whole site and raise it only on the paths that take uploads. Verified on both servers: with 1 MiB server-wide and 64 MiB on one path, a 33 MB body was refused on the default path and accepted on the raised one, and a 279 KB body was accepted on both. The directives are in the guard files as commented examples, off by default: Apache's `LimitRequestBody` at the end of `apache-php2shell-guard.conf`, and nginx's `client_max_body_size` at the end of `nginx-php2shell-guard-server.conf`, the snippet you include in each server block. In nginx, a limit set at `http` level is only a default that any server or location setting its own overrides, and a second `client_max_body_size` in the same block makes `nginx -t` fail, so uncomment the nginx line only if the server does not already set one.

Limits: this is not a fix. The sizes the phpot report observed are not sizes the bug requires, an attacker can resize a request, and a site that must accept large bodies everywhere gets nothing from it. It refuses the observed, unmodified chain's large stages; it does not show the chain fails without them.

## Verify on every virtual host

A server-level setting can be overridden per host, so confirm the guard is live on each one. Send a multipart POST to each host and look for the guard's line:

```bash
# Apache (one request per virtual host; set the Host header)
curl -s -o /dev/null -w '%{http_code}\n' -F a=b -H 'Host: your.site' http://127.0.0.1/
grep php2shell-guard /var/log/apache2/error.log | tail -3

# nginx
curl -s -o /dev/null -w '%{http_code}\n' -F a=b -H 'Host: your.site' http://127.0.0.1/
tail -3 /var/log/nginx/php2shell-guard.log
```

In log-only mode you get your site's normal response and one log line; once enforcing, a path not on the allowlist returns `403`. A plain form POST (`-d a=b`) should be unaffected in both modes. If a host logs nothing, its configuration overrides the guard.

## Verification

Ubuntu, benign requests only (small uploads, zero-filled bodies, and leak-sized headers of plain characters, never exploit content). Apache 2.4.58 ran PHP 8.3.6 as `mod_php` with a per-directory WordPress-style rewrite to `index.php`, and separately as `mod_proxy_fcgi` in front of PHP-FPM; nginx 1.24.0 ran PHP 8.3.6 through PHP-FPM with `try_files` falling back to `index.php`, and separately as a reverse proxy in front of the Apache `mod_php` backend. One check ran against the official WordPress codebase.

| Check | Apache with `mod_php` | Apache with `proxy_fcgi` | nginx with PHP-FPM | nginx in front of Apache |
|---|---|---|---|---|
| Configuration test passes | Yes | Yes | Yes | Yes |
| Log-only: a multipart POST passes and is logged; a urlencoded POST is ignored | Yes | Yes | Yes | Yes |
| Enforcing: a multipart POST to a path not on the allowlist gets `403`; an allowlisted upload script gets `200` | Yes | Yes | Yes | Yes |
| An allowlisted route handled through the `index.php` rewrite gets `200` | Yes | - | Yes | - |
| Allowlist bypass attempts get `403` (an allowed path in the query string, an extra path segment, a look-alike suffix) | Yes | - | Yes | - |
| A chunked-encoding multipart body is matched the same as a fixed-length one | Yes | - | Yes | - |
| Real HTTP/2 (negotiated over TLS) | Falls back to HTTP/1.1; see below | - | Yes | - |
| A normal PHP session cookie is left untouched | Yes | Yes | Yes | Yes |
| 200 KB upload accepted, 1.1 MB upload refused with `413` | Yes, at `LimitRequestBody 1048576` | - | Yes, at the default `1m` | - |
| A leak-sized `Set-Cookie` from PHP (819,200 bytes decoded, about 2 MB on the wire) | Cut to the marker, one log line | `500`: `mod_proxy_fcgi`'s own FastCGI header-size limit rejects it before the guard runs | `502` at default, 16k and 1m buffers; delivered at 4m buffers | Same as nginx with PHP-FPM (`proxy_buffer_size` behaves the same as `fastcgi_buffer_size`) |
| A `Set-Cookie` that is not the first one in the response is still cut, but the log line does not fire | Yes (Apache's log expression reads only the first value) | - | - | - |
| Apache's allowlist matches the project's own documented WordPress example (`/wp-admin/async-upload.php`, `/wp-admin/media-new.php`, `/wp-json/wp/v2/media`) against the real WordPress codebase; a non-matching path (`/wp-login.php`, `/xmlrpc.php`) gets `403` | Yes | - | Yes (nginx's allowlist map) | - |

Also verified with simple handlers and zero-filled bodies: the full body-size matrix above (fixed-length and chunked), the per-path limit override on both servers, the Apache guard file's own `LimitRequestBody 1048576` example uncommented, and how nginx treats the directive: an `http`-level value is overridden by a server's own, a value in the server snippet applies, and a duplicate in the same block fails `nginx -t`.

**HTTP/2 and `mod_php` do not go together.** Apache's own HTTP/2 module declines to operate under the `prefork` MPM that `mod_php` requires (Apache logs this itself: "the currently selected mpm will just not do"), so it silently serves such a connection over HTTP/1.1 regardless of what the client negotiates. A `mod_php` host therefore never actually serves HTTP/2, and the guard's behaviour there is the same HTTP/1.1 behaviour already covered above. `proxy_fcgi` and PHP-FPM have no such restriction, and nginx's HTTP/2 behaviour was verified directly.

The nftables egress rule was loaded on a live system and generated a real DNS lookup and a real outbound TCP connection as the web account; both were recorded, and the same traffic run as a different user was not.

## Limits

- An attacker can send multipart to any path you allowlist, so keep the list short. A request filter cannot defeat a bug that is reachable through a legitimate upload path.
- These guards act on one reported shape of the attack. They do not stop the memory read, a CLI-server (`php -S`) exposure, or an attack that does not use a multipart POST.
- Log-only is the default for a reason. Do not enforce before a full period of normal traffic, including admin and API paths, has gone through it.

---

## 🏛️ Support PrivacySafe Foundation

[PrivacySafe Foundation](https://privacysafe.foundation) is a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, decentralized technology, documentation, standards work, and public-interest privacy and security research.

Security work doesn't stop when a disclosure drops at midnight. If this repository helped you protect your users, please help us keep doing it:

* **[Donate directly to the Foundation](https://privacysafe.foundation)**
* [Open Collective](https://opencollective.com/privacysafe)
* [Ko-fi](https://ko-fi.com/R6R1194HN7)
* [Liberapay](https://liberapay.com/PrivacySafe/donate)

The Foundation website provides options for card donations, PayPal/Venmo, cryptocurrency, checks, and other forms of support. Donations are often tax-deductible in the USA. Federal EIN: 41-5237617.

## 🤝 Contributing

Found a bug in a script, or have a mitigation that belongs here? Please fork and submit a focused pull request.

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../../NOTICE) and [`LICENSE`](../../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
