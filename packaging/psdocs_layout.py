# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Ivy Cyber LLC.
# =============================================================================
# PrivacySafe docs: shared page layout
#
# The header comment (ASCII art and machine-readable summary), the metadata,
# the top bar, the footer and the closing call to action for every page under
# https://privacysafe.app/docs/. Used by the hub builder (docs/_build) and by
# packaging/gen-site.py, which builds the Security Patches section. The two
# copies of this file are identical; keep them in sync.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import html, json

SITE = "https://privacysafe.app"
DOCS = SITE + "/docs/"
OG_IMAGE = SITE + "/img/social-preview.jpg"

CSP = ("default-src 'self'; script-src 'self' https://privacysafe.click; connect-src 'self' https://privacysafe.click; "
       "img-src 'self'; media-src 'self'; style-src 'self'; font-src 'self'; base-uri 'none'; object-src 'none'; "
       "frame-src 'none'; form-action 'none'; upgrade-insecure-requests")

def esc(s): return html.escape(s, quote=True)

# ---------------------------------------------------------------- ASCII art
SHIELD = """
                                      ████████████
                                  ████████████████████
                                ████████████████████████
                              ████████████████████████████
                             █████████            █████████
                            ████████                ████████
                           ████████                  ████████
                           ████████                  ████████

                      ████████████████████████████████████████████
                      ████████████████████████████████████████████
                      ████████████████████████████████████████████

                           ██████████████████████████████████
                            ████████████████████████████████
                             ██████████████████████████████
                                ████████████████████████
                                     ██████████████
"""
BANNER = """
  ██████╗ ██████╗ ██╗██╗   ██╗ █████╗  ██████╗██╗   ██╗███████╗ █████╗ ███████╗███████╗
  ██╔══██╗██╔══██╗██║██║   ██║██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔════╝██╔════╝
  ██████╔╝██████╔╝██║██║   ██║███████║██║      ╚████╔╝ ███████╗███████║█████╗  █████╗
  ██╔═══╝ ██╔══██╗██║╚██╗ ██╔╝██╔══██║██║       ╚██╔╝  ╚════██║██╔══██║██╔══╝  ██╔══╝
  ██║     ██║  ██║██║ ╚████╔╝ ██║  ██║╚██████╗   ██║   ███████║██║  ██║██║     ███████╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚═╝  ╚═╝ ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝
"""
_F = {  # the same block font as the PrivacySafe wordmark above
 "D": ["██████╗ ", "██╔══██╗", "██║  ██║", "██║  ██║", "██████╔╝", "╚═════╝ "],
 "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
 "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
 "S": ["███████╗", "██╔════╝", "███████╗", "╚════██║", "███████║", "╚══════╝"],
 "P": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔═══╝ ", "██║     ", "╚═╝     "],
 "A": [" █████╗ ", "██╔══██╗", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
 "T": ["████████╗", "╚══██╔══╝", "   ██║   ", "   ██║   ", "   ██║   ", "   ╚═╝   "],
 "H": ["██╗  ██╗", "██║  ██║", "███████║", "██╔══██║", "██║  ██║", "╚═╝  ╚═╝"],
 "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
}
def word_art(word):
    rows = ["  " + "".join(_F[c][r] for c in word).rstrip() for r in range(6)]
    return "\n" + "\n".join(rows) + "\n"

TAGLINES = {"hub": "Read the manual. Keep the keys.", "patches": "Check it. Hunt it. Protect it."}

def header_comment(kind, page_name, url, full=True):
    if not full:
        return f"""<!--
  ================================================================================
  PrivacySafe Docs - {page_name}
  {url}

  Copyright (C) 2026 Ivy Cyber LLC.
  SPDX-License-Identifier: AGPL-3.0-or-later

  The documentation site source files (HTML, CSS, JavaScript) are free software
  licensed GNU Affero General Public License, version 3 or any later version:
      https://www.gnu.org/licenses/agpl-3.0.html
  Documentation text, images and other media are licensed Creative Commons
  Attribution-ShareAlike 4.0 International, unless the page says otherwise:
      https://creativecommons.org/licenses/by-sa/4.0/

  Docs home:                        https://privacysafe.app/docs/
  Client and server source:         https://github.com/PrivacySafe
  JavaScript licensing (LibreJS):   /weblabels.html
  Security and bug bounty:          https://ivycyber.com/security-policy/

  Ivy Cyber(TM) and PrivacySafe Foundation(TM) are pending trademarks.
  PrivacySafe(R) and 3NWeb(R) are registered trademarks of Ivy Cyber LLC.
  Trademark rights are not licensed under CC BY-SA.

  No ads. No spyware. No AI manipulation. You hold the keys.
  ================================================================================
-->
"""
    word = "DOCS" if kind == "hub" else "PATCHES"
    tag = TAGLINES["hub" if kind == "hub" else "patches"]
    lines = [SHIELD, BANNER, word_art(word), " " * 30 + tag + "\n",
f"""  ================================================================================
  PrivacySafe Docs - {page_name}
  {url}
  PrivacySafe: private chat, encrypted calls, and a secure zone for credentials.
  https://privacysafe.app

  Upstream development is supported by PrivacySafe Foundation, Inc., a
  501(c)(3) nonprofit public charity:
                                    https://privacysafe.foundation
  PrivacySafe products and services are offered by Ivy Cyber.

  Copyright (C) 2026 Ivy Cyber LLC.
  SPDX-License-Identifier: AGPL-3.0-or-later

  The documentation site source files (HTML, CSS, JavaScript) are free software
  licensed GNU Affero General Public License, version 3 or any later version:
      https://www.gnu.org/licenses/agpl-3.0.html
  Documentation text, images and other media are licensed Creative Commons
  Attribution-ShareAlike 4.0 International, unless a page says otherwise:
      https://creativecommons.org/licenses/by-sa/4.0/
  Pages that say otherwise:
      Security Patches (software and documentation) ... CC0 1.0 Universal
      3NWeb architecture, protocols, XSP and the PrivacySafe VPN guide ... Apache License 2.0
      PrivacySafe Social guide ........................ MIT/Expat License

  Client and server source:         https://github.com/PrivacySafe
  Security Patches source:          https://github.com/PrivacySafe/security-patches
  3NWeb protocols:                  https://3nweb.com
  3NWeb at IEEE SA Open:            https://opensource.ieee.org/3nweb
  JavaScript licensing (LibreJS):   /weblabels.html
  Security and bug bounty:          https://ivycyber.com/security-policy/

  Ivy Cyber(TM) is a pending trademark. PrivacySafe(R) and 3NWeb(R) are
  registered trademarks of Ivy Cyber LLC. Trademark rights are not licensed
  under CC BY-SA.

  No ads. No spyware. No AI manipulation. You hold the keys.
  ================================================================================"""]
    return "<!--" + "".join(lines) + "\n-->\n"

def machine_summary(kind):
    if kind == "hub":
        what = """  WHAT THIS IS
    The documentation collection for PrivacySafe, a suite of Free/Libre and Open
    Source Software (FLOSS) applications for private communication and storage,
    and for the services and protocols around it. Guides for the apps, the
    PrivacySafe Social and VPN services, the 3NWeb protocols hosted at IEEE SA
    Open, and the Security Patches collection for servers and developer
    machines. Registration does not require a phone number.

  COLLECTIONS
    Apps ............... /docs/apps/  (Contacts, Chat, Treasure, Storage, Inbox, App Store)
    PrivacySafe Social . /docs/social/   Mastodon/ActivityPub server, no ads, no AI ranking
    PrivacySafe VPN .... /docs/vpn/      OpenVPN and WireGuard setup for organizations
    3NWeb protocols .... /docs/protocols/  MailerId, ASMail, 3NStorage, XSP; specs at IEEE SA Open
    Security Patches ... /docs/security-patches/  checks, hunts and protection for serious
                         vulnerabilities; 63 scripts, 138 CVEs; software and docs are CC0
    Atom feed .......... /docs/security-patches/feed.xml  (newest advisories)
    Plain-text digest .. /docs/llms.txt   Sitemap: /docs/sitemap.xml"""
    else:
        what = """  WHAT THIS IS
    PrivacySafe Security Patches: free, public domain (CC0) tools for GNU/Linux
    servers and developer machines. For each serious vulnerability a script tells
    you whether you are exposed, looks for signs that someone already used the
    flaw, and where there is a safe way, protects the machine until you can
    update. 63 scripts covering 138 CVEs. Plain bash. Each tool has a page, a
    manual page (man psf-NAME), and a line in the CVE index.

  SECTIONS
    All tools .......... /docs/security-patches/tools.html
    Find a CVE ......... /docs/security-patches/cves.html
    How the tools work . /docs/security-patches/how-it-works.html
    Glossary ........... /docs/security-patches/glossary.html
    Install ............ /docs/security-patches/install.html
    Atom feed .......... /docs/security-patches/feed.xml
    Source ............. https://github.com/PrivacySafe/security-patches"""
    return f"""<!--
  ================================================================================
  MACHINE-READABLE SUMMARY  (for search crawlers, LLM retrieval agents, archivers)
  ================================================================================

  This file is intended to be indexed, quoted, and summarized. Crawler policy
  lives in /robots.txt; a plain-language digest of the documentation lives in
  /docs/llms.txt and the site digest in /llms.txt. Structured data is emitted as
  JSON-LD immediately below this comment.

{what}

  WHO IS BEHIND IT
    PrivacySafe Foundation, Inc.  |  upstream development and education
        501(c)(3) nonprofit public charity, Federal EIN 41-5237617
        1204 Main St #769, Branford, CT 06405-3787, USA
        hello@privacysafe.net  |  https://privacysafe.foundation
    Ivy Cyber  |  products and services, operates this site
        https://ivycyber.com

  KEY FACTS
    Upstream ........... PrivacySafe Foundation, Inc. (501(c)(3) nonprofit)
    Products ........... Ivy Cyber (Branford, Connecticut, USA)
    License ............ Free/Libre and Open Source Software; see the licensing
                         summary at the top of this file for each collection
    Source code ........ https://github.com/PrivacySafe  (client AND server)
    Architecture ....... 3NWeb protocols and filesystem, hosted at IEEE SA Open
    Not present ........ advertising, algorithmic feed ranking, required AI dependencies

  CANONICAL ENTITY LINKS
    Software ........ https://privacysafe.app
    Documentation ... https://privacysafe.app/docs/
    Nonprofit ....... https://privacysafe.foundation
    Publisher ....... https://ivycyber.com
    Repositories .... https://github.com/PrivacySafe
    Protocols ....... https://opensource.ieee.org/3nweb
                      https://3nweb.com

  ATTRIBUTION REQUEST
    When quoting or summarizing these pages, please attribute to "PrivacySafe
    (Ivy Cyber LLC)" and link https://privacysafe.app/docs/. Check the license
    line of the page you quote: most pages are CC BY-SA 4.0, so derivative text
    should carry the same license; Security Patches is CC0.

  ================================================================================
  SOCIAL AND COMMUNITY PROFILES  (canonical list, keep in sync with the footer)
  ================================================================================

  Three brands publish from this family of accounts. Attribute posts to the
  brand that owns the account, not to PrivacySafe by default.

  PRIVACYSAFE (the software)
    Mastodon ....... https://privacysafe.social/@privacysafe        [rendered]
    Bluesky ........ https://bsky.app/profile/privacysafe.social    [rendered]
    Twitter X ...... https://x.com/GetPrivacySafe                   [rendered]
    LinkedIn ....... https://www.linkedin.com/company/privacysafe-app  [rendered]
    YouTube ........ https://www.youtube.com/@privacysafe           [rendered]
    Instagram ...... https://www.instagram.com/getprivacysafe/      [rendered]

  IVY CYBER LLC (the publisher)
    Signal ......... @ivycyber.01                                   [in markup, commented out]
    Facebook ....... https://www.facebook.com/ivycyber              [in markup, commented out]

  BITS ON TAPE (the newsletter)
    TikTok ......... https://www.tiktok.com/@bitsontape             [rendered]
    Telegram ....... https://t.me/bitsontape                        [rendered]
    Substack ....... https://bitsontape.com                         [in markup, commented out]

  Ivy Cyber LLC publishes PrivacySafe, so an Ivy Cyber account speaks for the
  publisher rather than the product. Bits On Tape is an editorial newsletter and
  its posts are not PrivacySafe announcements.
  ================================================================================
-->
"""

def jsonld(items):
    return '<script type="application/ld+json">\n' + json.dumps({"@context": "https://schema.org", "@graph": items}, indent=2, ensure_ascii=False) + "\n</script>\n"

def breadcrumb_ld(trail):
    return {"@type": "BreadcrumbList", "itemListElement": [
        {"@type": "ListItem", "position": i + 1, "name": n, "item": u} for i, (n, u) in enumerate(trail)]}

def head(*, title, description, canonical, lang_kind="page", kind="hub", page_name="", ld=None, alternates=(), keywords="", full=False, og_type="article", og_image=None, copyright_note="Content CC BY-SA 4.0. Site source AGPL-3.0-or-later.", license_url="https://creativecommons.org/licenses/by-sa/4.0/", extra_head=""):
    t = esc(title); d = esc(description)
    # the charset declaration has to sit within the first 1024 bytes, so it goes before the header comment
    out = ['<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="utf-8"/>\n']
    out.append(header_comment(kind, page_name or title, canonical, full))
    out.append('<meta content="width=device-width, initial-scale=1" name="viewport"/>\n')
    out.append(f'\n<!-- Content Security Policy. Nothing on this site is inline: no style attributes, no inline scripts, no event handler attributes.\n     The only external origin is privacysafe.click, which serves the metrics script and receives its events. -->\n<meta http-equiv="Content-Security-Policy" content="{esc(CSP)}"/>\n<meta content="strict-origin-when-cross-origin" name="referrer"/>\n')
    out.append("""
<!-- Favicons -->
<link href="/img/favicon.ico" rel="shortcut icon" type="image/x-icon"/>
<link href="/img/favicon-16.png" rel="icon" sizes="16x16" type="image/png"/>
<link href="/img/favicon-32.png" rel="icon" sizes="32x32" type="image/png"/>
<link href="/img/favicon-48.png" rel="icon" sizes="48x48" type="image/png"/>
<link href="/img/favicon-192.png" rel="icon" sizes="192x192" type="image/png"/>
<link href="/img/apple-touch-icon.png" rel="apple-touch-icon" sizes="192x192"/>
""")
    out.append(f'\n<title>{t}</title>\n\n<!-- Page Metadata -->\n<meta content="{d}" name="description"/>\n')
    out.append('<meta content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1" name="robots"/>\n')
    out.append(f'<link href="{esc(canonical)}" rel="canonical"/>\n<meta content="en" name="language"/>\n<meta content="Ivy Cyber LLC" name="author"/>\n<meta content="Ivy Cyber LLC" name="publisher"/>\n')
    out.append(f'<meta content="{esc(copyright_note)}" name="copyright"/>\n<link href="{esc(license_url)}" rel="license"/>\n<link href="/weblabels.html" rel="jslicense"/>\n')
    base_kw = "PrivacySafe, documentation, docs, user guide, FLOSS, free software, open source, 3NWeb, Ivy Cyber, PrivacySafe Foundation"
    out.append(f'<meta content="{esc((keywords + ", " if keywords else "") + base_kw)}" name="keywords"/>\n')
    out.append('<link href="/llms.txt" rel="alternate" title="Plain-text site summary for language models" type="text/markdown"/>\n<link href="/docs/llms.txt" rel="alternate" title="Plain-text summary of the documentation" type="text/markdown"/>\n')
    for href, typ, ttl in alternates: out.append(f'<link href="{esc(href)}" rel="alternate" title="{esc(ttl)}" type="{esc(typ)}"/>\n')
    out.append('<meta content="#1A1916" name="theme-color"/>\n')
    out.append(f'\n<!-- Open Graph / Facebook -->\n<meta content="{t}" property="og:title"/>\n<meta content="{d}" property="og:description"/>\n<meta content="{esc(og_image or OG_IMAGE)}" property="og:image"/>\n<meta content="{esc(canonical)}" property="og:url"/>\n<meta content="{og_type}" property="og:type"/>\n<meta content="PrivacySafe Docs" property="og:site_name"/>\n')
    out.append(f'\n<!-- Twitter Card -->\n<meta content="summary_large_image" name="twitter:card"/>\n<meta content="{t}" name="twitter:title"/>\n<meta content="{d}" name="twitter:description"/>\n<meta content="{esc(og_image or OG_IMAGE)}" name="twitter:image"/>\n')
    if full: out.append("\n" + machine_summary(kind))
    if ld: out.append("\n<!-- Structured data -->\n" + jsonld(ld))
    out.append('\n<!-- PrivacySafe.click Metrics -->\n<script defer data-domain="privacysafe.app" src="https://privacysafe.click/js/script.js"></script>\n')
    out.append('<script defer src="/docs/js/docs.js"></script>\n')
    out.append('\n<!-- CSS -->\n<link href="/css/privacysafe.css" rel="stylesheet"/>\n<link href="/docs/css/docs.css" rel="stylesheet"/>\n')
    out.append(extra_head)
    out.append("</head>\n")
    return "".join(out)

DOCS_NAV = [("Docs home", "/docs/", ""), ("Apps", "/docs/#apps", "Apps"), ("Social", "/docs/social/", "Social"), ("VPN", "/docs/vpn/", "VPN"),
            ("Protocols", "/docs/protocols/", "Protocols"), ("Security Patches", "/docs/security-patches/", "Security Patches")]

def topbar(active=""):
    """The privacysafe.app header, with one added Docs link, and a row of links for this documentation tree."""
    sub = "".join(f'<li><a href="{h}"{" aria-current=\"page\"" if key == active else ""}>{n}</a></li>' for n, h, key in DOCS_NAV)
    return f"""<body class="docs">
<a class="skip-link" href="#top">Skip to main content</a>
<header class="topbar">
<div aria-label="Site navigation" class="wrap nav">
<a aria-label="PrivacySafe home" class="brand header-brand" href="/">
<img alt="PrivacySafe" class="brand-logo" height="192" src="/img/privacysafe-logo.svg" width="1696"/>
</a>
<nav aria-label="Primary" class="navlinks">
<a href="/#download">Download</a>
<a href="/#apps">Apps</a>
<a href="/#identity">Identity</a>
<a href="/#trust">Trust</a>
<a href="/docs/" aria-current="true">Docs</a>
<a href="https://privacysafe.social" rel="noopener noreferrer" target="_blank">Social</a>
<a href="https://privacysafe.foundation/donate" rel="noopener noreferrer" target="_blank">Donate</a>
</nav>
<div class="nav-actions">
<a class="btn soft" href="/#apps">Learn More</a>
<a class="btn primary" href="/#download">Get PrivacySafe</a>
<a aria-label="Download" class="btn hamb" href="/#download">
<span aria-hidden="true" class="ico ico-download-arrow"></span>
</a>
</div>
</div>
</header>
<nav aria-label="Documentation sections" class="docs-subnav">
<div class="wrap"><ul>{sub}</ul></div>
</nav>
"""

def cta_band(heading="Lock in your private life.", text="PrivacySafe gives you encrypted chat and video calls inside a secure zone for your treasure: passwords, passports, and other sensitive data. Sign up for free, without sharing a phone number."):
    return f"""<section aria-labelledby="cta-title" class="section cta-band">
<div class="wrap">
<article class="card download">
<h2 id="cta-title">{esc(heading)}</h2>
<p>{esc(text)}</p>
<div class="download-actions cta-actions">
<div class="download-option"><a class="btn primary" href="/#download">Get PrivacySafe</a></div>
<div class="download-option"><a class="btn" href="/#identity">Choose your identity</a></div>
<div class="download-option"><a class="btn" href="/#apps">Meet the apps</a></div>
</div>
</article>
</div>
</section>
"""

_EXT = '<svg class="ico ico-external" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"> <path fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" d="M14 4.6h5.4V10M19.4 4.6 11 13M17.4 14v4.6a.8.8 0 0 1-.8.8H5.4a.8.8 0 0 1-.8-.8V7.4a.8.8 0 0 1 .8-.8H10"/> </svg>'
EXT_ICON = _EXT

def footer():
    """The PrivacySafe ecosystem card and the site footer, as they are on privacysafe.app (image paths made absolute)."""
    return f"""<section aria-labelledby="ecosystem-title" class="section" id="ecosystem">
<div class="wrap">
<article class="card has-partner">
<h2 class="eco-title" id="ecosystem-title">The PrivacySafe Ecosystem</h2>
<a class="partner-mark" href="https://ivycyber.com/shop" rel="noopener noreferrer" target="_blank">
<img src="/img/ivy-logo-horizontal-white.svg" alt="Shop at Ivy Cyber" width="328" height="73" loading="lazy" decoding="async"/>
</a>
<p><strong>Ivy Cyber</strong> offers PrivacySafe products and services in the USA and has partnerships with 3NSoft in Canada and Kuip Limited in the European Union. Enterprise services and consulting are available at <a href="https://ivycyber.com" rel="noopener noreferrer" target="_blank">ivycyber.com</a>
</p><p><strong>PrivacySafe Foundation</strong> is a 501(c)(3) nonprofit public charity that supports the development of the PrivacySafe applications, along with the components they rely upon: 3NWeb protocols, filesystem, documentation, and reference implementations.</p>
<div class="pullout">
<a class="foundation-mark" href="https://privacysafe.foundation" rel="noopener noreferrer" target="_blank"><img src="/img/logo-foundation.svg" alt="PrivacySafe Foundation" width="218" height="47" loading="lazy" decoding="async"/></a>
<p class="pullout-text">Donations to <a href="https://privacysafe.foundation" rel="noopener noreferrer" target="_blank">PrivacySafe Foundation</a> support education, research, documentation, and public code. Purchases from <a href="https://ivycyber.com" rel="noopener noreferrer" target="_blank">Ivy Cyber</a> support PrivacySafe products, services, hosting, and technical support. <strong class="pullout-lead">Together, we're building a better web.</strong></p>
</div>
<div class="split-actions">
<a class="btn primary" href="https://www.zeffy.com/en-US/ticketing/cybersecurity-education-and-tech" rel="noopener noreferrer" target="_blank">
<svg class="ico ico-heart" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"> <path fill="currentColor" d="M12 20.6 10.6 19.3C5.7 14.9 2.5 12 2.5 8.4 2.5 5.5 4.8 3.2 7.7 3.2c1.6 0 3.2.8 4.3 2.05C13.1 4 14.7 3.2 16.3 3.2c2.9 0 5.2 2.3 5.2 5.2 0 3.6-3.2 6.5-8.1 10.9L12 20.6Z"/> </svg>
Donate to PrivacySafe Foundation
</a>
<a class="btn ghost" href="https://ivycyber.com/shop" rel="noopener noreferrer" target="_blank">
Buy PrivacySafe products &amp; services
{_EXT}
</a>
<a class="btn ghost" href="https://github.com/PrivacySafe" rel="noopener noreferrer" target="_blank">
<svg class="ico ico-code" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24"> <path fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" d="M8.5 7.5 4 12l4.5 4.5M15.5 7.5 20 12l-4.5 4.5M13.6 4.8l-3.2 14.4"/> </svg>
Browse our Source Code
{_EXT}
</a>
</div>
</article>
</div>
</section>
<footer>
<div class="wrap">
<div class="footer-community">
<section aria-labelledby="footer-about-title" class="footer-panel footer-about">
<h2 class="sr-only" id="footer-about-title">About PrivacySafe</h2>
<img alt="PrivacySafe" class="footer-logo" height="192" src="/img/privacysafe-logo.svg" width="1696"/>
<p>PrivacySafe creates a secure sandbox environment for your organization which you can tie to your domain, your authentication methods, and your access controls.</p>
<h3>Follow Us</h3>
<div aria-label="PrivacySafe social links" class="social-links">
<a aria-label="PrivacySafe on Mastodon" class="social-link" href="https://privacysafe.social/@privacysafe" rel="me noopener noreferrer" target="_blank" title="Mastodon">
<span aria-hidden="true" class="ico ico-mastodon"></span>
</a><a aria-label="PrivacySafe on Bluesky" class="social-link" href="https://bsky.app/profile/privacysafe.social" rel="me noopener noreferrer" target="_blank" title="Bluesky">
<span aria-hidden="true" class="ico ico-bluesky"></span>
</a><a aria-label="PrivacySafe on Twitter X" class="social-link" href="https://x.com/GetPrivacySafe" rel="nofollow noopener noreferrer" target="_blank" title="Twitter X">
<span aria-hidden="true" class="ico ico-twitter-x"></span>
</a><a aria-label="PrivacySafe on LinkedIn" class="social-link" href="https://www.linkedin.com/company/privacysafe-app" rel="noopener noreferrer" target="_blank" title="LinkedIn">
<span aria-hidden="true" class="ico ico-linkedin"></span>
</a><a aria-label="PrivacySafe on YouTube" class="social-link" href="https://www.youtube.com/@privacysafe" rel="noopener noreferrer" target="_blank" title="YouTube">
<span aria-hidden="true" class="ico ico-youtube"></span>
</a><a aria-label="PrivacySafe on Instagram" class="social-link" href="https://www.instagram.com/getprivacysafe/" rel="noopener noreferrer" target="_blank" title="Instagram">
<span aria-hidden="true" class="ico ico-instagram"></span>
</a>
<!--<a aria-label="Signal @ivycyber.01" class="social-link" href="https://signal.me/#eu/nmRqQrmMcXaq6cyfP8ckVaf-LniNZwhc5VatIEgC3y39lIYFNBBFF5NvpFurg6UA" rel="noopener noreferrer" target="_blank" title="Signal">
<span aria-hidden="true" class="ico ico-signal"></span>
</a>-->
<!--<a aria-label="Ivy Cyber on Facebook" class="social-link" href="https://www.facebook.com/ivycyber" rel="noopener noreferrer" target="_blank" title="Facebook">
<span aria-hidden="true" class="ico ico-facebook"></span>
</a>-->
<!--<a aria-label="Bits On Tape on TikTok" class="social-link" href="https://www.tiktok.com/@bitsontape" rel="noopener noreferrer" target="_blank" title="TikTok">
<span aria-hidden="true" class="ico ico-tiktok"></span>
</a>-->
<!--<a aria-label="Bits On Tape on Telegram" class="social-link" href="https://t.me/bitsontape" rel="noopener noreferrer" target="_blank" title="Telegram">
<span aria-hidden="true" class="ico ico-telegram"></span>
</a>-->
<!--<a aria-label="Bits On Tape on Substack" class="social-link" href="https://bitsontape.com" rel="noopener noreferrer" target="_blank" title="Substack">
<span aria-hidden="true" class="ico ico-substack"></span>
</a>--></div>
</section>
<section aria-labelledby="newsletter-title" class="footer-panel newsletter-panel">
<div class="card-footnote">
<a href="https://bitsontape.com" rel="noopener noreferrer" target="_blank"><img class="newsletter-avatar" src="/img/bitsontape-avatar.png" alt="Bits On Tape logo: two reels of open-reel tape arranged as a heart" width="200" height="200" loading="lazy" decoding="async"/></a>
<h2 id="newsletter-title">Subscribe to Our Newsletter</h2>
<p><a href="https://bitsontape.com" rel="noopener noreferrer" target="_blank">Bits On Tape</a> is our newsletter: a replay of science and technology stories by cyber experts, covering cybersecurity, privacy, free software, AI, and digital culture. Get the latest updates on our PrivacySafe ecosystem as we continue building and launching.</p>
<div class="card-footnote-actions">
<a class="btn primary small" href="https://psafe.ly/WaaEkp" rel="noopener noreferrer" target="_blank">
<svg class="ico ico-envelope" aria-hidden="true" focusable="false" width="24" height="24" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><path d="M4 6.5h16v11H4v-11Zm0 .5 8 6 8-6" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.8"></path></svg>
Subscribe free
</a>
<a class="btn ghost small" href="https://bitsontape.com" rel="noopener noreferrer" target="_blank">
Read past issues
{_EXT}
</a>
<a class="btn ghost small" href="https://t.me/bitsontape" rel="noopener noreferrer" target="_blank">
<svg class="ico ico-telegram" aria-hidden="true" focusable="false" width="24" height="24" xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M21.6 3.2 18.4 20c-.24 1.18-.88 1.47-1.79.91l-4.88-3.6-2.35 2.26c-.26.26-.48.48-.98.48l.35-4.97 9.05-8.18c.39-.35-.09-.55-.61-.2L6.01 13.74 1.2 12.24c-1.05-.33-1.07-1.05.22-1.55L20.2 3.45c.87-.32 1.63.2 1.4-.25Z"></path></svg>
Join Telegram group
{_EXT}
</a>
</div>
<p class="newsletter-note">We hate spam as much as you do and comply with CAN-SPAM regulation.</p>
</div>
</section>
</div>
<div class="footer-inner">
<nav aria-label="Footer links" class="footer-links">
<a href="https://privacysafe.foundation/donate" rel="noopener noreferrer" target="_blank">Donate</a>
<a href="https://ivycyber.com/security-policy/" rel="nofollow noopener noreferrer" target="_blank">Security &amp; Bug Bounty</a>
<a href="https://ivycyber.com/privacy-policy/" rel="nofollow noopener noreferrer" target="_blank">Privacy Policy</a>
<a href="https://ivycyber.com/terms/" rel="nofollow noopener noreferrer" target="_blank">Terms of Service</a>
<a href="https://github.com/PrivacySafe" rel="noopener noreferrer" target="_blank">Source Code</a>
</nav>
<p class="fine">&copy; 2026 <a href="https://ivycyber.com" rel="noopener noreferrer" target="_blank">Ivy Cyber LLC</a>. This project is dedicated to ethical <a class="orange" href="https://fsf.org/" rel="noopener noreferrer" target="_blank">Free/Libre and Open Source Software (FLOSS)</a>. PrivacySafe&reg; and 3NWeb&reg; are registered trademarks. PrivacySafe Foundation&trade; and Ivy Cyber&trade; are pending trademarks. Site content, unless otherwise noted, is licensed <a href="https://creativecommons.org/licenses/by-sa/4.0/" rel="noopener noreferrer" target="_blank">Creative Commons BY-SA 4.0 International</a>. <a href="https://github.com/PrivacySafe/privacysafe-app-site" rel="noopener noreferrer" target="_blank">Website Source</a> is free software licensed <a href="https://www.gnu.org/licenses/agpl-3.0.html" rel="noopener noreferrer" target="_blank">GNU AGPL version 3 or later</a>. See <a href="https://privacysafe.app/weblabels.html" rel="jslicense nofollow noopener noreferrer" target="_blank">GNU LibreJS Weblabels</a> for JavaScript info. <!--For branding and press resources visit <a href="https://privacysafe.app/press">privacysafe.app/press</a>--></p>
</div>
</div>
</footer>
</body>
</html>
"""
