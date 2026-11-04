#!/usr/bin/env python3
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: icons for the documentation site
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The READMEs use emoji, which look right on GitHub and Codeberg. The documentation
# site shows a solid, single-color icon in their place, drawn in the style of
# Font Awesome's solid set (original shapes, 24 by 24 grid, fill only), colored by
# the text around it through currentColor.
#
# This module is used by gen-site.py and by the privacysafe.app docs builder. Keep
# the copies of it identical (packaging/psf_icons.py and docs/_build/psf_icons.py).
#
#   python3 packaging/psf_icons.py sheet out.html   write a page that shows every icon
#
# To add an icon: draw it on the 24 by 24 grid, add it to ICONS, map its emoji in
# EMOJI_ICON, and look at the sheet. A build stops on an emoji that has no icon, so
# no emoji reaches a page by accident.
#
# Assisted-by: Claude Sonnet 5.5
# =============================================================================
import html as _html
import re
import sys

# name: path data on a 24 by 24 grid, filled with fill-rule evenodd where a shape has holes. An icon made of
# several shapes that overlap is a tuple of paths, one per shape, so the overlaps merge.
ICONS = {
    # a closed shipping box with a tape slot
    "box": "M3 3h18a1 1 0 0 1 1 1v3.2a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1zM4 9.6h16v9.9a1.8 1.8 0 0 1-1.8 1.8H5.8A1.8 1.8 0 0 1 4 19.5V9.6zm5.5 2.1a.8.8 0 0 0 0 1.6h5a.8.8 0 0 0 0-1.6h-5z",
    # a tray with an arrow going into it
    "inbox-in": "M10.6 2.6h2.8v5.9h2.7L12 13 7.9 8.5h2.7V2.6zM2.6 13.2h5.2l1.1 2.2c.2.4.6.6 1 .6h4.2c.4 0 .8-.2 1-.6l1.1-2.2h5.2v6.3a2 2 0 0 1-2 2H4.6a2 2 0 0 1-2-2v-6.3z",
    # a wall calendar
    "calendar": "M7 1.9a1.1 1.1 0 0 1 1.1 1.1v1h7.8V3A1.1 1.1 0 0 1 18 3v1h1a3 3 0 0 1 3 3v12a3 3 0 0 1-3 3H5a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h1V3A1.1 1.1 0 0 1 7 1.9zM4.2 10.2v8.9c0 .5.4.9.9.9h13.8c.5 0 .9-.4.9-.9v-8.9H4.2zm3 2.3h2.6v2.5H7.2v-2.5zm4.5 0h2.6v2.5h-2.6v-2.5zm4.5 0h2.6v2.5h-2.6v-2.5zM7.2 16.2h2.6v2.5H7.2v-2.5zm4.5 0h2.6v2.5h-2.6v-2.5z",
    # a warning triangle with an exclamation mark
    "triangle-exclamation": "M12 2.4c.7 0 1.4.4 1.8 1l8.5 14.9c.8 1.4-.2 3.2-1.8 3.2H3.5c-1.6 0-2.6-1.8-1.8-3.2L10.2 3.4c.4-.6 1.1-1 1.8-1zm0 6.1a1.1 1.1 0 0 0-1.1 1.1v4.4a1.1 1.1 0 0 0 2.2 0V9.6A1.1 1.1 0 0 0 12 8.5zm0 7.5a1.4 1.4 0 1 0 0 2.8 1.4 1.4 0 0 0 0-2.8z",
    # a building with a pediment and columns
    "landmark": "M11.2 1.8a1.7 1.7 0 0 1 1.6 0l8.4 4.2c.9.4.6 1.8-.4 1.8H3.2c-1 0-1.300-1.400-.4-1.800l8.4-4.2zM4.4 9.6h2.8v7.2H4.4V9.6zm6.2 0h2.8v7.2h-2.8V9.6zm6.2 0h2.8v7.2h-2.8V9.6zM3 18.4h18a1 1 0 0 1 1 1V21a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-1.6a1 1 0 0 1 1-1z",
    # three people: one in front and one on each side
    "users": (
        "M12 3.700a3.400 3.400 0 1 0 0 6.800 3.400 3.400 0 0 0 0-6.800z",
        "M12 12c-2.900 0-5 2-5 4.600v2.100c0 .700.600 1.300 1.300 1.300h7.400c.700 0 1.300-.600 1.300-1.300v-2.100c0-2.600-2.100-4.600-5-4.600z",
        "M4.400 6.600a2.300 2.300 0 1 0 0 4.600 2.300 2.300 0 0 0 0-4.600zM4.400 12.500C2.500 12.500 1 13.900 1 15.700v1.600c0 .700.500 1.200 1.200 1.200h2.600c-.2-.4-.3-.8-.3-1.200v-1.800c0-1.200.4-2.300 1.100-3.200-.4-.1-.8-.2-1.200-.2z",
        "M19.600 6.600a2.300 2.300 0 1 0 0 4.600 2.300 2.300 0 0 0 0-4.600zM19.600 12.500c1.900 0 3.400 1.400 3.400 3.200v1.600c0 .700-.5 1.200-1.200 1.200h-2.600c.2-.4.300-.8.300-1.200v-1.800c0-1.200-.4-2.300-1.100-3.200.4-.1.8-.2 1.200-.2z",
    ),
    # a closed padlock with a keyhole
    "lock": "M7 10V7a5 5 0 0 1 10 0v3h.5a2.5 2.5 0 0 1 2.5 2.5v7a2.5 2.5 0 0 1-2.5 2.5h-11A2.5 2.5 0 0 1 4 19.5v-7A2.5 2.5 0 0 1 6.5 10H7zm2.2 0h5.6V7a2.8 2.8 0 0 0-5.6 0v3zM12 13.6a1.7 1.7 0 0 0-.9 3.1v1.6a.9.9 0 0 0 1.8 0v-1.6a1.7 1.7 0 0 0-.9-3.1z",
    # a balance scale
    "scale-balanced": "M12 1.8a2.2 2.2 0 0 1 .9 4.2v1.2h8a1 1 0 1 1 0 2h-.5l2.5 5.6a1 1 0 0 1-.2 1.1 5 5 0 0 1-7.1 0 1 1 0 0 1-.2-1.1l2.5-5.6h-3.5v10.9h4a1 1 0 1 1 0 2H7.1a1 1 0 1 1 0-2h4V9.2H7.6l2.5 5.6a1 1 0 0 1-.2 1.1 5 5 0 0 1-7.1 0 1 1 0 0 1-.2-1.1l2.5-5.6h-.5a1 1 0 1 1 0-2h8V6A2.2 2.2 0 0 1 12 1.8zm-6.4 8.6L3.2 15.8a3 3 0 0 0 4.8 0l-2.4-5.4zm12.8 0-2.4 5.4a3 3 0 0 0 4.8 0l-2.4-5.4z",
    # a heart (the same one the privacysafe.app buttons use)
    "heart": "M12 20.6 10.6 19.3C5.7 14.9 2.5 12 2.5 8.4 2.5 5.5 4.8 3.2 7.7 3.2c1.6 0 3.2.8 4.3 2.05C13.1 4 14.7 3.2 16.3 3.2c2.9 0 5.2 2.3 5.2 5.2 0 3.6-3.2 6.5-8.1 10.9L12 20.6Z",
    # an open book
    "book-open": "M12 6.3C10.1 4.7 7.5 4 3.3 4.2a1 1 0 0 0-1 1v11.6a1 1 0 0 0 1.1 1c3.7-.2 6.1.4 8.6 2 2.5-1.6 4.9-2.2 8.6-2a1 1 0 0 0 1.1-1V5.2a1 1 0 0 0-1-1C16.5 4 13.9 4.7 12 6.3zm-.7 1.700v10.300h1.400V8h-1.400z",
    # a shield with a check mark
    "shield": "M12 1.9 4.3 4.8A1.5 1.5 0 0 0 3.3 6.2v5.1c0 5 3.2 9.2 8.4 11 .2.1.4.1.6 0 5.2-1.8 8.4-6 8.4-11V6.2a1.5 1.5 0 0 0-1-1.4L12 1.9zm3.6 6.7 1.3 1.2-5.8 6.1-3.3-3.2 1.3-1.3 2 1.9 4.5-4.7z",
    # sparkles: one large and two small four-point stars
    "sparkles": "M9.5 2.6 11.3 8l5.4 1.8-5.4 1.8-1.8 5.4-1.8-5.4L2.3 9.8 7.7 8l1.8-5.4zM18.2 2.4l.9 2.5 2.5.9-2.5.9-.9 2.5-.9-2.5-2.5-.9 2.5-.9.9-2.5zm-.6 11.3.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8.8-2.2z",
    # a laptop
    "laptop": "M5.6 3.5h12.8A1.6 1.6 0 0 1 20 5.1V14H4V5.1a1.6 1.6 0 0 1 1.6-1.6zM6 5.4v6.7h12V5.4H6zM1.8 15.6h20.4v1a2.7 2.7 0 0 1-2.7 2.7h-15a2.7 2.7 0 0 1-2.7-2.7v-1z",
    # a lightning bolt
    "bolt": "M13.6 1.6 4.6 13.4a.9.9 0 0 0 .7 1.5h5.1l-1.2 6.6c-.1.7.8 1 1.2.5l9-11.8a.9.9 0 0 0-.7-1.5h-5.1l1.2-6.6c.1-.7-.8-1-1.2-.5z",
    # a phone
    "mobile": "M7.5 1.8h9a2.7 2.7 0 0 1 2.7 2.7v15a2.7 2.7 0 0 1-2.7 2.7h-9a2.7 2.7 0 0 1-2.7-2.7v-15a2.7 2.7 0 0 1 2.7-2.7zm.1 2.4v12.4h8.8V4.2H7.6zM12 17.9a1.2 1.2 0 1 0 0 2.4 1.2 1.2 0 0 0 0-2.4z",
    # a globe: the outline, a meridian, the equator and two parallels
    "globe": (
        "M12 1.800a10.200 10.200 0 1 0 0 20.400 10.200 10.200 0 0 0 0-20.400zM12 3.600a8.400 8.400 0 1 1 0 16.800 8.400 8.400 0 0 1 0-16.800z",
        "M12 3.400a4.400 8.600 0 1 0 0 17.200 4.400 8.600 0 0 0 0-17.200zM12 3.400a2.900 8.600 0 1 1 0 17.200 2.900 8.600 0 0 1 0-17.200z",
        "M3.600 11.100h16.800v1.800H3.600z",
        "M5.200 6.900h13.600v1.500H5.200z",
        "M5.200 15.600h13.600v1.500H5.200z",
    ),
    # a wrench
    "wrench": "M22 6.2a1 1 0 0 0-1.700-.5l-2.600 2.600-2-.5-.5-2 2.600-2.600a1 1 0 0 0-.5-1.700 6.2 6.2 0 0 0-7.400 7.900L2.600 16.300a2.800 2.800 0 0 0 4 4l6.900-6.900A6.200 6.200 0 0 0 22 6.200zM5.600 17.100a1.100 1.100 0 1 1 0 2.200 1.100 1.100 0 0 1 0-2.200z",
    # a magnifying glass
    "magnifier": "M10.200 2a8.200 8.200 0 1 0 4.900 14.800l5.100 5.100a1.400 1.400 0 0 0 2-2l-5.100-5.100A8.200 8.200 0 0 0 10.200 2zm0 2.600a5.600 5.600 0 1 1 0 11.200 5.600 5.600 0 0 1 0-11.200z",
    # an envelope
    "envelope": "M3.500 4.800h17A1.800 1.800 0 0 1 22.300 6.600v10.800a1.800 1.800 0 0 1-1.800 1.800h-17A1.800 1.800 0 0 1 1.700 17.400V6.600A1.800 1.800 0 0 1 3.500 4.800zm.5 2.300L12 13.100l8-6-1.100-1.400L12 10.900 5.100 5.700 4 7.100z",
    # a download arrow into a tray line (the header's button on a phone)
    "download": "M10.900 2.800h2.200v9.100l3.300-3.300 1.600 1.600L12 16.100 6 10.200l1.600-1.600 3.300 3.300V2.800zM4 18.400h16v2.200H4v-2.200z",
    # Brand marks for the footer. These six come from Simple Icons (https://simpleicons.org, CC0 1.0), 24 by 24, one path each.
    # The brands' names and logos are their owners' trademarks. The "in" is a plain glyph of my own, not a logo:
    # LinkedIn's mark is no longer in Simple Icons.
    "mastodon": "M23.268 5.313c-.35-2.578-2.617-4.61-5.304-5.004C17.51.242 15.792 0 11.813 0h-.03c-3.98 0-4.835.242-5.288.309C3.882.692 1.496 2.518.917 5.127.64 6.412.61 7.837.661 9.143c.074 1.874.088 3.745.26 5.611.118 1.24.325 2.47.62 3.68.55 2.237 2.777 4.098 4.96 4.857 2.336.792 4.849.923 7.256.38.265-.061.527-.132.786-.213.585-.184 1.27-.39 1.774-.753a.057.057 0 0 0 .023-.043v-1.809a.052.052 0 0 0-.02-.041.053.053 0 0 0-.046-.01 20.282 20.282 0 0 1-4.709.545c-2.73 0-3.463-1.284-3.674-1.818a5.593 5.593 0 0 1-.319-1.433.053.053 0 0 1 .066-.054c1.517.363 3.072.546 4.632.546.376 0 .75 0 1.125-.01 1.57-.044 3.224-.124 4.768-.422.038-.008.077-.015.11-.024 2.435-.464 4.753-1.92 4.989-5.604.008-.145.03-1.52.03-1.67.002-.512.167-3.63-.024-5.545zm-3.748 9.195h-2.561V8.29c0-1.309-.55-1.976-1.67-1.976-1.23 0-1.846.79-1.846 2.35v3.403h-2.546V8.663c0-1.56-.617-2.35-1.848-2.35-1.112 0-1.668.668-1.67 1.977v6.218H4.822V8.102c0-1.31.337-2.35 1.011-3.12.696-.77 1.608-1.164 2.74-1.164 1.311 0 2.302.5 2.962 1.498l.638 1.06.638-1.06c.66-.999 1.65-1.498 2.96-1.498 1.13 0 2.043.395 2.74 1.164.675.77 1.012 1.81 1.012 3.12z",
    "bluesky": "M5.202 2.857C7.954 4.922 10.913 9.11 12 11.358c1.087-2.247 4.046-6.436 6.798-8.501C20.783 1.366 24 .213 24 3.883c0 .732-.42 6.156-.667 7.037-.856 3.061-3.978 3.842-6.755 3.37 4.854.826 6.089 3.562 3.422 6.299-5.065 5.196-7.28-1.304-7.847-2.97-.104-.305-.152-.448-.153-.327 0-.121-.05.022-.153.327-.568 1.666-2.782 8.166-7.847 2.97-2.667-2.737-1.432-5.473 3.422-6.3-2.777.473-5.899-.308-6.755-3.369C.42 10.04 0 4.615 0 3.883c0-3.67 3.217-2.517 5.202-1.026",
    "x-twitter": "M14.234 10.162 22.977 0h-2.072l-7.591 8.824L7.251 0H.258l9.168 13.343L.258 24H2.33l8.016-9.318L16.749 24h6.993zm-2.837 3.299-.929-1.329L3.076 1.56h3.182l5.965 8.532.929 1.329 7.754 11.09h-3.182z",
    "youtube": "M23.498 6.186a3.016 3.016 0 0 0-2.122-2.136C19.505 3.545 12 3.545 12 3.545s-7.505 0-9.377.505A3.017 3.017 0 0 0 .502 6.186C0 8.07 0 12 0 12s0 3.93.502 5.814a3.016 3.016 0 0 0 2.122 2.136c1.871.505 9.376.505 9.376.505s7.505 0 9.377-.505a3.015 3.015 0 0 0 2.122-2.136C24 15.93 24 12 24 12s0-3.93-.502-5.814zM9.545 15.568V8.432L15.818 12l-6.273 3.568z",
    "instagram": "M7.0301.084c-1.2768.0602-2.1487.264-2.911.5634-.7888.3075-1.4575.72-2.1228 1.3877-.6652.6677-1.075 1.3368-1.3802 2.127-.2954.7638-.4956 1.6365-.552 2.914-.0564 1.2775-.0689 1.6882-.0626 4.947.0062 3.2586.0206 3.6671.0825 4.9473.061 1.2765.264 2.1482.5635 2.9107.308.7889.72 1.4573 1.388 2.1228.6679.6655 1.3365 1.0743 2.1285 1.38.7632.295 1.6361.4961 2.9134.552 1.2773.056 1.6884.069 4.9462.0627 3.2578-.0062 3.668-.0207 4.9478-.0814 1.28-.0607 2.147-.2652 2.9098-.5633.7889-.3086 1.4578-.72 2.1228-1.3881.665-.6682 1.0745-1.3378 1.3795-2.1284.2957-.7632.4966-1.636.552-2.9124.056-1.2809.0692-1.6898.063-4.948-.0063-3.2583-.021-3.6668-.0817-4.9465-.0607-1.2797-.264-2.1487-.5633-2.9117-.3084-.7889-.72-1.4568-1.3876-2.1228C21.2982 1.33 20.628.9208 19.8378.6165 19.074.321 18.2017.1197 16.9244.0645 15.6471.0093 15.236-.005 11.977.0014 8.718.0076 8.31.0215 7.0301.0839m.1402 21.6932c-1.17-.0509-1.8053-.2453-2.2287-.408-.5606-.216-.96-.4771-1.3819-.895-.422-.4178-.6811-.8186-.9-1.378-.1644-.4234-.3624-1.058-.4171-2.228-.0595-1.2645-.072-1.6442-.079-4.848-.007-3.2037.0053-3.583.0607-4.848.05-1.169.2456-1.805.408-2.2282.216-.5613.4762-.96.895-1.3816.4188-.4217.8184-.6814 1.3783-.9003.423-.1651 1.0575-.3614 2.227-.4171 1.2655-.06 1.6447-.072 4.848-.079 3.2033-.007 3.5835.005 4.8495.0608 1.169.0508 1.8053.2445 2.228.408.5608.216.96.4754 1.3816.895.4217.4194.6816.8176.9005 1.3787.1653.4217.3617 1.056.4169 2.2263.0602 1.2655.0739 1.645.0796 4.848.0058 3.203-.0055 3.5834-.061 4.848-.051 1.17-.245 1.8055-.408 2.2294-.216.5604-.4763.96-.8954 1.3814-.419.4215-.8181.6811-1.3783.9-.4224.1649-1.0577.3617-2.2262.4174-1.2656.0595-1.6448.072-4.8493.079-3.2045.007-3.5825-.006-4.848-.0608M16.953 5.5864A1.44 1.44 0 1 0 18.39 4.144a1.44 1.44 0 0 0-1.437 1.4424M5.8385 12.012c.0067 3.4032 2.7706 6.1557 6.173 6.1493 3.4026-.0065 6.157-2.7701 6.1506-6.1733-.0065-3.4032-2.771-6.1565-6.174-6.1498-3.403.0067-6.156 2.771-6.1496 6.1738M8 12.0077a4 4 0 1 1 4.008 3.9921A3.9996 3.9996 0 0 1 8 12.0077",
    "telegram": "M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.82 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z",
    "linkedin": "M4 2h16a2 2 0 0 1 2 2v16a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zm3.200 3.600a1.700 1.700 0 1 0 0 3.400 1.700 1.700 0 0 0 0-3.400zM5.600 10.400v7.800h3.200v-7.800H5.600zm4.800 0v7.800h3.200v-4c0-1.100.4-1.700 1.300-1.700s1.300.6 1.300 1.700v4h3.200v-4.400c0-2.300-1.100-3.600-3.200-3.600-1.200 0-2.200.5-2.700 1.300v-1.100h-3.100z",
}

# emoji (without the variation selector) -> icon name
EMOJI_ICON = {
    "\U0001F4E6": "box",                  # package
    "\U0001F4E5": "inbox-in",             # inbox tray
    "\U0001F5D3": "calendar",             # spiral calendar
    "\u26A0": "triangle-exclamation",     # warning
    "\U0001F3DB": "landmark",             # classical building
    "\U0001F91D": "users",                # handshake: people working together
    "\U0001F510": "lock",                 # closed lock with key
    "\U0001F512": "lock",                 # closed lock
    "\u2696": "scale-balanced",           # balance scale
    "\u2764": "heart",                    # red heart
    "\U0001F49A": "heart",                # green heart
    "\U0001F4DA": "book-open",            # books
    "\U0001F6E1": "shield",               # shield
    "\u2728": "sparkles",                 # sparkles
    "\U0001F4BB": "laptop",               # laptop
    "\u26A1": "bolt",                     # high voltage
    "\U0001F4F1": "mobile",               # mobile phone
    "\U0001F30D": "globe",                # globe, Europe and Africa
    "\U0001F30E": "globe",                # globe, Americas
    "\U0001F310": "globe",                # globe with meridians
    "\U0001F6E0": "wrench",               # hammer and wrench
    "\U0001F9D0": "magnifier",            # face with monocle
    "\u2709": "envelope",                 # envelope
}

# These are plain text marks that scripts print and READMEs may quote. They are left alone.
KEEP_AS_TEXT = set("\u2713\u2717\u2192\u2190")

_PICT = "[\U0001F000-\U0001FAFF\u2600-\u26FF\u2700-\u27BF\u2B50\u2B55\u2300-\u23FF]"
EMOJI_RE = re.compile(_PICT + "\uFE0F?(?:\u200D" + _PICT + "\uFE0F?)*|\uFE0F")


def _is_text_mark(ch):
    return ch in KEEP_AS_TEXT


def svg(name, extra_class=""):
    """One icon as inline SVG, colored by the surrounding text."""
    if name not in ICONS:
        raise KeyError(f"no icon named {name}")
    cls = f"ico ico-{name}" + (f" {extra_class}" if extra_class else "")
    shapes = ICONS[name] if isinstance(ICONS[name], tuple) else (ICONS[name],)
    paths = "".join(f'<path fill="currentColor" fill-rule="evenodd" d="{d}"/>' for d in shapes)
    return (f'<svg class="{cls}" aria-hidden="true" focusable="false" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">{paths}</svg>')


def _name_for(match_text):
    base = match_text.replace("\uFE0F", "")
    if not base:
        return ""
    first = base[0]
    if _is_text_mark(first):
        return None
    if first in EMOJI_ICON:
        return EMOJI_ICON[first]
    raise ValueError(f"emoji {base!r} (U+{ord(first):04X}) has no icon: draw one in psf_icons.py and map it in EMOJI_ICON")


def iconize(markup):
    """Replace every emoji in the text of an HTML fragment with its icon.

    Only text between tags is touched: attributes, <pre>, <code>, <svg>, <script> and <style> are left alone.
    An emoji with no icon stops the build."""
    parts = re.split(r"(<pre\b.*?</pre>|<code\b.*?</code>|<svg\b.*?</svg>|<script\b.*?</script>|<style\b.*?</style>|<[^>]+>)", markup, flags=re.S)
    for i in range(0, len(parts), 2):
        def one(m):
            name = _name_for(m.group(0))
            if name == "":
                return ""
            if name is None:
                return m.group(0)
            return svg(name)
        parts[i] = EMOJI_RE.sub(one, parts[i])
    return "".join(parts)


def strip_emoji(text):
    """Plain text without emoji (for ids, the table of contents, search and metadata). Text marks like a check stay."""
    def one(m):
        return m.group(0) if _name_for_safe(m.group(0)) is None else ""
    out = EMOJI_RE.sub(one, text)
    return re.sub(r"[ \t]{2,}", " ", out).strip() if "\n" not in text else out


def _name_for_safe(t):
    base = t.replace("\uFE0F", "")
    return None if base and _is_text_mark(base[0]) else "x"


def has_emoji(text):
    return any(_name_for_safe(m.group(0)) is not None and m.group(0).replace("\uFE0F", "") for m in EMOJI_RE.finditer(text))


def sheet(path):
    cells = "".join(f'<figure><div class="big">{svg(n)}</div><div class="mid">{svg(n)}</div><div class="small">{svg(n)}</div><figcaption>{_html.escape(n)}</figcaption></figure>' for n in ICONS)
    page = ("<!doctype html><meta charset=\"utf-8\"><title>PrivacySafe icons</title><style>"
            "body{margin:24px;background:#1b1713;color:#f2e9e1;font:14px sans-serif}"
            ".grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:18px}"
            "figure{margin:0;padding:14px;border:1px solid #3a322c;border-radius:12px;text-align:center}"
            ".big svg{width:96px;height:96px;color:#ff7a45}.mid svg{width:32px;height:32px;color:#f2e9e1}.small svg{width:16px;height:16px;color:#c9bdb2}"
            ".mid,.small{display:inline-block;margin:8px 6px 0}figcaption{margin-top:6px;color:#c9bdb2}</style><div class=\"grid\">" + cells + "</div>")
    open(path, "w", encoding="utf-8").write(page)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "sheet":
        sheet(sys.argv[2])
        print(f"{len(ICONS)} icons written to {sys.argv[2]}")
    else:
        sys.exit("usage: psf_icons.py sheet OUT.html")
