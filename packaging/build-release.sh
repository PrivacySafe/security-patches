#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: release builder  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Builds a release tarball, a .deb and an .rpm, all named psf-security-patches
# and versioned by release date: YY.MM.DD-X.Y.Z, for example 26.11.02-1.0.0.
# In the deb the date is the upstream version and X.Y.Z the revision; in the
# rpm the date is Version and X.Y.Z is Release. The packages install the whole
# tree to /opt/psf-security-patches and the php2shell-watch systemd unit to
# /usr/lib/systemd/system (not enabled), and the manual pages and info manual to
# /usr/share/man and /usr/share/info, and the HTML documentation site to
# /usr/share/doc/psf-security-patches/html. No maintainer scripts are used.
#
# The manual pages and the documentation site are generated here, from the scripts'
# --help text and the READMEs, into a temporary folder, and checked (check-site.py and
# check-manuals.sh; the manual check uses man-db, groff, mandoc and info where they are installed).
# The site is also kept in docs/ in the repository. The build stops when docs/ differs from the
# site it just generated, and tells you the command that refreshes it (PSF_SKIP_DOCS_CHECK=1
# skips the comparison). The manual pages are not kept in the repository, which
# holds the scripts, one README for each folder and docs/.
#
# Usage:
#   packaging/build-release.sh [--date YY.MM.DD] [--rev X.Y.Z] [--out DIR]
#
#   --date   release date, default today in UTC
#   --rev    release revision, default 1.0.0
#   --out    output directory, default ./dist
#
# Output is reproducible: the same tree, date and revision give the same
# tarball and deb. Needs tar, gzip, python3 with markdown-it-py and linkify-it-py
# (Debian: python3-markdown-it python3-linkify-it) and makeinfo (texinfo) to build
# the documentation, and dpkg-deb and rpmbuild for the packages; a missing package
# tool is reported and that package is skipped.
# =============================================================================
set -euo pipefail

PKG="psf-security-patches"
MAINT="Sean O'Brien <sean@ivycyber.com>"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATEVER="$(date -u +%y.%m.%d)"
REV="1.0.0"
OUT="$ROOT/dist"

usage() { sed -n '/^# Usage:/,/^# Output/p' "${BASH_SOURCE[0]}" | sed '$d;s/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --date) DATEVER="${2:?--date needs a value}"; shift 2 ;;
    --rev)  REV="${2:?--rev needs a value}"; shift 2 ;;
    --out)  OUT="${2:?--out needs a value}"; shift 2 ;;
    -h|--help|help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ "$DATEVER" =~ ^([0-9]{2})\.([0-9]{2})\.([0-9]{2})$ ]] || { echo "--date must look like YY.MM.DD" >&2; exit 2; }
YY="${BASH_REMATCH[1]}"; MM="${BASH_REMATCH[2]}"; DD="${BASH_REMATCH[3]}"
[[ "$REV" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "--rev must look like X.Y.Z" >&2; exit 2; }
SDE="$(date -u -d "20${YY}-${MM}-${DD} 00:00:00" +%s 2>/dev/null)" || { echo "not a real date: 20${YY}-${MM}-${DD}" >&2; exit 2; }
export SOURCE_DATE_EPOCH="$SDE"

FULL="${DATEVER}-${REV}"
TOP="${PKG}-${FULL}"
RFCDATE="$(date -u -d "@$SDE" -R)"
RPMDATE="$(date -u -d "@$SDE" +'%a %b %d %Y')"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

subst() {
  sed -e "s|@FULL@|$FULL|g" -e "s|@DATEVER@|$DATEVER|g" -e "s|@REV@|$REV|g" \
      -e "s|@MAINT@|$MAINT|g" -e "s|@SIZE@|${SIZE:-0}|g" -e "s|@RPMDATE@|$RPMDATE|g" "$1"
}

normalize() {
  find "$1" -type d -exec chmod 0755 {} +
  find "$1" -type f -exec chmod 0644 {} +
  find "$1" -type f -name '*.sh' -exec chmod 0755 {} +
  find "$1" -exec touch -h -d "@$SDE" {} +
}

# 1. Stage the tree (no .git, no previous output).
mkdir -p "$WORK/$TOP"
tar -C "$ROOT" --exclude='./.git' --exclude='./dist' --exclude='./site' --exclude='./man' --exclude='__pycache__' -cf - . | tar -C "$WORK/$TOP" -xf -
printf '%s %s\nsource: https://codeberg.org/PrivacySafe/security-patches\nmirror: https://github.com/PrivacySafe/security-patches\n' "$PKG" "$FULL" > "$WORK/$TOP/VERSION"
normalize "$WORK/$TOP"

# Generated documentation, built from this tree for the packages and never written into it.
DOCS="$WORK/docs"
python3 -c 'import markdown_it, linkify_it' 2>/dev/null || { echo "building the documentation needs python3-markdown-it and python3-linkify-it (or: python3 -m pip install markdown-it-py linkify-it-py)" >&2; exit 1; }
command -v makeinfo >/dev/null 2>&1 || { echo "building the info manual needs makeinfo (apt install texinfo)" >&2; exit 1; }
python3 "$ROOT/packaging/gen-docs.py" --out "$DOCS/man" --date "20${YY}-${MM}-${DD}" --release "$FULL" >/dev/null
python3 "$ROOT/packaging/gen-site.py" --out "$DOCS/site" --date "20${YY}-${MM}-${DD}" --release "$FULL" >/dev/null
python3 "$ROOT/packaging/check-site.py" "$DOCS/site" >/dev/null || { echo "the documentation site failed packaging/check-site.py: run it by hand to see why" >&2; exit 1; }
if [ -d "$ROOT/docs" ] && [ -z "${PSF_SKIP_DOCS_CHECK:-}" ]; then
  if ! diff -r "$DOCS/site" "$ROOT/docs" >/dev/null 2>&1; then
    echo "docs/ is out of date. Refresh it with:" >&2
    echo "  python3 packaging/gen-site.py --out docs --release $FULL --date 20${YY}-${MM}-${DD}" >&2
    echo "then commit the result (PSF_SKIP_DOCS_CHECK=1 skips this check)." >&2
    exit 1
  fi
fi
if [ -z "${PSF_SKIP_MANUAL_CHECK:-}" ]; then
  "$ROOT/packaging/check-manuals.sh" "$DOCS/man" >"$WORK/check-manuals.log" 2>&1 || { cat "$WORK/check-manuals.log" >&2; echo "the manual pages failed packaging/check-manuals.sh (PSF_SKIP_MANUAL_CHECK=1 builds anyway)" >&2; exit 1; }
fi

# 2. Tarball.
TARBALL="$OUT/$TOP.tar.gz"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$SDE" \
    -C "$WORK" -cf - "$TOP" | gzip -9n > "$TARBALL"
echo "built $TARBALL"

# Payload shared by the deb: the tree as installed.
payload() {
  install -d "$1/opt/psf-security-patches" "$1/usr/lib/systemd/system"
  cp -a "$WORK/$TOP/." "$1/opt/psf-security-patches/"
  # the Red Hat advisory checker is the one part of packaging/ that is installed
  install -d "$1/opt/psf-security-patches/rhsa"
  cp -a "$WORK/$TOP/packaging/rhsa/." "$1/opt/psf-security-patches/rhsa/"
  chmod 0755 "$1/opt/psf-security-patches/rhsa/rhsa.py"
  rm -rf "$1/opt/psf-security-patches/packaging" "$1/opt/psf-security-patches/docs" "$1/opt/psf-security-patches/.gitattributes" "$1/opt/psf-security-patches/.gitignore"
  install -m 0644 "$ROOT/php/php2shell-watch.service" "$1/usr/lib/systemd/system/"
}

# Manual pages and the info manual, compressed, for both packages.
install_manuals() {   # $1 = root of the package file system
  rm -rf "$1/opt/psf-security-patches/man"
  install -d "$1/usr/share/man/man8" "$1/usr/share/man/man7" "$1/usr/share/info"
  for f in "$DOCS"/man/man8/*.8; do gzip -9n < "$f" > "$1/usr/share/man/man8/$(basename "$f").gz"; done
  gzip -9n < "$DOCS/man/man7/psf-security-patches.7" > "$1/usr/share/man/man7/psf-security-patches.7.gz"
  gzip -9n < "$DOCS/man/psf-security-patches.info" > "$1/usr/share/info/psf-security-patches.info.gz"
}

# The documentation site, as HTML documentation next to the other package docs.
install_site() {   # $1 = root of the package file system
  rm -rf "$1/opt/psf-security-patches/site"
  install -d "$1/usr/share/doc/$PKG/html"
  cp -a "$DOCS/site/." "$1/usr/share/doc/$PKG/html/"
  rm -f "$1/usr/share/doc/$PKG/html/.nojekyll"      # an empty marker file that only GitHub Pages reads
}

# 3. Debian package.
if command -v dpkg-deb >/dev/null 2>&1; then
  D="$WORK/deb"
  payload "$D"
  install_manuals "$D"
  install_site "$D"
  DOC="$D/usr/share/doc/$PKG"
  install -d "$DOC" "$D/DEBIAN"
  subst "$ROOT/packaging/deb/copyright.in" > "$DOC/copyright"
  cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$DOC/"
  install -D -m 0644 "$ROOT/packaging/deb/lintian-overrides" "$D/usr/share/lintian/overrides/$PKG"
  gzip -9n < "$ROOT/CHANGELOG.md" > "$DOC/changelog.gz"
  {
    printf '%s (%s) unstable; urgency=medium\n\n' "$PKG" "$FULL"
    printf '  * Release of PrivacySafe Security Patches. See changelog.gz for details.\n\n'
    printf ' -- %s  %s\n' "$MAINT" "$RFCDATE"
  } | gzip -9n > "$DOC/changelog.Debian.gz"
  normalize "$D"
  chmod 0755 "$D/opt/psf-security-patches/rhsa/rhsa.py"      # normalize resets it; the shebang needs it
  SIZE="$(du -sk --exclude=DEBIAN "$D" | cut -f1)"
  subst "$ROOT/packaging/deb/control.in" > "$D/DEBIAN/control"
  (cd "$D" && find . -type f -not -path './DEBIAN/*' -printf '%P\n' | LC_ALL=C sort | xargs -d '\n' md5sum) > "$D/DEBIAN/md5sums"
  chmod 0644 "$D/DEBIAN/control" "$D/DEBIAN/md5sums"; chmod 0755 "$D/DEBIAN"
  dpkg-deb --root-owner-group -Zxz -b "$D" "$OUT/${PKG}_${FULL}_all.deb" >/dev/null
  echo "built $OUT/${PKG}_${FULL}_all.deb"
else
  echo "skipped .deb: dpkg-deb not found" >&2
fi

# 4. RPM package.
if command -v rpmbuild >/dev/null 2>&1; then
  T="$WORK/rpm"
  mkdir -p "$T"/{BUILD,RPMS,SOURCES,SPECS,SRPMS,BUILDROOT}
  cp "$TARBALL" "$T/SOURCES/${PKG}-${DATEVER}-${REV}.tar.gz"
  tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$SDE" \
      -C "$DOCS" -cf - man site | gzip -9n > "$T/SOURCES/${PKG}-${DATEVER}-${REV}-docs.tar.gz"
  subst "$ROOT/packaging/rpm/psf-security-patches.spec.in" > "$T/SPECS/$PKG.spec"
  rpmbuild -bb --target noarch \
    --define "_topdir $T" \
    --define "_binary_payload w9.xzdio" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "_buildhost psf-security-patches" \
    "$T/SPECS/$PKG.spec" >"$WORK/rpmbuild.log" 2>&1 || { cat "$WORK/rpmbuild.log" >&2; exit 1; }
  cp "$T/RPMS/noarch/${PKG}-${DATEVER}-${REV}.noarch.rpm" "$OUT/"
  echo "built $OUT/${PKG}-${DATEVER}-${REV}.noarch.rpm"
else
  echo "skipped .rpm: rpmbuild not found" >&2
fi

# 5. Checksums of everything built for this release.
(cd "$OUT" && sha256sum "$TOP.tar.gz" "${PKG}_${FULL}_all.deb" "${PKG}-${DATEVER}-${REV}.noarch.rpm" 2>/dev/null) > "$OUT/SHA256SUMS-$FULL.txt"
echo "wrote $OUT/SHA256SUMS-$FULL.txt"

# Assisted-by: Claude Opus 5.5
# Assisted-by: Claude Sonnet 5.5
