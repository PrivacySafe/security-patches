#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PrivacySafe Security Patches: release builder  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Builds a release tarball, a .deb and an .rpm, all named psf-security-packages
# and versioned by release date: YY.MM.DD-X.Y.Z, for example 26.10.25-1.0.0.
# In the deb the date is the upstream version and X.Y.Z the revision; in the
# rpm the date is Version and X.Y.Z is Release. The packages install the whole
# tree to /opt/psf-security-patches and the php2shell-watch systemd unit to
# /usr/lib/systemd/system (not enabled). No maintainer scripts are used.
#
# Usage:
#   packaging/build-release.sh [--date YY.MM.DD] [--rev X.Y.Z] [--out DIR]
#
#   --date   release date, default today in UTC
#   --rev    release revision, default 1.0.0
#   --out    output directory, default ./dist
#
# Output is reproducible: the same tree, date and revision give the same
# tarball and deb. Needs tar, gzip, and dpkg-deb and rpmbuild for the packages;
# a missing package tool is reported and that package is skipped.
# =============================================================================
set -euo pipefail

PKG="psf-security-packages"
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
tar -C "$ROOT" --exclude='./.git' --exclude='./dist' -cf - . | tar -C "$WORK/$TOP" -xf -
printf '%s %s\nsource: https://codeberg.org/PrivacySafe/security-patches\nmirror: https://github.com/PrivacySafe/security-patches\n' "$PKG" "$FULL" > "$WORK/$TOP/VERSION"
normalize "$WORK/$TOP"

# 2. Tarball.
TARBALL="$OUT/$TOP.tar.gz"
tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner --mtime="@$SDE" \
    -C "$WORK" -cf - "$TOP" | gzip -9n > "$TARBALL"
echo "built $TARBALL"

# Payload shared by the deb: the tree as installed.
payload() {
  install -d "$1/opt/psf-security-patches" "$1/usr/lib/systemd/system"
  cp -a "$WORK/$TOP/." "$1/opt/psf-security-patches/"
  rm -rf "$1/opt/psf-security-patches/packaging" "$1/opt/psf-security-patches/.gitattributes"
  install -m 0644 "$ROOT/packaging/systemd/php2shell-watch.service" "$1/usr/lib/systemd/system/"
}

# 3. Debian package.
if command -v dpkg-deb >/dev/null 2>&1; then
  D="$WORK/deb"
  payload "$D"
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
  subst "$ROOT/packaging/rpm/psf-security-packages.spec.in" > "$T/SPECS/$PKG.spec"
  rpmbuild -bb --target noarch \
    --define "_topdir $T" \
    --define "_binary_payload w9.xzdio" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    --define "_buildhost psf-security-packages" \
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
