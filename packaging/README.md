# Release packaging

Releases are published as three files, all named `psf-security-packages` and versioned by release date, `YY.MM.DD-X.Y.Z`, for example `26.10.25-1.0.0`:

| File | Name | Version fields |
|---|---|---|
| Source tarball | `psf-security-packages-26.10.25-1.0.0.tar.gz` | whole version in the name |
| Debian package | `psf-security-packages_26.10.25-1.0.0_all.deb` | upstream `26.10.25`, revision `1.0.0` |
| RPM package | `psf-security-packages-26.10.25-1.0.0.noarch.rpm` | Version `26.10.25`, Release `1.0.0` |

The date is the release date in UTC. The second part is the revision: it is `1.0.0` for a first release of that date and goes up if the same date needs a rebuild.

## What the packages install

- The whole tree, scripts and documentation, in `/opt/psf-security-patches`.
- The `php2shell-watch` systemd unit in `/usr/lib/systemd/system`, pointed at the `/opt` path. It is not enabled.
- License material: `LICENSE` and `NOTICE`, plus a Debian `copyright` file (DEP-5, CC0-1.0) or an RPM `License: CC0-1.0` tag.

There are no maintainer scripts, so nothing runs at install or removal time. The only dependencies are bash 4.0 or newer and coreutils.

## Building

```bash
packaging/build-release.sh --date 26.10.25 --rev 1.0.0
```

Output goes to `dist/`, with a `SHA256SUMS-<version>.txt` file. The build needs `tar`, `gzip`, `dpkg-deb` for the `.deb` and `rpmbuild` for the `.rpm`. Output is reproducible: the same tree, date and revision give byte-identical files.

## Verifying and signing

```bash
sha256sum -c SHA256SUMS-26.10.25-1.0.0.txt
gpg --armor --detach-sign psf-security-packages-26.10.25-1.0.0.tar.gz   # maintainers
```

Maintainers should sign each file and the checksums file, and publish the `.asc` files with the release.
