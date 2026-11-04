# Red Hat advisories

Red Hat publishes a security advisory (RHSA) for each fix it ships. This page lists the advisories that name a CVE this collection covers, taken from Red Hat's advisory list for security advisories released 2026-04-01 to 2026-11-03 (7577 advisories for 5662 CVEs). Each tool README that has any carries the same data in its own **Red Hat advisories** section.

How to use it: a Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes. Find your stream and compare the installed release (`rpm -q PACKAGE`) with the one the advisory names. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The list holds security advisories only, not bug fixes or enhancements. The current state is always on Red Hat's own pages. On a Red Hat family host with the packages installed, `/opt/psf-security-patches/rhsa/rhsa.py verify --rpm` makes the comparison for every installed package (`man psf-rhsa`).

## By tool

| Tool | CVEs with an advisory | Advisories | First | Last |
|---|---|---|---|---|
| [bind](bind/README.md#red-hat-advisories) | 1 | 9 | 2026-10-21 | 2026-11-03 |
| [brotli](brotli/README.md#red-hat-advisories) | 1 | 71 | 2026-04-27 | 2026-11-03 |
| [curl](curl/README.md#red-hat-advisories) | 1 | 2 | 2026-10-11 | 2026-10-14 |
| [haproxy](haproxy/README.md#red-hat-advisories) | 1 | 1 | 2026-10-16 | 2026-10-16 |
| [jenkins](jenkins/README.md#red-hat-advisories) | 2 | 11 | 2026-10-22 | 2026-10-22 |
| [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 6 | 66 | 2026-07-08 | 2026-11-03 |
| [nginx](nginx/README.md#red-hat-advisories) | 4 | 1 | 2026-10-15 | 2026-10-15 |
| [node](node/README.md#red-hat-advisories) | 8 | 5 | 2026-10-22 | 2026-10-29 |
| [openssl](openssl/README.md#red-hat-advisories) | 1 | 31 | 2026-08-17 | 2026-10-29 |
| [php](php/README.md#red-hat-advisories) | 2 | 20 | 2026-10-21 | 2026-10-26 |
| [pillow](pillow/README.md#red-hat-advisories) | 1 | 1 | 2026-10-30 | 2026-10-30 |
| [pki](pki/README.md#red-hat-advisories) | 1 | 163 | 2026-10-20 | 2026-11-03 |
| [ruby](ruby/README.md#red-hat-advisories) | 4 | 3 | 2026-10-23 | 2026-10-24 |
| [storybook](storybook/README.md#red-hat-advisories) | 1 | 3 | 2026-10-23 | 2026-10-23 |
| [tomcat](tomcat/README.md#red-hat-advisories) | 2 | 2 | 2026-10-12 | 2026-10-20 |

## By CVE

| CVE | Tool | Advisories | Highest severity | First | Last |
|---|---|---|---|---|---|
| [CVE-2026-101356](https://access.redhat.com/security/cve/CVE-2026-101356) | [tomcat](tomcat/README.md#red-hat-advisories) | 2 | Important | 2026-10-12 | 2026-10-20 |
| [CVE-2026-103119](https://access.redhat.com/security/cve/CVE-2026-103119) | [tomcat](tomcat/README.md#red-hat-advisories) | 2 | Important | 2026-10-12 | 2026-10-20 |
| [CVE-2026-105481](https://access.redhat.com/security/cve/CVE-2026-105481) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-105482](https://access.redhat.com/security/cve/CVE-2026-105482) | [node](node/README.md#red-hat-advisories) | 4 | Important | 2026-10-22 | 2026-10-29 |
| [CVE-2026-105483](https://access.redhat.com/security/cve/CVE-2026-105483) | [node](node/README.md#red-hat-advisories) | 5 | Important | 2026-10-22 | 2026-10-29 |
| [CVE-2026-106069](https://access.redhat.com/security/cve/CVE-2026-106069) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106071](https://access.redhat.com/security/cve/CVE-2026-106071) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106072](https://access.redhat.com/security/cve/CVE-2026-106072) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106073](https://access.redhat.com/security/cve/CVE-2026-106073) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106074](https://access.redhat.com/security/cve/CVE-2026-106074) | [node](node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-109618](https://access.redhat.com/security/cve/CVE-2026-109618) | [php](php/README.md#red-hat-advisories) | 19 | Critical | 2026-10-21 | 2026-10-26 |
| [CVE-2026-109619](https://access.redhat.com/security/cve/CVE-2026-109619) | [php](php/README.md#red-hat-advisories) | 20 | Critical | 2026-10-21 | 2026-10-26 |
| [CVE-2026-110264](https://access.redhat.com/security/cve/CVE-2026-110264) | [ruby](ruby/README.md#red-hat-advisories) | 3 | Critical | 2026-10-23 | 2026-10-24 |
| [CVE-2026-110353](https://access.redhat.com/security/cve/CVE-2026-110353) | [haproxy](haproxy/README.md#red-hat-advisories) | 1 | Important | 2026-10-16 | 2026-10-16 |
| [CVE-2026-111497](https://access.redhat.com/security/cve/CVE-2026-111497) | [brotli](brotli/README.md#red-hat-advisories) | 71 | Critical | 2026-04-27 | 2026-11-03 |
| [CVE-2026-111943](https://access.redhat.com/security/cve/CVE-2026-111943) | [pki](pki/README.md#red-hat-advisories) | 163 | Critical | 2026-10-20 | 2026-11-03 |
| [CVE-2026-112900](https://access.redhat.com/security/cve/CVE-2026-112900) | [pillow](pillow/README.md#red-hat-advisories) | 1 | Critical | 2026-10-30 | 2026-10-30 |
| [CVE-2026-114126](https://access.redhat.com/security/cve/CVE-2026-114126) | [storybook](storybook/README.md#red-hat-advisories) | 3 | Important | 2026-10-23 | 2026-10-23 |
| [CVE-2026-15176](https://access.redhat.com/security/cve/CVE-2026-15176) | [nginx](nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-53266](https://access.redhat.com/security/cve/CVE-2026-53266) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 23 | Critical | 2026-07-08 | 2026-10-29 |
| [CVE-2026-68121](https://access.redhat.com/security/cve/CVE-2026-68121) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 32 | Critical | 2026-09-24 | 2026-10-29 |
| [CVE-2026-74469](https://access.redhat.com/security/cve/CVE-2026-74469) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 24 | Important | 2026-09-24 | 2026-10-22 |
| [CVE-2026-80844](https://access.redhat.com/security/cve/CVE-2026-80844) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 35 | Important | 2026-09-23 | 2026-10-29 |
| [CVE-2026-81000](https://access.redhat.com/security/cve/CVE-2026-81000) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 26 | Important | 2026-09-23 | 2026-10-22 |
| [CVE-2026-84782](https://access.redhat.com/security/cve/CVE-2026-84782) | [openssl](openssl/README.md#red-hat-advisories) | 31 | Critical | 2026-08-17 | 2026-10-29 |
| [CVE-2026-89078](https://access.redhat.com/security/cve/CVE-2026-89078) | [ruby](ruby/README.md#red-hat-advisories) | 3 | Critical | 2026-10-23 | 2026-10-24 |
| [CVE-2026-92123](https://access.redhat.com/security/cve/CVE-2026-92123) | [jenkins](jenkins/README.md#red-hat-advisories) | 11 | Critical | 2026-10-22 | 2026-10-22 |
| [CVE-2026-92125](https://access.redhat.com/security/cve/CVE-2026-92125) | [jenkins](jenkins/README.md#red-hat-advisories) | 11 | Critical | 2026-10-22 | 2026-10-22 |
| [CVE-2026-92392](https://access.redhat.com/security/cve/CVE-2026-92392) | [curl](curl/README.md#red-hat-advisories) | 2 | Important | 2026-10-11 | 2026-10-14 |
| [CVE-2026-93577](https://access.redhat.com/security/cve/CVE-2026-93577) | [ruby](ruby/README.md#red-hat-advisories) | 3 | Critical | 2026-10-23 | 2026-10-24 |
| [CVE-2026-94300](https://access.redhat.com/security/cve/CVE-2026-94300) | [bind](bind/README.md#red-hat-advisories) | 9 | Important | 2026-10-21 | 2026-11-03 |
| [CVE-2026-95101](https://access.redhat.com/security/cve/CVE-2026-95101) | [nginx](nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-97205](https://access.redhat.com/security/cve/CVE-2026-97205) | [nginx](nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-97229](https://access.redhat.com/security/cve/CVE-2026-97229) | [ruby](ruby/README.md#red-hat-advisories) | 3 | Critical | 2026-10-23 | 2026-10-24 |
| [CVE-2026-97629](https://access.redhat.com/security/cve/CVE-2026-97629) | [nginx](nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-98432](https://access.redhat.com/security/cve/CVE-2026-98432) | [linux-kernel](linux-kernel/README.md#red-hat-advisories) | 12 | Critical | 2026-11-01 | 2026-11-03 |

## Source and limits

- The data is Red Hat's published advisory list, one record per advisory with its CVEs and its packages, released 2026-04-01 to 2026-11-03. Regenerate this page and the README sections from a newer list with `packaging/rhsa/rhsa.py` (`fetch`, `index`, then `docs --write`; its README says how).
- Streams are read from the release of each package (`el8_10` is RHEL 8.10, `hum1` is a Hummingbird build), so a stream name here is a reading of a package name, not a statement by Red Hat.
- Rebuilds of RHEL (AlmaLinux, Rocky Linux, Oracle Linux) publish their own advisories and kernels; they follow Red Hat's fixes but not on the same day or with the same ids.
