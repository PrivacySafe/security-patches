# Red Hat advisories

Red Hat publishes a security advisory (RHSA) for each fix it ships. This page lists the advisories that name a CVE this collection covers, taken from Red Hat's advisory list for security advisories released 2026-04-01 to 2026-11-25 (9059 advisories for 6851 CVEs). Each tool README that has any carries the same data in its own **Red Hat advisories** section.

How to use it: a Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes. Find your stream and compare the installed release (`rpm -q PACKAGE`) with the one the advisory names. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The list holds security advisories only, not bug fixes or enhancements. The current state is always on Red Hat's own pages. On a Red Hat family host with the packages installed, `/opt/psf-security-patches/rhsa/rhsa.py verify --rpm` makes the comparison for every installed package (`man psf-rhsa`).

## By tool

| Tool | CVEs with an advisory | Advisories | First | Last |
|---|---|---|---|---|
| [developer/django](developer/django/README.md#red-hat-advisories) | 2 | 6 | 2026-11-04 | 2026-11-20 |
| [developer/jenkins](developer/jenkins/README.md#red-hat-advisories) | 2 | 11 | 2026-10-22 | 2026-10-22 |
| [developer/jupyter](developer/jupyter/README.md#red-hat-advisories) | 2 | 2 | 2026-11-06 | 2026-11-19 |
| [developer/nextjs](developer/nextjs/README.md#red-hat-advisories) | 3 | 1 | 2026-11-11 | 2026-11-11 |
| [developer/storybook](developer/storybook/README.md#red-hat-advisories) | 1 | 3 | 2026-10-23 | 2026-10-23 |
| [runtimes/java](runtimes/java/README.md#red-hat-advisories) | 1 | 27 | 2026-11-18 | 2026-11-24 |
| [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 8 | 12 | 2026-10-22 | 2026-11-23 |
| [runtimes/php](runtimes/php/README.md#red-hat-advisories) | 2 | 22 | 2026-10-21 | 2026-11-11 |
| [runtimes/ruby](runtimes/ruby/README.md#red-hat-advisories) | 4 | 18 | 2026-10-23 | 2026-11-24 |
| [servers/apache](servers/apache/README.md#red-hat-advisories) | 1 | 13 | 2026-11-11 | 2026-11-23 |
| [servers/bind](servers/bind/README.md#red-hat-advisories) | 1 | 22 | 2026-10-21 | 2026-11-11 |
| [servers/haproxy](servers/haproxy/README.md#red-hat-advisories) | 1 | 1 | 2026-10-16 | 2026-10-16 |
| [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 5 | 28 | 2026-07-26 | 2026-11-24 |
| [servers/tomcat](servers/tomcat/README.md#red-hat-advisories) | 2 | 2 | 2026-10-12 | 2026-10-20 |
| [system/apt](system/apt/README.md#red-hat-advisories) | 1 | 1 | 2026-11-07 | 2026-11-07 |
| [system/brotli](system/brotli/README.md#red-hat-advisories) | 1 | 102 | 2026-04-27 | 2026-11-24 |
| [system/curl](system/curl/README.md#red-hat-advisories) | 1 | 4 | 2026-10-11 | 2026-11-20 |
| [system/expat](system/expat/README.md#red-hat-advisories) | 3 | 9 | 2026-10-26 | 2026-11-24 |
| [system/ghostscript](system/ghostscript/README.md#red-hat-advisories) | 1 | 3 | 2026-11-25 | 2026-11-25 |
| [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 7 | 100 | 2026-07-08 | 2026-11-24 |
| [system/openssl](system/openssl/README.md#red-hat-advisories) | 1 | 44 | 2026-08-17 | 2026-11-20 |
| [system/pillow](system/pillow/README.md#red-hat-advisories) | 1 | 17 | 2026-10-30 | 2026-11-24 |
| [system/pki](system/pki/README.md#red-hat-advisories) | 1 | 225 | 2026-10-20 | 2026-11-24 |

## By CVE

| CVE | Tool | Advisories | Highest severity | First | Last |
|---|---|---|---|---|---|
| [CVE-2026-101356](https://access.redhat.com/security/cve/CVE-2026-101356) | [servers/tomcat](servers/tomcat/README.md#red-hat-advisories) | 2 | Important | 2026-10-12 | 2026-10-20 |
| [CVE-2026-103119](https://access.redhat.com/security/cve/CVE-2026-103119) | [servers/tomcat](servers/tomcat/README.md#red-hat-advisories) | 2 | Important | 2026-10-12 | 2026-10-20 |
| [CVE-2026-105481](https://access.redhat.com/security/cve/CVE-2026-105481) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-105482](https://access.redhat.com/security/cve/CVE-2026-105482) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 11 | Important | 2026-10-22 | 2026-11-23 |
| [CVE-2026-105483](https://access.redhat.com/security/cve/CVE-2026-105483) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 8 | Important | 2026-10-22 | 2026-11-11 |
| [CVE-2026-106069](https://access.redhat.com/security/cve/CVE-2026-106069) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 9 | Important | 2026-10-29 | 2026-11-23 |
| [CVE-2026-106071](https://access.redhat.com/security/cve/CVE-2026-106071) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106072](https://access.redhat.com/security/cve/CVE-2026-106072) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106073](https://access.redhat.com/security/cve/CVE-2026-106073) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-106074](https://access.redhat.com/security/cve/CVE-2026-106074) | [runtimes/node](runtimes/node/README.md#red-hat-advisories) | 2 | Important | 2026-10-29 | 2026-10-29 |
| [CVE-2026-109518](https://access.redhat.com/security/cve/CVE-2026-109518) | [system/apt](system/apt/README.md#red-hat-advisories) | 1 | Important | 2026-11-07 | 2026-11-07 |
| [CVE-2026-109618](https://access.redhat.com/security/cve/CVE-2026-109618) | [runtimes/php](runtimes/php/README.md#red-hat-advisories) | 21 | Critical | 2026-10-21 | 2026-11-11 |
| [CVE-2026-109619](https://access.redhat.com/security/cve/CVE-2026-109619) | [runtimes/php](runtimes/php/README.md#red-hat-advisories) | 22 | Critical | 2026-10-21 | 2026-11-11 |
| [CVE-2026-110264](https://access.redhat.com/security/cve/CVE-2026-110264) | [runtimes/ruby](runtimes/ruby/README.md#red-hat-advisories) | 18 | Critical | 2026-10-23 | 2026-11-24 |
| [CVE-2026-110353](https://access.redhat.com/security/cve/CVE-2026-110353) | [servers/haproxy](servers/haproxy/README.md#red-hat-advisories) | 1 | Important | 2026-10-16 | 2026-10-16 |
| [CVE-2026-111497](https://access.redhat.com/security/cve/CVE-2026-111497) | [system/brotli](system/brotli/README.md#red-hat-advisories) | 102 | Critical | 2026-04-27 | 2026-11-24 |
| [CVE-2026-111943](https://access.redhat.com/security/cve/CVE-2026-111943) | [system/pki](system/pki/README.md#red-hat-advisories) | 225 | Critical | 2026-10-20 | 2026-11-24 |
| [CVE-2026-112900](https://access.redhat.com/security/cve/CVE-2026-112900) | [system/pillow](system/pillow/README.md#red-hat-advisories) | 17 | Critical | 2026-10-30 | 2026-11-24 |
| [CVE-2026-113351](https://access.redhat.com/security/cve/CVE-2026-113351) | [system/expat](system/expat/README.md#red-hat-advisories) | 7 | Critical | 2026-10-26 | 2026-11-24 |
| [CVE-2026-114112](https://access.redhat.com/security/cve/CVE-2026-114112) | [developer/nextjs](developer/nextjs/README.md#red-hat-advisories) | 1 | Important | 2026-11-11 | 2026-11-11 |
| [CVE-2026-114113](https://access.redhat.com/security/cve/CVE-2026-114113) | [developer/nextjs](developer/nextjs/README.md#red-hat-advisories) | 1 | Important | 2026-11-11 | 2026-11-11 |
| [CVE-2026-114126](https://access.redhat.com/security/cve/CVE-2026-114126) | [developer/storybook](developer/storybook/README.md#red-hat-advisories) | 3 | Important | 2026-10-23 | 2026-10-23 |
| [CVE-2026-114135](https://access.redhat.com/security/cve/CVE-2026-114135) | [developer/jupyter](developer/jupyter/README.md#red-hat-advisories) | 1 | Critical | 2026-11-06 | 2026-11-06 |
| [CVE-2026-114137](https://access.redhat.com/security/cve/CVE-2026-114137) | [developer/django](developer/django/README.md#red-hat-advisories) | 6 | Critical | 2026-11-04 | 2026-11-20 |
| [CVE-2026-114138](https://access.redhat.com/security/cve/CVE-2026-114138) | [developer/django](developer/django/README.md#red-hat-advisories) | 6 | Critical | 2026-11-04 | 2026-11-20 |
| [CVE-2026-114140](https://access.redhat.com/security/cve/CVE-2026-114140) | [developer/jupyter](developer/jupyter/README.md#red-hat-advisories) | 2 | Critical | 2026-11-06 | 2026-11-19 |
| [CVE-2026-114938](https://access.redhat.com/security/cve/CVE-2026-114938) | [runtimes/java](runtimes/java/README.md#red-hat-advisories) | 27 | Critical | 2026-11-18 | 2026-11-24 |
| [CVE-2026-115506](https://access.redhat.com/security/cve/CVE-2026-115506) | [system/expat](system/expat/README.md#red-hat-advisories) | 8 | Critical | 2026-10-26 | 2026-11-24 |
| [CVE-2026-117610](https://access.redhat.com/security/cve/CVE-2026-117610) | [system/expat](system/expat/README.md#red-hat-advisories) | 8 | Critical | 2026-11-02 | 2026-11-24 |
| [CVE-2026-119618](https://access.redhat.com/security/cve/CVE-2026-119618) | [servers/apache](servers/apache/README.md#red-hat-advisories) | 13 | Critical | 2026-11-11 | 2026-11-23 |
| [CVE-2026-125396](https://access.redhat.com/security/cve/CVE-2026-125396) | [system/ghostscript](system/ghostscript/README.md#red-hat-advisories) | 3 | Important | 2026-11-25 | 2026-11-25 |
| [CVE-2026-15176](https://access.redhat.com/security/cve/CVE-2026-15176) | [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 18 | Critical | 2026-10-15 | 2026-11-24 |
| [CVE-2026-42533](https://access.redhat.com/security/cve/CVE-2026-42533) | [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 14 | Critical | 2026-07-26 | 2026-11-20 |
| [CVE-2026-53266](https://access.redhat.com/security/cve/CVE-2026-53266) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 23 | Critical | 2026-07-08 | 2026-10-29 |
| [CVE-2026-68121](https://access.redhat.com/security/cve/CVE-2026-68121) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 34 | Critical | 2026-09-24 | 2026-11-11 |
| [CVE-2026-74469](https://access.redhat.com/security/cve/CVE-2026-74469) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 24 | Important | 2026-09-24 | 2026-10-22 |
| [CVE-2026-80844](https://access.redhat.com/security/cve/CVE-2026-80844) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 35 | Important | 2026-09-23 | 2026-10-29 |
| [CVE-2026-81000](https://access.redhat.com/security/cve/CVE-2026-81000) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 34 | Important | 2026-09-23 | 2026-11-12 |
| [CVE-2026-84782](https://access.redhat.com/security/cve/CVE-2026-84782) | [system/openssl](system/openssl/README.md#red-hat-advisories) | 44 | Critical | 2026-08-17 | 2026-11-20 |
| [CVE-2026-89078](https://access.redhat.com/security/cve/CVE-2026-89078) | [runtimes/ruby](runtimes/ruby/README.md#red-hat-advisories) | 14 | Critical | 2026-10-23 | 2026-11-24 |
| [CVE-2026-92123](https://access.redhat.com/security/cve/CVE-2026-92123) | [developer/jenkins](developer/jenkins/README.md#red-hat-advisories) | 11 | Critical | 2026-10-22 | 2026-10-22 |
| [CVE-2026-92125](https://access.redhat.com/security/cve/CVE-2026-92125) | [developer/jenkins](developer/jenkins/README.md#red-hat-advisories) | 11 | Critical | 2026-10-22 | 2026-10-22 |
| [CVE-2026-92392](https://access.redhat.com/security/cve/CVE-2026-92392) | [system/curl](system/curl/README.md#red-hat-advisories) | 4 | Important | 2026-10-11 | 2026-11-20 |
| [CVE-2026-93577](https://access.redhat.com/security/cve/CVE-2026-93577) | [runtimes/ruby](runtimes/ruby/README.md#red-hat-advisories) | 18 | Critical | 2026-10-23 | 2026-11-24 |
| [CVE-2026-94300](https://access.redhat.com/security/cve/CVE-2026-94300) | [servers/bind](servers/bind/README.md#red-hat-advisories) | 22 | Critical | 2026-10-21 | 2026-11-11 |
| [CVE-2026-94482](https://access.redhat.com/security/cve/CVE-2026-94482) | [developer/nextjs](developer/nextjs/README.md#red-hat-advisories) | 1 | Important | 2026-11-11 | 2026-11-11 |
| [CVE-2026-95101](https://access.redhat.com/security/cve/CVE-2026-95101) | [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-97205](https://access.redhat.com/security/cve/CVE-2026-97205) | [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 18 | Critical | 2026-10-15 | 2026-11-24 |
| [CVE-2026-97229](https://access.redhat.com/security/cve/CVE-2026-97229) | [runtimes/ruby](runtimes/ruby/README.md#red-hat-advisories) | 18 | Critical | 2026-10-23 | 2026-11-24 |
| [CVE-2026-97629](https://access.redhat.com/security/cve/CVE-2026-97629) | [servers/nginx](servers/nginx/README.md#red-hat-advisories) | 1 | Important | 2026-10-15 | 2026-10-15 |
| [CVE-2026-98432](https://access.redhat.com/security/cve/CVE-2026-98432) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 34 | Critical | 2026-11-01 | 2026-11-20 |
| [CVE-2026-99288](https://access.redhat.com/security/cve/CVE-2026-99288) | [system/linux-kernel](system/linux-kernel/README.md#red-hat-advisories) | 5 | Important | 2026-11-23 | 2026-11-24 |

## Source and limits

- The data is Red Hat's published advisory list, one record per advisory with its CVEs and its packages, released 2026-04-01 to 2026-11-25. Regenerate this page and the README sections from a newer list with `packaging/rhsa/rhsa.py` (`fetch`, `index`, then `docs --write`; its README says how).
- Streams are read from the release of each package (`el8_10` is RHEL 8.10, `hum1` is a Hummingbird build), so a stream name here is a reading of a package name, not a statement by Red Hat.
- Rebuilds of RHEL (AlmaLinux, Rocky Linux, Oracle Linux) publish their own advisories and kernels; they follow Red Hat's fixes but not on the same day or with the same ids.
