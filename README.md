# openness-app-mapper

The application catalog of Openness Vulnerability Scanner. Windows has no package database, and the names in Installed apps ("7-Zip 24.08 (x64)", "Mozilla Firefox (x64 en-US)") rarely match the product names NVD uses. This file maps installed Windows applications to NVD products and carries the CVEs that affect each version, so a scanner can report them.

## Download

Each release has `app-mapper.json.gz` and `SHA256SUMS`. The latest:

```sh
curl -LO https://github.com/s4e-io/openness-app-mapper/releases/latest/download/app-mapper.json.gz
curl -LO https://github.com/s4e-io/openness-app-mapper/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS
```

With [openness-resolver](https://github.com/s4e-io/openness-resolver): `openness-resolver feed sync --source app-mapper`.

A new release is built from NVD data every day when something changed.

## Format (`openness-app-mapper/1`)

```json
{
  "format": "openness-app-mapper/1",
  "version": "2026.11.06",
  "catalog": [
    {
      "id": "7zip.7zip",
      "name": "7-Zip",
      "match": {"name": "^7-Zip\\b", "not_name": "\\bZS\\b"},
      "version": {"parts": 2},
      "cpe": ["7-zip:7-zip"],
      "update": "winget upgrade --id 7zip.7zip",
      "verified": true
    }
  ],
  "vulns": {"version": "...", "products": {"7-zip:7-zip": [{"cve": "CVE-2025-0411", "sev": "high", "r": [{"ee": "24.09"}]}]}}
}
```

- `match`: regular expressions on the DisplayName (`name`, `not_name`) and the Publisher.
- `version`: where the version is read (`display_version` or `product_name`), an optional `regex`, and how many parts count.
- `cpe`: NVD `vendor:product` pairs.
- `verified`: a person checked the match. Unverified entries are matched only when the user allows them.
- `verify` (optional): MSI product codes or a signed file that confirm the match.
- `vulns.products`: per product, CVEs with version ranges (`v` exact, `si`/`se` start, `ei`/`ee` end, inclusive or exclusive).

## How a CVE becomes a finding

The mapper is rebuilt every day from the NVD yearly feeds and after every catalog publish. A CVE enters it only when NVD lists an application CPE of a catalog product, marked vulnerable, on a configuration that can run on Windows, with a version or a version range. Openness Desktop downloads the new mapper with its daily data sync, and the next scan uses it. Nothing is guessed from the CVE text.

The same question on the other platforms is answered by the vendor's own data, read by [openness-resolver](https://github.com/s4e-io/openness-resolver): Microsoft MSRC for Windows itself, and the distribution's security data for Linux (Ubuntu, Debian, Red Hat, Rocky, AlmaLinux, SUSE, Amazon, Alpine). The table shows what each source does in the common cases.

| Case | Windows applications (this mapper, NVD) | Windows itself (MSRC) | Linux packages (distribution data) |
|---|---|---|---|
| CVE reserved, not published | No finding: nothing describes it yet | No finding | No finding |
| Published, NVD has not analyzed it (Received, Awaiting Analysis) | No finding until NVD adds the affected products and versions | Found when the monthly MSRC document lists a fix for the build | Found when the distribution lists the CVE for a package |
| Analyzed, with a version range | In the next daily build; a finding when the installed version is in the range | | |
| Analyzed, product listed without a version or range ("all versions") | Left out: a finding would claim every version | | |
| Vendor fixed it, a fixed version exists | Follows the NVD range (`ee`, end excluding) | Vulnerable when the build number and UBR are below the fixed build | Vulnerable when the installed version is below the fixed version, compared the package manager's way |
| Affected, no fix yet | Vulnerable while the version is in the NVD range | Not reported: only MSRC fixes with a fixed build become rules | Vulnerable, fix not available (`needed`); `deferred` when the vendor postponed it |
| Vendor says it will not fix | | | Potentially vulnerable (`ignored`, Debian `unimportant` or end of life), not counted as vulnerable |
| Vendor says not affected | | | Not applicable (`not-affected`, `DNE`, Debian fixed version `0`) |
| Vendor has not decided | | | Unknown (`undetermined`, a fix announced without a version), never shown as clean |
| NVD or the vendor changes the range or the fix | The next daily build carries the change; the finding follows at the next scan | Every MSRC month is read again daily | Read again every 6 to 24 hours, by source |
| CVE rejected or withdrawn | NVD status `Rejected`: dropped at the next build, the finding disappears at the next scan | Dropped when MSRC removes it from the document | Dropped when the distribution removes it or marks it not affected; withdrawn OSV records are dropped |
| CVE disputed | Kept: NVD keeps the record and its ranges | As MSRC publishes it | As the distribution publishes it |
| No severity yet | NVD CVSS, the newest version NVD has (4.0, 3.1, 3.0, 2.0) | Microsoft's severity | The distribution's own rating, else the NVD CVSS band, and the finding says so |
| Application the catalog does not know | A guess by name and publisher against NVD products: potentially vulnerable, not counted (it can be turned off) | | |
| Catalog entry no person has checked | Used only when the user allows unverified matches | | |

Safeguards of the build:

- A build whose CVE count or catalog shrinks more than the allowed share against the published one is held; scanners keep the last good mapper.
- A failed or held build is never published. The published file has a version (the build date) and a `SHA256SUMS` line.
- Every finding names the source it came from and the rule or range that matched, so a wrong one can be traced and reported.

## Report a mapping

Open an issue with the "Application mapping" form: a missing application, a wrong product, or a wrongly read version.
