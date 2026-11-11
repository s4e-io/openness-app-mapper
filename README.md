# openness-app-mapper

The application catalog of OpenNess Vulnerability Scanner. Windows has no package database, and the names in Installed apps ("7-Zip 24.08 (x64)", "Mozilla Firefox (x64 en-US)") rarely match the product names NVD uses. This file maps installed Windows applications to NVD products and carries the CVEs that affect each version, so a scanner can report them.

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

## Report a mapping

Open an issue with the "Application mapping" form: a missing application, a wrong product, or a wrongly read version.
