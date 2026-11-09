# Offline HTML dashboard

Your evidence, without the obligatory browser tab pilgrimage. `tools\export_html.py` turns Sentinel CSV result exports into one standalone HTML file. It works offline, uses only Python's standard library to generate, and needs no web server, subscription credentials, browser extensions or downloaded JavaScript.

**This is an exported-evidence viewer, not an HTML implementation of Azure Workbooks.** It does not execute KQL, discover attacks, recompute correlations, deduplicate incidents or refresh telemetry. Run the queries in Sentinel first. Existing detection logic and deployment defaults are unchanged.

## 1. Export result CSVs

Run the suite queries or workbook panels with the intended workspace, directory, identity and time range. Export the **result rows with column headers** as comma-separated CSV. Do not export chart images, query text, formatted workbooks or Excel `.xlsx` files. Keep inputs in the ignored `exports` folder or another approved private location.

| CLI option | Source | Required columns |
|---|---|---|
| `--s001` | Expanded `dist\S001.kql` or S001 workbook panel | `TimeGenerated`, `AccountObjectId`, `MethodEventId` |
| `--s002` | Expanded `dist\S002.kql` or S002 workbook panel | `TimeGenerated`, `AccountObjectId`, `MethodEventId` |
| `--s003` | Expanded `dist\S003.kql` or S003 workbook panel | `TimeGenerated`, `AccountObjectId`, `MethodEventId` |
| `--registrations` | Successful individual-method registrations panel | `MethodTime`, `AccountObjectId` |
| `--graph` | Successful content-oriented Graph requests panel | `TimeGenerated`, `RequestId` |
| `--downloads` | Recorded file downloads panel | `TimeGenerated`, `Operation` |
| `--alerts` | Available security alerts panel | `TimeGenerated`, `AlertName` |
| `--readiness` | Workspace-wide telemetry readiness panel | `TableName`, `Rows`, `Status` |

All columns are preserved. Directory/account filters use `EntraTenantId` and `AccountObjectId` when present; IDs are normalized only for comparison. A file without those columns cannot be scoped by those identity filters. Native-alert `Entities` JSON is displayed as evidence, not guessed into an account mapping. D001/H001 and arbitrary raw-table CSVs are not supported panel types in this version.

The importer accepts UTF-8 (with or without BOM) and BOM-marked UTF-16. Header matching is case-insensitive, trims surrounding whitespace and accepts a trailing ` [UTC]` on time columns. Quoted commas, multiline cells and dynamic JSON columns are retained. Export files must have unique, nonempty column names and a consistent number of cells per record; malformed or oversized inputs fail explicitly, not silently truncate.

**Check completeness at the source.** Workbook evidence panels currently end with `take 200`; portal export/result limits can reduce results further. Exporting a workbook panel does not retrieve its omitted rows. If a wider dataset is necessary, run the corresponding query in Logs with approved limits, time range and scope. Record workspace, filters, export UTC time, query version, result limits and whether the result is complete. The CSV cannot reliably prove any of these properties, and the generator cannot recover omitted rows.

## 2. Generate the HTML

From the repository folder in PowerShell, with Python 3.10+:

```powershell
python -B .\tools\export_html.py `
  --s001 '.\exports\s001.csv' `
  --s002 '.\exports\s002.csv' `
  --registrations '.\exports\registrations.csv' `
  --alerts '.\exports\alerts.csv' `
  --readiness '.\exports\readiness.csv' `
  --output '.\exports\investigation.html'
```

Supply any subset of the eight CSV options; a single `--s001` input is sufficient. Use each option at most once, with one combined result CSV for that panel. Choose a **new** `.html` filename for each export; existing outputs are never overwritten. Limits are **25 MiB per CSV**, **100 MiB combined**, and **100,000 total imported rows**. Very large individual CSV fields can also exceed Python's CSV parser limit and will fail explicitly. Prefer smaller, deliberately scoped investigations.

To try the interface without tenant data:

```powershell
python -B .\tools\export_html.py --demo --output '.\exports\demo.html'
Start-Process '.\exports\demo.html'
```

The demo is visibly labelled synthetic. It is not a known-positive tenant detection test. `--demo` cannot be mixed with CSV inputs.

## 3. Investigate locally

Open the generated file in a current Edge, Chrome or Firefox browser. JavaScript must be enabled. No server is required.

- Filter evidence by panel, exact directory/account IDs, cell text and UTC interval. The ending minute is inclusive. Readiness is always an **unfiltered workspace snapshot**.
- Review row-count cards and a chart of the latest 14 observed UTC dates. These count exported rows, not unique events or incidents. The same method event can occur in multiple panels; dates without observations are not drawn.
- Inspect every imported column in paginated, horizontally scrollable tables (50 rows per page). Filters search the full dataset, not just the current page.
- Distinguish **not imported**, **header-only CSV**, and **no rows matching filters**. None establishes a clean tenant or a functioning connector. Readiness describes export-time observations, not current health.
- Unrecognized timestamps remain in the evidence tables and are counted in a warning. They are omitted from the date chart and excluded when applying a time filter. Timestamps are interpreted as UTC if no offset is provided. Accepted formats are ISO 8601 and US-style `M/D/YYYY, h:mm:ss[.fraction] AM/PM` or `M/D/YYYY, HH:mm:ss[.fraction]`; ambiguous non-ISO locale formats are not guessed. Prefer ISO UTC output from Sentinel.
- Printing captures the current filters and **only currently displayed table pages**, not the full dataset. Keep the original CSVs for complete evidence handling.

## Handling sensitive evidence

The generated HTML embeds **every imported cell**. Filtering or pagination does not redact or remove evidence. Identities, IPs, resource paths, native alert details and input filenames can be sensitive. Source directory paths are not embedded. Apply the same storage, access, retention and sharing controls as the CSVs. There is no encryption, authentication or audit trail inside the HTML itself.

No external resources, fonts, analytics or network requests are used. A restrictive content-security policy and text-only DOM rendering keep imported cells from becoming active markup or scripts. This does not make the embedded log data safe for public sharing.

`exports\` is ignored by Git as a convenience, **not a data-loss-prevention boundary**. Never commit tenant CSVs or generated tenant HTML to this public repository, attach them to public issues, or publish them with GitHub Pages. The normal `tools\build.py` does not read CSVs or generate tenant exports.

## Validation

```powershell
python -B -m unittest discover -s .\tests -v
python -B .\tools\build.py --check
```

Tests cover CSV structure/encoding, timestamp handling, input limits, embedded-data escaping, content-security-policy hashes and CLI guardrails. They do not validate the provenance, completeness or correctness of tenant evidence. Consult [deployment validation](deployment.md) and [analyst triage](triage.md) before treating any correlation as actionable.
