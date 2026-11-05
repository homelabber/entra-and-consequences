# Entra and Consequences

*Because a successful sign-in shouldn’t be the end of the investigation.*

Evidence-focused Microsoft Entra attack-chain investigations for Microsoft Sentinel and Defender XDR. Less déjà vu, more useful context.

Version **0.1.0** · Research assessed **November 5, 2026** · **Offline package; tenant validation required**

Explainable identity attack-chain correlations for Microsoft Sentinel, with one narrower Defender XDR custom-detection candidate. This supplements native evidence; it does not replace Entra ID Protection, Defender, Conditional Access, or incident investigation. No rule is advertised as a proven Microsoft product gap.

## Included

| Content | Purpose | Default |
|---|---|---|
| **S001** | Successful device-code sign-in → successful individual security-method registration for the same directory/user within two hours | Deploy disabled |
| **S002** | Method registration → 25 distinct successful Graph GETs across three resource surfaces by the same directory/user/application within two hours | Optional; not deployed |
| **S003** | Successful medium/high native-risk sign-in → method registration within two hours | Optional; not deployed |
| **D001** | Successful medium/high native-risk sign-in → self-attributed phone-app method ID addition, including replacement without a count increase | Manual Defender setup after validation; alternative to S003 |
| **H001** | Service-principal credential metadata change → sign-in origin first observed in available 14-day history | Hunting only |
| **Workbook** | Eight query panels: readiness, three correlations, registrations, content-oriented Graph requests, recorded downloads, available security alerts | Import/deploy separately |

**S003 and D001 overlap intentionally as alternative platforms. Do not enable both by default.** S001/S002 can also describe different stages of the same legitimate or malicious sequence; inspect native coverage before enabling either. Identity/time correlation is not proof of shared session, stolen token, malicious registration, or exfiltration.

## Start here

1. Read [coverage and research](docs/coverage.md), especially the unverified native-template comparison and raw audit-label caveat.
2. Follow [deployment and tenant validation](docs/deployment.md). No tenant changes have been made by creating this package.
3. Use [triage guidance](docs/triage.md) before defining response automation. The package has **no automatic response actions**.

### Build and local checks

Python 3.10+; standard library only. From this folder in PowerShell:

```powershell
python -B .\tools\build.py
python -B .\tools\build.py --check
python -B -m unittest discover -s .\tests -v
```

The builder prints every output path. Rebuild after editing queries, `suite.json`, workbook construction, or fixture data. `--check` and tests do not write artifacts. No dependency installation is needed.

Local checks cover deterministic packaging, JSON/Python syntax, schedule/entity contracts, and an **independent Python model** of synthetic behavioral cases. They do **not** compile KQL, validate Azure resource-provider behavior, render Azure Workbooks, or query tenant logs. `dist\sentinel-fixtures.kql` and `dist\defender-fixtures.kql` embed the real queries with synthetic table bindings for engine-side validation; those still need to be executed in the respective portals.

## Package layout

- `suite.json`: rule metadata, dependencies, overlap and deployment defaults.
- `sentinel\queries`: editable query sources and shared registration fragment.
- `defender`: self-contained D001 query.
- `hunting`: intentionally non-alerting research query.
- `dist\S001.kql`–`S003.kql`: fully expanded, paste-ready Sentinel queries.
- `dist\sentinel-rules.arm.json`: existing-workspace analytics rule deployment.
- `dist\workbook.arm.json`: workbook deployment with workspace binding.
- `workbook\entra-investigation.workbook.json`: Advanced Editor workbook document; bind the workspace placeholder before direct import.
- `dist\*-fixtures.kql`: synthetic KQL-engine checks, not production detections.
- `tools`, `tests`: deterministic build and local verification.

## Operational guardrails

Scheduled rules run hourly, search four hours, correlate two hours, and emit final-stage evidence from the last two hours. This deliberate overlap tolerates some delayed ingestion but can repeat alerts. Incident grouping uses account plus directory; it is not exactly-once delivery or cross-product incident merging. Delays longer than the available windows can still cause misses.

Exclusions are empty by default and use immutable, lowercase user/application IDs. Do not blanket-exclude trusted networks or Microsoft first-party apps. Document every exception with an owner and expiry. Ingestion charges, permissions, licensing, and log retention remain environment-specific.
