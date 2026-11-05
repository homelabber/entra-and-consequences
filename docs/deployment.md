# Deployment and tenant validation

## Prerequisites and safe defaults

Use an existing Sentinel-enabled Log Analytics workspace. This package does not provision a workspace, connectors, diagnostic settings, licenses, app consents, or response permissions. Deployment requires the corresponding resource permissions; query access requires workspace/data RBAC. Use least privilege.

| Content | Required data | Important checks |
|---|---|---|
| S001 | `SigninLogs`, `AuditLogs` | Successful device-code events actually exported; individual-method operation labels and User target IDs confirmed |
| S002 | `AuditLogs`, `MicrosoftGraphActivityLogs` | Enable appropriate Graph diagnostics; verify licensing/export rights, Analytics log plan and `RequestUri` format; joins are not promised on Basic/Auxiliary plans |
| S003 | `SigninLogs`, `AuditLogs` | Entra ID Protection risk visibility, normally Entra P2; qualifying native at-sign-in risks actually populated |
| D001 | `EntraIdSignInEvents`, `CloudAppEvents` | Entra P2 and Defender for Cloud Apps with Microsoft 365 activity collection; actual raw user-update payload matches strict parser |
| H001 | `AuditLogs`, `AADServicePrincipalSignInLogs` | At least 14 days of retained and continuously exported sign-ins; tenant-local principal object IDs and credential-change properties verified |
| Workbook download panel | `OfficeActivity`, `AuditLogs` | M365 audit connector includes SharePoint/OneDrive; full UPN plus directory mapping available in seven-day user audit targets |
| Workbook alerts panel | `SecurityAlert` | Exported alert evidence only; not an inventory of all Microsoft detections |

`SigninLogs` is intentionally the only Sentinel sign-in source for S001/S003. Other sign-in categories are not silently unioned with uncertain schemas. Verify your relevant events appear here; the Defender table has its own interactive/non-interactive coverage.

An absent/empty table is not evidence of a clean tenant. The readiness panel reports events and ingestion-delay percentiles, not license status or connector configuration. It is workspace-wide and deliberately ignores identity filters. Optional panels may display a table-resolution error when their data is unavailable; that error is not hidden as zero results.

## 1. Local package checks

From the suite folder:

```powershell
python -B .\tools\build.py
python -B .\tools\build.py --check
python -B -m unittest discover -s .\tests -v
```

Build outputs use deterministic rule GUIDs. Redeploying updates those resources; review changes before reusing the same GUIDs for different logic. The workbook name also has a stable GUID; change its parameter to create a separate copy.

## 2. Execute synthetic queries in the real engines

- In Sentinel Logs, run the **entire** `dist\sentinel-fixtures.kql` as a single query. It declares synthetic table bindings before using the exact production rule bodies; it does not read tenant events. Expect **six rows**, each `Passed == true`, each with `Actual == Expected == 1`.
- In Defender Advanced Hunting, run the **entire** `dist\defender-fixtures.kql`. Expect **three rows**, all passing with one expected and one actual event each.
- A compile/binding error is a failed gate. Fix source, rebuild and rerun. Do not enable a rule merely because the independent Python model passed.

Synthetic coverage includes failed sign-ins/registrations, event order, directory mismatch, target versus actor, a two-hour boundary, excluded emission boundary, completion versus individual registration, duplicate Graph request IDs, per-app grouping, URI boundary matching, failed Graph requests, phone-app replacement without a count increase, malformed arrays and duplicate target entries.

## 3. Validate queries against representative tenant events

Run `dist\S001.kql`, `S002.kql`, `S003.kql` only where their tables exist. First verify expected raw registration activity:

```kusto
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName has 'register' and OperationName has 'security'
| summarize Events=count() by OperationName, Result
```

Inspect authorized representative rows for `TargetResources`, `InitiatedBy`, `AADTenantId`, `Id` and timestamps. Identify successful **individual-method** registration, not review, completion, cancellation or deletion. Update the shared fragment only after confirming exact semantics; rebuild after edits. For a controlled authorized onboarding test, compare a known source registration ID with query output. Zero results alone do not validate the parser.

Validate Graph URI parsing and distinct request IDs using known authorized activity. S002 requires 25 distinct requests and three named top-level surfaces in two hours, per application and target user. These starting thresholds are hypotheses, not empirically tuned tenant baselines. Its scope is delegated-user reads; use app-governance/workload-identity telemetry for app-only abuse.

For D001, inspect raw `CloudAppEvents` updates to verify target prefixes, actor attribution, property names, valid JSON arrays and method IDs. Many service-mediated updates will not have actor=target and deliberately will not match. Do not weaken identity attribution simply to increase match counts. Preserve original `Timestamp`, `ReportId`, `AccountObjectId` in every returned event.

Sample typical legitimate registration/helpdesk workflows and approved applications across representative business cycles. Document exclusions by immutable lowercase IDs with owner/expiry. Any event-time, exclusion or threshold edit requires rebuilding and rerunning both local and engine fixtures. Exclusions in Sentinel sources do not automatically propagate to D001, and workbook detection panels inherit Sentinel source exclusions; the raw registration panel does not.

## 4. Review native overlap

Inspect Content Hub's actual template queries, active rules, Entra risk detections, app-governance policies and Defender incidents. Record template/policy version and whether its existing incident already includes the same sequence. Follow `coverage.md`; the assessment is not an exhaustive verified template inventory.

Select **S003 or D001**, not both by default. You can also leave both disabled if native incidents already supply enough context. Sentinel per-rule incident grouping is not guaranteed to merge separate rule incidents or Defender incidents. S001 and S002 can still describe the same broader sequence; measure incremental value rather than alert count.

## 5. Validate and deploy the disabled Sentinel resources

The following are **operator-run examples**, not commands already executed for your tenant. Authenticate with your approved Azure workflow and select the intended subscription first. Replace placeholders; review the target resource group carefully.

```powershell
az deployment group validate --resource-group '<existing-resource-group>' --template-file '.\dist\sentinel-rules.arm.json' --parameters workspaceName='<existing-workspace>' enableRules=false deployDeviceCodeRule=true deployGraphRule=false deployRiskRule=false
az deployment group what-if --resource-group '<existing-resource-group>' --template-file '.\dist\sentinel-rules.arm.json' --parameters workspaceName='<existing-workspace>' enableRules=false deployDeviceCodeRule=true deployGraphRule=false deployRiskRule=false
az deployment group create --resource-group '<existing-resource-group>' --template-file '.\dist\sentinel-rules.arm.json' --parameters workspaceName='<existing-workspace>' enableRules=false deployDeviceCodeRule=true deployGraphRule=false deployRiskRule=false
```

Optional Graph/risk rule resources are opt-in even while disabled, because the provider can validate their queries against workspace schemas. ARM local tests do not replace Azure validation/what-if. Reference API: [scheduled analytics rules](https://learn.microsoft.com/en-us/azure/templates/microsoft.securityinsights/2024-03-01/alertrules).

A false `condition` in an incremental ARM deployment does **not** delete a previously deployed rule. To retire an earlier optional rule, explicitly disable/delete that rule after review. `enableRules` applies to all resources selected in that deployment; avoid enabling unrelated rules inadvertently.

## 6. Deploy the workbook

```powershell
az deployment group validate --resource-group '<existing-resource-group>' --template-file '.\dist\workbook.arm.json' --parameters workspaceResourceId='/subscriptions/<subscription>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>'
az deployment group create --resource-group '<existing-resource-group>' --template-file '.\dist\workbook.arm.json' --parameters workspaceResourceId='/subscriptions/<subscription>/resourceGroups/<resource-group>/providers/Microsoft.OperationalInsights/workspaces/<workspace>'
```

Alternatively, open a new Azure Workbook's Advanced Editor and import `workbook\entra-investigation.workbook.json`, replacing `{{WORKSPACE_RESOURCE_ID}}` with the intended full workspace resource ID in both occurrences. The ARM template does this automatically.

Visually verify parameter loading, workspace selection, all eight panels, directory/user isolation, an expected test registration and optional-table errors. The user selector contains only GUID-validated audit targets from the last seven days, not a complete directory inventory. When investigating a user with no suitable audit target, use a manually scoped query rather than interpreting a missing dropdown choice as no activity.

The workbook uses the chosen time range for investigation, not the scheduled emission window; correlation stays two hours. A predecessor outside the chosen interval is not loaded. Download events are joined by exact lowercase UPN and directory using observed audit targets; renames, non-UPN IDs and missing mappings can omit events. The content-API panel shows successful requests, not data received by an external party. The alert panel is an available-evidence view and cannot certify native coverage.

## 7. Create D001 manually only after validation

1. In Defender Advanced Hunting, run `defender\D001-risk-phoneapp-addition.kql` against live data and confirm the schema and returned source-event identifiers.
2. Select **Create detection rule**. Use the name in `suite.json`, **Medium** severity, **Persistence**, and **one-hour** frequency. This is a scheduled join query, not an NRT rule.
3. Map the impacted account to the existing `AccountObjectId`. Preserve `Timestamp` and `ReportId` from the final CloudAppEvents event. Add available sign-in evidence to details where the portal permits.
4. Leave all automatic response actions **off**. Confirm your intended account scope and permissions; apply a pilot only if the portal supports that scope, otherwise keep this query hunting-only during evaluation.
5. Confirm S003 is not independently generating redundant alerts. Verify actual alert creation from an authorized controlled example before production enablement.

This release deliberately does not claim automated Defender rule deployment or a verified REST payload. Portal capabilities and role requirements can vary; see [Microsoft's custom-detection instructions](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules).

## 8. Pilot, monitor, and roll back

Keep rules disabled until all preceding gates pass. Then enable selected rules individually in the portal, or redeploy only the reviewed selections with `enableRules=true`. Collect latency, volume, true/false positives, native overlap and incremental investigation value before expanding.

Hourly scheduling plus a two-hour final-event emission window intentionally re-evaluates evidence. `AlertKey` is a stable correlation key, not a server-enforced deduplication token. Repeated alerts may group into the same Sentinel incident for four hours by directory/account. The provider can cap per-run alert production; monitor result volume and actual emitted alerts. Results delayed beyond these windows or source risk updated later can still be missed; tune based on measured ingestion/processing delays.

Rollback: disable only this suite's selected analytics rules, disable D001 if created, and optionally remove this suite's workbook. Do not delete connectors, native rules, logs, workspaces, or licensed services. Revalidate after schema changes or significant native detection updates.

## Acceptance record

Record operator/date/workspace, local test output, both engine-fixture outputs, Azure validation/what-if results, raw field/operation examples, known-positive reproduction, negative/legitimate sample review, native overlap decisions, workbook render checks, selected rules, exclusions, measured latency, pilot results and rollback owner. Without that record this remains an **offline-validated candidate package**, not a production-validated detection suite.
