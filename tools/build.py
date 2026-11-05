"""Deterministically build offline ARM/workbook artifacts using the standard library."""
import argparse
import json
from pathlib import Path

from fixtures import defender_kql, sentinel_kql

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def load_suite():
    return json.loads(read("suite.json"))


def render_rule(rule):
    query = read(Path("sentinel") / "queries" / rule["query"])
    return query.replace("{{METHOD_REGISTRATIONS}}", read(Path("sentinel") / "queries" / "method-registrations.kql").strip())


def parameter(kind, default=None, description=None):
    result = {"type": kind}
    if default is not None:
        result["defaultValue"] = default
    if description:
        result["metadata"] = {"description": description}
    return result


def template(parameters, resources):
    return {"$schema": SCHEMA, "contentVersion": "1.0.0.0", "parameters": parameters, "resources": resources}


def analytics_template(suite):
    parameters = {
        "workspaceName": parameter("string", description="Existing Sentinel-enabled Log Analytics workspace in this resource group."),
        "enableRules": parameter("bool", False, "Leave false until schema, overlap and tenant-data validation are complete."),
        "deployDeviceCodeRule": parameter("bool", True),
        "deployGraphRule": parameter("bool", False, "Requires MicrosoftGraphActivityLogs on the Analytics plan."),
        "deployRiskRule": parameter("bool", False, "Alternative to overlapping Defender D001; requires native risk visibility."),
    }
    resources = []
    for rule in suite["rules"]:
        mappings = [{"entityType": "Account", "fieldMappings": [
            {"identifier": "AadUserId", "columnName": "AccountObjectId"},
            {"identifier": "AadTenantId", "columnName": "EntraTenantId"},
        ]}]
        if rule["ipEntity"]:
            mappings.append({"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}]})
        properties = {
            "displayName": rule["name"], "description": rule["description"],
            "enabled": "[parameters('enableRules')]", "severity": rule["severity"],
            "query": render_rule(rule), "queryFrequency": "PT1H", "queryPeriod": "PT4H",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0,
            "suppressionEnabled": False, "suppressionDuration": "PT1H",
            "tactics": rule["tactics"], "techniques": rule["techniques"],
            "entityMappings": mappings, "customDetails": rule["details"],
            "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
            "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
                "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "PT4H",
                "matchingMethod": "Selected", "groupByEntities": ["Account"],
                "groupByAlertDetails": [], "groupByCustomDetails": ["EntraTenantId"],
            }},
        }
        resources.append({
            "condition": f"[parameters('{rule['deployParameter']}')]",
            "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
            "apiVersion": "2024-03-01", "kind": "Scheduled",
            "name": f"[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/{rule['guid']}')]",
            "properties": properties,
        })
    return template(parameters, resources)


GUID_RE = r"^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$"
CONTEXT = """let SelectedUserId = tolower('{UserObjectId}');
let SelectedTenantId = tolower('{DirectoryId}');
"""
USER_FILTER = "\n| where SelectedUserId == '*' or AccountObjectId == SelectedUserId\n| where SelectedTenantId == '*' or EntraTenantId == SelectedTenantId"


def query_item(name, title, query, optional=False):
    return {"type": 3, "name": name, "content": {
        "version": "KqlItem/1.0", "title": title + (" [optional telemetry]" if optional else ""),
        "query": query, "size": 0, "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
        "crossComponentResources": ["{Workspace}"], "visualization": "table",
    }}


def workbook(suite):
    user_query = f"""datatable(value:string, label:string) ['*', 'All users']
| union (AuditLogs
| where TimeGenerated > ago(7d)
| where tolower(AADTenantId) == tolower('{{DirectoryId}}') or '{{DirectoryId}}' == '*'
| mv-expand Target = TargetResources
| where tostring(Target.type) =~ 'User'
| extend value = tolower(tostring(Target.id)), label = tostring(Target.userPrincipalName)
| where value matches regex @'{GUID_RE}'
| summarize label = take_any(label) by value)
| order by label asc"""
    tenant_query = f"""datatable(value:string, label:string) ['*', 'All directories']
| union (AuditLogs | where TimeGenerated > ago(7d)
| extend value = tolower(AADTenantId)
| where value matches regex @'{GUID_RE}'
| distinct value | extend label = value)"""
    parameters = [
        {"id": "workspace", "name": "Workspace", "type": 5, "isRequired": True,
         "value": "{{WORKSPACE_RESOURCE_ID}}", "typeSettings": {"resourceTypeFilter": {"microsoft.operationalinsights/workspaces": True}}},
        {"id": "time", "name": "TimeRange", "type": 4, "isRequired": True,
         "value": {"durationMs": 86400000}, "typeSettings": {"selectableValues": [
             {"durationMs": 14400000}, {"durationMs": 86400000}, {"durationMs": 604800000}]}},
        {"id": "directory", "name": "DirectoryId", "type": 2, "isRequired": True, "value": "*",
         "query": tenant_query, "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
         "crossComponentResources": ["{Workspace}"], "typeSettings": {"allowCustomValues": False}},
        {"id": "user", "name": "UserObjectId", "type": 2, "isRequired": True, "value": "*",
         "query": user_query, "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
         "crossComponentResources": ["{Workspace}"], "typeSettings": {"allowCustomValues": False}},
    ]
    items = [
        {"type": 1, "name": "scope", "content": {"json": "# Entra identity attack-chain investigation\n\n**Candidate correlations, not confirmed compromise or proven product gaps.** Native Microsoft alerts remain authoritative evidence, not signals to suppress blindly. No response actions are automated.\n\nChoose a workspace, directory and user. User choices come from seven days of user audit targets; an absent user may still exist. Investigation panels use the selected range, but their correlation window stays two hours. Scheduled rules use four-hour lookback and two-hour emission overlap. Each sequence is linked by identity and time, **not proven token/session continuity**.\n\nOptional Graph, Office and service-principal panels require their own tables; an unavailable panel is not a clean result. Native alert absence does not establish a detection gap."}},
        {"type": 9, "name": "parameters", "content": {"version": "KqlParameterItem/1.0", "parameters": parameters, "style": "pills"}},
    ]
    readiness = """let Expected = datatable(TableName:string, LastEvent:datetime, Rows:long, IngestP95Minutes:real)
['SigninLogs', datetime(null), 0, real(null), 'AuditLogs', datetime(null), 0, real(null),
 'MicrosoftGraphActivityLogs', datetime(null), 0, real(null), 'OfficeActivity', datetime(null), 0, real(null),
 'AADServicePrincipalSignInLogs', datetime(null), 0, real(null), 'SecurityAlert', datetime(null), 0, real(null)];
union isfuzzy=true Expected,
(SigninLogs | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='SigninLogs'),
(AuditLogs | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='AuditLogs'),
(MicrosoftGraphActivityLogs | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='MicrosoftGraphActivityLogs'),
(OfficeActivity | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='OfficeActivity'),
(AADServicePrincipalSignInLogs | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='AADServicePrincipalSignInLogs'),
(SecurityAlert | where TimeGenerated > ago({TimeRange:seconds}s) | summarize LastEvent=max(TimeGenerated), Rows=count(), IngestP95Minutes=percentile(todouble(datetime_diff('minute', ingestion_time(), TimeGenerated)),95) | extend TableName='SecurityAlert')
| summarize LastEvent=max(LastEvent), Rows=max(Rows), IngestP95Minutes=max(IngestP95Minutes) by TableName
| extend Status=case(Rows == 0, 'No events: check availability, connector, permissions or idle workload', LastEvent < ago(2h), 'No events in last two hours: check freshness or idle workload', 'Recent events observed')
| order by TableName asc"""
    items.append(query_item("readiness", "Workspace-wide telemetry readiness (not filtered by identity)", readiness))
    for rule in suite["rules"]:
        query = render_rule(rule).replace("let QueryLookback = 4h;", "let QueryLookback = {TimeRange:seconds}s;")
        query = query.replace("let EmissionWindow = 2h;", "let EmissionWindow = QueryLookback;")
        items.append(query_item(rule["id"], rule["name"], CONTEXT + query + USER_FILTER + "\n| order by TimeGenerated desc | take 200", rule["id"] == "S002"))
    methods = read(Path("sentinel") / "queries" / "method-registrations.kql")
    items.append(query_item("method-events", "Successful individual-method registrations: target versus actor", CONTEXT +
        "let QueryLookback = {TimeRange:seconds}s;\nlet ExcludedUserIds=dynamic([]);\n" + methods +
        "MethodRegistrations | extend AccountObjectId=TargetUserId" + USER_FILTER + "\n| order by MethodTime desc | take 200"))
    graph = """MicrosoftGraphActivityLogs
| where TimeGenerated > ago({TimeRange:seconds}s)
| extend EntraTenantId=tolower(AadTenantId), AccountObjectId=tolower(UserId), RequestPath=tolower(tostring(parse_url(RequestUri).Path))
| where RequestMethod =~ 'GET' and ResponseStatusCode between (200 .. 299)
| where RequestPath contains '/messages' or RequestPath endswith '/content'
"""
    items.append(query_item("content-api", "Successful content-oriented Graph requests: not proof of exfiltration", CONTEXT + graph + USER_FILTER +
        "\n| project TimeGenerated, EntraTenantId, AccountObjectId, AppId, IPAddress, RequestPath, ResponseStatusCode, RequestId\n| order by TimeGenerated desc | take 200", True))
    office = f"""let UserMap = AuditLogs
| where TimeGenerated > ago(7d)
| mv-expand Target=TargetResources
| where tostring(Target.type) =~ 'User'
| extend EntraTenantId=tolower(AADTenantId), AccountObjectId=tolower(tostring(Target.id)), JoinUPN=tolower(tostring(Target.userPrincipalName))
| where AccountObjectId matches regex @'{GUID_RE}' and isnotempty(JoinUPN)
| summarize arg_max(TimeGenerated, AccountObjectId) by EntraTenantId, JoinUPN;
OfficeActivity
| where TimeGenerated > ago({{TimeRange:seconds}}s)
| where OfficeWorkload in~ ('SharePoint', 'OneDrive') and Operation in ('FileDownloaded', 'FileSyncDownloadedFull')
| extend EntraTenantId=tolower(OrganizationId), JoinUPN=tolower(UserId)
| join kind=inner UserMap on EntraTenantId, JoinUPN
"""
    items.append(query_item("downloads", "Recorded file downloads (audit-mapped users only; not proof of external exfiltration)", CONTEXT + office + USER_FILTER +
        "\n| project TimeGenerated, EntraTenantId, AccountObjectId, UserId, Operation, ClientIP, OfficeObjectId\n| order by TimeGenerated desc | take 200", True))
    alerts = """SecurityAlert
| where TimeGenerated > ago({TimeRange:seconds}s)
| where SelectedUserId == '*' or tostring(Entities) contains SelectedUserId
| where SelectedTenantId == '*' or tostring(Entities) contains SelectedTenantId or tostring(ExtendedProperties) contains SelectedTenantId
| project TimeGenerated, AlertName, AlertSeverity, ProviderName, SystemAlertId, Entities
| order by TimeGenerated desc | take 200"""
    items.append(query_item("native-alerts", "Available security alerts: contextual evidence, not exhaustive native coverage", CONTEXT + alerts, True))
    items.append({"type": 1, "name": "limits", "content": {"json": "## Interpretation and coverage\n\nS001 overlaps native token/phishing/credential-addition detections. S002 overlaps suspicious API traffic and app governance. S003 deliberately enriches native risk and overlaps Defender D001; select one alerting route. A missing alert in this workspace does not prove Microsoft failed to detect the activity.\n\n**Service-principal hunting:** use H001-service-principal-origin.kql separately. It needs 14 days of sign-in history and only maps audited service-principal objects, never application object IDs.\n\nNo panel proves remediation complete. Confirm sessions were revoked and unauthorized methods/credentials removed in the authoritative services. Exported logs contain sensitive identity and resource information; apply workspace RBAC."}})
    return {"version": "Notebook/1.0", "items": items, "isLocked": False,
            "fallbackResourceIds": ["{{WORKSPACE_RESOURCE_ID}}"]}


def workbook_template(document):
    serialized = json.dumps(document, ensure_ascii=False, separators=(",", ":"))
    return template({
        "workspaceResourceId": parameter("string", description="Full existing Log Analytics workspace resource ID."),
        "workbookName": parameter("string", "e0506f06-043c-42e4-bbb5-9209ea49e705"),
        "location": parameter("string", "[resourceGroup().location]"),
    }, [{
        "type": "Microsoft.Insights/workbooks", "apiVersion": "2022-04-01",
        "name": "[parameters('workbookName')]", "location": "[parameters('location')]", "kind": "shared",
        "properties": {"displayName": "Entra identity attack-chain investigation", "category": "sentinel",
            "sourceId": "[parameters('workspaceResourceId')]",
            "serializedData": "[replace(" + arm_string(serialized) + ", '{{WORKSPACE_RESOURCE_ID}}', parameters('workspaceResourceId'))]"},
    }])


def arm_string(value):
    return "'" + value.replace("'", "''") + "'"


def artifacts():
    suite = load_suite()
    document = workbook(suite)
    outputs = {
        Path("dist") / "sentinel-rules.arm.json": analytics_template(suite),
        Path("dist") / "workbook.arm.json": workbook_template(document),
        Path("workbook") / "entra-investigation.workbook.json": document,
    }
    result = {path: json.dumps(value, indent=2, ensure_ascii=False) + "\n" for path, value in outputs.items()}
    for rule in suite["rules"]:
        result[Path("dist") / (rule["id"] + ".kql")] = render_rule(rule)
    result[Path("dist") / "sentinel-fixtures.kql"] = sentinel_kql({rule["id"]: render_rule(rule) for rule in suite["rules"]})
    result[Path("dist") / "defender-fixtures.kql"] = defender_kql(read(Path("defender") / suite["defender"][0]["query"]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify generated files are current without writing.")
    args = parser.parse_args()
    stale = []
    for path, text in artifacts().items():
        destination = ROOT / path
        if args.check:
            if not destination.exists() or destination.read_text(encoding="utf-8") != text:
                stale.append(str(path))
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(text, encoding="utf-8", newline="\n")
            print(destination)
    if stale:
        raise SystemExit("Stale generated artifacts: " + ", ".join(stale))
    if args.check:
        print("Generated artifacts are current.")


if __name__ == "__main__":
    main()
