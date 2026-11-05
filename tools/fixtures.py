"""Synthetic events and hand-selected expectations; no customer data."""
import json
from uuid import UUID

TENANT = str(UUID(int=1))
OTHER_TENANT = str(UUID(int=2))
APP = str(UUID(int=500))


def uid(number):
    return str(UUID(int=1000 + number))


def method(number, age=10, **overrides):
    value = {"id": f"m{number}", "age": age, "tenant": TENANT, "user": uid(number),
             "actor": uid(999), "result": "success", "operation": "User registered security info", "targetType": "User"}
    value.update(overrides)
    return value


def sign_in(number, age=30, **overrides):
    value = {"id": f"s{number}", "age": age, "tenant": TENANT, "user": uid(number),
             "result": "0", "protocol": "deviceCode", "risk": "none", "ip": "192.0.2.10", "app": APP}
    value.update(overrides)
    return value


def graph(number, age=40, count=25, **overrides):
    rows = []
    for index in range(count):
        surface = ("users", "groups", "sites")[index % 3]
        value = {"id": f"g{number}-{index}", "age": age, "tenant": TENANT, "user": uid(number),
                 "app": APP, "method": "GET", "status": 200,
                 "uri": f"https://graph.microsoft.com/v1.0/{surface}?$top=1", "ip": "198.51.100.9"}
        value.update(overrides)
        rows.append(value)
    return rows


def sentinel_events():
    methods = [method(number) for number in range(1, 11)]
    methods[6]["result"] = "failure"
    methods[7]["operation"] = "User registered all required security info"
    methods += [method(number, age=90) for number in range(11, 18)]
    methods += [method(18, age=119), method(19, age=120), method(20, user=""), method(21, operation="User registered security information")]
    signs = [sign_in(1), sign_in(2, result="50126"), sign_in(3, age=5),
             sign_in(4, tenant=OTHER_TENANT), sign_in(5), sign_in(6, age=141), sign_in(7), sign_in(8),
             sign_in(9, protocol="oAuth2", risk="high"), sign_in(10, protocol="oAuth2", risk="low"),
             sign_in(18, age=239), sign_in(19, age=130), sign_in(20, user=""), sign_in(21)]
    reads = graph(11) + graph(12, id="duplicate")
    split = graph(13)
    for index, row in enumerate(split):
        row["app"] = str(UUID(int=600 + index % 3))
    reads += split + graph(14, status=403) + graph(15, age=100)
    reads += graph(16, tenant=OTHER_TENANT) + graph(17, uri="https://graph.microsoft.com/v1.0/usersNotAResource")
    expected = [("S001", f"S001:{TENANT}:m{number}") for number in (1, 5, 18, 21)]
    expected += [("S002", f"S002:{TENANT}:m11:{APP}"), ("S003", f"S003:{TENANT}:m9")]
    return {"methods": methods, "signins": signs, "graph": reads, "expected": expected}


def defender_events():
    signs, updates = [], []
    for number in range(1, 10):
        user = uid(100 + number)
        signs.append({"user": user, "age": 60, "risk": 50, "error": 0})
        old = [{"Id": "old"}]
        new = [{"Id": "old"}, {"Id": "new"}]
        updates.append({"report": f"d{number}", "user": user, "age": 10,
                        "raw": {"Workload": "AzureActiveDirectory", "ResultStatus": "Success",
                                "Target": [{"ID": "User_" + user}],
                                "ModifiedProperties": [{"Name": "StrongAuthenticationPhoneAppDetail",
                                                        "OldValue": json.dumps(old), "NewValue": json.dumps(new)}]}})
    updates[1]["raw"]["ModifiedProperties"][0]["NewValue"] = '[{"Id":"replacement"}]'
    updates[2]["raw"]["ModifiedProperties"][0]["NewValue"] = '[{"Id":"old","DeviceName":"renamed"}]'
    updates[3]["user"] = uid(999)
    updates[4]["raw"]["ModifiedProperties"][0]["OldValue"] = 'malformed'
    signs[5]["error"] = 50126
    updates[6]["raw"]["ModifiedProperties"][0]["NewValue"] = '[{"Id":""}]'
    updates[7]["raw"]["Target"] *= 2
    signs[8]["age"] = 5
    return {"signins": signs, "updates": updates, "expected": ["d1", "d2", "d8"]}


def literal(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def datatable(name, columns, rows):
    schema = ", ".join(f"{key}:{kind}" for key, kind in columns)
    rendered = []
    for row in rows:
        cells = []
        for (_, kind), value in zip(columns, row):
            if kind == "dynamic":
                cells.append("dynamic(" + json.dumps(value, separators=(",", ":")) + ")")
            elif kind in ("long", "int"):
                cells.append(str(value))
            else:
                cells.append(literal(value))
        rendered.append("    " + ", ".join(cells))
    return f"let {name} = datatable({schema})[\n" + ",\n".join(rendered) + "\n]"


def sentinel_kql(queries):
    events = sentinel_events()
    source = datatable("AuditLogs", [("Age", "long"), ("AADTenantId", "string"), ("Id", "string"),
                                   ("Result", "string"), ("OperationName", "string"),
                                   ("TargetResources", "dynamic"), ("InitiatedBy", "dynamic")], [
        [m["age"], m["tenant"], m["id"], m["result"], m["operation"],
         [{"type": m["targetType"], "id": m["user"], "userPrincipalName": f"user{index}@example.invalid"}],
         {"user": {"id": m["actor"], "ipAddress": "192.0.2.99"}}]
        for index, m in enumerate(events["methods"])
    ]) + " | extend TimeGenerated=now()-Age*1m;\n"
    source += datatable("SigninLogs", [("Age", "long"), ("AADTenantId", "string"), ("Id", "string"),
                                     ("UserId", "string"), ("ResultType", "string"), ("AuthenticationProtocol", "string"),
                                     ("RiskLevelDuringSignIn", "string"), ("IPAddress", "string"), ("AppId", "string")], [
        [s["age"], s["tenant"], s["id"], s["user"], s["result"], s["protocol"], s["risk"], s["ip"], s["app"]]
        for s in events["signins"]
    ]) + " | extend TimeGenerated=now()-Age*1m;\n"
    source += datatable("MicrosoftGraphActivityLogs", [("Age", "long"), ("AadTenantId", "string"),
        ("UserId", "string"), ("AppId", "string"), ("RequestMethod", "string"), ("ResponseStatusCode", "int"),
        ("RequestUri", "string"), ("RequestId", "string"), ("IPAddress", "string")], [
            [g["age"], g["tenant"], g["user"], g["app"], g["method"], g["status"], g["uri"], g["id"], g["ip"]]
            for g in events["graph"]
        ]) + " | extend TimeGenerated=now()-Age*1m;\n"
    for rule_id, query in queries.items():
        source += f"let Test{rule_id} = () {{\n{query}\n| project RuleId='{rule_id}', AlertKey\n}};\n"
    source += datatable("Expected", [("RuleId", "string"), ("AlertKey", "string")], events["expected"]) + ";\n"
    source += "union (TestS001()), (TestS002()), (TestS003())\n| extend Source='actual'\n| union (Expected | extend Source='expected')\n| summarize Actual=countif(Source == 'actual'), Expected=countif(Source == 'expected') by RuleId, AlertKey\n| extend Passed = Actual == Expected\n| order by Passed asc, RuleId asc\n"
    return source


def defender_kql(query):
    events = defender_events()
    source = datatable("EntraIdSignInEvents", [("Age", "long"), ("AccountObjectId", "string"),
        ("RiskLevelDuringSignIn", "int"), ("ErrorCode", "int"), ("IPAddress", "string"), ("CorrelationId", "string")], [
            [s["age"], s["user"], s["risk"], s["error"], "192.0.2.10", f"c{index}"] for index, s in enumerate(events["signins"])
        ]) + " | extend Timestamp=now()-Age*1m;\n"
    source += datatable("CloudAppEvents", [("Age", "long"), ("AccountObjectId", "string"), ("ReportId", "string"),
        ("ActionType", "string"), ("RawEventData", "dynamic")], [
            [u["age"], u["user"], u["report"], "Update user.", u["raw"]] for u in events["updates"]
        ]) + " | extend Timestamp=now()-Age*1m;\n"
    source += "let Actual = () {\n" + query + "\n| project ReportId\n};\n"
    source += datatable("Expected", [("ReportId", "string")], [[v] for v in events["expected"]]) + ";\n"
    source += "Actual() | extend Source='actual'\n| union (Expected | extend Source='expected')\n| summarize Actual=countif(Source == 'actual'), Expected=countif(Source == 'expected') by ReportId\n| extend Passed=Actual == Expected\n| order by Passed asc, ReportId asc\n"
    return source
