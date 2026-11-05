"""Independent Python behavioral model. This does not compile or execute KQL."""
import json
import re
from collections import defaultdict
from urllib.parse import urlsplit

SURFACE = re.compile(r"^/(?:v1\.0|beta)/(users|groups|rolemanagement|applications|serviceprincipals|sites|drives)(?:/|$)")
TARGET = re.compile(r"^User_([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$")
METHOD_OPERATIONS = {"user registered security info", "user registered security information"}


def normalized(value):
    return value.lower() if isinstance(value, str) else ""


def in_window(age, window):
    return 0 <= age < window


def sentinel(events, excluded_users=(), excluded_apps=()):
    results = []
    for m in events["methods"]:
        tenant, user = normalized(m["tenant"]), normalized(m["user"])
        if not tenant or not user or user in excluded_users or not m["id"]:
            continue
        if not in_window(m["age"], 240) or m["result"].lower() != "success":
            continue
        if m["operation"].lower() not in METHOD_OPERATIONS or m["targetType"].lower() != "user":
            continue
        if in_window(m["age"], 120):
            for rule_id, predicate in (
                ("S001", lambda s: s["protocol"].lower() == "devicecode"),
                ("S003", lambda s: s["risk"].lower() in ("medium", "high")),
            ):
                signs = [s for s in events["signins"]
                         if normalized(s["tenant"]) == tenant and normalized(s["user"]) == user
                         and in_window(s["age"], 240) and s["result"] == "0"
                         and 0 <= s["age"] - m["age"] <= 120 and predicate(s)]
                if signs:
                    results.append((rule_id, f"{rule_id}:{tenant}:{m['id']}"))
        groups = defaultdict(list)
        for g in events["graph"]:
            if not in_window(g["age"], 240) or not 0 <= m["age"] - g["age"] <= 120:
                continue
            if normalized(g["tenant"]) != tenant or normalized(g["user"]) != user:
                continue
            if g["method"].lower() != "get" or not 200 <= g["status"] <= 299 or not g["id"]:
                continue
            app = normalized(g["app"])
            match = SURFACE.match(urlsplit(g["uri"]).path.lower())
            if app and app not in excluded_apps and match:
                groups[app].append((g, match[1]))
        for app, reads in groups.items():
            if (len({g["id"] for g, _ in reads}) >= 25 and len({s for _, s in reads}) >= 3
                    and in_window(min(g["age"] for g, _ in reads), 120)):
                results.append(("S002", f"S002:{tenant}:{m['id']}:{app}"))
    return sorted(set(results))


def defender(events):
    results = []
    for update in events["updates"]:
        if not in_window(update["age"], 120) or not update["user"] or not update["report"]:
            continue
        raw = update["raw"]
        if raw.get("Workload") != "AzureActiveDirectory" or raw.get("ResultStatus", "").lower() != "success":
            continue
        targets = [TARGET.match(t.get("ID") or t.get("Id") or "") for t in raw.get("Target", [])]
        user = normalized(update["user"])
        if not any(t and normalized(t[1]) == user for t in targets):
            continue
        changed = False
        for prop in raw.get("ModifiedProperties", []):
            if prop.get("Name") != "StrongAuthenticationPhoneAppDetail":
                continue
            try:
                old, new = json.loads(prop.get("OldValue") or "[]"), json.loads(prop.get("NewValue") or "null")
            except (ValueError, TypeError):
                continue
            if not isinstance(old, list) or not isinstance(new, list):
                continue
            old_ids = {normalized(d.get("Id")) for d in old if isinstance(d, dict)}
            changed |= any(isinstance(d, dict) and normalized(d.get("Id"))
                           and normalized(d.get("Id")) not in old_ids for d in new)
        signs = [s for s in events["signins"] if normalized(s["user"]) == user
                 and in_window(s["age"], 240) and s["error"] == 0 and s["risk"] in (50, 100)
                 and 0 <= s["age"] - update["age"] <= 120]
        if changed and signs:
            results.append(update["report"])
    return sorted(set(results))
