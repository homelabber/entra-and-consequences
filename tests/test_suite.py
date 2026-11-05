import ast
import copy
import json
import re
import sys
import unittest
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import build
import fixtures
import reference


class BehavioralFixtures(unittest.TestCase):
    def setUp(self):
        self.events = fixtures.sentinel_events()

    def test_sentinel_positive_and_negative_fixtures(self):
        self.assertEqual(reference.sentinel(self.events), sorted(self.events["expected"]))

    def test_actor_is_not_target(self):
        event = next(m for m in self.events["methods"] if m["id"] == "m5")
        self.assertNotEqual(event["actor"], event["user"])
        self.assertIn(("S001", f"S001:{fixtures.TENANT}:m5"), reference.sentinel(self.events))

    def test_failure_reverse_order_cross_tenant_and_long_gap_do_not_alert(self):
        results = reference.sentinel(self.events)
        for number in (2, 3, 4, 6, 7, 8, 10, 12, 13, 14, 15, 16, 17, 19, 20):
            self.assertFalse(any(re.search(fr":m{number}(?::|$)", key) for _, key in results), number)

    def test_user_exclusion_is_target_scoped(self):
        results = reference.sentinel(self.events, excluded_users=[fixtures.uid(1)])
        self.assertNotIn(("S001", f"S001:{fixtures.TENANT}:m1"), results)
        self.assertIn(("S001", f"S001:{fixtures.TENANT}:m5"), results)

    def test_app_exclusion_applies_to_graph_only(self):
        results = reference.sentinel(self.events, excluded_apps=[fixtures.APP])
        self.assertFalse(any(rule == "S002" for rule, _ in results))
        self.assertTrue(any(rule == "S001" for rule, _ in results))

    def test_future_events_are_not_accepted(self):
        self.events["methods"][0]["age"] = -5
        self.assertNotIn(("S001", f"S001:{fixtures.TENANT}:m1"), reference.sentinel(self.events))

    def test_empty_directory_does_not_correlate(self):
        self.events["methods"][0]["tenant"] = ""
        self.events["signins"][0]["tenant"] = ""
        self.assertNotIn(("S001", ":m1"), reference.sentinel(self.events))
        self.assertFalse(any(key.endswith(":m1") for _, key in reference.sentinel(self.events)))

    def test_graph_threshold_and_one_application_required(self):
        self.events["graph"] = [g for g in self.events["graph"] if g["id"] != "g11-24"]
        self.assertFalse(any(rule == "S002" for rule, _ in reference.sentinel(self.events)))

    def test_exact_correlation_boundary_is_inclusive(self):
        self.assertIn(("S001", f"S001:{fixtures.TENANT}:m18"), reference.sentinel(self.events))

    def test_exact_emission_boundary_is_exclusive(self):
        self.assertNotIn(("S001", f"S001:{fixtures.TENANT}:m19"), reference.sentinel(self.events))

    def test_defender_addition_replacement_and_duplicate_target(self):
        events = fixtures.defender_events()
        self.assertEqual(reference.defender(events), events["expected"])

    def test_defender_does_not_require_array_count_increase(self):
        events = fixtures.defender_events()
        prop = events["updates"][1]["raw"]["ModifiedProperties"][0]
        self.assertEqual(len(json.loads(prop["OldValue"])), len(json.loads(prop["NewValue"])))
        self.assertIn("d2", reference.defender(events))

    def test_defender_malformed_new_data_fails_closed(self):
        events = fixtures.defender_events()
        events["updates"][0]["raw"]["ModifiedProperties"][0]["NewValue"] = '{"Id":"not-an-array"}'
        self.assertNotIn("d1", reference.defender(events))

    def test_defender_success_required(self):
        events = fixtures.defender_events()
        events["updates"][0]["raw"]["ResultStatus"] = "Failure"
        self.assertNotIn("d1", reference.defender(events))

    def test_defender_ambiguous_target_format_not_guessed(self):
        events = fixtures.defender_events()
        events["updates"][0]["raw"]["Target"] = [{"ID": events["updates"][0]["user"]}]
        self.assertNotIn("d1", reference.defender(events))


class PackageContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.suite = build.load_suite()
        cls.outputs = build.artifacts()
        cls.arm = build.analytics_template(cls.suite)
        cls.workbook = build.workbook(cls.suite)

    def test_all_generated_files_persisted_and_current(self):
        for path, content in self.outputs.items():
            with self.subTest(path=path):
                self.assertTrue((ROOT / path).is_file())
                self.assertEqual((ROOT / path).read_text(encoding="utf-8"), content)

    def test_build_is_deterministic(self):
        self.assertEqual(self.outputs, build.artifacts())

    def test_all_python_sources_parse(self):
        for path in ROOT.rglob("*.py"):
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    def test_all_json_files_parse(self):
        for path in ROOT.rglob("*.json"):
            json.loads(path.read_text(encoding="utf-8"))

    def test_stable_unique_rule_guids(self):
        guids = [str(UUID(rule["guid"])) for rule in self.suite["rules"]]
        self.assertEqual(len(guids), len(set(guids)))

    def test_rules_disabled_and_optional_dependencies_opt_in(self):
        parameters = self.arm["parameters"]
        self.assertFalse(parameters["enableRules"]["defaultValue"])
        self.assertFalse(parameters["deployGraphRule"]["defaultValue"])
        self.assertFalse(parameters["deployRiskRule"]["defaultValue"])
        for resource in self.arm["resources"]:
            self.assertEqual(resource["properties"]["enabled"], "[parameters('enableRules')]")
            self.assertIn("condition", resource)

    def test_query_windows_match_schedule_and_overlap(self):
        for resource in self.arm["resources"]:
            props = resource["properties"]
            self.assertEqual(props["queryPeriod"], "PT4H")
            self.assertEqual(props["queryFrequency"], "PT1H")
            self.assertIn("let QueryLookback = 4h;", props["query"])
            self.assertIn("let EmissionWindow = 2h;", props["query"])

    def test_directory_and_target_are_join_keys(self):
        for rule in self.suite["rules"]:
            query = build.render_rule(rule)
            self.assertIn("join kind=inner", query)
            self.assertIn("on EntraTenantId, TargetUserId", query)
            self.assertNotIn("innerunique", query)
            self.assertIn("tostring(Target.id)", query)
            self.assertIn("TimeGenerated <= now()", query)

    def test_queries_are_expanded_and_output_entities_exist(self):
        for resource in self.arm["resources"]:
            query = resource["properties"]["query"]
            self.assertNotIn("{{METHOD_REGISTRATIONS}}", query)
            self.assertIn("| project TimeGenerated, EntraTenantId, AccountObjectId", query)
            for mapping in resource["properties"]["entityMappings"]:
                for field in mapping["fieldMappings"]:
                    self.assertIn(field["columnName"], query.split("| project TimeGenerated,")[-1])
            for column in resource["properties"]["customDetails"].values():
                self.assertIn(column, query.split("| project TimeGenerated,")[-1])

    def test_incident_grouping_is_not_global_alert_suppression(self):
        for resource in self.arm["resources"]:
            props = resource["properties"]
            self.assertFalse(props["suppressionEnabled"])
            grouping = props["incidentConfiguration"]["groupingConfiguration"]
            self.assertEqual(grouping["groupByEntities"], ["Account"])
            self.assertIn("EntraTenantId", grouping["groupByCustomDetails"])

    def test_defender_source_event_identity_preserved(self):
        query = build.read(Path("defender") / self.suite["defender"][0]["query"])
        self.assertIn("| project Timestamp, ReportId, AccountObjectId", query)
        self.assertNotIn("Timestamp =", query)
        self.assertIn("TargetUserId == tolower(AccountObjectId)", query)
        self.assertIn("NewMethodId !in (OldMethodIds)", query)
        self.assertIn("gettype(OldDevices)", query)

    def test_workbook_arm_replaces_workspace_not_queries(self):
        arm = build.workbook_template(self.workbook)
        expression = arm["resources"][0]["properties"]["serializedData"]
        prefix, suffix = "[replace('", "', '{{WORKSPACE_RESOURCE_ID}}', parameters('workspaceResourceId'))]"
        self.assertTrue(expression.startswith(prefix) and expression.endswith(suffix))
        payload = expression[len(prefix):-len(suffix)].replace("''", "'")
        decoded = json.loads(payload)
        self.assertEqual(decoded, self.workbook)
        self.assertNotIn("{{METHOD_REGISTRATIONS}}", payload)

    def test_workbook_parameters_are_scoped_and_no_free_text_query_input(self):
        parameters = next(i for i in self.workbook["items"] if i["type"] == 9)["content"]["parameters"]
        for p in parameters:
            if p["name"] in ("UserObjectId", "DirectoryId"):
                self.assertFalse(p["typeSettings"]["allowCustomValues"])
                self.assertIn(build.GUID_RE, p["query"])
        panels = [i for i in self.workbook["items"] if i["type"] == 3]
        self.assertEqual(len(panels), 8)
        self.assertIn("Expected", panels[0]["content"]["query"])
        for item in panels[1:]:
            self.assertIn("SelectedUserId", item["content"]["query"])
            self.assertIn("SelectedTenantId", item["content"]["query"])

    def test_readiness_union_keeps_ingestion_delay_type_consistent(self):
        query = next(i for i in self.workbook["items"] if i["name"] == "readiness")["content"]["query"]
        self.assertIn("IngestP95Minutes:real", query)
        self.assertEqual(query.count("IngestP95Minutes=percentile(todouble(datetime_diff("), 6)
        self.assertNotIn("IngestP95Minutes=percentile(datetime_diff(", query)

    def test_local_documentation_links_exist(self):
        for path in ROOT.rglob("*.md"):
            for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
                if "://" in target or target.startswith("#"):
                    continue
                with self.subTest(document=path, target=target):
                    self.assertTrue((path.parent / target.split("#", 1)[0]).is_file())

    def test_engine_fixtures_embed_actual_production_queries(self):
        sentinel_fixture = self.outputs[Path("dist") / "sentinel-fixtures.kql"]
        for rule in self.suite["rules"]:
            self.assertIn(build.render_rule(rule), sentinel_fixture)
        defender_fixture = self.outputs[Path("dist") / "defender-fixtures.kql"]
        self.assertIn(build.read(Path("defender") / self.suite["defender"][0]["query"]), defender_fixture)
        self.assertIn("Passed", sentinel_fixture)
        self.assertIn("Passed", defender_fixture)

    def test_hunting_uses_principal_object_id_not_application_object_id(self):
        query = build.read(Path("hunting") / "H001-service-principal-origin.kql")
        self.assertIn('tostring(Target.type) =~ "ServicePrincipal"', query)
        self.assertIn("tolower(ServicePrincipalId)", query)
        self.assertNotIn("ResourceServicePrincipalId", query)
        self.assertIn("Credential use is not proven", query)


if __name__ == "__main__":
    unittest.main()
