import base64
import contextlib
import csv
import hashlib
from html.parser import HTMLParser
import io
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import export_html


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.scripts = {}
        self.style = ""
        self.active = None
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append((tag, attrs))
        if tag == "script":
            self.active = attrs.get("id")
            self.scripts[self.active] = ""
        elif tag == "style":
            self.active = "style"

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.active = None

    def handle_data(self, data):
        if self.active == "style":
            self.style += data
        elif self.active:
            self.scripts[self.active] += data


class CsvImport(unittest.TestCase):
    def load(self, text, key="s001", encoding="utf-8-sig"):
        raw = text.encode(encoding)
        with patch.object(Path, "stat", return_value=SimpleNamespace(st_size=len(raw))), patch.object(Path, "read_bytes", return_value=raw):
            return export_html.read_panel(key, Path("private-folder") / "evidence.csv")

    def test_sentinel_headers_bom_multiline_and_source_path_privacy(self):
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(["TimeGenerated [UTC]", "AccountObjectId", "MethodEventId", "EntraTenantId", "Evidence"])
        writer.writerow(["2026-11-05T12:30:00Z", "USER", "m1", "TENANT", 'Line one, "quoted"\nLine two'])
        panel = self.load(stream.getvalue())
        self.assertEqual(panel["source"], "evidence.csv")
        self.assertEqual(panel["rows"][0]["user"], "user")
        self.assertEqual(panel["rows"][0]["tenant"], "tenant")
        self.assertEqual(panel["rows"][0]["cells"][-1], 'Line one, "quoted"\nLine two')
        self.assertEqual(panel["rows"][0]["time"], 1793881800000)

    def test_utf16_export(self):
        panel = self.load("TimeGenerated,AccountObjectId,MethodEventId\n2026-11-05T12:30:00Z,u,m1\n", encoding="utf-16")
        self.assertEqual(len(panel["rows"]), 1)

    def test_header_only_is_explicitly_empty(self):
        self.assertEqual(self.load("TimeGenerated,AccountObjectId,MethodEventId\n")["rows"], [])

    def test_missing_or_duplicate_headers_fail(self):
        for text in ("", "TimeGenerated,AccountObjectId\n", "TimeGenerated,TimeGenerated [UTC],MethodEventId\n", ",AccountObjectId,MethodEventId\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.load(text)

    def test_inconsistent_and_malformed_csv_fail(self):
        for text in ("TimeGenerated,AccountObjectId,MethodEventId\na,b\n", 'TimeGenerated,AccountObjectId,MethodEventId\n"unterminated,b,c'):
            with self.subTest(text=text), self.assertRaises((ValueError, csv.Error)):
                self.load(text)

    def test_bad_timestamps_are_retained_and_counted(self):
        panel = self.load("TimeGenerated,AccountObjectId,MethodEventId\nnot-a-date,u,m1\n")
        self.assertEqual(panel["untimed"], 1)
        self.assertIsNone(panel["rows"][0]["time"])

    def test_registration_and_readiness_panels(self):
        panel = self.load("MethodTime,AccountObjectId\n2026-11-05T12:30:00Z,u\n", "registrations")
        self.assertIsNotNone(panel["rows"][0]["time"])
        readiness = self.load("TableName,Rows,Status\nAuditLogs,0,No events\n", "readiness")
        self.assertEqual(readiness["untimed"], 0)
        self.assertEqual(readiness["rows"][0]["cells"][1], "0")

    def test_file_and_row_limits_fail_without_truncation(self):
        with patch.object(export_html, "MAX_FILE_BYTES", 8), self.assertRaises(ValueError):
            self.load("TimeGenerated,AccountObjectId,MethodEventId\n")
        with patch.object(export_html, "MAX_ROWS", 1), self.assertRaises(ValueError):
            self.load("TimeGenerated,AccountObjectId,MethodEventId\na,u,m1\nb,u,m2\n")

    def test_dates_are_explicitly_utc(self):
        expected = export_html.timestamp("2026-11-05T12:30:00Z")
        for date in ("2026-11-05T12:30:00", "2026-11-05T14:30:00+02:00", "11/05/2026, 12:30:00 PM", "11/05/2026, 12:30:00.000 PM"):
            with self.subTest(date=date):
                self.assertEqual(export_html.timestamp(date), expected)
        self.assertIsNone(export_html.timestamp("05/11/2026 12:30"))


class HtmlExport(unittest.TestCase):
    def test_embedded_json_is_lossless_and_cannot_close_the_script(self):
        panels = export_html.demo_panels()
        attack = '</script><img src=x onerror=alert(1)> & {{SCRIPT_HASH}} {{DATA}} \u2028'
        panels[0]["rows"][0]["cells"][-1] = attack
        panels[0]["headers"][-1] = attack
        document = export_html.render(panels, generated="synthetic")
        parsed = Document(document)
        self.assertEqual(set(parsed.scripts), {"evidence-data", "dashboard-code"})
        decoded = json.loads(parsed.scripts["evidence-data"])
        self.assertEqual(decoded["panels"], panels)
        self.assertNotIn("<img", document)
        self.assertNotIn("<", parsed.scripts["evidence-data"])

    def test_content_security_hashes_match_exact_embedded_code(self):
        document = Document(export_html.render(export_html.demo_panels()))
        policy = next(attrs["content"] for tag, attrs in document.tags if tag == "meta" and attrs.get("http-equiv") == "Content-Security-Policy")
        for source in (document.scripts["dashboard-code"], document.style):
            digest = base64.b64encode(hashlib.sha256(source.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", policy)
        self.assertIn("connect-src 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertFalse(any("src" in attrs or tag == "link" for tag, attrs in document.tags))

    def test_template_uses_text_not_html_for_imported_cells(self):
        code = Document(export_html.render(export_html.demo_panels())).scripts["dashboard-code"]
        for unsafe in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "fetch(", "XMLHttpRequest", "localStorage"):
            self.assertNotIn(unsafe, code)
        self.assertIn("textContent", code)
        self.assertIn('if(panel.key===\"readiness\")return panel.rows;', code)

    def test_demo_is_explicit_and_all_panel_keys_are_present(self):
        document = export_html.render(export_html.demo_panels(), demo=True)
        data = json.loads(Document(document).scripts["evidence-data"])
        self.assertTrue(data["demo"])
        for key in export_html.PANELS:
            self.assertIn(key, document)
        self.assertIn("Not imported", document)
        self.assertIn("Header-only export", document)

    def test_render_is_deterministic_for_given_generation_time(self):
        panels = export_html.demo_panels()
        self.assertEqual(export_html.render(panels, generated="fixed"), export_html.render(panels, generated="fixed"))

    def test_cli_rejects_no_inputs_and_demo_mixed_with_csv(self):
        cases = (["--output", "exports\\report.html"], ["--demo", "--s001", "input.csv", "--output", "exports\\report.html"])
        for args in cases:
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                export_html.main(args)
            self.assertEqual(error.exception.code, 2)

    def test_cli_rejects_duplicate_panel_arguments(self):
        message = io.StringIO()
        with contextlib.redirect_stderr(message), self.assertRaises(SystemExit) as error:
            export_html.main(["--s001", "first.csv", "--s001", "second.csv", "--output", "exports\\report.html"])
        self.assertEqual(error.exception.code, 2)
        self.assertIn("--s001 may be supplied only once", message.getvalue())

    def test_cli_never_overwrites_existing_outputs(self):
        with patch.object(Path, "exists", return_value=True), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            export_html.main(["--demo", "--output", "exports\\report.html"])


if __name__ == "__main__":
    unittest.main()
