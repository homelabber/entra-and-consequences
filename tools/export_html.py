"""Build a self-contained, offline investigation dashboard from Sentinel CSV exports."""
import argparse
import base64
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_ROWS = 100_000
PANELS = {
    "s001": ("S001 · Device code → registration", ("TimeGenerated", "AccountObjectId", "MethodEventId")),
    "s002": ("S002 · Registration → Graph reads", ("TimeGenerated", "AccountObjectId", "MethodEventId")),
    "s003": ("S003 · Native risk → registration", ("TimeGenerated", "AccountObjectId", "MethodEventId")),
    "registrations": ("Individual method registrations", ("MethodTime", "AccountObjectId")),
    "graph": ("Content-oriented Graph requests", ("TimeGenerated", "RequestId")),
    "downloads": ("Recorded file downloads", ("TimeGenerated", "Operation")),
    "alerts": ("Available native security alerts", ("TimeGenerated", "AlertName")),
    "readiness": ("Workspace telemetry snapshot", ("TableName", "Rows", "Status")),
}


def canonical(name):
    return re.sub(r"\s*\[UTC\]\s*$", "", name, flags=re.IGNORECASE).strip().lower()


def timestamp(value):
    value = value.strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        parsed = None
        for fmt in ("%m/%d/%Y, %I:%M:%S.%f %p", "%m/%d/%Y, %I:%M:%S %p",
                    "%m/%d/%Y, %H:%M:%S.%f", "%m/%d/%Y, %H:%M:%S"):
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            return None
    try:
        parsed = parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed
        return int(parsed.timestamp() * 1000)
    except (OverflowError, OSError, ValueError):
        return None


def read_panel(key, path):
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ValueError(f"{key}: CSV exceeds the 25 MiB per-file limit")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"{key}: CSV exceeds the 25 MiB per-file limit")
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    text = raw.decode(encoding, errors="strict")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    headers = next(reader, None)
    if not headers:
        raise ValueError(f"{key}: CSV has no header; export the query result with column names")
    normalized = [canonical(h) for h in headers]
    if any(not h for h in normalized) or len(set(normalized)) != len(normalized):
        raise ValueError(f"{key}: column names must be nonempty and unique")
    required = {canonical(h) for h in PANELS[key][1]}
    missing = required - set(normalized)
    if missing:
        raise ValueError(f"{key}: missing required columns: {', '.join(sorted(missing))}")
    indices = dict(zip(normalized, range(len(headers))))

    def cell(row, name):
        index = indices.get(canonical(name))
        return row[index] if index is not None else ""

    rows = []
    untimed = 0
    for row in reader:
        if not row:
            continue
        if len(row) != len(headers):
            raise ValueError(f"{key}: CSV record ending at line {reader.line_num} has {len(row)} cells; expected {len(headers)}")
        if len(rows) >= MAX_ROWS:
            raise ValueError(f"{key}: CSV exceeds the {MAX_ROWS:,} row limit")
        time = timestamp(cell(row, "MethodTime" if key == "registrations" else "TimeGenerated"))
        if key != "readiness" and time is None:
            untimed += 1
        rows.append({"cells": row, "time": time,
                     "tenant": cell(row, "EntraTenantId").strip().lower(),
                     "user": cell(row, "AccountObjectId").strip().lower()})
    return {"key": key, "title": PANELS[key][0], "source": path.name,
            "headers": headers, "rows": rows, "untimed": untimed, "bytes": len(raw)}


def demo_panels():
    tenant = "00000000-0000-0000-0000-000000000001"
    user = "00000000-0000-0000-0000-000000000401"
    panels = []
    for key in ("s001", "s002", "s003"):
        headers = ["TimeGenerated", "EntraTenantId", "AccountObjectId", "MethodEventId", "Evidence"]
        cells = ["2026-11-05T12:30:00Z", tenant, user, "synthetic-method-1", "Synthetic example, not a confirmed incident"]
        panels.append({"key": key, "title": PANELS[key][0], "source": "Built-in synthetic example",
                       "headers": headers, "rows": [{"cells": cells, "time": timestamp(cells[0]), "tenant": tenant, "user": user}],
                       "untimed": 0, "bytes": 0})
    panels.append({"key": "readiness", "title": PANELS["readiness"][0], "source": "Built-in synthetic example",
                   "headers": ["TableName", "Rows", "Status"], "rows": [{"cells": ["AuditLogs", "1", "Synthetic snapshot"],
                   "time": None, "tenant": "", "user": ""}], "untimed": 0, "bytes": 0})
    return panels


def safe_json(value):
    return (json.dumps(value, ensure_ascii=True, separators=(",", ":"))
            .replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))


def script_hash(text):
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def render(panels, demo=False, generated=None):
    data = {"panels": panels, "demo": demo,
            "generated": generated or datetime.now(timezone.utc).isoformat()}
    template = (ROOT / "tools" / "html_dashboard.html").read_text(encoding="utf-8")
    script = re.search(r"<script id=\"dashboard-code\">([\s\S]*?)</script>", template).group(1)
    style = re.search(r"<style>([\s\S]*?)</style>", template).group(1)
    # Replace data last: imported cell text must never become a template directive.
    return (template.replace("{{SCRIPT_HASH}}", script_hash(script)).replace("{{STYLE_HASH}}", script_hash(style))
            .replace("{{DATA}}", safe_json(data)))


class SingleInput(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error(f"{option_string} may be supplied only once")
        setattr(namespace, self.dest, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key, (title, _) in PANELS.items():
        parser.add_argument("--" + key, type=Path, action=SingleInput, metavar="CSV", help=title)
    parser.add_argument("--demo", action="store_true", help="Use clearly labelled synthetic examples, not tenant data")
    parser.add_argument("--output", required=True, type=Path, metavar="HTML", help="New HTML file; existing files are never overwritten")
    args = parser.parse_args(argv)
    inputs = [(key, getattr(args, key)) for key in PANELS if getattr(args, key) is not None]
    if args.demo == bool(inputs):
        parser.error("Provide one or more panel CSVs, or --demo, but not both")
    if args.output.suffix.lower() != ".html":
        parser.error("--output must end in .html")
    if args.output.exists():
        parser.error("Output already exists; choose a new filename")
    try:
        if sum(path.stat().st_size for _, path in inputs) > MAX_TOTAL_BYTES:
            raise ValueError("Input CSVs exceed the 100 MiB combined limit")
        panels = demo_panels() if args.demo else [read_panel(key, path) for key, path in inputs]
        if sum(p["bytes"] for p in panels) > MAX_TOTAL_BYTES:
            raise ValueError("Input CSVs exceed the 100 MiB combined limit")
        if sum(len(p["rows"]) for p in panels) > MAX_ROWS:
            raise ValueError(f"Inputs exceed the {MAX_ROWS:,} combined row limit")
        document = render(panels, demo=args.demo)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(document)
    except (OSError, UnicodeError, csv.Error, ValueError) as error:
        parser.error(str(error))
    print(args.output.resolve())
    print(f"Exported {sum(len(p['rows']) for p in panels):,} rows from {len(panels)} panels. Treat this HTML as sensitive log data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
