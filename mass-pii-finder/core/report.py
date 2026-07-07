"""
report.py (v2)
Turns validated findings into whichever format the downstream workflow
needs:
  - JSON            machine-readable, good for other tooling
  - HTML            readable, shareable, now with client-side search/filter
  - SARIF 2.1.0     drop straight into GitHub code scanning / most CI
                    security dashboards
  - Markdown        pastes cleanly into a PR comment, Slack, or a ticket
  - CSV             quick pivot-table triage in a spreadsheet
"""

import csv
import io
import json
import html
from datetime import datetime, timezone

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#65a30d",
}

SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _counts(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.get("severity", "LOW")] = counts.get(f.get("severity", "LOW"), 0) + 1
    return counts


def build_json_report(target, findings, meta):
    return json.dumps({
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "meta": meta,
        "findings_count": len(findings),
        "findings": findings,
    }, indent=2)


def build_html_report(target, findings, meta):
    counts = _counts(findings)

    rows = []
    for i, f in enumerate(findings):
        color = SEVERITY_COLORS.get(f["severity"], "#6b7280")
        files = "<br>".join(html.escape(s) for s in f.get("source_files", []))
        notes = "<br>".join(html.escape(n) for n in f.get("validation", {}).get("notes", []))
        value_display = html.escape(f["value"])
        if len(value_display) > 120:
            value_display = value_display[:120] + "…"
        search_blob = html.escape(" ".join([
            f["severity"], f["type"], f["category"], f["value"], " ".join(f.get("source_files", []))
        ]).lower())
        rows.append(f"""
        <tr class="row" data-search="{search_blob}" data-severity="{f['severity']}">
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td>{html.escape(f['type'])}</td>
          <td>{f['confidence']}</td>
          <td><code>{value_display}</code></td>
          <td class="small">{files}</td>
          <td class="small">{notes}</td>
        </tr>""")

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Mass PII Finder — Report for {html.escape(target)}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1117; color:#e5e7eb; margin:0; padding:32px; }}
  h1 {{ font-size:22px; margin-bottom:4px; }}
  .sub {{ color:#9ca3af; margin-bottom:24px; font-size:13px; }}
  .summary {{ display:flex; gap:12px; margin-bottom:20px; flex-wrap:wrap; }}
  .stat {{ background:#1a1d27; border-radius:10px; padding:14px 20px; min-width:100px; cursor:pointer; border:1px solid transparent; }}
  .stat.active {{ border-color:#4b5563; }}
  .stat .num {{ font-size:24px; font-weight:700; }}
  .stat .label {{ font-size:11px; color:#9ca3af; text-transform:uppercase; letter-spacing:0.05em; }}
  .toolbar {{ margin-bottom:16px; }}
  .toolbar input {{ width:100%; max-width:420px; padding:10px 12px; border-radius:8px; border:1px solid #2b2f3f; background:#1a1d27; color:#e5e7eb; font-size:13px; }}
  table {{ width:100%; border-collapse:collapse; background:#1a1d27; border-radius:10px; overflow:hidden; }}
  th {{ text-align:left; background:#232635; padding:10px 12px; font-size:11px; text-transform:uppercase; color:#9ca3af; }}
  td {{ padding:10px 12px; border-top:1px solid #2b2f3f; vertical-align:top; font-size:13px; }}
  .small {{ font-size:11px; color:#9ca3af; max-width:260px; word-break:break-all; }}
  code {{ background:#0f1117; padding:2px 6px; border-radius:4px; word-break:break-all; }}
  .badge {{ color:white; padding:2px 8px; border-radius:6px; font-size:11px; font-weight:600; }}
  .row.hidden {{ display:none; }}
</style></head>
<body>
  <h1>Mass PII / Secret Finder — Recon Report</h1>
  <div class="sub">Target: {html.escape(target)} &nbsp;•&nbsp; Generated {datetime.now(timezone.utc).isoformat()} &nbsp;•&nbsp;
    JS files scanned: {meta.get('js_file_count', '?')} &nbsp;•&nbsp; Sourcemaps found: {meta.get('sourcemap_count', '?')}
    {f" &nbsp;•&nbsp; Subdomains discovered: {meta.get('subdomain_count')}" if meta.get('subdomain_count') is not None else ""}</div>
  <div class="summary" id="stats">
    <div class="stat" data-filter="ALL"><div class="num">{len(findings)}</div><div class="label">All</div></div>
    <div class="stat" data-filter="CRITICAL"><div class="num" style="color:{SEVERITY_COLORS['CRITICAL']}">{counts['CRITICAL']}</div><div class="label">Critical</div></div>
    <div class="stat" data-filter="HIGH"><div class="num" style="color:{SEVERITY_COLORS['HIGH']}">{counts['HIGH']}</div><div class="label">High</div></div>
    <div class="stat" data-filter="MEDIUM"><div class="num" style="color:{SEVERITY_COLORS['MEDIUM']}">{counts['MEDIUM']}</div><div class="label">Medium</div></div>
    <div class="stat" data-filter="LOW"><div class="num" style="color:{SEVERITY_COLORS['LOW']}">{counts['LOW']}</div><div class="label">Low</div></div>
  </div>
  <div class="toolbar"><input id="search" type="text" placeholder="Filter by type, value, file, category..." /></div>
  <table>
    <tr><th>Severity</th><th>Type</th><th>Conf.</th><th>Value</th><th>Found in</th><th>Notes</th></tr>
    {''.join(rows) if rows else '<tr><td colspan="6">No findings.</td></tr>'}
  </table>
<script>
  let activeSeverity = "ALL";
  const rows = Array.from(document.querySelectorAll(".row"));
  const searchInput = document.getElementById("search");
  const stats = document.querySelectorAll(".stat");

  function applyFilter() {{
    const q = searchInput.value.trim().toLowerCase();
    rows.forEach(r => {{
      const matchesSeverity = activeSeverity === "ALL" || r.dataset.severity === activeSeverity;
      const matchesSearch = !q || r.dataset.search.includes(q);
      r.classList.toggle("hidden", !(matchesSeverity && matchesSearch));
    }});
  }}

  stats.forEach(s => s.addEventListener("click", () => {{
    activeSeverity = s.dataset.filter;
    stats.forEach(x => x.classList.remove("active"));
    s.classList.add("active");
    applyFilter();
  }}));
  searchInput.addEventListener("input", applyFilter);
</script>
</body></html>"""


def build_sarif_report(target, findings, meta, tool_name="mass-pii-finder", tool_version="2.0.0"):
    """SARIF 2.1.0 — importable by GitHub code scanning and most CI
    security dashboards, so findings show up as inline annotations."""
    rules = {}
    results = []
    for f in findings:
        rule_id = f["type"].replace(" ", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f["type"],
                "shortDescription": {"text": f["type"]},
                "properties": {"category": f["category"]},
            }
        locations = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": src}
                }
            }
            for src in f.get("source_files", [target])
        ] or [{"physicalLocation": {"artifactLocation": {"uri": target}}}]

        results.append({
            "ruleId": rule_id,
            "level": SARIF_LEVEL.get(f["severity"], "warning"),
            "message": {
                "text": f"{f['type']} (confidence {f['confidence']}): "
                        f"{f['value'][:80]}{'…' if len(f['value']) > 80 else ''}"
            },
            "locations": locations[:1],
            "properties": {
                "severity": f["severity"],
                "confidence": f["confidence"],
                "category": f["category"],
                "needs_manual_verification": f.get("needs_manual_verification", False),
            },
        })

    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://example.invalid/mass-pii-finder",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "properties": {"target": target, "meta": meta},
        }],
    }, indent=2)


def build_markdown_report(target, findings, meta):
    counts = _counts(findings)
    lines = [
        f"# Mass PII / Secret Finder — Report for `{target}`",
        "",
        f"_Generated {datetime.now(timezone.utc).isoformat()}_",
        "",
        f"- JS files scanned: **{meta.get('js_file_count', '?')}**",
        f"- Sourcemaps found: **{meta.get('sourcemap_count', '?')}**",
        f"- Findings: **{len(findings)}** "
        f"(Critical: {counts['CRITICAL']}, High: {counts['HIGH']}, Medium: {counts['MEDIUM']}, Low: {counts['LOW']})",
        "",
        "| Severity | Type | Conf. | Value (truncated) | Found in |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        value = f["value"].replace("|", "\\|").replace("\n", " ")
        if len(value) > 60:
            value = value[:60] + "…"
        files = "<br>".join(f.get("source_files", []))[:200]
        lines.append(f"| {f['severity']} | {f['type']} | {f['confidence']} | `{value}` | {files} |")

    if not findings:
        lines.append("| — | No findings | — | — | — |")

    return "\n".join(lines) + "\n"


def build_csv_report(target, findings, meta):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "target", "severity", "type", "category", "confidence", "value",
        "source_files", "needs_manual_verification", "notes",
    ])
    for f in findings:
        writer.writerow([
            target,
            f["severity"],
            f["type"],
            f["category"],
            f["confidence"],
            f["value"],
            ";".join(f.get("source_files", [])),
            f.get("needs_manual_verification", False),
            " | ".join(f.get("validation", {}).get("notes", [])),
        ])
    return buf.getvalue()


REPORT_BUILDERS = {
    "json": build_json_report,
    "html": build_html_report,
    "sarif": build_sarif_report,
    "markdown": build_markdown_report,
    "md": build_markdown_report,
    "csv": build_csv_report,
}
