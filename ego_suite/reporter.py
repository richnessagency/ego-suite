"""Consolidated HTML and Markdown report generator for EGO Suite."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .config import REPORTS_DIR, ensure_directories
from .db import get_scan_detail


def generate_reports(scan_id: int) -> tuple[Path, Path] | None:
    """Generate consolidated HTML and Markdown reports for a scan."""
    ensure_directories()
    detail = get_scan_detail(scan_id)
    if not detail:
        return None

    scan = detail["scan"]
    findings = detail["findings"]
    summary = json.loads(scan.get("summary_json") or "{}")

    md_lines = [
        f"# EGO Suite — تقرير الفحص الأمني المجمع (#{scan_id})",
        f"- **المشروع:** {scan['project_name']}",
        f"- **الرابط:** {scan['target_url'] or 'غير محدد'}",
        f"- **المسار المحلي:** {scan['local_path'] or 'غير محدد'}",
        f"- **الوضع:** {scan['mode']} | **الحالة:** {scan['status']}",
        f"- **إجمالي النتائج:** {summary.get('total', len(findings))} | **جديدة:** {summary.get('new', 0)} | **تم حلها منذ آخر فحص:** {summary.get('fixed', 0)}",
        "",
        "## قائمة المشاكل المرصودة",
    ]
    for idx, f in enumerate(findings, 1):
        md_lines.extend(
            [
                f"### {idx}. [{f['severity']}] {f['title']}",
                f"- **الأداة:** {f['source_tool']} ({f['category']}) | **الحالة:** {f['status']}",
                f"- **الموقع:** `{f['location']}`",
                f"- **الوصف:** {f['description']}",
                f"- **الحل المقترح:** {f['remediation'] or 'راجع توثيق الأداة.'}",
                "",
            ]
        )

    md_path = REPORTS_DIR / f"ego-report-{scan_id}.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    rows_html = "\n".join(
        f"<tr>"
        f"<td><span class='sev sev-{html.escape(f['severity'].lower())}'>{html.escape(f['severity'])}</span></td>"
        f"<td>{html.escape(f['title'])}</td>"
        f"<td>{html.escape(f['source_tool'])}</td>"
        f"<td><code>{html.escape(f['location'])}</code></td>"
        f"<td>{html.escape(f['status'])}</td>"
        f"</tr>"
        for f in findings
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="UTF-8">
  <title>EGO Suite Report #{scan_id}</title>
  <style>
    body {{ background:#09090B; color:#FAFAFA; font-family:system-ui,sans-serif; margin:2rem; line-height:1.6; }}
    h1 {{ color:#FACC15; border-bottom:2px solid #27272F; padding-bottom:.5rem; }}
    .meta {{ background:#121216; border:1px solid #27272F; padding:1rem; border-radius:8px; margin-bottom:1.5rem; }}
    table {{ width:100%; border-collapse:collapse; background:#121216; }}
    th, td {{ border:1px solid #27272F; padding:.65rem; text-align:right; font-size:.9rem; }}
    th {{ background:#18181D; color:#FACC15; }}
    .sev {{ padding:.2rem .5rem; border-radius:4px; font-weight:700; font-size:.8rem; }}
    .sev-critical {{ background:#EF4444; color:#fff; }}
    .sev-high {{ background:#F97316; color:#09090B; }}
    .sev-medium {{ background:#FACC15; color:#09090B; }}
    .sev-low {{ background:#38BDF8; color:#09090B; }}
    .sev-info {{ background:#52525B; color:#fff; }}
  </style>
</head>
<body>
  <h1>EGO Suite — التقرير الأمني المجمع (#{scan_id})</h1>
  <div class="meta">
    <strong>المشروع:</strong> {html.escape(scan['project_name'])} |
    <strong>الرابط:</strong> {html.escape(scan['target_url'] or '-')} |
    <strong>المسار المحلي:</strong> {html.escape(scan['local_path'] or '-')} |
    <strong>إجمالي النتائج:</strong> {len(findings)} |
    <strong>تم حلها:</strong> {summary.get('fixed', 0)}
  </div>
  <table>
    <thead><tr><th>الخطورة</th><th>المشكلة</th><th>الأداة</th><th>الموقع</th><th>الحالة</th></tr></thead>
    <tbody>{rows_html or '<tr><td colspan="5">لا توجد ثغرات مرصودة.</td></tr>'}</tbody>
  </table>
</body>
</html>"""

    html_path = REPORTS_DIR / f"ego-report-{scan_id}.html"
    html_path.write_text(html_doc, encoding="utf-8")
    return html_path, md_path

