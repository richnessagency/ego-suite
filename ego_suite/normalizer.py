"""Normalize SARIF, JSON, and tool-specific outputs into Unified Findings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SEVERITY_MAP = {
    "critical": "Critical",
    "error": "High",
    "high": "High",
    "warning": "Medium",
    "medium": "Medium",
    "note": "Low",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}


def compute_fingerprint(source_tool: str, title: str, location: str) -> str:
    raw = f"{source_tool.lower()}::{title.strip().lower()}::{location.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def normalize_severity(raw: str | None) -> str:
    if not raw:
        return "Medium"
    return SEVERITY_MAP.get(str(raw).strip().lower(), "Medium")


def make_finding(
    title: str,
    severity: str,
    category: str,
    source_tool: str,
    location: str,
    description: str,
    remediation: str = "",
) -> dict[str, Any]:
    sev = normalize_severity(severity)
    return {
        "fingerprint": compute_fingerprint(source_tool, title, location),
        "title": title.strip()[:240],
        "severity": sev,
        "category": category,
        "source_tool": source_tool,
        "location": location.strip()[:300] or "N/A",
        "description": description.strip()[:1200],
        "remediation": remediation.strip()[:800],
    }


def parse_sarif(path: Path, source_tool: str, category: str) -> list[dict[str, Any]]:
    """Parse standard SARIF v2.1.0 output produced by Semgrep, Trivy, Gitleaks, Checkov, etc."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    findings: list[dict[str, Any]] = []
    for run in data.get("runs", []):
        rules = {
            r.get("id", ""): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "Security Issue")
            rule = rules.get(rule_id, {})
            level = res.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
            props = rule.get("properties", {})
            sev = props.get("security-severity") or props.get("severity") or level
            if isinstance(sev, (int, float)) or (isinstance(sev, str) and sev.replace(".", "", 1).isdigit()):
                score = float(sev)
                sev = "Critical" if score >= 9.0 else "High" if score >= 7.0 else "Medium" if score >= 4.0 else "Low"

            msg = res.get("message", {}).get("text") or rule.get("shortDescription", {}).get("text") or rule_id
            locs = res.get("locations", [])
            loc_str = "Project Root"
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", "")
                loc_str = f"{uri}:{line}" if line else uri

            help_text = rule.get("help", {}).get("text", "")
            findings.append(
                make_finding(
                    title=f"[{rule_id}] {msg[:120]}",
                    severity=str(sev),
                    category=category,
                    source_tool=source_tool,
                    location=loc_str,
                    description=msg,
                    remediation=help_text,
                )
            )
    return findings


def parse_bandit_json(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return []

    findings: list[dict[str, Any]] = []
    for item in data.get("results", []):
        loc = f"{item.get('filename', '')}:{item.get('line_number', '')}"
        findings.append(
            make_finding(
                title=f"[{item.get('test_id', 'Bandit')}] {item.get('test_name', 'Issue')}",
                severity=item.get("issue_severity", "Medium"),
                category="SAST",
                source_tool="Bandit",
                location=loc,
                description=item.get("issue_text", ""),
                remediation=item.get("more_info", ""),
            )
        )
    return findings


def parse_nuclei_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    findings: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info", {})
        findings.append(
            make_finding(
                title=info.get("name", obj.get("template-id", "Nuclei Finding")),
                severity=info.get("severity", "Info"),
                category="DAST",
                source_tool="Nuclei",
                location=obj.get("matched-at", obj.get("host", "")),
                description=info.get("description", f"Template: {obj.get('template-id', '')}"),
                remediation=info.get("remediation", ""),
            )
        )
    return findings

