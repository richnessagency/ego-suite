"""Tool registry, healthchecks, safe runners, and installers for EGO Suite."""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .config import BIN_DIR, NODE_BIN_DIR, VENV_BIN_DIR, load_selected_tools
from .normalizer import make_finding, parse_bandit_json, parse_nuclei_jsonl, parse_sarif


def _find_binary(name: str) -> str | None:
    """Locate a tool binary in portable dirs first, then system PATH."""
    for folder in (BIN_DIR, VENV_BIN_DIR, NODE_BIN_DIR):
        candidate = folder / name
        if candidate.exists() and os.access(candidate, os.X_OK):
            return str(candidate)
    return shutil.which(name)


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _docker_image_present(image: str) -> bool:
    if not _docker_available():
        return False
    res = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return res.returncode == 0


TOOL_SPECS: dict[str, dict[str, Any]] = {
    "ego-http-audit": {"bin": "builtin", "category": "DAST", "mode": "url", "builtin": True},
    "owasp-zap": {"bin": "zaproxy", "docker": "ghcr.io/zaproxy/zaproxy:stable", "category": "DAST", "mode": "url"},
    "nuclei": {"bin": "nuclei", "category": "DAST", "mode": "url"},
    "testssl": {"bin": "testssl.sh", "category": "DAST", "mode": "url"},
    "nikto": {"bin": "nikto", "category": "DAST", "mode": "url"},
    "nmap": {"bin": "nmap", "category": "DAST", "mode": "url"},
    "wapiti": {"bin": "wapiti", "category": "DAST", "mode": "url"},
    "httpx-headers": {"bin": "httpx", "category": "DAST", "mode": "url"},
    "semgrep": {"bin": "semgrep", "category": "SAST", "mode": "local"},
    "bandit": {"bin": "bandit", "category": "SAST", "mode": "local"},
    "eslint-security": {"bin": "eslint", "category": "SAST", "mode": "local"},
    "bearer": {"bin": "bearer", "category": "SAST", "mode": "local"},
    "sonarqube-scanner": {"bin": "sonar-scanner", "docker": "sonarqube:community", "category": "SAST", "mode": "local"},
    "trivy": {"bin": "trivy", "docker": "aquasec/trivy:latest", "category": "SCA", "mode": "local"},
    "osv-scanner": {"bin": "osv-scanner", "category": "SCA", "mode": "local"},
    "retirejs": {"bin": "retire", "category": "SCA", "mode": "both"},
    "pip-npm-audit": {"bin": "pip-audit", "category": "SCA", "mode": "local"},
    "gitleaks": {"bin": "gitleaks", "docker": "zricethezav/gitleaks:latest", "category": "Secrets", "mode": "local"},
    "trufflehog": {"bin": "trufflehog", "docker": "trufflesecurity/trufflehog:latest", "category": "Secrets", "mode": "local"},
    "checkov": {"bin": "checkov", "category": "IaC", "mode": "local"},
}


def get_tools_status() -> list[dict[str, Any]]:
    """Return all selected tools with live installation status."""
    selected = load_selected_tools()
    results: list[dict[str, Any]] = [
        {
            "id": "ego-http-audit",
            "name": "EGO Built-in HTTP & Security Headers Audit",
            "category": "DAST",
            "mode": "url",
            "installed": True,
            "runtime": "Built-in Python",
            "installCmd": "مدمج تلقائياً",
            "repoUrl": "",
        }
    ]
    for tool in selected:
        tid = tool["id"]
        spec = TOOL_SPECS.get(tid, {})
        bin_name = spec.get("bin", tid)
        bin_path = _find_binary(bin_name)
        docker_img = spec.get("docker")
        has_docker = bool(docker_img and _docker_image_present(docker_img))

        if tid == "testssl" and not bin_path:
            local_testssl = BIN_DIR / "testssl.sh" / "testssl.sh"
            if local_testssl.exists():
                bin_path = str(local_testssl)

        if tid == "nikto" and not bin_path:
            local_nikto = BIN_DIR / "nikto" / "program" / "nikto.pl"
            if local_nikto.exists():
                bin_path = str(local_nikto)

        installed = bool(bin_path or has_docker)
        runtime = bin_path if bin_path else (f"Docker ({docker_img})" if has_docker else "غير مثبت")
        results.append(
            {
                **tool,
                "installed": installed,
                "runtime": runtime,
            }
        )
    return results


def install_tool(tool_id: str) -> dict[str, Any]:
    """Install a single tool into EGO Suite's portable workspace."""
    pip_bin = str(VENV_BIN_DIR / "pip") if (VENV_BIN_DIR / "pip").exists() else "pip3"
    npm_bin = shutil.which("npm")

    pip_packages = {
        "semgrep": "semgrep",
        "bandit": "bandit",
        "wapiti": "wapiti3",
        "checkov": "checkov",
        "pip-npm-audit": "pip-audit",
    }
    if tool_id in pip_packages:
        proc = subprocess.run(
            [pip_bin, "install", "--quiet", pip_packages[tool_id]],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    if tool_id in ("eslint-security", "retirejs") and npm_bin:
        prefix = str(BIN_DIR.parent / ".node_tools")
        pkg = "retire" if tool_id == "retirejs" else "eslint eslint-plugin-security"
        proc = subprocess.run(
            f"{npm_bin} install --prefix {prefix} {pkg}",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    if tool_id == "testssl":
        dest = BIN_DIR / "testssl.sh"
        if dest.exists():
            return {"ok": True, "output": "testssl.sh already present"}
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    spec = TOOL_SPECS.get(tool_id, {})
    if spec.get("docker") and _docker_available():
        proc = subprocess.run(
            ["docker", "pull", spec["docker"]],
            capture_output=True,
            text=True,
            check=False,
        )
        return {"ok": proc.returncode == 0, "output": (proc.stdout + "\n" + proc.stderr).strip()}

    return {
        "ok": False,
        "output": f"Run ./ego-setup.sh or install '{tool_id}' manually for your OS ({platform.machine()}).",
    }


def run_builtin_http_audit(url: str) -> list[dict[str, Any]]:
    """Safe, read-only HTTP security headers & transport audit."""
    findings: list[dict[str, Any]] = []
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "http":
        findings.append(
            make_finding(
                title="Site uses unencrypted HTTP instead of HTTPS",
                severity="High",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description="الاتصال يتم عبر HTTP غير المشفر، مما يعرض البيانات والتوكنات للاعتراض.",
                remediation="قم بتفعيل HTTPS وإعادة توجيه كافة طلبات HTTP تلقائياً إلى HTTPS.",
            )
        )

    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "EGO-Suite-Auditor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.URLError as exc:
        findings.append(
            make_finding(
                title="Target URL unreachable during HTTP audit",
                severity="Info",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description=f"تعذر الوصول إلى الرابط: {exc.reason}",
                remediation="تأكد من أن الموقع يعمل ومتاح من الشبكة المحلية.",
            )
        )
        return findings

    required_headers = [
        ("strict-transport-security", "Missing HSTS Header (Strict-Transport-Security)", "Medium", "أضف ترويسة Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("content-security-policy", "Missing Content-Security-Policy (CSP)", "Medium", "أضف سياسة CSP لتقليل مخاطر هجمات XSS."),
        ("x-content-type-options", "Missing X-Content-Type-Options Header", "Low", "أضف X-Content-Type-Options: nosniff"),
        ("x-frame-options", "Missing X-Frame-Options / Clickjacking Protection", "Low", "أضف X-Frame-Options: DENY أو SAMEORIGIN (أو frame-ancestors في CSP)."),
        ("referrer-policy", "Missing Referrer-Policy Header", "Info", "أضف Referrer-Policy: strict-origin-when-cross-origin"),
    ]
    for h_key, title, sev, fix in required_headers:
        if h_key not in headers:
            findings.append(
                make_finding(
                    title=title,
                    severity=sev,
                    category="DAST",
                    source_tool="ego-http-audit",
                    location=url,
                    description=f"الترويسة الأمنية `{h_key}` غير موجودة في استجابة الخادم.",
                    remediation=fix,
                )
            )

    if headers.get("access-control-allow-origin") == "*":
        findings.append(
            make_finding(
                title="Wildcard CORS Policy (Access-Control-Allow-Origin: *)",
                severity="Medium",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description="الخادم يسمح بالوصول عبر CORS من أي نطاق خارجي.",
                remediation="قصر Access-Control-Allow-Origin على النطاقات الموثوقة فقط.",
            )
        )

    if "server" in headers or "x-powered-by" in headers:
        disclosed = ", ".join(f"{k}: {headers[k]}" for k in ("server", "x-powered-by") if k in headers)
        findings.append(
            make_finding(
                title="Server Technology Banner Disclosed",
                severity="Info",
                category="DAST",
                source_tool="ego-http-audit",
                location=url,
                description=f"يكشف الخادم عن تفاصيل التقنية المستخدمة ({disclosed}).",
                remediation="أخفِ ترويسة X-Powered-By وقلّل تفاصيل Server في إعدادات الخادم.",
            )
        )

    return findings


def execute_tool(tool_id: str, target_url: str, local_path: str) -> tuple[list[dict[str, Any]], str]:
    """Run an individual tool safely and return (findings, status_note)."""
    if tool_id == "ego-http-audit":
        if not target_url:
            return [], "skipped (no URL)"
        return run_builtin_http_audit(target_url), "ok"

    with tempfile.TemporaryDirectory(prefix="ego_") as tmp:
        out_file = Path(tmp) / "output.sarif"

        if tool_id == "semgrep" and local_path:
            bin_p = _find_binary("semgrep")
            if not bin_p:
                return [], "not installed"
            subprocess.run(
                [bin_p, "scan", "--config", "auto", "--sarif", "-o", str(out_file), local_path],
                capture_output=True,
                timeout=180,
                check=False,
            )
            return parse_sarif(out_file, "Semgrep", "SAST"), "ok"

        if tool_id == "bandit" and local_path:
            bin_p = _find_binary("bandit")
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "bandit.json"
            subprocess.run(
                [bin_p, "-r", local_path, "-f", "json", "-o", str(json_out), "-q"],
                capture_output=True,
                timeout=120,
                check=False,
            )
            return parse_bandit_json(json_out), "ok"

        if tool_id == "trivy" and local_path:
            bin_p = _find_binary("trivy")
            if bin_p:
                subprocess.run(
                    [bin_p, "fs", "--format", "sarif", "-o", str(out_file), local_path],
                    capture_output=True,
                    timeout=180,
                    check=False,
                )
                return parse_sarif(out_file, "Trivy", "SCA"), "ok"
            return [], "not installed"

        if tool_id == "gitleaks" and local_path:
            bin_p = _find_binary("gitleaks")
            if bin_p:
                subprocess.run(
                    [bin_p, "detect", "--source", local_path, "--no-git", "--report-format", "sarif", "--report-path", str(out_file)],
                    capture_output=True,
                    timeout=120,
                    check=False,
                )
                return parse_sarif(out_file, "Gitleaks", "Secrets"), "ok"
            return [], "not installed"

        if tool_id == "checkov" and local_path:
            bin_p = _find_binary("checkov")
            if not bin_p:
                return [], "not installed"
            subprocess.run(
                [bin_p, "-d", local_path, "-o", "sarif", "--output-file-path", tmp, "--quiet"],
                capture_output=True,
                timeout=180,
                check=False,
            )
            sarif_files = list(Path(tmp).glob("*.sarif"))
            return (parse_sarif(sarif_files[0], "Checkov", "IaC"), "ok") if sarif_files else ([], "ok")

        if tool_id == "nuclei" and target_url:
            bin_p = _find_binary("nuclei")
            if not bin_p:
                return [], "not installed"
            jsonl_out = Path(tmp) / "nuclei.jsonl"
            subprocess.run(
                [bin_p, "-u", target_url, "-etags", "dos,fuzz", "-rl", "20", "-jsonl", "-o", str(jsonl_out), "-silent"],
                capture_output=True,
                timeout=240,
                check=False,
            )
            return parse_nuclei_jsonl(jsonl_out), "ok"

        if tool_id == "nmap" and target_url:
            bin_p = _find_binary("nmap")
            if not bin_p:
                return [], "not installed"
            host = urllib.parse.urlparse(target_url).hostname or target_url
            proc = subprocess.run(
                [bin_p, "-F", "--open", host],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            findings = []
            for line in proc.stdout.splitlines():
                if "/tcp" in line and "open" in line:
                    findings.append(
                        make_finding(
                            title=f"Open Port Detected: {line.strip()}",
                            severity="Info",
                            category="DAST",
                            source_tool="Nmap",
                            location=host,
                            description=f"تم رصد منفذ مفتوح على الخادم: {line.strip()}",
                            remediation="تأكد من أن هذه الخدمة مطلوبة للعامة، وأغلق المنافذ غير الضرورية عبر الجدار الناري.",
                        )
                    )
            return findings, "ok"

        if tool_id == "wapiti" and target_url:
            bin_p = _find_binary("wapiti")
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "wapiti.json"
            subprocess.run(
                [bin_p, "-u", target_url, "-f", "json", "-o", str(json_out), "--max-scan-time", "60", "--flush-session"],
                capture_output=True,
                timeout=90,
                check=False,
            )
            if not json_out.exists():
                return [], "ok"
            try:
                wdata = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return [], "ok"
            findings = []
            for cat_name, items in (wdata.get("vulnerabilities") or {}).items():
                for item in items or []:
                    findings.append(
                        make_finding(
                            title=cat_name,
                            severity="Medium" if item.get("level", 1) <= 2 else "High",
                            category="DAST",
                            source_tool="Wapiti",
                            location=item.get("path", target_url),
                            description=item.get("info", cat_name),
                            remediation="راجع تفاصيل الثغرة في Wapiti وأغلق نقطة الإدخال أو الإعداد غير الآمن.",
                        )
                    )
            return findings, "ok"

        if tool_id == "testssl" and target_url:
            bin_p = _find_binary("testssl.sh")
            if not bin_p:
                local_t = BIN_DIR / "testssl.sh" / "testssl.sh"
                bin_p = str(local_t) if local_t.exists() else None
            if not bin_p:
                return [], "not installed"
            json_out = Path(tmp) / "testssl.json"
            subprocess.run(
                [bin_p, "--quiet", "--fast", "--jsonfile", str(json_out), target_url],
                capture_output=True,
                timeout=120,
                check=False,
            )
            if not json_out.exists():
                return [], "ok"
            try:
                tdata = json.loads(json_out.read_text(encoding="utf-8", errors="replace"))
            except json.JSONDecodeError:
                return [], "ok"
            findings = []
            for item in tdata if isinstance(tdata, list) else []:
                sev = str(item.get("severity", "INFO")).upper()
                if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    findings.append(
                        make_finding(
                            title=f"TLS/SSL: {item.get('id', 'Issue')}",
                            severity=sev.title(),
                            category="DAST",
                            source_tool="testssl.sh",
                            location=target_url,
                            description=item.get("finding", ""),
                            remediation="حدّث إعدادات TLS/SSL لإلغاء البروتوكولات والتشفير الضعيف.",
                        )
                    )
            return findings, "ok"

        if tool_id == "pip-npm-audit" and local_path:
            bin_p = _find_binary("pip-audit")
            req_file = Path(local_path) / "requirements.txt"
            if bin_p and req_file.exists():
                proc = subprocess.run(
                    [bin_p, "-r", str(req_file), "-f", "json"],
                    capture_output=True,
                    text=True,
                    timeout=90,
                    check=False,
                )
                try:
                    pdata = json.loads(proc.stdout or "{}")
                except json.JSONDecodeError:
                    pdata = {}
                findings = []
                for dep in pdata.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        findings.append(
                            make_finding(
                                title=f"{dep.get('name')} ({vuln.get('id')})",
                                severity="High",
                                category="SCA",
                                source_tool="pip-audit",
                                location=str(req_file),
                                description=vuln.get("description", ""),
                                remediation=f"Fix versions: {', '.join(vuln.get('fix_versions', []))}",
                            )
                        )
                return findings, "ok"
            return [], "skipped (no requirements.txt)"

        if tool_id == "retirejs" and (local_path or target_url):
            bin_p = _find_binary("retire")
            if not bin_p or not local_path:
                return [], "skipped"
            proc = subprocess.run(
                [bin_p, "--path", local_path, "--outputformat", "json"],
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
            try:
                rdata = json.loads(proc.stdout or "{}")
            except json.JSONDecodeError:
                rdata = {}
            findings = []
            for entry in rdata.get("data", []):
                for res in entry.get("results", []):
                    for v in res.get("vulnerabilities", []):
                        findings.append(
                            make_finding(
                                title=f"Outdated JS: {res.get('component')} {res.get('version')}",
                                severity=v.get("severity", "Medium"),
                                category="SCA",
                                source_tool="Retire.js",
                                location=entry.get("file", local_path),
                                description=v.get("identifiers", {}).get("summary", "Vulnerable JS library"),
                                remediation="قم بترقية مكتبة JavaScript إلى أحدث إصدار آمن.",
                            )
                        )
            return findings, "ok"

    return [], "skipped or not installed"

