# 2026-07-30
# Report formatter — JSON/Text/Markdown/HTML/SARIF 2.1.0
import json
from typing import List
from .detectors import VulnFinding

_SEV_COLORS = {"CRITICAL": "#d73a4a", "HIGH": "#cf222e", "MEDIUM": "#bf8700",
               "LOW": "#6a737d", "INFO": "#0366d6"}


class ReportFormatter:
    def __init__(self, findings: List[VulnFinding], contract_name: str = ""):
        self.findings = findings
        self.name = contract_name or "smart_contract"

    def to_json(self) -> str:
        return json.dumps([{
            "type": f.vuln_type, "severity": f.severity, "confidence": f.confidence,
            "swc": f.swc_id, "description": f.description,
            "affected_pcs": f.affected_pcs, "evidence": f.evidence,
        } for f in self.findings], indent=2)

    def to_text(self) -> str:
        lines = [f"Smart Contract Analysis: {self.name}", "=" * 50]
        by_sev = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for f in self.findings:
            by_sev.setdefault(f.severity, []).append(f)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            group = by_sev[sev]
            if group:
                lines.append(f"\n[{sev}] ({len(group)} findings)")
                for f in group:
                    lines.append(f"  - {f.vuln_type} (conf={f.confidence:.0%}): {f.description}")
        lines.append(f"\nTotal: {len(self.findings)} findings")
        return "\n".join(lines)

    def to_markdown(self) -> str:
        lines = [f"# Smart Contract Analysis: `{self.name}`", "",
                 "| Severity | Type | Confidence | SWC | Description |",
                 "|----------|------|------------|-----|-------------|"]
        for f in sorted(self.findings, key=lambda x: -x.confidence):
            lines.append(f"| {f.severity} | {f.vuln_type} | {f.confidence:.0%} | {f.swc_id} | {f.description} |")
        return "\n".join(lines)

    def to_html(self) -> str:
        rows = ""
        for f in sorted(self.findings, key=lambda x: -x.confidence):
            color = _SEV_COLORS.get(f.severity, "#333")
            rows += (f'<tr><td style="color:{color};font-weight:bold">{f.severity}</td>'
                     f'<td>{f.vuln_type}</td><td>{f.confidence:.0%}</td>'
                     f'<td>{f.swc_id}</td><td>{f.description}</td></tr>')
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Smart Contract Analysis: {self.name}</title></head>
<body><h1>Analysis: <code>{self.name}</code></h1>
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>Severity</th><th>Type</th><th>Confidence</th><th>SWC</th><th>Description</th></tr>
{rows}</table><p>Total: {len(self.findings)} findings</p></body></html>"""

    def to_sarif(self) -> str:
        """SARIF v2.1.0 — GitHub Code Scanning 兼容。"""
        results = []
        for f in self.findings:
            results.append({
                "ruleId": f"BINMIND-{f.vuln_type.upper()}",
                "level": "error" if f.severity in ("CRITICAL", "HIGH") else
                         "warning" if f.severity == "MEDIUM" else "note",
                "message": {"text": f.description},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f"{self.name}.sol"},
                    "region": {"byteOffset": pc}
                }} for pc in f.affected_pcs[:1]] or [{"physicalLocation": {
                    "artifactLocation": {"uri": f"{self.name}.sol"}
                }}],
                "properties": {"confidence": f.confidence, "swc": f.swc_id},
            })
        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "BinMind", "version": "1.0"}},
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)
