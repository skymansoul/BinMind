# 报告格式化器 — JSON/Text/Markdown/HTML/SARIF 2.1.0
# 不拆: 所有输出格式集中管理
import json
from typing import List, Dict, Any, Optional  # 不拆: Optional 以后可能加 metadata

from .core.models import VulnerabilityReport

_SEV_COLORS = {
  "CRITICAL": "#d73a4a",
  "HIGH": "#cf222e",
  "MEDIUM": "#bf8700",
  "LOW": "#6a737d",
  "INFO": "#0366d6",
}


class ReportFormatter:
  """漏洞报告格式化器 — 支持 JSON/Text/Markdown/HTML/SARIF。"""

  def __init__(self, findings: List[VulnerabilityReport], contract_name: str = ""):
    self.findings = findings
    self.name = contract_name or "smart_contract"

  def to_json(self) -> str:
    """JSON output — machine-readable, one object per finding."""
    return json.dumps([{
      "type": f.vuln_type,
      "severity": f.severity,
      "confidence": f.confidence,
      "swc": f.swc_id,
      "description": f.description,
      "location": hex(f.location) if f.location else "",
      "opcode": f.opcode,
      "recommendation": f.recommendation,
      "affected_pcs": f.affected_pcs,
      "evidence": f.evidence,
    } for f in self.findings], indent=2)

  def to_text(self) -> str:
    """Plain text report — grouped by severity."""
    lines = [f"Smart Contract Analysis: {self.name}", "=" * 50]
    by_sev: Dict[str, list] = {
      "CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []
    }
    for f in self.findings:
      sev = f.severity if f.severity in by_sev else "INFO"
      by_sev[sev].append(f)

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
      group = by_sev[sev]
      if group:
        lines.append(f"\n[{sev}] ({len(group)} findings)")
        for f in group:
          lines.append(
            f"  - {f.vuln_type} (conf={f.confidence:.0%}): {f.description}"
          )

    lines.append(f"\nTotal: {len(self.findings)} findings")
    return "\n".join(lines)

  def to_markdown(self) -> str:
    """Markdown table — sorted by confidence descending."""
    lines = [
      f"# Smart Contract Analysis: `{self.name}`",
      "",
      "| Severity | Type | Confidence | SWC | Description |",
      "|----------|------|------------|-----|-------------|",
    ]
    sorted_findings = sorted(self.findings, key=lambda x: -x.confidence)
    for f in sorted_findings:
      lines.append(
        f"| {f.severity} | {f.vuln_type} | {f.confidence:.0%} "
        f"| {f.swc_id} | {f.description} |"
      )
    return "\n".join(lines)

  def to_html(self) -> str:
    """HTML table with severity color coding."""
    rows = ""
    sorted_findings = sorted(self.findings, key=lambda x: -x.confidence)
    for f in sorted_findings:
      color = _SEV_COLORS.get(f.severity, "#333")
      rows += (
        f'<tr><td style="color:{color};font-weight:bold">{f.severity}</td>'
        f'<td>{f.vuln_type}</td><td>{f.confidence:.0%}</td>'
        f'<td>{f.swc_id}</td><td>{f.description}</td></tr>'
      )
    return (
      f'<!DOCTYPE html><html><head><meta charset="utf-8">\n'
      f'<title>Smart Contract Analysis: {self.name}</title></head>\n'
      f'<body><h1>Analysis: <code>{self.name}</code></h1>\n'
      f'<table border="1" cellpadding="6" cellspacing="0">\n'
      f'<tr><th>Severity</th><th>Type</th><th>Confidence</th>'
      f'<th>SWC</th><th>Description</th></tr>\n'
      f'{rows}</table>\n'
      f'<p>Total: {len(self.findings)} findings</p></body></html>'
    )

  def to_sarif(self) -> str:
    """SARIF v2.1.0 — GitHub Code Scanning compatible."""
    results: List[Dict[str, Any]] = []
    for f in self.findings:
      level = (
        "error" if f.severity in ("CRITICAL", "HIGH")
        else "warning" if f.severity == "MEDIUM"
        else "note"
      )
      locations: List[Dict[str, Any]] = []
      for pc in (f.affected_pcs[:1] or [f.location]):
        regions: Dict[str, Any] = {}
        if isinstance(pc, int) and pc >= 0:
          regions["byteOffset"] = pc
        locations.append({
          "physicalLocation": {
            "artifactLocation": {"uri": f"{self.name}.sol"},
            "region": regions,
          }
        })
      if not locations:
        locations = [{
          "physicalLocation": {
            "artifactLocation": {"uri": f"{self.name}.sol"}
          }
        }]
      results.append({
        "ruleId": f"BINMIND-{f.vuln_type.upper()}",
        "level": level,
        "message": {"text": f.description},
        "locations": locations,
        "properties": {
          "confidence": f.confidence,
          "swc": f.swc_id,
        },
      })

    sarif = {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [{
        "tool": {
          "driver": {
            "name": "BinMind",
            "version": "1.0"
          }
        },
        "results": results,
      }],
    }
    return json.dumps(sarif, indent=2)
