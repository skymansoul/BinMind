# 2026-07-30
# 报告格式化器 — JSON/Text/Markdown/HTML/SARIF 2.1.0/CSV/JUnit XML
# 2026-07 新增: HexGraph 风格类型化发现图 + 发现去重

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    title: str; description: str; severity: str
    location: str; recommendation: str = ""
    cve_id: Optional[str] = None
    assurance_level: str = "code_present"  # HexGraph 风格: code_present / input_reachable / static / dynamic


@dataclass
class SummaryStats:
    total: int = 0; critical: int = 0; high: int = 0
    medium: int = 0; low: int = 0; info: int = 0


class ReportFormatter:
    """多格式报告生成器 — JSON/Plaintext/Markdown/HTML/SARIF 2.1.0/CSV/JUnit"""

    FORMATS = {"json", "text", "markdown", "html", "sarif", "csv", "junit"}

    def _generate_report(self, findings: list, metadata: dict, fmt: str) -> str:
        _dispatch = {
            "json": self.format_json, "text": self.format_text,
            "markdown": self.format_markdown, "html": self.format_html,
            "sarif": self.format_sarif, "csv": self.format_csv,
            "junit": self.format_junit,
        }
        _fn = _dispatch.get(fmt)
        if not _fn:
            raise ValueError(f"Unsupported format: {fmt}. Use: {self.FORMATS}")
        return _fn(findings, metadata)

    # 发现去重: 按 (title, location) 作为近似 key。保留最高严重级别的条目。
    def _dedup(self, findings: list) -> list:
        seen = {}
        for f in findings:
            if isinstance(f, dict):
                key = (f.get("title", f.get("finding", "")),
                       f.get("location", f.get("bootloader", "")))
            elif isinstance(f, Finding):
                key = (f.title, f.location)
            else:
                continue
            sev = (f.get("severity", "INFO") if isinstance(f, dict) else f.severity).upper()
            sev_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
            if key not in seen or sev_order.get(sev, 0) > sev_order.get(seen[key][1], 0):
                seen[key] = (f, sev)
        return [v[0] for v in seen.values()]

    def format_json(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _out = {
            "schema_version": "1.1.0",
            "metadata": metadata,
            "summary": self._compute_summary(findings),
            "findings": [self._finding_to_dict(f) for f in findings if isinstance(f, Finding)],
            "raw_findings": [f for f in findings if isinstance(f, dict)],
            "assurance_map": self._assurance_summary(findings),
        }
        return json.dumps(_out, indent=2, ensure_ascii=False)

    def _assurance_summary(self, findings: list) -> dict:
        counts = {"code_present": 0, "input_reachable": 0, "static": 0, "dynamic": 0}
        for f in findings:
            lvl = f.assurance_level if isinstance(f, Finding) else f.get("assurance_level", "code_present")
            counts[lvl] = counts.get(lvl, 0) + 1
        return counts

    def format_text(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _stats = self._compute_summary(findings)
        _lines = []
        _lines.append("=" * 60)
        _lines.append("  固 件 安 全 审 计 报 告")
        _lines.append("=" * 60)
        _lines.append("")
        for _k, _v in metadata.items():
            _lines.append(f"  {_k}: {_v}")
        _lines.append("")
        _lines.append("-" * 40)
        _lines.append("  严重级别分布")
        _lines.append("-" * 40)
        for _name, _cnt in [("CRITICAL", _stats["critical"]), ("HIGH", _stats["high"]),
                             ("MEDIUM", _stats["medium"]), ("LOW", _stats["low"]),
                             ("INFO", _stats["info"])]:
            _lines.append(f"  {_name:>8}: {_cnt}")
        _lines.append(f"  {'TOTAL':>8}: {_stats['total']}")
        _lines.append("")
        for _i, _f in enumerate(findings, 1):
            if isinstance(_f, dict):
                _lines.append(f"[{_i}] {_f.get('title', _f.get('finding', 'Unknown'))}")
                _lines.append(f"    严重级别: {_f.get('severity', 'N/A')}")
                if _f.get("cve_id"):
                    _lines.append(f"    CVE: {_f['cve_id']}")
                _lines.append(f"    描述: {_f.get('description', _f.get('finding', ''))}")
                _lines.append("")
            elif isinstance(_f, Finding):
                _lines.append(f"[{_i}] {_f.title}")
                _lines.append(f"    严重级别: {_f.severity}")
                _lines.append(f"    位置: {_f.location}")
                _lines.append(f"    描述: {_f.description}")
                if _f.cve_id:
                    _lines.append(f"    CVE: {_f.cve_id}")
                if _f.recommendation:
                    _lines.append(f"    建议: {_f.recommendation}")
                _lines.append(f"    确认度: {_f.assurance_level}")
                _lines.append("")
        return "\n".join(_lines)

    def format_markdown(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _stats = self._compute_summary(findings)
        _lines = ["# 固件安全审计报告", "", "## 元数据", "",
                  "| 项目 | 值 |", "|------|-----|"]
        for _k, _v in metadata.items():
            _lines.append(f"| {_k} | {_v} |")
        _lines.extend(["", "## 严重级别分布", "",
                       "| 级别 | 数量 |", "|------|------|",
                       f"| CRITICAL | {_stats['critical']} |",
                       f"| HIGH | {_stats['high']} |",
                       f"| MEDIUM | {_stats['medium']} |",
                       f"| LOW | {_stats['low']} |",
                       f"| INFO | {_stats['info']} |",
                       f"| **TOTAL** | **{_stats['total']}** |",
                       "", "## 发现详情", "",
                       "| # | 标题 | 级别 | 位置 | CVE | 确认度 |",
                       "|---|------|------|------|-----|--------|"])
        for _i, _f in enumerate(findings, 1):
            if isinstance(_f, dict):
                _title = _f.get("title", _f.get("finding", "N/A"))[:50]
                _sev = _f.get("severity", "N/A")
                _loc = _f.get("location", _f.get("bootloader", "-"))
                _cve = _f.get("cve_id", "-")
                _al = _f.get("assurance_level", "code_present")
                _lines.append(f"| {_i} | {_title} | {_sev} | {_loc} | {_cve} | {_al} |")
            elif isinstance(_f, Finding):
                _lines.append(f"| {_i} | {_f.title[:50]} | {_f.severity} | {_f.location} | {_f.cve_id or '-'} | {_f.assurance_level} |")
        return "\n".join(_lines)

    def format_html(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _stats = self._compute_summary(findings)
        _finding_rows = []
        for _i, _f in enumerate(findings, 1):
            if isinstance(_f, dict):
                _title = _f.get("title", _f.get("finding", "N/A"))
                _sev = _f.get("severity", "N/A")
                _desc = _f.get("description", _f.get("finding", ""))
                _loc = _f.get("location", _f.get("bootloader", "-"))
                _cve = _f.get("cve_id", "")
                _al = _f.get("assurance_level", "code_present")
                _finding_rows.append(f"""<tr>
              <td>{_i}</td><td><span class="badge badge-{_sev.lower()}">{_sev}</span></td>
              <td><strong>{self._esc(_title)}</strong></td><td>{self._esc(_loc)}</td>
              <td>{self._esc(_desc[:120])}</td><td>{self._esc(_cve)}</td>
              <td>{self._esc(_al)}</td></tr>""")
            elif isinstance(_f, Finding):
                _finding_rows.append(f"""<tr>
              <td>{_i}</td><td><span class="badge badge-{_f.severity.lower()}">{_f.severity}</span></td>
              <td><strong>{self._esc(_f.title)}</strong></td><td>{self._esc(_f.location)}</td>
              <td>{self._esc(_f.description[:120])}</td><td>{self._esc(_f.cve_id or '')}</td>
              <td>{self._esc(_f.assurance_level)}</td></tr>""")
        return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<title>固件安全审计报告</title><style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#1a1a2e;color:#e0e0e0;font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
.container{{max-width:1200px;margin:0 auto}}
h1{{color:#e94560;margin-bottom:1rem;font-size:1.8rem}}
h2{{color:#0f3460;background:#16213e;padding:.5rem 1rem;border-radius:4px;margin:1.5rem 0 1rem}}
.summary-grid{{display:grid;grid-template-columns:repeat(6,1fr);gap:1rem;margin:1rem 0}}
.stat-card{{background:#16213e;border-radius:8px;padding:1rem;text-align:center}}
.stat-card .count{{font-size:2rem;font-weight:bold;display:block}}
.stat-card .label{{font-size:.8rem;color:#a0a0a0}}
.stat-card.critical .count{{color:#dc3545}}.stat-card.high .count{{color:#fd7e14}}
.stat-card.medium .count{{color:#ffc107}}.stat-card.low .count{{color:#0dcaf0}}
.stat-card.info .count{{color:#6c757d}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th{{background:#0f3460;color:#e0e0e0;padding:.6rem;text-align:left;font-size:.85rem}}
td{{padding:.5rem .6rem;border-bottom:1px solid #16213e;font-size:.85rem}}
tr:hover{{background:#16213e}}
.badge{{display:inline-block;padding:.15rem .5rem;border-radius:3px;font-size:.75rem;font-weight:bold;text-transform:uppercase}}
.badge-critical{{background:#dc3545;color:white}}.badge-high{{background:#fd7e14;color:white}}
.badge-medium{{background:#ffc107;color:black}}.badge-low{{background:#0dcaf0;color:black}}
.badge-info{{background:#6c757d;color:white}}
.meta-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.5rem}}
.meta-item{{background:#16213e;padding:.5rem 1rem;border-radius:4px}}
.meta-item .key{{font-size:.75rem;color:#a0a0a0}}
</style></head><body><div class="container">
<h1>固件安全审计报告</h1><h2>元数据</h2><div class="meta-grid">
{''.join(f'<div class="meta-item"><span class="key">{self._esc(k)}</span><br>{self._esc(str(v))}</div>' for k,v in metadata.items())}
</div><h2>严重级别分布</h2><div class="summary-grid">
<div class="stat-card critical"><span class="count">{_stats['critical']}</span><span class="label">CRITICAL</span></div>
<div class="stat-card high"><span class="count">{_stats['high']}</span><span class="label">HIGH</span></div>
<div class="stat-card medium"><span class="count">{_stats['medium']}</span><span class="label">MEDIUM</span></div>
<div class="stat-card low"><span class="count">{_stats['low']}</span><span class="label">LOW</span></div>
<div class="stat-card info"><span class="count">{_stats['info']}</span><span class="label">INFO</span></div>
<div class="stat-card"><span class="count">{_stats['total']}</span><span class="label">TOTAL</span></div>
</div><h2>发现详情</h2><table><thead>
<tr><th>#</th><th>级别</th><th>标题</th><th>位置</th><th>描述</th><th>CVE</th><th>确认度</th></tr>
</thead><tbody>{''.join(_finding_rows)}</tbody></table></div></body></html>"""

    def format_sarif(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _rules = []
        _results = []
        _sev_rule_map = {"CRITICAL": "FW-CRIT-001", "HIGH": "FW-HIGH-001",
                         "MEDIUM": "FW-MED-001", "LOW": "FW-LOW-001", "INFO": "FW-INFO-001"}
        _rules.extend([
            {"id": "FW-CRIT-001", "shortDescription": {"text": "Critical"}, "defaultConfiguration": {"level": "error"}},
            {"id": "FW-HIGH-001", "shortDescription": {"text": "High"}, "defaultConfiguration": {"level": "error"}},
            {"id": "FW-MED-001", "shortDescription": {"text": "Medium"}, "defaultConfiguration": {"level": "warning"}},
            {"id": "FW-LOW-001", "shortDescription": {"text": "Low"}, "defaultConfiguration": {"level": "note"}},
            {"id": "FW-INFO-001", "shortDescription": {"text": "Info"}, "defaultConfiguration": {"level": "note"}},
        ])
        for _i, _f in enumerate(findings):
            if isinstance(_f, dict):
                _title = _f.get("title", _f.get("finding", "Unknown"))
                _sev = _f.get("severity", "INFO")
                _desc = _f.get("description", _f.get("finding", ""))
                _loc = _f.get("location", _f.get("bootloader", ""))
            elif isinstance(_f, Finding):
                _title, _sev, _desc, _loc = _f.title, _f.severity, _f.description, _f.location
            else:
                continue
            _results.append({"ruleId": _sev_rule_map.get(_sev.upper(), "FW-INFO-001"),
                            "message": {"text": f"{_title}: {_desc}"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _loc or "unknown"}}}]})
        _sarif = {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                  "runs": [{"tool": {"driver": {"name": "BinMind Firmware Analyzer", "version": "1.1.0",
                     "informationUri": "https://github.com/binmind/firmware", "rules": _rules}},
                     "results": _results}]}
        return json.dumps(_sarif, indent=2, ensure_ascii=False)

    def format_csv(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _lines = ["#,Severity,Title,Location,CVE,Assurance,Description"]
        for _i, _f in enumerate(findings, 1):
            if isinstance(_f, dict):
                _title = _f.get("title", _f.get("finding", "")).replace(',', ';')
                _sev, _loc = _f.get("severity", ""), _f.get("location", _f.get("bootloader", "")).replace(',', ';')
                _cve = _f.get("cve_id", "")
                _al = _f.get("assurance_level", "code_present")
                _desc = _f.get("description", _f.get("finding", "")).replace(',', ';')[:200]
            elif isinstance(_f, Finding):
                _title, _sev = _f.title.replace(',', ';'), _f.severity
                _loc, _cve = _f.location.replace(',', ';'), _f.cve_id or ""
                _al, _desc = _f.assurance_level, _f.description.replace(',', ';')[:200]
            else:
                continue
            _lines.append(f"{_i},{_sev},{_title},{_loc},{_cve},{_al},{_desc}")
        return "\n".join(_lines)

    def format_junit(self, findings: list, metadata: dict) -> str:
        findings = self._dedup(findings)
        _stats = self._compute_summary(findings)
        _testsuite = ET.Element("testsuite", {"name": "Firmware Security Audit",
            "tests": str(len(findings)), "failures": str(_stats["critical"]),
            "errors": str(_stats["high"]), "time": "0"})
        for _i, _f in enumerate(findings, 1):
            if isinstance(_f, dict):
                _name = _f.get("title", _f.get("finding", "unknown"))
                _sev = _f.get("severity", "INFO")
            elif isinstance(_f, Finding):
                _name, _sev = _f.title, _f.severity
            else:
                continue
            _tc = ET.SubElement(_testsuite, "testcase", {"name": _name, "classname": "firmware.security"})
            if _sev.upper() in ("CRITICAL", "HIGH"):
                _msg = _f.get("description", _f.get("finding", "")) if isinstance(_f, dict) else _f.description
                ET.SubElement(_tc, "failure", {"message": _msg[:200]})
        return ET.tostring(_testsuite, encoding="unicode")

    def _severity_to_sarif_level(self, sev: str) -> str:
        return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}.get(sev.upper(), "note")

    @staticmethod
    def _esc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict:
        return {"title": f.title, "description": f.description, "severity": f.severity,
                "location": f.location, "recommendation": f.recommendation, "cve_id": f.cve_id,
                "assurance_level": f.assurance_level}

    def _compute_summary(self, findings: list) -> dict:
        _stats = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for _f in findings:
            _sev = ""
            if isinstance(_f, dict):
                _sev = _f.get("severity", "").upper()
            elif isinstance(_f, Finding):
                _sev = _f.severity.upper()
            else:
                continue
            _stats["total"] += 1
            _key = _sev.lower() if _sev.lower() in _stats else "info"
            _stats[_key] = _stats.get(_key, 0) + 1
        return _stats
