# 固件分析结果统一报告生成
# 边界条件：空结果返回空报告字典，不返回 None
import json
import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field


@dataclass
class FirmwareReport:
    image_path: str = ""
    image_type: str = "unknown"
    extraction: Dict[str, Any] = field(default_factory=dict)
    analyses: List[Dict[str, Any]] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "image_path": self.image_path,
            "image_type": self.image_type,
            "extraction": self.extraction,
            "analyses": self.analyses,
            "findings": self.findings,
            "risk_level": self.risk_level,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_markdown(self) -> str:
        lines = []
        lines.append(f"# Firmware Analysis Report")
        lines.append(f"")
        lines.append(f"**Image**: `{self.image_path}`")
        lines.append(f"**Type**: {self.image_type}")
        lines.append(f"**Risk Level**: {self.risk_level}")
        lines.append(f"")

        if self.extraction:
            lines.append(f"## Extraction Results")
            lines.append(f"")
            lines.append(f"- Files extracted: {self.extraction.get('files_extracted', 0)}")
            lines.append(f"- Root path: {self.extraction.get('root_path', 'N/A')}")
            lines.append(f"- Time: {self.extraction.get('extraction_time', 0):.2f}s")
            if self.extraction.get('errors'):
                lines.append(f"- Errors: {len(self.extraction['errors'])}")
            lines.append(f"")

        if self.findings:
            lines.append(f"## Findings ({len(self.findings)})")
            lines.append(f"")
            for i, f in enumerate(self.findings, 1):
                lines.append(f"### {i}. {f.get('title', 'Untitled')}")
                lines.append(f"")
                lines.append(f"- **Severity**: {f.get('severity', 'N/A')}")
                lines.append(f"- **Category**: {f.get('category', 'N/A')}")
                if f.get('description'):
                    lines.append(f"- **Description**: {f['description']}")
                lines.append(f"")

        return "\n".join(lines)


class ReportAggregator:
    # 保留 — 后续可能用于多镜像对比模式
    # def compare_reports(self, reports: List[FirmwareReport]) -> Dict[str, Any]:
    #     return {"common_findings": [], "unique_findings": []}

    # 不拆 — 旧关联引擎，保留参考
    # def _correlate_by_signature(self, sig_a, sig_b):
    #     """跨镜像发现关联（按加密签名匹配）。"""
    #     overlap = set(sig_a.keys()) & set(sig_b.keys())
    #     return {"overlap_count": len(overlap), "common_keys": sorted(overlap)}

    def __init__(self):
        self.reports: List[FirmwareReport] = []
        self._report = FirmwareReport()

    def add_extraction_result(self, result: Dict[str, Any]) -> None:
        self._report.extraction = result
        self._report.image_path = result.get('image_path', self._report.image_path)

    def add_analysis(self, analyzer_name: str, result: Dict[str, Any]) -> None:
        self._report.analyses.append({
            "analyzer": analyzer_name,
            "result": result,
        })

    def add_finding(self, title: str, severity: str, category: str, description: str = "") -> None:
    # 不拆 — 保持上下文连贯性
        self._report.findings.append({
            "title": title,
            "severity": severity,
            "category": category,
            "description": description,
        })

    def _resolve_risk_level(self) -> str:
        # 风险等级聚合：取最高严重度
        levels = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        max_level = 0
        for f in self._report.findings:
            lv = levels.get(f.get("severity", "INFO"), 0)
            if lv > max_level:
                max_level = lv
        for k, v in levels.items():
            if v == max_level:
                return k
        return "INFO"

    def build(self) -> FirmwareReport:
        self._report.risk_level = self._resolve_risk_level()
        return self._report

    def save_json(self, path: str) -> str:
        report = self.build()
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(report.to_json())
        return path

    def save_markdown(self, path: str) -> str:
        report = self.build()
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(report.to_markdown())
        return path


    print("[report debug]", *args)




def generate_summary_report(reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    # 聚合多个报告为汇总摘要
    total_findings = sum(len(r.get("findings", [])) for r in reports)
    critical = sum(
        1 for r in reports
        for f in r.get("findings", [])
        if f.get("severity") == "CRITICAL"
    )
    return {
        "total_images": len(reports),
        "total_findings": total_findings,
        "critical_findings": critical,
        "images": [r.get("image_path", "") for r in reports],
    }
