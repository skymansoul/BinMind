"""
智能报告模板自定义与数据填充模块

功能:
    1. 允许用户定义报告模板变量(如公司名称、特定合规条款)
    2. 自动从分析结果中抽取数据填入
    3. 支持生成符合 ISO 27001、SOC2 等合规要求的报告章节

核心技术:
    - 模板引擎: 基于占位符 {{var}} 的轻量级渲染
    - 合规规则集: 条款 -> 所需字段的映射
    - 自动数据抽取: 从漏洞/资产/分析结果中聚合
    - 多格式输出: Markdown/HTML/JSON
"""

import logging
import os
import re
import json
import time
import hashlib
import threading
from typing import Dict, Any, List, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)


class ComplianceStandard(Enum):
    """合规标准"""
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    NIST_800_53 = "nist_800_53"
    CUSTOM = "custom"


class OutputFormat(Enum):
    """输出格式"""
    MARKDOWN = "markdown"
    HTML = "html"
    JSON = "json"
    PLAIN = "plain"


@dataclass
class TemplateVariable:
    """模板变量定义"""
    name: str
    default: Any = None
    description: str = ""
    required: bool = False
    data_source: Optional[str] = None  # 数据源路径


@dataclass
class ComplianceClause:
    """合规条款"""
    standard: ComplianceStandard
    clause_id: str
    title: str
    required_fields: List[str]
    template: str = ""
    description: str = ""


@dataclass
class RenderedReport:
    """渲染后的报告"""
    title: str
    content: str
    format: OutputFormat
    variables: Dict[str, Any] = field(default_factory=dict)
    clauses: List[str] = field(default_factory=list)
    timestamp: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class TemplateEngine:
    """模板引擎"""

    PLACEHOLDER = re.compile(r"\{\{\s*([\w\.\-]+)\s*\}\}")

    def __init__(self):
        self._lock = threading.Lock()
        self._helpers: Dict[str, Callable[..., Any]] = {
            "upper": lambda s: str(s).upper(),
            "lower": lambda s: str(s).lower(),
            "len": lambda s: len(s) if s is not None else 0,
            "now": lambda: time.strftime("%Y-%m-%d %H:%M:%S"),
            "default": lambda v, d: v if v else d,
        }

    def register_helper(self, name: str, func: Callable[..., Any]):
        with self._lock:
            self._helpers[name] = func

    def render(self, template: str, context: Dict[str, Any]) -> str:
        """渲染模板"""
        def repl(m):
            key = m.group(1).strip()
            if "." in key:
                parts = key.split(".")
                cur: Any = context
                for p in parts:
                    if isinstance(cur, dict) and p in cur:
                        cur = cur[p]
                    else:
                        return m.group(0)
                return str(cur) if cur is not None else ""
            val = context.get(key, "")
            if val is None:
                return ""
            if isinstance(val, list):
                return "\n".join(str(x) for x in val)
            return str(val)

        return self.PLACEHOLDER.sub(repl, template)


class ComplianceLibrary:
    """合规规则库"""

    def __init__(self):
        self.clauses: List[ComplianceClause] = []
        self._init_builtin()

    def _init_builtin(self):
        """初始化内置条款"""
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.ISO_27001,
            clause_id="A.12.6.1",
            title="技术漏洞管理",
            required_fields=["vulnerability_count", "severity_distribution", "remediation_status"],
            description="应建立技术漏洞管理流程, 及时获取和响应漏洞信息"
        ))
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.ISO_27001,
            clause_id="A.14.2.1",
            title="安全开发策略",
            required_fields=["secure_dev_policy", "code_review_records"],
            description="软件开发中应遵循安全开发原则"
        ))
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.SOC2,
            clause_id="CC7.1",
            title="漏洞检测",
            required_fields=["vulnerability_count", "scanning_frequency", "detection_tools"],
            description="应使用漏洞检测工具识别安全风险"
        ))
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.SOC2,
            clause_id="CC7.2",
            title="漏洞响应",
            required_fields=["response_procedures", "mean_time_to_remediate"],
            description="应建立漏洞响应流程"
        ))
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.PCI_DSS,
            clause_id="11.3.1",
            title="内部漏洞扫描",
            required_fields=["vulnerability_count", "scan_results", "remediation_timeline"],
            description="应执行内部漏洞扫描"
        ))
        self.clauses.append(ComplianceClause(
            standard=ComplianceStandard.NIST_800_53,
            clause_id="RA-5",
            title="漏洞扫描",
            required_fields=["vulnerability_count", "scan_frequency", "remediation_plan"],
            description="应建立漏洞扫描和修复计划"
        ))

    def get_clauses(self, standard: ComplianceStandard) -> List[ComplianceClause]:
        return [c for c in self.clauses if c.standard == standard]

    def add_clause(self, clause: ComplianceClause):
        self.clauses.append(clause)


class DataExtractor:
    """数据抽取器 - 从分析结果中抽取报告数据"""

    def __init__(self):
        self._lock = threading.Lock()

    def extract_from_vulns(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从漏洞列表抽取数据"""
        with self._lock:
            if not vulns:
                return {
                    "vulnerability_count": 0,
                    "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "vuln_types": [],
                    "affected_assets": 0,
                }
            severity_dist: Dict[str, int] = defaultdict(int)
            types: Counter = Counter()
            assets: set = set()
            for v in vulns:
                sev = v.get("severity", "medium").lower()
                severity_dist[sev] += 1
                vtype = v.get("type", v.get("category", "unknown"))
                types[vtype] += 1
                if "binary" in v:
                    assets.add(v["binary"])
                if "asset" in v:
                    assets.add(v["asset"])
            return {
                "vulnerability_count": len(vulns),
                "severity_distribution": dict(severity_dist),
                "vuln_types": [{"type": t, "count": c} for t, c in types.most_common()],
                "affected_assets": len(assets),
                "most_common_type": types.most_common(1)[0][0] if types else "N/A",
            }

    def extract_from_analysis(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """从分析结果抽取数据"""
        with self._lock:
            result: Dict[str, Any] = {}
            if "binary" in analysis_result:
                result["target_binary"] = analysis_result["binary"]
            if "functions" in analysis_result:
                funcs = analysis_result["functions"]
                result["function_count"] = len(funcs) if isinstance(funcs, list) else 0
            if "strings" in analysis_result:
                strings = analysis_result["strings"]
                result["string_count"] = len(strings) if isinstance(strings, list) else 0
            if "imports" in analysis_result:
                result["import_count"] = len(analysis_result["imports"])
            if "scan_date" in analysis_result:
                result["scan_date"] = analysis_result["scan_date"]
            else:
                result["scan_date"] = time.strftime("%Y-%m-%d")
            vulns = analysis_result.get("vulnerabilities", [])
            result.update(self.extract_from_vulns(vulns))
            return result

    def extract_from_assets(self, assets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """从资产列表抽取数据"""
        with self._lock:
            return {
                "asset_count": len(assets),
                "asset_names": [a.get("name", "unknown") for a in assets],
                "asset_types": list({a.get("type", "unknown") for a in assets}),
            }


class ReportTemplateEngine:
    """报告模板引擎"""

    DEFAULT_TEMPLATE = """# {{ title }}

**报告生成时间**: {{ scan_date }}  
**目标**: {{ target_binary }}  
**生成方**: {{ generator|default('Binary Analysis Tool') }}

## 1. 概述

本次分析共发现 **{{ vulnerability_count }}** 个漏洞, 涉及 **{{ affected_assets }}** 个资产。

## 2. 漏洞统计

| 严重程度 | 数量 |
|---------|------|
| 严重 (Critical) | {{ severity_distribution.critical|default(0) }} |
| 高危 (High) | {{ severity_distribution.high|default(0) }} |
| 中危 (Medium) | {{ severity_distribution.medium|default(0) }} |
| 低危 (Low) | {{ severity_distribution.low|default(0) }} |

## 3. 漏洞类型分布

{% for vt in vuln_types %}
- **{{ vt.type }}**: {{ vt.count }} 个
{% endfor %}

## 4. 合规条款检查

{% for cl in clauses %}
### {{ cl.clause_id }} - {{ cl.title }}
{{ cl.description }}

- 所需字段: {{ cl.fields }}
- 状态: {{ cl.status }}
{% endfor %}

## 5. 结论

整体漏洞态势: {{ overall_status|default('需要关注') }}。
"""

    def __init__(self):
        self.engine = TemplateEngine()
        self.compliance = ComplianceLibrary()
        self.extractor = DataExtractor()
        self._templates: Dict[str, str] = {"default": self.DEFAULT_TEMPLATE}
        self._lock = threading.Lock()

    def register_template(self, name: str, content: str):
        with self._lock:
            self._templates[name] = content

    def get_template(self, name: str) -> str:
        with self._lock:
            return self._templates.get(name, self.DEFAULT_TEMPLATE)

    def check_compliance(
        self,
        standard: ComplianceStandard,
        data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """检查合规状态"""
        clauses = self.compliance.get_clauses(standard)
        results: List[Dict[str, Any]] = []
        for cl in clauses:
            missing = [f for f in cl.required_fields if f not in data or data[f] is None]
            results.append({
                "clause_id": cl.clause_id,
                "title": cl.title,
                "description": cl.description,
                "fields": cl.required_fields,
                "missing": missing,
                "status": "compliant" if not missing else "non_compliant",
            })
        return results

    def render(
        self,
        template_name: str = "default",
        data: Optional[Dict[str, Any]] = None,
        variables: Optional[Dict[str, Any]] = None,
        compliance: Optional[List[ComplianceStandard]] = None,
        output_format: OutputFormat = OutputFormat.MARKDOWN,
        title: str = "Binary Security Analysis Report"
    ) -> RenderedReport:
        """渲染报告"""
        data = data or {}
        variables = variables or {}

        # 自动抽取数据
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            extracted = self.extractor.extract_from_vulns(data["vulnerabilities"])
            for k, v in extracted.items():
                if k not in data:
                    data[k] = v

        # 合规检查
        compliance_results: List[Dict[str, Any]] = []
        if compliance:
            for std in compliance:
                compliance_results.extend(self.check_compliance(std, data))

        # 合并上下文
        context = dict(data)
        context.update(variables)
        context["title"] = title
        context["generator"] = "Binary Analysis Tool"
        context["scan_date"] = data.get("scan_date", time.strftime("%Y-%m-%d"))
        context["clauses"] = compliance_results
        if compliance_results:
            compliant = sum(1 for c in compliance_results if c["status"] == "compliant")
            total = len(compliance_results)
            context["overall_compliance"] = f"{compliant}/{total}"

        # 渲染模板
        tpl = self.get_template(template_name)
        content = self.engine.render(tpl, context)
        content = self._apply_loops(content, context)
        content = self._apply_conditionals(content, context)

        return RenderedReport(
            title=title,
            content=content,
            format=output_format,
            variables=context,
            clauses=[c["clause_id"] for c in compliance_results],
            meta={
                "template": template_name,
                "vulnerability_count": data.get("vulnerability_count", 0),
                "compliance_standards": [c.value for c in (compliance or [])],
            }
        )

    def _apply_loops(self, content: str, context: Dict[str, Any]) -> str:
        """处理简单循环 {% for x in y %}"""
        loop_pattern = re.compile(
            r"\{%\s*for\s+(\w+)\s+in\s+([\w\.]+)\s*%\}(.*?)\{%\s*endfor\s*%\}",
            re.DOTALL
        )
        def repl(m):
            var_name = m.group(1)
            list_path = m.group(2)
            body = m.group(3)
            items: Any = context
            for p in list_path.split("."):
                if isinstance(items, dict) and p in items:
                    items = items[p]
                else:
                    return ""
            if not isinstance(items, list):
                return ""
            out: List[str] = []
            for item in items:
                local = dict(context)
                if isinstance(item, dict):
                    local.update(item)
                    local[var_name] = item
                else:
                    local[var_name] = item
                out.append(self.engine.render(body, local))
            return "".join(out)
        return loop_pattern.sub(repl, content)

    def _apply_conditionals(self, content: str, context: Dict[str, Any]) -> str:
        """处理简单条件 {% if var %} ... {% endif %}"""
        if_pattern = re.compile(
            r"\{%\s*if\s+([\w\.]+)\s*%\}(.*?)\{%\s*endif\s*%\}",
            re.DOTALL
        )
        def repl(m):
            key = m.group(1)
            body = m.group(2)
            val: Any = context
            for p in key.split("."):
                if isinstance(val, dict) and p in val:
                    val = val[p]
                else:
                    return ""
            if val:
                return self.engine.render(body, context)
            return ""
        return if_pattern.sub(repl, content)

    def export(self, report: RenderedReport, file_path: str) -> str:
        """导出报告到文件"""
        ext = os.path.splitext(file_path)[1].lower()
        with open(file_path, "w", encoding="utf-8") as f:
            if ext in (".md", ".markdown", ".txt"):
                f.write(report.content)
            elif ext in (".html", ".htm"):
                f.write(self._to_html(report))
            elif ext == ".json":
                f.write(json.dumps({
                    "title": report.title,
                    "content": report.content,
                    "format": report.format.value,
                    "variables": report.variables,
                    "clauses": report.clauses,
                    "meta": report.meta,
                    "timestamp": report.timestamp,
                }, ensure_ascii=False, indent=2))
            else:
                f.write(report.content)
        return file_path

    def _to_html(self, report: RenderedReport) -> str:
        """转换为 HTML"""
        body = report.content
        # 简单 Markdown -> HTML
        body = re.sub(r"^# (.+)$", r"<h1>\1</h1>", body, flags=re.MULTILINE)
        body = re.sub(r"^## (.+)$", r"<h2>\1</h2>", body, flags=re.MULTILINE)
        body = re.sub(r"^### (.+)$", r"<h3>\1</h3>", body, flags=re.MULTILINE)
        body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body)
        body = body.replace("\n", "<br>\n")
        return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{report.title}</title></head>
<body>{body}</body></html>"""


# 便捷入口
_default_engine: Optional[ReportTemplateEngine] = None
_engine_lock = threading.Lock()


def get_template_engine() -> ReportTemplateEngine:
    global _default_engine
    with _engine_lock:
        if _default_engine is None:
            _default_engine = ReportTemplateEngine()
        return _default_engine


def render_report(
    data: Dict[str, Any],
    template: str = "default",
    compliance: Optional[List[str]] = None,
    title: str = "Binary Security Analysis Report"
) -> RenderedReport:
    eng = get_template_engine()
    stds: Optional[List[ComplianceStandard]] = None
    if compliance:
        try:
            stds = [ComplianceStandard(c) for c in compliance]
        except ValueError:
            stds = None
    return eng.render(template, data, compliance=stds, title=title)
