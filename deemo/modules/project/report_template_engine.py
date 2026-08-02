"""Report template engine with compliance-clause mapping and data extraction."""
import logging, os, re, json, time, hashlib, threading
from typing import Dict, Any, List, Optional, Callable, Set, Union
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from contextlib import suppress

logger = logging.getLogger(__name__)
WEASYPRINT_AVAILABLE = False
try: from weasyprint import HTML as _WP_HTML; WEASYPRINT_AVAILABLE = True
except ImportError: logger.debug("[ReportEngine] WeasyPrint absent")

class ComplianceStandard: ISO_27001 = "iso_27001"; SOC2 = "soc2"; PCI_DSS = "pci_dss"; GDPR = "gdpr"; HIPAA = "hipaa"; NIST_800_53 = "nist_800_53"; CUSTOM = "custom"; SOC2 = ComplianceStandard("soc2"); NIST_800_53 = ComplianceStandard("nist_800_53")
class OutputFormat: MARKDOWN = "markdown"; HTML = "html"; JSON = "json"; PDF = "pdf"; PLAIN = "plain"; PLAIN = OutputFormat("plain")
class TemplateVariable:
    __slots__ = ('name', 'default', 'description', 'required', 'data_source')
    def __init__(self, name, default=None, description="", required=False, data_source=None): self.default = default; self.description = description; self.required = required; self.data_source = data_source
class ComplianceClause:
    __slots__ = ('standard', 'clause_id', 'title', 'required_fields', 'template', 'description')
    def __init__(self, standard, clause_id, title, required_fields, template="", description=""): self.template = template; self.description = description
class RenderedReport:
    __slots__ = ('title', 'content', 'format', 'variables', 'clauses', 'timestamp', 'meta')
    def __init__(self, title, content, format, variables=None, clauses=None, timestamp=0.0, meta=None): self.variables = variables if variables is not None else dict(); self.clauses = clauses if clauses is not None else list(); self.timestamp = timestamp; self.meta = meta if meta is not None else dict()
    def __post_init__(self):
        if self.timestamp == 0.0: self.timestamp = time.time()

class TemplateEngine:
    PH = re.compile(r"\{\{\s*([\w\.\-]+)(?:\|([^}]+))?\s*\}\}")
    def __init__(self):
        self._lock = threading.Lock()
        self._h: Dict[str, Callable[..., Any]] = {"upper": lambda s: str(s).upper(), "lower": lambda s: str(s).lower(), "len": lambda s: len(s) if s is not None else 0, "now": lambda: time.strftime("%Y-%m-%d %H:%M:%S"), "default": lambda v, d: v if v else d, "truncate": lambda s, n=80: str(s)[:int(n)] + ("..." if len(str(s)) > int(n) else ""), "filesize": lambda b: _fb(b)}
    def register_helper(self, n, f):
        with self._lock: self._h[n] = f
    def render(self, tpl, ctx):
        def _res(k):
            if "." in k:
                cur = ctx
                for p in k.split("."):
                    if isinstance(cur, dict) and p in cur: cur = cur[p]
                    else: return None
                return cur
            return ctx.get(k)
        def _repl(m):
            key = m.group(1).strip(); val = _res(key)
            if val is None: return ""
            if fr := m.group(2):
                for f in fr.split("|"):
                    f = f.strip()
                    if "(" in f: fn, a = f.split("(", 1); a = a.rstrip(")"); args = [x.strip().strip("'\"") for x in a.split(",") if x.strip()]
                    else: fn = f; args = []
                    if h := self._h.get(fn): val = h(val, *args) if args else h(val)
            if isinstance(val, list): return "\n".join(str(x) for x in val)
            return str(val) if val is not None else ""
        return self.PH.sub(_repl, tpl)

def _fb(b):
    try: n = int(b)
    except (ValueError, TypeError): return str(b)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n} {u}"
        n //= 1024
    return f"{n} TB"

class ComplianceLibrary:
    def __init__(self): self.clauses: List[ComplianceClause] = []; self._init()
    def _init(self):
        self.clauses.append(ComplianceClause(ComplianceStandard.ISO_27001, "A.12.6.1", "技术漏洞管理", ["vulnerability_count", "severity_distribution", "remediation_status"], description="应建立技术漏洞管理流程, 及时获取和response漏洞info"))
        self.clauses.append(ComplianceClause(ComplianceStandard.ISO_27001, "A.14.2.1", "安全开发strategy", ["secure_dev_policy", "code_review_records"], description="软件开发中应遵循安全开发原则"))
        self.clauses.append(ComplianceClause(ComplianceStandard.SOC2, "CC7.1", "vulnerability detection", ["vulnerability_count", "scanning_frequency", "detection_tools"], description="应使用vulnerability detection工具identify安全风险"))
        self.clauses.append(ComplianceClause(ComplianceStandard.SOC2, "CC7.2", "漏洞response", ["response_procedures", "mean_time_to_remediate"], description="应建立漏洞response流程"))
        self.clauses.append(ComplianceClause(ComplianceStandard.PCI_DSS, "11.3.1", "内部vulnerability scanning", ["vulnerability_count", "scan_results", "remediation_timeline"], description="应execute内部vulnerability scanning"))
        self.clauses.append(ComplianceClause(ComplianceStandard.NIST_800_53, "RA-5", "vulnerability scanning", ["vulnerability_count", "scan_frequency", "remediation_plan"], description="应建立vulnerability scanning和fix计划"))
    def get_clauses(self, s): return [c for c in self.clauses if c.standard == s]
    def add_clause(self, c): self.clauses.append(c)

class DataExtractor:
    def __init__(self): self._lock = threading.Lock()
    def extract_from_vulns(self, vulns):
        with self._lock:
            if not vulns: return {"vulnerability_count": 0, "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "vuln_types": [], "affected_assets": 0}
            sd = defaultdict(int); types = Counter(); assets = set()
            for v in vulns:
                sd[v.get("severity", "medium").lower()] += 1; types[v.get("type", v.get("category", "unknown"))] += 1
                if "binary" in v: assets.add(v["binary"])
                if "asset" in v: assets.add(v["asset"])
            mc = types.most_common(1)
            return {"vulnerability_count": len(vulns), "severity_distribution": dict(sd), "vuln_types": [{"type": t, "count": c} for t, c in types.most_common()], "affected_assets": len(assets), "most_common_type": mc[0][0] if mc else "N/A", "cvss_scores": [v.get("cvss", 0) for v in vulns if v.get("cvss")]}
    def extract_from_analysis(self, ar):
        with self._lock:
            r = {}
            if "binary" in ar: r["target_binary"] = ar["binary"]
            if f := ar.get("functions"): r["function_count"] = len(f) if isinstance(f, list) else 0
            if s := ar.get("strings"): r["string_count"] = len(s) if isinstance(s, list) else 0
            if "imports" in ar: r["import_count"] = len(ar["imports"])
            r["scan_date"] = ar.get("scan_date", time.strftime("%Y-%m-%d")); r.update(self.extract_from_vulns(ar.get("vulnerabilities", []))); return r
    def extract_from_assets(self, assets):
        with self._lock: return {"asset_count": len(assets), "asset_names": [a.get("name", "unknown") for a in assets], "asset_types": list({a.get("type", "unknown") for a in assets})}

class ReportTemplateEngine:
    DEFAULT_TEMPLATE = """# {{ title }}\n\n**报告生成时间**: {{ scan_date }}\n**target**: {{ target_binary }}\n**生成方**: {{ generator|default('Binary Analysis Tool') }}\n\n## 1. 概述\n\n本次分析共发现 **{{ vulnerability_count }}** 个漏洞, 涉及 **{{ affected_assets }}** 个资产。\n\n## 2. 漏洞统计\n\n| severity | 数量 |\n|---------|------|\n| 严重 (Critical) | {{ severity_distribution.critical|default(0) }} |\n| 高危 (High) | {{ severity_distribution.high|default(0) }} |\n| 中危 (Medium) | {{ severity_distribution.medium|default(0) }} |\n| 低危 (Low) | {{ severity_distribution.low|default(0) }} |\n\n## 3. vulnerability type分布\n\n{% for vt in vuln_types %}\n- **{{ vt.type }}**: {{ vt.count }} 个\n{% endfor %}\n\n## 4. 合规条款check\n\n{% for cl in clauses %}\n### {{ cl.clause_id }} - {{ cl.title }}\n{{ cl.description }}\n\n- 所需field: {{ cl.fields }}\n- status: {{ cl.status }}\n{% endfor %}\n\n## 5. 结论\n\n整体漏洞态势: {{ overall_status|default('需要关注') }}。\n"""
    def __init__(self): self.engine = TemplateEngine(); self.compliance = ComplianceLibrary(); self.extractor = DataExtractor(); self._tpls: Dict[str, str] = {"default": self.DEFAULT_TEMPLATE}; self._lock = threading.Lock()
    def register_template(self, n, c):
        with self._lock: self._tpls[n] = c
    def get_template(self, n):
        with self._lock: return self._tpls.get(n, self.DEFAULT_TEMPLATE)
    def check_compliance(self, std, data):
        r = []
        for cl in self.compliance.get_clauses(std):
            m = [f for f in cl.required_fields if f not in data or data[f] is None]
            r.append({"clause_id": cl.clause_id, "title": cl.title, "description": cl.description, "fields": cl.required_fields, "missing": m, "status": "compliant" if not m else "non_compliant"})
        return r
    def render(self, tn="default", data=None, variables=None, compliance=None, ofmt=OutputFormat.MARKDOWN, title="Binary Security Analysis Report"):
        data = data or {}; variables = variables or {}
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            ex = self.extractor.extract_from_vulns(data["vulnerabilities"])
            for k, v in ex.items():
                if k not in data: data[k] = v
        cr = []
        if compliance:
            for s in compliance: cr.extend(self.check_compliance(s, data))
        ctx = dict(data); ctx.update(variables); ctx["title"] = title; ctx["generator"] = "Binary Analysis Tool"; ctx["scan_date"] = data.get("scan_date", time.strftime("%Y-%m-%d")); ctx["clauses"] = cr
        if cr: ctx["overall_compliance"] = f"{sum(1 for c in cr if c['status'] == 'compliant')}/{len(cr)}"
        tpl = self.get_template(tn); content = self.engine.render(tpl, ctx); content = self._loops(content, ctx); content = self._ifs(content, ctx)
        return RenderedReport(title=title, content=content, format=ofmt, variables=ctx, clauses=[c["clause_id"] for c in cr], meta={"template": tn, "vulnerability_count": data.get("vulnerability_count", 0), "compliance_standards": [c.value for c in (compliance or [])]})
    def _loops(self, content, ctx):
        lp = re.compile(r"\{%\s*for\s+(\w+)\s+in\s+([\w\.]+)\s*%\}(.*?)\{%\s*endfor\s*%\}", re.DOTALL)
        def _r(m):
            vn, lpth, body = m.group(1), m.group(2), m.group(3); items = ctx
            for p in lpth.split("."):
                if isinstance(items, dict) and p in items: items = items[p]
                else: return ""
            if not isinstance(items, list): return ""
            out = []
            for item in items:
                loc = dict(ctx)
                if isinstance(item, dict): loc.update(item); loc[vn] = item
                else: loc[vn] = item
                out.append(self.engine.render(body, loc))
            return "".join(out)
        return lp.sub(_r, content)
    def _ifs(self, content, ctx):
        ip = re.compile(r"\{%\s*if\s+([\w\.]+)\s*%\}(.*?)\{%\s*endif\s*%\}", re.DOTALL)
        def _r(m):
            key, body = m.group(1), m.group(2); val = ctx
            for p in key.split("."):
                if isinstance(val, dict) and p in val: val = val[p]
                else: return ""
            return self.engine.render(body, ctx) if val else ""
        return ip.sub(_r, content)
    def export(self, report, fp):
        ext = os.path.splitext(fp)[1].lower()
        with open(fp, "w", encoding="utf-8") as f:
            if ext in (".md", ".markdown", ".txt"): f.write(report.content)
            elif ext in (".html", ".htm"): f.write(self._html(report))
            elif ext == ".json": f.write(json.dumps({"title": report.title, "content": report.content, "format": report.format.value, "variables": report.variables, "clauses": report.clauses, "meta": report.meta, "timestamp": report.timestamp}, ensure_ascii=False, indent=2))
            else: f.write(report.content)
        return fp
    def export_pdf(self, report, fp, css=None):
        if not WEASYPRINT_AVAILABLE: logger.warning("WeasyPrint 不可用"); return False
        hb = self._html(report, full=True)
        try:
            doc = _WP_HTML(string=hb)
            if css and os.path.isfile(css):
                with open(css) as cf: doc = _WP_HTML(string=f"<style>{cf.read()}</style>{hb}")
            doc.write_pdf(fp); logger.info("PDF: %s", fp); return True
        except Exception as e: logger.error("PDF fail: %s", e); return False
    def _html(self, report, full=False):
        body = report.content
        body = re.sub(r"^# (.+)$", r"<h1>\1</h1>", body, flags=re.MULTILINE); body = re.sub(r"^## (.+)$", r"<h2>\1</h2>", body, flags=re.MULTILINE); body = re.sub(r"^### (.+)$", r"<h3>\1</h3>", body, flags=re.MULTILINE)
        body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", body); body = re.sub(r"`([^`]+)`", r"<code>\1</code>", body); body = re.sub(r"^\|(.+)\|$", r"<tr>\1</tr>", body, flags=re.MULTILINE); body = body.replace("\n", "<br>\n")
        if full: return f"""<!DOCTYPE html>\n<html><head><meta charset="utf-8"><title>{report.title}</title>\n<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;line-height:1.6;color:#1a1a1a}}h1{{border-bottom:2px solid #2563eb;padding-bottom:.5rem}}h2{{color:#2563eb}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #e2e8f0;padding:.5rem .75rem}}</style></head>\n<body>{body}</body></html>"""
        return body

_default_engine = None; _engine_lock = threading.Lock()
def get_template_engine():
    global _default_engine
    with _engine_lock:
        if _default_engine is None: _default_engine = ReportTemplateEngine()
        return _default_engine
def render_report(data, template="default", compliance=None, title="Binary Security Analysis Report"):
    eng = get_template_engine(); stds = None
    if compliance:
        try: stds = [ComplianceStandard(c) for c in compliance]
        except ValueError: stds = None
    return eng.render(template, data, compliance=stds, title=title)
