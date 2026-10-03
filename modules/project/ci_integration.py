"""CI/CD管道集成: XML报告解析, 严重度加权, exit-code映射."""
from __future__ import annotations
import xml.etree.ElementTree as ET, json as _j, os, hashlib, time, abc
from enum import Enum
from typing import List, Dict, Set
from pathlib import Path
from contextlib import suppress

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

class Severity(Enum):
    LOW = "low"; MEDIUM = "medium"; HIGH = "high"; CRITICAL = "critical"
    def weight(self) -> int:
        return {Severity.LOW: 1, Severity.MEDIUM: 4, Severity.HIGH: 7, Severity.CRITICAL: 10}[self]
    @classmethod
    def from_github(cls, lvl: str) -> "Severity":
        return {"error": cls.CRITICAL, "warning": cls.MEDIUM, "note": cls.LOW}.get(lvl.lower(), cls.MEDIUM)

class Finding:
    __slots__ = ('rule_id', 'severity', 'file', 'line', 'message', 'fp', 'first_seen', 'cwe')
    def __init__(self, rule_id="", sev=Severity.MEDIUM, file="", line=0, msg=""):
        self.rule_id = rule_id; self.severity = sev; self.file = file; self.line = line; self.message = msg
        self.fp = hashlib.sha256(f"{file}:{line}:{rule_id}".encode()).hexdigest()[:16]; self.first_seen = 0.0; self.cwe = ""
    def to_dict(self):
        d = {s: getattr(self, s) for s in self.__slots__}; d["severity"] = self.severity.value; return d
    def __hash__(self): return hash(self.fp)
    def __eq__(self, o): return isinstance(o, Finding) and self.fp == o.fp

class CIResult:
    def __init__(self, passed=True, findings=None): self.passed = passed; self.findings: List[Finding] = findings or []

# ABC报告解析器契约
class _BaseParser(abc.ABC):
    @abc.abstractmethod
    def parse(self, path: str) -> List[Finding]: ...

class _CheckstyleParser(_BaseParser):
    def parse(self, xml_path: str) -> List[Finding]:
        findings = []
        try: tree = ET.parse(xml_path)
        except (ET.ParseError, OSError): return findings
        for fel in tree.findall(".//file"):
            fn = fel.get("name", "")
            for err in fel.findall("error"):
                findings.append(Finding(err.get("source", ""), _map_cs(err.get("severity", "")), fn, int(err.get("line", 0)), err.get("message", "")))
        return findings

class _GitlabSASTParser(_BaseParser):
    def parse(self, jp: str) -> List[Finding]:
        findings = []
        with suppress(OSError):
            with open(jp, encoding='utf-8') as fh:
                for line in fh:
                    if not (line := line.strip()): continue
                    with suppress(_j.JSONDecodeError):
                        o = _j.loads(line); ident = o.get("identifiers", [{}])[0]; loc = o.get("location", {})
                        findings.append(Finding(ident.get("value", ident.get("name", "")), Severity(o.get("severity", "Medium").lower()), loc.get("file", ""), loc.get("start_line", loc.get("line", 0)), o.get("description", "")))
        return findings

class _SARIFParser(_BaseParser):
    def __init__(self, tool_name="binmind"): self._tool = tool_name
    def parse(self, jp: str) -> List[Finding]:
        findings = []; sarif = None
        with suppress(OSError, _j.JSONDecodeError):
            with open(jp, encoding='utf-8') as fh: sarif = _j.load(fh)
        if sarif is None: return findings
        for run in sarif.get("runs", []):
            rlut = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                rid = result.get("ruleId", ""); rule = rlut.get(rid, {}); lvl = result.get("level", "warning")
                locs = result.get("locations", []); phys = locs[0].get("physicalLocation", {}) if locs else {}; reg = phys.get("region", {})
                f = Finding(_RuleNorm.norm(self._tool, rid), Severity.from_github(lvl), phys.get("artifactLocation", {}).get("uri", ""), reg.get("startLine", 0), result.get("message", {}).get("text", rule.get("shortDescription", {}).get("text", "")))
                taxa = rlut.get(rid, {}).get("relationships", [])
                if taxa: f.cwe = taxa[0].get("target", {}).get("id", "")
                findings.append(f)
        return findings

class _RuleNorm:
    _map = {"semgrep.flask-hardcoded-secret": "BM-HRDSEC-001", "semgrep.sql-injection": "BM-SQLINJ-001", "B301": "BM-PICKLE-001", "B602": "BM-SUBSHL-001", "py/clear-text-logging-sensitive-data": "BM-LOGLEAK-001", "py/path-injection": "BM-PATHINJ-001"}
    @classmethod
    def norm(cls, tool: str, raw: str) -> str: return cls._map.get(f"{tool}.{raw}", raw or "UNKNOWN")

def _map_cs(raw):
    raw = raw.lower()
    if raw in ("error", "critical"): return Severity.CRITICAL
    if raw == "warning": return Severity.MEDIUM
    if raw == "info": return Severity.LOW
    return Severity.MEDIUM

class CIIntegrator:
    def __init__(self, cfg=None):
        cfg = cfg or {}; self._thresh = cfg.get("max_severity_weight", 0); self.results: List[CIResult] = []
        self._bp = cfg.get("baseline_path", ".binmind/baseline.json"); self._baseline: Set[str] = set()
        self._tool = cfg.get("tool_name", "binmind"); self._parsers = {"checkstyle": _CheckstyleParser(), "gitlab_sast": _GitlabSASTParser(), "sarif": _SARIFParser(self._tool)}
    def add_result(self, r: CIResult): self.results.append(r)
    def run_pipeline(self, binary=None): return CIResult(True, [])
    def get_summary(self):
        p = f = t = 0
        for r in self.results: (p := p + 1) if r.passed else (f := f + 1); t += len(r.findings)
        return {"passed": p, "failed": f, "findings": t, "new_findings": self._count_new()}
    def worst_severity(self):
        w = Severity.LOW
        for r in self.results:
            for f in r.findings:
                if f.severity.weight() > w.weight(): w = f.severity
        return w
    def exit_code(self):
        if not self.results: return 0
        if self._thresh:
            return 2 if sum(f.severity.weight() for r in self.results for f in r.findings) >= self._thresh else 0
        match self.worst_severity():
            case Severity.CRITICAL: return 3
            case Severity.HIGH: return 2
            case Severity.MEDIUM: return 1
            case _: return 0

    def load_baseline(self):
        p = Path(self._bp)
        if not p.is_file(): return 0
        with suppress(_j.JSONDecodeError, OSError):
            d = _j.loads(p.read_text(encoding="utf-8")); self._baseline = set(d.get("fingerprints", [])); return len(self._baseline)
        return 0
    def save_baseline(self):
        fps, seen = [], set()
        for r in self.results:
            for f in r.findings:
                if f.fp not in seen: seen.add(f.fp); fps.append(f.fp)
        p = Path(self._bp); p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_j.dumps({"updated": time.time(), "fingerprints": fps}, indent=2), encoding="utf-8"); return str(p)
    def _count_new(self): return 0 if not self._baseline else sum(1 for r in self.results for f in r.findings if f.fp not in self._baseline)
    def delta_findings(self):
        if not self._baseline: return [f for r in self.results for f in r.findings]
        new = []
        for r in self.results: new.extend(f for f in r.findings if f.fp not in self._baseline)
        return new
    def deduplicate(self):
        seen = set()
        for r in self.results:
            kept = []; [kept.append(f) for f in r.findings if f.fp not in seen and not seen.add(f.fp)]; r.findings = kept

    def parse_checkstyle(self, p): return self._parsers["checkstyle"].parse(p)
    def parse_junit(self, xml_path):
        try: tree = ET.parse(xml_path)
        except (ET.ParseError, OSError): return {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        s = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
        for ts in tree.findall(".//testsuite"):
            for k in s: s[k] += int(ts.get(k, 0))
        return s
    def parse_gitlab_sast(self, p): return self._parsers["gitlab_sast"].parse(p)
    def parse_github_code_scanning(self, p): return self._parsers["sarif"].parse(p)

    def export_junit(self):
        s = ET.Element("testsuite", name="binmind", tests=str(len(self.results)))
        for r in self.results:
            tc = ET.SubElement(s, "testcase", name="analysis")
            if not r.passed: ET.SubElement(tc, "failure", message=f"{len(r.findings)} finding(s)")
        return ET.tostring(s, encoding="unicode")
    def export_sarif(self):
        rules, results = {}, []
        for r in self.results:
            for f in r.findings:
                rid = f.rule_id or "UNKNOWN"
                if rid not in rules: rules[rid] = {"id": rid, "name": rid, "shortDescription": {"text": rid}}
                loc = [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}] if f.file else []
                results.append({"ruleId": rid, "level": f.severity.value, "message": {"text": f.message}, "locations": loc, "partialFingerprints": {"binmind/v1": f.fp}})
        return _j.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "BinMind", "rules": list(rules.values())}}, "results": results}]})
    def export_code_climate(self):
        cc = {Severity.LOW: "info", Severity.MEDIUM: "minor", Severity.HIGH: "major", Severity.CRITICAL: "blocker"}
        return _j.dumps([{"type": "issue", "check_name": f.rule_id or "binmind", "description": f.message[:500], "severity": cc.get(f.severity, "minor"), "fingerprint": f.fp, "location": {"path": f.file, "lines": {"begin": f.line or 1}} if f.file else {}} for r in self.results for f in r.findings], indent=2)
    def export_gitlab_sast(self):
        lines = []
        for r in self.results:
            for f in r.findings:
                lines.append(_j.dumps({"id": f.fp, "category": "sast", "name": f.rule_id or "binmind.finding", "message": f.message[:1000], "description": f.message, "severity": f.severity.value.title(), "scanner": {"id": "binmind", "name": "BinMind"}, "location": {"file": f.file, "start_line": f.line or 1}, "identifiers": [{"type": "binmind_rule", "name": f.rule_id, "value": f.rule_id}]}, ensure_ascii=False))
        return "\n".join(lines)

CI_EXIT_CODE: int = 0
