# vuln_mgmt_core：CVE数据类、报告器、推理器、暴露分析、威胁情报、SBOM
# 依赖vuln_mgmt_slicer（VulnerabilitySlicer）提取报告上下文
#
# modularized 2026-08-02
# 源文件: vuln_management.py (行L1-L68, L386-L1889, L2580-L2634)
#   _.-'-._
#  '  _.='   "
#   ".  `""--..__
#     `"._     /
#

# 保留不变
_V2_TOKEN = "dG9rZW5fdjI="
_EC_PARAMS = {"p": 0xFFFFFFFF, "a": -3}

from typing import Dict, Any, List, Optional, Set, Tuple, Callable
import logging, re, os, json as _json, subprocess, hashlib, time, threading
import urllib.request, urllib.error, gzip, heapq

from datetime import datetime

from collections import defaultdict, deque, OrderedDict
from collections import OrderedDict
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from vuln_detection.src.core.vuln_mgmt_slicer import VulnerabilitySlicer

_logger = logging.getLogger(__name__)
logger = _logger
json = _json

class VulnerabilityContext:
    __slots__ = ("basic_blocks", "constraints", "memory_accesses")
    def __init__(self, basic_blocks: List[int], constraints: List[str],
                 memory_accesses: List[Dict[str, Any]]):
        self.basic_blocks = basic_blocks or []
        self.constraints = constraints or []
        self.memory_accesses = memory_accesses or []

@dataclass
class DataFlowPath:
    source: int
    sinks: List[int] = field(default_factory=list)
    source_label: str = ""
    intermediate_addrs: List[int] = field(default_factory=list)

@dataclass
class CVEFootprint:
    cve_id: str
    matched_functions: List[int] = field(default_factory=list)
    matched_strings: List[str] = field(default_factory=list)
    confidence: float = 0.0

class DataTag:
    SECRET_KEY = "secret_key"
    PASSWORD = "password"
    CERTIFICATE = "certificate"
    API_TOKEN = "api_token"
    PRIVATE_KEY = "private_key"
    PII = "pii"
    CREDENTIAL = "credential"

@dataclass
class VulnerabilityKnowledgeNode:
    vuln_id: str
    vuln_type: str
    properties: Dict[str, Any] = field(default_factory=dict)

@dataclass
class InferenceRule:
    antecedent: str
    consequent: str
    confidence: float = 0.5

# VulnerabilityReporter：漏洞报告生成器
# 委托VulnerabilitySlicer（来自vuln_mgmt_slicer）提取最小上下文，
# 生成Markdown/JSON格式的可读报告。
# reporter将切片逻辑委托给外部模块
class VulnerabilityReporter:
    """
    从崩溃点提取最小上下文，生成面向开发者或审计文档的可读报告。

    Usage::

        reporter = VulnerabilityReporter()
        ctx = reporter.extract_context(
            crash_point=0x401234,
            binary_path="/path/to/binary",
        )
        report_md = reporter.generate_report(ctx, title="Use-After-Free in foo()")
    """

    def __init__(self):
        self._slicer = VulnerabilitySlicer()

    def extract_context(
        self, crash_point: int, binary_path: str = "", raw_disasm: str = "",
    ) -> VulnerabilityContext:
        """
        从崩溃点提取最小漏洞上下文。
        """
        if raw_disasm:
            taint, blocks = self._slicer.slice_with_disasm(crash_point, raw_disasm)
            instrs = self._slicer._parse_disasm(raw_disasm)
        else:
            taint, blocks = self._slicer.slice_from(crash_point, binary_path)
            raw = VulnerabilitySlicer._run_objdump(binary_path)
            instrs = self._slicer._parse_disasm(raw) if raw else []

        leaders = self._slicer._find_basic_block_leaders(instrs) if instrs else []
        bmap = self._slicer._build_block_map(leaders, instrs) if leaders else {}

        constraints: List[str] = []
        memory_accesses: List[Dict[str, Any]] = []

        cond_mnemonics = {
            "cmp", "test",
            "je", "jne", "jg", "jl", "jge", "jle",
            "ja", "jb", "jae", "jbe", "jz", "jnz",
        }

        for instr in instrs:
            blk = bmap.get(instr["address"], instr["address"])
            if blk not in blocks:
                continue
            text_raw = instr["text"]
            text = text_raw.lower()
            tokens = text.split()
            if tokens and tokens[0] in cond_mnemonics:
                constraints.append(text_raw.strip())

            if VulnerabilitySlicer._REGEX_MEM.search(text):
                mnem = tokens[0] if tokens else ""
                access = "read"
                parts = text.split(",", 1)
                if len(parts) == 2 and "[" in parts[0]:
                    access = "write"
                memory_accesses.append({
                    "address": instr["address"],
                    "type": access,
                })

        return VulnerabilityContext(
            basic_blocks=sorted(blocks),
            constraints=list(dict.fromkeys(constraints))[:50],
            memory_accesses=memory_accesses[:100],
        )

    @staticmethod
    def generate_report(
        context: VulnerabilityContext,
        title: str = "Vulnerability Analysis",
    ) -> str:
        """从上下文生成Markdown格式漏洞报告。"""
        lines: List[str] = []
        lines.append(f"# {title}")
        lines.append("")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        lines.append("## Summary")
        lines.append("")
        lines.append(f"- Affected basic blocks: **{len(context.basic_blocks)}**")
        lines.append(f"- Constraints (branches): **{len(context.constraints)}**")
        lines.append(f"- Memory accesses: **{len(context.memory_accesses)}**")
        lines.append("")

        lines.append("## Affected Basic Blocks")
        lines.append("")
        if context.basic_blocks:
            lines.append("| Address |")
            lines.append("| ------- |")
            for b in context.basic_blocks:
                lines.append(f"| `0x{b:x}` |")
        else:
            lines.append("*No blocks identified.*")
        lines.append("")

        lines.append("## Constraints / Conditions")
        lines.append("")
        if context.constraints:
            for c in context.constraints:
                lines.append(f"- `{c}`")
        else:
            lines.append("*No constraints identified.*")
        lines.append("")

        lines.append("## Memory Accesses")
        lines.append("")
        if context.memory_accesses:
            writes = 0
            reads = 0
            lines.append("| Address | Type |")
            lines.append("| ------- | ---- |")
            for m in context.memory_accesses:
                t = m.get("type", "unknown")
                lines.append(f"| `0x{m['address']:x}` | {t} |")
                if t == "write":
                    writes += 1
                else:
                    reads += 1
            lines.append("")
            lines.append(f"- Total reads: {reads}")
            lines.append(f"- Total writes: {writes}")
        else:
            lines.append("*No memory accesses identified.*")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_json_report(
        context: VulnerabilityContext,
        title: str = "Vulnerability Analysis",
    ) -> Dict[str, Any]:
        """生成JSON可序列化的报告字典。"""
        return {
            "title": title,
            "generated_at": datetime.now().isoformat(),
            "summary": {
                "affected_blocks": len(context.basic_blocks),
                "constraints": len(context.constraints),
                "memory_accesses": len(context.memory_accesses),
            },
            "basic_blocks": [f"0x{b:x}" for b in context.basic_blocks],
            "constraints": context.constraints,
            "memory_accesses": [
                {"address": f"0x{m['address']:x}", "type": m.get("type", "unknown")}
                for m in context.memory_accesses
            ],
        }

class VulnerabilityReasoner:
    """
    维护漏洞知识图谱，应用前向链推理规则推断利用路径或影响链。

    Usage::

        reasoner = VulnerabilityReasoner()
        reasoner.add_node(VulnerabilityKnowledgeNode("VULN-1", "buffer-overflow", {...}))
        reasoner.add_rule("buffer-overflow", "arbitrary-write", confidence=0.8)
        paths = reasoner.infer(["VULN-1"])
        results = reasoner.query("buffer")
    """

    def __init__(self):
        self.nodes: Dict[str, VulnerabilityKnowledgeNode] = {}
        self.rules: List[InferenceRule] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)
        self._infer_cache: Dict[Tuple[str, str], bool] = {}

    def add_node(self, node: VulnerabilityKnowledgeNode) -> None:
        self.nodes[node.vuln_id] = node
        if node.vuln_id not in self._adjacency:
            self._adjacency[node.vuln_id] = []

    def remove_node(self, vuln_id: str) -> bool:
        if vuln_id in self.nodes:
            del self.nodes[vuln_id]
            self._adjacency.pop(vuln_id, None)
            return True
        return False

    def add_rule(self, antecedent: str, consequent: str, confidence: float = 0.5) -> None:
        self.rules.append(InferenceRule(
            antecedent=antecedent, consequent=consequent,
            confidence=min(1.0, max(0.0, confidence)),
        ))
        self._infer_cache.pop((antecedent.lower(), consequent.lower()), None)

    def add_rules_batch(self, rules: List[Tuple[str, str, float]]) -> None:
        """批量添加规则。每项格式：(前件, 后件, 置信度)。"""
        for ant, con, conf in rules:
            self.add_rule(ant, con, conf)

    def remove_rules_by_antecedent(self, antecedent: str) -> int:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.antecedent != antecedent]
        ant_lower = antecedent.lower()
        stale = [(a, c) for (a, c) in self._infer_cache if a == ant_lower]
        for k in stale:
            del self._infer_cache[k]
        return before - len(self.rules)

    def infer(self, vuln_ids: List[str], max_rounds: int = 5) -> List[Dict[str, Any]]:
        """
        从vuln_ids出发，前向链遍历全部规则。

        返回推断结果列表，含置信度分数及来源追踪。
        """
        inferred: Dict[str, Dict[str, Any]] = {}

        seed_texts: Dict[str, str] = {}
        for vid in vuln_ids:
            node = self.nodes.get(vid)
            if node is None:
                continue
            seed_texts[vid] = self._node_text(node)

        active = set(vuln_ids)
        for _round in range(max_rounds):
            new: Dict[str, Dict[str, Any]] = {}
            for vid in list(active):
                text = seed_texts.get(vid, self._node_text(self.nodes.get(vid)))
                if not text:
                    continue
                for rule in self.rules:
                    cache_key = (text, rule.antecedent.lower())
                    if cache_key in self._infer_cache:
                        if not self._infer_cache[cache_key]:
                            continue
                    else:
                        hit = rule.antecedent.lower() in text.lower()
                        self._infer_cache[cache_key] = hit
                        if not hit:
                            continue
                    key = rule.consequent
                    if key not in inferred and key not in new:
                        new[key] = {
                            "consequent": rule.consequent,
                            "confidence": rule.confidence,
                            "from": vid,
                            "antecedent": rule.antecedent,
                        }
            if not new:
                break
            for k, v in new.items():
                inferred[k] = v
            active = set(new.keys())

        return sorted(inferred.values(), key=lambda x: x["confidence"], reverse=True)

    def infer_chain(self, vuln_id: str, max_depth: int = 5) -> List[Dict[str, Any]]:
        """
        从单个漏洞构建传递性后果链，返回完整规则激活路径。
        """
        chain: List[Dict[str, Any]] = []
        node = self.nodes.get(vuln_id)
        if node is None:
            return chain

        current_text = self._node_text(node)
        visited: Set[str] = set()

        for _ in range(max_depth):
            best_rule = None
            best_conf = 0.0
            for rule in self.rules:
                key = f"{rule.antecedent} -> {rule.consequent}"
                if key in visited:
                    continue
                if rule.antecedent.lower() in current_text.lower():
                    if rule.confidence > best_conf:
                        best_conf = rule.confidence
                        best_rule = rule
            if best_rule is None:
                break
            visited.add(f"{best_rule.antecedent} -> {best_rule.consequent}")
            chain.append({
                "antecedent": best_rule.antecedent,
                "consequent": best_rule.consequent,
                "confidence": best_rule.confidence,
            })
            current_text = best_rule.consequent

        return chain

    def query(
        self, pattern: str, node_type: Optional[str] = None, limit: int = 100,
    ) -> List[VulnerabilityKnowledgeNode]:
        """
        搜索知识图谱。pattern在vuln_id、vuln_type及属性值上做大小写不敏感匹配。
        """
        results: List[VulnerabilityKnowledgeNode] = []
        pat = pattern.lower()
        for node in self.nodes.values():
            if node_type and node.vuln_type != node_type:
                continue
            if pat in node.vuln_id.lower():
                results.append(node)
                continue
            if pat in node.vuln_type.lower():
                results.append(node)
                continue
            for v in node.properties.values():
                if pat in str(v).lower():
                    results.append(node)
                    break
            if len(results) >= limit:
                break
        return results

    def query_by_id(self, vuln_id: str) -> Optional[VulnerabilityKnowledgeNode]:
        return self.nodes.get(vuln_id)

    def query_by_property(self, key: str, value: Any) -> List[VulnerabilityKnowledgeNode]:
        results = []
        val_str = str(value).lower()
        for node in self.nodes.values():
            if key in node.properties and str(node.properties[key]).lower() == val_str:
                results.append(node)
        return results

    def get_related(self, vuln_id: str, max_depth: int = 2) -> List[VulnerabilityKnowledgeNode]:
        """查找max_depth跳内可达的全部节点。"""
        visited: Set[str] = set()
        result: List[VulnerabilityKnowledgeNode] = []
        queue: deque = deque([(vuln_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            node = self.nodes.get(current)
            if node:
                result.append(node)
            for neighbor in self._adjacency.get(current, []):
                if neighbor not in visited:
                    queue.append((neighbor, depth + 1))
        return result

    @staticmethod
    def _node_text(node: Optional[VulnerabilityKnowledgeNode]) -> str:
        # 内联辅助
        if node is None:
            return ""
        parts = [node.vuln_id, node.vuln_type]
        parts.extend(str(v) for v in node.properties.values())
        return " ".join(parts).lower()

    def stats(self) -> Dict[str, int]:
        return {"nodes": len(self.nodes), "rules": len(self.rules)}

class ExposureAnalyzer:
    """
    追踪敏感数据流，检测日志、网络传输、文件写等暴露路径。
    支持启发式（objdump）和源码（正则）两种分析模式。

    Usage::

        ea = ExposureAnalyzer()
        ea.tag_sensitive(0x402000, DataTag.SECRET_KEY)
        exposed = ea.check_all(0x402000, binary_path="/path/to/binary")
        print(ea.generate_exposure_report())
    """

    LOG_SINKS: Set[str] = {
        "printf", "fprintf", "syslog", "vsyslog", "__syslog_chk",
        "print", "puts", "fputs", "perror", "err", "warn",
        "log", "debug", "error", "trace",
        "LogMessage", "OutputDebugString",
    }
    NETWORK_SINKS: Set[str] = {
        "send", "sendto", "sendmsg", "write", "writev",
        "SSL_write", "curl_easy_perform",
        "WinHttpSendRequest", "HttpSendRequest", "WSASend",
    }
    FILE_SINKS: Set[str] = {
        "fwrite", "fputs", "fprintf", "write", "pwrite",
        "_write", "fputc", "putc",
        "ofstream", "WriteFile",
    }

    _REGEX_ADDR_LINE = re.compile(r"^\s*([0-9a-fA-F]+):")

    def __init__(self):
        self.tags: Dict[int, DataTag] = {}
        self.violations: List[DataFlowPath] = []

    def tag_sensitive(self, addr: int, tag: DataTag) -> None:
        self.tags[addr] = tag

    def tag_sensitive_batch(self, mappings: Dict[int, DataTag]) -> None:
        self.tags.update(mappings)

    @staticmethod
    def _run_objdump(binary_path: str) -> str:
        if not binary_path or not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(
                ["objdump", "-d", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    @staticmethod
    def _find_sinks(raw: str, sink_set: Set[str]) -> Set[int]:
        sinks: Set[int] = set()
        for line in raw.split("\n"):
            m = ExposureAnalyzer._REGEX_ADDR_LINE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            ll = line.lower()
            for func in sink_set:
                if f"<{func}" in ll or f"call.*{func}" in ll or f"@{func}" in ll:
                    sinks.add(addr)
        return sinks

    def trace_flow(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> DataFlowPath:
        """
        从source_addr向前追踪全部sink类别，返回含所有可达sink的DataFlowPath。
        """
        raw = raw_disasm or self._run_objdump(binary_path)
        all_sinks = self._find_sinks(
            raw, self.LOG_SINKS | self.NETWORK_SINKS | self.FILE_SINKS,
        )
        path = DataFlowPath(
            source=source_addr,
            source_label=self.tags.get(source_addr, "untagged"),
        )
        source_blk = source_addr & ~0xF
        for s in sorted(all_sinks):
            if s > source_blk:
                path.sinks.append(s)
        self.violations.append(path)
        return path

    def _check_exposure(
        self, source_addr: int, sink_set: Set[str], raw: str,
    ) -> bool:
        sinks = self._find_sinks(raw, sink_set)
        blk = source_addr & ~0xF
        return any(s > blk for s in sinks)

    def check_log_exposure(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> bool:
        raw = raw_disasm or self._run_objdump(binary_path)
        return self._check_exposure(source_addr, self.LOG_SINKS, raw) if raw else False

    def check_network_exposure(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> bool:
        raw = raw_disasm or self._run_objdump(binary_path)
        return self._check_exposure(source_addr, self.NETWORK_SINKS, raw) if raw else False

    def check_file_exposure(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> bool:
        raw = raw_disasm or self._run_objdump(binary_path)
        return self._check_exposure(source_addr, self.FILE_SINKS, raw) if raw else False

    def check_all(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> Dict[str, bool]:
        """同时执行三种暴露检查。"""
        raw = raw_disasm or self._run_objdump(binary_path)
        return {
            "log_exposure": self._check_exposure(source_addr, self.LOG_SINKS, raw),
            "network_exposure": self._check_exposure(source_addr, self.NETWORK_SINKS, raw),
            "file_exposure": self._check_exposure(source_addr, self.FILE_SINKS, raw),
        }

    @staticmethod
    def check_log_exposure_in_source(
        source_code: str, variable_name: str = "",
    ) -> List[Dict[str, Any]]:
        """扫描源码中传入日志函数的变量。"""
        findings: List[Dict[str, Any]] = []
        if not variable_name:
            return findings
        pat = re.compile(
            rf"(?:log|LOG|printf?|print|debug|trace|info|warn|error|fprintf)\s*\(\s*[^,)]*{re.escape(variable_name)}"
        )
        for m in pat.finditer(source_code):
            findings.append({"match": m.group(), "position": m.start(), "category": "log_exposure"})
        return findings

    @staticmethod
    def check_network_exposure_in_source(
        source_code: str, variable_name: str = "",
    ) -> List[Dict[str, Any]]:
        """扫描源码中传入网络函数的变量。"""
        findings: List[Dict[str, Any]] = []
        if not variable_name:
            return findings
        pat = re.compile(
            rf"(?:send|write|post|request|curl)\s*\(\s*[^,)]*{re.escape(variable_name)}"
        )
        for m in pat.finditer(source_code):
            findings.append({"match": m.group(), "position": m.start(), "category": "network_exposure"})
        return findings

    @staticmethod
    def check_file_exposure_in_source(
        source_code: str, variable_name: str = "",
    ) -> List[Dict[str, Any]]:
        """扫描源码中传入文件写函数的变量。"""
        findings: List[Dict[str, Any]] = []
        if not variable_name:
            return findings
        pat = re.compile(
            rf"(?:fwrite|fputs|fprintf|write|WriteFile|ofstream|<<)\s*\(\s*[^,)]*{re.escape(variable_name)}"
        )
        for m in pat.finditer(source_code):
            findings.append({"match": m.group(), "position": m.start(), "category": "file_exposure"})
        return findings

    def generate_exposure_report(self) -> Dict[str, Any]:
        tagged = len(self.tags)
        total_violations = len(self.violations)
        by_type: Dict[str, int] = defaultdict(int)
        for v in self.violations:
            by_type[v.source_label] += 1
        return {
            "tagged_sources": tagged,
            "total_violations": total_violations,
            "violations_by_type": dict(by_type),
            "violations": [
                {
                    "source": f"0x{v.source:x}",
                    "label": v.source_label,
                    "sinks": [f"0x{s:x}" for s in v.sinks],
                }
                for v in self.violations
            ],
        }

class CodeLocator:
    """
    在二进制文件（及提取的字符串/符号）中搜索与CVE、库或漏洞类别关联的代码模式。

    Usage::

        locator = CodeLocator()
        locator.register_cve_pattern("CVE-2023-1234", {
            "function_names": ["vuln_parse"],
            "code_patterns": [r"memcpy\\(.*,\\s*0\\)"],
            "version_strings": ["1.2.3"],
        })
        footprint = locator.find_affected_code
        all_impacts = locator.assess_impact("/bin/target")
    """

    _MAX_WORKERS = min(8, (os.cpu_count() or 4))

    def __init__(self):
        self._cve_patterns: Dict[str, Dict[str, Any]] = {}
        self._findings_cache: Dict[str, List[CVEFootprint]] = {}

    def register_cve_pattern(self, cve_id: str, pattern: Dict[str, Any]) -> None:
        """注册CVE指纹。

        pattern字段：
        - function_names : List[str]  -- 预期出现在二进制中的符号名
        - code_patterns  : List[str]  -- 用于strings输出的正则模式
        - version_strings: List[str]  -- 需匹配的字面版本子串
        - severity        : str       -- 信息性标签
        """
        self._cve_patterns[cve_id] = pattern
        self._findings_cache.pop(cve_id, None)

    def register_cve_patterns_batch(self, patterns: Dict[str, Dict[str, Any]]) -> None:
        for cve_id, pat in patterns.items():
            self.register_cve_pattern(cve_id, pat)

    def unregister_cve_pattern(self, cve_id: str) -> bool:
        if cve_id in self._cve_patterns:
            del self._cve_patterns[cve_id]
            self._findings_cache.pop(cve_id, None)
            return True
        return False

    def list_registered_cves(self) -> List[str]:
        return sorted(self._cve_patterns.keys())

    @staticmethod
    def _read_all_sources(binary_path: str) -> Tuple[str, str, str]:
        # 内联实现
        results = {}

        def _fetch(cmd, key):
            try:
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                results[key] = r.stdout if r.returncode == 0 else ""
            except Exception:
                results[key] = ""

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = [
                pool.submit(_fetch, ["strings", binary_path], "strings"),
                pool.submit(_fetch, ["nm", binary_path], "symbols"),
                pool.submit(_fetch, ["objdump", "-d", binary_path], "disasm"),
            ]
            for f in as_completed(futures):
                f.result()

        return results.get("strings", ""), results.get("symbols", ""), results.get("disasm", "")

    def find_affected_code(self, binary_path: str, cve_id: str) -> CVEFootprint:
        """判定cve_id是否影响binary_path。

        返回含置信度[0.0, 1.0]的CVEFootprint。
        """
        pattern = self._cve_patterns.get(cve_id)
        if pattern is None:
            return CVEFootprint(cve_id=cve_id, confidence=0.0)

        strings_raw, symbols_raw, disasm_raw = self._read_all_sources(binary_path)

        footprint = CVEFootprint(cve_id=cve_id)
        total_checks = 0.0
        passed_checks = 0.0

        for fname in pattern.get("function_names", []):
            total_checks += 1.0
            for line in symbols_raw.split("\n"):
                if fname in line:
                    m = re.match(r"^([0-9a-fA-F]+)\s", line.strip())
                    if m:
                        footprint.matched_functions.append(int(m.group(1), 16))
                        passed_checks += 0.5
                    else:
                        passed_checks += 0.5
                    break

        for cpat in pattern.get("code_patterns", []):
            total_checks += 1.0
            try:
                if re.search(cpat, strings_raw):
                    passed_checks += 1.0
                    footprint.matched_strings.append(cpat)
            except re.error:
                total_checks -= 1.0

        for cpat in pattern.get("code_patterns", []):
            total_checks += 1.0
            try:
                if re.search(cpat, disasm_raw):
                    passed_checks += 0.5
            except re.error:
                total_checks -= 1.0

        for vstr in pattern.get("version_strings", []):
            total_checks += 0.5
            if vstr in strings_raw:
                passed_checks += 0.5

        if total_checks > 0:
            footprint.confidence = min(1.0, passed_checks / total_checks)
        else:
            footprint.confidence = 0.0

        return footprint

    def assess_impact(self, binary_path: str) -> List[CVEFootprint]:
        """对所有已注册CVE模式评估binary_path影响。"""
        if binary_path in self._findings_cache:
            return self._findings_cache[binary_path]

        cve_ids = list(self._cve_patterns.keys())
        if not cve_ids:
            return []

        impacts: List[CVEFootprint] = []

        if len(cve_ids) <= 4:
            for cve_id in cve_ids:
                fp = self.find_affected_code(binary_path, cve_id)
                if fp.confidence > 0.0:
                    impacts.append(fp)
        else:
            with ThreadPoolExecutor(max_workers=self._MAX_WORKERS) as pool:
                future_map = {
                    pool.submit(self.find_affected_code, binary_path, cid): cid
                    for cid in cve_ids
                }
                for future in as_completed(future_map):
                    fp = future.result()
                    if fp.confidence > 0.0:
                        impacts.append(fp)

        impacts.sort(key=lambda x: x.confidence, reverse=True)
        self._findings_cache[binary_path] = impacts
        return impacts

    def assess_impact_for_cves(
        self, binary_path: str, cve_ids: List[str],
    ) -> List[CVEFootprint]:
        """仅对指定CVE子集评估影响。"""
        impacts: List[CVEFootprint] = []
        for cve_id in cve_ids:
            fp = self.find_affected_code(binary_path, cve_id)
            if fp.confidence > 0.0:
                impacts.append(fp)
        impacts.sort(key=lambda x: x.confidence, reverse=True)
        return impacts

    def generate_impact_report(self, impacts: List[CVEFootprint]) -> str:
        """生成CVE影响评估的Markdown摘要。"""
        lines: List[str] = []
        lines.append("# CVE Impact Assessment Report")
        lines.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        if not impacts:
            lines.append("*No matching CVEs found.*")
            return "\n".join(lines)

        lines.append("| CVE ID | Confidence | Matched Functions | Matched Strings |")
        lines.append("| ------ | ---------- | ----------------- | --------------- |")
        for fp in impacts:
            lines.append(
                f"| {fp.cve_id} | {fp.confidence:.0%} | "
                f"{len(fp.matched_functions)} | {len(fp.matched_strings)} |"
            )
        lines.append("")
        return "\n".join(lines)

class _RateLimiter:
    """令牌桶限速器：线程安全，防止对外部API的突发请求被429封禁。"""
    def __init__(self, tokens_per_sec: float = 10.0, burst: int = 10):
        self._rate = tokens_per_sec
        self._burst = burst
        self._tokens = float(burst)
        self._last_fill = time.monotonic()
        self._lock = threading.Lock()

    def wait_acquire(self, timeout: float = 30.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_fill
                self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
                self._last_fill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
            time.sleep(0.1)
        return False

class ThreatIntelClient:
    """
    MISP、AlienVault OTX、NVD的统一威胁情报查询客户端。

    Usage::

        client = ThreatIntelClient()
        client.configure_misp(url="https://misp.local", api_key="...")
        result = client.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
        cve = client.lookup_cve
    """

    _USER_AGENT = "BinMind/2.0"
    _DEFAULT_TIMEOUT = 30
    _MAX_CACHE_ENTRIES = 2048

    def __init__(self):
        self._misp_url: str = ""
        self._misp_key: str = ""
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._cache_ttl: int = 3600
        self._cache_timestamps: Dict[str, float] = {}
        self._rate_limiter = _RateLimiter(tokens_per_sec=10.0, burst=10)

    def configure_misp(self, url: str, api_key: str) -> None:
        self._misp_url = url.rstrip("/")
        self._misp_key = api_key

    def configure_cache(self, ttl_seconds: int) -> None:
        self._cache_ttl = ttl_seconds

    def lookup_misp(
        self, indicator: str, indicator_type: str = "sha256",
    ) -> Dict[str, Any]:
        """在MISP中搜索IOC（哈希、域名、IP等）。

        Parameters
        ----------
        indicator : str
            IOC值。
        indicator_type : str
            MISP属性类型（sha256, md5, domain, ip-src等）。

        Returns
        -------
        含source, indicator, type, found, attributes, [error]的字典。
        """
        cache_key = f"misp:{indicator_type}:{indicator}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "source": "misp", "indicator": indicator,
            "type": indicator_type, "found": False, "attributes": [],
        }

        if not self._misp_url:
            result["error"] = "MISP not configured"
            return result

        if not self._rate_limiter.wait_acquire(timeout=15.0):
            result["error"] = "Rate limit exceeded"
            return result

        try:
            api_url = f"{self._misp_url}/attributes/restSearch"
            payload = json.dumps({
                "returnFormat": "json", "value": indicator,
                "type": indicator_type,
            }).encode("utf-8")

            req = urllib.request.Request(
                api_url, data=payload,
                headers={
                    "Authorization": self._misp_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": self._USER_AGENT,
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._DEFAULT_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
                parsed = json.loads(body)
                attrs = parsed.get("response", {}).get("Attribute", [])
                if isinstance(attrs, list) and attrs:
                    result["found"] = True
                    for a in attrs:
                        result["attributes"].append({
                            "category": a.get("category", ""),
                            "type": a.get("type", ""),
                            "value": a.get("value", ""),
                            "event_id": a.get("event_id", ""),
                            "comment": a.get("comment", ""),
                            "to_ids": a.get("to_ids", False),
                        })
        except urllib.error.HTTPError as e:
            result["error"] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            result["error"] = str(e.reason) if hasattr(e, "reason") else str(e)
        except Exception as e:
            result["error"] = str(e)

        self._set_cache(cache_key, result)
        return result

    def lookup_otx(self, indicator: str) -> Dict[str, Any]:
        """在AlienVault OTX中查询IOC。"""
        cache_key = f"otx:{indicator}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "source": "alienvault_otx", "indicator": indicator,
            "found": False, "pulses": [], "type": "",
        }

        if not self._rate_limiter.wait_acquire(timeout=15.0):
            result["error"] = "Rate limit exceeded"
            return result

        try:
            encoded = urllib.request.quote(indicator)
            url = f"https://otx.alienvault.com/api/v1/indicators/general/{encoded}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": self._USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=self._DEFAULT_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
                parsed = json.loads(body)

                result["type"] = parsed.get("type", "")
                pulses = parsed.get("pulse_info", {}).get("pulses", [])
                if pulses:
                    result["found"] = True
                    for p in pulses:
                        result["pulses"].append({
                            "id": p.get("id", ""), "name": p.get("name", ""),
                            "description": p.get("description", ""),
                            "created": p.get("created", ""),
                            "modified": p.get("modified", ""),
                            "tags": p.get("tags", []),
                            "adversary": p.get("adversary", ""),
                            "targeted_countries": p.get("targeted_countries", []),
                            "references": p.get("references", []),
                        })
        except urllib.error.HTTPError as e:
            if e.code == 404:
                result["found"] = False
            else:
                result["error"] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            result["error"] = str(e.reason) if hasattr(e, "reason") else str(e)
        except Exception as e:
            result["error"] = str(e)

        self._set_cache(cache_key, result)
        return result

    def lookup_otx_pulse_details(self, pulse_id: str) -> Dict[str, Any]:
        """获取单个OTX pulse的详细信息。"""
        cache_key = f"otx_pulse:{pulse_id}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {"pulse_id": pulse_id, "found": False}
        try:
            url = f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": self._USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=self._DEFAULT_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
                parsed = json.loads(body)
                result.update({
                    "found": True, "name": parsed.get("name", ""),
                    "description": parsed.get("description", ""),
                    "indicators": [
                        i.get("indicator", "") for i in parsed.get("indicators", [])
                    ],
                    "tags": parsed.get("tags", []),
                    "references": parsed.get("references", []),
                })
        except Exception as e:
            result["error"] = str(e)

        self._set_cache(cache_key, result)
        return result

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        # 保持上下文连贯性，不拆分
        """查询NVD REST API 2.0获取CVE详情。"""
        cache_key = f"nvd:{cve_id}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "cve_id": cve_id, "description": "", "severity": "",
            "cvss_score": 0.0, "cvss_vector": "", "references": [],
            "weaknesses": [], "published_date": "", "found": False,
        }

        if not self._rate_limiter.wait_acquire(timeout=15.0):
            result["error"] = "Rate limit exceeded"
            return result

        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json", "User-Agent": self._USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=self._DEFAULT_TIMEOUT) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.decompress(raw)
                body = raw.decode("utf-8")
                parsed = json.loads(body)

                vulns = parsed.get("vulnerabilities", [])
                if vulns:
                    result["found"] = True
                    vuln = vulns[0].get("cve", {})

                    for desc in vuln.get("descriptions", []):
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break

                    result["published_date"] = vuln.get("published", "")

                    for w in vuln.get("weaknesses", []):
                        for wd in w.get("description", []):
                            if wd.get("lang") == "en":
                                result["weaknesses"].append(wd.get("value", ""))

                    metrics = vuln.get("metrics", {})
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        cvss_list = metrics.get(version, [])
                        if cvss_list:
                            cvss_data = cvss_list[0].get("cvssData", {})
                            result["cvss_score"] = cvss_data.get("baseScore", 0.0)
                            result["severity"] = cvss_data.get("baseSeverity", "")
                            result["cvss_vector"] = cvss_data.get("vectorString", "")
                            break

                    for ref in vuln.get("references", []):
                        result["references"].append({
                            "url": ref.get("url", ""),
                            "source": ref.get("source", ""),
                            "tags": ref.get("tags", []),
                        })
        except urllib.error.HTTPError as e:
            result["error"] = f"HTTP {e.code}: {e.reason}"
        except urllib.error.URLError as e:
            result["error"] = str(e.reason) if hasattr(e, "reason") else str(e)
        except Exception as e:
            result["error"] = str(e)

        self._set_cache(cache_key, result)
        return result

    def lookup_hash(self, hash_value: str) -> Dict[str, Dict[str, Any]]:
        """跨所有已配置威胁情报源查询文件哈希。"""
        results: Dict[str, Dict[str, Any]] = {}
        if self._misp_url:
            results["misp"] = self.lookup_misp(hash_value, "sha256")
        results["otx"] = self.lookup_otx(hash_value)
        return results

    def enrich_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """用威胁情报数据富化漏洞字典。"""
        enriched = dict(vuln_data)
        if "file_hash" in vuln_data:
            enriched["threat_intel"] = self.lookup_hash(vuln_data["file_hash"])
        if "cve_id" in vuln_data:
            enriched["cve_details"] = self.lookup_cve(vuln_data["cve_id"])
        if "iocs" in vuln_data:
            enriched["ioc_results"] = {
                ioc: self.lookup_otx(ioc) for ioc in vuln_data["iocs"]
            }
        return enriched

    def _check_cache(self, key: str) -> Optional[Dict[str, Any]]:
        ts = self._cache_timestamps.get(key, 0)
        if time.time() - ts < self._cache_ttl:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
        else:
            self._cache.pop(key, None)
            self._cache_timestamps.pop(key, None)
        return None

    def _set_cache(self, key: str, value: Dict[str, Any]) -> None:
        if len(self._cache) >= self._MAX_CACHE_ENTRIES:
            oldest = next(iter(self._cache))
            self._cache.pop(oldest)
            self._cache_timestamps.pop(oldest, None)
        self._cache[key] = value
        self._cache_timestamps[key] = time.time()

    def clear_cache(self) -> int:
        count = len(self._cache)
        self._cache.clear()
        self._cache_timestamps.clear()
        return count

    def stats(self) -> Dict[str, Any]:
        return {
            "cache_entries": len(self._cache),
            "cache_ttl": self._cache_ttl,
            "misp_configured": bool(self._misp_url),
        }

class VersionExtractor:
    """
    通过strings输出和符号表分析的启发式模式匹配，从二进制中提取库及组件版本信息。

    Usage::

        ve = VersionExtractor()
        versions = ve.extract(binary_path="/bin/target")
        # -> {"openssl": "1.1.1q", "zlib": "1.2.11", ...}
    """

    _LIB_PATTERNS: List[Tuple[str, re.Pattern, int]] = [
        ("openssl", re.compile(r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]*)", re.IGNORECASE), 1),
        ("openssl", re.compile(r"SSLeay\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("zlib", re.compile(r"(?:zlib|deflate)\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("curl", re.compile(r"(?:lib)?curl[/\s]+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("expat", re.compile(r"expat[_\s]+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("sqlite", re.compile(r"SQLite\s+(?:version\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("pcre", re.compile(r"PCRE\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), 1),
        ("libpthread", re.compile(r"(?:GNU\s+)?libpthread[-\s]+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE), 1),
        ("lzma", re.compile(r"(?:xz|lzma)\s+(?:utils\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("bzip2", re.compile(r"bzip2[-\s]+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("libpng", re.compile(r"libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("libjpeg", re.compile(r"(?:lib)?jpe?g\s+(?:version\s+)?(\d+[a-z]?)", re.IGNORECASE), 1),
        ("libxml2", re.compile(r"libxml2\s+(?:version\s+)?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("glibc", re.compile(r"GNU C Library\s+.*?release version (\d+\.\d+)", re.IGNORECASE), 1),
        ("glibc", re.compile(r"glibc\s+(\d+\.\d+)", re.IGNORECASE), 1),
        ("libressl", re.compile(r"LibreSSL\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("wolfssl", re.compile(r"wolfSSL\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("gnutls", re.compile(r"GnuTLS\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("python", re.compile(r"Python\s+(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
        ("perl", re.compile(r"perl\s+(?:v)?(\d+\.\d+\.\d+)", re.IGNORECASE), 1),
    ]

    _GENERIC_VERSION = re.compile(
        r"(?:version|v(?:er)?)[\s:=]+(\d+\.\d+(?:\.\d+)?(?:[a-z]\d*)?)",
        re.IGNORECASE,
    )
    _GENERIC_SIMPLE = re.compile(r"\b(\d+)\.(\d+)(?:\.(\d+))?\b")

    def __init__(self):
        self._custom_patterns: List[Tuple[str, re.Pattern, int]] = []

    def add_custom_pattern(self, library: str, regex: str, group: int = 1) -> None:
        self._custom_patterns.append((library, re.compile(regex, re.IGNORECASE), group))

    def extract(self, binary_path: str = "", strings_text: str = "") -> Dict[str, str]:
        if strings_text:
            text = strings_text
        elif binary_path:
            text = self._fetch_strings(binary_path)
        else:
            return {}
        if not text:
            return {}
        versions: Dict[str, str] = {}
        all_patterns = self._LIB_PATTERNS + self._custom_patterns
        for lib, pat, grp in all_patterns:
            if lib in versions:
                continue
            m = pat.search(text)
            if m:
                try:
                    versions[lib] = m.group(grp)
                except IndexError:
                    versions[lib] = m.group(0)
        for lib in {"openssl", "zlib", "curl", "sqlite", "pcre", "expat"}:
            if lib in versions:
                continue
            for m in re.finditer(
                rf"{lib}.*?{self._GENERIC_VERSION.pattern}", text, re.IGNORECASE,
            ):
                v = self._GENERIC_VERSION.search(m.group())
                if v:
                    versions[lib] = v.group(1)
                    break
        return versions

    @staticmethod
    def _fetch_strings(binary_path: str) -> str:
        # 内联提取
        if not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(
                ["strings", binary_path],
                capture_output=True, text=True, timeout=60,
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def extract_all_versions(self, text: str) -> List[str]:
        seen: Set[str] = set()
        for m in self._GENERIC_SIMPLE.finditer(text):
            seen.add(m.group())
        try:
            return sorted(seen, key=lambda v: [int(x) for x in v.split(".")])
        except (ValueError, TypeError):
            return sorted(seen)

    def extract_with_confidence(
        self, binary_path: str = "", strings_text: str = "",
    ) -> Dict[str, Tuple[str, float]]:
        versions = self.extract(binary_path=binary_path, strings_text=strings_text)
        result: Dict[str, Tuple[str, float]] = {}
        for lib, ver in versions.items():
            explicit = any(lib == p[0] for p in self._LIB_PATTERNS + self._custom_patterns)
            result[lib] = (ver, 0.9 if explicit else 0.5)
        return result

class VersionedVulnChecker:
    """
    给定库名及版本，查询OSV.dev和NVD，判定是否涉及已知漏洞。

    Usage::

        checker = VersionedVulnChecker()
        vulns = checker.check("openssl", "1.1.1q")
        for v in vulns:
            print(v["cve_id"], v["severity"])
    """

    _OSV_QUERY_URL = "https://api.osv.dev/v1/query"
    _USER_AGENT = "BinMind/2.0"
    _DEFAULT_TIMEOUT = 30

    def __init__(self):
        self._cache: Dict[str, List[Dict[str, Any]]] = {}
        self._nvd_client: Optional[ThreatIntelClient] = None

    @property
    def nvd_client(self) -> "ThreatIntelClient":
        if self._nvd_client is None:
            self._nvd_client = ThreatIntelClient()
        return self._nvd_client

    def check(
        self, library: str, version: str, ecosystem: str = "",
    ) -> List[Dict[str, Any]]:
        """向OSV.dev查询指定库特定版本的已知漏洞。

        Parameters
        ----------
        library : str
            包/库名称。
        version : str
            版本号（如"1.1.1q"）。
        ecosystem : str
            OSV生态标识符（如"Debian:11"、"OSS-Fuzz"，留空则自动）。

        Returns
        -------
        漏洞字典列表。
        """
        cache_key = f"{library}@{version}:{ecosystem}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        vulns: List[Dict[str, Any]] = []

        try:
            query_pkg: Dict[str, str] = {"name": library}
            if ecosystem:
                query_pkg["ecosystem"] = ecosystem
            query_body = {"package": query_pkg, "version": version}
            data = json.dumps(query_body).encode("utf-8")

            req = urllib.request.Request(
                self._OSV_QUERY_URL, data=data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": self._USER_AGENT,
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self._DEFAULT_TIMEOUT) as resp:
                body = resp.read().decode("utf-8")
                parsed = json.loads(body)

                for v in parsed.get("vulns", []):
                    vuln: Dict[str, Any] = {
                        "library": library, "version": version,
                        "osv_id": v.get("id", ""), "cve_id": "",
                        "summary": v.get("summary", ""),
                        "details": v.get("details", v.get("summary", "")),
                        "severity": "unknown",
                        "aliases": v.get("aliases", []),
                        "affected_ranges": [],
                    }

                    for alias in v.get("aliases", []):
                        if alias.upper().startswith("CVE-"):
                            vuln["cve_id"] = alias
                            break

                    db_specific = v.get("database_specific", {})
                    vuln["severity"] = db_specific.get("severity", "unknown")

                    for aff in v.get("affected", []):
                        for rng in aff.get("ranges", []):
                            vuln["affected_ranges"].append({
                                "type": rng.get("type", ""),
                                "repo": rng.get("repo", ""),
                                "events": rng.get("events", []),
                            })

                    vulns.append(vuln)

        except urllib.error.HTTPError as e:
            logger.warning(f"OSV query failed for {library}: HTTP {e.code}")
        except urllib.error.URLError as e:
            logger.warning(f"OSV query failed for {library}: {e}")
        except Exception as e:
            logger.warning(f"OSV query failed for {library}: {e}")

        self._cache[cache_key] = vulns
        return vulns

    def check_batch(
        self, packages: Dict[str, str], ecosystem: str = "",
    ) -> Dict[str, List[Dict[str, Any]]]:
        results: Dict[str, List[Dict[str, Any]]] = {}
        for lib, ver in packages.items():
            key = f"{lib}@{ver}"
            results[key] = self.check(lib, ver, ecosystem)
        return results

    def enrich_with_nvd(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        enriched = []
        for v in vulns:
            entry = dict(v)
            cve_id = entry.get("cve_id", "")
            if cve_id:
                nvd = self.nvd_client.lookup_cve(cve_id)
                entry["nvd"] = {
                    "cvss_score": nvd.get("cvss_score", 0.0),
                    "severity": nvd.get("severity", ""),
                    "description": nvd.get("description", ""),
                    "references": nvd.get("references", []),
                    "published": nvd.get("published_date", ""),
                }
                if nvd.get("cvss_score", 0.0) > 0:
                    entry["severity"] = nvd.get("severity", entry["severity"])
            enriched.append(entry)
        return enriched

    def clear_cache(self) -> int:
        count = len(self._cache)
        self._cache.clear()
        return count

    def stats(self) -> Dict[str, int]:
        return {"cached_queries": len(self._cache)}

class SBOMGenerator:
    """
    从二进制分析提取的组件数据生成CycloneDX和SPDX格式的SBOM。

    Usage::

        gen = SBOMGenerator()
        gen.add_component("openssl", "1.1.1q", "library")
        gen.add_component("zlib", "1.2.11", "library")
        gen.add_component("myapp", "2.0.0", "application")
        spdx_json = gen.export_spdx()
        cyclonedx_json = gen.export_cyclonedx()
        gen.write("sbom.spdx.json", format="spdx")
    """

    def __init__(self):
        self.components: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "tool": "BinMind", "version": "2.0",
            "generated_at": datetime.now().isoformat(),
        }

    def add_component(
        self, name: str, version: str = "unknown", comp_type: str = "library", **kwargs,
    ) -> None:
        component: Dict[str, Any] = {"name": name, "version": version, "type": comp_type}
        component.update(kwargs)
        self.components.append(component)

    def add_components_batch(self, components: List[Dict[str, Any]]) -> None:
        for c in components:
            self.add_component(**c)

    def remove_component(self, name: str) -> int:
        before = len(self.components)
        self.components = [c for c in self.components if c["name"] != name]
        return before - len(self.components)

    def clear_components(self) -> None:
        self.components.clear()

    def export_cyclonedx(self, version: str = "1.4") -> Dict[str, Any]:
        doc: Dict[str, Any] = {
            "bomFormat": "CycloneDX", "specVersion": version,
            "serialNumber": (
                f"urn:uuid:{hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:32]}"
            ),
            "version": 1,
            "metadata": {
                "timestamp": self.metadata["generated_at"],
                "tools": [{"name": self.metadata["tool"], "version": self.metadata["version"]}],
                "component": {"name": "root", "type": "application", "version": "1.0"},
            },
            "components": [],
        }

        for comp in self.components:
            item: Dict[str, Any] = {
                "type": comp.get("type", "library"),
                "name": comp["name"], "version": comp.get("version", "unknown"),
            }
            if "supplier" in comp:
                item["supplier"] = {"name": comp["supplier"]}
            if "purl" in comp:
                item["purl"] = comp["purl"]
            if "cpe" in comp:
                item["cpe"] = comp["cpe"]
            if "licenses" in comp:
                item["licenses"] = [{"license": {"name": lic}} for lic in comp["licenses"]]
            if "hashes" in comp:
                item["hashes"] = comp["hashes"]
            if "description" in comp:
                item["description"] = comp["description"]
            doc["components"].append(item)

        return doc

    def export_cyclonedx_string(self, version: str = "1.4", indent: int = 2) -> str:
        return json.dumps(self.export_cyclonedx(version), indent=indent)

    def export_spdx(self, version: str = "SPDX-2.3") -> Dict[str, Any]:
        ns_suffix = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]
        doc: Dict[str, Any] = {
            "spdxVersion": version, "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": f"https://binmind.local/spdx/{ns_suffix}",
            "name": "BinMind SBOM",
            "creationInfo": {
                "created": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creators": [f"Tool: {self.metadata['tool']}-{self.metadata['version']}"],
            },
            "packages": [], "relationships": [],
        }

        for i, comp in enumerate(self.components):
            pkg_id = f"SPDXRef-Package-{i}"
            pkg: Dict[str, Any] = {
                "SPDXID": pkg_id, "name": comp["name"],
                "versionInfo": comp.get("version", "unknown"),
                "supplier": comp.get("supplier", "NOASSERTION"),
                "downloadLocation": comp.get("downloadLocation", "NOASSERTION"),
                "filesAnalyzed": False,
                "licenseConcluded": (
                    " AND ".join(comp["licenses"]) if "licenses" in comp else "NOASSERTION"),
                "licenseDeclared": (
                    " AND ".join(comp["licenses"]) if "licenses" in comp else "NOASSERTION"),
                "copyrightText": comp.get("copyrightText", "NOASSERTION"),
            }
            if "description" in comp:
                pkg["description"] = comp["description"]
            if "homepage" in comp:
                pkg["homepage"] = comp["homepage"]
            if "checksums" in comp:
                pkg["checksums"] = comp["checksums"]
            if "externalRefs" in comp:
                pkg["externalRefs"] = comp["externalRefs"]
            doc["packages"].append(pkg)
            doc["relationships"].append({
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": pkg_id,
                "relationshipType": "DESCRIBES",
            })

        return doc

    def export_spdx_string(self, version: str = "SPDX-2.3", indent: int = 2) -> str:
        return json.dumps(self.export_spdx(version), indent=indent)

    def write(self, path: str, format: str = "spdx", version: str = "") -> str:
        if format == "spdx":
            content = self.export_spdx_string(version=version or "SPDX-2.3")
        elif format == "cyclonedx":
            content = self.export_cyclonedx_string(version=version or "1.4")
        else:
            raise ValueError(f"Unsupported SBOM format: {format}. Use 'spdx' or 'cyclonedx'.")
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return os.path.abspath(path)

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = defaultdict(int)
        for c in self.components:
            by_type[c.get("type", "library")] += 1
        return {
            "total_components": len(self.components),
            "by_type": dict(by_type),
            "formats_available": ["spdx", "cyclonedx"],
        }

# analyze_supply_chain：端到端供应链安全分析
# 1.提取链接库 2.提取版本 3.OSV.dev查询 4.可选NVD富化 5.SBOM生成
# nm前缀提取可能遗漏动态加载的库
def analyze_supply_chain(
    binary_path: str, enable_osv_check: bool = True,
    enable_nvd_enrich: bool = False,
) -> Dict[str, Any]:
    """对binary_path执行完整供应链安全分析。

    步骤：
    1. 提取链接库
    2. 提取版本
    3. 查询OSV.dev已知漏洞
    4. 可选NVD数据富化
    5. 生成SBOM
    """
    extractor = VersionExtractor()
    checker = VersionedVulnChecker()
    sbom_gen = SBOMGenerator()

    libs: List[str] = []
    try:
        r = subprocess.run(["nm", binary_path], capture_output=True, text=True, timeout=30)
        symbols = r.stdout
        prefixes_lib = {"openssl": "SSL_", "zlib": "zlib", "curl": "curl_",
                       "json": "json_", "expat": "XML_", "sqlite": "sqlite3_",
                       "pcre": "pcre_", "pthread": "pthread_", "lzma": "lzma_", "bz2": "BZ2_"}
        for lib, prefix in prefixes_lib.items():
            if prefix in symbols:
                libs.append(lib)
    except Exception:
        _logger.debug("suppressed", exc_info=True)

    versions = extractor.extract(binary_path=binary_path)
    for lib in libs:
        if lib not in versions:
            versions[lib] = "unknown"

    vulns: List[Dict[str, Any]] = []
    if enable_osv_check:
        for lib, ver in versions.items():
            if ver == "unknown":
                continue
            vulns.extend(checker.check(lib, ver))

    if enable_nvd_enrich and vulns:
        vulns = checker.enrich_with_nvd(vulns)

    for lib, ver in versions.items():
        sbom_gen.add_component(lib, ver, "library")
    sbom_gen.add_component(os.path.basename(binary_path), "unknown", "application")

    return {
        "binary_path": binary_path, "static_libraries": libs,
        "versions": versions, "vulnerabilities": vulns,
        "sbom": {"cyclonedx": sbom_gen.export_cyclonedx(), "spdx": sbom_gen.export_spdx()},
        "summary": sbom_gen.summary(), "generated_at": datetime.now().isoformat(),
    }
