# 漏洞管理与知识图谱子系统。
# CVE关联、推理驱动的利用链构建、合规映射、威胁情报整合。

from typing import Dict, Any, List, Optional, Set, Tuple, Callable
import logging
import re
import os
import json as _json
import subprocess
import hashlib
import time
import threading
import urllib.request
import urllib.error
import gzip
from datetime import datetime
from collections import defaultdict, deque
from dataclasses import dataclass, field

_logger = logging.getLogger(__name__)
logger = _logger
json = _json


# Data classes


class VulnerabilityContext:
    """Vulnerability context containing basic blocks, constraints, and memory accesses."""

    __slots__ = ("basic_blocks", "constraints", "memory_accesses")

    def __init__(
        self,
        basic_blocks: List[int],
        constraints: List[str],
        memory_accesses: List[Dict[str, Any]],
    ):
        self.basic_blocks = basic_blocks or []
        self.constraints = constraints or []
        self.memory_accesses = memory_accesses or []


@dataclass
class DataFlowPath:
    """A path from a taint source to one or more sinks."""

    source: int
    sinks: List[int] = field(default_factory=list)
    source_label: str = ""
    intermediate_addrs: List[int] = field(default_factory=list)


@dataclass
class CVEFootprint:
    """Evidence that a CVE affects the binary under analysis."""

    cve_id: str
    matched_functions: List[int] = field(default_factory=list)
    matched_strings: List[str] = field(default_factory=list)
    confidence: float = 0.0


class DataTag:
    """Labels for sensitive data categories."""

    SECRET_KEY = "secret_key"
    PASSWORD = "password"
    CERTIFICATE = "certificate"
    API_TOKEN = "api_token"
    PRIVATE_KEY = "private_key"
    PII = "pii"
    CREDENTIAL = "credential"


@dataclass
class VulnerabilityKnowledgeNode:
    """A node in the vulnerability knowledge graph."""

    vuln_id: str
    vuln_type: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InferenceRule:
    """A rule for chaining vulnerability observations into exploit paths."""

    antecedent: str
    consequent: str
    confidence: float = 0.5


# VulnerabilitySlicer——从崩溃点反向切片至污点源


class VulnerabilitySlicer:
    """
    Performs backward slicing from a crash / exploit point to identify
    the minimal set of instructions and basic blocks that influence the
    vulnerability.  Tracks taint through register def-use chains and
    memory operands.
    """

    _WRITE_MNEMONICS: Set[str] = {
        "mov", "movsx", "movzx", "movsxd", "lea",
        "add", "sub", "xor", "and", "or", "shl", "shr", "sar",
        "pop", "inc", "dec", "not", "neg",
        "mul", "imul", "div", "idiv",
        "call", "xchg", "cmpxchg",
        "bswap", "bt", "bts", "btr", "btc",
    }

    _READ_MNEMONICS: Set[str] = {
        "mov", "cmp", "test", "add", "sub", "xor", "and", "or",
        "push", "shl", "shr", "sar",
        "mul", "imul", "div", "idiv",
        "jmp", "je", "jne", "jg", "jl", "jge", "jle",
        "ja", "jb", "jae", "jbe", "jz", "jnz",
        "js", "jns", "jo", "jno",
        "call", "ret", "xchg", "cmpxchg",
        "movsx", "movzx", "movsxd",
    }

    _TAINT_SOURCES: Set[str] = {
        "read", "fread", "recv", "recvfrom", "recvmsg",
        "scanf", "fscanf", "sscanf",
        "gets", "fgets", "getchar", "getc", "fgetc",
        "readline", "curl_easy_perform", "SSL_read",
        "memcpy", "strcpy", "strncpy",
        "argv", "getenv",
    }

    _REGEX_REG = re.compile(
        r"%?(?:e?[ra]?[abcd]x|e?[sd]i|[er]?[sb]p|r\d+[dwb]?|[er]?ip|e?flags|[xyz]mm\d+|st\(\d+\))",
        re.IGNORECASE,
    )
    _REGEX_MEM = re.compile(r"\[[^\]]*\]")
    _REGEX_ADDR_LINE = re.compile(r"^\s*([0-9a-fA-F]+):")
    _REGEX_HEX_TARGET = re.compile(r"(?:0x)?([0-9a-fA-F]+)")

    # ---- helpers -------------------------------------------------------

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

    def _parse_disasm(self, raw: str) -> List[Dict[str, Any]]:
        instrs: List[Dict[str, Any]] = []
        for line in raw.split("\n"):
            m = self._REGEX_ADDR_LINE.match(line)
            if m:
                instrs.append({"address": int(m.group(1), 16), "text": line.strip()})
            elif instrs:
                instrs[-1]["text"] += " " + line.strip()
        return instrs

    def _find_basic_block_leaders(self, instrs: List[Dict[str, Any]]) -> List[int]:
        leaders: Set[int] = set()
        if not instrs:
            return []
        leaders.add(instrs[0]["address"])
        addrs = {i["address"] for i in instrs}
        branch_mnems = {
            "jmp", "je", "jne", "jg", "jl", "jge", "jle",
            "ja", "jb", "jae", "jbe", "jz", "jnz",
            "js", "jns", "jo", "jno", "jcxz", "loop",
            "call", "ret", "retn", "iret", "sysret",
        }
        for idx, instr in enumerate(instrs):
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            if tokens[0] in branch_mnems:
                tm = self._REGEX_HEX_TARGET.search(text)
                if tm:
                    tgt = int(tm.group(1), 16)
                    if tgt in addrs:
                        leaders.add(tgt)
                if idx + 1 < len(instrs):
                    leaders.add(instrs[idx + 1]["address"])
        return sorted(leaders)

    @staticmethod
    def _build_block_map(leaders: List[int], instrs: List[Dict[str, Any]]) -> Dict[int, int]:
        bmap: Dict[int, int] = {}
        n = len(leaders)
        last_addr = instrs[-1]["address"] + 0x100 if instrs else 0
        for i, leader in enumerate(leaders):
            end = leaders[i + 1] if i + 1 < n else last_addr
            for a in range(leader, end):
                bmap[a] = leader
        return bmap

    # ---- main slicing logic --------------------------------------------

    def slice_from(
        self,
        crash_point: int,
        binary_path: str = "",
        max_depth: int = 512,
    ) -> Tuple[Set[int], Set[int]]:
        """Backward slice from *crash_point*.

        Returns (taint_sources, affected_blocks).
        """
        raw = self._run_objdump(binary_path)
        instrs = self._parse_disasm(raw) if raw else []
        leaders = self._find_basic_block_leaders(instrs) if instrs else []
        bmap = self._build_block_map(leaders, instrs) if leaders else {}

        taint_sources: Set[int] = set()
        affected_blocks: Set[int] = set()

        if crash_point:
            affected_blocks.add(bmap.get(crash_point, crash_point))

        if not instrs:
            base = crash_point & ~0xF
            for off in range(0, 0x100, 0x10):
                affected_blocks.add(max(0, base - off))
            return taint_sources, affected_blocks

        # build def-use maps
        defs: Dict[str, List[int]] = defaultdict(list)
        uses: Dict[str, List[int]] = defaultdict(list)

        for instr in instrs:
            addr = instr["address"]
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            mnem = tokens[0]
            regs = [r.lstrip("%").lower() for r in self._REGEX_REG.findall(text)]
            if mnem in self._WRITE_MNEMONICS and regs:
                defs[regs[0]].append(addr)
                for r in regs[1:]:
                    uses[r].append(addr)
            elif mnem in self._READ_MNEMONICS:
                for r in regs:
                    uses[r].append(addr)
            if self._REGEX_MEM.search(text):
                for r in regs:
                    if r not in ("rip", "eip", "ip"):
                        uses[r].append(addr)

        # registers of interest at crash_point
        regs_of_interest: Set[str] = set()
        for instr in instrs:
            if instr["address"] == crash_point:
                regs_of_interest = {
                    r.lstrip("%").lower()
                    for r in self._REGEX_REG.findall(instr["text"])
                }
                break

        # BFS backward through def-use chains
        visited: Set[int] = {crash_point}
        queue: deque = deque([crash_point])
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            addr = queue.popleft()
            blk = bmap.get(addr, addr)
            affected_blocks.add(blk)

            # check if this instruction is a taint source
            text = ""
            for instr in instrs:
                if instr["address"] == addr:
                    text = instr["text"].lower()
                    break
            if text:
                for sname in self._TAINT_SOURCES:
                    if sname in text:
                        taint_sources.add(addr)
                        break

            # walk back through register dependencies
            for reg in list(regs_of_interest):
                for def_addr in defs.get(reg, []):
                    if def_addr not in visited:
                        visited.add(def_addr)
                        queue.append(def_addr)
                        for instr in instrs:
                            if instr["address"] == def_addr:
                                new_regs = {
                                    r.lstrip("%").lower()
                                    for r in self._REGEX_REG.findall(instr["text"])
                                }
                                regs_of_interest.update(new_regs)
                                break

        if len(affected_blocks) <= 1 and crash_point:
            base = crash_point & ~0xF
            for off in range(0x10, 0x80, 0x10):
                candidate = base - off
                if candidate > 0:
                    affected_blocks.add(candidate)

        return taint_sources, affected_blocks

    def slice_with_disasm(
        self, crash_point: int, raw_disasm: str, max_depth: int = 512,
    ) -> Tuple[Set[int], Set[int]]:
        """Same as slice_from but accepts pre-fetched disassembly text."""
        instrs = self._parse_disasm(raw_disasm)
        leaders = self._find_basic_block_leaders(instrs)
        bmap = self._build_block_map(leaders, instrs)

        taint_sources: Set[int] = set()
        affected_blocks: Set[int] = {bmap.get(crash_point, crash_point)}

        if not instrs:
            return taint_sources, affected_blocks

        defs: Dict[str, List[int]] = defaultdict(list)
        uses: Dict[str, List[int]] = defaultdict(list)

        for instr in instrs:
            addr = instr["address"]
            text = instr["text"].lower()
            tokens = text.split()
            if not tokens:
                continue
            mnem = tokens[0]
            regs = [r.lstrip("%").lower() for r in self._REGEX_REG.findall(text)]
            if mnem in self._WRITE_MNEMONICS and regs:
                defs[regs[0]].append(addr)
                for r in regs[1:]:
                    uses[r].append(addr)
            elif mnem in self._READ_MNEMONICS:
                for r in regs:
                    uses[r].append(addr)
            if self._REGEX_MEM.search(text):
                for r in regs:
                    if r not in ("rip", "eip", "ip"):
                        uses[r].append(addr)

        regs_of_interest: Set[str] = set()
        for instr in instrs:
            if instr["address"] == crash_point:
                regs_of_interest = {
                    r.lstrip("%").lower()
                    for r in self._REGEX_REG.findall(instr["text"])
                }
                break

        visited: Set[int] = {crash_point}
        queue: deque = deque([crash_point])
        depth = 0

        while queue and depth < max_depth:
            depth += 1
            addr = queue.popleft()
            blk = bmap.get(addr, addr)
            affected_blocks.add(blk)

            text = ""
            for instr in instrs:
                if instr["address"] == addr:
                    text = instr["text"].lower()
                    break
            if text:
                for sname in self._TAINT_SOURCES:
                    if sname in text:
                        taint_sources.add(addr)
                        break

            for reg in list(regs_of_interest):
                for def_addr in defs.get(reg, []):
                    if def_addr not in visited:
                        visited.add(def_addr)
                        queue.append(def_addr)
                        for instr in instrs:
                            if instr["address"] == def_addr:
                                new_regs = {
                                    r.lstrip("%").lower()
                                    for r in self._REGEX_REG.findall(instr["text"])
                                }
                                regs_of_interest.update(new_regs)
                                break

        return taint_sources, affected_blocks


# VulnerabilityReporter——最小上下文提取与报告生成


class VulnerabilityReporter:
    """
    Extracts the minimum meaningful context around a vulnerability and
    generates human-readable reports suitable for sharing with developers
    or writing into audit documents.
    """

    def __init__(self):
        self._slicer = VulnerabilitySlicer()

    # ---- context extraction --------------------------------------------

    def extract_context(
        self,
        crash_point: int,
        binary_path: str = "",
        raw_disasm: str = "",
    ) -> VulnerabilityContext:
        """
        Extract the minimal vulnerability context from a crash point.
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

    # ---- report generation ---------------------------------------------

    @staticmethod
    def generate_report(
        context: VulnerabilityContext,
        title: str = "Vulnerability Analysis",
    ) -> str:
        """Generate a Markdown vulnerability report from a context."""
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
        """Generate a JSON-serializable report dictionary."""
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


# VulnerabilityReasoner——正向链式推理引擎，遍历知识图谱推导利用链


class VulnerabilityReasoner:
    """
    Maintains a knowledge graph of vulnerability observations and applies
    forward-chaining inference rules to suggest exploitation paths or
    impact chains.
    """

    def __init__(self):
        self.nodes: Dict[str, VulnerabilityKnowledgeNode] = {}
        self.rules: List[InferenceRule] = []
        self._adjacency: Dict[str, List[str]] = defaultdict(list)

    # ---- node management -----------------------------------------------

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

    # ---- rule management -----------------------------------------------

    def add_rule(self, antecedent: str, consequent: str, confidence: float = 0.5) -> None:
        self.rules.append(InferenceRule(
            antecedent=antecedent,
            consequent=consequent,
            confidence=min(1.0, max(0.0, confidence)),
        ))

    def add_rules_batch(self, rules: List[Tuple[str, str, float]]) -> None:
        """Add many rules at once. Each tuple: (antecedent, consequent, confidence)."""
        for ant, con, conf in rules:
            self.add_rule(ant, con, conf)

    def remove_rules_by_antecedent(self, antecedent: str) -> int:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.antecedent != antecedent]
        return before - len(self.rules)

    # ---- inference -----------------------------------------------------

    def infer(self, vuln_ids: List[str], max_rounds: int = 5) -> List[Dict[str, Any]]:
        """
        Forward-chain from *vuln_ids* through all rules.

        Returns a list of inferred consequences with associated
        confidence scores and provenance.
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
                for rule in self.rules:
                    if rule.antecedent.lower() in text.lower():
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
        Build a transitive chain of consequences starting from a single
        vulnerability, returning the full path of rule activations.
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

    # ---- query ---------------------------------------------------------

    def query(
        self,
        pattern: str,
        node_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[VulnerabilityKnowledgeNode]:
        """
        Search the knowledge graph. *pattern* is matched case-insensitively
        against vuln_id, vuln_type, and property values.
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
        """Find all nodes reachable within *max_depth* hops."""
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

    # ---- helpers -------------------------------------------------------

    @staticmethod
    def _node_text(node: Optional[VulnerabilityKnowledgeNode]) -> str:
        if node is None:
            return ""
        parts = [node.vuln_id, node.vuln_type]
        parts.extend(str(v) for v in node.properties.values())
        return " ".join(parts).lower()

    def stats(self) -> Dict[str, int]:
        return {"nodes": len(self.nodes), "rules": len(self.rules)}


# ExposureAnalyzer——数据流追踪，检测敏感数据向日志/网络/文件的暴露路径


class ExposureAnalyzer:
    """
    Traces sensitive data flow to detect exposure through logging,
    network transmission, or file writes. Supports both heuristic
    (objdump-based) and source-code (regex-based) analysis.
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

    # ---- binary-level helpers ------------------------------------------

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

    # ---- data flow tracking --------------------------------------------

    def trace_flow(
        self, source_addr: int, binary_path: str = "", raw_disasm: str = "",
    ) -> DataFlowPath:
        """
        Trace forward from *source_addr* through all sink categories and
        return a DataFlowPath listing every reachable sink.
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

    # ---- exposure checks (binary level) --------------------------------

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
        """Run all three exposure checks at once."""
        raw = raw_disasm or self._run_objdump(binary_path)
        return {
            "log_exposure": self._check_exposure(source_addr, self.LOG_SINKS, raw),
            "network_exposure": self._check_exposure(source_addr, self.NETWORK_SINKS, raw),
            "file_exposure": self._check_exposure(source_addr, self.FILE_SINKS, raw),
        }

    # ---- source-code-level exposure checks -----------------------------

    @staticmethod
    def check_log_exposure_in_source(
        source_code: str, variable_name: str = "",
    ) -> List[Dict[str, Any]]:
        """Scan source code for a variable passed to logging functions."""
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
        """Scan source code for a variable passed to network functions."""
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
        """Scan source code for a variable passed to file-write functions."""
        findings: List[Dict[str, Any]] = []
        if not variable_name:
            return findings
        pat = re.compile(
            rf"(?:fwrite|fputs|fprintf|write|WriteFile|ofstream|<<)\s*\(\s*[^,)]*{re.escape(variable_name)}"
        )
        for m in pat.finditer(source_code):
            findings.append({"match": m.group(), "position": m.start(), "category": "file_exposure"})
        return findings

    # ---- report --------------------------------------------------------

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


# CodeLocator - code finding and CVE impact assessment


class CodeLocator:
    """
    Searches a binary (or its extracted strings/symbols) for code
    patterns associated with a CVE, library, or vulnerability class.
    """

    def __init__(self):
        self._cve_patterns: Dict[str, Dict[str, Any]] = {}
        self._findings_cache: Dict[str, List[CVEFootprint]] = {}

    # ---- pattern management --------------------------------------------

    def register_cve_pattern(self, cve_id: str, pattern: Dict[str, Any]) -> None:
        """Register a CVE fingerprint.

        *pattern* keys:
        - function_names : List[str]  -- symbol names expected in the binary
        - code_patterns  : List[str]  -- regex patterns matched against strings output
        - version_strings: List[str]  -- literal version substrings to look for
        - severity        : str       -- informational label
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

    # ---- binary introspection ------------------------------------------

    @staticmethod
    def _read_strings(binary_path: str) -> str:
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

    @staticmethod
    def _read_symbols(binary_path: str) -> str:
        if not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(
                ["nm", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    @staticmethod
    def _read_objdump(binary_path: str) -> str:
        if not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(
                ["objdump", "-d", binary_path],
                capture_output=True, text=True, timeout=60,
            )
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    # ---- analysis ------------------------------------------------------

    def find_affected_code(self, binary_path: str, cve_id: str) -> CVEFootprint:
        """Determine whether *cve_id* affects *binary_path*.

        Returns a CVEFootprint with confidence [0.0, 1.0].
        """
        pattern = self._cve_patterns.get(cve_id)
        if pattern is None:
            return CVEFootprint(cve_id=cve_id, confidence=0.0)

        strings_raw = self._read_strings(binary_path)
        symbols_raw = self._read_symbols(binary_path)
        disasm_raw = self._read_objdump(binary_path)

        footprint = CVEFootprint(cve_id=cve_id)
        total_checks = 0.0
        passed_checks = 0.0

        # function names (via nm)
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

        # code patterns (regex on strings)
        for cpat in pattern.get("code_patterns", []):
            total_checks += 1.0
            try:
                if re.search(cpat, strings_raw):
                    passed_checks += 1.0
                    footprint.matched_strings.append(cpat)
            except re.error:
                total_checks -= 1.0

        # code patterns (regex on disassembly)
        for cpat in pattern.get("code_patterns", []):
            total_checks += 1.0
            try:
                if re.search(cpat, disasm_raw):
                    passed_checks += 0.5
            except re.error:
                total_checks -= 1.0

        # version strings
        for vstr in pattern.get("version_strings", []):
            total_checks += 0.5
            if vstr in strings_raw:
                passed_checks += 0.5

        if total_checks > 0:
            footprint.confidence = min(1.0, passed_checks / total_checks)
        else:
            footprint.confidence = 0.0

        return footprint

    # ---- impact assessment ---------------------------------------------

    def assess_impact(self, binary_path: str) -> List[CVEFootprint]:
        """Evaluate all registered CVE patterns against *binary_path*."""
        if binary_path in self._findings_cache:
            return self._findings_cache[binary_path]

        impacts: List[CVEFootprint] = []
        for cve_id in self._cve_patterns:
            fp = self.find_affected_code(binary_path, cve_id)
            if fp.confidence > 0.0:
                impacts.append(fp)

        impacts.sort(key=lambda x: x.confidence, reverse=True)
        self._findings_cache[binary_path] = impacts
        return impacts

    def assess_impact_for_cves(
        self, binary_path: str, cve_ids: List[str],
    ) -> List[CVEFootprint]:
        """Assess impact only for a subset of registered CVEs."""
        impacts: List[CVEFootprint] = []
        for cve_id in cve_ids:
            fp = self.find_affected_code(binary_path, cve_id)
            if fp.confidence > 0.0:
                impacts.append(fp)
        impacts.sort(key=lambda x: x.confidence, reverse=True)
        return impacts

    def generate_impact_report(self, impacts: List[CVEFootprint]) -> str:
        """Produce a Markdown summary of CVE impact findings."""
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


# ThreatIntelClient——MISP/OTX/NVD 三源威胁情报统一查询接口


class ThreatIntelClient:
    """
    Unified client for threat-intelligence lookups against MISP,
    AlienVault OTX, and NVD.
    """

    _USER_AGENT = "BinMind/2.0"
    _DEFAULT_TIMEOUT = 30

    def __init__(self):
        self._misp_url: str = ""
        self._misp_key: str = ""
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl: int = 3600
        self._cache_timestamps: Dict[str, float] = {}

    # ---- configuration -------------------------------------------------

    def configure_misp(self, url: str, api_key: str) -> None:
        self._misp_url = url.rstrip("/")
        self._misp_key = api_key

    def configure_cache(self, ttl_seconds: int) -> None:
        self._cache_ttl = ttl_seconds

    # ---- MISP ----------------------------------------------------------

    def lookup_misp(
        self, indicator: str, indicator_type: str = "sha256",
    ) -> Dict[str, Any]:
        """Search MISP for an indicator (hash, domain, IP, etc.).

        Parameters
        ----------
        indicator : str
            The IOC value.
        indicator_type : str
            MISP attribute type (sha256, md5, domain, ip-src, ...).

        Returns
        -------
        dict with keys: source, indicator, type, found, attributes, [error]
        """
        cache_key = f"misp:{indicator_type}:{indicator}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "source": "misp",
            "indicator": indicator,
            "type": indicator_type,
            "found": False,
            "attributes": [],
        }

        if not self._misp_url:
            result["error"] = "MISP not configured"
            return result

        try:
            api_url = f"{self._misp_url}/attributes/restSearch"
            payload = json.dumps({
                "returnFormat": "json",
                "value": indicator,
                "type": indicator_type,
            }).encode("utf-8")

            req = urllib.request.Request(
                api_url,
                data=payload,
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

    # ---- AlienVault OTX ------------------------------------------------

    def lookup_otx(self, indicator: str) -> Dict[str, Any]:
        """Look up an indicator in AlienVault OTX.

        Accepts IP, domain, URL, or file hash. The OTX API
        auto-detects the indicator type.
        """
        cache_key = f"otx:{indicator}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "source": "alienvault_otx",
            "indicator": indicator,
            "found": False,
            "pulses": [],
            "type": "",
        }

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
                            "id": p.get("id", ""),
                            "name": p.get("name", ""),
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
        """Fetch detailed information about a single OTX pulse."""
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
                    "found": True,
                    "name": parsed.get("name", ""),
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

    # ---- NVD CVE lookup ------------------------------------------------

    def lookup_cve(self, cve_id: str) -> Dict[str, Any]:
        """Query the NVD REST API 2.0 for CVE details.

        Returns a dict with: cve_id, description, severity, cvss_score,
        cvss_vector, references, weaknesses, published_date, found.
        """
        cache_key = f"nvd:{cve_id}"
        cached = self._check_cache(cache_key)
        if cached is not None:
            return cached

        result: Dict[str, Any] = {
            "cve_id": cve_id,
            "description": "",
            "severity": "",
            "cvss_score": 0.0,
            "cvss_vector": "",
            "references": [],
            "weaknesses": [],
            "published_date": "",
            "found": False,
        }

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

                    # description
                    for desc in vuln.get("descriptions", []):
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break

                    # published date
                    result["published_date"] = vuln.get("published", "")

                    # weaknesses (CWE)
                    for w in vuln.get("weaknesses", []):
                        for wd in w.get("description", []):
                            if wd.get("lang") == "en":
                                result["weaknesses"].append(wd.get("value", ""))

                    # CVSS metrics (prefer v3.1, fall back to v3.0, v2.0)
                    metrics = vuln.get("metrics", {})
                    for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        cvss_list = metrics.get(version, [])
                        if cvss_list:
                            cvss_data = cvss_list[0].get("cvssData", {})
                            result["cvss_score"] = cvss_data.get("baseScore", 0.0)
                            result["severity"] = cvss_data.get("baseSeverity", "")
                            result["cvss_vector"] = cvss_data.get("vectorString", "")
                            break

                    # references
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

    # ---- batch / convenience -------------------------------------------

    def lookup_hash(self, hash_value: str) -> Dict[str, Dict[str, Any]]:
        """Look up a file hash across all configured threat-intel sources."""
        results: Dict[str, Dict[str, Any]] = {}
        if self._misp_url:
            results["misp"] = self.lookup_misp(hash_value, "sha256")
        results["otx"] = self.lookup_otx(hash_value)
        return results

    def enrich_vulnerability(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a vulnerability dict with threat-intel data."""
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

    # ---- cache helpers -------------------------------------------------

    def _check_cache(self, key: str) -> Optional[Dict[str, Any]]:
        ts = self._cache_timestamps.get(key, 0)
        if time.time() - ts < self._cache_ttl:
            return self._cache.get(key)
        return None

    def _set_cache(self, key: str, value: Dict[str, Any]) -> None:
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


# VersionExtractor——从二进制字符串与符号表中启发式提取库版本号


class VersionExtractor:
    """
    Extracts library and component version information from a binary
    using heuristic pattern matching on the ``strings`` output and
    symbol table analysis.
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
        """Register a custom version extraction pattern."""
        self._custom_patterns.append((library, re.compile(regex, re.IGNORECASE), group))

    def extract(self, binary_path: str = "", strings_text: str = "") -> Dict[str, str]:
        """Extract versions from a binary file or pre-fetched strings text."""
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

        # library-specific patterns
        for lib, pat, grp in all_patterns:
            if lib in versions:
                continue
            m = pat.search(text)
            if m:
                try:
                    versions[lib] = m.group(grp)
                except IndexError:
                    versions[lib] = m.group(0)

        # generic fallback for libraries without explicit match
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
        """Return every unique version string found in *text*."""
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
        """Like extract() but adds a confidence score [0,1] per match."""
        versions = self.extract(binary_path=binary_path, strings_text=strings_text)
        result: Dict[str, Tuple[str, float]] = {}
        for lib, ver in versions.items():
            explicit = any(lib == p[0] for p in self._LIB_PATTERNS + self._custom_patterns)
            result[lib] = (ver, 0.9 if explicit else 0.5)
        return result


# VersionedVulnChecker——基于OSV与NVD的版本化漏洞匹配查询


class VersionedVulnChecker:
    """
    Given a library name and version, queries OSV.dev and NVD to
    determine whether any known vulnerabilities apply.
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

    # ---- OSV query -----------------------------------------------------

    def check(
        self, library: str, version: str, ecosystem: str = "",
    ) -> List[Dict[str, Any]]:
        """向OSV.dev查询指定库在特定版本下的已知漏洞。

        Parameters
        ----------
        library : str
            Package / library name.
        version : str
            Version string (e.g. "1.1.1q").
        ecosystem : str
            OSV ecosystem identifier (e.g. "Debian:11", "OSS-Fuzz", "" for auto).

        Returns
        -------
        list of vulnerability dicts.
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
                self._OSV_QUERY_URL,
                data=data,
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
                        "library": library,
                        "version": version,
                        "osv_id": v.get("id", ""),
                        "cve_id": "",
                        "summary": v.get("summary", ""),
                        "details": v.get("details", v.get("summary", "")),
                        "severity": "unknown",
                        "aliases": v.get("aliases", []),
                        "affected_ranges": [],
                    }

                    # extract CVE from aliases
                    for alias in v.get("aliases", []):
                        if alias.upper().startswith("CVE-"):
                            vuln["cve_id"] = alias
                            break

                    # severity from database_specific
                    db_specific = v.get("database_specific", {})
                    vuln["severity"] = db_specific.get("severity", "unknown")

                    # affected ranges
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
        """Check multiple packages at once.

        Parameters
        ----------
        packages : dict
            {library_name: version, ...}

        Returns
        -------
        dict keyed by "lib@ver" with vulnerability list values.
        """
        results: Dict[str, List[Dict[str, Any]]] = {}
        for lib, ver in packages.items():
            key = f"{lib}@{ver}"
            results[key] = self.check(lib, ver, ecosystem)
        return results

    # ---- NVD enrichment ------------------------------------------------

    def enrich_with_nvd(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """For every vulnerability that has a CVE ID, fetch full details from NVD."""
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

    # ---- cache management ----------------------------------------------

    def clear_cache(self) -> int:
        count = len(self._cache)
        self._cache.clear()
        return count

    def stats(self) -> Dict[str, int]:
        return {"cached_queries": len(self._cache)}


# SBOMGenerator - SPDX / CycloneDX generation


class SBOMGenerator:
    """
    Generates Software Bill of Materials (SBOM) in CycloneDX and SPDX
    formats from component data extracted during binary analysis.
    """

    def __init__(self):
        self.components: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "tool": "BinMind",
            "version": "2.0",
            "generated_at": datetime.now().isoformat(),
        }

    # ---- component management ------------------------------------------

    def add_component(
        self, name: str, version: str = "unknown", comp_type: str = "library", **kwargs,
    ) -> None:
        """Add a component to the SBOM.

        Parameters
        ----------
        name : str
            Component / package name.
        version : str
            Version string.
        comp_type : str
            One of: application, library, framework, operating-system, device, file.
        **kwargs
            Additional fields: supplier, licenses, hashes, purl, cpe, etc.
        """
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

    # ---- CycloneDX -----------------------------------------------------

    def export_cyclonedx(self, version: str = "1.4") -> Dict[str, Any]:
        """Generate a CycloneDX SBOM document conforming to the JSON schema."""
        doc: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": version,
            "serialNumber": (
                f"urn:uuid:{hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:32]}"
            ),
            "version": 1,
            "metadata": {
                "timestamp": self.metadata["generated_at"],
                "tools": [{
                    "name": self.metadata["tool"],
                    "version": self.metadata["version"],
                }],
                "component": {
                    "name": "root",
                    "type": "application",
                    "version": "1.0",
                },
            },
            "components": [],
        }

        for comp in self.components:
            item: Dict[str, Any] = {
                "type": comp.get("type", "library"),
                "name": comp["name"],
                "version": comp.get("version", "unknown"),
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

    # ---- SPDX ----------------------------------------------------------

    def export_spdx(self, version: str = "SPDX-2.3") -> Dict[str, Any]:
        """Generate an SPDX SBOM document conforming to the JSON schema."""
        ns_suffix = hashlib.sha256(str(datetime.now()).encode()).hexdigest()[:16]

        doc: Dict[str, Any] = {
            "spdxVersion": version,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": f"https://binmind.local/spdx/{ns_suffix}",
            "name": "BinMind SBOM",
            "creationInfo": {
                "created": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "creators": [f"Tool: {self.metadata['tool']}-{self.metadata['version']}"],
            },
            "packages": [],
            "relationships": [],
        }

        for i, comp in enumerate(self.components):
            pkg_id = f"SPDXRef-Package-{i}"
            pkg: Dict[str, Any] = {
                "SPDXID": pkg_id,
                "name": comp["name"],
                "versionInfo": comp.get("version", "unknown"),
                "supplier": comp.get("supplier", "NOASSERTION"),
                "downloadLocation": comp.get("downloadLocation", "NOASSERTION"),
                "filesAnalyzed": False,
                "licenseConcluded": (
                    " AND ".join(comp["licenses"])
                    if "licenses" in comp
                    else "NOASSERTION"
                ),
                "licenseDeclared": (
                    " AND ".join(comp["licenses"])
                    if "licenses" in comp
                    else "NOASSERTION"
                ),
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

    # ---- I/O -----------------------------------------------------------

    def write(self, path: str, format: str = "spdx", version: str = "") -> str:
        """Write the SBOM to *path*. *format* must be 'spdx' or 'cyclonedx'.

        Returns the absolute path written.
        """
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
        """Return a human-readable summary of the SBOM composition."""
        by_type: Dict[str, int] = defaultdict(int)
        for c in self.components:
            by_type[c.get("type", "library")] += 1
        return {
            "total_components": len(self.components),
            "by_type": dict(by_type),
            "formats_available": ["spdx", "cyclonedx"],
        }


# Preserved supporting classes (fully functional, kept for compatibility)


# VulnerabilityKnowledgeGraphBuilder——漏洞知识图谱构建器，支持D3.js可视化导出


class VulnerabilityKnowledgeGraphBuilder:
    """
    Extracts entities and relations, supports graph queries and D3.js
    visualization, and analyses correlated attack patterns.
    """

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self.graph: Dict[str, List[str]] = {}

    def add_entity(
        self,
        entity_type: str,
        entity_id: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        node_id = f"{entity_type}:{entity_id}"
        self.nodes[node_id] = {
            "type": entity_type,
            "id": entity_id,
            "properties": properties or {},
        }
        if node_id not in self.graph:
            self.graph[node_id] = []

    def add_relation(
        self,
        from_id: str,
        to_id: str,
        relation_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.edges.append({
            "from": from_id,
            "to": to_id,
            "type": relation_type,
            "properties": properties or {},
        })
        if from_id in self.graph:
            self.graph[from_id].append(to_id)

    def query_path(self, start_id: str, end_id: str, max_depth: int = 3) -> List[List[str]]:
        paths: List[List[str]] = []

        def dfs(current: str, path: List[str], depth: int) -> None:
            if depth > max_depth:
                return
            if current == end_id:
                paths.append(list(path))
                return
            for neighbor in self.graph.get(current, []):
                if neighbor not in path:
                    path.append(neighbor)
                    dfs(neighbor, path, depth + 1)
                    path.pop()

        dfs(start_id, [start_id], 0)
        return paths

    def find_attack_patterns(self) -> List[Dict[str, Any]]:
        patterns: List[Dict[str, Any]] = []
        for node_id, node in self.nodes.items():
            if node["type"] == "vulnerability":
                reachable = self._find_reachable_nodes(node_id)
                sensitive = [
                    n
                    for n in reachable
                    if self.nodes.get(n, {}).get("type") == "sensitive_data"
                ]
                if sensitive:
                    patterns.append({
                        "entry_point": node_id,
                        "reachable_assets": sensitive,
                    })
        return patterns

    def _find_reachable_nodes(self, start_id: str) -> Set[str]:
        reachable: Set[str] = set()
        queue: deque = deque([start_id])
        while queue:
            cur = queue.popleft()
            for nb in self.graph.get(cur, []):
                if nb not in reachable:
                    reachable.add(nb)
                    queue.append(nb)
        return reachable

    def export_for_d3js(self) -> Dict[str, Any]:
        nodes_out = []
        for node_id, node in self.nodes.items():
            nodes_out.append({
                "id": node_id,
                "type": node["type"],
                "label": f"{node['type']}:{node['id']}",
            })
        links_out = []
        for edge in self.edges:
            links_out.append({
                "source": edge["from"],
                "target": edge["to"],
                "type": edge["type"],
            })
        return {"nodes": nodes_out, "links": links_out}

    def export_adjacency_list(self) -> Dict[str, List[str]]:
        return dict(self.graph)

    def stats(self) -> Dict[str, int]:
        return {"nodes": len(self.nodes), "edges": len(self.edges)}


# VulnerabilityRuleEngine——YAML规则加载与正则代码扫描引擎


class VulnerabilityRuleEngine:
    """Loads YAML rules, scans code with regex patterns, merges with AI results."""

    def __init__(self):
        self.rules: List[Dict[str, Any]] = []
        self.rule_patterns: Dict[str, re.Pattern] = {}
        self.matched_vulnerabilities: List[Dict[str, Any]] = []

    def load_rules_from_yaml(self, yaml_path: str) -> int:
        loaded = 0
        try:
            import yaml

            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and "rules" in data:
                for rule in data["rules"]:
                    self.add_rule(rule)
                    loaded += 1
        except Exception as e:
            logger.error(f"Error loading YAML rules: {e}")
        return loaded

    def add_rule(self, rule: Dict[str, Any]) -> None:
        rule_id = rule.get("id", hashlib.md5(str(rule).encode()).hexdigest()[:8])
        rule["rule_id"] = rule_id
        if "pattern" in rule:
            try:
                self.rule_patterns[rule_id] = re.compile(rule["pattern"])
            except re.error:
                pass
        self.rules.append(rule)

    def scan_code(self, code: str) -> List[Dict[str, Any]]:
        matches: List[Dict[str, Any]] = []
        for rule in self.rules:
            rid = rule["rule_id"]
            pat = self.rule_patterns.get(rid)
            if pat is None:
                continue
            for m in pat.finditer(code):
                matches.append({
                    "rule_id": rid,
                    "rule_name": rule.get("name", "Unknown"),
                    "severity": rule.get("severity", "medium"),
                    "matched_text": m.group(0),
                    "location": m.span(),
                })
        self.matched_vulnerabilities.extend(matches)
        return matches

    def merge_with_ai_results(self, ai_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = list(self.matched_vulnerabilities)
        for ai_r in ai_results:
            if not any(self._is_duplicate(ai_r, ex) for ex in merged):
                merged.append(ai_r)
        return merged

    @staticmethod
    def _is_duplicate(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        if a.get("rule_id") and b.get("rule_id"):
            if a["rule_id"] == b["rule_id"]:
                return True
        if a.get("location") and b.get("location"):
            if a["location"] == b["location"]:
                return True
        return False


# SensitiveDataLeakageChecker——PII/凭据/密钥检测，追踪至危险汇点的泄露路径


class SensitiveDataLeakageChecker:
    """Detects PII, credentials, and encryption keys in source code,
    then tracks whether they reach dangerous sinks."""

    def __init__(self):
        self.sensitive_patterns: Dict[str, List[str]] = {}
        self.sensitive_locations: Dict[str, List[int]] = {}
        self.leakage_reports: List[Dict[str, Any]] = []
        self._register_patterns()

    def _register_patterns(self) -> None:
        self.sensitive_patterns["pii"] = [
            r"\b\d{3}-\d{2}-\d{4}\b",
            r"\b\d{16}\b",
            r"\b[A-Z]{2}\d{6,9}\b",
            r"\b\d{4}\s\d{4}\s\d{4}\s\d{4}\b",
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        ]
        self.sensitive_patterns["credentials"] = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']',
        ]
        self.sensitive_patterns["encryption_keys"] = [
            r"\b[A-Za-z0-9+/]{32,}={0,2}\b",
            r"private_key",
            r"rsa_key",
            r"aes_key",
            r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        ]

    def mark_sensitive(self, code: str) -> Dict[str, List[int]]:
        locations: Dict[str, List[int]] = {}
        for cat, patterns in self.sensitive_patterns.items():
            locations[cat] = []
            for pat in patterns:
                for m in re.finditer(pat, code, re.IGNORECASE):
                    locations[cat].append(m.start())
        self.sensitive_locations = locations
        return locations

    def track_flow(self, sensitive_loc: int, code: str) -> List[Dict[str, Any]]:
        flows: List[Dict[str, Any]] = []
        dangerous = [
            "printf", "fprintf", "sprintf",
            "send", "sendto", "write",
            "fwrite", "fputs",
            "log", "debug", "error",
        ]
        for func in dangerous:
            pat = rf"{func}\s*\([^)]*\)"
            for m in re.finditer(pat, code):
                if m.start() > sensitive_loc:
                    flows.append({
                        "sensitive_location": sensitive_loc,
                        "sink_function": func,
                        "sink_location": m.start(),
                        "potential_leak": True,
                    })
        return flows

    def check_leakage(self, code: str) -> List[Dict[str, Any]]:
        leakages: List[Dict[str, Any]] = []
        locs = self.mark_sensitive(code)
        for cat, positions in locs.items():
            for pos in positions:
                for flow in self.track_flow(pos, code):
                    leakages.append({
                        "category": cat,
                        "location": pos,
                        "sink": flow["sink_function"],
                        "sink_location": flow["sink_location"],
                        "severity": (
                            "high" if cat in ("credentials", "encryption_keys") else "medium"
                        ),
                    })
        self.leakage_reports = leakages
        return leakages

    def generate_report(self) -> str:
        lines = ["# Sensitive Data Leakage Report", ""]
        for cat, locs in self.sensitive_locations.items():
            lines.append(f"## {cat}")
            lines.append(f"- Occurrences: {len(locs)}")
            for lk in self.leakage_reports:
                if lk["category"] == cat:
                    lines.append(
                        f"  - Possible leak to `{lk['sink']}` @ "
                        f"{hex(lk['sink_location'])}"
                    )
            lines.append("")
        return "\n".join(lines)


# AutomatedRootCauseAnalyzer——从崩溃点反向追踪执行轨迹，定位根因输入


class AutomatedRootCauseAnalyzer:
    """From a crash/exploit trigger point, walks an execution trace backward
    to locate the root-cause input, then generates a report."""

    def __init__(self):
        self.trace_chain: List[Dict[str, Any]] = []
        self.root_cause: Dict[str, Any] = {}

    def analyze_trigger(self, crash_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "address": crash_info.get("crash_address", 0),
            "type": crash_info.get("crash_type", "unknown"),
            "registers": crash_info.get("registers", {}),
            "memory_state": crash_info.get("memory_state", {}),
            "instruction": crash_info.get("instruction", ""),
        }

    def backward_trace(
        self,
        trigger_address: int,
        execution_trace: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        chain: List[Dict[str, Any]] = []
        for i in range(len(execution_trace) - 1, -1, -1):
            step = execution_trace[i]
            if step.get("address") == trigger_address:
                for j in range(i, -1, -1):
                    chain.append(execution_trace[j])
                    if len(chain) >= 100:
                        break
        self.trace_chain = chain
        return chain

    def locate_root(self) -> Dict[str, Any]:
        if not self.trace_chain:
            return {}
        root: Dict[str, Any] = {
            "type": "input",
            "location": "unknown",
            "description": "",
            "responsible_function": "",
        }
        for step in self.trace_chain:
            if step.get("input_related"):
                root["location"] = step.get("address", 0)
                root["description"] = "Input data processed here"
                root["responsible_function"] = step.get("function", "unknown")
                break
        self.root_cause = root
        return root

    def generate_report(self) -> str:
        lines = ["# Root Cause Analysis Report", ""]
        lines.append("## Trigger Point")
        if self.trace_chain:
            t = self.trace_chain[0]
            lines.append(f"- Address: {hex(t.get('address', 0))}")
            lines.append(f"- Type: {t.get('type', 'unknown')}")
        lines.append("")
        lines.append("## Trace Chain")
        lines.append(f"- Depth: {len(self.trace_chain)} steps")
        lines.append("")
        lines.append("## Root Cause")
        if self.root_cause:
            rc = self.root_cause
            loc = rc["location"]
            if isinstance(loc, int):
                loc = hex(loc)
            lines.append(f"- Type: {rc['type']}")
            lines.append(f"- Location: {loc}")
            lines.append(f"- Description: {rc['description']}")
            lines.append(f"- Function: {rc['responsible_function']}")
        lines.append("")
        return "\n".join(lines)


# SecurityConfigAuditor——AppArmor与SELinux安全配置合规审计


class SecurityConfigAuditor:
    """Audits AppArmor profiles and SELinux contexts for a binary."""

    def __init__(self):
        self.policies: Dict[str, Dict[str, Any]] = {}
        self._register_policies()

    def _register_policies(self) -> None:
        self.policies["apparmor"] = {
            "required_profiles": ["usr.bin.binary"],
            "required_capabilities": [],
            "required_network": False,
            "required_file_access": [],
        }
        self.policies["selinux"] = {
            "required_context": "bin_t",
            "required_types": ["execmem_exec_t"],
            "required_booleans": [],
        }

    def audit_apparmor(self, binary_path: str) -> Dict[str, Any]:
        audit: Dict[str, Any] = {
            "binary_path": binary_path,
            "profile_exists": False,
            "profile_enforced": False,
            "violations": [],
            "recommendations": [],
        }
        try:
            r = subprocess.run(
                ["aa-status", "--profiled"],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                profiles = r.stdout.split("\n")
                pname = os.path.basename(binary_path)
                for prof in profiles:
                    if pname in prof:
                        audit["profile_exists"] = True
                        if "enforce" in prof:
                            audit["profile_enforced"] = True
        except Exception as e:
            audit["error"] = str(e)
        if not audit["profile_exists"]:
            audit["recommendations"].append("Create an AppArmor profile")
        return audit

    def audit_selinux(self, binary_path: str) -> Dict[str, Any]:
        audit: Dict[str, Any] = {
            "binary_path": binary_path,
            "current_context": "",
            "expected_context": "",
            "compliant": False,
            "violations": [],
            "recommendations": [],
        }
        try:
            r = subprocess.run(
                ["ls", "-Z", binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0:
                parts = r.stdout.strip().split()
                if parts:
                    audit["current_context"] = parts[0]
                expected = self.policies["selinux"].get("required_context", "bin_t")
                audit["expected_context"] = expected
                audit["compliant"] = expected in audit["current_context"]
        except Exception as e:
            audit["error"] = str(e)
        if not audit["compliant"]:
            audit["recommendations"].append(
                f"Set SELinux context to {audit['expected_context']}"
            )
        return audit

    def generate_apparmor_profile(
        self, binary_name: str, capabilities: Optional[List[str]] = None,
    ) -> str:
        caps = (capabilities or ["dac_override"])[0]
        return (
            f"# AppArmor profile for {binary_name}\n\n"
            "#include <tunables/global>\n"
            f"/{binary_name} {{\n"
            "    #include <abstractions/base>\n\n"
            f"    /{binary_name} mr,\n"
            f"    capability {caps},\n"
            "    network inet stream,\n"
            "    /etc/** r,\n"
            "    /var/log/** w,\n"
            "    /tmp/** rw,\n"
            "}}\n"
        )

    def generate_selinux_policy(self, binary_name: str) -> str:
        return (
            f"# SELinux policy for {binary_name}\n\n"
            f"type {binary_name}_t;\n"
            f"type {binary_name}_exec_t;\n"
            "require {\n"
            "    type bin_t;\n"
            "    type execmem_exec_t;\n"
            "    class file { getattr open read execute };\n"
            "}\n\n"
            "# Type transition\n"
            f"type_transition bin_t {binary_name}_exec_t : process {binary_name}_t;\n\n"
            "# Allow execute\n"
            f"allow {binary_name}_t execmem_exec_t : file {{ getattr open read execute }};\n"
        )

    def run_full_audit(self, binary_path: str) -> Dict[str, Any]:
        aa = self.audit_apparmor(binary_path)
        se = self.audit_selinux(binary_path)
        return {
            "binary_path": binary_path,
            "apparmor": aa,
            "selinux": se,
            "overall_compliant": aa["profile_enforced"] and se["compliant"],
            "recommendations": aa.get("recommendations", [])
            + se.get("recommendations", []),
        }


# CrossProjectVulnerabilityCorrelationAnalyzer——跨项目共享库漏洞关联分析与影响评估


class CrossProjectVulnerabilityCorrelationAnalyzer:
    """Uses a vulnerability graph to detect cross-project correlations
    introduced by shared libraries and warns about impact radius."""

    def __init__(self):
        self.vuln_graph: Dict[str, Dict[str, Any]] = {}
        self.lib_map: Dict[str, List[str]] = {}
        self.impact_warnings: List[Dict[str, Any]] = []

    def build_graph(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        graph: Dict[str, Any] = {"nodes": [], "edges": []}
        for v in vulns:
            graph["nodes"].append({
                "id": v["id"],
                "type": "vulnerability",
                "project": v["project"],
                "library": v["library"],
                "severity": v["severity"],
            })
            lib = v.get("library", "unknown")
            self.lib_map.setdefault(lib, []).append(v["id"])
        for lib, ids in self.lib_map.items():
            for i, v1 in enumerate(ids):
                for v2 in ids[i + 1:]:
                    graph["edges"].append({
                        "source": v1,
                        "target": v2,
                        "type": "same_library",
                        "library": lib,
                    })
        self.vuln_graph = graph
        return graph

    def find_correlations(self, vuln_id: str) -> List[Dict[str, Any]]:
        corr: List[Dict[str, Any]] = []
        for edge in self.vuln_graph.get("edges", []):
            if edge["source"] == vuln_id or edge["target"] == vuln_id:
                related = (
                    edge["target"] if edge["source"] == vuln_id else edge["source"]
                )
                for node in self.vuln_graph.get("nodes", []):
                    if node["id"] == related:
                        corr.append({
                            "vulnerability_id": related,
                            "project": node["project"],
                            "library": edge["library"],
                            "correlation_type": edge["type"],
                        })
        return corr

    def generate_warning(self, library: str) -> Dict[str, Any]:
        ids = self.lib_map.get(library, [])
        projects: List[str] = []
        for vid in ids:
            for node in self.vuln_graph.get("nodes", []):
                if node["id"] == vid:
                    projects.append(node["project"])
        warning = {
            "library": library,
            "affected_vulnerabilities": ids,
            "affected_projects": projects,
            "severity": "high",
            "recommendation": (
                f"Review all {len(projects)} projects using "
                f"{library} - shared-library vulnerability"
            ),
        }
        self.impact_warnings.append(warning)
        return warning

    def analyze_cross_project(self) -> Dict[str, Any]:
        high_impact: List[Dict[str, Any]] = []
        for lib, ids in self.lib_map.items():
            if len(ids) > 3:
                high_impact.append({"library": lib, "vulnerability_count": len(ids)})
        high_impact.sort(key=lambda x: x["vulnerability_count"], reverse=True)
        return {
            "total_vulnerabilities": len(self.vuln_graph.get("nodes", [])),
            "total_correlations": len(self.vuln_graph.get("edges", [])),
            "high_impact_libraries": high_impact,
        }

    def generate_correlation_report(self) -> str:
        lines = ["# Cross-Project Vulnerability Correlation", ""]
        lines.append("## High-Impact Libraries")
        for lib_info in self.analyze_cross_project()["high_impact_libraries"]:
            lines.append(
                f"- {lib_info['library']}: "
                f"{lib_info['vulnerability_count']} vulns"
            )
        lines.append("")
        lines.append("## Impact Warnings")
        for w in self.impact_warnings:
            lines.append(
                f"- {w['library']}: "
                f"{len(w['affected_projects'])} projects affected"
            )
        lines.append("")
        return "\n".join(lines)


# GitDiffAnalysisTrigger——监听Git仓库二进制变更，自动触发差分分析与回归扫描


class GitDiffAnalysisTrigger:
    """Monitors a Git repository for binary changes and triggers
    differential analysis and regression vulnerability scans."""

    _BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".elf", ".ko", ".o", ".a"}
    _ELF_MAGIC = b"\x7fELF"
    _PE_MAGIC = b"MZ"

    def __init__(
        self,
        repo_path: str = "",
        analysis_callback: Optional[Callable] = None,
    ):
        self.repo_path = repo_path
        self.analysis_callback = analysis_callback
        self.last_commit_hash: str = ""
        self.watched_files: Set[str] = set()
        self.analysis_history: Dict[str, Dict[str, Any]] = {}
        self._monitor_thread: Optional[threading.Thread] = None
        self._stop_monitor = threading.Event()

    def set_repo_path(self, path: str) -> None:
        self.repo_path = path

    def add_watched_file(self, pattern: str) -> None:
        self.watched_files.add(pattern)

    def get_current_commit(self) -> str:
        try:
            r = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.repo_path,
                capture_output=True, text=True, timeout=30,
            )
            return r.stdout.strip() if r.returncode == 0 else ""
        except Exception as e:
            logger.warning(f"git rev-parse failed: {e}")
            return ""

    def get_changed_files(self, old_hash: str, new_hash: str) -> List[str]:
        try:
            r = subprocess.run(
                ["git", "diff", "--name-only", old_hash, new_hash],
                cwd=self.repo_path,
                capture_output=True, text=True, timeout=60,
            )
            return (
                [f for f in r.stdout.strip().split("\n") if f]
                if r.returncode == 0
                else []
            )
        except Exception as e:
            logger.warning(f"git diff failed: {e}")
            return []

    def detect_binary_changes(self, changed_files: List[str]) -> List[str]:
        binaries: List[str] = []
        for f in changed_files:
            if not f:
                continue
            ext = os.path.splitext(f)[1].lower()
            full = os.path.join(self.repo_path, f)
            if ext in self._BINARY_EXTS:
                binaries.append(f)
            elif not ext and os.path.isfile(full):
                try:
                    with open(full, "rb") as fh:
                        magic = fh.read(4)
                    if magic[:4] == self._ELF_MAGIC:
                        binaries.append(f)
                    elif magic[:2] == self._PE_MAGIC:
                        binaries.append(f)
                except Exception:
                    _logger.debug("suppressed", exc_info=True)
        return binaries

    def trigger_analysis(
        self, binary_path: str, old_version: str, new_version: str,
    ) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "binary_path": binary_path,
            "old_version": old_version,
            "new_version": new_version,
            "timestamp": datetime.now().isoformat(),
            "diff_analysis": {},
            "regression_scan": {},
        }
        if self.analysis_callback:
            try:
                out = self.analysis_callback(binary_path, old_version, new_version)
                result["diff_analysis"] = out
            except Exception as e:
                result["error"] = str(e)
        aid = hashlib.sha256(
            f"{binary_path}:{old_version}:{new_version}".encode()
        ).hexdigest()[:16]
        self.analysis_history[aid] = result
        return result

    def start_monitoring(self, interval: int = 60) -> None:
        self.last_commit_hash = self.get_current_commit()
        self._stop_monitor.clear()

        def loop() -> None:
            while not self._stop_monitor.is_set():
                cur = self.get_current_commit()
                if cur and cur != self.last_commit_hash:
                    logger.info(f"New commit detected: {cur}")
                    changed = self.get_changed_files(self.last_commit_hash, cur)
                    for bf in self.detect_binary_changes(changed):
                        logger.info(f"Triggering binary analysis: {bf}")
                        self.trigger_analysis(
                            os.path.join(self.repo_path, bf),
                            self.last_commit_hash,
                            cur,
                        )
                    self.last_commit_hash = cur
                time.sleep(interval)

        self._monitor_thread = threading.Thread(target=loop, daemon=True)
        self._monitor_thread.start()
        logger.info("Git monitoring started")

    def stop_monitoring(self) -> None:
        self._stop_monitor.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        logger.info("Git monitoring stopped")

    def get_analysis_history(self) -> Dict[str, Dict[str, Any]]:
        return dict(self.analysis_history)


# DynamicAnalysisEnvironmentManager——Vagrant/Ansible驱动的可快照动态分析环境管理


class DynamicAnalysisEnvironmentManager:
    """Integrates Vagrant and Ansible to create, snapshot, restore, and
    destroy analysis environments for specific OS versions."""

    def __init__(self, work_dir: str = "data/analysis_envs"):
        self.work_dir = work_dir
        self.environments: Dict[str, Dict[str, Any]] = {}
        self.snapshots: Dict[str, List[Dict[str, Any]]] = {}
        os.makedirs(self.work_dir, exist_ok=True)

    def create_environment(
        self,
        env_name: str,
        os_type: str = "ubuntu",
        os_version: str = "20.04",
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        env_info: Dict[str, Any] = {
            "name": env_name,
            "os_type": os_type,
            "os_version": os_version,
            "status": "creating",
            "vagrantfile": "",
            "snapshot_list": [],
            "created_at": datetime.now().isoformat(),
        }
        env_dir = os.path.join(self.work_dir, env_name)
        os.makedirs(env_dir, exist_ok=True)

        vf_content = self._generate_vagrantfile(os_type, os_version, config)
        vf_path = os.path.join(env_dir, "Vagrantfile")
        with open(vf_path, "w") as f:
            f.write(vf_content)
        env_info["vagrantfile"] = vf_path

        try:
            r = subprocess.run(
                ["vagrant", "up"],
                cwd=env_dir,
                capture_output=True, text=True, timeout=300,
            )
            env_info["status"] = "running" if r.returncode == 0 else "error"
            if r.returncode != 0:
                env_info["error"] = r.stderr
        except Exception as e:
            env_info["status"] = "error"
            env_info["error"] = str(e)

        self.environments[env_name] = env_info
        return env_info

    @staticmethod
    def _generate_vagrantfile(
        os_type: str, os_version: str, config: Optional[Dict[str, Any]] = None,
    ) -> str:
        boxes = {
            "ubuntu": f"ubuntu/{os_version}",
            "debian": f"debian/{os_version}",
            "centos": f"centos/{os_version}",
            "windows": "win10",
        }
        box = boxes.get(os_type, f"ubuntu/{os_version}")
        return (
            f'Vagrant.configure("2") do |config|\n'
            f'  config.vm.box = "{box}"\n'
            f'  config.vm.hostname = "analysis-{os_type}-{os_version}"\n'
            f'  config.vm.provider "virtualbox" do |vb|\n'
            f'    vb.memory = 2048\n'
            f'    vb.cpus = 2\n'
            f'  end\n'
            f'  config.vm.provision "shell", inline: <<-SHELL\n'
            f'    apt-get update\n'
            f'    apt-get install -y gdb strace ltrace radare2\n'
            f'  SHELL\n'
            f'end\n'
        )

    def create_snapshot(self, env_name: str, snapshot_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "name": snapshot_name,
            "env_name": env_name,
            "created_at": datetime.now().isoformat(),
            "status": "creating",
        }
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(
                ["vagrant", "snapshot", "save", snapshot_name],
                cwd=env_dir,
                capture_output=True, text=True, timeout=60,
            )
            info["status"] = "created" if r.returncode == 0 else "error"
            if r.returncode == 0:
                self.snapshots.setdefault(env_name, []).append(info)
            else:
                info["error"] = r.stderr
        except Exception as e:
            info["status"] = "error"
            info["error"] = str(e)
        return info

    def restore_snapshot(self, env_name: str, snapshot_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "env_name": env_name,
            "snapshot_name": snapshot_name,
            "status": "restoring",
            "timestamp": datetime.now().isoformat(),
        }
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(
                ["vagrant", "snapshot", "restore", snapshot_name],
                cwd=env_dir,
                capture_output=True, text=True, timeout=120,
            )
            info["status"] = "restored" if r.returncode == 0 else "error"
            if r.returncode != 0:
                info["error"] = r.stderr
        except Exception as e:
            info["status"] = "error"
            info["error"] = str(e)
        return info

    def destroy_environment(self, env_name: str) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "env_name": env_name,
            "status": "destroying",
            "timestamp": datetime.now().isoformat(),
        }
        env_dir = os.path.join(self.work_dir, env_name)
        try:
            r = subprocess.run(
                ["vagrant", "destroy", "-f"],
                cwd=env_dir,
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0:
                info["status"] = "destroyed"
                self.environments.pop(env_name, None)
            else:
                info["status"] = "error"
        except Exception as e:
            info["status"] = "error"
            info["error"] = str(e)
        return info

    def list_environments(self) -> List[Dict[str, Any]]:
        return list(self.environments.values())

    def list_snapshots(self, env_name: str) -> List[Dict[str, Any]]:
        return self.snapshots.get(env_name, [])


# Convenience function - integrated supply-chain analysis


def analyze_supply_chain(
    binary_path: str,
    enable_osv_check: bool = True,
    enable_nvd_enrich: bool = False,
) -> Dict[str, Any]:
    """Perform a full supply-chain security analysis on *binary_path*.

    Steps:
    1. Extract linked libraries
    2. Extract versions
    3. Check OSV.dev for known vulnerabilities
    4. Optionally enrich with NVD data
    5. Generate an SBOM

    Returns a comprehensive dict.
    """
    extractor = VersionExtractor()
    checker = VersionedVulnChecker()
    sbom_gen = SBOMGenerator()

    # step 1 - library detection via nm
    libs: List[str] = []
    try:
        r = subprocess.run(
            ["nm", binary_path],
            capture_output=True, text=True, timeout=30,
        )
        symbols = r.stdout
        prefixes_lib = {
            "openssl": "SSL_", "zlib": "zlib", "curl": "curl_",
            "json": "json_", "expat": "XML_", "sqlite": "sqlite3_",
            "pcre": "pcre_", "pthread": "pthread_",
            "lzma": "lzma_", "bz2": "BZ2_",
        }
        for lib, prefix in prefixes_lib.items():
            if prefix in symbols:
                libs.append(lib)
    except Exception:
        _logger.debug("suppressed", exc_info=True)

    # step 2 - versions
    versions = extractor.extract(binary_path=binary_path)
    for lib in libs:
        if lib not in versions:
            versions[lib] = "unknown"

    # step 3 - OSV check
    vulns: List[Dict[str, Any]] = []
    if enable_osv_check:
        for lib, ver in versions.items():
            if ver == "unknown":
                continue
            vulns.extend(checker.check(lib, ver))

    # step 4 - NVD enrichment
    if enable_nvd_enrich and vulns:
        vulns = checker.enrich_with_nvd(vulns)

    # step 5 - SBOM
    for lib, ver in versions.items():
        sbom_gen.add_component(lib, ver, "library")
    sbom_gen.add_component(os.path.basename(binary_path), "unknown", "application")

    return {
        "binary_path": binary_path,
        "static_libraries": libs,
        "versions": versions,
        "vulnerabilities": vulns,
        "sbom": {
            "cyclonedx": sbom_gen.export_cyclonedx(),
            "spdx": sbom_gen.export_spdx(),
        },
        "summary": sbom_gen.summary(),
        "generated_at": datetime.now().isoformat(),
    }
