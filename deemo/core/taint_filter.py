# 两级污点过滤
from typing import List, Set, Optional
import re

_SOURCE_FUNCTIONS = {
    "read", "fread", "recv", "recvfrom", "fgets", "gets",
    "scanf", "fscanf", "getenv", "getopt",
}

def is_external_source(func_name):
    return func_name.lower() in _SOURCE_FUNCTIONS

def taint_trace_2hop(proj, target_call_addr):
    try:
        cfg = proj.analyses.CFGFast(normalize=True)
        node = cfg.model.get_any_node(target_call_addr)
        if node is None: return False
        preds = list(cfg.model.get_predecessors(node))
        for pred in preds[:5]:
            block = cfg.model.get_any_node(pred.addr)
            if block is None: continue
            insns = getattr(block, "disassembly", None)
            if insns is None: continue
            for insn in reversed(insns.insns if hasattr(insns, "insns") else []):
                if insn.mnemonic == "call":
                    op = insn.op_str or ""
                    for src in _SOURCE_FUNCTIONS:
                        if src in op: return True
                    break
        return False
    except Exception:
        return False

def filter_format_findings(findings, binary_path):
    filtered = []
    for f_r in findings:
        call_line = f_r.get("call_line", "")
        if not call_line:
            filtered.append(f_r)
            continue
        # printf("const") -> safe
        if re.match(r'.*(printf|fprintf|sprintf|snprintf)\s*\(\s*"', call_line):
            continue
        filtered.append(f_r)
    return filtered


class TaintFilter:
    """两级污点过滤 — 标记漏洞候选是否源自外部输入。

    第一级: 按反编译伪代码的函数名判断外部输入源;
    第二级: 按调用行判断格式化参数是否为编译期常量。
    """

    def __init__(self):
        self.sources = set(_SOURCE_FUNCTIONS)

    def is_external_source(self, func_name: str) -> bool:
        return func_name.lower() in self.sources

    def add_source(self, func_name: str) -> None:
        self.sources.add(func_name.lower())

    def filter_findings(self, findings: List[dict]) -> List[dict]:
        """过滤掉格式化参数为常量的误报候选。"""
        return filter_format_findings(findings, None)

    def analyze(self, ir):
        """从 IR 行识别外部输入源调用。

        记录命中的输入源函数, 返回 self 供链式调用。
        """
        self._external_calls = []
        for line in (ir or []):
            for src in self.sources:
                if re.search(r'\b' + re.escape(src) + r'\s*\(', line):
                    self._external_calls.append(src)
                    break
        return self
