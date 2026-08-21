# 供应链漏洞可达性分析。
# 三层递进：导入表直接引用 - objdump调用图BFS - 二进制字符串匹配。
# 置信度递减: L1=100%, L2=85%, L3=50%

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
import subprocess
import re
import os
from collections import deque


@dataclass
class ReachabilityResult:
    """CVE-组件对可达性分析结论。"""
    component: str
    cve_id: str
    reachable: bool
    confidence: float  # 置信度区间0.0-1.0
    path: List[str] = field(default_factory=list)
    evidence: str = ""


# CallGraphBuilder: objdump解析与调用图构建

class CallGraphBuilder:
    """从objdump反汇编提取call/bl指令，构建有向调用图。

    parse_objdump: 按函数边界切分，每条call指令提取目标符号。
    bfs_reachable: BFS判断start_func到target_func的可达路径。
    """

    _FUNC_START = re.compile(r'^([0-9a-fA-F]+)\s+<([^>]+)>:')
    _CALL_INSN = re.compile(r'(call|bl|blx|b\s+)\s+(0x)?<?([0-9a-fA-F]+|[\w@.]+)>?')

    def __init__(self):
        self.edges: Dict[str, Set[str]] = {}
        self._reverse: Dict[str, Set[str]] = {}

    def parse_objdump(self, disasm: str) -> None:
        current_func = ""
        for line in disasm.split("\n"):
            fm = self._FUNC_START.match(line)
            if fm:
                current_func = fm.group(2)
                self.edges.setdefault(current_func, set())
                self._reverse.setdefault(current_func, set())
                continue
            if current_func:
                cm = self._CALL_INSN.search(line)
                if cm:
                    target = cm.group(3)
                    self.edges[current_func].add(target)
                    self._reverse.setdefault(target, set()).add(current_func)

    def parse_objdump_raw(self, binary_path: str) -> str:
        if not os.path.isfile(binary_path):
            return ""
        try:
            r = subprocess.run(["objdump", "-d", binary_path],
                               capture_output=True, text=True, timeout=30)
            return r.stdout if r.returncode == 0 else ""
        except Exception:
            return ""

    def build_from_binary(self, binary_path: str) -> None:
        raw = self.parse_objdump_raw(binary_path)
        if raw:
            self.parse_objdump(raw)

    def bfs_reachable(self, start_func: str, target_func: str,
                      max_depth: int = 6) -> Tuple[bool, List[str]]:
        if start_func not in self.edges:
            return False, []
        if target_func == start_func:
            return True, [start_func]
        # 模糊匹配目标名
        targets = {target_func}
        for fname in self.edges:
            if target_func in fname or fname in target_func:
                targets.add(fname)
        visited = {start_func}
        parent: Dict[str, Optional[str]] = {start_func: None}
        q: deque = deque([(start_func, 0)])
        while q:
            cur, depth = q.popleft()
            if depth >= max_depth:
                continue
            for callee in self.edges.get(cur, set()):
                if callee in targets:
                    path = [callee]
                    p = cur
                    while p is not None:
                        path.append(p)
                        p = parent[p]
                    path.reverse()
                    return True, path
                if callee not in visited:
                    visited.add(callee)
                    parent[callee] = cur
                    q.append((callee, depth + 1))
        return False, []

    def get_callers(self, func_name: str) -> Set[str]:
        return self._reverse.get(func_name, set())

    def stats(self) -> Dict:
        return {"functions": len(self.edges),
                "edges": sum(len(v) for v in self.edges.values())}


# 三层可达性检测辅助函数

def _find_imports(disasm: str, component_symbols: List[str]) -> Dict[str, bool]:
    """L1检测。反汇编中搜索call/jmp/bl对目标符号的直接引用。"""
    results = {}
    for sym in component_symbols:
        pat = re.compile(rf'(call|jmp|bl|blx)\s+.*<?{re.escape(sym)}>?', re.IGNORECASE)
        found = bool(pat.search(disasm))
        if not found:
            found = sym in disasm
        results[sym] = found
    return results


def _find_string_refs(strings_text: str, component_names: List[str],
                      version_strs: List[str]) -> Dict[str, List[str]]:
    """L3检测。strings输出中检索组件名及版本号。"""
    results: Dict[str, List[str]] = {}
    txt_lower = strings_text.lower()
    for name in component_names:
        if name.lower() in txt_lower:
            results.setdefault(name, []).append(f"string_match:{name}")
    for vstr in version_strs:
        if vstr and vstr in strings_text:
            for name in component_names:
                results.setdefault(name, []).append(f"version:{vstr}")
    return results


# 主分析入口

def analyze_reachability(binary_path: str, sbom_components: List[Dict],
                         disasm: str = "", strings_text: str = "",
                         entry_points: Optional[List[str]] = None
                         ) -> List[ReachabilityResult]:
    """三层供应链漏洞可达性分析。

    参数:
        binary_path: 目标二进制路径
        sbom_components: SBOM组件列表
        disasm: 预取反汇编文本（可选）
        strings_text: 预取strings输出（可选）
        entry_points: 入口函数列表（可选，默认main/start）

    返回按置信度降序排列的ReachabilityResult列表。
    """
    if not disasm:
        cg = CallGraphBuilder()
        disasm = cg.parse_objdump_raw(binary_path)
    if not strings_text and binary_path and os.path.isfile(binary_path):
        try:
            r = subprocess.run(["strings", binary_path],
                               capture_output=True, text=True, timeout=30)
            strings_text = r.stdout if r.returncode == 0 else ""
        except Exception:
            strings_text = ""

    cg = CallGraphBuilder()
    cg.parse_objdump(disasm)

    if not entry_points:
        entry_points = ["main", "_start", "start", "WinMain", "DllMain"]

    results = []
    for comp in sbom_components:
        cve_ids = comp.get("cve_ids", [comp.get("cve_id", "")])
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids] if cve_ids else []
        name = comp.get("name", "")
        if not name:
            continue
        symbols = comp.get("symbols", [])
        if not symbols:
            symbols = [name, f"lib{name}", f"{name}_init", f"{name}_main"]

        for cid in cve_ids:
            if not cid:
                continue
            reachable = False; confidence = 0.0; evidence = ""; path = []

            # L1: 导入表直接引用
            import_hits = _find_imports(disasm, symbols)
            direct_hits = [s for s, h in import_hits.items() if h]
            if direct_hits:
                reachable = True; confidence = 1.0
                evidence = f"L1: direct import ({','.join(direct_hits)})"
                path = [direct_hits[0]]
            else:
                # L2: 调用图BFS
                l2_hit = False
                for ep in entry_points:
                    for sym in symbols:
                        ok, bfs_path = cg.bfs_reachable(ep, sym, max_depth=6)
                        if ok:
                            reachable = True; l2_hit = True; confidence = 0.85
                            evidence = f"L2: BFS from {ep}"
                            path = bfs_path
                            break
                    if l2_hit:
                        break
                # L3: 字符串引用
                if not l2_hit:
                    ver_strs = [comp.get("version", "")]
                    str_hits = _find_string_refs(strings_text, symbols, ver_strs)
                    if str_hits:
                        reachable = True; confidence = 0.50
                        matched = ";".join(f"{k}:{','.join(v)}" for k, v in str_hits.items())
                        evidence = f"L3: string ref ({matched[:120]})"

            results.append(ReachabilityResult(
                component=name, cve_id=cid, reachable=reachable,
                confidence=round(confidence, 2), path=path, evidence=evidence))

    results.sort(key=lambda r: r.confidence, reverse=True)
    return results


def batch_analyze_reachability(binary_paths: List[str],
                               sbom: List[Dict]) -> Dict[str, List[ReachabilityResult]]:
    all_results = {}
    for bp in binary_paths:
        if os.path.isfile(bp):
            all_results[bp] = analyze_reachability(bp, sbom)
    return all_results


def reachability_summary(results: List[ReachabilityResult]) -> Dict:
    total = len(results)
    rc = sum(1 for r in results if r.reachable)
    l1 = sum(1 for r in results if r.evidence.startswith("L1"))
    l2 = sum(1 for r in results if r.evidence.startswith("L2"))
    l3 = sum(1 for r in results if r.evidence.startswith("L3"))
    return {"total_pairs": total, "reachable": rc,
            "tiers": {"L1_direct": l1, "L2_callgraph": l2, "L3_string": l3},
            "rate": round(rc / total, 2) if total > 0 else 0.0}
