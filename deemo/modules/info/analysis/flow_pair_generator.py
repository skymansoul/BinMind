# analysis/flow_pair_generator — FC-VRA 阶段C0: 流相关分配-写入对生成器
# 核心创新点: 用值流绑定替代笛卡尔积配对。
# 现有 _make_pairs 将全部alloc函数 × 全部write函数 做叉积 (11×11≈121对),
# 其中绝大多数写入目标的缓冲区与分配结果无关联 — 误报主体来源。
# 堆溢出的必要条件: 写入目标缓冲区 = 某分配点产生的缓冲区,
# 因此按缓冲区别名流做绑定可保证召回不变 (真漏洞必然满足此条件),
# 同时把候选对数量从 O(A×W) 降到 O(实际写入点)。
# 理论依据: 堆分配点间不交集 — 不同分配点的缓冲区必须分开建模;
# 指针绑定用并查集式传播, 保持近线性。
#
# 与 pointer_tracker.py 的关系: 复用其提取/别名/绑定逻辑,
# 此处聚焦"绑定结果 → 候选对 + 大小表达式 + 绑定强度"的产出契约。

from __future__ import annotations
from typing import Dict, List, Optional, Tuple
import re

from pointer_tracker import (
    HeapPtr, extract_heap_ptrs, extract_write_sites,
    build_ptr_aliases, bind_writes_to_allocs,
)

def _sanitize_expr(expr: str) -> str:
    """去掉空白与多余括号, 作为后续等价比较的前置归一化。"""
    return re.sub(r"\s+", "", expr).strip()

class CorrelatedPair:
    """流相关候选对: 分配点 + 写入点 + 各自大小表达式。

    binding_conf 表示绑定强度: 1.0 唯一绑定 (must-alias),
    0.6 共享别名 (可能别名)。共享别名情况下不确定度上升。
    """

    __slots__ = ("alloc_var", "alloc_func", "alloc_size_expr",
                 "write_func", "write_buffer", "write_size_expr",
                 "binding_conf", "reason", "alloc_line", "write_line",
                 "raw_buffer")

    def __init__(self, alloc_var: str, alloc_func: str, alloc_size_expr: str,
                 write_func: str, write_buffer: str, write_size_expr: str,
                 binding_conf: float, reason: str,
                 alloc_line: int, write_line: int, raw_buffer: str = ""):
        self.alloc_var = alloc_var
        self.alloc_func = alloc_func
        self.alloc_size_expr = alloc_size_expr
        self.write_func = write_func
        self.write_buffer = write_buffer
        self.write_size_expr = write_size_expr
        self.binding_conf = binding_conf
        self.reason = reason
        self.alloc_line = alloc_line
        self.write_line = write_line
        self.raw_buffer = raw_buffer or write_buffer

    def to_dict(self) -> Dict:
        return {
            "alloc_var": self.alloc_var,
            "alloc_func": self.alloc_func,
            "alloc_size_expr": self.alloc_size_expr,
            "write_func": self.write_func,
            "write_buffer": self.write_buffer,
            "raw_buffer": self.raw_buffer,
            "write_size_expr": self.write_size_expr,
            "binding_conf": round(self.binding_conf, 2),
            "reason": self.reason,
            "alloc_line": self.alloc_line,
            "write_line": self.write_line,
        }

def _alloc_size_for(hp: HeapPtr) -> str:
    """从 HeapPtr 取出归一化的分配大小表达式。"""
    return _sanitize_expr(hp.alloc_size_expr) if hp.alloc_size_expr else "unknown"

def _write_size_for(ws: Dict) -> str:
    """从写入点取出归一化的写入量表达式。"""
    return _sanitize_expr(ws.get("size_expr", "unknown"))

def generate_correlated_pairs(code: str) -> List[CorrelatedPair]:
    """C0 主入口: 值流绑定生成候选对。

    输入: 函数体/整文件 C 源码。
    输出: 按绑定强度降序的候选对列表。

    若无分配点或无写入点 → 空列表 (调用方回退到笛卡尔积)。
    """
    heap_ptrs = extract_heap_ptrs(code)
    if not heap_ptrs:
        return []

    write_sites = extract_write_sites(code)
    if not write_sites:
        return []

    aliases = build_ptr_aliases(code, heap_ptrs)
    bindings = bind_writes_to_allocs(heap_ptrs, write_sites, aliases)

    pairs: List[CorrelatedPair] = []
    for b in bindings:
        hp: HeapPtr = b["alloc_ptr"]
        ws: Dict = b["write_site"]
        conf = b.get("confidence", 0.60)
        reason = b.get("reason", "alias_bind")
        pairs.append(CorrelatedPair(
            alloc_var=hp.var,
            alloc_func=hp.alloc_func or "malloc",
            alloc_size_expr=_alloc_size_for(hp),
            write_func=ws.get("func", "memcpy"),
            write_buffer=ws.get("buffer", ""),
            write_size_expr=_write_size_for(ws),
            binding_conf=conf,
            reason=reason,
            alloc_line=hp.line,
            write_line=ws.get("line", 0),
            raw_buffer=ws.get("raw_buffer", ws.get("buffer", "")),
        ))

    pairs.sort(key=lambda p: p.binding_conf, reverse=True)

    # 同一 (缓冲区, 分配变量) 出现多个分配点 (realloc链/遮蔽) → 保留最新分配
    # realloc 会释放旧块, 旧分配点的写目标已失效; 保留旧块会产生系统性误报。
    latest: Dict[Tuple[str, str], CorrelatedPair] = {}
    for p in pairs:
        key = (p.write_buffer, p.alloc_var)
        cur = latest.get(key)
        if cur is None or p.alloc_line > cur.alloc_line:
            latest[key] = p
    pairs = sorted(latest.values(), key=lambda p: p.binding_conf, reverse=True)
    return pairs

def stat_pair_reduction(code: str) -> Dict:
    """对比笛卡尔积与流相关绑定的数量级, 供实验记录。"""
    allocs = set(m.group(1) for m in re.finditer(
        r"\b(malloc|calloc|realloc)\s*\(", code))
    writes = set(m.group(1) for m in re.finditer(
        r"\b(memcpy|memmove|strcpy|strcat|strncpy|strncat|sprintf|"
        r"snprintf|read|recv|fread|gets)\s*\(", code))
    cartesian = len(allocs) * len(writes)
    pairs = generate_correlated_pairs(code)
    return {
        "alloc_funcs": sorted(allocs),
        "write_funcs": sorted(writes),
        "cartesian_pairs": cartesian,
        "correlated_pairs": len(pairs),
        "reduction_ratio": round(cartesian / max(len(pairs), 1), 2),
    }

def correlate_to_v2_pairs(code: str, raw_pairs: List[Dict]) -> List[Dict]:
    """流相关配对 → v2 管线兼容格式 (P0.5-C 集成)。

    若源码可用且值流绑定产出候选对, 用流相关对替换笛卡尔积对。
    真溢出必然满足"写入目标=分配缓冲区" (必要不充分), 故召回下界不变,
    而候选对数量由 O(A×W) 降至 O(写入点) — 误报主体被结构性消除。
    """
    if not code:
        return raw_pairs
    try:
        pairs = generate_correlated_pairs(code)
    except Exception:
        return raw_pairs
    if not pairs:
        return raw_pairs
    converted = []
    for p in pairs:
        wf = p.write_func
        risk = 0.90 if wf in ("gets", "manual_loop_write") else (
            0.85 if wf in ("strcpy", "strcat", "sprintf", "recv") else 0.60)
        converted.append({
            "alloc_func": p.alloc_func,
            "write_func": wf,
            "alloc_size_source": p.alloc_size_expr or "UNKNOWN",
            "write_size_source": p.write_size_expr or "UNKNOWN",
            "overflow_risk": round(min(1.0, risk + 0.2 * (p.binding_conf - 0.5)), 2),
            "reason": "P0.5-C:flow=" + p.reason,
            "same_dll": False,
            "__alloc_expr__": p.alloc_size_expr,
            "__write_expr__": p.write_size_expr,
            "__buffer__": p.write_buffer,
        })
    converted.sort(key=lambda x: x["overflow_risk"], reverse=True)
    return converted

if __name__ == "__main__":
    import sys
    sample = sys.stdin.read() if not sys.stdin.isatty() else ""
    if not sample:
        sample = ("char *b = malloc(64);\n"
                  "memcpy(b, src, 128);\n"
                  "char *c = malloc(256);\n"
                  "memcpy(c, src, 32);\n")
    pairs = generate_correlated_pairs(sample)
    for p in pairs:
        print(p.to_dict())
    print("stats:", stat_pair_reduction(sample))
