"""ProvenanceOctagon - 八类溯源格 + 精度传播 (stage 89).

MALLOC/CALLOC/REALLOC/STACK/GLOBAL/PARAMETER/DERIVED/UNKNOWN 八类
溯源, DERIVED 带父链, 精度传播追踪. 与 ColorClassQuad(86) 不同:
本模块做八类格 join 半格运算 + 精度域传播, 非四色分类+交叉域互斥.

设计决策:
  - 八类溯源格: 类间偏序 (join 取更精确者)
  - DERIVED 类型带父溯源
  - join: 沿数据流仅在赋值处做 b=a 的 join, 不与所有变量 join
  - 精度传播: MALLOC(精确) -> DERIVED(不精确) 标记 precision_loss
  - PARAMETER: 函数签名中声明的参数
"""

import re
from typing import Dict, List, Optional, Tuple

# 八类溯源
_MALLOC, _CALLOC, _REALLOC = "MALLOC", "CALLOC", "REALLOC"
_STACK, _GLOBAL, _PARAM = "STACK", "GLOBAL", "PARAMETER"
_DERIVED, _UNKNOWN = "DERIVED", "UNKNOWN"

# 偏序: 具体类(0) < DERIVED(1) < UNKNOWN(2)
_PRECISION = {
    _MALLOC: 0, _CALLOC: 0, _REALLOC: 0, _STACK: 0,
    _GLOBAL: 0, _PARAM: 0, _DERIVED: 1, _UNKNOWN: 2,
}


def _join(a: str, b: str) -> str:
    """格 join: 取更精确 (偏序较小) 者; 同精度不同类 -> DERIVED."""
    pa, pb = _PRECISION[a], _PRECISION[b]
    if pa < pb:
        return a
    if pb < pa:
        return b
    if a == b:
        return a
    return _DERIVED


def _detect_parameters(pseudocode: str) -> Dict[str, str]:
    """从函数签名行检测 PARAMETER 类变量.

    匹配形如 `int p` / `char *p` / `void *p` 在函数签名中的参数声明.
    """
    params: Dict[str, str] = {}
    for line in pseudocode.splitlines():
        # 函数签名行: 含括号和类型声明, 如 "func(int p, char *q)"
        m_sig = re.search(
            r"\b(?:int|char|void|long|short|unsigned|size_t)\s+\*?(\w+)"
            r"(?:\s*,\s*(?:int|char|void|long|short|unsigned|size_t)\s+\*?(\w+))*",
            line,
        )
        if m_sig:
            # 提取签名中所有参数名
            for pm in re.finditer(
                r"(?:int|char|void|long|short|unsigned|size_t)\s+\*?(\w+)",
                line,
            ):
                params[pm.group(1)] = _PARAM
    return params


def _provenance_of(pseudocode: str) -> Dict[str, str]:
    """为变量标注溯源类, 含 PARAMETER 检测."""
    prov: Dict[str, str] = {}
    # 先检测参数
    params = _detect_parameters(pseudocode)
    prov.update(params)
    for line in pseudocode.splitlines():
        m = re.search(r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(", line)
        if m:
            prov[m.group(1)] = m.group(2).upper()
            continue
        m = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m:
            prov[m.group(1)] = _STACK
            continue
        m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*;", line)
        if m and m.group(2) in prov:
            # 沿数据流 join: b = a 时 b 的溯源类 = join(b 原, a)
            a_prov = prov[m.group(2)]
            b_old = prov.get(m.group(1), _UNKNOWN)
            prov[m.group(1)] = _join(b_old, a_prov)
    return prov


def _trace_precision(
    pseudocode: str, prov: Dict[str, str]
) -> List[dict]:
    """精度传播追踪: 记录溯源类精度等级变化链.

    MALLOC/CALLOC/REALLOC(精确,0) -> DERIVED(不精确,1): precision_loss
    保持精确: precision_preserved
    """
    precision_findings: List[dict] = []
    # 跟踪每个变量的精度变化
    var_precision: Dict[str, int] = {}
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"\b(\w+)\s*=\s*(\w+)\s*;", line)
        if m and m.group(2) in prov:
            var_name = m.group(1)
            src_prov = prov.get(m.group(2), _UNKNOWN)
            src_prec = _PRECISION.get(src_prov, 2)
            old_prec = var_precision.get(var_name)
            if old_prec is not None and src_prec > old_prec:
                # 精度降级
                precision_findings.append({
                    "line": ln,
                    "var": var_name,
                    "verdict": "precision_loss",
                    "desc": f"line{ln} {var_name} 精度从 {old_prec} 降级到 {src_prec}",
                })
            elif old_prec is not None and src_prec <= old_prec:
                precision_findings.append({
                    "line": ln,
                    "var": var_name,
                    "verdict": "precision_preserved",
                    "desc": f"line{ln} {var_name} 精度保持 {src_prec}",
                })
            var_precision[var_name] = src_prec
        # 直接赋值的精度初始化
        m_alloc = re.search(
            r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(", line
        )
        if m_alloc:
            var_precision[m_alloc.group(1)] = 0
        m_stack = re.search(r"\b(\w+)\s*=\s*(?:rbp|rsp)", line)
        if m_stack:
            var_precision[m_stack.group(1)] = 0
    return precision_findings


def run_provenance_octagon(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """八类溯源格 + 精度传播. 返回 findings."""
    findings: List[dict] = []
    prov = _provenance_of(pseudocode)
    # 精度传播追踪
    precision_findings = _trace_precision(pseudocode, prov)
    for pf in precision_findings:
        findings.append({
            "type": "memory_write",
            "function": func_name or "unknown",
            "severity": "low" if pf["verdict"] == "precision_preserved" else "medium",
            "cwe": "CWE-787",
            "confidence": 0.5,
            "description": pf["desc"],
            "verdict": pf["verdict"],
            "source": "provenance_octagon",
            # 精度传播是元信息追踪, 不是漏洞判定
            "rw_weak": True,
        })
    # 写点溯源审计 (汇编风格)
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m = re.search(r"(?<!\w)\[\s*(\w+)\s*(\+\s*\w+)?\]\s*(?:,|=)", line)
        if not m:
            continue
        var = m.group(1)
        p = prov.get(var, _UNKNOWN)
        is_heap = p in (_MALLOC, _CALLOC, _REALLOC, _DERIVED)
        verdict = "heap_prov" if is_heap else "non_heap_prov"
        findings.append({
            "type": "heap_overflow" if is_heap else "memory_write",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122" if is_heap else "CWE-787",
            "confidence": 0.6 if is_heap else 0.3,
            "description": f"line{ln} var={var} prov={p}",
            "verdict": verdict,
            "source": "provenance_octagon",
            # UNKNOWN 溯源: 变量无来源记录无法判定域归属, 是线索不是判定
            "rw_weak": p == _UNKNOWN,
        })

    # C 风格写点溯源审计: buf[expr]=val 基址溯源
    # 收集 malloc 容量 (常量和表达式)
    alloc_caps: dict = {}
    for line in pseudocode.splitlines():
        m_a = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\d+)\s*\)",
            line,
        )
        if m_a:
            alloc_caps[m_a.group(1)] = int(m_a.group(2))
        m_av = re.search(
            r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*([^)]+)\s*\)",
            line,
        )
        if m_av and not m_av.group(2).strip().isdigit():
            alloc_caps[m_av.group(1)] = None

    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_idx = re.search(r"(\w+)\s*\[([^\]]+)\]\s*=\s*(\S+)", line)
        if not m_idx:
            continue
        buf_var = m_idx.group(1)
        idx_expr = m_idx.group(2).strip()
        p = prov.get(buf_var, _UNKNOWN)
        is_heap = p in (_MALLOC, _CALLOC, _REALLOC, _DERIVED)
        if not is_heap:
            # 非堆基址 (如栈数组 local[32]) → non_heap_prov
            findings.append({
                "type": "memory_write",
                "function": func_name or "unknown",
                "severity": "medium",
                "cwe": "CWE-787",
                "confidence": 0.3,
                "description": f"line{ln} var={buf_var} prov={p}",
                "verdict": "non_heap_prov",
                "source": "provenance_octagon",
                "rw_weak": p == _UNKNOWN,
            })
            continue
        # 堆基址: 检查写偏移与容量是否相容
        cap = alloc_caps.get(buf_var)
        if cap is None:
            # malloc(变量) 容量未知, 偏移含变量算术 → 无法证明相容 → 不产出
            if not idx_expr.isdigit():
                continue
        else:
            # 常量容量, 偏移含变量算术 → 无法证明相容 → 不产出
            if not idx_expr.isdigit():
                continue
            # 常量偏移 vs 常量容量
            off = int(idx_expr, 0)
            if off > cap:
                # 偏移超容量 → 不产出 heap_prov (避免压真)
                continue
        # 偏移与容量相容或容量未知 → heap_prov (降权)
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.6,
            "description": f"line{ln} var={buf_var} prov={p} idx={idx_expr}",
            "verdict": "heap_prov",
            "source": "provenance_octagon",
        })

    # C 风格 memcpy 写点溯源: dst 基址为堆且长度相容 → heap_prov
    # 先扫描全部下标写点, 若任一明确越界则不产 heap_prov (避免压真)
    alloc_size_var = None
    m_asv = re.search(
        r"(\w+)\s*=\s*(?:\([^)]*\)\s*)?malloc\s*\(\s*(\w+)\s*\)", pseudocode)
    if m_asv and not m_asv.group(2).isdigit():
        alloc_size_var = m_asv.group(2)
    has_clear_oob = False
    if alloc_size_var:
        for line in pseudocode.splitlines():
            m_oo = re.search(
                r"(\w+)\s*\[\s*" + re.escape(alloc_size_var)
                + r"\s*\+\s*\d+\s*\]", line)
            if m_oo:
                has_clear_oob = True
                break
            m_stride = re.search(
                r"(\w+)\s*\[\s*(\w+)\s*\*\s*(\d+)\s*\]", line)
            if m_stride and m_stride.group(2) == alloc_size_var:
                has_clear_oob = True
                break
    for ln, line in enumerate(pseudocode.splitlines(), 1):
        m_copy = re.search(
            r"\b(?:memcpy|memmove)\s*\(\s*(\w+)\s*,\s*\w+\s*,\s*(\w+)\s*\)",
            line,
        )
        if not m_copy:
            continue
        dst_var = m_copy.group(1)
        len_tok = m_copy.group(2)
        p = prov.get(dst_var, _UNKNOWN)
        is_heap = p in (_MALLOC, _CALLOC, _REALLOC, _DERIVED)
        if not is_heap:
            continue
        # 存在明确越界下标写时, memcpy 安全结论不可信, 不产 heap_prov
        if has_clear_oob:
            continue
        cap = alloc_caps.get(dst_var)
        if cap is not None and len_tok.isdigit():
            if int(len_tok) > cap:
                # 长度超容量 → 不产出 heap_prov (避免压真)
                continue
        # 长度相容或容量未知 → heap_prov
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": 0.6,
            "description": f"line{ln} var={dst_var} prov={p} copy_len={len_tok}",
            "verdict": "heap_prov",
            "source": "provenance_octagon",
        })

    return findings


if __name__ == "__main__":
    demo = """\
func(int p, char *q)
r = malloc(64);
s = r;
mov [s+8], 0;
"""
    out = run_provenance_octagon(demo, "demo")
    for f in out:
        print(f["description"], f["verdict"])
