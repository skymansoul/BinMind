"""EvalHarnessReplica - 端到端评估复算 (stage 65).

对当前函数的 findings 在内置迷你评估器上复算 TP/FP 语义一致性
(告警类型 vs 源码特征), 不一致的降权. 与全部检测模块不同:
这是元评估层 (对 findings 二次审计).

设计决策:
  - 内置迷你评估器: 根据 finding.type 与伪代码特征做一致性判断
  - heap_overflow: 需存在 malloc + 越界写
  - use_after_free: 需存在 free + 后续写
  - format_string: 需存在非字面量格式串
  - 不一致 -> confidence 减半, verdict 标记 inconsistent
"""

import re
from typing import List, Optional


def _mini_eval(pseudocode: str, ftype: str) -> bool:
    """迷你评估器: 伪代码是否具备该告警类型的特征."""
    if ftype == "heap_overflow":
        # 汇编风格: 分配 + 数组越界写
        if (re.search(r"malloc|calloc|realloc", pseudocode) is not None
                and re.search(r"\[[^\]]+\]\s*=", pseudocode) is not None):
            return True
        # C 风格: 提取 malloc 常量容量与 memcpy/memset 长度做比对
        malloc_consts = re.findall(r"(?:malloc|calloc|realloc)\s*\(\s*(\d+)\s*\)", pseudocode)
        copy_lens = re.findall(r"(?:memcpy|memset)\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\)", pseudocode)
        if malloc_consts and copy_lens:
            max_alloc = max(int(x) for x in malloc_consts)
            for cl in copy_lens:
                if cl.isdigit() and int(cl) > max_alloc:
                    return True
                if not cl.isdigit():
                    # 常量分配 + 变量长度拷贝 → 潜在溢出
                    return True
        # C 风格: 变量分配 + 拷贝长度与分配变量不同 → 潜在溢出
        malloc_vars = re.findall(r"(?:malloc|calloc|realloc)\s*\(\s*([a-zA-Z_]\w*)\s*\)", pseudocode)
        if malloc_vars and copy_lens:
            for cl in copy_lens:
                if cl.isdigit():
                    return True
                if cl not in malloc_vars:
                    return True
        return False
    if ftype == "use_after_free":
        if re.search(r"\bfree\s*\(", pseudocode) is None:
            return False
        # 汇编风格: free 后数组写
        if re.search(r"\[[^\]]+\]\s*=", pseudocode) is not None:
            return True
        # C 风格: free 后 memcpy/memset 使用已释放指针
        if re.search(r"\bfree\s*\([^)]+\)\s*;.*?(?:memcpy|memset)\s*\(", pseudocode, re.DOTALL) is not None:
            return True
        # C 风格: free 后指针解引用写
        if re.search(r"\bfree\s*\([^)]+\)\s*;.*?->\w+\s*=", pseudocode, re.DOTALL) is not None:
            return True
        return False
    if ftype == "format_string":
        # 汇编风格: 含格式符
        if "%" in pseudocode:
            return True
        # C 风格: 非字面量直接作为格式串参数
        if re.search(r"\b(?:printf|fprintf|sprintf|snprintf)\s*\(\s*[a-zA-Z_]\w*\s*\)", pseudocode) is not None:
            return True
        return False
    return True


def run_eval_harness_replica(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
) -> List[dict]:
    """端到端评估复算. 返回 findings."""
    findings: List[dict] = []
    targets = existing_findings or []
    if not targets:
        # 无输入时对伪代码做一次自检
        for ftype in ("heap_overflow", "use_after_free", "format_string"):
            consistent = _mini_eval(pseudocode, ftype)
            if consistent:
                targets.append({"type": ftype, "confidence": 0.5})
    for f in targets:
        out = dict(f)
        consistent = _mini_eval(pseudocode, f.get("type", ""))
        if not consistent:
            out["confidence"] = round(out.get("confidence", 0.5) * 0.5, 2)
            out["verdict"] = "inconsistent"
            out["source"] = "eval_harness_replica"
        else:
            out["verdict"] = "consistent"
            out["source"] = "eval_harness_replica"
        findings.append(out)
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(16);
mov [p+32], 0;
"""
    out = run_eval_harness_replica(
        demo, "demo",
        [{"type": "heap_overflow", "confidence": 0.8}])
    for item in out:
        print(item["type"], item["verdict"], item["confidence"])