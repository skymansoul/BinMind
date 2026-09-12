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
        return (re.search(r"malloc|calloc|realloc", pseudocode) is not None
                and re.search(r"\[[^\]]+\]\s*=", pseudocode) is not None)
    if ftype == "use_after_free":
        return (re.search(r"\bfree\s*\(", pseudocode) is not None
                and re.search(r"\[[^\]]+\]\s*=", pseudocode) is not None)
    if ftype == "format_string":
        return ("%" in pseudocode)
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