"""DemandTriggerBudget - 按需触发预算管理器 (stage 73).

全局配额制: 每函数高级分析次数上限 N 次, 低置信度先用轻量证据,
配额耗尽走保守路径. 与按需符号尺寸关联 (Demand-Driven Symbolic Size Correlation) 不同: 预算管理器模式.

设计决策:
  - 类 DemandBudget: budget 计数 + 消耗接口
  - 低置信度 finding 用轻量正则证据判定
  - 配额耗尽后剩余 finding 走保守路径 (conf 减半, verdict=conservative)
"""

import re
from typing import Dict, List, Optional


class _Budget:
    """按需触发预算管理器."""

    def __init__(self, capacity: int):
        self.capacity = capacity
        self.used = 0

    def request(self) -> bool:
        """申请一次高级分析配额, 成功返回 True."""
        if self.used < self.capacity:
            self.used += 1
            return True
        return False

    def remaining(self) -> int:
        return self.capacity - self.used


def _lightweight_evidence(line: str) -> bool:
    """轻量证据: 是否含有明显的守卫或边界约束."""
    return "if" in line or "guard" in line or "<=" in line


def run_demand_trigger_budget(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    budget_size: int = 3,
) -> List[dict]:
    """按需触发预算. 返回 findings."""
    findings: List[dict] = []
    budget = _Budget(budget_size)
    lines = pseudocode.splitlines()
    targets = existing_findings or []
    if not targets:
        for i, line in enumerate(lines, 1):
            if re.search(r"\[[^\]]+\]\s*(?:,|=)", line):
                targets.append({
                    "type": "heap_overflow", "confidence": 0.5,
                    "description": f"write@line{i}",
                })
    for f in targets:
        out = dict(f)
        # 预算分类会覆盖 verdict 字段; 先保留基础检测器的原始判定,
        # 供计数层(pipeline 词表过滤)按原语义豁免, 避免基础检出
        # (如 intof LIKELY)被改写为中间态后误杀成漏报
        out.setdefault('verdict_original', out.get('verdict'))
        # 高置信度直接走高级分析
        if out.get("confidence", 0.5) >= 0.7:
            if budget.request():
                out["verdict"] = "advanced"
                out["source"] = "demand_trigger_budget"
            else:
                out["verdict"] = "conservative"
                out["confidence"] = round(out.get("confidence", 0.5) * 0.5, 2)
                out["source"] = "demand_trigger_budget"
        else:
            # 低置信度先用轻量证据
            if _lightweighted(lines):
                out["verdict"] = "lightweight"
                out["source"] = "demand_trigger_budget"
            elif budget.request():
                out["verdict"] = "advanced"
                out["source"] = "demand_trigger_budget"
            else:
                out["verdict"] = "conservative"
                out["confidence"] = round(out.get("confidence", 0.5) * 0.5, 2)
                out["source"] = "demand_trigger_budget"
        findings.append(out)
    return findings


def _lightweighted(lines: List[str]) -> bool:
    return any(_lightweight_evidence(line) for line in lines)


if __name__ == "__main__":
    demo = """\
p = malloc(64);
mov [p+8], 0;
"""
    out = run_demand_trigger_budget(
        demo, "demo",
        [
            {"type": "heap_overflow", "confidence": 0.8,
             "description": "write@line2"},
            {"type": "heap_overflow", "confidence": 0.4,
             "description": "write@line3"},
        ])
    for f in out:
        print(f["description"], f["verdict"], f["confidence"])