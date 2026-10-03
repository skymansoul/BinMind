"""
仿射关系边界验证 逐阶段能力演示 — 对每个FP削减阶段, 用合成候选展示其过滤机制.

与 validate_fp_reduction.py 的关系:
  - validate_fp_reduction: 端到端17样本回归测试 (整体指标)
  - 本脚本: 逐阶段机制演示 (论文方法部分) — 展示每个阶段"为什么"能过滤

每个stage一个演示用例, 跟踪: 输入候选 → 阶段处理 → 输出 + 置信度变化.
"""

from __future__ import annotations

import json, os, sys, time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _BASE)

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)


# 演示用例: (描述, alloc_site, store, 期望过滤的阶段)

DEMO_CASES = [
    # S1: allocator semantics — write within requested size should be filtered
    {
        "name": "S1_in_request_bounds",
        "description": "malloc(64) → store offset=32 size=16 → 48 ≤ 64 (在请求范围内)",
        "alloc": HeapAllocSite(pc=0, alloc_func="malloc", size_arg=64,
                               size_is_dynamic=False, result_var="buf"),
        "store": HeapStore(pc=1, base_var="buf", offset=32, offset_is_dynamic=False,
                           store_size=16, mnemonic="mov"),
        "expected_stage": "S1_AllocatorSemantics",
        "should_filter": True,
        "is_vuln": False,
    },
    # S1: NOT filtered — genuine overflow
    {
        "name": "S1_genuine_overflow",
        "description": "malloc(64) → store offset=72 size=8 → 80 > 64 (真实溢出)",
        "alloc": HeapAllocSite(pc=0, alloc_func="malloc", size_arg=64,
                               size_is_dynamic=False, result_var="buf"),
        "store": HeapStore(pc=1, base_var="buf", offset=72, offset_is_dynamic=False,
                           store_size=8, mnemonic="mov"),
        "expected_stage": "S1_AllocatorSemantics",
        "should_filter": False,
        "is_vuln": True,
    },
    # S3: size constraints — clamp pattern
    {
        "name": "S3_clamp_constrained",
        "description": "if(size>1024)size=1024; malloc(size); memcpy(buf,src,size) → size≤1024, alloc≥1024",
        "alloc": HeapAllocSite(pc=4, alloc_func="malloc", size_arg=0,
                               size_is_dynamic=True, result_var="buf",
                               size_expr="size"),
        "store": HeapStore(pc=5, base_var="buf", offset=0, offset_is_dynamic=False,
                           store_size=-1, mnemonic="memcpy"),
        "expected_stage": "S3_SizeConstraints",
        "should_filter": True,
        "is_vuln": False,
        "source": """int process(int size, char *src) {
    if (size > 1024) { size = 1024; }
    char *buf = (char *)malloc(size);
    if (!buf) return -1;
    memcpy(buf, src, size);
    free(buf);
    return 0;
}""",
    },
    # S4: proof obligation — guard at write site
    {
        "name": "S4_guard_protected",
        "description": "malloc(256); if(idx<256) buf[idx]=val → idx≤255, 256B边界内",
        "alloc": HeapAllocSite(pc=2, alloc_func="malloc", size_arg=256,
                               size_is_dynamic=False, result_var="buf"),
        "store": HeapStore(pc=4, base_var="buf", offset=0,
                           offset_is_dynamic=True, store_size=4, mnemonic="mov"),
        "expected_stage": "S4_ProofObligations",
        "should_filter": True,
        "is_vuln": False,
        "source": """int process(int idx, int val) {
    char *buf = (char *)malloc(256);
    if (!buf) return -1;
    if (idx < 256) {
        buf[idx] = val;
    }
    free(buf);
    return 0;
}""",
    },
    # S5: slack space — offset in chunk tail padding
    {
        "name": "S5_slack_space_safe",
        "description": "malloc(20) → chunk=48, usable≈32, offset=24 size=4 → end=28 < 32 (在slack内)",
        "alloc": HeapAllocSite(pc=0, alloc_func="malloc", size_arg=20,
                               size_is_dynamic=False, result_var="buf"),
        "store": HeapStore(pc=1, base_var="buf", offset=24, offset_is_dynamic=False,
                           store_size=4, mnemonic="mov"),
        "expected_stage": "S5_SlackSpace",
        "should_filter": True,
        "is_vuln": False,
    },
    # S7: non-heap write
    {
        "name": "S7_stack_write",
        "description": "栈变量p的写入被误识别为堆写入 → S7应过滤",
        "alloc": HeapAllocSite(pc=0, alloc_func="malloc", size_arg=64,
                               size_is_dynamic=False, result_var="heap_buf"),
        "store": HeapStore(pc=2, base_var="stack_var", offset=0, offset_is_dynamic=False,
                           store_size=16, mnemonic="memcpy"),
        "expected_stage": "S7_NonHeapFilter",
        "should_filter": True,
        "is_vuln": False,
    },
]


def make_candidate(alloc: HeapAllocSite, store: HeapStore,
                   desc: str = "", confidence: float = 0.60) -> HeapOverflowCandidate:
    """创建测试候选."""
    overflow = max(0, store.offset + max(store.store_size, 1) - alloc.size_arg)
    return HeapOverflowCandidate(
        alloc_site=alloc,
        overflow_store=store,
        overflow_bytes=overflow if alloc.size_arg > 0 else 0,
        confidence=confidence,
        description=desc,
    )


def run_stage_demo() -> List[Dict]:
    """对每个演示用例运行对应的FP削减阶段, 记录结果."""
    from analysis.fp_reduction_integrator import FPReductionIntegrator
    from analysis.fp_filter_stages import (
        stage1_allocator_semantics, stage3_size_constraints,
        stage4_proof_obligations, stage5_slack_space, stage7_non_heap,
    )

    integrator = FPReductionIntegrator()
    results = []

    for case in DEMO_CASES:
        name = case["name"]
        alloc = case["alloc"]
        store = case["store"]
        expected_stage = case["expected_stage"]
        should_filter = case["should_filter"]

        c = make_candidate(alloc, store, desc=case["description"])
        candidates = [c]

        # 获取源码行 (如果有)
        src_lines = case.get("source", "").splitlines()

        # 运行对应阶段
        before_conf = c.confidence
        before_desc = c.description

        if expected_stage == "S1_AllocatorSemantics":
            after = stage1_allocator_semantics(integrator, candidates)
            filtered = len(after) == 0
        elif expected_stage == "S3_SizeConstraints":
            after, _ = stage3_size_constraints(integrator, candidates, src_lines)
            filtered = c.confidence < 0.30  # 置信度大幅降低
        elif expected_stage == "S4_ProofObligations":
            after, _, _ = stage4_proof_obligations(integrator, candidates, src_lines)
            filtered = c.confidence < 0.30
        elif expected_stage == "S5_SlackSpace":
            after, _ = stage5_slack_space(integrator, candidates)
            filtered = c.confidence < 0.30
        elif expected_stage == "S7_NonHeapFilter":
            after, _ = stage7_non_heap(integrator, candidates, src_lines)
            filtered = len(after) == 0
        else:
            after = candidates
            filtered = False

        after_conf = c.confidence
        match = filtered == should_filter

        result = {
            "case": name,
            "stage": expected_stage,
            "description": case["description"],
            "should_filter": should_filter,
            "actually_filtered": filtered,
            "confidence_before": before_conf,
            "confidence_after": after_conf,
            "match": match,
        }
        results.append(result)

    return results


def main():
    print("仿射关系边界验证 Stage Mechanism Demonstration")
    print("=" * 70)

    results = run_stage_demo()

    passed = sum(1 for r in results if r["match"])
    total = len(results)
    print(f"{'Case':<30} {'Stage':<24} {'Expect':>7} {'Got':>7} {'Match':>6}")
    print("-" * 80)
    for r in results:
        exp = "FILTER" if r["should_filter"] else "KEEP"
        got = "FILTER" if r["actually_filtered"] else "KEEP"
        status = "OK" if r["match"] else "FAIL"
        print(f"{r['case']:<30} {r['stage']:<24} {exp:>7} {got:>7} {status:>6}")
        if r["confidence_before"] != r["confidence_after"]:
            print(f"  conf: {r['confidence_before']:.2f} → {r['confidence_after']:.2f}")
        print(f"  {r['description'][:100]}")

    print("-" * 80)
    print(f"Stage demos: {passed}/{total} passed")

    # 写JSON
    out_path = os.path.join(os.path.dirname(__file__), "stage_demo_results.json")
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_demos": total,
        "passed": passed,
        "results": results,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"\nResults → {out_path}")

    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
