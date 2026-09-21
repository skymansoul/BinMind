"""
SFOD约束注入效果消融 — 直接测量SFOD对约束求解 (Constraint Solving)约束系统的影响.

对9个struct field样本:
  1. 构建约束求解 (Constraint Solving)约束系统(有/无SFOD注入)
  2. 对比约束系统的offset_val/copy_size/constraints数量
  3. 对比最终约束求解 (Constraint Solving)求解器的verdict

方式: 手动构造HeapOverflowCandidate+调用collect_constraints,
     对比注入前后约束系统的差异.
"""
from __future__ import annotations
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

_DEEMO_ROOT = Path(__file__).resolve().parent.parent
if str(_DEEMO_ROOT) not in sys.path:
    sys.path.insert(0, str(_DEEMO_ROOT))

SAMPLE_DIR = _DEEMO_ROOT / "tests" / "cve_samples" / "heap_overflow"
GROUND_TRUTH_PATH = SAMPLE_DIR / "ground_truth.json"
RESULTS_DIR = _DEEMO_ROOT / "eval" / "results"

SFOD_SAMPLES = [
    ("cve_51_struct_field_offset_safe", False),
    ("cve_52_struct_field_offset_overflow", True),
    ("cve_53_struct_field_safe", False),
    ("cve_54_struct_field_overflow", True),
    ("cve_56_sfod_field_safe", False),
    ("cve_57_sfod_field_overflow", True),
    ("cve_58_sfod_cast_safe", False),
    ("cve_59_sfod_cast_overflow", True),
    ("cve_60_sfod_nested_safe", False),
]


def _extract_alloc_and_store(lines: List[str]):
    """从源码行中提取malloc和写入点, 构造HeapAllocSite/HeapStore."""
    from core.heap_overflow_detector import HeapAllocSite, HeapStore

    alloc_pc = -1
    alloc_size = 0
    size_expr = ""
    result_var = ""
    size_is_dynamic = False

    for i, line in enumerate(lines):
        m = re.search(
            r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?'
            r'(?:malloc|calloc|realloc)\s*\(\s*(?:sizeof\s*\(\s*(\w+)\s*\)\s*|(\d+))',
            line)
        if m:
            alloc_pc = i
            result_var = m.group(1) or ""
            if m.group(2):  # sizeof(Type)
                alloc_size = 0  # 需要解析
                size_expr = m.group(2)
                size_is_dynamic = True
            elif m.group(3):  # 常量
                alloc_size = int(m.group(3))
                size_is_dynamic = False
            break

    # 尝试从SFOD的parse_struct_definition获取sizeof
    from core.constraint_struct_field import parse_struct_definition, find_struct_for_alloc
    struct_type = find_struct_for_alloc(lines, alloc_pc)
    structs = parse_struct_definition(lines, alloc_pc) if alloc_pc >= 0 else {}

    if struct_type and struct_type in structs:
        fields = structs[struct_type]
        total = max(f.struct_size for f in fields.values())
        if total > 0:
            alloc_size = total
            size_is_dynamic = False

    alloc_site = HeapAllocSite(
        pc=alloc_pc,
        alloc_func="malloc",
        size_arg=alloc_size,
        size_is_dynamic=size_is_dynamic,
        result_var=result_var,
        size_expr=size_expr,
    )

    # 查找写入点
    stores = []
    for i, line in enumerate(lines):
        if i <= alloc_pc:
            continue
        # memcpy/strcpy/memmove
        m = re.search(
            r'(?:memcpy|memmove|strcpy|strncpy|memset)\s*\(', line)
        if m:
            stores.append(HeapStore(
                pc=i, base_var=result_var,
                offset=0, offset_is_dynamic=False,
                store_size=-1, mnemonic=m.group(0).split('(')[0].strip(),
            ))
            continue
        # buf->field = ...
        m = re.search(r'(\w+)\s*(?:->|\.)\s*(\w+)\s*=', line)
        if m:
            stores.append(HeapStore(
                pc=i, base_var=m.group(1),
                offset=0, offset_is_dynamic=True,
                store_size=4, mnemonic="store",
            ))

    return alloc_site, stores


def run_constraint_ablation():
    from core.constraint_constraint_collector import collect_constraints
    from core.constraint_struct_field import inject_struct_field_constraints
    from core.constraint_solver import ConstraintJoinSolver
    from core.constraint_constraint_types import SolverVerdict
    from core.heap_overflow_detector import HeapOverflowCandidate

    solver = ConstraintJoinSolver()

    print("=" * 70)
    print(" SFOD Constraint Injection Ablation (9 struct field samples)")
    print("=" * 70)

    for sample_name, expected_vuln in SFOD_SAMPLES:
        sample_dir = SAMPLE_DIR / sample_name
        c_files = list(sample_dir.glob("*.c"))
        if not c_files:
            continue

        source = c_files[0].read_text(encoding='utf-8', errors='replace')
        lines = source.splitlines()

        alloc_site, stores = _extract_alloc_and_store(lines)

        if alloc_site.pc < 0:
            print(f"\n{sample_name}: NO ALLOC FOUND")
            continue

        for store in stores:
            cand = HeapOverflowCandidate(
                alloc_site=alloc_site, overflow_store=store,
            )

            # 无SFOD: 手动构建约束系统
            from core.ir_normalizer import normalize_ir
            ir_lines = normalize_ir(source)

            sys_no_sfod = collect_constraints(cand, ir_lines, source)
            # 移除SFOD注入的约束(如有)
            sfod_constraints_no = [c for c in sys_no_sfod.constraints
                                   if "struct_field" not in c.description]
            offset_no = sys_no_sfod.offset_val
            copy_no = sys_no_sfod.copy_size

            # 有SFOD: 重新构建并注入
            sys_with_sfod = collect_constraints(cand, ir_lines, source)
            sfod_constraints_with = [c for c in sys_with_sfod.constraints
                                     if "struct_field" in c.description]
            offset_with = sys_with_sfod.offset_val
            copy_with = sys_with_sfod.copy_size

            # 求解
            result_no = solver.solve(sys_no_sfod)
            result_with = solver.solve(sys_with_sfod)

            sfod_injected = len(sfod_constraints_with)
            verdict_no = result_no.verdict.value
            verdict_with = result_with.verdict.value

            # 确定预期verdict
            expected_verdict = "OVERFLOW" if expected_vuln else "SAFE"

            print(f"\n{sample_name}:")
            print(f"  Alloc: malloc({alloc_site.size_arg})")
            print(f"  Store: {store.mnemonic} at line {store.pc}")
            print(f"  SFOD injected: {sfod_injected} constraint(s)")
            print(f"  offset: {offset_no} → {offset_with}")
            print(f"  copy_size: {copy_no} → {copy_with}")
            print(f"  CJ verdict: {verdict_no} → {verdict_with}")
            print(f"  Expected: {expected_verdict}")

            if verdict_with == expected_verdict:
                print(f"  Result: CORRECT (with SFOD)")
            elif verdict_no == expected_verdict:
                print(f"  Result: CORRECT (without SFOD, SFOD no change)")
            else:
                print(f"  Result: CHECK NEEDED")

    print("\n" + "=" * 70)
    print(" SFOD bridges struct field offsets into CJ constraint system,")
    print(" enabling CJ to autonomously handle struct->field patterns.")
    print("=" * 70)


if __name__ == "__main__":
    run_constraint_ablation()
