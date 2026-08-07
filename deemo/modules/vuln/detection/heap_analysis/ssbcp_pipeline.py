# coding: utf-8
# 创建: 2026-07-21  |  SSBCP三阶段过滤管线 — 整合符号约束+分支窄化+分配器模型
#
"""
SSBCP (Symbolic Size-Bound Constraint Propagation) 过滤管线。

整合三个创新模块:
  Stage 1: sym_constraint_engine — 符号化大小约束传播
           追踪malloc size和write len的算术关系, 求解不等式
  Stage 2: branch_narrower — 路径敏感分支窄化
           对Stage1的uncertain候选做CFG路径可达性验证
  Stage 3: alloc_model_filter — 分配器感知FP消除
           对仍uncertain的候选做padding zone验证

与现有fp_filter_v2.py的关系:
  fp_filter_v2保留为兼容接口, 本模块作为v3替代,
  在orchestrator中优先调用SSBCP, 回退到fp_filter_v2。

设计决策:
  每阶段独立输出reasoning, 支持审计和debug。
  仅当某阶段无法判定时才进入下一阶段, 早期退出。

  SAIL— 需求驱动稀疏值流, 避免全程序分析
  KLEE(OSDI'08)— 路径级约束求解, 我们简化为区间法
  ptmalloc2/jemalloc — 分配器内部模型
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time

from modules.vuln.detection.heap_analysis.sym_constraint_engine import (
    SymConstraintEngine, SymAnalysisResult, SymWriteRecord,
    SymAllocRecord, SymExpr, analyze_function_symbolic)
from modules.vuln.detection.heap_analysis.branch_narrower import (
    BranchNarrower, BranchNarrowResult)
from modules.vuln.detection.heap_analysis.alloc_model_filter import (
    AllocatorType, AllocModelFilter, AllocModelResult, detect_allocator)
from modules.vuln.detection.heap_analysis.insn_parser import (
    disassemble, parse_instructions, is_user_function, Function, Instruction)

@dataclass
class SSBCPFinding:
    """SSBCP分析的单条发现"""
    func_name: str = ""
    insn_addr: int = 0
    alloc_info: str = ""
    write_info: str = ""
    stage: str = ""           # stage1/stage2/stage3
    decision: str = ""        # safe/overflow/uncertain
    reasoning: str = ""
    alloc_size: int = 0
    write_size: int = 0
    offset: int = 0
    fp_probability: float = 0.5

@dataclass
class SSBCPReport:
    """SSBCP管线完整报告"""
    binary_path: str = ""
    n_functions: int = 0
    n_user_functions: int = 0
    total_raw: int = 0
    stage1_safe: int = 0
    stage1_overflow: int = 0
    stage1_uncertain: int = 0
    stage2_filtered: int = 0
    stage2_retained: int = 0
    stage3_safe: int = 0
    stage3_uncertain: int = 0
    final_confirmed: int = 0
    final_likely: int = 0
    final_uncertain: int = 0
    final_filtered: int = 0
    fp_reduction_pct: float = 0.0
    findings: List[SSBCPFinding] = field(default_factory=list)
    elapsed_sec: float = 0.0
    disasm_error: str = ""

def analyze_heap_ssbcp(binary_path: str,
                       timeout_s: int = 60) -> SSBCPReport:
    """SSBCP完整管线: 反汇编→解析→符号传播→分支窄化→分配器模型

    参数:
      binary_path: 二进制文件路径
      timeout_s: objdump超时秒数

    返回: SSBCPReport
    """
    t0 = time.time()
    report = SSBCPReport(binary_path=binary_path)

    # objdump反汇编
    asm_text = disassemble(binary_path, timeout_s)
    if not asm_text:
        report.elapsed_sec = round(time.time() - t0, 3)
        report.disasm_error = "objdump failed — no output"
        return report

    # 按函数解析
    functions = parse_instructions(asm_text)
    report.n_functions = len(functions)

    # 检测分配器类型
    all_symbols = [fn.name for fn in functions]
    alloc_type = detect_allocator(all_symbols)

    # 初始化三个阶段的引擎
    sym_engine = SymConstraintEngine(abi="auto")
    narrower = BranchNarrower(max_paths=32)
    alloc_filter = AllocModelFilter(alloc_type=alloc_type)

    all_findings: List[SSBCPFinding] = []
    n_user_fn = 0

    # 逐函数分析
    for fn in functions:
        if len(fn.insns) < 3 or not is_user_function(fn.name):
            continue
        n_user_fn += 1

        # 将Instruction转为raw字符串列表
        insns_raw = [_insn_to_raw(insn) for insn in fn.insns]

        # Stage 1: 符号约束传播
        sym_result = sym_engine.analyze(insns_raw, fn.name)
        report.total_raw += len(sym_result.writes)

        # 按stage1结果分流
        uncertain_indices: List[int] = []
        stage1_finding_map: Dict[int, SSBCPFinding] = {}

        for write in sym_result.writes:
            finding = SSBCPFinding(
                func_name=fn.name,
                insn_addr=write.addr,
                write_info=str(write.size_expr),
                alloc_info=str(write.linked_alloc.size_expr)
                    if write.linked_alloc else "unknown",
                stage="stage1")

            if write.insn_idx in sym_result.proven_safe:
                finding.decision = "safe"
                finding.reasoning = _safe_reasoning(write)
                finding.fp_probability = 0.9
                report.stage1_safe += 1
            elif write.insn_idx in sym_result.proven_overflow:
                finding.decision = "overflow"
                finding.reasoning = _overflow_reasoning(write)
                finding.fp_probability = 0.05
                report.stage1_overflow += 1
            else:
                finding.decision = "uncertain"
                finding.reasoning = "symbolic relation inconclusive"
                finding.fp_probability = 0.5
                report.stage1_uncertain += 1
                uncertain_indices.append(write.insn_idx)
                stage1_finding_map[write.insn_idx] = finding

            if write.linked_alloc:
                finding.alloc_size = (
                    write.linked_alloc.size_expr.const
                    if write.linked_alloc.size_expr.is_const else 0)
            finding.write_size = (
                write.size_expr.const
                if write.size_expr.is_const else 0)
            finding.offset = (
                write.offset_expr.const
                if write.offset_expr.is_const else 0)

            all_findings.append(finding)

        # Stage 2: 分支窄化(仅对uncertain)
        if uncertain_indices:
            narrow_result = narrower.narrow(
                insns_raw, uncertain_indices,
                sym_result.constraints,
                base_addr=0x400000)

            for detail in narrow_result.details:
                idx = detail['idx']
                finding = stage1_finding_map.get(idx)
                if finding and detail['verdict'] == 'filtered':
                    finding.stage = "stage2"
                    finding.decision = "safe"
                    finding.reasoning = (
                        f"path unreachable — {detail['reason']}")
                    finding.fp_probability = 0.85
                    report.stage2_filtered += 1
                elif finding:
                    report.stage2_retained += 1

        # Stage 3: 分配器模型(仅对仍uncertain的)
        remaining_uncertain = [
            f for f in all_findings
            if f.func_name == fn.name and f.decision == "uncertain"]
        if remaining_uncertain:
            for finding in remaining_uncertain:
                alloc_sz = finding.alloc_size or 128
                ar = alloc_filter.evaluate(
                    alloc_sz, finding.offset, finding.write_size)
                if ar.is_safe:
                    finding.stage = "stage3"
                    finding.decision = "safe"
                    finding.reasoning = ar.reasoning
                    finding.fp_probability = 0.8
                    report.stage3_safe += 1
                else:
                    report.stage3_uncertain += 1

    # 最终统计
    for f in all_findings:
        if f.decision == "overflow":
            report.final_confirmed += 1
        elif f.decision == "uncertain":
            if f.write_size == -1:  # unbounded
                report.final_likely += 1
            else:
                report.final_uncertain += 1
        elif f.decision == "safe":
            report.final_filtered += 1

    if report.total_raw > 0:
        report.fp_reduction_pct = round(
            report.final_filtered / report.total_raw * 100, 1)

    report.n_user_functions = n_user_fn
    report.findings = all_findings
    report.elapsed_sec = round(time.time() - t0, 3)
    return report

def _safe_reasoning(write: SymWriteRecord) -> str:
    """生成safe判定的reasoning"""
    if write.linked_alloc:
        alloc_sz = write.linked_alloc.size_expr
        write_sz = write.size_expr
        return (f"alloc({alloc_sz}) >= write({write_sz}) "
                f"— proven safe by symbolic constraint")
    return "symbolic analysis proves safe"

def _overflow_reasoning(write: SymWriteRecord) -> str:
    """生成overflow判定的reasoning"""
    if write.linked_alloc:
        alloc_sz = write.linked_alloc.size_expr
        write_sz = write.size_expr
        return (f"alloc({alloc_sz}) < write({write_sz}) "
                f"— confirmed overflow by symbolic constraint")
    return "symbolic analysis confirms overflow"

def _insn_to_raw(insn: Instruction) -> str:
    """Instruction转raw字符串 — 含地址和操作数用于符号引擎解析

    格式: "addr mnemonic operands"
    symbol引擎的_parse_insn和get_callee会从此格式提取信息
    """
    # 用addr: 后跟mnemonic+operands的格式
    # get_callee处理含<symbol>的操作数
    return f"{insn.addr:x}: {insn.mnemonic} {insn.operands}"

# 兼容旧接口 ---

def _check():
    """SSBCP自检 — 基本功能验证"""
    # 模拟指令: malloc(64) → memcpy(p, src, 128) → overflow
    insns = [
        "401000: mov rdi, 0x40",
        "401005: call malloc",
        "40100a: mov rbx, rax",
        "40100f: mov rdi, rbx",
        "401014: mov rsi, rax",
        "401019: mov rdx, 0x80",
        "40101e: call memcpy",
    ]
    engine = SymConstraintEngine(abi="auto")
    result = engine.analyze(insns, "test_fn")
    print(f"[SSBCP] allocs={len(result.allocs)}, "
          f"writes={len(result.writes)}, "
          f"overflow={len(result.proven_overflow)}, "
          f"safe={len(result.proven_safe)}")
    assert len(result.allocs) == 1
    assert len(result.writes) == 1
    assert len(result.proven_overflow) == 1
    print("[OK] SSBCP self-check passed")

if __name__ == "__main__":
    _check()

__all__ = [
    "SSBCPFinding", "SSBCPReport",
    "analyze_heap_ssbcp",
]
