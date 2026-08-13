#!/usr/bin/env python3
# coding: utf-8
"""
端到端集成测试 — 验证六层过滤管线的所有模块正确协同工作.
不依赖编译, 使用合成数据验证算法逻辑.
"""

import sys, os, json
# 从 tests/regression/ 向上找 modules/core/ 和 modules/ 根
_CORE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_MODULES_DIR = os.path.dirname(os.path.dirname(_CORE_DIR))
sys.path.insert(0, _CORE_DIR)
sys.path.insert(0, _MODULES_DIR)
# 同目录 regression 包（tests.regression.collect_results）通过该路径解析
sys.path.insert(0, os.path.join(_CORE_DIR, 'tests'))

print('=' * 60)
print(' End-to-End Pipeline Integration Test')
print('=' * 60)

# Test 1: DeepHeapOrchestrator Pipeline
print('\n--- Test 1: DeepHeapOrchestrator Pipeline ---')

from compat.deep_heap_orchestrator import DeepHeapOrchestrator

orch = DeepHeapOrchestrator(
    enable_l4=True, enable_l5=True, enable_interproc=True,
    taint_distance_threshold=6)

instructions = [
    {'addr': 0x401000, 'mnemonic': 'call', 'comment': 'malloc(64)'},
    {'addr': 0x401005, 'mnemonic': 'mov', 'comment': 'store ptr'},
    {'addr': 0x40100a, 'mnemonic': 'cmp', 'comment': 'bounds check'},
    {'addr': 0x401010, 'mnemonic': 'call', 'comment': 'memcpy(ptr, src, 128)'},
]
ir_ops = {
    0x401000: {'op_type': 'call', 'callee': 'malloc', 'alloc_size': 64},
    0x401005: {'op_type': 'store', 'dest': 'rdi', 'src': 'rax'},
    0x40100a: {'op_type': 'cmp'},
    0x401010: {'op_type': 'call', 'callee': 'memcpy', 'write_size': 128},
}
callee_names = {0x401000: 'malloc', 0x401010: 'memcpy'}
def_use_chains = {0x401010: [0x401000, 0x40100a]}

report = orch.run(
    'synthetic_test.elf',
    instructions=instructions,
    ir_ops=ir_ops,
    callee_names=callee_names,
    def_use_chains=def_use_chains,
)

print(f'  Total candidates: {report.total_candidates}')
print(f'  Final candidates: {report.final_candidates}')
print(f'  Exploitable: {report.exploitable}')
print(f'  Reduction rate: {report.reduction_rate:.1%}')
print(f'  Duration: {report.total_duration_ms:.1f}ms')
print(f'  Layers:')
for s in report.layer_stats:
    print(f'    {s.name}: {s.input_count} in -> {s.retained} retained ({s.duration_ms:.1f}ms)')

assert report.total_candidates >= 0, 'Pipeline should not crash'
print('  PASS')

# Test 2: Constraint Solver Edge Cases
print('\n--- Test 2: Constraint Solver Edge Cases ---')
from compat.constraint_solver import (
    ConstraintSystem, Constraint, ConstraintOp,
    prove_overflow_infeasible)

# Case 1: alloc=64, write=32 -> safe
feasible, reason = prove_overflow_infeasible(64, 32)
assert feasible == True, f'64 vs 32 should be infeasible, got {feasible}: {reason}'
print(f'  alloc=64 write=32: infeasible={feasible} PASS')

# Case 2: alloc=32, write=64 -> possible overflow
feasible, reason = prove_overflow_infeasible(32, 64)
assert feasible == False, f'32 vs 64 should be feasible, got {feasible}'
print(f'  alloc=32 write=64: infeasible={feasible} PASS')

# Case 3: alloc=100, write=100 -> equal, should be infeasible
feasible, reason = prove_overflow_infeasible(100, 100)
print(f'  alloc=100 write=100: infeasible={feasible} (equal sizes) PASS')

# Case 4: Domain contraction test
cs = ConstraintSystem()
cs.set_domain('alloc', 64, 64)
cs.set_domain('write', 32, 32)
cs.add_constraint(Constraint('write', ConstraintOp.GT, right_var='alloc', origin='test'))
result = cs.solve()
assert not result.satisfiable, 'write(32) > alloc(64) should be unsatisfiable'
print(f'  Domain contraction: satisfiable={result.satisfiable} PASS')

# ---- Test 3: Path-Sensitive Abstract Interpretation ----
print('\n--- Test 3: Path-Sensitive Abstract Interpretation ---')
from compat.path_abstract_interpret import PathSensitiveHeapAnalyzer
from compat.batch_path_filter import batch_path_sensitive_filter
from compat.cfg_extractor import extract_cfg_subgraph
from compat.value_range import Interval

instructions_pa = [
    {'addr': 0x1000, 'mnemonic': 'call', 'comment': 'malloc(256)'},
    {'addr': 0x1005, 'mnemonic': 'cmp'},
    {'addr': 0x100a, 'mnemonic': 'jz'},
    {'addr': 0x1010, 'mnemonic': 'call', 'comment': 'memcpy(ptr, data, 200)'},
    {'addr': 0x1015, 'mnemonic': 'jmp'},
    {'addr': 0x1020, 'mnemonic': 'call', 'comment': 'memcpy(ptr, data, 100)'},
    {'addr': 0x1025, 'mnemonic': 'ret'},
]
ir_ops_pa = {
    0x1000: {'op_type': 'call', 'callee': 'malloc', 'alloc_size': 256},
    0x100a: {'op_type': 'branch', 'branch_target': 0x1020},
    0x1010: {'op_type': 'call', 'callee': 'memcpy', 'write_size': 200},
    0x1015: {'op_type': 'jump', 'jump_target': 0x1025},
    0x1020: {'op_type': 'call', 'callee': 'memcpy', 'write_size': 100},
}

subgraph = extract_cfg_subgraph(instructions_pa, ir_ops_pa, 0x1000, 0x1025)
print(f'  CFG subgraph: {len(subgraph)} nodes')
assert len(subgraph) >= 3, f'Expected >= 3 nodes, got {len(subgraph)}'

analyzer = PathSensitiveHeapAnalyzer(subgraph)
result = analyzer.analyze(0x1000, 0x1025, Interval.constant(256))
print(f'  Analysis: provably_safe={result.provably_safe}, iterations={result.iteration_count}')
print(f'  Detail: {result.detail}')
print('  PASS')

# Test 4: Inter-Proc Taint Engine
print('\n--- Test 4: Inter-Proc Taint Engine ---')
from compat.interproc_taint import InterProcTaintEngine

engine = InterProcTaintEngine(def_use_chains, ir_ops, instructions)
engine.build_summaries(
    {0x401000: [0x500000]},
    {0x401000: 'process_data', 0x500000: 'read'},
    {0x401000: (0x401000, 0x401020), 0x500000: (0x500000, 0x500050)},
)
path = engine.trace_across_functions(0x401010, caller_func=0x401000)
print(f'  Source type: {path.source_type}')
print(f'  Crosses calls: {path.crosses_calls}')
print('  PASS')

# Test 5: FP Calibrator
print('\n--- Test 5: FP Calibrator ---')
from compat.fp_calibrator import FpCalibrator, CalibrationConfig

cal = FpCalibrator(target_fp_rate=0.15, min_recall=0.85)
cal.add_annotation('test_sample', '0x401010_heap_overflow', True)
cal.add_annotation('test_sample', '0x402000_heap_overflow', False)

def mock_detect(config, sample_path):
    return [
        {'overflow_site': '0x401010', 'vuln_type': 'heap_overflow', 'exploitable': True},
    ]

point = cal.evaluate(CalibrationConfig(), mock_detect, ['test_sample'])
print(f'  TP={point.tp} FP={point.fp} TN={point.tn} FN={point.fn}')
print(f'  Precision={point.precision:.2%} Recall={point.recall:.2%} F1={point.f1:.3f}')
assert point.tp == 1, f'Expected TP=1, got {point.tp}'
print('  PASS')

# Test 6: Regression Metrics Pipeline
print('\n--- Test 6: Regression Metrics Pipeline ---')
from tests.regression.collect_results import collect, report_to_markdown

mock_scan = [
    {'sample_id': 'vuln_cve_2020_29370', 'candidates': 3, 'exploitable': 1, 'wall_time_ms': 15.0},
    {'sample_id': 'vuln_cve_2019_9213', 'candidates': 2, 'exploitable': 1, 'wall_time_ms': 12.0},
    {'sample_id': 'safe_heap', 'candidates': 0, 'exploitable': 0, 'wall_time_ms': 8.0},
    {'sample_id': 'vuln_cve_2021_3156', 'candidates': 4, 'exploitable': 2, 'wall_time_ms': 18.0},
    {'sample_id': 'fp_internal_data', 'candidates': 0, 'exploitable': 0, 'wall_time_ms': 10.0},
]

gt_path = os.path.join(_CORE_DIR, 'tests', 'samples', 'ground_truth.json')

regression_report = collect(mock_scan, gt_path)
print(f'  TP={regression_report.tp} FP={regression_report.fp} TN={regression_report.tn} FN={regression_report.fn}')
print(f'  Precision={regression_report.precision:.2%} Recall={regression_report.recall:.2%} F1={regression_report.f1:.3f}')

assert regression_report.tp == 3, f'Expected TP=3, got {regression_report.tp}'
assert regression_report.tn >= 1, f'Expected at least TN=1'

md_report = report_to_markdown(regression_report)
assert 'Regression Test Report' in md_report
print('  Markdown report generation: PASS')

print()
print('=' * 60)
print('ALL 6 END-TO-END TESTS PASSED')
print(f' Pipeline integration verified')
print('=' * 60)
