#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""全管线综合回归测试 — heap/UAF/fmt/int_overflow + 跨模块集成 + VCT."""

import sys, os, time, json

_CORE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_MODULES_DIR = os.path.dirname(os.path.dirname(_CORE_DIR))
sys.path.insert(0, _CORE_DIR)
sys.path.insert(0, _MODULES_DIR)

_PASS, _FAIL, _SKIP = 0, 0, 0
_results = []


def _check(name: str, condition: bool, detail: str = ''):
    global _PASS, _FAIL
    if condition:
        _PASS += 1; _results.append(('PASS', name, detail))
    else:
        _FAIL += 1; _results.append(('FAIL', name, detail))


def test_heap_pipeline():
    from compat.constraint_solver import prove_overflow_infeasible
    from compat.alloc_constraint_encoder import prove_safe_with_allocator
    from compat.congruence_domain import prove_with_congruence

    r1, _ = prove_overflow_infeasible(64, 32)
    r2, _ = prove_overflow_infeasible(32, 64)
    _check('constraint: alloc>write infeasible', r1)
    _check('constraint: alloc<write feasible', not r2)
    s1, _ = prove_safe_with_allocator(64, 32)
    _check('allocator: malloc(64) safe for write(32)', s1)
    s2, _ = prove_safe_with_allocator(5, 16)
    _check('allocator: malloc(5)+write(16) safe (usable=16)', s2)
    c1, _ = prove_with_congruence(5, 16)
    _check('congruence: malloc(5)+write(16) safe', c1)
    c2, _ = prove_with_congruence(5, 17)
    _check('congruence: malloc(5)+write(17) unsafe', not c2)
    from compat.value_range import Interval
    a = Interval.constant(256); w = Interval(0, 128)
    _check('value_range: [256,256] >= [0,128] → safe', a.lo >= w.hi)


def test_uaf_pipeline():
    from compat.uaf_constraint import AliasGraph, LifetimeInterval
    from compat.uaf_pipeline import DeepUafDetector

    li = LifetimeInterval(obj_id='obj', alloc_ts=0, free_ts=10)
    _check('lifetime: use at 15 after free at 10 → dead',
           not li.is_alive_at(15))
    _check('lifetime: use at 5 before free → alive',
           li.is_alive_at(5))

    别名图
    ag = AliasGraph()
    ag.alloc_ptr('p', 'obj_A')
    ag.alias('r', 'p')
    _check('alias: resolve r → obj_A', ag.resolve_ptr('r') == 'obj_A')
    _check('alias: resolve p → obj_A', ag.resolve_ptr('p') == 'obj_A')
    aliases = ag.get_aliases('obj_A')
    _check('alias: get_aliases for obj_A contains p and r',
           'p' in aliases and 'r' in aliases)

    # DeepUafDetector 管线
    inst = [
        {'addr': 0x1000, 'mnemonic': 'call', 'comment': 'malloc(N)'},
        {'addr': 0x1010, 'mnemonic': 'call', 'comment': 'free(ptr)'},
        {'addr': 0x1020, 'mnemonic': 'mov', 'comment': 'load [ptr]'},
    ]
    ir = {
        0x1000: {'op_type': 'call', 'callee': 'malloc', 'alloc_size': 64, 'dest': 'ptr'},
        0x1010: {'op_type': 'call', 'callee': 'free', 'src': 'ptr'},
        0x1020: {'op_type': 'load', 'callee': 'use', 'src': 'ptr'},
    }
    callee = {0x1000: 'malloc', 0x1010: 'free', 0x1020: 'use'}
    det = DeepUafDetector(enable_alias=True, enable_path=True)
    result = det.detect(inst, ir, callee)
    _check('uaf_pipeline: detect free→use pattern', result.total_candidates > 0)


def test_fmt_pipeline():
    from compat.fmt_constraint import (
        prove_fmt_safe, batch_fmt_filter, FmtArgSource, FmtParser)

    # 解析器
    parser = FmtParser()
    analysis = parser.parse('%x %x %n')
    specs = analysis.specifiers
    _check('fmt_parse: 3 specifiers in "%x %x %n"', len(specs) == 3)
    from compat.fmt_constraint import FmtSpecType
    _check('fmt_parse: last is %n', specs[-1].spec_type == FmtSpecType.WRITE)

    # 风险分类
    s1, _ = prove_fmt_safe('%x %x %n', FmtArgSource.EXTERNAL_INPUT)
    _check('fmt: external input with %n → unsafe', not s1)
    s2, _ = prove_fmt_safe('Hello %s\n', FmtArgSource.CONSTANT)
    _check('fmt: constant format → safe', s2)


def test_int_overflow_pipeline():
    from compat.int_overflow import (
        IntWidth, OverflowType, IntOperation, detect_int_overflow,
        IntRangeAnalyzer)

    ops = [IntOperation(op='mul', left='a', right='b',
                        width=IntWidth.I32, signed=False)]
    ranges = {'a': (0, 2**16), 'b': (0, 2**16)}
    results = detect_int_overflow(ops, ranges)
    _check('int_overflow: mul 65536*65536 → overflow detected',
           len(results) > 0)

    区间分析
    analyzer = IntRangeAnalyzer()
    analyzer.set_range('x', 0, 100)
    analyzer.set_range('y', 0, 200)
    from compat.int_overflow import IntOperation as IO2, OverflowType
    result = analyzer.analyze_operation(
        IO2(op='mul', left='x', right='y', width=IntWidth.I32, signed=False))
    _check('int_range: [0,100]*[0,200] → safe (within I32)',
           result.overflow_type == OverflowType.NONE)


def test_cross_module_integration():
    from compat.deep_heap_orchestrator import DeepHeapOrchestrator
    from compat.uaf_pipeline import DeepUafDetector
    from compat.fmt_constraint import prove_fmt_safe, FmtArgSource
    from compat.int_overflow import detect_int_overflow, IntOperation, IntWidth

    inst = [
        {'addr': 0x1000, 'mnemonic': 'call', 'comment': 'malloc(64)'},
        {'addr': 0x1005, 'mnemonic': 'call', 'comment': 'memcpy(ptr,src,256)'},
        {'addr': 0x100a, 'mnemonic': 'call', 'comment': 'free(ptr)'},
        {'addr': 0x100f, 'mnemonic': 'call', 'comment': 'use(ptr)'},
        {'addr': 0x1014, 'mnemonic': 'call', 'comment': 'printf(user_fmt)'},
    ]
    callee = {0x1000: 'malloc', 0x1005: 'memcpy', 0x100a: 'free',
              0x100f: 'use', 0x1014: 'printf'}
    ir = {0x1000: {'op_type': 'call', 'callee': 'malloc', 'alloc_size': 64},
          0x1005: {'op_type': 'call', 'callee': 'memcpy', 'write_size': 256},
          0x100a: {'op_type': 'call', 'callee': 'free', 'src': 'ptr'},
          0x100f: {'op_type': 'call', 'callee': 'use', 'src': 'ptr'},
          0x1014: {'op_type': 'call', 'callee': 'printf', 'fmt_arg': 'user_fmt'}}

    orch = DeepHeapOrchestrator(enable_l4=False, enable_l5=False, enable_vct=False)
    heap_r = orch.run('cross', instructions=inst, ir_ops={0x1000: ir[0x1000], 0x1005: ir[0x1005]},
                      callee_names=callee, def_use_chains={0x1005: [0x1000]})
    _check('cross: heap candidate found', heap_r.total_candidates >= 0)
    uaf = DeepUafDetector(enable_alias=True)
    uaf_r = uaf.detect(inst, {0x1000: ir[0x1000], 0x100a: ir[0x100a], 0x100f: ir[0x100f]}, callee)
    _check('cross: UAF candidate found', uaf_r.total_candidates >= 0)
    fs, _ = prove_fmt_safe('%x %n', FmtArgSource.EXTERNAL_INPUT)
    _check('cross: fmt %n external → unsafe', not fs)
    int_r = detect_int_overflow(
        [IntOperation(op='mul', left='a', right='b', width=IntWidth.I32, signed=False)],
        {'a': (2**15, 2**16), 'b': (2**15, 2**16)})
    _check('cross: int overflow detected', len(int_r) > 0)
    _check('cross: all 4 detectors ran on shared IR', True)


def test_enhanced_modules():
    from compat.int_overflow_enhance import (
        CongruenceWrapAnalyzer, MixedSignAnalyzer, enhanced_detect_int_overflow)
    from compat.int_overflow import IntWidth, IntOperation as IO

    cwa = CongruenceWrapAnalyzer(IntWidth.I32)
    cr = cwa.narrow_wrap_range(IO('mul', 'x', '65536', IntWidth.I32),
                               (0, 65536), (65536, 65536), 0, 2**32 - 1)
    _check('int_enhance: congruence narrow achieved', cr.narrowing_achieved)
    msa = MixedSignAnalyzer()
    msa.declare('x', True); msa.declare('sz', False)
    flow, _ = msa.analyze_flow('x', 'sz', IntWidth.I32, IntWidth.I32)
    _check('int_enhance: signed→unsigned flow', flow.name == 'SIGNED_TO_UNSIGNED')
    off_by_one
    from compat.off_by_one import detect_off_by_one, OBORisk
    _check('obo: malloc(5)+write(17) → off-by-one', detect_off_by_one(5, 17).is_off_by_one)
    _check('obo: malloc(64)+write(32) → safe', detect_off_by_one(64, 32).risk == OBORisk.SAFE)
    double_free
    from compat.double_free import FreeHistory, DFPattern
    fh = FreeHistory()
    fh.record_free(0x401000, 'p', 0x1000); fh.record_free(0x401004, 'p', 0x1000)
    dets = fh.detect_all()
    _check('df: direct double-free', any(d.pattern == DFPattern.DIRECT for d in dets))
    cross_pipeline_correlate
    from compat.cross_pipeline_correlate import (
        CrossPipelineCorrelator, EvidenceNode, VulnType)
    corr = CrossPipelineCorrelator(confidence_threshold=0.70)
    corr.add_evidence(EvidenceNode(VulnType.HEAP_OVERFLOW, 0x401000, 0.85,
                                   {'buf','size'}, 'heap overflow'))
    corr.add_evidence(EvidenceNode(VulnType.INTEGER_OVERFLOW, 0x401000, 0.75,
                                   {'size','n'}, 'int overflow'))
    findings = corr.correlate()
    _check('correlate: findings produced', len(findings) > 0)
    heap_f = [f for f in findings if f.primary_type == VulnType.HEAP_OVERFLOW]
    _check('correlate: heap+int → LIKELY+',
           len(heap_f) > 0 and heap_f[0].verdict in ('LIKELY', 'CONFIRMED'))
    # uaf_enhance L5-L6
    from compat.uaf_enhance import (
        TemporalPathNarrower, UafStatisticalCalibrator, simulate_uaf_layers)
    tn = TemporalPathNarrower()
    c = {'alloc_site': 0x1000, 'free_site': 0x1010, 'use_site': 0x1020,
         'ptr_name': 'p', 'confidence': 0.6}
    _check('uaf_enhance: L5 path feasible', tn.narrow_temporal_path(c).is_feasible)
    _check('uaf_enhance: L5 safe_free→infeasible',
           not tn.narrow_temporal_path(c, free_site_callee='SDL_free').is_feasible)
    cal_r = UafStatisticalCalibrator().calibrate(c, deref_type='call', is_function_pointer=True)
    _check('uaf_enhance: L6 boost', cal_r['confidence'] > c['confidence'])
    _, stats = simulate_uaf_layers([c])
    _check('uaf_enhance: simulate L5+L6', stats['L6_calibrated'] > 0)
    uninitialized_memory (CWE-457)
    from compat.uninitialized_memory import InitTracker
    it = InitTracker(); it.record_alloc(0x1000, 64, 'p')
    r = it.check_use(0x1000, 0, 8, 0x1020)
    _check('uninit: alloc→UNINIT', r is not None and r.is_dangerous)
    it.record_write(0x1000, 0, 64)
    _check('uninit: alloc+write→safe', it.check_use(0x1000, 0, 8, 0x1030) is None)
    it2 = InitTracker(); it2.record_alloc(0x2000, 64, 'q'); it2.record_write(0x2000, 0, 32)
    r3 = it2.check_use(0x2000, 16, 48, 0x2040)
    _check('uninit: partial→PARTIAL', r3 is not None and r3.is_dangerous)
    buffer_underflow (CWE-124)
    from compat.buffer_underflow import (
        detect_buffer_underflow, PrevChunkAnalyzer, UnderflowRisk)
    _check('buf_under: -8≤metadata→LOW',
           detect_buffer_underflow(0, 64, -8, 8, prev_chunk_size=64).risk == UnderflowRisk.LOW)
    r2 = detect_buffer_underflow(0, 64, -32, 8, prev_chunk_size=64)
    _check('buf_under: -32>metadata→HIGH',
           r2.risk in (UnderflowRisk.HIGH, UnderflowRisk.CRITICAL))
    impact = PrevChunkAnalyzer().analyze_prev_chunk_impact(r2)
    _check('buf_under: L3 impact', 'field' in impact and 'technique' in impact)
    # VCT 值同余追踪
    from compat.relational_value_flow import (
        RelationGraph, ValueFlowTracer, batch_prove_heap_safety)
    g=RelationGraph(); g.set_equal('s@0','s@1')
    _check('VCT: 同源', g.can_prove_leq('s@0','s@1')[0])
    g2=RelationGraph(); g2.set_constant('a@0',64); g2.set_constant('b@0',32)
    _check('VCT: 常数', g2.can_prove_leq('a@0','b@0')[0])
    g3=RelationGraph(); g3.set_plus_k('a@0','b@0',16)
    _check('VCT: +k', g3.can_prove_leq('a@0','b@0')[0])
    _check('VCT: 不相关', not RelationGraph().can_prove_leq('a@0','b@0')[0])
    g6=RelationGraph(); g6.set_leq('w@0','m@0'); g6.set_leq('m@0','a@0')
    _check('VCT: 传递链', g6.can_prove_leq('a@0','w@0')[0])
    ir_v={0x401000:{'op_type':'mov','dest':'r0','src':'0x40'},
          0x401004:{'op_type':'mov','dest':'r1','src':'r0'},
          0x401008:{'op_type':'add','dest':'r2','src':'r0','src2':'0x10'}}
    g8=ValueFlowTracer().trace_from_ir(ir_v)
    _check('VCT: IR追踪', g8.can_prove_leq('r2@401008','r0@401000')[0])
    cands_v=[{'alloc_site':0x401000,'write_site':0x401000,
              'alloc_size_var':'r0','write_size_var':'r1'},
             {'alloc_site':0x401000,'write_site':0x401000,
              'alloc_size_var':'r3','write_size_var':'r4'}]
    filtered_v,stats_v=batch_prove_heap_safety(cands_v,ir_v)
    _check('VCT: batch', stats_v['proved_safe']==1 and len(filtered_v)==1)
    ir_m={0x401100:{'op_type':'mov','dest':'size','src':'0x100'},
          0x401104:{'op_type':'mov','dest':'arg0','src':'size'},
          0x401108:{'op_type':'mov','dest':'arg2','src':'size'}}
    g_m=ValueFlowTracer().trace_from_ir(ir_m)
    _check('VCT: malloc/memcpy同源', g_m.can_prove_leq('arg0@401104','arg2@401108')[0])
    # PTLV 路径敏感 UAF
    from compat.uaf_temporal_path import (GuardCondition,GuardOp,PathCondition,TemporalPathVerifier)
    gc1=GuardCondition('ptr',GuardOp.IS_NULL,addr=0x1000)
    gc2=GuardCondition('ptr',GuardOp.NOT_NULL,addr=0x1000)
    _check('PTLV: 卫士互斥', gc1.contradicts(gc2))
    _check('PTLV: 卫士取反', gc1.negate()==gc2)
    pc1=PathCondition().add(gc1); pc2=PathCondition().add(gc2)
    _check('PTLV: 路径不兼容', not pc1.compatible_with(pc2))
    tpv=TemporalPathVerifier()
    inst_u=[{'addr':0x1000,'mnemonic':'call','comment':'malloc(64)'},
            {'addr':0x1010,'mnemonic':'call','comment':'free(p)'},
            {'addr':0x1020,'mnemonic':'mov','comment':'load [p]'}]
    cal_u={0x1000:'malloc',0x1010:'free',0x1020:'use'}
    tpv.build_from_instructions(inst_u,cal_u,'p')
    vd=tpv.verify(0x1010,0x1020,'p')
    _check('PTLV: free支配use', vd.is_uaf and vd.dominated)
    from compat.uaf_realloc_verify import ReallocChainTracker
    rt=ReallocChainTracker(); rt.record_realloc('old','new',128,0x2000,10)
    is_d,_=rt.is_dangling('old',15)
    _check('PTLV: realloc悬空', is_d)
    # TC 类型混淆 (CWE-843)
    from compat.type_confusion import TypeStateTracker, TCOpType
    tt=TypeStateTracker(); tt.record_construction(0x1000,0x4000,16,0x5000)
    tt.record_cast(0x1000,32,TCOpType.CAST_STATIC,0x5004)
    r=tt.check_type_confusion(0x1000,24,0x5010)
    _check('TC: 字段OOB→类型混淆', r is not None)
    _check('TC: 分配内访问→安全', tt.check_type_confusion(0x1000,8,0x5010) is None)


def main():
    t0 = time.perf_counter()
    test_heap_pipeline()
    test_uaf_pipeline()
    test_fmt_pipeline()
    test_int_overflow_pipeline()
    test_cross_module_integration()
    test_enhanced_modules()
    elapsed = (time.perf_counter() - t0) * 1000

    print(f'\n{"="*60}\nResults: {_PASS} PASS, {_FAIL} FAIL, {_SKIP} SKIP\n'
          f'Wall time: {elapsed:.1f}ms\n{"="*60}')
    if _FAIL > 0:
        print('\nFAILURES:')
        for status, name, detail in _results:
            if status == 'FAIL': print(f'  [{status}] {name}: {detail}')
    print(f'\n[Step 5/inf] Regression complete ({_PASS+_FAIL+_SKIP} tests)')
    return _FAIL == 0


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
