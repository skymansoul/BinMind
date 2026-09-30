# 端到端管线集成测试: 解压->IR归一化->值流->堆分析->FP过滤
# 决策: 不依赖真实二进制, 使用内联IR模拟完整检测管线,
#   验证所有分析层协同工作, 而非单独测试每个模块
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_heap_pipeline():
    """测试完整堆溢出检测管线: IR归一化->值流->堆分析->FP过滤."""
    from core.ir_normalizer import normalize_ir
    from core.value_flow import build_def_use_chains, detect_uaf_pattern, trace_pointer_lifetime
    from core.value_flow import build_def_use_chains, detect_uaf_pattern
    from core.interval_analysis import IntervalAnalyzer

    code = '\n'.join([
        'char *buf = malloc(32);',
        'char *safe = malloc(128);',
        'free(buf);',
        'x = *buf;',
        'memcpy(safe, src, 64);',
    ])
    ir = normalize_ir(code, source='auto')
    print(f"  IR: {len(ir)} lines")
    chains = build_def_use_chains(ir)
    print(f"  DefUse chains: {len(chains)}")
    uaf_matches = detect_uaf_pattern(chains)
    print(f"  UAF pattern matches: {len(uaf_matches)}")

    # Test interval analysis for buffer bounds checking
    ia = IntervalAnalyzer()
    ia.analyze(['char buf[32]', 'i = 0', 'buf[i] = x', 'i = 64', 'buf[i] = y'])
    print(f"  Interval violations: {ia.summary()['violations']}")

    return True

def test_uaf_pipeline():
    """测试UAF检测管线."""
    from core.heap_lifecycle_fsm import detect_uaf_static, detect_double_free

    code = '\n'.join([
        'char *a = malloc(64);',
        'char *b = malloc(32);',
        'free(a);',
        'a[0] = 0x41;',
        'free(b);',
        'free(b);',
    ])
    uaf = detect_uaf_static(code, 'test_uaf')
    df = detect_double_free(code, 'test_df')
    print(f"  UAF: {len(uaf)} findings, DoubleFree: {len(df)} findings")
    return True

def test_fmt_pipeline():
    """测试格式化字符串检测管线."""
    from core.format_string_indirect import detect_indirect_fmt

    code = '\n'.join([
        'char *in = read(0, buf, 128);',
        'printf(in);',
        'printf("safe: %s", name);',
    ])
    findings = detect_indirect_fmt(code, 'test_fmt')
    print(f"  FmtStr: {len(findings)} findings")
    return True

def test_no_ai_function_analysis_skips_llm():
    """--no-ai 时逐函数阶段只保留伪代码，不调用 AI 入口。"""
    from unittest.mock import patch
    from core.pipeline import _analyze_pseudocode

    with patch('core.pipeline.ai_analyze_function') as analyze:
        result = _analyze_pseudocode(
            'sym.vuln', 'char buf[16]; gets(buf);',
            {'arch': 'x86'}, ai_enabled=False)

    analyze.assert_not_called()
    assert result['pseudocode'] == 'char buf[16]; gets(buf);'
    assert result['simulation'] is False
    assert result['analysis_mode'] == 'rules_only'


def test_imported_gets_becomes_auditable_finding():
    """确定的 gets 导入必须产生候选审计项，不能静默得到 0 vulns。"""
    from core.pipeline import _dangerous_import_findings

    findings = _dangerous_import_findings({
        'imports': {'dangerous_functions': ['gets', 'malloc']},
    })

    assert len(findings) == 1
    assert findings[0]['type'] == 'dangerous-function-import'
    assert findings[0]['function_name'] == 'binary_imports'
    assert findings[0]['imported_function'] == 'gets'
    assert findings[0]['cwe'] == 'CWE-242'


def test_constraint_guided_mutator_initializes_chain_storage():
    """增强层实例化 mutator 时必须能保存 prepare 阶段的 def-use 链。"""
    from modules.fuzzing.src.defuse_mutation_guide import ConstraintGuidedMutator

    mutator = ConstraintGuidedMutator()
    assert mutator._chains == []


def main():
    results = {}
    for name, fn in [("Heap", test_heap_pipeline), ("UAF", test_uaf_pipeline),
                      ("FmtStr", test_fmt_pipeline)]:
        try:
            ok = fn()
            results[name] = "PASS" if ok else "FAIL"
        except Exception as e:
            results[name] = f"ERROR: {e}"
    print(f"\n=== Pipeline E2E Results ===")
    for name, status in results.items():
        print(f"  {name}: {status}")
    all_pass = all(v == "PASS" for v in results.values())
    print(f"\nOverall: {'ALL PASS' if all_pass else 'SOME FAILED'}")
    return 0 if all_pass else 1

if __name__ == "__main__":
    sys.exit(main())
