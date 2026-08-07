"""根因分析测试。

验证：crash 模式匹配、寄存器启发式、CWE 映射、
严重度分类、crash 聚类、hash 去重。
"""

import sys, os, pytest

_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
if _patch not in sys.path:
    sys.path.insert(0, _patch)

from auto_root_cause import (
    AutoRootCauseAnalyzer, AnalysisReport, VulnerabilityContext,
    VulnerabilitySeverity, Exploitability, CWEDatabase,
    CrashCluster, _CRASH_PATTERNS, _REGISTER_RULES,
    _parse_hex, _crash_exact_hash, _crash_fuzzy_hash,
    triage_capabilities, format_root_cause_report,
    analyze_root_cause,
)


class TestCrashPatternMatching:
    """crash type 分类正则匹配 —— _CRASH_PATTERNS。"""

    def test_segfault_on_null(self):
        text = "Program received signal SIGSEGV, Segmentation fault.\nfault addr 0x0"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'SEGFAULT_ON_ADDRESS'
        assert report.summary['confidence'] > 0.5

    def test_stack_buffer_overflow(self):
        text = "ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7fff1234"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'STACK_BUFFER_OVERFLOW'

    def test_heap_buffer_overflow(self):
        text = "ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'HEAP_BUFFER_OVERFLOW'

    def test_use_after_free(self):
        text = "ERROR: AddressSanitizer: heap-use-after-free on address 0x603000000020"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'USE_AFTER_FREE'

    def test_null_dereference(self):
        text = "Program terminated with signal SIGSEGV. null pointer dereference at rip=0x0"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        # null deref 与 SEGFAULT 有重叠但优先级不同
        assert report.summary['crash_type'] in ('NULL_DEREFERENCE', 'SEGFAULT_ON_ADDRESS')

    def test_integer_overflow(self):
        text = "runtime error: signed integer overflow: 2147483647 + 1 cannot be represented"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'INTEGER_OVERFLOW'

    def test_format_string(self):
        text = "printf with user-controlled format string detected"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'FORMAT_STRING'

    def test_unknown_crash(self):
        text = "something weird happened, idk what it is"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['crash_type'] == 'UNKNOWN'
        assert report.summary['confidence'] == 0.0


class TestRegisterHeuristics:
    """验证 _REGISTER_RULES 寄存器启发式规则。"""

    def test_null_rip_detection(self):
        from auto_root_cause import _REGISTER_RULES as rules
        regs = {'rip': '0x0', 'rsp': '0x7fffffffe000'}
        for condition, interpretation, boost in rules:
            try:
                if condition(regs):
                    assert 'null' in interpretation.lower() or 'null' in interpretation
                    assert boost > 0
                    return
            except Exception:
                pass
        # 至少一条规则应命中
        # 确认 null RIP 规则触发
        rule = rules[0]
        assert rule[0]({'rip': '0x0'})

    def test_stack_pivot_detection(self):
        # rsp > rbp 表示栈 pivot
        regs = {'rsp': '0x7fffffffe000', 'rbp': '0x7fffffffd000'}
        from auto_root_cause import _REGISTER_RULES
        rule = _REGISTER_RULES[1]
        assert rule[0](regs)

    def test_arm64_null_pc(self):
        regs = {'pc': '0x0', 'lr': '0x400000', 'sp': '0x7fffffffe000'}
        from auto_root_cause import _REGISTER_RULES
        # arm64 PC/LR 规则 (索引 5)
        rule = _REGISTER_RULES[5]
        assert rule[0](regs)

    def test_registers_merge_boosts_confidence(self):
        """寄存器启发式应提高置信度。"""
        # NULL deref + RIP=0 应为超高置信度
        text = "null dereference\nrip: 0x0"
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(text)
        assert report.summary['confidence'] >= 0.9


class TestCWEDatabase:
    def test_known_cwe(self):
        cwe_id, desc = CWEDatabase.lookup('STACK_BUFFER_OVERFLOW')
        assert cwe_id == 'CWE-121'
        assert 'Stack' in desc

    def test_heap_overflow_cwe(self):
        cwe_id, desc = CWEDatabase.lookup('HEAP_BUFFER_OVERFLOW')
        assert cwe_id == 'CWE-122'

    def test_unknown_cwe(self):
        cwe_id, desc = CWEDatabase.lookup('SOME_WEIRD_CRASH')
        assert cwe_id == 'CWE-0'
        assert desc == 'Unknown'


class TestSeverityClassification:
    def test_critical_types(self):
        for t in ('USE_AFTER_FREE', 'HEAP_BUFFER_OVERFLOW', 'TYPE_CONFUSION'):
            report = AnalysisReport()
            ctx = VulnerabilityContext()
            ctx.crash_type = t
            report.add_vuln(ctx)
            assert report.severity_distribution['critical'] == 1

    def test_high_types(self):
        for t in ('STACK_BUFFER_OVERFLOW', 'DOUBLE_FREE', 'FORMAT_STRING', 'NULL_DEREFERENCE'):
            report = AnalysisReport()
            ctx = VulnerabilityContext()
            ctx.crash_type = t
            report.add_vuln(ctx)
            assert report.severity_distribution['high'] == 1


class TestCrashHashing:
    def test_exact_hash_deterministic(self):
        h1 = _crash_exact_hash('NULL_DEREFERENCE', 0x0, ['func1', 'func2'])
        h2 = _crash_exact_hash('NULL_DEREFERENCE', 0x0, ['func1', 'func2'])
        assert h1 == h2

    def test_exact_hash_different(self):
        h1 = _crash_exact_hash('NULL_DEREFERENCE', 0x0, ['func1'])
        h2 = _crash_exact_hash('NULL_DEREFERENCE', 0x1, ['func1'])
        assert h1 != h2

    def test_fuzzy_hash_aslr_resistant(self):
        """Fuzzy hash 应剥离地址，跨 ASLR 变化一致。"""
        h1 = _crash_fuzzy_hash('NULL_DEREFERENCE',
            ['func_a+0x10 at 0x7f0001234567', 'func_b+0x8 at 0x7f0009876543'])
        h2 = _crash_fuzzy_hash('NULL_DEREFERENCE',
            ['func_a+0x10 at 0x7f000fffa000', 'func_b+0x8 at 0x7f000bbbcccd'])
        assert h1 == h2

    def test_fuzzy_hash_different_crashes(self):
        h1 = _crash_fuzzy_hash('NULL_DEREFERENCE', ['func_a'])
        h2 = _crash_fuzzy_hash('USE_AFTER_FREE', ['func_a'])
        assert h1 != h2


class TestCrashClustering:
    def test_cluster_grouping(self):
        cluster = CrashCluster()
        ctx1 = VulnerabilityContext()
        ctx1.crash_type = 'NULL_DEREFERENCE'
        ctx1.stack_trace = ['func_a', 'func_b']
        ctx2 = VulnerabilityContext()
        ctx2.crash_type = 'NULL_DEREFERENCE'
        ctx2.stack_trace = ['func_a', 'func_b']
        fh1, count1 = cluster.add(ctx1)
        fh2, count2 = cluster.add(ctx2)
        assert fh1 == fh2  # 同 fuzzy hash
        assert count2 == 2  # 第二个落入同一簇
        assert cluster.stats()['total_clusters'] == 1
        assert cluster.stats()['largest_cluster'] == 2

    def test_cluster_different_crashes(self):
        cluster = CrashCluster()
        ctx1 = VulnerabilityContext()
        ctx1.crash_type = 'NULL_DEREFERENCE'
        ctx1.stack_trace = ['func_a']
        ctx2 = VulnerabilityContext()
        ctx2.crash_type = 'USE_AFTER_FREE'
        ctx2.stack_trace = ['func_b']
        fh1, _ = cluster.add(ctx1)
        fh2, _ = cluster.add(ctx2)
        assert fh1 != fh2
        assert cluster.stats()['total_clusters'] == 2

    def test_cluster_to_dict(self):
        cluster = CrashCluster()
        ctx = VulnerabilityContext()
        ctx.crash_type = 'NULL_DEREFERENCE'
        cluster.add(ctx)
        d = cluster.to_dict()
        assert len(d) == 1


class TestCapabilityTriage:
    def test_use_after_free(self):
        ctx = VulnerabilityContext()
        ctx.crash_type = 'USE_AFTER_FREE'
        caps = triage_capabilities(ctx)
        assert 'heap_feng_shui' in caps

    def test_stack_overflow(self):
        ctx = VulnerabilityContext()
        ctx.crash_type = 'STACK_BUFFER_OVERFLOW'
        caps = triage_capabilities(ctx)
        assert 'write_primitive' in caps
        assert 'control_flow_hijack' in caps

    def test_null_deref_with_rip_zero(self):
        ctx = VulnerabilityContext()
        ctx.crash_type = 'NULL_DEREFERENCE'
        ctx.registers = {'rip': '0x0'}
        caps = triage_capabilities(ctx)
        assert 'control_flow_hijack' in caps

    def test_format_string(self):
        ctx = VulnerabilityContext()
        ctx.crash_type = 'FORMAT_STRING'
        caps = triage_capabilities(ctx)
        assert 'info_leak' in caps


class TestDictInput:
    """验证分析器接受结构化字段的 dict 输入。"""

    def test_dict_with_registers(self):
        crash = {
            'signal': 'SIGSEGV',
            'registers': {'rip': '0x7f0000123456', 'rsp': '0x7fffffffe000', 'rax': '0x41'},
            'stack_trace': ['func1+0x42', 'main+0x12'],
            'fault_addr': '0x0',
        }
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(crash)
        assert report.summary['crash_type'] in ('NULL_DEREFERENCE', 'SEGFAULT_ON_ADDRESS')
        assert '0x7f0000123456' in str(report.vulnerabilities[0].registers)

    def test_dict_with_asan_type(self):
        crash = {
            'type': 'heap-buffer-overflow',
            'description': 'WRITE of size 8 at 0x602000000010',
            'registers': {},
            'stack_trace': ['#0 func_a'],
        }
        analyzer = AutoRootCauseAnalyzer()
        report = analyzer.analyze(crash)
        assert report.summary['crash_type'] == 'HEAP_BUFFER_OVERFLOW'


class TestFormatRootCauseReport:
    def test_generates_output(self):
        ctx = VulnerabilityContext()
        ctx.crash_type = 'STACK_BUFFER_OVERFLOW'
        ctx.cwe_id = 'CWE-121'
        report = AnalysisReport()
        report.add_vuln(ctx)
        report.summary = {
            'crash_type': 'STACK_BUFFER_OVERFLOW',
            'confidence': 0.95,
            'exploitability': 'LIKELY',
            'cwe': 'CWE-121',
            'exact_hash': 'a1b2c3d4e5f6',
            'fuzzy_hash': 'f1e2d3c4b5a6',
            'capabilities_required': ['write_primitive'],
        }
        output = format_root_cause_report(report)
        assert 'STACK_BUFFER_OVERFLOW' in output
        assert 'CWE-121' in output
        # 2026-08-02: to_dict 路径应输出相同结果
        output2 = format_root_cause_report(dict(report.to_dict()))
        assert 'STACK_BUFFER_OVERFLOW' in output2


class TestModuleLevelShim:
    def test_analyze_root_cause_shim(self):
        """模块级 analyze_root_cause 应存在且可调用。"""
        assert callable(analyze_root_cause)

    def test_rootcause_analysis_alias(self):
        from auto_root_cause import RootCauseAnalysis
        assert RootCauseAnalysis is AnalysisReport
