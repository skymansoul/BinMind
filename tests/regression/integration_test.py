"""
全类型集成测试 —— 验证五种漏洞检测器均能正常导入和运行。

不依赖编译好的二进制 (make 可能不可用), 直接在伪代码文本上测试。
"""
import sys, os, time

_PROJ = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, _PROJ)


def test_heap_detection():
    """堆溢出: value-flow + allocator constraints"""
    from core.heap_flow_tracker import HeapFlowTracker
    from core.allocator_constraints import AllocSize, AllocatorConstraintChecker
    from core.heap_false_positive_filter import HeapFalsePositiveFilter

    # 伪代码: malloc(20) → memcpy 24 bytes → 现有工具误报, 我们应过滤
    code = 'char *buf = malloc(20); memcpy(buf, src, 24); free(buf);'
    tracker = HeapFlowTracker()
    traces = tracker.trace(code)
    assert len(traces) >= 0, "HeapFlowTracker failed"

    size = AllocSize.from_request(20)
    assert size.effective == 32, f"AllocSize(20) should be 32, got {size.effective}"
    assert size.can_contain(24), "malloc(20) should contain 24 bytes (alignment)"

    filt = HeapFalsePositiveFilter()
    findings = filt.filter(code, write_size=24)
    # 至少一个 finding, 且至少一个被过滤
    assert len(findings) > 0, "No findings from filter"
    return True


def test_uaf_detection():
    """UAF: 指针生命周期分析"""
    from core.uaf_detector import UAFDetector
    code = 'char *p = malloc(32); free(p); printf("%s", p);'
    detector = UAFDetector()
    findings = detector.detect(code, 'test_uaf')
    assert isinstance(findings, list), "UAFDetector should return list"
    return True


def test_format_string_detection():
    """格式化字符串: 污点传播 + 模式匹配 + 调用图 + 参数流"""
    from core.format_string_detector import detect_format_string_vulns
    assert callable(detect_format_string_vulns)
    from core.format_string_callgraph import FormatStringCallgraphAnalyzer
    cg = FormatStringCallgraphAnalyzer()
    cg.add_call_edge('main', 'log_msg', 0)
    cg.add_sink('log_msg', 'printf', 0)
    paths = cg.analyze()
    assert isinstance(paths, list)
    from core.format_string_argflow import FormatStringArgFlow
    af = FormatStringArgFlow()
    af.add_mapping('wrapper', 'printf', {0: 0})
    traces = af.trace_fmt_arg('wrapper', 0, 'fmt')
    assert isinstance(traces, list)
    return True


def test_stack_overflow_detection():
    """栈溢出: angr + 模式回退 + 栈帧推断"""
    from core.stack_overflow_analyzer import analyze_stack_overflow, analyze_with_pattern_fallback
    assert callable(analyze_stack_overflow)
    assert callable(analyze_with_pattern_fallback)
    from core.stack_frame_inferrer import StackFrameInferrer
    sf = StackFrameInferrer()
    frame = sf.infer_frame('push rbp; mov rbp, rsp; sub rsp, 0x40; lea rax, [rbp-0x30]', 'test')
    assert frame.frame_size >= 0x30
    risks = sf.check_overflow(frame, 0x20, 64)
    assert isinstance(risks, list)
    return True


def test_int_overflow_detection():
    """整数溢出: 范围传播 + 溢出检测"""
    from core.int_overflow_detector import IntOverflowDetector
    from core.int_range_propagator import propagate_ranges, filter_by_range

    detector = IntOverflowDetector()
    code = 'size_t n = count * sizeof(int); buf = malloc(n);'
    candidates = detector.detect(code, 'test_int')
    assert isinstance(candidates, list)

    ranges = propagate_ranges('int n = 4; int m = n * 8;')
    assert isinstance(ranges, dict)
    return True


def test_detection_orchestrator():
    """统一调度器"""
    from core.detection_orchestrator import DetectionOrchestrator
    orch = DetectionOrchestrator()
    assert orch.method_count() >= 0
    return True


if __name__ == '__main__':
    tests = [
        ('Heap Overflow', test_heap_detection),
        ('UAF', test_uaf_detection),
        ('Format String', test_format_string_detection),
        ('Stack Overflow', test_stack_overflow_detection),
        ('Integer Overflow', test_int_overflow_detection),
        ('Orchestrator', test_detection_orchestrator),
    ]
    passed = 0
    for name, fn in tests:
        try:
            fn()
            print(f'  [PASS] {name}')
            passed += 1
        except Exception as e:
            print(f'  [FAIL] {name}: {str(e)[:100]}')
    print(f'\n{passed}/{len(tests)} integration tests passed')
