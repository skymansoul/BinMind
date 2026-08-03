# 2026-08-01
"""dynamic — core logic tests (engine, passes, 追踪)"""

import tempfile
import time
import os

import pytest

from modules.analysis.dynamic.src.engine import (
    AnalysisContext,
    DynamicAnalysisEngine,
    EntropyScanPass,
    PatternMatchPass,
    RiskScoringPass,
    ImportAnalysisPass,
    RuntimeTrace,
    BehaviorSeverity,
    quick_scan,
)
from modules.analysis.dynamic.src.tracing import (
    BehaviorTracer,
    BehaviorCategory,
    IntelPTDecoder,
    HWTraceAnalyzer,
    HWTraceConfig,
)


class TestEntropyScanPass:
    """Test entropy scanning pass"""

    def test_empty_data_entropy_zero(self):
        """Empty data entropy 0"""
        assert EntropyScanPass._shannon_entropy(b"") == 0.0

    def test_all_same_entropy_zero(self):
        """-identical bytes entropy 0"""
        assert EntropyScanPass._shannon_entropy(b"\xAA" * 256) == 0.0

    def test_random_data_high_entropy(self):
        """Random data high entropy (关闭 8)"""
        import os as _os
        data = _os.urandom(256)
        ent = EntropyScanPass._shannon_entropy(data)
        assert ent > 5.0, f"Expected high entropy, got {ent}"

    def test_pass_registers_outputs(self):
        """Pass populate entropy_report context"""
        ctx = AnalysisContext(binary_path="")
        p = EntropyScanPass()
        result = p.run(ctx)
        assert "entropy" in result.metadata

    def test_pass_on_binary(self):
        """Pass work a real binary file"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 128 + b"\xFF" * 64)
            tmp_name = f.name

        try:
            ctx = AnalysisContext(binary_path=tmp_name)
            p = EntropyScanPass()
            result = p.run(ctx)
            assert "entropy" in result.metadata
        finally:
            os.unlink(tmp_name)

    def test_entropy_is_float_between_0_and_8(self):
        """Entropy [0, 8] range"""
        for data in [b"\x00" * 100, os.urandom(100)]:
            ent = EntropyScanPass._shannon_entropy(data)
            assert 0.0 <= ent <= 8.0, f"Entropy out of range: {ent}"


class TestDynamicAnalysisEngine:
    """Test main engine"""

    def test_engine_initialization(self):
        """Engine 初始化 errors"""
        engine = DynamicAnalysisEngine()
        assert engine is not None

    def test_add_and_remove_pass(self):
        """able add remove passes"""
        engine = DynamicAnalysisEngine()
        p = EntropyScanPass()
        engine.add_pass(p)
        engine.remove_pass(p.name)
        engine.add_pass(p)
        engine.add_pass(RiskScoringPass())
        engine.add_pass(PatternMatchPass())
        engine.add_pass(ImportAnalysisPass())

    def test_analyze_returns_report(self):
        """分析() 返回 a structured 报告"""
        engine = DynamicAnalysisEngine()
        engine.add_pass(EntropyScanPass())
        engine.add_pass(RiskScoringPass())

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 512)
            tmp_name = f.name

        try:
            report = engine.analyze(tmp_name)
            assert "risk_score" in report
            assert "findings" in report
            assert "traces" in report
            assert "metadata" in report
            assert "duration_seconds" in report
            assert isinstance(report["risk_score"], float)
            assert isinstance(report["findings"], list)
        finally:
            os.unlink(tmp_name)

    def test_quick_scan(self):
        """quick_scan work explicit setup"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 256)
            tmp_name = f.name

        try:
            report = quick_scan(tmp_name)
            assert "risk_score" in report
        finally:
            os.unlink(tmp_name)

    def test_lookup_mitre(self):
        """MITRE lookup 返回 technique info"""
        result = DynamicAnalysisEngine.lookup_mitre("T1055")
        assert result is not None
        assert result["technique"] == "T1055"
        assert "apis" in result

    def test_lookup_unknown_mitre(self):
        """Unknown MITRE ID 返回 None"""
        result = DynamicAnalysisEngine.lookup_mitre("T99999")
        assert result is None

    def test_enrich_traces(self):
        """assign severity traces"""
        traces = [
            RuntimeTrace(
                trace_id="1", timestamp=0, behavior_type="process_inject",
                api_name="VirtualAllocEx", process_name="test", pid=1,
            ),
            RuntimeTrace(
                trace_id="2", timestamp=0, behavior_type="file_create",
                api_name="CreateFile", process_name="test", pid=1,
            ),
        ]
        enriched = DynamicAnalysisEngine.enrich_traces_with_severity(traces)
        assert enriched[0].severity == "critical"
        assert enriched[1].severity == "low"


class TestPatternMatchPass:
    """Test MITRE pattern matching"""

    def test_subsequence_match_basic(self):
        """Basic subsequence matching work"""
        assert PatternMatchPass._subsequence_match(
            ["a", "b", "c", "d"], ["b", "c"]
        )
        assert not PatternMatchPass._subsequence_match(
            ["a", "b", "c"], ["c", "b"]
        )
        assert PatternMatchPass._subsequence_match(
            ["a", "b", "c"], ["c"]
        )

    def test_subsequence_match_gaps(self):
        """Subsequence matching tolerate gaps"""
        assert PatternMatchPass._subsequence_match(
            ["a", "x", "b", "y", "c"], ["a", "b", "c"]
        )

    def test_subsequence_empty_needle(self):
        """Empty needle always match"""
        assert PatternMatchPass._subsequence_match(["a", "b"], [])

    def test_subsequence_needle_longer_than_haystack(self):
        """Longer needle hay栈 match"""
        assert not PatternMatchPass._subsequence_match(
            ["a"], ["a", "b", "c"]
        )


class TestBehaviorTracer:
    """Test API behavior 追踪"""

    def test_record_and_classify(self):
        """Recording calls accumulate categories"""
        tracer = BehaviorTracer()
        assert tracer.classify() == BehaviorCategory.NONE
        tracer.record("CreateFile")
        assert BehaviorCategory.FILE_OPERATION in tracer.classify()

    def test_detect_malicious_chain(self):
        """检测 injection chains"""
        tracer = BehaviorTracer(window_size=8)
        tracer.record("VirtualAllocEx", {"size": 4096})
        tracer.record("WriteProcessMemory", {"addr": 0x400000})
        tracer.record("CreateRemoteThread", {"entry": 0x400000})

        chains = tracer.detect_malicious_chains()
        assert len(chains) > 0
        assert any("Process Injection" in str(c.get("chain", "")) for c in chains)

    def test_clear_resets_everything(self):
        """清除 重置 recorded data"""
        tracer = BehaviorTracer()
        tracer.record("CreateFile")
        assert tracer.get_summary()["total_events"] == 1
        tracer.clear()
        assert tracer.get_summary()["total_events"] == 0

    def test_summary_has_expected_keys(self):
        """Summary 包含 expected fields"""
        tracer = BehaviorTracer()
        tracer.record("connect")
        summary = tracer.get_summary()
        assert "total_events" in summary
        assert "unique_apis" in summary
        assert "has_network" in summary
        assert summary["has_network"] is True


class TestIntelPTDecoder:
    """Test Intel PT decoder"""

    def test_initial_state(self):
        """Decoder 启动 IDLE state"""
        decoder = IntelPTDecoder()
        assert not decoder.has_events()
        stats = decoder.get_stats()
        assert stats["packets"] == 0

    def test_feed_tnt_packet(self):
        """Feeding a TNT 数据包 produce events"""
        decoder = IntelPTDecoder()
        decoder.feed(b"\x00\xAA\x05")  # TNT8 数据包
        events = []
        while decoder.has_events():
            events.append(decoder.next_event())
        assert len(events) > 0

    def test_feed_psb(self):
        """Feeding a PSB produce a 同步 event"""
        decoder = IntelPTDecoder()
        decoder.feed(b"\x02\x82\x02\x82\x02\x82\x02\x82")
        events = []
        while decoder.has_events():
            events.append(decoder.next_event())
        assert any(e["type"] == "PSB" for e in events)

    def test_next_event_empty_returns_none(self):
        """next_event() empty 缓冲区 返回 None"""
        decoder = IntelPTDecoder()
        assert decoder.next_event() is None

    def test_decode_filename_nonexistent(self):
        """解码 a nonexistent file 返回 empty list"""
        decoder = IntelPTDecoder()
        events = decoder.decode_filename("/nonexistent/pt_trace.data")
        assert events == []


class TestHWTraceAnalyzer:
    """Test hardware trace analyzer"""

    def test_collect_trace(self):
        """collect_trace succeed binary"""
        analyzer = HWTraceAnalyzer()
        result = analyzer.collect_trace("/usr/bin/true")
        assert result is True

    def test_decode_trace(self):
        """decode_trace 返回 decoded blocks"""
        analyzer = HWTraceAnalyzer()
        blocks = analyzer.decode_trace("trace.data")
        assert len(blocks) > 0
        assert all(b.address > 0 for b in blocks)

    def test_reconstruct_cfg(self):
        """reconstruct_cfg produce CFG nodes"""
        analyzer = HWTraceAnalyzer()
        blocks = analyzer.decode_trace("trace.data")
        cfg = analyzer.reconstruct_cfg(blocks)
        assert len(cfg) > 0

    def test_performance_counters(self):
        """返回 性能 counter data"""
        analyzer = HWTraceAnalyzer()
        counters = analyzer.analyze_performance_counters()
        assert "branches" in counters
        assert "ipc" in counters
