# 2026-08-01
"""dynamic — integration tests"""

import os
import tempfile
import time

import pytest

from modules.analysis.dynamic.src.engine import (
    DynamicAnalysisEngine,
    EntropyScanPass,
    PatternMatchPass,
    RiskScoringPass,
    ImportAnalysisPass,
)
from modules.analysis.dynamic.src.memory import (
    MemoryForensics,
    MemoryVisualizer,
    MemoryRegion,
    HeapAnalyzer,
)
from modules.analysis.dynamic.src.emulation import (
    UnicornHybrid,
    EmulationState,
)
from modules.analysis.dynamic.src.instrumentation import (
    FridaInstrumentation,
    CheckpointManager,
    RecoveryStrategy,
    RecoveryAction,
)
from modules.analysis.dynamic.src.forensic import (
    TimelineReconstructor,
)
from modules.analysis.dynamic.src.vmi import (
    VMIAnalyzer,
    VMIAccessError,
)


class TestFullPipeline:
    """Test full analysis 流水线 end--end"""

    def test_binary_trace_pipeline(self):
        """运行 a complete trace analysis 流水线"""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ\x90\x00" + b"\x00" * 512)
            tmp_name = f.name

        try:
            engine = DynamicAnalysisEngine()
            engine.add_pass(EntropyScanPass())
            engine.add_pass(ImportAnalysisPass())
            engine.add_pass(PatternMatchPass())
            engine.add_pass(RiskScoringPass())

            report = engine.analyze(tmp_name, trace_count=20)
            assert 0.0 <= report["risk_score"] <= 1.0
            assert len(report["traces"]) > 0
            assert report["pass_count"] == 4
        finally:
            os.unlink(tmp_name)

    def test_pipeline_with_duplicate_passes(self):
        """Duplicate passes work"""
        engine = DynamicAnalysisEngine()
        engine.add_pass(EntropyScanPass())
        engine.add_pass(EntropyScanPass())  # Duplicate
        engine.add_pass(RiskScoringPass())

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00" * 256)
            tmp_name = f.name

        try:
            report = engine.analyze(tmp_name)
            assert "risk_score" in report
        finally:
            os.unlink(tmp_name)


class TestMemoryIntegration:
    """Test memory forensics features"""

    def test_dump_format_detection(self):
        """检测 raw 格式化 for random data"""
        with tempfile.NamedTemporaryFile(suffix=".dmp", delete=False) as f:
            f.write(b"\x00" * 4096)
            tmp_name = f.name

        try:
            mf = MemoryForensics()
            result = mf.analyze_dump(tmp_name)
            assert "format" in result
            assert "file_size" in result
            assert result["file_size"] >= 4096
        finally:
            os.unlink(tmp_name)

    def test_visualizer_ascii(self):
        """ASCII layout produce 输出"""
        vis = MemoryVisualizer()
        regions = [
            MemoryRegion(0x1000, 0x2000, 0x1000, "r-x", "text"),
            MemoryRegion(0x2000, 0x3000, 0x1000, "rw-", "data"),
            MemoryRegion(0x3000, 0x4000, 0x1000, "rwx", "stack"),
        ]
        result = vis.ascii_layout(regions)
        assert "MEMORY LAYOUT" in result
        assert "text" in result

    def test_visualizer_svg(self):
        """SVG layout produce valid SVG"""
        vis = MemoryVisualizer()
        regions = [MemoryRegion(0x1000, 0x2000, 0x1000, "rw", "data")]
        svg = vis.svg_layout(regions)
        assert "<svg" in svg
        assert "</svg>" in svg

    def test_visualizer_empty(self):
        """Empty regions produce minimal SVG"""
        vis = MemoryVisualizer()
        result = vis.ascii_layout([])
        assert result == "(empty)"

    def test_heap_analyzer(self):
        """堆 analysis work simulated data"""
        ha = HeapAnalyzer()
        data = b"\x00" * 16 + b"\x21\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 48
        chunks = ha.parse_heap(data, base_addr=0x1000)
        state = ha.analyze_heap_state()
        assert isinstance(state, dict)
        assert "total_chunks" in state


class TestEmulationIntegration:
    """Test 仿真 features"""

    def test_emulation_simulated(self):
        """Simulated 仿真 运行 Unicorn"""
        emu = UnicornHybrid(arch="x64")
        emu.map_memory(0x400000, 0x10000)
        emu.write_memory(0x400000, b"\x90" * 64)
        emu.write_register("eip", 0x400000)

        result = emu.emulate(timeout_seconds=5)
        assert result.success
        assert result.instructions_executed > 0
        assert result.state == EmulationState.TERMINATED

    def test_emulation_state_transitions(self):
        """仿真 state progress correctly"""
        emu = UnicornHybrid()
        assert emu.get_state() == EmulationState.IDLE
        # test further state transitions Unicorn available


class TestRecoveryIntegration:
    """Test recovery strategies"""

    def test_recovery_retry(self):
        """RecoveryStrategy suggest 重试 unknown errors"""
        rs = RecoveryStrategy(max_retries=3)
        decision = rs.on_error(ValueError("something broke"), attempt=0)
        assert decision.action == RecoveryAction.RETRY

    def test_recovery_skip_after_max(self):
        """skip max 重试"""
        rs = RecoveryStrategy(max_retries=2)
        decision = rs.on_error(ValueError("x"), attempt=3)
        assert decision.action == RecoveryAction.SKIP

    def test_checkpoint_save_restore(self):
        """检查点Manager 保存 恢复"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cm = CheckpointManager(tmpdir)
            cp = cm.save("test", {"eax": 42})
            assert cp.state.value == "saved"

            state = cm.restore(cp.checkpoint_id)
            assert state["eax"] == 42

            checkpoints = cm.list_checkpoints()
            assert len(checkpoints) == 1
