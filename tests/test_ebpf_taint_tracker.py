"""
测试eBPF污点跟踪模块
"""

import pytest
_MOD_DEBUG = False
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.ebpf_taint_tracker import (
    EBPFTaintTracker, TaintSource, TaintSink,
    TrackerResult, create_ebpf_tracker,
    EBPFCodeGenerator, EBPFProgram,
    TaintSourceDatabase, TaintSinkDatabase
)


class TestTaintSource:
    """测试污点源数据类"""

    def test_taint_source_creation(self):
        """测试污点源创建"""
        source = TaintSource(name="read_input", syscall="sys_read", buffer_arg=1)
        assert source.name == "read_input"
        assert source.syscall == "sys_read"
        assert source.buffer_arg == 1


class TestTaintSink:
    """测试污点汇数据类"""

    def test_taint_sink_creation(self):
        """测试污点汇创建"""
        sink = TaintSink(name="copy_to_user", function="copy_to_user", risk="data_leak")
        assert sink.name == "copy_to_user"
        assert sink.function == "copy_to_user"
        assert sink.risk == "data_leak"


class TestEBPFProgram:
    """测试eBPF程序数据类"""

    def test_ebpf_program_creation(self):
        """测试eBPF程序创建"""
        sources = [TaintSource(name="read_input", syscall="sys_read", buffer_arg=1)]
        sinks = [TaintSink(name="copy_to_user", function="copy_to_user", risk="data_leak")]
        program = EBPFProgram(
            name="test_tracker",
            c_code="#include <linux/bpf.h>",
            taint_sources=sources,
            taint_sinks=sinks
        )
        assert program.name == "test_tracker"
        assert len(program.taint_sources) == 1
        assert len(program.taint_sinks) == 1
        assert "bpf.h" in program.c_code


class TestTrackerResult:
    """测试跟踪结果数据类"""

    def test_tracker_result_success(self):
        """测试成功的跟踪结果"""
        program = EBPFProgram(name="test", c_code="// empty", taint_sources=[], taint_sinks=[])
        result = TrackerResult(success=True, program=program)
        assert result.success is True
        assert result.program is not None
        assert len(result.violations) == 0

    def test_tracker_result_failure(self):
        """测试失败的跟踪结果"""
        result = TrackerResult(success=False, program=None, violations=["BCC not found"])
        assert result.success is False
        assert result.program is None
        assert "BCC" in result.violations[0]


class TestTaintSourceDatabase:
    """测试污点源数据库"""

    def test_sources_not_empty(self):
        """测试污点源列表不为空"""
        assert len(TaintSourceDatabase.SOURCES) > 0
        for source in TaintSourceDatabase.SOURCES:
            assert isinstance(source, TaintSource)


class TestTaintSinkDatabase:
    """测试污点汇数据库"""

    def test_sinks_not_empty(self):
        """测试污点汇列表不为空"""
        assert len(TaintSinkDatabase.SINKS) > 0
        for sink in TaintSinkDatabase.SINKS:
            assert isinstance(sink, TaintSink)


class TestEBPFCodeGenerator:
    """测试eBPF代码生成器"""

    def test_generate_code(self):
        sources = [TaintSource(name="read_input", syscall="sys_read", buffer_arg=1)]
        sinks = [TaintSink(name="copy_to_user", function="copy_to_user", risk="data_leak")]
        code = EBPFCodeGenerator.generate(sources, sinks)
        assert isinstance(code, str)
        assert "BPF_MAP_TYPE_HASH" in code
        assert "TAINT_FLAG" in code
        assert "trace_read_input" in code
        assert "check_copy_to_user" in code

    def test_generate_code_empty(self):
        """测试空源和汇的代码生成"""
        code = EBPFCodeGenerator.generate([], [])
        assert isinstance(code, str)
        assert "BPF_MAP_TYPE_HASH" in code


class TestEBPFTaintTracker:
    """测试eBPF污点跟踪器"""

    def test_initialization(self):
        """测试初始化"""
        tracker = EBPFTaintTracker()
        assert tracker is not None

    def test_create_ebpf_tracker(self):
        """测试工厂函数"""
        tracker = create_ebpf_tracker()
        assert isinstance(tracker, EBPFTaintTracker)

    def test_run(self):
        """测试运行分析"""
        tracker = EBPFTaintTracker()
        result = tracker.run(verify=False)

        assert result.success is True
        assert result.program is not None
        assert result.program.name == "taint_tracker"



if __name__ == "__main__":
    pytest.main([__file__, "-v"])
