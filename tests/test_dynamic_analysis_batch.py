"""Basic import & init smoke-tests for all dynamic_analysis submodules.

Each test just verifies the module can be imported and key classes
instantiated — no method-call assertions since those depend on
internal APIs that may change. Functional tests live in individual
test_<module>.py files.
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest


# core engine

def test_dynamic_analysis_engine_import():
    from modules.dynamic_analysis.dynamic_analysis_engine import (
        DynamicAnalysisEngine, RuntimeTrace, RuntimeBehaviorType,
        BehaviorSeverity, DynamicAnalysisResult, BehaviorPattern)
    engine = DynamicAnalysisEngine()
    assert engine is not None
    assert len(engine.MALICIOUS_PATTERNS) >= 5
    # quick smoke: trace serialization
    t = RuntimeTrace(
        trace_id='t1', timestamp=1000.0, behavior_type=RuntimeBehaviorType.FILE_CREATE,
        api_name='CreateFileW', process_name='test.exe', pid=1234, tid=5678,
        arguments={'path': 'C:\\test.txt'}, success=True, severity=BehaviorSeverity.MEDIUM)
    d = t.to_dict()
    assert d['trace_id'] == 't1'


# breakpoint_recovery

def test_breakpoint_recovery_import():
    from modules.dynamic_analysis.breakpoint_recovery import (
        BreakpointRecoveryManager, CheckpointManager, RecoveryPlan,
        RecoveryStrategy, AutoRetryStrategy, ErrorRecord)
    mgr = BreakpointRecoveryManager()
    assert mgr is not None


# memory detectors

def test_memory_malware_detector_import():
    from modules.dynamic_analysis.memory_malware_detector import (
        MemoryMalwareDetector, InjectionTechnique)
    d = MemoryMalwareDetector()
    assert d is not None


def test_sensitive_op_detector_import():
    from modules.dynamic_analysis.memory_sensitive_op_detector import (
        MemorySensitiveOpDetector, OperationType, SensitiveOperation)
    d = MemorySensitiveOpDetector()
    assert d is not None


def test_memory_primitive_extractor_import():
    from modules.dynamic_analysis.memory_primitive_extractor import (
        MemoryPrimitiveExtractor, PrimitiveType)
    e = MemoryPrimitiveExtractor()
    assert e is not None


# shadow stack

def test_shadow_stack_detector_import():
    from modules.dynamic_analysis.shadow_stack_detector import (
        ShadowStackDetector, ReturnViolation)
    d = ShadowStackDetector(f_binpath='/tmp/fake.bin')
    assert d is not None


# smc

def test_smc_dynamic_analyzer_import():
    from modules.dynamic_analysis.smc_dynamic_analyzer import (
        SMCDynamicAnalyzer, SMCCategory, CodePageModification)
    assert SMCCategory.PACKER == 'packer'
    a = SMCDynamicAnalyzer()
    assert a is not None


# auto_input_minimizer

def test_auto_input_minimizer_import():
    from modules.dynamic_analysis.auto_input_minimizer import (
        CrashInputMinimizer, DeltaDebugger, MinimizationStrategy,
        MinimizationResult)
    m = CrashInputMinimizer(binary_path='/tmp/fake.bin')
    assert m is not None


# behavior_tracing

def test_behavior_tracing_import():
    from modules.dynamic_analysis.behavior_tracing import BehaviorTracer
    t = BehaviorTracer()
    assert t is not None


# memory heap & visualizer

def test_memory_heap_import():
    from modules.dynamic_analysis.memory_heap import (
        HeapAllocatorStateAnalyzer, HeapBlock, HeapFuzzGenerator,
        HeapFengShuiRecorder, MemoryCorruptionPreciseLocator)
    a = HeapAllocatorStateAnalyzer()
    assert a is not None


def test_memory_visualizer_import():
    from modules.dynamic_analysis.memory_visualizer import (
        MemoryVisualizer, MemoryRegion, MemoryProtection, ASCIICanvas,
        SVGCanvas, HeapVisualizer)
    v = MemoryVisualizer()
    assert v is not None


# hw breakpoint & intel pt

def test_hw_breakpoint_detector_import():
    from modules.dynamic_analysis.hw_breakpoint_detector import (
        HardwareBreakpointDetector, DebugRegisterMonitor,
        DrRegister, BreakpointType)
    d = HardwareBreakpointDetector()
    assert d is not None


def test_intel_pt_import():
    from modules.dynamic_analysis.intel_pt import (
        PTPacketType, PTPacket, PTInstruction, ControlFlowEdge,
        PTPacketDecoder, PTControlFlowGraph, PTKeyTracker)
    assert PTPacketType.TNT is not None
    instr = PTInstruction(address=0x401000, opcode=b'\x90',
                          executed=True, timestamp=100)
    assert instr.address == 0x401000


# forensic timeline & diagnostic

def test_forensic_timeline_reconstructor_import():
    from modules.dynamic_analysis.forensic_timeline_reconstructor import (
        ForensicTimelineReconstructor, TimelineEvent, TimelineEventType,
        TimestampExtractor, ForensicTimeline)
    r = ForensicTimelineReconstructor()
    assert r is not None


def test_diagnostic_trace_mode_import():
    from modules.dynamic_analysis.diagnostic_trace_mode import (
        DiagnosticTracer, DiagnosticSession, TraceEvent)
    t = DiagnosticTracer()
    assert t is not None


# process dumper (new module)

def test_process_dumper_import():
    from modules.dynamic_analysis.process_dumper import (
        ProcessDumper, DumpMethod, DumpResult, ProcessScanner)
    assert DumpMethod.GCORE == 'gcore'
    dumper = ProcessDumper()
    methods = dumper.list_methods()
    assert isinstance(methods, list)
