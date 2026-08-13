#!/usr/bin/env python3
# Intel Processor Trace decoder, handles the packet format
import os
import shutil
import sys
import tempfile
import unittest


from modules.hw_trace_analyzer import (
    DataFlow,
    HWTraceAnalyzer,
    IntelPTDecoder,
    PerfDecoder,
    TraceAnalysisResult,
    TraceFunction,
    TraceInstruction,
    TracePacket,
    TracePath,
    TraceStatus,
    TraceType,
)


class TestTraceTypeEnum(unittest.TestCase):
    def setUp(self):
        pass

    def test_trace_type_values(self):
        self.assertEqual(TraceType.INTEL_PT.value, "intel_pt")
        self.assertEqual(TraceType.ARM_ETM.value, "arm_etm")
        self.assertEqual(TraceType.PERF_RECORD.value, "perf_record")


class TestTraceStatusEnum(unittest.TestCase):
    def test_trace_status_values(self):
        self.assertEqual(TraceStatus.COLLECTING.value, "collecting")
        self.assertEqual(TraceStatus.DECODED.value, "decoded")
        self.assertEqual(TraceStatus.ANALYZED.value, "analyzed")
        self.assertEqual(TraceStatus.ERROR.value, "error")


class TestTracePacketDataclass(unittest.TestCase):
    def test_trace_packet_creation(self):
        """TIP packet at 0x401000 with timestamp"""
        packet = TracePacket(
            timestamp=123456, type="TIP",
            payload=b"\x00\x01\x02\x03", address=0x401000,
        )
        if packet is None:
            self.fail("TracePacket is None")
        self.assertEqual(packet.timestamp, 123456)
        self.assertEqual(packet.type, "TIP")
        self.assertEqual(packet.address, 0x401000)


class TestTraceInstructionDataclass(unittest.TestCase):
    def test_trace_instruction_creation(self):
        instr = TraceInstruction(
            address=0x401000, mnemonic="mov",
            executed=True, timestamp=123456, cycle_count=10,
        )
        self.assertEqual(instr.address, 0x401000)
        self.assertTrue(instr.executed)
        self.assertEqual(instr.cycle_count, 10)


class TestTraceFunctionDataclass(unittest.TestCase):
    def test_trace_function_creation(self):
        """main function, 0x401000-0x401050, entered 1 time, exited 1 time"""
        func = TraceFunction(
            name="main", start_address=0x401000,
            end_address=0x401050, entry_count=1, exit_count=1,
        )
        self.assertEqual(func.name, "main")
        self.assertEqual(func.start_address, 0x401000)
        self.assertEqual(func.end_address, 0x401050)


class TestTracePathDataclass(unittest.TestCase):
    def test_trace_path_creation(self):
        instr = TraceInstruction(
            address=0x401000, mnemonic="mov",
            executed=True, timestamp=123456,
        )
        path = TracePath(
            instructions=[instr],
            function_calls=[(0x401000, 0x402000)],
            is_complete=True,
        )
        self.assertEqual(len(path.instructions), 1)
        self.assertEqual(len(path.function_calls), 1)
        self.assertTrue(path.is_complete)


class TestDataFlowDataclass(unittest.TestCase):
    def test_data_flow_creation(self):
        """source->dest, value=42, 4-byte mov"""
        flow = DataFlow(
            source=0x1000, destination=0x2000,
            value=42, size=4, operation="mov",
        )
        self.assertEqual(flow.source, 0x1000)
        self.assertEqual(flow.destination, 0x2000)
        self.assertEqual(flow.value, 42)


class TestIntelPTDecoder(unittest.TestCase):
    """Intel PT decoder -- empty and sample data"""

    def test_decode_empty_data(self):
        decoder = IntelPTDecoder("/nonexistent")
        result = decoder.decode(b"")
        self.assertEqual(len(result), 0)

    def test_decode_sample_data(self):
        decoder = IntelPTDecoder("/nonexistent")
        sample = b"\x00\x00\x00\x00\x01\x00\x00\x00\x40\x10\x00\x00"
        result = decoder.decode(sample)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].type, "TNT")


class TestPerfDecoder(unittest.TestCase):
    """Perf decoder -- empty and sample data"""

    def test_decode_empty_data(self):
        decoder = PerfDecoder()
        result = decoder.decode(b"")
        self.assertEqual(len(result), 0)

    def test_decode_sample_data(self):
        decoder = PerfDecoder()
        sample_data = (
            b"\x18\x00\x00\x00\x00\x00\x00\x00"
            b"\x07\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        result = decoder.decode(sample_data)
        self.assertEqual(len(result), 1)


class TestHWTraceAnalyzer(unittest.TestCase):
    """Hardware trace analyzer -- test analyze_trace, generate_report, save_result"""

    def setUp(self):
        self.m_tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        if os.path.exists(self.m_tmpdir):
            shutil.rmtree(self.m_tmpdir)

    def test_analyzer_creation(self):
        test_file = os.path.join(self.m_tmpdir, "test.bin")
        with open(test_file, "wb") as j:
            j.write(b"\x7fELF" + b"\x00" * 100)
        analyzer = HWTraceAnalyzer(test_file, TraceType.INTEL_PT)
        self.assertEqual(analyzer.binary_path, test_file)
        self.assertEqual(analyzer.trace_type, TraceType.INTEL_PT)

    def test_analyzer_missing_binary(self):
        with self.assertRaises(FileNotFoundError):
            HWTraceAnalyzer("/nonexistent/file.bin")

    def test_analyze_empty_trace(self):
        test_file = os.path.join(self.m_tmpdir, "test.bin")
        with open(test_file, "wb") as k:
            k.write(b"\x00" * 100)
        analyzer = HWTraceAnalyzer(test_file)
        result = analyzer.analyze_trace(b"")
        self.assertFalse(result.success)
        self.assertEqual(result.status, TraceStatus.ERROR)

    def test_analyze_valid_trace(self):
        test_file = os.path.join(self.m_tmpdir, "test.bin")
        with open(test_file, "wb") as ii:
            ii.write(b"\x00" * 100)
        analyzer = HWTraceAnalyzer(test_file)
        sample = b"\x00\x00\x00\x00\x01\x00\x00\x00\x40\x10\x00\x00"
        result = analyzer.analyze_trace(sample)
        self.assertTrue(result.success)
        self.assertEqual(result.status, TraceStatus.ANALYZED)

    def test_generate_report(self):
        test_file = os.path.join(self.m_tmpdir, "test.bin")
        with open(test_file, "wb") as jj:
            jj.write(b"\x00" * 100)
        analyzer = HWTraceAnalyzer(test_file)
        result = TraceAnalysisResult(
            success=True, status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[], data_flows=[],
        )
        report = analyzer.generate_report(result)
        self.assertIn("硬件跟踪analysis report", report)

    def test_save_result(self):
        test_file = os.path.join(self.m_tmpdir, "test.bin")
        with open(test_file, "wb") as kk:
            kk.write(b"\x00" * 100)
        analyzer = HWTraceAnalyzer(test_file)
        result = TraceAnalysisResult(
            success=True, status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[], data_flows=[],
        )
        output_path = os.path.join(self.m_tmpdir, "result.json")
        success = analyzer.save_result(result, output_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


class TestTraceAnalysisResultDataclass(unittest.TestCase):
    """TraceAnalysisResult -- contains warnings + CFG"""

    def test_trace_analysis_result_creation(self):
        result = TraceAnalysisResult(
            success=True,
            status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[],
            data_flows=[],
            control_flow_graph={},
            warnings=["warning"],
            errors=[],
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status, TraceStatus.ANALYZED)
        self.assertEqual(len(result.warnings), 1)


if __name__ == "__main__":
    unittest.main()
