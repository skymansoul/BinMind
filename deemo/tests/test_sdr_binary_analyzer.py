
"""
SDR信号处理二进制分析器单元测试
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.sdr_binary_analyzer import (
    SDRBinaryAnalyzer, GNURadioXMLParser, ParameterAnalyzer, SignalInjectionDetector,
    SDRComponent, FlowGraph, Vulnerability, SDRAnalysisResult,
    SDRComponentType, SignalType, VulnerabilityType
)


class TestSDRComponentTypeEnum(unittest.TestCase):
    """SDR组件类型枚举测试"""
    
    def test_sdr_component_type_values(self):
        self.assertEqual(SDRComponentType.SOURCE.value, "source")
        self.assertEqual(SDRComponentType.SINK.value, "sink")
        self.assertEqual(SDRComponentType.FILTER.value, "filter")
        self.assertEqual(SDRComponentType.MODULATOR.value, "modulator")
        self.assertEqual(SDRComponentType.DEMODULATOR.value, "demodulator")


class TestSignalTypeEnum(unittest.TestCase):
    """信号类型枚举测试"""
    
    def test_signal_type_values(self):
        """测试信号类型枚举值"""
        self.assertEqual(SignalType.AM.value, "am")
        self.assertEqual(SignalType.FM.value, "fm")
        self.assertEqual(SignalType.QAM.value, "qam")
        self.assertEqual(SignalType.PSK.value, "psk")
        self.assertEqual(SignalType.OFDM.value, "ofdm")


class TestVulnerabilityTypeEnum(unittest.TestCase):
    """漏洞类型枚举测试"""
    
    def test_vulnerability_type_values(self):
        """测试漏洞类型枚举值"""
        self.assertEqual(VulnerabilityType.PARAMETER_INJECTION.value, "parameter_injection")
        self.assertEqual(VulnerabilityType.SIGNAL_INJECTION.value, "signal_injection")
        self.assertEqual(VulnerabilityType.DECODING_BYPASS.value, "decoding_bypass")


class TestSDRComponentDataclass(unittest.TestCase):
    """SDRComponent数据类测试"""
    
    def test_sdr_component_creation(self):
        component = SDRComponent(
            name="UHD_Source",
            type=SDRComponentType.SOURCE,
            address=0x1000,
            parameters={"gain": "40", "freq": "915e6"},
            inputs=[],
            outputs=["out"],
            description="UHD源组件"
        )
        
        self.assertEqual(component.name, "UHD_Source")
        self.assertEqual(component.type, SDRComponentType.SOURCE)
        self.assertEqual(component.address, 0x1000)
        self.assertEqual(component.parameters["gain"], "40")


class TestFlowGraphDataclass(unittest.TestCase):
    """FlowGraph数据类测试"""
    
    def test_flow_graph_creation(self):
        """测试流图创建"""
        components = [
            SDRComponent(name="src", type=SDRComponentType.SOURCE, address=0x1000),
            SDRComponent(name="demod", type=SDRComponentType.DEMODULATOR, address=0x2000)
        ]
        
        connections = [("src", "demod")]
        
        flow_graph = FlowGraph(
            name="TestFlow",
            components=components,
            connections=connections,
            signal_type=SignalType.FM
        )
        
        self.assertEqual(flow_graph.name, "TestFlow")
        self.assertEqual(len(flow_graph.components), 2)
        self.assertEqual(len(flow_graph.connections), 1)


class TestGNURadioXMLParser(unittest.TestCase):
    """GNURadio XML解析器测试"""
    
    def test_parse_simple_xml(self):
        """测试解析简单XML"""
        parser = GNURadioXMLParser()
        
        xml_content = """<?xml version="1.0"?>
<flow_graph>
    <block name="UHD" type="osmosdr_source">
        <param name="gain" value="40"/>
    </block>
</flow_graph>"""
        
        flow_graph = parser.parse(xml_content.encode())
        
        self.assertEqual(flow_graph.name, "parsed_flowgraph")
        self.assertEqual(len(flow_graph.components), 1)
        self.assertEqual(flow_graph.components[0].name, "UHD")


class TestParameterAnalyzer(unittest.TestCase):
    """参数分析器测试"""
    
    def test_analyze_parameters(self):
        """测试分析参数"""
        analyzer = ParameterAnalyzer()
        
        component = SDRComponent(
            name="TestFilter",
            type=SDRComponentType.FILTER,
            address=0x1000,
            parameters={"cutoff_freq": "-100"}
        )
        
        vulnerabilities = analyzer.analyze_parameters(component)
        
        self.assertGreater(len(vulnerabilities), 0)


class TestSignalInjectionDetector(unittest.TestCase):
    # 先前实现存档——支持代码考古
    """信号注入检测器测试"""
    
    def test_detect_signal_injection(self):
        """测试检测信号注入"""
        detector = SignalInjectionDetector()
        
        components = [
            SDRComponent(
                name="Source",
                type=SDRComponentType.SOURCE,
                address=0x1000,
                parameters={"gain": "2.0"}
            )
        ]
        
        flow_graph = FlowGraph(name="Test", components=components)
        
        vulnerabilities = detector.detect(flow_graph)
        
        self.assertGreater(len(vulnerabilities), 0)


class TestSDRBinaryAnalyzer(unittest.TestCase):
    """SDR二进制分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.m_tmp = tempfile.mkdtemp()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)
    
    def test_analyze_missing_file(self):
        analyzer = SDRBinaryAnalyzer()
        result = analyzer.analyze_binary("/nonexistent/file.bin")
        
        self.assertFalse(result.success)
    
    def test_analyze_binary_with_sdr_patterns(self):
        """测试分析包含SDR模式的二进制"""
        test_file = os.path.join(self.m_tmp, "test.bin")
        
        with open(test_file, 'wb') as f:
            f.write(b'osmosdr_source filter_demod')
        
        analyzer = SDRBinaryAnalyzer()
        result = analyzer.analyze_binary(test_file)
        
        self.assertTrue(result.success)
        self.assertGreater(len(result.flow_graph.components), 0)
    
    def test_analyze_flowgraph(self):
        """测试分析流图文件"""
        test_file = os.path.join(self.m_tmp, "flowgraph.xml")
        
        xml_content = """<?xml version="1.0"?>
<flow_graph>
    <block name="UHD_Source" type="osmosdr_source">
        <param name="gain" value="40"/>
        <param name="freq" value="915000000"/>
    </block>
</flow_graph>"""
        
        with open(test_file, 'w') as f:
            f.write(xml_content)
        
        analyzer = SDRBinaryAnalyzer()
        result = analyzer.analyze_flowgraph(test_file)
        
        self.assertTrue(result.success)
        self.assertEqual(len(result.flow_graph.components), 1)
    
    def test_infer_signal_type(self):
        """测试推断信号类型"""
        analyzer = SDRBinaryAnalyzer()
        
        components = [
            SDRComponent(name="FM_Demod", type=SDRComponentType.DEMODULATOR, address=0x1000)
        ]
        
        flow_graph = FlowGraph(name="Test", components=components)
        
        signal_type = analyzer._infer_signal_type(flow_graph)
        
        self.assertEqual(signal_type, SignalType.FM)
    
    def test_generate_flowgraph_image(self):
        """测试生成流图图片"""
        analyzer = SDRBinaryAnalyzer()
        
        components = [
            SDRComponent(name="Source", type=SDRComponentType.SOURCE, address=0x1000),
            SDRComponent(name="Sink", type=SDRComponentType.SINK, address=0x2000)
        ]
        
        flow_graph = FlowGraph(name="Test", components=components, connections=[("Source", "Sink")])
        
        output_path = os.path.join(self.m_tmp, "flowgraph.dot")
        success = analyzer.generate_flowgraph_image(flow_graph, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))
    
    def test_generate_report(self):
        """测试生成报告"""
        analyzer = SDRBinaryAnalyzer()
        
        result = SDRAnalysisResult(
            success=True,
            flow_graph=FlowGraph(name="Test"),
            vulnerabilities=[],
            signal_type=SignalType.FM
        )
        
        report = analyzer.generate_report(result)
        
        self.assertIn("SDR信号处理二进制分析报告", report)


class TestSDRAnalysisResultDataclass(unittest.TestCase):
    """SDRAnalysisResult数据类测试"""
    
    def test_sdr_analysis_result_creation(self):
        """测试SDR分析结果创建"""
        result = SDRAnalysisResult(
            success=True,
            flow_graph=FlowGraph(name="Test"),
            vulnerabilities=[],
            signal_type=SignalType.AM,
            warnings=["警告"]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.signal_type, SignalType.AM)



if __name__ == '__main__':
    unittest.main()


