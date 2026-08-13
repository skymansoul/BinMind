"""SDR 二进制分析：主分析器编排。

负责文件读取、解析器与检测器编排、信号类型推断、
流图 DOT 导出与文本报告生成。
"""
import os
import logging
from typing import Optional

from .sdr_types import (
    SDRComponent,
    SDRComponentType,
    FlowGraph,
    SignalType,
    SDRAnalysisResult,
    Vulnerability,
    VulnerabilityType,
)
from .sdr_parser import (
    GNURadioParser,
    GNURadioXMLParser,
    analyze_binary_sdr,
    infer_signal_type as _infer_signal_type_impl,
    is_xml_flowgraph,
)
from .sdr_detectors import (
    ParameterAnalyzer,
    SignalInjectionDetector,
    IQSampleIntegrityChecker,
)

logger = logging.getLogger(__name__)


class SDRBinaryAnalyzer:

    def __init__(self):
        self.xml_parser = GNURadioXMLParser()
        self.parameter_analyzer = ParameterAnalyzer()
        self.signal_injection_detector = SignalInjectionDetector()
        self.iq_checker = IQSampleIntegrityChecker()

    def analyze_binary(self, binary_path: str) -> SDRAnalysisResult:
        if not os.path.exists(binary_path):
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[f"文件未找到: {binary_path}"])

        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            if is_xml_flowgraph(data):
                flow_graph = self.xml_parser.parse(data)
            else:
                flow_graph = self._analyze_binary_sdr(data)

            vulnerabilities = []
            for component in flow_graph.components:
                vulns = self.parameter_analyzer.analyze_parameters(component)
                vulnerabilities.extend(vulns)

            injection_vulns = self.signal_injection_detector.detect(flow_graph)
            vulnerabilities.extend(injection_vulns)

            signal_type = self._infer_signal_type(flow_graph)

            return SDRAnalysisResult(
                success=True,
                flow_graph=flow_graph,
                vulnerabilities=vulnerabilities,
                signal_type=signal_type)

        except Exception as e:
            logger.error(f"分析失败: {e}")
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[str(e)]
            )

    def _analyze_binary_sdr(self, data: bytes) -> FlowGraph:
        return analyze_binary_sdr(data)

    def _infer_signal_type(self, flow_graph: FlowGraph) -> Optional[SignalType]:
        return _infer_signal_type_impl(flow_graph)

    def analyze_flowgraph(self, flowgraph_path: str) -> SDRAnalysisResult:
        if not os.path.exists(flowgraph_path):
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[f"文件未找到: {flowgraph_path}"])

        try:
            with open(flowgraph_path, 'rb') as f:
                data = f.read()

            flow_graph = self.xml_parser.parse(data)

            vulnerabilities = []
            for component in flow_graph.components:
                vulns = self.parameter_analyzer.analyze_parameters(component)
                vulnerabilities.extend(vulns)

            injection_vulns = self.signal_injection_detector.detect(flow_graph)
            vulnerabilities.extend(injection_vulns)

            signal_type = self._infer_signal_type(flow_graph)

            return SDRAnalysisResult(
                success=True,
                flow_graph=flow_graph,
                vulnerabilities=vulnerabilities,
                signal_type=signal_type)

        except Exception as e:
            logger.error(f"流图分析失败: {e}")
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[str(e)]
            )

    def generate_flowgraph_image(self, flow_graph: FlowGraph, output_path: str) -> bool:
        try:
            with open(output_path, 'w') as f:
                f.write("digraph FlowGraph {\n")
                f.write("    rankdir=LR;\n")

                for component in flow_graph.components:
                    color = self._get_component_color(component.type)
                    f.write(f"    \"{component.name}\" [color={color}, style=filled];\n")

                for src, dst in flow_graph.connections:
                    f.write(f"    \"{src}\" -> \"{dst}\";\n")

                f.write("}\n")

            logger.info(f"流图已导出: {output_path}")
            return True

        except Exception as e:
            logger.error(f"流图生成失败: {e}")
            return False

    @staticmethod
    def _get_component_color(comp_type: SDRComponentType) -> str:
        color_map = {
            SDRComponentType.SOURCE: "green",
            SDRComponentType.SINK: "red",
            SDRComponentType.FILTER: "blue",
            SDRComponentType.MODULATOR: "orange",
            SDRComponentType.DEMODULATOR: "purple",
            SDRComponentType.ENCODER: "cyan",
            SDRComponentType.DECODER: "magenta",
            SDRComponentType.MIXER: "yellow",
            SDRComponentType.RESAMPLER: "pink",
            SDRComponentType.FFT: "gray",
            SDRComponentType.CONSTELLATION: "brown",
        }
        return color_map.get(comp_type, "white")

    def generate_report(self, result: SDRAnalysisResult) -> str:
        report = []
        report.append("=" * 60)
        report.append("SDR信号处理二进制分析报告")
        report.append("=" * 60)
        report.append(f"执行状态: {result.success}")
        report.append(f"信号类型: {result.signal_type if result.signal_type else '未知'}")
        report.append(f"组件数量: {len(result.flow_graph.components)}")
        report.append(f"漏洞数量: {len(result.vulnerabilities)}")
        report.append("")

        if result.flow_graph.components:
            report.append("组件清单:")
            report.append("-" * 40)
            for component in result.flow_graph.components:
                report.append(f"  组件: {component.name}")
                report.append(f"    类型: {component.type}")
                report.append(f"    地址: 0x{component.address:x}")
                if component.parameters:
                    report.append(f"    参数: {component.parameters}")
                report.append("")

        if result.vulnerabilities:
            report.append("漏洞清单:")
            report.append("-" * 40)
            for vuln in result.vulnerabilities:
                report.append(f"  类型: {vuln.type}")
                report.append(f"  组件: {vuln.component}")
                report.append(f"  描述: {vuln.description}")
                report.append(f"  严重程度: {vuln.severity}")
                if vuln.recommended_fix:
                    report.append(f"  修复方案: {vuln.recommended_fix}")
                report.append("")

        return "\n".join(report)
