from typing import Optional, List
import logging
import os
import re
import math
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class SDRComponentType(Enum):
    SOURCE = "source"
    SINK = "sink"
    FILTER = "filter"
    MODULATOR = "modulator"
    DEMODULATOR = "demodulator"
    ENCODER = "encoder"
    DECODER = "decoder"
    MIXER = "mixer"
    RESAMPLER = "resampler"
    FFT = "fft"
    CONSTELLATION = "constellation"

class SignalType(Enum):
    AM = "am"
    FM = "fm"
    PM = "pm"
    QAM = "qam"
    PSK = "psk"
    FSK = "fsk"
    OFDM = "ofdm"

class VulnerabilityType(Enum):
    PARAMETER_INJECTION = "parameter_injection"
    SIGNAL_INJECTION = "signal_injection"
    DECODING_BYPASS = "decoding_bypass"
    IMPROPER_VALIDATION = "improper_validation"
    WEAK_CIPHER = "weak_cipher"
    SIDE_CHANNEL = "side_channel"
    IQ_DC_OFFSET = "iq_dc_offset"
    PHASE_NOISE = "phase_noise"


@dataclass
class SDRComponent:
    name: str
    type: SDRComponentType
    address: int = 0
    parameters: dict = field(default_factory=dict)
    inputs: list = field(default_factory=list)
    outputs: list = field(default_factory=list)
    description: str = ""

@dataclass
class FlowGraph:
    name: str
    components: list = field(default_factory=list)
    connections: list = field(default_factory=list)
    signal_type: Optional[SignalType] = None

@dataclass
class ParameterValidation:
    parameter_name: str
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    valid_values: Optional[list] = None
    is_required: bool = False

@dataclass
class Vulnerability:
    type: VulnerabilityType
    description: str
    component: str
    location: int = 0
    severity: str = "medium"
    parameters: list = field(default_factory=list)
    recommended_fix: str = ""

@dataclass
class SDRAnalysisResult:
    success: bool
    flow_graph: FlowGraph
    vulnerabilities: list
    signal_type: Optional[SignalType] = None
    warnings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class GNURadioParser:

    def parse(self, binary_data: bytes) -> FlowGraph:
        pass


class GNURadioXMLParser(GNURadioParser):

    def parse(self, binary_data: bytes) -> FlowGraph:
        try:
            import xml.etree.ElementTree as ET
            from functools import lru_cache

            flow_graph = FlowGraph(name="parsed_flowgraph")

            root = ET.fromstring(binary_data.decode('utf-8', errors='ignore'))

            for block in root.findall('.//block'):
                name = block.get('name', '')
                type_name = block.get('type', '')

                component_type = self._map_type(type_name)

                component = SDRComponent(
                    name=name,
                    type=component_type,
                    address=0,
                    description=block.get('comment', ''))

                for param in block.findall('.//param'):
                    param_name = param.get('name')
                    param_value = param.get('value')
                    if param_name and param_value:
                        component.parameters[param_name] = param_value

                flow_graph.components.append(component)

            for connection in root.findall('.//connection'):
                src = connection.get('src_block')
                dst = connection.get('dst_block')
                if src and dst:
                    flow_graph.connections.append((src, dst))

            return flow_graph

        except Exception as e:
            logger.error(f"GNURadio XML 解析失败: {e}")
            return FlowGraph(name="empty")

    def _map_type(self, type_name: str) -> SDRComponentType:
        type_map = {
            "osmosdr_source": SDRComponentType.SOURCE,
            "osmosdr_sink": SDRComponentType.SINK,
            "rational_resampler": SDRComponentType.RESAMPLER,
            "fft": SDRComponentType.FFT,
            "freq_xlating_fir_filter": SDRComponentType.FILTER,
            "analog_am_demod_cf": SDRComponentType.DEMODULATOR,
            "analog_fm_demod_cf": SDRComponentType.DEMODULATOR,
            "digital_psk_demod": SDRComponentType.DEMODULATOR,
            "digital_qam_demod": SDRComponentType.DEMODULATOR,
            "digital_constellation_decoder": SDRComponentType.DECODER,
            "add_const_vxx": SDRComponentType.MIXER,
        }

        for pattern, component_type in type_map.items():
            if pattern in type_name.lower():
                return component_type

        return SDRComponentType.FILTER


class ParameterAnalyzer:

    def __init__(self):
        self.validation_rules: dict[SDRComponentType, List[ParameterValidation]] = {
            SDRComponentType.FILTER: [
                ParameterValidation(parameter_name="cutoff_freq", min_value=0.0, max_value=1e9),
                ParameterValidation(parameter_name="taps", is_required=True),
            ],
            SDRComponentType.DEMODULATOR: [
                ParameterValidation(parameter_name="samp_rate", min_value=1000.0),
                ParameterValidation(parameter_name="freq", min_value=0.0, max_value=6e9),
            ],
            SDRComponentType.MIXER: [
                ParameterValidation(parameter_name="frequency", min_value=0.0, max_value=6e9),
            ],
            SDRComponentType.RESAMPLER: [
                ParameterValidation(parameter_name="interpolation", min_value=1),
                ParameterValidation(parameter_name="decimation", min_value=1),
            ],
        }

    def analyze_parameters(self, component: SDRComponent) -> List[Vulnerability]:
        vulnerabilities = []

        rules = self.validation_rules.get(component.type, [])

        for rule in rules:
            if rule.parameter_name in component.parameters:
                value = component.parameters[rule.parameter_name]

                try:
                    num_value = float(value)

                    if rule.min_value is not None and num_value < rule.min_value:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.PARAMETER_INJECTION,
                            description=f"参数 {rule.parameter_name}={value} 低于下限 {rule.min_value}",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=[rule.parameter_name],
                            recommended_fix=f"增设边界校验: {rule.parameter_name} >= {rule.min_value}"
                        ))

                    if rule.max_value is not None and num_value > rule.max_value:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.PARAMETER_INJECTION,
                            description=f"参数 {rule.parameter_name}={value} 超出上限 {rule.max_value}",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=[rule.parameter_name],
                            recommended_fix=f"增设边界校验: {rule.parameter_name} <= {rule.max_value}"
                        ))

                except ValueError:
                    pass

            elif rule.is_required:
                vulnerabilities.append(Vulnerability(
                    type=VulnerabilityType.IMPROPER_VALIDATION,
                    description=f"必选参数 {rule.parameter_name} 缺失",
                    component=component.name,
                    location=component.address,
                    severity="medium",
                    parameters=[rule.parameter_name],
                    recommended_fix=f"增加必选参数存在性检查: {rule.parameter_name}"
                ))

        return vulnerabilities


class SignalInjectionDetector:

    def detect(self, flow_graph: FlowGraph) -> List[Vulnerability]:
        vulnerabilities = []

        for component in flow_graph.components:
            if component.type == SDRComponentType.SOURCE:
                if "gain" in component.parameters:
                    gain = float(component.parameters["gain"])
                    if gain > 1.0:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.SIGNAL_INJECTION,
                            description=f"源组件 {component.name} 增益={gain} 突破安全阈值 —— 存在恶意信号放大风险",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=["gain"],
                            recommended_fix="将增益参数限制在 [0.0, 1.0] 区间"
                        ))

            elif component.type == SDRComponentType.DEMODULATOR:
                has_security = any(keyword in component.name.lower() for keyword in ["crypto", "auth", "encrypt"])
                if not has_security:
                    vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.DECODING_BYPASS,
                        description=f"解调器 {component.name} 缺乏认证机制 —— 易受信号欺骗攻击",
                        component=component.name,
                        location=component.address,
                        severity="high",
                        recommended_fix="增加信号认证与完整性校验"
                    ))

        return vulnerabilities


class IQSampleIntegrityChecker:
    # IQ 样本完整性分析 —— 检测 DC 偏移与相位噪声
    # DC 偏移：IQ 星座中心偏离原点 —— 常见于直接变频架构
    @staticmethod
    def check_dc_offset(iq_samples: list[complex]) -> dict:
        """计算 IQ 样本 DC 偏移估计 —— 样本均值幅值"""
        if not iq_samples:
            return {"dc_offset_db": 0.0, "risk": "info"}
        n = len(iq_samples)
        mean_i = sum(s.real for s in iq_samples) / n
        mean_q = sum(s.imag for s in iq_samples) / n
        dc_mag = math.sqrt(mean_i ** 2 + mean_q ** 2)
        # 归一化至信号 RMS 幅值
        rms = math.sqrt(sum(abs(s) ** 2 for s in iq_samples) / n)
        if rms < 1e-9:
            return {"dc_offset_db": -100.0, "risk": "info"}
        dc_db = 20 * math.log10(dc_mag / rms) if dc_mag > 0 else -100.0
        risk = "high" if dc_db > -20 else "medium" if dc_db > -30 else "info"
        return {"dc_offset_db": round(dc_db, 2), "risk": risk}

    @staticmethod
    def check_phase_noise(iq_samples: list[complex], sample_rate: float = 1.0) -> dict:
        """相位差分方差 —— 估计本地振荡器相噪

        计算相邻样本相位差，再算差分序列方差。
        方差 > 0.1 rad² 暗示相位噪声偏高。
        """
        if len(iq_samples) < 2:
            return {"phase_variance_rad2": 0.0, "risk": "info"}
        deltas = []
        for i in range(1, len(iq_samples)):
            a, b = iq_samples[i - 1], iq_samples[i]
            if abs(a) < 1e-9 or abs(b) < 1e-9:
                continue
            phase_diff = math.atan2(
                (b * a.conjugate()).imag,
                (b * a.conjugate()).real,
            )
            deltas.append(phase_diff)
        if len(deltas) < 2:
            return {"phase_variance_rad2": 0.0, "risk": "info"}
        mean_d = sum(deltas) / len(deltas)
        var_d = sum((d - mean_d) ** 2 for d in deltas) / len(deltas)
        risk = "high" if var_d > 0.5 else "medium" if var_d > 0.1 else "info"
        return {"phase_variance_rad2": round(var_d, 4), "risk": risk}


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

            if data.startswith(b'<?xml'):
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
        flow_graph = FlowGraph(name="binary_sdr")

        patterns = [
            (b'osmosdr_source', SDRComponentType.SOURCE),
            (b'osmosdr_sink', SDRComponentType.SINK),
            (b'fft_', SDRComponentType.FFT),
            (b'filter_', SDRComponentType.FILTER),
            (b'demod_', SDRComponentType.DEMODULATOR),
            (b'mod_', SDRComponentType.MODULATOR),
        ]

        for pattern, comp_type in patterns:
            matches = [m.start() for m in re.finditer(pattern, data)]
            for match in matches[:5]:
                flow_graph.components.append(SDRComponent(
                    name=f"{comp_type}_{hex(match)}",
                    type=comp_type,
                    address=match,
                    description=f"偏移量 0x{match:x}"))

        return flow_graph

    def _infer_signal_type(self, flow_graph: FlowGraph) -> Optional[SignalType]:
        demod_types = {
            'am': ['am', 'amplitude'],
            'fm': ['fm', 'frequency'],
            'pm': ['pm', 'phase'],
            'qam': ['qam', 'quadrature'],
            'psk': ['psk', 'phase_shift'],
            'fsk': ['fsk', 'frequency_shift'],
            'ofdm': ['ofdm', 'orthogonal'],
        }

        for signal_type, keywords in demod_types.items():
            for component in flow_graph.components:
                if any(keyword in component.name.lower() for keyword in keywords):
                    return SignalType(signal_type)

        return None

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

    def _get_component_color(self, comp_type: SDRComponentType) -> str:
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
        report.append("SDR 信号处理 —— 二进制分析报告")
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
