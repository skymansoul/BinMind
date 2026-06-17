#!/usr/bin/env python3
"""
SDR信号处理二进制分析

识别GNURadio流图中的信号处理算法，检测参数脆弱点，防止信号注入或解码绕过。
"""

import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from pathlib import Path

logger = logging.getLogger(__name__)


class SDRComponentType(Enum):
    """SDR组件类型枚举"""
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
    """信号类型枚举"""
    AM = "am"
    FM = "fm"
    PM = "pm"
    QAM = "qam"
    PSK = "psk"
    FSK = "fsk"
    OFDM = "ofdm"


class VulnerabilityType(Enum):
    """漏洞类型枚举"""
    PARAMETER_INJECTION = "parameter_injection"
    SIGNAL_INJECTION = "signal_injection"
    DECODING_BYPASS = "decoding_bypass"
    IMPROPER_VALIDATION = "improper_validation"
    WEAK_CIPHER = "weak_cipher"
    SIDE_CHANNEL = "side_channel"


@dataclass
class SDRComponent:
    """SDR组件定义"""
    name: str
    type: SDRComponentType
    address: int
    parameters: Dict[str, Any] = field(default_factory=dict)
    inputs: List[str] = field(default_factory=list)
    outputs: List[str] = field(default_factory=list)
    description: str = ""


@dataclass
class FlowGraph:
    """流图定义"""
    name: str
    components: List[SDRComponent] = field(default_factory=list)
    connections: List[Tuple[str, str]] = field(default_factory=list)
    signal_type: Optional[SignalType] = None


@dataclass
class ParameterValidation:
    """参数验证规则"""
    parameter_name: str
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    valid_values: Optional[List[Any]] = None
    is_required: bool = False


@dataclass
class Vulnerability:
    """漏洞信息"""
    type: VulnerabilityType
    description: str
    component: str
    location: int
    severity: str = "medium"
    parameters: List[str] = field(default_factory=list)
    recommended_fix: str = ""


@dataclass
class SDRAnalysisResult:
    """SDR分析结果"""
    success: bool
    flow_graph: FlowGraph
    vulnerabilities: List[Vulnerability]
    signal_type: Optional[SignalType] = None
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class GNURadioParser(ABC):
    """GNURadio解析器基类"""
    
    @abstractmethod
    def parse(self, binary_data: bytes) -> FlowGraph:
        """
        解析GNURadio流图
        
        Args:
            binary_data: 二进制数据
        
        Returns:
            流图定义
        """
        pass


class GNURadioXMLParser(GNURadioParser):
    """GNURadio XML流图解析器"""
    
    def parse(self, binary_data: bytes) -> FlowGraph:
        """解析GNURadio XML流图"""
        try:
            import xml.etree.ElementTree as ET
            
            flow_graph = FlowGraph(name="parsed_flowgraph")
            
            root = ET.fromstring(binary_data.decode('utf-8', errors='ignore'

            
            for block in root.findall('.//block'):
                name = block.get('name', '')
                type_name = block.get('type', '')
                
                component_type = self._map_type(type_name)
                
                component = SDRComponent()
                    name=name,
                    type=component_type,
                    address=0,
                    description=block.get('comment', '')
                
                
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
                    flow_graph.connections.append((src, dst

            
            return flow_graph
        
        except Exception as e:
            logger.error(f"解析GNURadio XML失败: {e}")
            return FlowGraph(name="empty")
    
    def _map_type(self, type_name: str) -> SDRComponentType:
        """映射类型名称"""
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
    """参数分析器"""
    
    def __init__(self):
        """初始化参数分析器"""
        self.validation_rules: Dict[str, List[ParameterValidation]] = {
            SDRComponentType.FILTER.name: [
                ParameterValidation(parameter_name="cutoff_freq", min_value=0.0, max_value=1e9),
                ParameterValidation(parameter_name="taps", is_required=True),
            ],
            SDRComponentType.DEMODULATOR.name: [
                ParameterValidation(parameter_name="samp_rate", min_value=1000.0),
                ParameterValidation(parameter_name="freq", min_value=0.0, max_value=6e9),
            ],
            SDRComponentType.MIXER.name: [
                ParameterValidation(parameter_name="frequency", min_value=0.0, max_value=6e9),
            ],
            SDRComponentType.RESAMPLER.name: [
                ParameterValidation(parameter_name="interpolation", min_value=1),
                ParameterValidation(parameter_name="decimation", min_value=1),
            ],
        }
    
    def analyze_parameters(self, component: SDRComponent) -> List[Vulnerability]:
        """
        分析组件参数
        
        Args:
            component: SDR组件
        
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        rules = self.validation_rules.get(component.type.name, [])
        
        for rule in rules:
            if rule.parameter_name in component.parameters:
                value = component.parameters[rule.parameter_name]
                
                try:
                    num_value = float(value)
                    
                    if rule.min_value is not None and num_value < rule.min_value:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.PARAMETER_INJECTION,
                            description=f"参数 {rule.parameter_name} 值 {value} 低于最小值 {rule.min_value}",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=[rule.parameter_name],
                            recommended_fix=f"添加参数验证，确保 {rule.parameter_name} >= {rule.min_value}"
                        

                    
                    if rule.max_value is not None and num_value > rule.max_value:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.PARAMETER_INJECTION,
                            description=f"参数 {rule.parameter_name} 值 {value} 超过最大值 {rule.max_value}",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=[rule.parameter_name],
                            recommended_fix=f"添加参数验证，确保 {rule.parameter_name} <= {rule.max_value}"
                        

                
                except ValueError:
                    # 非数值参数
                    pass
            
            elif rule.is_required:
                vulnerabilities.append(Vulnerability(
                    type=VulnerabilityType.IMPROPER_VALIDATION,
                    description=f"必需参数 {rule.parameter_name} 缺失",
                    component=component.name,
                    location=component.address,
                    severity="medium",
                    parameters=[rule.parameter_name],
                    recommended_fix=f"添加必需参数 {rule.parameter_name} 的检查"
                

        
        return vulnerabilities


class SignalInjectionDetector:
    """信号注入检测器"""
    
    def detect(self, flow_graph: FlowGraph) -> List[Vulnerability]:
        """
        检测信号注入漏洞
        
        Args:
            flow_graph: 流图
        
        Returns:
            漏洞列表
        """
        vulnerabilities = []
        
        # 检测信号注入点
        for component in flow_graph.components:
            if component.type == SDRComponentType.SOURCE:
                # 检查是否有输入验证
                if "gain" in component.parameters:
                    gain = float(component.parameters["gain"])
                    if gain > 1.0:
                        vulnerabilities.append(Vulnerability(
                            type=VulnerabilityType.SIGNAL_INJECTION,
                            description=f"源组件 {component.name} 增益 {gain} 过高，可能放大恶意信号",
                            component=component.name,
                            location=component.address,
                            severity="high",
                            parameters=["gain"],
                            recommended_fix="限制增益参数范围"
                        

            
            elif component.type == SDRComponentType.DEMODULATOR:
                # 检测是否有认证/加密机制
                has_security = any(keyword in component.name.lower() for keyword in ["crypto", "auth", "encrypt"])
                if not has_security:
                    vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.DECODING_BYPASS,
                        description=f"解调器 {component.name} 缺少认证机制，可能被恶意信号欺骗",
                        component=component.name,
                        location=component.address,
                        severity="high",
                        recommended_fix="添加信号认证和完整性检查"
                    

        
        return vulnerabilities


class SDRBinaryAnalyzer:
    """
    SDR信号处理二进制分析器
    
    识别GNURadio流图中的信号处理算法，检测参数脆弱点，防止信号注入或解码绕过。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.xml_parser = GNURadioXMLParser()
        self.parameter_analyzer = ParameterAnalyzer()
        self.signal_injection_detector = SignalInjectionDetector()
    
    def analyze_binary(self, binary_path: str) -> SDRAnalysisResult:
        """
        分析二进制文件
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            分析结果
        """
        if not os.path.exists(binary_path):
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[f"文件不存在: {binary_path}"])
            

        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            # 检查是否是XML流图文件
            if data.startswith(b'<?xml'):
                flow_graph = self.xml_parser.parse(data)
            else:
                flow_graph = self._analyze_binary_sdr(data)
            
            # 分析参数漏洞
            vulnerabilities = []
            for component in flow_graph.components:
                vulns = self.parameter_analyzer.analyze_parameters(component)
                vulnerabilities.extend(vulns)
            
            # 检测信号注入漏洞
            injection_vulns = self.signal_injection_detector.detect(flow_graph)
            vulnerabilities.extend(injection_vulns)
            
            # 推断信号类型
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
                errors=[str(e)])
            

    
    def _analyze_binary_sdr(self, data: bytes) -> FlowGraph:
        """分析二进制SDR代码"""
        flow_graph = FlowGraph(name="binary_sdr")
        
        # 搜索GNURadio组件模式
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
            for match in matches[:5]:  # 限制每个类型最多5个组件
                flow_graph.components.append(SDRComponent(
                    name=f"{comp_type.name}_{hex(match)}",
                    type=comp_type,
                    address=match,
                    description=f"发现于地址 0x{match:x}"
                

        
        return flow_graph
    
    def _infer_signal_type(self, flow_graph: FlowGraph) -> Optional[SignalType]:
        """推断信号类型"""
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
        """
        分析GNURadio流图文件
        
        Args:
            flowgraph_path: 流图文件路径
        
        Returns:
            分析结果
        """
        if not os.path.exists(flowgraph_path):
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[f"文件不存在: {flowgraph_path}"])
            

        
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
            logger.error(f"分析流图失败: {e}")
            return SDRAnalysisResult(
                success=False,
                flow_graph=FlowGraph(name=""),
                vulnerabilities=[],
                errors=[str(e)])
            

    
    def generate_flowgraph_image(self, flow_graph: FlowGraph, output_path: str) -> bool:
        """
        生成流图可视化图片
        
        Args:
            flow_graph: 流图
            output_path: 输出路径
        
        Returns:
            是否成功
        """
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
            
            logger.info(f"流图已保存: {output_path}")
            return True
        
        except Exception as e:
            logger.error(f"生成流图失败: {e}")
            return False
    
    def _get_component_color(self, comp_type: SDRComponentType) -> str:
        """获取组件颜色"""
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
        """
        生成分析报告
        
        Args:
            result: 分析结果
        
        Returns:
            报告字符串
        """
        report = []
        report.append("=" * 60)
        report.append("SDR信号处理二进制分析报告")
        report.append("=" * 60)
        report.append(f"成功: {result.success}")
        report.append(f"信号类型: {result.signal_type.value if result.signal_type else '未知'}")
        report.append(f"组件数量: {len(result.flow_graph.components)}")
        report.append(f"漏洞数量: {len(result.vulnerabilities)}")
        report.append("")
        
        if result.flow_graph.components:
            report.append("组件列表:")
            report.append("-" * 40)
            for component in result.flow_graph.components:
                report.append(f"组件: {component.name}")
                report.append(f"  类型: {component.type.value}")
                report.append(f"  地址: 0x{component.address:x}")
                if component.parameters:
                    report.append(f"  参数: {component.parameters}")
                report.append("")
        
        if result.vulnerabilities:
            report.append("漏洞列表:")
            report.append("-" * 40)
            for vuln in result.vulnerabilities:
                report.append(f"类型: {vuln.type.value}")
                report.append(f"  组件: {vuln.component}")
                report.append(f"  描述: {vuln.description}")
                report.append(f"  严重程度: {vuln.severity}")
                if vuln.recommended_fix:
                    report.append(f"  修复建议: {vuln.recommended_fix}")
                report.append("")
        
        return "\n".join(report)))))))))))))))))