"""SDR 二进制分析：GNURadio 流图解析器。

解析 XML 流图以及二进制中的 SDR 组件签名，
输出 FlowGraph 供后续检测使用。
"""
import logging
import os
import re
from typing import Optional

from .sdr_types import (
    FlowGraph,
    SDRComponent,
    SDRComponentType,
    SignalType,
)

logger = logging.getLogger(__name__)


class GNURadioParser:
    # 解析器基类——保留空接口供后续扩展自定义格式
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


def analyze_binary_sdr(data: bytes) -> FlowGraph:
    # 二进制中无 XML 头时——按已知符号特征识别组件偏移
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


def infer_signal_type(flow_graph: FlowGraph) -> Optional[SignalType]:
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


def is_xml_flowgraph(data: bytes) -> bool:
    # XML 头识别——区分结构化流图与原始二进制
    return data.startswith(b'<?xml')
