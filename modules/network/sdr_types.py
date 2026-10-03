"""SDR 二进制分析：枚举定义与数据结构。

组件类型、信号类型、漏洞类型枚举；组件、流图、参数校验、漏洞、
分析结果数据结构。供解析器、检测器与分析器共享。
"""
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List

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
