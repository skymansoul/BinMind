"""SDR 二进制分析：漏洞检测器集合。

参数边界检测、信号注入与解调旁路检测、IQ 样本完整性检测。
各检测器独立运行，由分析器编排调用。
"""
import math
import logging
from typing import List

from .sdr_types import (
    SDRComponent,
    SDRComponentType,
    FlowGraph,
    ParameterValidation,
    Vulnerability,
    VulnerabilityType,
)

logger = logging.getLogger(__name__)


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
    # IQ 样本完整性分析——检测 DC 偏移与相位噪声
    # DC 偏移：IQ 星座中心偏离原点——常见于直接变频架构
    @staticmethod
    def check_dc_offset(iq_samples: list[complex]) -> dict:
        # 样本均值幅值评估 DC 偏移——归一化至信号 RMS
        if not iq_samples:
            return {"dc_offset_db": 0.0, "risk": "info"}
        n = len(iq_samples)
        mean_i = sum(s.real for s in iq_samples) / n
        mean_q = sum(s.imag for s in iq_samples) / n
        dc_mag = math.sqrt(mean_i ** 2 + mean_q ** 2)
        rms = math.sqrt(sum(abs(s) ** 2 for s in iq_samples) / n)
        if rms < 1e-9:
            return {"dc_offset_db": -100.0, "risk": "info"}
        dc_db = 20 * math.log10(dc_mag / rms) if dc_mag > 0 else -100.0
        risk = "high" if dc_db > -20 else "medium" if dc_db > -30 else "info"
        return {"dc_offset_db": round(dc_db, 2), "risk": risk}

    @staticmethod
    def check_phase_noise(iq_samples: list[complex], sample_rate: float = 1.0) -> dict:
        # 相位差分方差估计本地振荡器相噪——>0.5 rad² 判为高风险
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
