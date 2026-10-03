"""重打包检测 —— 文件格式识别、节区熵分析、风险评分。

检测 PE/ELF/DEX 二进制中的重打包迹象：异常节区、高熵区域、
overlay 追加数据等，输出重打包类型、严重度与修复建议。
"""

import json
import math
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class Severity(Enum):
    """重打包风险等级。"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RepackType(Enum):
    """重打包类型分类。"""
    NONE = "none"
    INJECTED_CODE = "injected_code"
    BUNDLED_PAYLOAD = "bundled_payload"


@dataclass
class SectionInfo:
    """节区元数据与异常标记。"""
    name: str = ""
    virtual_address: int = 0
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    is_anomalous: bool = False

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'virtual_address': self.virtual_address,
            'virtual_size': self.virtual_size,
            'raw_size': self.raw_size,
            'entropy': self.entropy,
            'is_anomalous': self.is_anomalous,
        }


@dataclass
class Anomaly:
    """单条异常记录。"""
    type: str = ""
    severity: Severity = Severity.LOW
    description: str = ""
    location: str = ""
    evidence: str = ""
    original_value: str = ""
    repackaged_value: str = ""

    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity.value,
            'description': self.description,
            'location': self.location,
            'evidence': self.evidence,
        }


@dataclass
class RepackConfig:
    """检测开关与参数配置。"""
    check_overlay: bool = True
    check_sections: bool = True
    check_entry_point: bool = True
    entropy_threshold: float = 7.0
    known_signatures_db: str = ""
    compare_with_original: bool = False
    original_file_path: str = ""

    def validate(self) -> bool:
        return True


@dataclass
class RepackResult:
    """重打包检测结果。"""
    is_repacked: bool = False
    repack_type: RepackType = RepackType.NONE
    severity: Severity = Severity.SAFE
    risk_score: float = 0.0
    confidence: float = 0.0
    anomalies: List[Anomaly] = field(default_factory=list)
    sections: List[SectionInfo] = field(default_factory=list)
    overlay_size: int = 0

    def to_dict(self) -> Dict:
        return {
            'is_repacked': self.is_repacked,
            'repack_type': self.repack_type.value,
            'severity': self.severity.value,
            'risk_score': self.risk_score,
            'confidence': self.confidence,
            'anomalies': [
                {'type': a.type, 'severity': a.severity.value, 'description': a.description}
                for a in self.anomalies
            ],
            'overlay_size': self.overlay_size,
        }


_SUSPICIOUS_SECTION_NAMES = {
    '.inject', '.payload', '.bundle', '.resource', '.overlay',
    '.packer', '.upx', '.crypted', '.stub',
}


class RepackDetector:
    """重打包检测器 —— 格式识别 + 节区熵判定 + 风险聚合。"""

    def __init__(self, config: Optional[RepackConfig] = None):
        self.config = config or RepackConfig()

    def _detect_file_type(self, data: bytes) -> str:
        """按魔数识别文件格式。"""
        if data.startswith(b'MZ'):
            return 'pe'
        if data.startswith(b'\x7fELF'):
            return 'elf'
        if data.startswith(b'dex\n'):
            return 'dex'
        return 'unknown'

    def _calculate_entropy(self, data: bytes) -> float:
        """计算字节级 Shannon 熵。"""
        if not data:
            return 0.0
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        n = len(data)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / n
            entropy -= p * math.log2(p)
        return entropy

    def _is_section_anomalous(self, name: str, entropy: float,
                              virtual_size: int, raw_size: int) -> bool:
        """判定节区是否异常: 可疑名称或熵超阈值。"""
        if name.lower() in _SUSPICIOUS_SECTION_NAMES:
            return True
        if entropy > self.config.entropy_threshold:
            return True
        if virtual_size > 0 and raw_size > virtual_size:
            return True
        return False

    def _scan_sections(self, data: bytes) -> List[SectionInfo]:
        """按固定窗口切分节区并计算熵。"""
        sections = []
        window = 512
        idx = 0
        while idx + window <= len(data):
            chunk = data[idx:idx + window]
            entropy = self._calculate_entropy(chunk)
            name = f'.section_{idx // window}'
            is_anomalous = self._is_section_anomalous(name, entropy, window, window)
            sections.append(SectionInfo(
                name=name, virtual_address=idx, virtual_size=window,
                raw_size=window, entropy=round(entropy, 3),
                is_anomalous=is_anomalous,
            ))
            idx += window
        return sections

    def detect(self, file_path: str) -> RepackResult:
        """检测文件是否被重打包。"""
        result = RepackResult()
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except OSError:
            return result

        file_type = self._detect_file_type(data)
        if file_type == 'unknown':
            return result

        if self.config.check_sections:
            result.sections = self._scan_sections(data)
            for section in result.sections:
                if section.is_anomalous:
                    result.anomalies.append(Anomaly(
                        type='anomalous_section',
                        severity=Severity.HIGH,
                        description=f'节区 {section.name} 熵 {section.entropy:.2f} 异常',
                    ))

        result.overlay_size = self._detect_overlay_size(file_type, data)
        if result.overlay_size > 1024:
            result.anomalies.append(Anomaly(
                type='overlay_data',
                severity=Severity.MEDIUM,
                description=f'尾部追加 {result.overlay_size} 字节数据',
            ))

        result.is_repacked = len(result.anomalies) > 0
        result.repack_type = self._determine_repack_type(result)
        result.severity = self._determine_severity(result)
        result.risk_score = self._calculate_risk_score(result)
        result.confidence = min(0.95, 0.5 + 0.1 * len(result.anomalies))
        return result

    @staticmethod
    def _detect_overlay_size(file_type: str, data: bytes) -> int:
        """估算文件尾部未映射数据大小。"""
        if file_type == 'pe' and len(data) >= 0x3C + 4:
            pe_off = struct.unpack_from('<I', data, 0x3C)[0]
            if pe_off + 0x18 <= len(data):
                size_of_image = struct.unpack_from('<I', data, pe_off + 0x50)[0]
                if size_of_image and len(data) > size_of_image:
                    return len(data) - size_of_image
        return 0

    def _determine_repack_type(self, result: RepackResult) -> RepackType:
        """根据异常类型推断重打包方式。"""
        for anomaly in result.anomalies:
            if anomaly.type == 'anomalous_section':
                return RepackType.INJECTED_CODE
        if result.overlay_size > 1024:
            return RepackType.BUNDLED_PAYLOAD
        return RepackType.NONE

    def _determine_severity(self, result: RepackResult) -> Severity:
        """按异常数量映射严重度。"""
        count = len(result.anomalies)
        if count == 0:
            return Severity.SAFE
        if count == 1:
            return Severity.LOW
        if count == 2:
            return Severity.MEDIUM
        if count == 3:
            return Severity.HIGH
        return Severity.CRITICAL

    def _calculate_risk_score(self, result: RepackResult) -> float:
        """按异常严重度与 overlay 大小计算风险分。"""
        score = 0.0
        weight = {Severity.LOW: 10, Severity.MEDIUM: 25,
                  Severity.HIGH: 40, Severity.CRITICAL: 60}
        for anomaly in result.anomalies:
            score += weight.get(anomaly.severity, 0)
        if result.overlay_size > 1024:
            score += min(20, result.overlay_size // 1024)
        return round(score, 1)

    def _generate_recommendation(self, result: RepackResult) -> str:
        """生成处置建议。"""
        if not result.is_repacked:
            return '文件未被重打包，可判定为可信。'
        if result.repack_type == RepackType.INJECTED_CODE:
            return '检测到代码注入迹象，建议隔离分析。'
        return '检测到可疑载荷，建议进一步审查。'

    def generate_report(self, result: RepackResult, file_path: str) -> Dict:
        """生成报告字典。"""
        report = result.to_dict()
        report['file_path'] = file_path
        report['recommendation'] = self._generate_recommendation(result)
        return report

    def save_report(self, result: RepackResult, file_path: str) -> str:
        """将报告写入同名 .json 文件。"""
        report = self.generate_report(result, file_path)
        report_path = file_path + '.report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return report_path


def create_repack_detector(config: Optional[RepackConfig] = None) -> RepackDetector:
    """便捷入口: 创建重打包检测器。"""
    return RepackDetector(config)
