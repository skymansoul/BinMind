"""隐写与隐藏数据检测 —— 字节级魔数/熵扫描。

对外暴露 SteganoDetector 检测器与 HiddenDataType / DetectionConfidence
枚举。内嵌归档通过魔数匹配识别，高熵区域通过滑动窗口熵判定。
"""

import math
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class HiddenDataType(Enum):
    """隐藏数据类型分类。"""
    ZIP_EMBEDDED = "zip_embedded"
    HIGH_ENTROPY = "high_entropy"
    OVERLAY = "overlay"
    EOF_GAP = "eof_gap"
    SECTION_GAP = "section_gap"
    UNKNOWN = "unknown"


class DetectionConfidence(Enum):
    """检测置信度分级。"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class HiddenDataResult:
    """单条隐藏数据检测结果。"""
    offset: int = 0
    magic: str = ""
    data_type: HiddenDataType = HiddenDataType.UNKNOWN
    confidence: DetectionConfidence = DetectionConfidence.LOW
    size: int = 0
    description: str = ""


@dataclass
class StegoScanResult:
    """单次文件扫描结果。"""
    file_path: str = ""
    is_suspicious: bool = False
    hidden_data: List[HiddenDataResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


_MAGIC_MAP = [
    (b'\x50\x4B\x03\x04', 'ZIP'),
    (b'\x50\x4B\x05\x06', 'ZIP'),
    (b'\x7F\x45\x4C\x46', 'ELF'),
    (b'\x4D\x5A', 'PE/EXE'),
    (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', 'PNG'),
    (b'\xFF\xD8\xFF', 'JPEG'),
    (b'\x47\x49\x46\x38', 'GIF'),
    (b'\x1F\x8B', 'GZIP'),
    (b'\xFD\x37\x7A\x58\x5A\x00', 'XZ'),
    (b'\x52\x61\x72\x21', 'RAR'),
    (b'\x25\x50\x44\x46', 'PDF'),
    (b'\x1F\x9D', 'COMPRESS'),
    (b'\x42\x5A\x68', 'BZ2'),
]


class SteganoDetector:
    """隐写检测器: 魔数匹配 + 熵分析。"""

    _WINDOW = 4096
    _HIGH_ENTROPY_THRESHOLD = 0.90

    def __init__(self, entropy_threshold: float = 0.8):
        self.entropy_threshold = entropy_threshold

    def calculate_entropy(self, data: bytes) -> float:
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

    def _detect_magic(self, data: bytes) -> Optional[str]:
        """按魔数识别文件格式。"""
        for magic, name in _MAGIC_MAP:
            if data.startswith(magic):
                return name
        return None

    def detect_embedded_archives(self, data: bytes) -> List[HiddenDataResult]:
        """扫描内嵌归档文件（排除偏移 0 的主格式）。"""
        results = []
        for magic, name in _MAGIC_MAP:
            start = 0
            while True:
                idx = data.find(magic, start)
                if idx < 0:
                    break
                if idx > 0:
                    results.append(HiddenDataResult(
                        offset=idx,
                        magic=name,
                        data_type=HiddenDataType.ZIP_EMBEDDED if name == 'ZIP' else HiddenDataType.UNKNOWN,
                        confidence=DetectionConfidence.MEDIUM,
                        size=len(magic),
                        description=f'内嵌 {name} 魔数 @ 0x{idx:x}',
                    ))
                start = idx + 1
        return results

    def detect_high_entropy_regions(self, data: bytes) -> List[HiddenDataResult]:
        """按滑动窗口检测高熵区域。"""
        results = []
        step = self._WINDOW // 4
        idx = 0
        while idx < len(data):
            window = data[idx:idx + self._WINDOW]
            if len(window) >= self._WINDOW:
                entropy = self.calculate_entropy(window)
                if entropy > self._HIGH_ENTROPY_THRESHOLD:
                    results.append(HiddenDataResult(
                        offset=idx,
                        magic='',
                        data_type=HiddenDataType.HIGH_ENTROPY,
                        confidence=DetectionConfidence.HIGH,
                        size=len(window),
                        description=f'高熵区域 @ 0x{idx:x} (熵 {entropy:.3f})',
                    ))
            idx += step
        return results

    def scan_file(self, path: str) -> StegoScanResult:
        """扫描文件，汇总隐藏数据线索。"""
        result = StegoScanResult(file_path=path)
        try:
            with open(path, 'rb') as f:
                data = f.read()
        except OSError:
            result.notes.append('文件读取失败')
            return result

        result.hidden_data.extend(self.detect_embedded_archives(data))
        result.hidden_data.extend(self.detect_high_entropy_regions(data))
        result.is_suspicious = len(result.hidden_data) > 0
        if result.is_suspicious:
            result.notes.append(f'发现 {len(result.hidden_data)} 处可疑数据')
        return result

    def generate_report(self, result: StegoScanResult) -> str:
        """生成隐写检测报告文本。"""
        lines = [f'隐写检测报告: {result.file_path}']
        lines.append(f'可疑: {"是" if result.is_suspicious else "否"}')
        for item in result.hidden_data:
            lines.append(
                f'- @0x{item.offset:x} {item.magic or item.data_type.value} '
                f'({item.confidence.value})'
            )
        for note in result.notes:
            lines.append(f'  {note}')
        return '\n'.join(lines)


def scan_steganography(path: str) -> StegoScanResult:
    """便捷入口: 扫描文件中的隐藏数据。"""
    return SteganoDetector().scan_file(path)


def extract_hidden_data(result: StegoScanResult) -> List[dict]:
    """将检测结果导出为可序列化结构。"""
    return [
        {
            'offset': item.offset,
            'magic': item.magic,
            'data_type': item.data_type.value,
            'confidence': item.confidence.value,
            'size': item.size,
            'description': item.description,
        }
        for item in result.hidden_data
    ]
