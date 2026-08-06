"""
数据质量评分器 (Data Quality Scorer, DQS)
------------------------------------------
对二进制分析输入数据做质量评估——识别损坏/截断/加壳/混淆
导致的低质量输入, 避免浪费分析资源.

设计依据:
  分析管线常遇到损坏的二进制 (下载不完整)、加壳样本 (无法静态分析)、
  或格式错误的输入. 对这类输入运行完整管线是资源浪费.
  DQS 在管线入口做快速质量评估, 低于阈值的输入标记为 "低质量"
  并跳过重分析阶段.
"""
import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class QualityReport:
    """数据质量报告."""
    is_usable: bool = True
    overall_score: float = 1.0   # 0-1
    dimensions: Dict[str, float] = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)


class DataQualityScorer:
    """数据质量快速评分器.

    用法:
      dqs = DataQualityScorer()
      report = dqs.assess(binary_data, file_type='elf')
      if not report.is_usable:
          logger.warning(f'Low quality input: {report.issues}')
    """

    def __init__(self, min_quality_score: float = 0.4):
        self._min_score = min_quality_score
        self._magic_bytes = {
            'elf': b'\x7FELF', 'pe': b'MZ', 'macho': b'\xFE\xED\xFA',
        }

    def assess(self, data: bytes, file_type: str = "",
               expected_size: int = 0) -> QualityReport:
        """评估二进制数据的质量."""
        dims = {}
        issues = []

        # 1. 完整性
        size_score = self._size_check(data, expected_size)
        dims['completeness'] = size_score
        if size_score < 0.5:
            issues.append(f'文件可能不完整 (size={len(data)}, expected={expected_size})')

        # 2. 格式有效性
        format_score = self._format_check(data, file_type)
        dims['format_validity'] = format_score
        if format_score < 0.5:
            issues.append(f'文件头格式不匹配 (expected={file_type})')

        # 3. 熵合理性: 极高熵=可能加密/损坏, 极低熵=可能全零填充
        entropy_score = self._entropy_check(data)
        dims['entropy_plausibility'] = entropy_score
        if entropy_score < 0.4:
            issues.append('熵值异常——可能全零填充或随机数据损坏')

        # 4. 可解析性: 是否有基本的段/节结构
        structure_score = self._structure_check(data, file_type)
        dims['structure'] = structure_score

        overall = sum(dims.values()) / max(1, len(dims))
        return QualityReport(
            is_usable=overall >= self._min_score,
            overall_score=round(overall, 3),
            dimensions={k: round(v, 3) for k, v in dims.items()},
            issues=issues,
        )

    def _size_check(self, data: bytes, expected: int) -> float:
        if expected <= 0:
            return 0.8 if len(data) > 64 else 0.3
        ratio = len(data) / max(1, expected)
        if 0.95 <= ratio <= 1.05:
            return 1.0
        if 0.8 <= ratio <= 1.2:
            return 0.7
        if ratio < 0.5:
            return 0.2
        return 0.5

    def _format_check(self, data: bytes, file_type: str) -> float:
        if not file_type:
            return 0.6
        magic = self._magic_bytes.get(file_type.lower())
        if magic is None:
            return 0.5
        return 1.0 if data[:len(magic)] == magic else 0.1

    def _entropy_check(self, data: bytes) -> float:
        if len(data) < 64:
            return 0.3
        freq = [0] * 256
        for b in data[:4096]:
            freq[b] += 1
        n = min(4096, len(data))
        ent = 0.0
        for f in freq:
            if f > 0:
                p = f / n
                ent -= p * math.log2(p)
        # 正常二进制: 4-7 bits/byte
        if 3.5 <= ent <= 7.5:
            return 1.0
        if 2.0 <= ent <= 3.5 or 7.5 <= ent <= 7.8:
            return 0.6
        return 0.2

    def _structure_check(self, data: bytes, file_type: str) -> float:
        """检查是否有基本的段表/导入表结构."""
        ft = file_type.lower()
        if ft == 'elf':
            # ELF: 检查 e_phoff 和 e_shoff 是否非零
            if len(data) >= 64:
                phoff = int.from_bytes(data[32:40], 'little')
                shoff = int.from_bytes(data[40:48], 'little')
                return 0.8 if (phoff > 0 or shoff > 0) else 0.3
        elif ft == 'pe':
            # PE: 检查 NT Header 偏移
            if len(data) >= 64:
                pe_offset = int.from_bytes(data[60:64], 'little')
                if 64 <= pe_offset < len(data) - 4:
                    sig = data[pe_offset:pe_offset+4]
                    return 1.0 if sig == b'PE\x00\x00' else 0.3
        return 0.5
