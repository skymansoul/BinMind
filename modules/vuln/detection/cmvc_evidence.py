# coding: utf-8
"""
跨模态漏洞关联 - 多模态证据表示。

技术问题:
  现有漏洞检测管线产出多种模态的独立finding:
    - 静态分析: 'memcpy在0x401000处无边界检查'(score=0.8)
    - LLM分析: 'parse_packet函数疑似栈溢出'(score=0.75)
    - 模糊测试: '输入0x41414141在0x401000处崩溃'(score=N/A)
    - 动态沙箱: '执行流到达memcpy时len=1024>buf=256'(score=0.9)

  这些finding可能指向同一漏洞, 但来自不同模态的独立输出
  缺乏关联机制 - 安全分析师需手工判断"崩溃#1234是否验证了静态finding#567"。

解决方案:
  统一证据表示 - 抽象为(位置, 类型, 严重度, 模态, 置信度)五元组:
    - 位置归一化: 源码行号/二进制地址/函数名/调用栈帧的互映射
    - 类型归一化: 静态类型/CWE/崩溃信号/LLM分类的通用分类法
    - 证据强度: 各模态的置信度校准至统一[0, 1]标度

  归一化后的证据可在统一空间中做空间-语义联合相似度计算,
  支撑后续的因果关联推断。

与multimodal_vuln_fusion的差异:
  multimodal_vuln_fusion, 分数级融合(加权平均/sugeno/自适应)
  cmvc, 实例级关联(确认/争议/补充, finding间的推理关系)
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


# 模态与证据类型


class AnalysisModality(str, Enum):
    STATIC = "static_analysis"
    DYNAMIC = "dynamic_sandbox"
    LLM = "llm_semantic"
    FUZZING = "fuzzing_crash"
    SYMBEX = "symbolic_execution"
    MANUAL = "manual_audit"
    ASAN = "address_sanitizer"


class CorrelationRelation(str, Enum):
    CONFIRMS = "confirms"           # 证据B验证了证据A的漏洞存在
    DISPUTES = "disputes"           # 证据B与证据A矛盾(可能一者为误报)
    REFINES = "refines"             # 证据B细化了证据A的描述(如添加了溢出量)
    EXTENDS = "extends"             # 证据B扩展了证据A的影响范围
    DUPLICATE = "duplicate"         # 证据B是证据A的重复(同模态同位置)
    INDEPENDENT = "independent"     # 无关


# 归一化证据


@dataclass
class NormalizedEvidence:
    """归一化漏洞证据 - 统一不同模态finding的结构"""
    evidence_id: str
    modality: str                   # AnalysisModality值
    # 位置, 三要素至少一者非空
    function_name: str = ""
    file_path: str = ""
    line_number: int = 0
    binary_address: int = 0
    # 漏洞类型(归一化后)
    vuln_type: str = ""             # 统一类型: buffer_overflow|uaf|format_string|...
    cwe_id: str = ""
    # 严重度与置信度[0, 1]
    severity_score: float = 0.0
    confidence: float = 0.0
    # 证据细节
    description: str = ""
    crash_signal: int = 0
    overflow_size: int = 0
    # 来源溯源
    source_finding_id: str = ""
    source_module: str = ""
    # 元数据
    metadata: Dict = field(default_factory=dict)


@dataclass
class EvidencePair:
    """证据对 - 两条归一化证据及其关系"""
    evidence_a: NormalizedEvidence
    evidence_b: NormalizedEvidence
    relation: str = CorrelationRelation.INDEPENDENT
    # 关联强度
    spatial_similarity: float = 0.0     # 位置相似度[0, 1]
    semantic_similarity: float = 0.0    # 类型相似度[0, 1]
    correlation_score: float = 0.0      # 综合关联评分[0, 1]
    # 因果推断
    causal_direction: str = ""          # A到B | B到A | bidirectional | none
    confounding_risk: float = 0.0       # 混淆风险(第三方因素导致二者相关)
    # 推理链
    reasoning: str = ""


# 证据归一化器


class EvidenceNormalizer:
    """将各模态的原生finding归一化为统一的NormalizedEvidence。

    归一化规则 - 漏洞类型映射:
      静态分析memcpy无检查, buffer_overflow(CWE-787)
      LLM语义分析栈溢出,   buffer_overflow(CWE-787)
      模糊测试SIGSEGV,       取决于崩溃指令(memcpy, buffer_overflow)
      ASAN堆溢出,           heap_overflow(CWE-122)
      GDB崩溃分析,          取决于崩溃类型分类器(CSSA)

    位置归一化:
      二进制地址/函数名/源码行号互映射(通过调试符号/IDA/反汇编)
      无调试符号时回退至(二进制地址, 函数名)二元组匹配
    """

    # 模态到置信度校准因子(基于各模态的实证FP/FN率)
    _MODALITY_CALIBRATION = {
        AnalysisModality.ASAN: 0.95,
        AnalysisModality.DYNAMIC: 0.75,
        AnalysisModality.STATIC: 0.60,
        AnalysisModality.LLM: 0.55,
        AnalysisModality.FUZZING: 0.70,
        AnalysisModality.SYMBEX: 0.80,
        AnalysisModality.MANUAL: 0.90,
    }

    # 漏洞类型归一化映射表
    _TYPE_NORMALIZATION = {
        'stack_buffer_overflow': 'buffer_overflow',
        'heap_overflow': 'buffer_overflow',
        'buffer_overflow': 'buffer_overflow',
        'global_overflow': 'buffer_overflow',
        'memcpy_no_check': 'buffer_overflow',
        'strcpy_no_check': 'buffer_overflow',
        'use_after_free': 'use_after_free',
        'uaf': 'use_after_free',
        'double_free': 'double_free',
        'format_string': 'format_string',
        'printf_no_format': 'format_string',
        'integer_overflow': 'integer_overflow',
        'null_pointer_dereference': 'null_deref',
        'null_deref': 'null_deref',
        'wild_write': 'wild_write',
        'race_condition': 'race_condition',
    }

    def normalize(self, raw_finding: Dict,
                   modality: str,
                   finding_id: str = ""
                   ) -> NormalizedEvidence:
        """将原始finding归一化为统一证据表示。

        参数:
          raw_finding: 原始finding字典(各模态格式不同)
          modality: AnalysisModality值
          finding_id: 唯一标识符(可选)

        返回NormalizedEvidence。
        """
        # 类型归一化, 含崩溃信号推断
        raw_type = raw_finding.get('vuln_type', raw_finding.get('type', ''))
        norm_type = self._TYPE_NORMALIZATION.get(raw_type, '')
        if not norm_type:
            # 从崩溃信号推断漏洞类型 - SIGSEGV, 可能溢出; SIGABRT, 可能堆破坏
            sig = raw_finding.get('signal', raw_finding.get('crash_signal', 0))
            if sig == 11:
                norm_type = 'buffer_overflow'  # SIGSEGV, 最可能的类型
            elif sig == 6:
                norm_type = 'buffer_overflow'  # SIGABRT, asan常见
            elif sig in (4, 8):
                norm_type = 'buffer_overflow'
            else:
                norm_type = raw_finding.get('cwe_type', 'unknown')

        # 置信度校准
        raw_conf = raw_finding.get('confidence', raw_finding.get(
            'score', raw_finding.get('cvss_score', 0.5)))
        calibration = self._MODALITY_CALIBRATION.get(modality, 0.5)
        calibrated_conf = min(1.0, raw_conf * calibration)

        # 严重度
        severity = raw_finding.get('severity_score', raw_finding.get(
            'cvss', raw_finding.get('severity', 0.0)))
        if isinstance(severity, str):
            severity = {'CRITICAL': 0.95, 'HIGH': 0.75, 'MEDIUM': 0.5,
                        'LOW': 0.25, 'INFO': 0.1}.get(severity, 0.5)

        return NormalizedEvidence(
            evidence_id=finding_id or f"EVID_{modality}_{raw_finding.get('id', '?')}",
            modality=modality,
            function_name=raw_finding.get('function_name', raw_finding.get('function', '')),
            file_path=raw_finding.get('file_path', raw_finding.get('file', '')),
            line_number=raw_finding.get('line_number', raw_finding.get('line', 0)),
            binary_address=raw_finding.get('address', raw_finding.get('addr', 0)),
            vuln_type=norm_type,
            cwe_id=raw_finding.get('cwe_id', raw_finding.get('cwe', '')),
            severity_score=float(severity),
            confidence=round(calibrated_conf, 3),
            description=raw_finding.get('description', '')[:200],
            crash_signal=raw_finding.get('signal', raw_finding.get('crash_signal', 0)),
            overflow_size=raw_finding.get('overflow_size', 0),
            source_finding_id=raw_finding.get('id', ''),
            source_module=raw_finding.get('source', modality),
            metadata=raw_finding)


__all__ = [
    "AnalysisModality",
    "CorrelationRelation",
    "NormalizedEvidence",
    "EvidencePair",
    "EvidenceNormalizer",
]
