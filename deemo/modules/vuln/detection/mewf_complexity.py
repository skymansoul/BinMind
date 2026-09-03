# coding: utf-8
#
"""
多因子漏洞武器化预测-漏洞利用复杂度量化。

技术问题:
  CVSS/EPSS基于元数据预测利用概率，忽略漏洞本身的代码级特征。
  两个同为CVSS 8.0的漏洞-一个在memcpy(无边界检查)中，另一个在
  加密协议协商中-武器化难度相差数个量级。
  现有评分系统无法捕捉此差异。

解决方案:
  从漏洞代码特征量化利用复杂度-15维特征空间:
    1. 内存安全维度(5维): 溢出类型、可控字节数、目标缓冲区类型、对齐约束、写原语
    2. 控制流维度(4维): 寄存器可控性、返回地址偏移、栈canary可见性、间接调用目标
    3. 环境维度(3维): ASLR熵、NX/PIE存在性、沙箱/seccomp约束
    4. 可利用性维度(3维): 信息泄露可用性、堆风水难度、竞态窗口大小

  特征-复杂度映射: 加权线性模型×非线性激活
  complexity = sigmoid(Σ w_i × normalized_feature_i)

  权重来自CGC/CTF漏洞利用经验先验(可随更多数据贝叶斯更新)。

与AEAS的差异:
  AEAS评估已有exploit代码的成熟度-需exploit已存在
  本模块预测漏洞的武器化难度-exploit创建之前即可评分
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List
from enum import Enum

_log = logging.getLogger(__name__)


# 复杂度特征空间


class OverflowType(str, Enum):
    STACK = "stack"
    HEAP = "heap"
    GLOBAL = "global"
    INTEGER = "integer"
    FORMAT = "format_string"
    TYPE_CONFUSION = "type_confusion"
    NONE = "none"


class WritePrimitive(str, Enum):
    LINEAR = "linear_overflow"
    ARBITRARY_WRITE = "arbitrary_write"
    ARBITRARY_READ = "arbitrary_read"
    INCREMENT = "increment_only"
    CONTROLLED = "fully_controlled"
    NONE = "none"


@dataclass
class ExploitComplexity:
    """漏洞利用复杂度-多维度量化"""
    # 内存安全维度 [0,1] - 越高越难利用
    overflow_type_score: float = 0.5
    controllable_bytes: float = 0.5     # 可控字节数/需要字节数
    buffer_type_score: float = 0.5      # 栈(易)/堆(中)/全局(难)
    alignment_score: float = 0.0        # 对齐要求严格度
    write_primitive_score: float = 0.5  # 线性溢出不需精确写(高评分)

    # 控制流维度 [0,1]
    register_control: float = 0.5       # RIP可控性
    ret_offset_certainty: float = 0.5   # 返回地址偏移精确度
    canary_visible: float = 0.0         # 栈canary是否可通过信息泄露读取
    indirect_call_hijack: float = 0.5   # 间接调用劫持可行性

    # 环境维度 [0,1] - 越高防护越强
    aslr_entropy: float = 0.7           # ASLR熵(32位=0.3/64位=0.7)
    nx_enabled: float = 0.9             # NX位(启用=0.9)
    sandbox_constraint: float = 0.5     # seccomp/沙箱约束

    # 可利用性维度 [0,1]
    info_leak_available: float = 0.0    # 信息泄露是否已知
    heap_feng_shui_difficulty: float = 0.7  # 堆布局操纵难度
    race_window_size: float = 0.5       # 竞态窗口大小(越小越难)

    # 聚合复杂度
    overall_complexity: float = 0.0     # [0,1] - 1=极难利用
    complexity_tier: str = "MEDIUM"     # LOW/MEDIUM/HIGH/EXTREME


# 复杂度估计器


class ExploitComplexityEstimator:
    """漏洞利用复杂度量化-基于代码特征的加权评分。

    权重先验来源:
      CGC(Cyber Grand Challenge)统计: 栈溢出平均利用时间<2h,
      堆溢出6-24h, 类型混淆>48h。
      CTF writeup meta-analysis: 信息泄露将利用时间缩短约3x。

    贝叶斯更新:
      权重可作为Dirichlet先验，随新漏洞的利用成功/失败反馈
      逐步更新。初始权重用于冷启动-零样本漏洞也可评分。
    """

    # 维度权重-基于CGC/CTF经验先验
    _DIMENSION_WEIGHTS = {
        # 内存安全-单一维度最大权重(根因决定利用路径)
        'overflow_type': 0.22,
        'controllable_bytes': 0.08,
        'buffer_type': 0.06,
        'alignment': 0.04,
        'write_primitive': 0.10,
        # 控制流-ROP/JOP链复杂度
        'register_control': 0.08,
        'ret_offset': 0.05,
        'canary_visible': 0.07,
        'indirect_call': 0.04,
        # 环境-防护强度
        'aslr': 0.08,
        'nx': 0.04,
        'sandbox': 0.04,
        # 可利用性-辅助因素
        'info_leak': 0.06,
        'heap_feng_shui': 0.03,
        'race_window': 0.01,
    }

    def estimate(self, vuln_type: str = "",
                  overflow_size: int = 0,
                  protections: Dict[str, str] = None,
                  info_leak: bool = False,
                  stack_addr_leak: int = 0,
                  libc_base_leak: int = 0) -> ExploitComplexity:
        """从漏洞描述符估计利用复杂度。

        参数:
          vuln_type: buffer_overflow|use_after_free|format_string|...
          overflow_size: 溢出字节数(若为溢出类)
          protections: {NX, ASLR, PIE, CANARY, RELRO, SECCOMP}
          info_leak: 是否存在信息泄露
          stack_addr_leak: 栈地址泄露(0=无)
          libc_base_leak: libc基址泄露(0=无)

        返回ExploitComplexity。
        """
        ec = ExploitComplexity()
        prot = protections or {}

        # 内存安全维度
        ec.overflow_type_score = self._score_overflow_type(vuln_type)
        ec.controllable_bytes = self._score_controllable(overflow_size)
        ec.buffer_type_score = self._score_buffer_type(vuln_type)
        ec.alignment_score = 0.3 if 'x86_64' in str(protections) else 0.1
        ec.write_primitive_score = self._score_write_primitive(vuln_type)

        # 控制流维度
        ec.register_control = self._score_register_control(vuln_type)
        ec.ret_offset_certainty = 0.8 if vuln_type == 'stack_buffer_overflow' else 0.3
        ec.canary_visible = 1.0 if (info_leak and prot.get('CANARY', '') == 'yes') else 0.0
        ec.indirect_call_hijack = 0.5

        # 环境维度
        ec.aslr_entropy = self._score_aslr(prot)
        ec.nx_enabled = 0.9 if prot.get('NX', 'yes') == 'yes' else 0.1
        ec.sandbox_constraint = 0.8 if prot.get('SECCOMP', '') == 'strict' else 0.3

        # 可利用性维度
        ec.info_leak_available = 1.0 if (info_leak or stack_addr_leak or libc_base_leak) else 0.0
        ec.heap_feng_shui_difficulty = 0.9 if vuln_type == 'use_after_free' else 0.3
        ec.race_window_size = 0.9 if vuln_type == 'race_condition' else 0.3

        # 聚合复杂度-加权线性组合+非线性映射
        raw = (
            self._DIMENSION_WEIGHTS['overflow_type'] * ec.overflow_type_score +
            self._DIMENSION_WEIGHTS['controllable_bytes'] * (1.0 - ec.controllable_bytes) +
            self._DIMENSION_WEIGHTS['buffer_type'] * ec.buffer_type_score +
            self._DIMENSION_WEIGHTS['alignment'] * ec.alignment_score +
            self._DIMENSION_WEIGHTS['write_primitive'] * (1.0 - ec.write_primitive_score) +
            self._DIMENSION_WEIGHTS['register_control'] * (1.0 - ec.register_control) +
            self._DIMENSION_WEIGHTS['ret_offset'] * (1.0 - ec.ret_offset_certainty) +
            self._DIMENSION_WEIGHTS['canary_visible'] * (1.0 - ec.canary_visible) +
            self._DIMENSION_WEIGHTS['indirect_call'] * (1.0 - ec.indirect_call_hijack) +
            self._DIMENSION_WEIGHTS['aslr'] * ec.aslr_entropy +
            self._DIMENSION_WEIGHTS['nx'] * ec.nx_enabled +
            self._DIMENSION_WEIGHTS['sandbox'] * ec.sandbox_constraint +
            self._DIMENSION_WEIGHTS['info_leak'] * (1.0 - ec.info_leak_available) +
            self._DIMENSION_WEIGHTS['heap_feng_shui'] * ec.heap_feng_shui_difficulty +
            self._DIMENSION_WEIGHTS['race_window'] * ec.race_window_size
        )
        # sigmoid非线性-拉大中段差异
        centered = (raw - 0.5) * 4.0
        ec.overall_complexity = round(1.0 / (1.0 + math.exp(-centered)), 4)

        # 分级
        if ec.overall_complexity >= 0.80:
            ec.complexity_tier = "EXTREME"
        elif ec.overall_complexity >= 0.55:
            ec.complexity_tier = "HIGH"
        elif ec.overall_complexity >= 0.30:
            ec.complexity_tier = "MEDIUM"
        else:
            ec.complexity_tier = "LOW"

        return ec

    # 各维度评分方法
    def _score_overflow_type(self, vt: str) -> float:
        mapped = {
            'stack_buffer_overflow': 0.2, 'buffer_overflow': 0.3,
            'heap_overflow': 0.5, 'use_after_free': 0.7,
            'type_confusion': 0.8, 'integer_overflow': 0.6,
            'format_string': 0.4, 'race_condition': 0.7,
        }
        return mapped.get(vt, 0.5)

    def _score_controllable(self, size: int) -> float:
        if size <= 0:
            return 0.1
        if size <= 8:
            return 0.3
        if size <= 64:
            return 0.6
        if size <= 256:
            return 0.85
        return 0.95

    def _score_buffer_type(self, vt: str) -> float:
        if 'stack' in vt:
            return 0.2
        if 'heap' in vt:
            return 0.5
        if 'global' in vt:
            return 0.7
        return 0.5

    def _score_write_primitive(self, vt: str) -> float:
        if vt == 'format_string':
            return 0.8
        if 'overflow' in vt:
            return 0.5
        return 0.3

    def _score_register_control(self, vt: str) -> float:
        if 'overflow' in vt and 'stack' in vt:
            return 0.9
        return 0.4

    def _score_aslr(self, prot: Dict[str, str]) -> float:
        if prot.get('PIE', 'no') == 'yes':
            return 0.8
        if prot.get('ASLR', 'yes') == 'yes':
            return 0.6
        return 0.2


__all__ = [
    "OverflowType",
    "WritePrimitive",
    "ExploitComplexity",
    "ExploitComplexityEstimator",
]
