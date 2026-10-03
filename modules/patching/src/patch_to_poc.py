# 初始实现：补丁反向推导漏洞触发条件 + PoC 输入合成
# 增加边界值外推：从补丁的 cmp 阈值推导触发范围

"""Patch-to-PoC Generator — 从二进制补丁反向生成漏洞验证代码。

TransferFuzz 从历史执行迹移植 fuzzing 种子到新 binary。
AI-SSD 用 LLM 生成 PoC。本模块的差异：
  不依赖 LLM，不依赖历史执行迹——直接从补丁的汇编变更推导漏洞触发条件。

方法：
  1. 分析补丁添加的安全检查（cmp N, jcc）
  2. 反向推导：什么样的输入会触发被检查的漏洞路径
  3. 对边界检查 (cmp size, N)：构造 size ≥ N 的输入
  4. 对 NULL 检查 (test ptr, ptr; jz)：构造空指针输入
  5. 对输入净化 (and mask)：构造含被过滤字符的输入
  6. 合成 PoC 输入并验证（在 original binary 上应 crash）

推导规则（示例）：
  patch: cmp rdi, 256; jbe .ok; call abort
  → 漏洞触发条件: rdi ≥ 256
  → 若 rdi = 输入长度 → PoC 输入长度 ≥ 256
  → 若 rdi = 指向输入的指针 → PoC 输入前 8 bytes = 0x0000000000000100 (256)

与 adversarial_bypass_finder 的差异：
  bypass_finder 搜索绕过补丁的输入（patch 后仍 crash）。
  本模块搜索触发原始漏洞的输入（patch 前 crash）。
  方向相反——bypass 测试补丁强度，PoC 证明漏洞存在。
"""

import re
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class PoCStrategy(str, Enum):
    SIZE_EXCEED = "size_exceed"         # 超出边界检查的大小
    NULL_POINTER = "null_pointer"       # 空指针触发
    FORMAT_STRING = "format_string"     # 格式字符串攻击
    SPECIAL_CHARS = "special_chars"     # 含被过滤的特殊字符
    INTEGER_OVERFLOW = "integer_overflow"  # 触发整数溢出
    UNKNOWN = "unknown"


@dataclass
class VulnTrigger:
    """从补丁推导出的漏洞触发条件。"""
    strategy: PoCStrategy
    description: str = ""
    # 触发参数
    trigger_value: int = 0             # 触发阈值
    trigger_register: str = ""         # 被检查的寄存器
    trigger_offset: int = 0            # 输入中的偏移位置
    # 生成的 PoC
    poc_input: bytes = b""
    poc_description: str = ""


@dataclass
class PoCReport:
    """PoC 生成报告。"""
    patch_id: str = ""
    triggers: List[VulnTrigger] = field(default_factory=list)
    total_pocs: int = 0
    # 验证结果（如在 original binary 上执行）
    verified_on_original: bool = False
    original_crash_signal: int = 0

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'pocs': self.total_pocs,
            'verified': self.verified_on_original,
            'triggers': [
                {'strategy': t.strategy.value, 'desc': t.poc_description,
                 'poc_hex': t.poc_input[:32].hex()}
                for t in self.triggers[:5]
            ],
        }


# 漏洞触发推导器

class VulnTriggerDeriver:
    """从补丁汇编变更推导漏洞触发条件。"""

    def derive(self, original_asm: List[str],
               patched_asm: List[str]) -> List[VulnTrigger]:
        """主推导入口。"""
        triggers = []
        orig_set = set(self._norm(original_asm))
        patch_set = set(self._norm(patched_asm))
        added = patch_set - orig_set
        removed = orig_set - patch_set

        # 规则 1: 边界检查 → SIZE_EXCEED
        triggers.extend(self._derive_size_exceed(added))

        # 规则 2: NULL 检查 → NULL_POINTER
        triggers.extend(self._derive_null_pointer(added))

        # 规则 3: 格式字符串 → FORMAT_STRING
        triggers.extend(self._derive_format_string(added, removed))

        # 规则 4: 输入净化 → SPECIAL_CHARS
        triggers.extend(self._derive_special_chars(added))

        # 规则 5: 整数溢出 → INTEGER_OVERFLOW
        triggers.extend(self._derive_integer_overflow(added))

        return triggers

    def _derive_size_exceed(self, added: Set[str]) -> List[VulnTrigger]:
        """从 cmp + jbe/ja 推导大小触发条件。"""
        triggers = []
        for inst in added:
            m = re.search(r'\bcmp\s+(\w+),?\s*(0x[0-9a-f]+|\d+)', inst, re.I)
            if not m:
                continue
            reg = m.group(1)
            val_str = m.group(2)
            threshold = int(val_str, 16) if val_str.startswith('0x') else int(val_str)

            # 查找对应的条件跳转
            jcc_found = any('jbe' in a or 'jb' in a or 'ja' in a or 'jae' in a
                          for a in added)

            if jcc_found:
                triggers.append(VulnTrigger(
                    strategy=PoCStrategy.SIZE_EXCEED,
                    description="边界检查: cmp %s, %d → 输入 ≥ %d 触发溢出" % (
                        reg, threshold, threshold),
                    trigger_value=threshold,
                    trigger_register=reg,
                    poc_input=b'A' * threshold,
                    poc_description="发送 %d bytes 的输入以触发原始缓冲区溢出" % threshold,
                ))
        return triggers

    def _derive_null_pointer(self, added: Set[str]) -> List[VulnTrigger]:
        """从 test + jz 推导 NULL 指针触发。"""
        triggers = []
        for inst in added:
            m = re.search(r'\btest\s+(\w+),?\s+(\w+)\b', inst, re.I)
            if m and m.group(1) == m.group(2):
                # test reg, reg; jz → NULL pointer check
                has_jz = any('jz' in a or 'je' in a for a in added)
                if has_jz:
                    triggers.append(VulnTrigger(
                        strategy=PoCStrategy.NULL_POINTER,
                        description="NULL 检查被添加——原始代码缺少空指针验证",
                        trigger_value=0,
                        poc_input=b'\x00' * 8,
                        poc_description="发送 NULL/零值指针以触发空指针解引用",
                    ))
        return triggers

    def _derive_format_string(self, added: Set[str],
                              removed: Set[str]) -> List[VulnTrigger]:
        """从 printf 修复推导格式字符串漏洞。"""
        triggers = []
        for inst in removed:
            if re.search(r'\bcall\s+printf\b', inst, re.I):
                # 检查补丁是否添加了格式字符串参数
                has_fix = any('"%s"' in a or '"%d"' in a or 'rax, rdi' in a
                            for a in added)
                if has_fix:
                    triggers.append(VulnTrigger(
                        strategy=PoCStrategy.FORMAT_STRING,
                        description="printf 格式字符串修复被添加",
                        poc_input=b'%x%x%x%x%x%x%x%n',
                        poc_description="发送格式字符串以泄漏栈内容或写入任意地址",
                    ))
        return triggers

    def _derive_special_chars(self, added: Set[str]) -> List[VulnTrigger]:
        """从 and/or 掩码推导被过滤的字符。"""
        triggers = []
        for inst in added:
            m = re.search(r'\band\s+\w+,\s*~(0x[0-9a-f]+)', inst, re.I)
            if m:
                mask = int(m.group(1), 16)
                # 推导被过滤的字符
                filtered = []
                for c in range(256):
                    if c & mask:
                        filtered.append(c)
                if filtered:
                    sample = bytes(filtered[:8])
                    triggers.append(VulnTrigger(
                        strategy=PoCStrategy.SPECIAL_CHARS,
                        description="输入净化掩码 ~0x%x——过滤了 %d 个字符" % (
                            mask, len(filtered)),
                        poc_input=sample,
                        poc_description="发送含被过滤字符的输入以触发命令注入/XSS",
                    ))
        return triggers

    def _derive_integer_overflow(self, added: Set[str]) -> List[VulnTrigger]:
        """从 jo/jno 检测整数溢出修复。"""
        triggers = []
        for inst in added:
            if re.search(r'\bjo\b', inst, re.I):
                triggers.append(VulnTrigger(
                    strategy=PoCStrategy.INTEGER_OVERFLOW,
                    description="溢出检查 (jo) 被添加——原始代码存在整数溢出",
                    trigger_value=0x7FFFFFFF,
                    poc_input=struct.pack('<Q', 0x7FFFFFFF),
                    poc_description="发送接近 INT_MAX 的值以触发整数溢出",
                ))
        return triggers

    @staticmethod
    def _norm(lines: List[str]) -> List[str]:
        return [l.strip().lower().replace(',', ' ').split(';')[0].strip()
                for l in lines if l.strip()]


# PoC 合成器

class PoCGenerator:
    """从触发条件合成可执行的 PoC 输入。

    用法:
        gen = PoCGenerator()
        report = gen.generate
        for t in report.triggers:
            print(f'PoC: {t.poc_description} → {t.poc_input[:32].hex()}')
    """

    def __init__(self):
        self._deriver = VulnTriggerDeriver()

    def generate(self, original_asm: List[str],
                 patched_asm: List[str],
                 patch_id: str = "") -> PoCReport:
        """从补丁生成 PoC。"""
        report = PoCReport(patch_id=patch_id)
        triggers = self._deriver.derive(original_asm, patched_asm)
        report.triggers = triggers
        report.total_pocs = len(triggers)

        # 合成复合 PoC（合并多个触发条件）
        if len(triggers) >= 2:
            combined = self._combine_pocs(triggers)
            if combined:
                triggers.append(combined)
                report.total_pocs += 1

        return report

    def _combine_pocs(self, triggers: List[VulnTrigger]) -> Optional[VulnTrigger]:
        """将多个触发条件合并为一个复合 PoC。"""
        size_trig = next((t for t in triggers
                        if t.strategy == PoCStrategy.SIZE_EXCEED), None)
        char_trig = next((t for t in triggers
                        if t.strategy == PoCStrategy.SPECIAL_CHARS), None)
        if size_trig and char_trig:
            # 超长 + 特殊字符 = 复合攻击
            combined_input = char_trig.poc_input * (
                (size_trig.trigger_value // max(len(char_trig.poc_input), 1)) + 1)
            return VulnTrigger(
                strategy=PoCStrategy.SIZE_EXCEED,
                description="复合 PoC: 超长输入 + 特殊字符",
                trigger_value=size_trig.trigger_value,
                poc_input=combined_input[:size_trig.trigger_value],
                poc_description="结合了大小超出和特殊字符过滤的复合攻击向量",
            )
        return None
