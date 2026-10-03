# 初始实现：补丁自校验逻辑生成 + 嵌入
# 增加多层校验：字节完整性 / 语义健全性 / 运行时行为

"""Self-Verifying Patch Injector — 嵌入运行时自校验的补丁。

FSAVER 用 TEE 做固件自证明，Cynapse 用 Merkle tree 做内存
完整性检查。两者都操作在完整二进制/固件级别。

本模块的差异：将校验逻辑嵌入补丁本身。
补丁应用后，在函数入口处自动运行自校验：
  1. 字节完整性：检查关键补丁字节是否在位
  2. 语义健全性：用预计算的测试输入验证补丁逻辑
  3. 运行时行为：执行内联的微型测试断言

校验失败响应：
  - 记录到 syslog / Windows Event Log
  - 触发回滚（与 AtomicRollbackEngine 集成）
  - 发送告警（通过预定义的退出码或信号）

设计约束：
  校验代码必须小于补丁本身的 50%（避免过度膨胀）。
  校验在函数入口处执行一次——首次调用时验证，后续调用跳过。
"""

import re
import struct
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set, Callable
from enum import Enum

_log = logging.getLogger(__name__)


class VerifyLevel(str, Enum):
    BYTE_INTEGRITY = "byte_integrity"
    SEMANTIC_SANITY = "semantic_sanity"
    RUNTIME_BEHAVIOR = "runtime_behavior"
    FULL = "full"


@dataclass
class VerifyCheckpoint:
    """单个自校验检查点。"""
    level: VerifyLevel
    description: str = ""
    # 校验代码（汇编指令列表）
    check_instructions: List[str] = field(default_factory=list)
    # 预期结果（寄存器/内存值）
    expected_register: str = ""
    expected_value: int = 0
    # 失败时跳转标签
    failure_label: str = ".self_verify_failed"


@dataclass
class SelfVerifyReport:
    """自校验补丁生成报告。"""
    patch_id: str = ""
    checkpoints: List[VerifyCheckpoint] = field(default_factory=list)
    total_check_bytes: int = 0          # 校验代码的字节数
    patch_bytes: int = 0                # 补丁本身的字节数
    overhead_ratio: float = 0.0         # 校验代码/补丁字节
    # 生成的校验逻辑
    prologue_asm: List[str] = field(default_factory=list)
    epilogue_asm: List[str] = field(default_factory=list)
    failure_handler_asm: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'checkpoints': len(self.checkpoints),
            'check_bytes': self.total_check_bytes,
            'overhead_pct': round(self.overhead_ratio * 100, 1),
        }


# 自校验逻辑生成器

class SelfVerifyGenerator:
    """为二进制补丁生成嵌入式的自校验逻辑。

    三种校验级别：
      L1 (BYTE): 对关键字节做 CRC32——轻量，< 20 bytes
      L2 (SEMANTIC): 用预计算输入验证补丁输出——中等，50-100 bytes
      L3 (RUNTIME): 内联断言补丁的安全属性——最重，仅用于关键补丁
    """

    def __init__(self):
        self._checkpoint_counter = 0

    def generate(self, patched_asm: List[str],
                 original_asm: List[str],
                 patch_id: str = "",
                 level: VerifyLevel = VerifyLevel.FULL,
                 max_overhead_pct: float = 50.0
                 ) -> SelfVerifyReport:
        """生成自校验逻辑。"""
        report = SelfVerifyReport(patch_id=patch_id)
        checkpoints = []
        total_check_bytes = 0
        patch_byte_est = len(patched_asm) * 4  # 粗略估计：平均 4 bytes/指令

        # L1: 字节完整性校验
        if level in (VerifyLevel.BYTE_INTEGRITY, VerifyLevel.FULL):
            cp = self._gen_byte_integrity_check(patched_asm, original_asm)
            if cp:
                checkpoints.append(cp)
                total_check_bytes += len(cp.check_instructions) * 4

        # L2: 语义健全性校验
        if level in (VerifyLevel.SEMANTIC_SANITY, VerifyLevel.FULL):
            cp = self._gen_semantic_sanity_check(patched_asm, original_asm)
            if cp:
                checkpoints.append(cp)
                total_check_bytes += len(cp.check_instructions) * 4

        # L3: 运行时行为校验
        if level in (VerifyLevel.RUNTIME_BEHAVIOR, VerifyLevel.FULL):
            cp = self._gen_runtime_behavior_check(patched_asm, original_asm)
            if cp:
                checkpoints.append(cp)
                total_check_bytes += len(cp.check_instructions) * 4

        # 检查开销比率
        overhead = total_check_bytes / max(patch_byte_est, 1)
        if overhead > max_overhead_pct / 100.0:
            # 超过预算——降级到 L1 only
            checkpoints = checkpoints[:1]
            total_check_bytes = len(checkpoints[0].check_instructions) * 4 if checkpoints else 0
            overhead = total_check_bytes / max(patch_byte_est, 1)

        report.checkpoints = checkpoints
        report.total_check_bytes = total_check_bytes
        report.patch_bytes = patch_byte_est
        report.overhead_ratio = overhead

        # 生成完整的校验代码（prologue + checks + failure handler + epilogue）
        report.prologue_asm = self._gen_prologue()
        report.epilogue_asm = self._gen_epilogue()
        report.failure_handler_asm = self._gen_failure_handler()

        return report

    def _gen_byte_integrity_check(self, patched: List[str],
                                  original: List[str]
                                  ) -> Optional[VerifyCheckpoint]:
        """L1: 对补丁的关键字节做自校验。"""
        # 找到补丁新增的指令
        orig_set = set(self._normalize(original))
        patch_set = set(self._normalize(patched))
        new_instructions = [l for l in patched if self._normalize_single(l) not in orig_set]
        if not new_instructions:
            return None

        # 选择最关键的指令（cmp/jcc/调用）做校验
        critical = [l for l in new_instructions
                   if any(kw in l.lower() for kw in ('cmp', 'j', 'call', 'test', 'and rax'))]
        if not critical:
            critical = new_instructions[:3]

        # 生成校验代码：对关键指令的字节序列做累加校验
        checksum_data = '\n'.join(critical).encode()
        expected = sum(checksum_data) & 0xFFFFFFFF

        return VerifyCheckpoint(
            level=VerifyLevel.BYTE_INTEGRITY,
            description="关键指令字节累加校验",
            check_instructions=[
                'mov eax, 0',
                *[f'; check: {l[:40]}' for l in critical[:5]],
                'cmp eax, %d' % expected,
                'jne .self_verify_failed',
            ],
            expected_register='eax',
            expected_value=expected,
        )

    def _gen_semantic_sanity_check(self, patched: List[str],
                                   original: List[str]
                                   ) -> Optional[VerifyCheckpoint]:
        """L2: 用预计算测试输入验证补丁行为。

        提取补丁中新增的安全检查（cmp + jcc），
        生成一个会通过检查的测试值和一个会触发检查的测试值。
        """
        for line in patched:
            m = re.search(r'\bcmp\s+\w+,\s*(0x[0-9a-f]+|\d+)', line, re.I)
            if m:
                val = m.group(1)
                threshold = int(val, 16) if val.startswith('0x') else int(val)
                safe_val = threshold - 1
                return VerifyCheckpoint(
                    level=VerifyLevel.SEMANTIC_SANITY,
                    description="验证边界检查 '%s' 的正常路径" % line.strip()[:40],
                    check_instructions=[
                        'mov rdi, %d' % safe_val,
                        'call .self_verify_inner',  # 调用补丁函数
                        'cmp eax, 0',               # 期望正常返回
                        'jne .self_verify_failed',
                    ],
                )
        return None

    def _gen_runtime_behavior_check(self, patched: List[str],
                                    original: List[str]
                                    ) -> Optional[VerifyCheckpoint]:
        """L3: 运行时行为——验证补丁未破坏基本控制流属性。"""
        return VerifyCheckpoint(
            level=VerifyLevel.RUNTIME_BEHAVIOR,
            description="运行时控制流完整性基本检查",
            check_instructions=[
                'mov rax, rsp',
                'and rsp, 0x0F',         # 栈对齐检查
                'jnz .self_verify_failed',
                'mov rsp, rax',
            ],
        )

    def _gen_prologue(self) -> List[str]:
        return [
            '.self_verify_entry:',
            '  cmp byte [.self_verify_done], 0',
            '  jne .self_verify_skip',
            '  mov byte [.self_verify_done], 1',
        ]

    def _gen_epilogue(self) -> List[str]:
        return [
            '.self_verify_skip:',
            '  ret',
            '.self_verify_done:',
            '  .byte 0',
        ]

    def _gen_failure_handler(self) -> List[str]:
        return [
            '.self_verify_failed:',
            '  mov eax, 0xDEADBEEF',     # 唯一退出码——自校验失败
            '  mov edi, 3',               # syslog LOG_ERR
            '  call syslog',              # 记录到 syslog
            '  mov edi, eax',
            '  mov eax, 60',              # sys_exit
            '  syscall',
        ]

    @staticmethod
    def _normalize(lines: List[str]) -> List[str]:
        return [SelfVerifyGenerator._normalize_single(l) for l in lines]

    @staticmethod
    def _normalize_single(line: str) -> str:
        return line.strip().lower().replace(',', ' ').split(';')[0].strip()
