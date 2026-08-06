# 修改记录:
# 2025-09-12 13:40 — 初始实现：网络协议变更检测 + 消息格式分析
# 2025-09-13 10:15 — 增加状态机变更推断（send/recv 调用的时序变化）

"""Patch Protocol Delta Analyzer — 补丁对网络协议行为的影响分析。

对于网络服务 binary（nginx, OpenSSH, DNS server 等），补丁可能改变
网络协议行为——消息格式、状态机转换、错误处理路径。

检测维度：
  1. send/write 调用的数据格式变更：补丁是否改变了发送数据的结构
  2. recv/read 解析逻辑变更：补丁是否改变了输入解析方式
  3. 状态机转换变更：新增/移除的状态转换路径
  4. 错误码变更：补丁是否新增了不同的错误响应

本模块将补丁前后的网络 I/O 操作序列抽象为协议状态机，
比较两状态机的差异，输出协议变更报告。
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum

_log = logging.getLogger(__name__)


class ProtoChangeType(str, Enum):
    FORMAT_CHANGE = "format_change"       # 消息格式变更
    PARSE_CHANGE = "parse_change"         # 解析逻辑变更
    STATE_CHANGE = "state_change"         # 状态机变更
    ERROR_CHANGE = "error_change"         # 错误处理变更
    TIMING_CHANGE = "timing_change"       # 超时/时序变更


@dataclass
class ProtoDelta:
    """单条协议变更。"""
    change_type: ProtoChangeType
    description: str = ""
    # 关联代码
    original_code: List[str] = field(default_factory=list)
    patched_code: List[str] = field(default_factory=list)
    # 影响评估
    backward_compatible: bool = True  # 是否向后兼容
    security_impact: str = ""


@dataclass
class ProtoDeltaReport:
    """协议变更分析报告。"""
    patch_id: str = ""
    binary_name: str = ""
    deltas: List[ProtoDelta] = field(default_factory=list)
    # 统计
    format_changes: int = 0
    parse_changes: int = 0
    state_changes: int = 0
    # 判定
    backward_compatible: bool = True
    protocol_version_change: str = "none"  # none | minor | major
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'patch_id': self.patch_id,
            'binary': self.binary_name,
            'backward_compat': self.backward_compatible,
            'version_change': self.protocol_version_change,
            'format': self.format_changes,
            'parse': self.parse_changes,
            'state': self.state_changes,
            'recommendation': self.recommendation,
        }


# ── 网络操作模式库 ────────────────────────────────────────────────

# 发送操作
_SEND_PATTERNS = re.compile(
    r'\bcall\s+.*\b(send|sendto|sendmsg|write|writev|'
    r'SSL_write|fprintf.*socket|puts)\b', re.I)

# 接收操作
_RECV_PATTERNS = re.compile(
    r'\bcall\s+.*\b(recv|recvfrom|recvmsg|read|readv|'
    r'SSL_read|fgets|scanf|getc)\b', re.I)

# 连接操作
_CONNECT_PATTERNS = re.compile(
    r'\bcall\s+.*\b(connect|accept|accept4|listen|bind|'
    r'socket|close|shutdown)\b', re.I)

# 缓冲区操作（send/recv 前后的数据处理）
_BUFFER_PATTERNS = re.compile(
    r'\bcall\s+.*\b(memcpy|memmove|sprintf|snprintf|strncpy|'
    r'htonl|htons|ntohl|ntohs|memset)\b', re.I)

# 协议状态相关
_STATE_PATTERNS = re.compile(
    r'\bcall\s+.*\b(select|poll|epoll_wait|sleep|usleep|'
    r'nanosleep|alarm|setitimer)\b', re.I)


# ── 协议 Delta 提取器 ─────────────────────────────────────────────

class ProtoDeltaExtractor:
    """从补丁汇编中提取协议级别的变更。"""

    def extract(self, original_asm: List[str],
                patched_asm: List[str]) -> List[ProtoDelta]:
        """提取协议变更列表。"""
        deltas = []

        # 1. 消息格式变更
        delta = self._check_format_change(original_asm, patched_asm)
        if delta:
            deltas.append(delta)

        # 2. 解析逻辑变更
        delta = self._check_parse_change(original_asm, patched_asm)
        if delta:
            deltas.append(delta)

        # 3. 状态机变更
        delta = self._check_state_change(original_asm, patched_asm)
        if delta:
            deltas.append(delta)

        # 4. 错误处理变更
        delta = self._check_error_change(original_asm, patched_asm)
        if delta:
            deltas.append(delta)

        return deltas

    def _check_format_change(self, orig: List[str], patched: List[str]
                             ) -> Optional[ProtoDelta]:
        """检测 send 相关操作的数据格式变更。"""
        orig_sends = self._find_io_ops(orig, _SEND_PATTERNS)
        patch_sends = self._find_io_ops(patched, _SEND_PATTERNS)
        if len(patch_sends) != len(orig_sends):
            return ProtoDelta(
                change_type=ProtoChangeType.FORMAT_CHANGE,
                description="发送操作数量变更: %d → %d" % (len(orig_sends), len(patch_sends)),
                backward_compatible=len(patch_sends) >= len(orig_sends),
                security_impact="新增的发送路径可能泄漏信息或改变协议行为")
        # 检查 send 前缓冲区构造的变化
        orig_bufs = self._find_io_ops(orig, _BUFFER_PATTERNS)
        patch_bufs = self._find_io_ops(patched, _BUFFER_PATTERNS)
        if len(patch_bufs) != len(orig_bufs):
            return ProtoDelta(
                change_type=ProtoChangeType.FORMAT_CHANGE,
                description="发送缓冲区构造逻辑变更: %d → %d 缓冲区操作" % (
                    len(orig_bufs), len(patch_bufs)),
                backward_compatible=True,
                security_impact="缓冲区构造变更可能影响消息格式但通常保持兼容")
        return None

    def _check_parse_change(self, orig: List[str], patched: List[str]
                            ) -> Optional[ProtoDelta]:
        """检测接收/解析逻辑变更。"""
        orig_recvs = self._find_io_ops(orig, _RECV_PATTERNS)
        patch_recvs = self._find_io_ops(patched, _RECV_PATTERNS)
        if len(patch_recvs) != len(orig_recvs):
            return ProtoDelta(
                change_type=ProtoChangeType.PARSE_CHANGE,
                description="接收/解析操作变更: %d → %d" % (len(orig_recvs), len(patch_recvs)),
                backward_compatible=len(patch_recvs) <= len(orig_recvs),
                security_impact="解析逻辑收紧（减少recv）通常是安全改进")
        return None

    def _check_state_change(self, orig: List[str], patched: List[str]
                            ) -> Optional[ProtoDelta]:
        """检测状态机转换变更。"""
        orig_states = self._find_io_ops(orig, _STATE_PATTERNS)
        patch_states = self._find_io_ops(patched, _STATE_PATTERNS)
        if len(patch_states) != len(orig_states):
            return ProtoDelta(
                change_type=ProtoChangeType.STATE_CHANGE,
                description="状态相关操作变更: %d → %d" % (len(orig_states), len(patch_states)),
                backward_compatible=True,
                security_impact="超时/状态机变更可能影响协议交互时序")
        return None

    def _check_error_change(self, orig: List[str], patched: List[str]
                            ) -> Optional[ProtoDelta]:
        """检测错误处理路径变更。"""
        orig_err = self._count_error_paths(orig)
        patch_err = self._count_error_paths(patched)
        if orig_err != patch_err:
            return ProtoDelta(
                change_type=ProtoChangeType.ERROR_CHANGE,
                description="错误处理路径变更: %d → %d" % (orig_err, patch_err),
                backward_compatible=patch_err >= orig_err,
                security_impact="新增错误处理通常提高安全性但可能改变协议错误响应")
        return None

    @staticmethod
    def _find_io_ops(asm: List[str], pattern: re.Pattern) -> List[int]:
        """返回匹配行的索引。"""
        return [i for i, line in enumerate(asm) if pattern.search(line)]

    @staticmethod
    def _count_error_paths(asm: List[str]) -> int:
        """统计错误处理路径数。"""
        return sum(1 for line in asm
                  if re.search(r'\b(ret|jmp)\b.*\b-?\d+\b', line, re.I)
                  or re.search(r'\bcall\s+(abort|exit|err|__assert)\b', line, re.I))


# ── 协议分析器 ────────────────────────────────────────────────────

class ProtocolDeltaAnalyzer:
    """补丁协议变更分析引擎。"""

    def __init__(self):
        self._extractor = ProtoDeltaExtractor()

    def analyze(self, original_asm: List[str],
                patched_asm: List[str],
                patch_id: str = "",
                binary_name: str = "") -> ProtoDeltaReport:
        """分析补丁的协议变更。"""
        report = ProtoDeltaReport(patch_id=patch_id, binary_name=binary_name)
        report.deltas = self._extractor.extract(original_asm, patched_asm)

        report.format_changes = sum(1 for d in report.deltas
                                    if d.change_type == ProtoChangeType.FORMAT_CHANGE)
        report.parse_changes = sum(1 for d in report.deltas
                                   if d.change_type == ProtoChangeType.PARSE_CHANGE)
        report.state_changes = sum(1 for d in report.deltas
                                   if d.change_type == ProtoChangeType.STATE_CHANGE)

        report.backward_compatible = all(
            d.backward_compatible for d in report.deltas)

        # 版本变更建议
        if report.format_changes > 0 and not report.backward_compatible:
            report.protocol_version_change = "major"
            report.recommendation = "协议格式不兼容变更——需要 MAJOR 版本号递增"
        elif report.format_changes > 0 or report.parse_changes > 0:
            report.protocol_version_change = "minor"
            report.recommendation = "协议向后兼容变更——MINOR 版本号递增即可"
        elif report.state_changes > 0:
            report.protocol_version_change = "minor"
            report.recommendation = "协议状态机微调——建议 MINOR 版本递增"
        else:
            report.recommendation = "未检测到协议级变更"

        return report
