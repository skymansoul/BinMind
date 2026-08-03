# 2026-07-19
# 崩溃分类与可利用性评估 —— 微软.exploitable 方法论
# 设计思路：基于崩溃特征（寄存器状态、栈帧、异常码）打分判定可利用性
# 每条规则带 confidence，综合评估并给出缓解

import re
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Any

_log = logging.getLogger(__name__)


# ===== 枚举 =====

class CrashType(Enum):
    ACCESS_VIOLATION = auto()
    ILLEGAL_INSTRUCTION = auto()
    STACK_OVERFLOW = auto()
    HEAP_CORRUPTION = auto()
    DIVIDE_BY_ZERO = auto()
    PRIVILEGED_INSTRUCTION = auto()
    ASSERT_FAILURE = auto()
    UNKNOWN = auto()


class Exploitability(Enum):
    EXPLOITABLE = auto()
    PROBABLY_EXPLOITABLE = auto()
    PROBABLY_NOT_EXPLOITABLE = auto()
    NOT_EXPLOITABLE = auto()
    UNKNOWN = auto()


# ===== 数据类 =====

@dataclass
class CrashInfo:
    crash_type: CrashType = CrashType.UNKNOWN
    fault_address: int = 0
    crash_address: int = 0
    exception_code: int = 0
    register_context: Dict[str, int] = field(default_factory=dict)
    stack_trace: List[Dict[str, Any]] = field(default_factory=list)  # [{addr, module, symbol}]
    instruction_bytes: bytes = b""
    modules_loaded: List[str] = field(default_factory=list)
    thread_id: int = 0
    process_name: str = ""


# ===== 崩溃分类器 =====

class CrashClassifier:
    """
    基于.exploitable 规则的崩溃分类器
    每种崩溃类型对应一个可利用性评分和置信度
    """

    # ---- 主分类入口 ----
    def classify(self, crash_info: CrashInfo) -> Tuple[CrashType, Exploitability, float, str]:
        ct = crash_info.crash_type
        reasoning_parts: List[str] = []

        if ct == CrashType.ACCESS_VIOLATION:
            return self._classify_av(crash_info, reasoning_parts)
        elif ct == CrashType.ILLEGAL_INSTRUCTION:
            return self._classify_illegal(crash_info, reasoning_parts)
        elif ct == CrashType.STACK_OVERFLOW:
            return self._classify_stack_overflow(crash_info, reasoning_parts)
        elif ct == CrashType.HEAP_CORRUPTION:
            return self._classify_heap_corruption(crash_info, reasoning_parts)
        elif ct == CrashType.DIVIDE_BY_ZERO:
            reason = "除零错误通常不可直接利用，除非与信息泄露结合"
            return (ct, Exploitability.PROBABLY_NOT_EXPLOITABLE, 0.20, reason)
        elif ct == CrashType.PRIVILEGED_INSTRUCTION:
            reason = "用户态特权指令执行，可能由 ROP 或控制流劫持触发"
            return (ct, Exploitability.PROBABLY_EXPLOITABLE, 0.55, reason)
        elif ct == CrashType.ASSERT_FAILURE:
            reason = "断言失败一般是防御性检查触发，利用可能性极低"
            return (ct, Exploitability.NOT_EXPLOITABLE, 0.10, reason)
        else:
            return (ct, Exploitability.UNKNOWN, 0.50, "无法确定的崩溃类型")

    # ---- 访问违规分类 ----
    def _classify_av(self, ci: CrashInfo, parts: List[str]) -> Tuple[CrashType, Exploitability, float, str]:
        # 规则 1: crash_address == fault_address → 高度可疑
        if ci.crash_address and ci.fault_address and ci.crash_address == ci.fault_address:
            if self._check_controlled_eip(ci.register_context, ci.stack_trace):
                parts.append("EIP 被用户可控数据覆盖")
                return (ci.crash_type, Exploitability.EXPLOITABLE, 0.90, "; ".join(parts))
            parts.append("崩溃地址 == 故障地址，可能是虚表劫持或函数指针覆盖")
            return (ci.crash_type, Exploitability.EXPLOITABLE, 0.80, "; ".join(parts))

        # 规则 2: 写入 AV near NULL
        exception_name = self._exception_code_name(ci.exception_code)
        is_write = "WRITE" in exception_name.upper() or "write" in exception_name.lower()

        if is_write and self._check_near_null(ci.crash_address):
            parts.append("近 NULL 地址写入，可能是 NULL 指针解引用利用")
            return (ci.crash_type, Exploitability.PROBABLY_EXPLOITABLE, 0.70, "; ".join(parts))

        # 规则 3: 读取 AV NULL
        if self._check_near_null(ci.crash_address):
            parts.append("NULL 地址读取，可能的信息泄露")
            return (ci.crash_type, Exploitability.PROBABLY_EXPLOITABLE, 0.60, "; ".join(parts))

        # 规则 4: controlled EIP/RIP
        if self._check_controlled_eip(ci.register_context, ci.stack_trace):
            parts.append("EIP/RIP 被用户数据覆盖")
            return (ci.crash_type, Exploitability.EXPLOITABLE, 0.85, "; ".join(parts))

        # 规则 5: 栈 pivot
        if self._check_stack_pivot(ci.register_context):
            parts.append("检测到栈迁移")
            return (ci.crash_type, Exploitability.EXPLOITABLE, 0.85, "; ".join(parts))

        parts.append("通用访问违规，需要更多上下文")
        return (ci.crash_type, Exploitability.PROBABLY_EXPLOITABLE, 0.50, "; ".join(parts))

    # ---- 非法指令分类 ----
    def _classify_illegal(self, ci: CrashInfo, parts: List[str]) -> Tuple[CrashType, Exploitability, float, str]:
        # UD2 / INT3 / 0xCC → 可能是断言或反调试
        if ci.instruction_bytes:
            if ci.instruction_bytes[0] in (0xCC,):
                parts.append("INT3 断点指令，非利用崩溃")
                return (ci.crash_type, Exploitability.NOT_EXPLOITABLE, 0.10, "; ".join(parts))
            if bytes(ci.instruction_bytes[:2]) in (b"\x0f\x0b",):  # UD2
                parts.append("UD2 指令，通常是断言触发")
                return (ci.crash_type, Exploitability.NOT_EXPLOITABLE, 0.10, "; ".join(parts))

        # 如果 EIP 指向非可执行区域
        if self._check_controlled_eip(ci.register_context, ci.stack_trace):
            parts.append("EIP 指向不可执行区域，控制流被劫持")
            return (ci.crash_type, Exploitability.EXPLOITABLE, 0.85, "; ".join(parts))

        parts.append("非法指令，可能由内存损坏导致")
        return (ci.crash_type, Exploitability.PROBABLY_NOT_EXPLOITABLE, 0.25, "; ".join(parts))

    # ---- 栈溢出分类 ----
    def _classify_stack_overflow(self, ci: CrashInfo, parts: List[str]) -> Tuple[CrashType, Exploitability, float, str]:
        parts.append("栈溢出通常用于拒绝服务，直接利用难度高")
        return (ci.crash_type, Exploitability.PROBABLY_NOT_EXPLOITABLE, 0.30, "; ".join(parts))

    # ---- 堆损坏分类 ----
    def _classify_heap_corruption(self, ci: CrashInfo, parts: List[str]) -> Tuple[CrashType, Exploitability, float, str]:
        if self._check_controlled_eip(ci.register_context, ci.stack_trace):
            parts.append("堆损坏 + 控制流劫持 = 高度可利用")
            return (ci.crash_type, Exploitability.EXPLOITABLE, 0.80, "; ".join(parts))
        parts.append("堆损坏，需进一步分析")
        return (ci.crash_type, Exploitability.PROBABLY_EXPLOITABLE, 0.50, "; ".join(parts))

    # ===== 辅助检测方法 =====

    @staticmethod
    def _check_controlled_eip(registers: Dict[str, int],
                               stack_trace: 'List[Dict[str, Any]]') -> bool:
        """
        检查 EIP/RIP 是否被明显控制
        启发性: 检查常见 pattern 值 (0x41414141, 0x42424242.)
        """
        eip_val = registers.get("rip", None) or registers.get("eip", None)
        if eip_val is None:
            return False
        # 常见填充模式
        patterns = [0x41414141, 0x42424242, 0x43434343, 0x44444444,
                    0x90909090, 0xCCCCCCCC, 0xCDCDCDCD, 0xFEEEFEEE,
                    0xABABABAB, 0xDDDDDDDD, 0xFDFDFDFD]
        for p in patterns:
            if eip_val == p or eip_val & 0xFFFFFFFF == p:
                return True
            # 64-bit 全填充
            if eip_val == (p | (p << 32)):
                return True
        # 检查可打印 ASCII: 0x41414141 → "AAAA"
        if 0x20202020 <= (eip_val & 0xFFFFFFFF) <= 0x7E7E7E7E:
            return True
        # 检查 EIP 是否不在任何加载模块范围内 (粗略)
        return False

    @staticmethod
    def _check_near_null(addr: int) -> bool:
        """地址是否在 NULL 页面范围内 (< 0x1000)"""
        return addr < 0x1000

    @staticmethod
    def _check_stack_pivot(registers: Dict[str, int]) -> bool:
        """检查 ESP/RSP 是否指向堆区域 (非栈)"""
        rsp = registers.get("rsp", None) or registers.get("esp", None)
        if rsp is None:
            return False
        # 启发式: 栈通常在 0x7ff* 范围 (Windows) 或 0x7fff* (Linux)
        # 如果 RSP < 0x100000 或 > 0x800000000000，可能是 pivot
        if rsp < 0x100000 and rsp > 0x1000:
            return True
        # 检查是否在其他 page 类型的地址
        if rsp > 0x100000000000:
            return False  # 可能是正常高地址
        return False

    @staticmethod
    def _exception_code_name(code: int) -> str:
        codes = {
            0xC0000005: "ACCESS_VIOLATION",
            0xC0000017: "NO_MEMORY",
            0xC000001D: "ILLEGAL_INSTRUCTION",
            0xC000008C: "ARRAY_BOUNDS_EXCEEDED",
            0xC000008D: "FLOAT_DENORMAL_OPERAND",
            0xC000008E: "FLOAT_DIVIDE_BY_ZERO",
            0xC000008F: "FLOAT_INEXACT_RESULT",
            0xC0000090: "FLOAT_INVALID_OPERATION",
            0xC0000091: "FLOAT_OVERFLOW",
            0xC0000092: "FLOAT_STACK_CHECK",
            0xC0000093: "FLOAT_UNDERFLOW",
            0xC0000094: "INTEGER_DIVIDE_BY_ZERO",
            0xC0000095: "INTEGER_OVERFLOW",
            0xC0000096: "PRIVILEGED_INSTRUCTION",
            0xC00000FD: "STACK_OVERFLOW",
            0x80000003: "BREAKPOINT",
            0x80000004: "SINGLE_STEP",
        }
        return codes.get(code, f"UNKNOWN(0x{code:08X})")


# ===== 崩溃分析器 =====

class CrashAnalyzer:
    """
    综合崩溃分析器
    分类 + 评估 + 缓解 + 报告生成
    """

    def __init__(self, crash_info: CrashInfo, binary_path: Optional[str] = None):
        self.crash_info = crash_info
        self.binary_path = binary_path
        self._classifier = CrashClassifier()

    # ---- 评估可利用性 ----
    def assess_exploitability(self) -> Dict[str, Any]:
        ct, expl, conf, reason = self._classifier.classify(self.crash_info)
        mitigations = self.suggest_mitigations(ct, expl)
        return {
            "crash_type": ct.name,
            "exploitability": expl.name,
            "confidence": conf,
            "reasoning": reason,
            "fault_address": f"0x{self.crash_info.fault_address:X}",
            "crash_address": f"0x{self.crash_info.crash_address:X}",
            "exception_code": f"0x{self.crash_info.exception_code:08X}",
            "mitigations": mitigations,
        }

    # ---- 缓解 ----
    def suggest_mitigations(self, ct: CrashType = None,
                            expl: Exploitability = None) -> List[str]:
        mitigs: List[str] = []

        # 通用缓解
        mitigs.append("DEP (数据执行保护)")
        mitigs.append("ASLR (地址空间布局随机化)")
        mitigs.append("CFG/CET (控制流完整性)")

        ct = ct or self.crash_info.crash_type
        if ct == CrashType.STACK_OVERFLOW:
            mitigs.append("/GS (栈金丝雀)")
            mitigs.append("SafeSEH / SEHOP")
        elif ct == CrashType.HEAP_CORRUPTION:
            mitigs.append("LFH 加固")
            mitigs.append("HeapEnableTerminationOnCorruption")
            mitigs.append("Isolated Heap (隔离堆)")
            mitigs.append("Delay Free (延迟释放)")
        elif ct == CrashType.ACCESS_VIOLATION:
            mitigs.append("sandboxing (沙箱隔离)")
            mitigs.append("VTableGuard / XFG")

        return mitigs

    # ---- 生成可读报告 ----
    def generate_report(self) -> str:
        """
        生成人类可读的崩溃分析报告
        """
        assessment = self.assess_exploitability()
        ci = self.crash_info
        lines = [
            "=" * 60,
            "  崩溃分析报告",
            "=" * 60,
            f"  进程名称:      {ci.process_name}",
            f"  线程 ID:       {ci.thread_id}",
            f"  崩溃类型:      {assessment['crash_type']}",
            f"  可利用性:      {assessment['exploitability']}",
            f"  置信度:        {assessment['confidence']:.0%}",
            f"  故障地址:      {assessment['fault_address']}",
            f"  崩溃地址:      {assessment['crash_address']}",
            f"  异常码:        {assessment['exception_code']}",
            "-" * 40,
            f"  判定理由:      {assessment['reasoning']}",
            "-" * 40,
            "  寄存器上下文:",
        ]
        for reg, val in sorted(ci.register_context.items()):
            lines.append(f"    {reg:>6s} = 0x{val:016X}")

        lines.append("-" * 40)
        lines.append("  调用栈:")
        for i, frame in enumerate(ci.stack_trace[:10]):
            addr = frame.get("addr", 0)
            module = frame.get("module", "")
            symbol = frame.get("symbol", "")
            lines.append(f"    #{i:2d}  0x{addr:016X}  {module}!{symbol}")

        lines.append("-" * 40)
        lines.append("  建议缓解措施:")
        for m in assessment["mitigations"]:
            lines.append(f"    - {m}")

        lines.append("=" * 60)
        return "\n".join(lines)


# ===== 崩溃解析器 =====

class CrashParser:
    """
    从不同调试器/格式中解析崩溃信息
    支持 WinDbg!分析 -v、GDB backtrace、minidump/core 转存
    """

    # ---- 解析 WinDbg!分析 -v 输出 ----
    @staticmethod
    def parse_windbg_output(text: str) -> CrashInfo:
        ci = CrashInfo()
        # 异常码
        m = re.search(r'ExceptionCode:\s*([0-9A-Fa-f]+)', text)
        if m:
            ci.exception_code = int(m.group(1), 16)

        # 故障地址
        m = re.search(r'FAULTING_IP:\s*\S+\+([0-9A-Fa-f]+)', text)
        if m:
            ci.fault_address = int(m.group(1), 16)

        # 崩溃类型推断
        if ci.exception_code == 0xC0000005:
            ci.crash_type = CrashType.ACCESS_VIOLATION
        elif ci.exception_code == 0xC000001D:
            ci.crash_type = CrashType.ILLEGAL_INSTRUCTION
        elif ci.exception_code == 0xC00000FD:
            ci.crash_type = CrashType.STACK_OVERFLOW
        elif ci.exception_code == 0xC0000094:
            ci.crash_type = CrashType.DIVIDE_BY_ZERO
        elif ci.exception_code == 0xC0000096:
            ci.crash_type = CrashType.PRIVILEGED_INSTRUCTION
        elif ci.exception_code == 0x80000003:
            ci.crash_type = CrashType.ASSERT_FAILURE
        else:
            ci.crash_type = CrashType.UNKNOWN

        # 寄存器: 尝试匹配 CONTEXT 块
        reg_pattern = re.compile(r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|r8|r9|r10|r11|r12|r13|r14|r15|'
                                 r'eax|ebx|ecx|edx|esi|edi|ebp|esp|eip)=([0-9a-fA-F`]+)')
        for m in reg_pattern.finditer(text):
            reg_name = m.group(1).lower()
            val_str = m.group(2).replace('`', '')
            ci.register_context[reg_name] = int(val_str, 16)

        # 进程名
        m = re.search(r'PROCESS_NAME:\s*(\S+)', text)
        if m:
            ci.process_name = m.group(1)

        return ci

    # ---- 解析 GDB backtrace ----
    @staticmethod
    def parse_gdb_output(text: str) -> CrashInfo:
        ci = CrashInfo()
        ci.crash_type = CrashType.UNKNOWN

        # 信号
        m = re.search(r'Program received signal (\w+)', text)
        if m:
            sig = m.group(1)
            sig_map = {
                "SIGSEGV": CrashType.ACCESS_VIOLATION,
                "SIGILL":  CrashType.ILLEGAL_INSTRUCTION,
                "SIGFPE":  CrashType.DIVIDE_BY_ZERO,
                "SIGABRT": CrashType.ASSERT_FAILURE,
                "SIGSTKFLT": CrashType.STACK_OVERFLOW,
            }
            ci.crash_type = sig_map.get(sig, CrashType.UNKNOWN)

        # 寄存器
        reg_pattern = re.compile(r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|rip|'
                                  r'r\d{1,2})\s+0x([0-9a-fA-F]+)')
        for m in reg_pattern.finditer(text):
            ci.register_context[m.group(1)] = int(m.group(2), 16)

        # 调用栈 (bt)
        bt_pattern = re.compile(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s+\(.*\)\s+at\s+(.+)')
        for m in bt_pattern.finditer(text):
            ci.stack_trace.append({
                "index": int(m.group(1)),
                "addr": int(m.group(2), 16),
                "symbol": m.group(3),
                "module": m.group(4).strip(),
            })

        return ci

    # ---- 解析崩溃转储文件 ----
    @staticmethod
    def parse_crash_dump(path: str) -> CrashInfo:
        """
        读取 minidump (.dmp) 或 core 转存 文件
        此处提供框架 —— 完整解析需要 DbgEng 或 pyelftools
        """
        ci = CrashInfo()
        ext = os.path.splitext(path)[1].lower()
        if ext == ".dmp":
            # Windows minidump: 需要 DbgEng COM 接口或 minidump 解析库
            # 当前回退: 尝试用 cdb 命令行解析
            return CrashParser._parse_dmp_via_cdb(path) or ci
        elif ext in ("", ".core"):
            # Linux core 转存: 可尝试用 gdb 批处理
            return CrashParser._parse_core_via_gdb(path) or ci
        return ci

    @staticmethod
    def _parse_dmp_via_cdb(path: str) -> Optional[CrashInfo]:
        """用 cdb.exe 解析 Windows minidump"""
        try:
            import subprocess
            r = subprocess.run(
                ["cdb.exe", "-z", path, "-c", "!analyze -v; q"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                return CrashParser.parse_windbg_output(r.stdout)
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_core_via_gdb(path: str) -> Optional[CrashInfo]:
        """用 gdb 批处理解析 core dump"""
        try:
            import subprocess
            r = subprocess.run(
                ["gdb", "-batch", "-ex", "thread apply all bt full",
                 "-ex", "info registers", "-ex", "quit", path],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                return CrashParser.parse_gdb_output(r.stdout)
        except Exception:
            pass
        return None


# Round 3: FrameShift式碰撞去重 —— 基于堆栈哈希的崩溃分组
# 参考LibAFL的crash dedup策略：将调用栈的前N帧做页对齐哈希
# 编辑距离<阈值(0.3)的崩溃视为同类，仅对代表性崩溃做深入分析
# 这避免了单个bug产生数百个变体时分析资源的浪费

class CrashDeduplicator:
    """FrameShift风格的崩溃去重器。堆栈哈希分组减少冗余分析"""

    @staticmethod
    def stack_hash(frames: List[int]) -> str:
        """调用栈标准化哈希 —— 页对齐去噪后SHA256
        同一函数的不同偏移量调用被归入同一bucket"""
        normalized = [f & 0xFFFFFFFFFFFFF000 for f in frames]
        return hashlib.sha256(
            b''.join(f.to_bytes(8, 'little') for f in normalized)).hexdigest()

    @staticmethod
    def similarity(a: List[int], b: List[int]) -> float:
        """计算两个调用栈的相似度（基于公共前缀长度的Jaccard系数）"""
        min_len = min(len(a), len(b))
        if min_len == 0: return 0.0
        matches = sum(1 for i in range(min_len)
                     if (a[i] & 0xFFFFFFFFFFFFF000) == (b[i] & 0xFFFFFFFFFFFFF000))
        return matches / max(len(a), len(b))

    @classmethod
    def cluster(cls, crashes: List[Dict[str, Any]]) -> Dict[str, List[int]]:
        """将崩溃列表按堆栈相似度聚类。返回cluster_id -> [crash_indices]的映射"""
        clusters: Dict[str, List[int]] = {}
        for i, crash in enumerate(crashes):
            frames = crash.get('stack', [])
            matched = False
            for cid, indices in clusters.items():
                rep_frames = crashes[indices[0]].get('stack', [])
                if cls.similarity(frames, rep_frames) >= 0.7:
                    indices.append(i)
                    matched = True
                    break
            if not matched:
                clusters[f"CLUSTER-{len(clusters):03d}"] = [i]
        return clusters


import os  # noqa: E402
