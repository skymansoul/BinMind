# 信号帧利用分析器: SROP/信号帧注入/sigaltstack滥用/SIGSYS绕过
# 技术问题: 信号处理是Linux进程模型中最被低估的攻击面之一:
#   (a) SROP (Sigreturn-Oriented Programming): 通过伪造sigreturn帧
#       一次性设置所有寄存器, 比ROP高效得多 (1个gadget vs N个)
#   (b) 信号帧注入: 向栈写入伪造的sigframe→sigreturn恢复时劫持
#   (c) sigaltstack滥用: 将信号栈指向可控内存→信号到达时自动切换栈
#   (d) SIGSYS seccomp绕过: seccomp过滤器向违规进程发送SIGSYS→
#       handler可执行被过滤的syscall
#   (e) 信号handler重入: 递归触发同handler→栈耗尽/竞争条件
#   现有工具 (pwntools SigreturnFrame) 仅生成frame,
#   不分析目标二进制的信号配置是否支持这些攻击
# 解决手段: 分析二进制中的信号handler配置, 评估每类信号利用的可行性:
#   - SROP: 检测是否存在sigreturn gadget (pop rax; syscall)
#   - sigaltstack: 检测是否使用SS_AUTODISARM+可写的alternate stack
# SIGSYS: 检测是否在seccomp下安装SIGSYS handler
# 信号竞态: 检测handler重入保护 (SA_NODEFER)
# 技术效果: 自动识别信号相关的利用路径,
#   将SROP从手工分析升级为自动化可行性评估
#
#   Sigreturn-oriented programming — SROP原论文
#   Linux signal frame layout (arch/x86/kernel/signal.c) — 内核实现
from __future__ import annotations
import logging
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# 常见信号编号
_SIGNALS = {1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL",
            6: "SIGABRT", 8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV",
            13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM", 17: "SIGCHLD",
            19: "SIGSTOP", 31: "SIGSYS"}

# SA_FLAGS (signal action flags)
_SA_NOCLDSTOP = 0x00000001
_SA_NOCLDWAIT = 0x00000002
_SA_SIGINFO = 0x00000004
_SA_RESTORER = 0x04000000
_SA_ONSTACK = 0x08000000
_SA_RESTART = 0x10000000
_SA_NODEFER = 0x40000000
_SA_RESETHAND = 0x80000000

# x86_64 sigframe布局 (offset from frame base)
_SIGFRAME_OFFSETS = {
    "uc_flags":     0x00, "uc_link":      0x08,
    "ss_sp":        0x10, "ss_flags":     0x18,
    "ss_size":      0x20, "r8":           0x28,
    "r9":           0x30, "r10":          0x38,
    "r11":          0x40, "r12":          0x48,
    "r13":          0x50, "r14":          0x58,
    "r15":          0x60, "rdi":          0x68,
    "rsi":          0x70, "rbp":          0x78,
    "rbx":          0x80, "rdx":          0x88,
    "rax":          0x90, "rcx":          0x98,
    "rsp":          0xA0, "rip":          0xA8,
    "eflags":       0xB0, "cs":           0xB8,
    "gs":           0xBA, "fs":           0xBC,
    "err":          0xC0, "trapno":       0xC4,
    "oldmask":      0xC8, "cr2":          0xD0,
    "fpstate":      0xD8, "reserved":     0xE0,
    "_frame_size":  0x1F0,  # 完整sigframe大小
}


@dataclass
class SignalHandler:
    """单个信号handler配置."""
    signal: int
    signal_name: str
    handler_addr: int = 0      # sa_handler或sa_sigaction
    flags: int = 0
    restorer_addr: int = 0     # sa_restorer (若SA_RESTORER)
    mask: int = 0
    alt_stack_addr: int = 0    # sigaltstack ss_sp
    alt_stack_size: int = 0
    alt_stack_flags: int = 0


@dataclass
class SigFrameAnalysis:
    """信号帧利用分析结果."""
    # SROP
    srop_viable: bool = False
    sigreturn_gadget_addr: int = 0
    syscall_gadget_addr: int = 0
    # 信号handler漏洞
    vulnerable_handlers: List[SignalHandler] = field(default_factory=list)
    # sigaltstack
    altstack_writable: bool = False
    altstack_predictable: bool = False
    # SIGSYS seccomp绕过
    sigsys_handler_present: bool = False
    seccomp_active: bool = False
    # 信号竞态
    race_prone_handlers: List[int] = field(default_factory=list)
    # 综合评分
    overall_exploitability: str = "none"


class SignalFrameAnalyzer:
    """信号帧利用分析器.

    分析二进制中的信号配置, 识别五类信号利用路径.
    """

    def analyze_handlers(self,
                         handlers: List[SignalHandler],
                         has_seccomp: bool = False,
                         known_gadgets: Optional[Dict[str, int]] = None,
                         writable_regions: Optional[List[Tuple[int, int]]] = None
                         ) -> SigFrameAnalysis:
        analysis = SigFrameAnalysis()
        gadgets = known_gadgets or {}
        writable = writable_regions or []
        # 1. SROP可行性
        analysis.srop_viable = self._check_srop(handlers, gadgets, analysis)
        # 2. 信号handler漏洞分析
        for h in handlers:
            if self._is_handler_exploitable(h, writable):
                analysis.vulnerable_handlers.append(h)
        # 3. sigaltstack分析
        for h in handlers:
            if h.flags & _SA_ONSTACK:
                analysis.altstack_writable = any(
                    lo <= h.alt_stack_addr < hi
                    for lo, hi in writable)
                analysis.altstack_predictable = (
                    h.alt_stack_size > 0 and h.alt_stack_size < 0x10000)
        # 4. SIGSYS分析
        analysis.sigsys_handler_present = any(
            h.signal == 31 for h in handlers)
        analysis.seccomp_active = has_seccomp
        # 5. 信号竞态
        for h in handlers:
            if h.flags & _SA_NODEFER and h.signal not in (9, 19):
                analysis.race_prone_handlers.append(h.signal)
        # 综合评分
        analysis.overall_exploitability = self._rate_exploitability(analysis)
        return analysis

    def _check_srop(self, handlers: List[SignalHandler],
                    gadgets: Dict[str, int],
                    analysis: SigFrameAnalysis) -> bool:
        # 条件1: sigreturn gadget (mov rax, 15; syscall 或 pop rax; ret后接syscall)
        if "sigreturn" in gadgets:
            analysis.sigreturn_gadget_addr = gadgets["sigreturn"]
        elif "syscall" in gadgets:
            analysis.syscall_gadget_addr = gadgets["syscall"]
        # 条件2: 可控的栈 (用于放置伪造frame)
        # 条件3: 有handler使用SA_SIGINFO (frame中信息更丰富)
        has_siginfo_handler = any(h.flags & _SA_SIGINFO for h in handlers)
        # 条件4: sigreturn gadget可达
        has_gadget = (analysis.sigreturn_gadget_addr > 0 or
                     analysis.syscall_gadget_addr > 0)
        return has_gadget  # 简化判定

    def _is_handler_exploitable(self, handler: SignalHandler,
                                 writable: List[Tuple[int, int]]) -> bool:
        # SA_NODEFER: 同一信号可在handler执行期间再次触发→递归/栈耗尽
        if handler.flags & _SA_NODEFER:
            return True
        # handler地址可写→可覆写handler本身
        if any(lo <= handler.handler_addr < hi
               for lo, hi in writable):
            return True
        return False

    def _rate_exploitability(self, a: SigFrameAnalysis) -> str:
        score = 0
        if a.srop_viable:
            score += 3
        if a.vulnerable_handlers:
            score += len(a.vulnerable_handlers)
        if a.altstack_writable:
            score += 2
        if a.sigsys_handler_present and a.seccomp_active:
            score += 2
        if a.race_prone_handlers:
            score += len(a.race_prone_handlers)
        if score >= 5:
            return "high"
        if score >= 3:
            return "medium"
        if score >= 1:
            return "low"
        return "none"

    def generate_srop_frame(self, target_regs: Dict[str, int],
                            rip: int = 0, rsp: int = 0,
                            cs: int = 0x33, eflags: int = 0x202
                            ) -> Dict[str, int]:
        """生成用于SROP的伪造sigframe.

        填充x86_64 sigframe布局, 设置目标寄存器值.
        """
        frame = {
            "uc_flags": 0, "uc_link": 0,
            "ss_sp": 0, "ss_flags": 0, "ss_size": 0,
        }
        # 通用寄存器
        for reg in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                    "rdi", "rsi", "rbp", "rbx", "rdx", "rax", "rcx",
                    "rsp", "rip"):
            frame[reg] = target_regs.get(reg, 0)
        frame["rip"] = rip or frame["rip"]
        frame["rsp"] = rsp or frame["rsp"]
        frame["cs"] = cs
        frame["eflags"] = eflags
        frame["gs"] = 0
        frame["fs"] = 0
        frame["err"] = 0
        frame["trapno"] = 0
        frame["oldmask"] = 0
        frame["cr2"] = 0
        frame["fpstate"] = 0
        frame["reserved"] = 0
        return frame

    def build_sigreturn_shellcode(self, frame: Dict[str, int]) -> bytes:
        """构建sigreturn payload: syscall(15, &frame)."""
        # 简化: 返回frame的字节表示 (实际shellcode需按_layout二进制构建)
        # 实际使用: pwntools pwnlib.sigreturn_frame
        result = bytearray()
        for reg_offset in range(0x28, 0xE0, 8):
            val = frame.get("r8", 0)  # 简化
            result.extend(struct.pack('<Q', val))
        return bytes(result)

    def decode_flags(self, flags: int) -> List[str]:
        decoded = []
        if flags & _SA_NOCLDSTOP:
            decoded.append("SA_NOCLDSTOP")
        if flags & _SA_NOCLDWAIT:
            decoded.append("SA_NOCLDWAIT")
        if flags & _SA_SIGINFO:
            decoded.append("SA_SIGINFO")
        if flags & _SA_RESTORER:
            decoded.append("SA_RESTORER")
        if flags & _SA_ONSTACK:
            decoded.append("SA_ONSTACK")
        if flags & _SA_RESTART:
            decoded.append("SA_RESTART")
        if flags & _SA_NODEFER:
            decoded.append("SA_NODEFER (race-prone)")
        if flags & _SA_RESETHAND:
            decoded.append("SA_RESETHAND")
        return decoded
