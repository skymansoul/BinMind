# UAF (Use-After-Free) 静态检测器 — 堆指针生命周期分析
# 在线性扫描框架内追踪堆指针的alloc→free→use生命周期,
#   检测free后通过悬挂指针的解引用/传参/返回
# 与ASA-VRA共享基础设施 (PointerProvenance, AllocationTracker),
#   但追踪目标从"写入是否超出分配边界"变为"使用是否在释放之后"
# 三阶段管道:
#   Pass 1 — 分配+释放追踪: 模型化malloc调用的分配点, 标记free调用点
#   Pass 2 — 悬挂指针传播: free后的指针通过mov/lea继续传播,
#             追踪别名链 (mov rdx, rax; free(rax) → rdx也悬挂)
#   Pass 3 — 使用点检测: 扫描悬挂后的所有指令, 检测:
#              (a) 解引用: mov reg, [dangling_ptr] / mov [dangling_ptr], reg
#              (b) 函数调用: call memcpy(..., dangling_ptr, ...)
#              (c) 双重释放: free(ptr)后再free(ptr)
from __future__ import annotations
import logging, re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

from .allocation_tracker import AllocationTracker
from .pointer_provenance import PointerProvenanceTracker
from .dangling_tracker import DanglingInfo, DanglingPtrTracker
from .instruction_parser import InstructionParser
from .uaf_helpers import rip_slot_key, is_crt_function

# 重导出: 保持 from analysis.uaf_detector import UafFinding, UafSeverity 兼容
__all__ = ['UafDetector', 'UafFinding', 'UafSeverity', 'FreeSiteInfo']

log = logging.getLogger(__name__)


# 数据模型

class UafSeverity(Enum):
    CRITICAL = auto()   # 写入通过悬挂指针 → 确定性利用
    HIGH = auto()       # 读取通过悬挂指针 / 悬挂指针传参
    MEDIUM = auto()     # 双重释放
    LOW = auto()        # 悬挂指针返回/存全局 → 间接危险
    INFO = auto()       # 悬挂指针传递但未解引用


@dataclass
class FreeSiteInfo:
    free_idx: int = 0
    free_func: str = ""
    freed_reg: str = ""
    ptr_origin: Optional['PointerOrigin'] = None
    alloc_site_id: str = ""
    in_function: str = ""
    is_double_free_candidate: bool = False


@dataclass
class UafFinding:
    finding_id: str
    severity: UafSeverity
    confidence: float = 1.0
    free_site: Optional[FreeSiteInfo] = None
    use_type: str = ""
    use_idx: int = 0
    use_instruction: str = ""
    use_reg: str = ""
    function_name: str = ""
    distance_from_free: int = 0
    detail: str = ""
    is_false_positive: bool = False
    false_positive_reason: str = ""

    def __repr__(self):
        return (f"UAF({self.severity.name}) conf={self.confidence:.2f} "
                f"dist={self.distance_from_free} "
                f"{self.use_type} @ {self.use_idx} in {self.function_name} "
                f"| {self.detail}")


from .uaf_handlers import UafHandlerMixin

class UafDetector(UafHandlerMixin):
    """UAF静态检测核心引擎.

    在线性扫描过程中追踪:
      1. 指针来源 (复用PointerProvenanceTracker)
      2. 分配点 (复用AllocationTracker)
      3. 悬挂状态 (新增DanglingPtrTracker)
      4. 悬挂使用检测 (UafHandlerMixin: _check_*方法)
    """

    def __init__(self):
        self._alloc = AllocationTracker()
        self._prov = PointerProvenanceTracker()
        self._dangling = DanglingPtrTracker()
        self._current_func = "_entry_"
        self._in_crt = True  # _entry_ is CRT glue code
        self._call_ctr = 0
        self._findings: List[UafFinding] = []

    # CRT噪声: 非用户代码函数, UAF检测需跳过
    _CRT_NOISE = {
        'duplicate_ppstrings', '__do_global_dtors', '__do_global_ctors',
        '__gcc_register_frame', '__gcc_deregister_frame',
        '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
        'atexit', 'check_managed_app', 'safe_flush',
        '__mingw_invalidParameterHandler', 'dtoa_lock',
        '__mingw_glob', '__mingw_dirname', '__mingw_basename',
        '__set_errno', 'abort', 'exit',
    }
    _CRT_PREFIXES = ('__', '_.', '<', '_Unwind', '__cxa', '__mingw_')
    _AUTO_FUNC_RE = re.compile(r'^func_\d+$')

    def analyze(self, instructions: List[str],
                func_map: Optional[Dict[str, Tuple[int, int]]] = None,
                instr_addrs: Optional[List[int]] = None
                ) -> List[UafFinding]:
        self._reset()
        func_map = func_map or {}

        # 回跳检测: 记录循环体指令索引集合 (循环内 free 双释放用)
        from .uaf_helpers import detect_backward_jumps
        self._loop_body = detect_backward_jumps(
            instructions, instr_addrs or [])

        for idx, line in enumerate(instructions):
            stripped = line.strip()
            if not stripped:
                continue
            cleaned = InstructionParser._SIZE_PREFIX_RE.sub('', stripped)
            parts = cleaned.replace(',', ' ').split()
            if not parts:
                continue
            op = parts[0]

            # 更新当前函数 — 使用指令索引而非绝对地址
            if func_map:
                for fname, (start, end) in func_map.items():
                    if start <= idx <= end:
                        if self._current_func != fname:
                            self._dangling.clear_all()
                            self._current_func = fname
                            from .uaf_helpers import is_crt_function
                            self._in_crt = is_crt_function(fname)
                        break

            # CRT噪声函数: 跳过UAF检测 (仅维护alloc/prov状态)
            if self._in_crt:
                continue

# 指令传播
            self._propagate(idx, op, parts, instructions)

# 调用处理
            if op == 'call':
                self._process_call(idx, parts, instructions,
                                   in_loop=idx in self._loop_body)

        return self._findings

    def _is_user_function(self, fname: str) -> bool:
        """判断函数是否为用户代码 (非CRT/编译器生成)."""
        if fname == '_entry_':
            return False
        if self._AUTO_FUNC_RE.match(fname):
            return False
        if fname in self._CRT_NOISE:
            return False
        if fname.startswith(self._CRT_PREFIXES):
            return False
        return True

    def _is_crt_function(self, fname: str) -> bool:
        """判断函数名是否为CRT/编译器生成的非用户代码."""
        return not self._is_user_function(fname)

    def _reset(self):
        self._alloc = AllocationTracker()
        self._prov = PointerProvenanceTracker()
        self._dangling = DanglingPtrTracker()
        self._current_func = "_entry_"
        self._in_crt = True  # _entry_ is CRT glue code
        self._call_ctr = 0
        self._findings = []
        self._loop_body: set = set()

# 指令级传播

    def _propagate(self, idx: int, op: str, parts: List[str],
                   instructions: List[str]):
        """单条指令的状态传播: provenance + dangling."""

# mov / movzx / movsx / movsxd
        if op in ('mov', 'movzx', 'movsx', 'movsxd') and len(parts) >= 3:
            dst = InstructionParser.clean_reg(parts[1])
            src = InstructionParser.clean_reg(parts[2])
            dst64 = InstructionParser.normalize_reg64(dst)
            src64 = InstructionParser.normalize_reg64(src)

            # 溯源传播: 从内存加载 (必须在 reg→reg 前检查,
            # 因为 clean_reg 会剥掉括号使 [rax]→rax 看起来像寄存器)
            if InstructionParser.is_reg(dst) and '[' in parts[2]:
                # 从内存加载到寄存器
                # 检查是否从悬挂的栈槽加载
                loaded_from_dangling = False
                _mem_txt = parts[2].lower()
                if ('rbp' in _mem_txt or 'rsp' in _mem_txt
                        or 'rip' in _mem_txt):
                    mem_base, mem_off = InstructionParser.parse_mem(parts[2])
                    if mem_base:
                        if 'rip' in _mem_txt:
                            mem_off = rip_slot_key(
                                instructions[idx], mem_off)
                        loaded_from_dangling = self._dangling.load_from_stack(
                            mem_base, mem_off, dst64, idx)
                # 检查是否从悬挂指针读取 (deref read)
                if not loaded_from_dangling:
                    self._check_deref_read(idx, parts)
                    self._dangling.clear_reg(dst64)

            elif InstructionParser.is_reg(dst) and InstructionParser.is_reg(src):
                # 寄存器→寄存器传播
                self._prov.propagate_reg_to_reg(dst64, src64, str(idx))
                # 悬挂传播: src悬挂 → dst悬挂
                if self._dangling.is_dangling(src64):
                    self._dangling.propagate_alias(src64, dst64, idx)
                elif src64 != dst64:
                    self._dangling.clear_reg(dst64)

            elif '[' in parts[1] and InstructionParser.is_reg(src):
                # 存储寄存器到内存
                self._check_deref_write(idx, parts)
                # 栈槽/全局槽悬挂追踪 (rbp/rsp/rip 基址)
                _dst_txt = parts[1].lower()
                if ('rbp' in _dst_txt or 'rsp' in _dst_txt
                        or 'rip' in _dst_txt):
                    mem_base, mem_off = InstructionParser.parse_mem(parts[1])
                    if mem_base:
                        if 'rip' in _dst_txt:
                            mem_off = rip_slot_key(
                                instructions[idx], mem_off)
                        if self._dangling.is_dangling(src64):
                            # 悬挂寄存器存入栈 → 栈槽也标记为悬挂
                            info = self._dangling.get_info(src64)
                            if info:
                                self._dangling.mark_stack_dangling(
                                    mem_base, mem_off, info, idx)
                        else:
                            # 非悬挂值 (如xor清零后的0) 存入栈 → 清除栈槽悬挂
                            self._dangling.clear_stack_slot(mem_base, mem_off)
            elif '[' in parts[1] and not InstructionParser.is_reg(
                InstructionParser.clean_reg(parts[2]) if len(parts) > 2 else ''):
                # mov [mem], imm — 检查通过悬挂指针的立即数写入
                self._check_deref_write(idx, parts)
                # 清除栈槽/全局槽悬挂
                _dst_txt = parts[1].lower()
                if ('rbp' in _dst_txt or 'rsp' in _dst_txt
                        or 'rip' in _dst_txt):
                    mem_base, mem_off = InstructionParser.parse_mem(parts[1])
                    if mem_base:
                        if 'rip' in _dst_txt:
                            mem_off = rip_slot_key(
                                instructions[idx], mem_off)
                        self._dangling.clear_stack_slot(mem_base, mem_off)

            # 溯源: 栈/全局槽存储
            if '[' in parts[1] and ('rbp' in parts[1].lower()
                                    or 'rip' in parts[1].lower()):
                base, offset = InstructionParser.parse_mem(parts[1])
                if 'rip' in parts[1].lower():
                    offset = rip_slot_key(instructions[idx], offset)
                if InstructionParser.is_reg(src):
                    self._prov.propagate_reg_to_stack(
                        base, offset, src64, str(idx))
            # 溯源: 栈/全局槽加载
            if '[' in parts[2] and ('rbp' in parts[2].lower()
                                    or 'rip' in parts[2].lower()):
                base, offset = InstructionParser.parse_mem(parts[2])
                if 'rip' in parts[2].lower():
                    offset = rip_slot_key(instructions[idx], offset)
                if InstructionParser.is_reg(dst):
                    self._prov.propagate_stack_to_reg(
                        dst64, base, offset, str(idx))

            return

# lea dst, [base+offset]
        if op == 'lea' and len(parts) >= 3:
            dst = InstructionParser.clean_reg(parts[1])
            dst64 = InstructionParser.normalize_reg64(dst)
            src_str = parts[2]
            base = _extract_mem_base_lea(src_str)
            if base:
                base64 = InstructionParser.normalize_reg64(base)
                if self._dangling.is_dangling(base64):
                    self._dangling.propagate_alias(base64, dst64, idx)
                    return
            self._dangling.clear_reg(dst64)
            return

# xor reg, reg → 清零
        if op == 'xor' and len(parts) >= 3:
            dst = InstructionParser.clean_reg(parts[1])
            src = InstructionParser.clean_reg(parts[2])
            dst64 = InstructionParser.normalize_reg64(dst)
            src64 = InstructionParser.normalize_reg64(src)
            if dst64 == src64:
                self._dangling.clear_reg(dst64)
            return

    def summary(self) -> Dict:
        sevs = {}
        for f in self._findings:
            s = f.severity.name
            sevs[s] = sevs.get(s, 0) + 1
        return {'total_uaf_findings': len(self._findings),
                'by_severity': sevs}


# 本地辅助: lea基址提取 (只在_propagate中使用)

def _extract_mem_base_lea(s: str) -> str:
    """从 [base+offset] 中提取基址寄存器 (lea专用)."""
    s = s.strip()
    if s.startswith('[') and s.endswith(']'):
        inner = s[1:-1]
        m = re.match(r'(\w+)', inner)
        if m:
            reg = m.group(1)
            if reg.lower() == 'rip':
                return ''
            return reg
    return ''


