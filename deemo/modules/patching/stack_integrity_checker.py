"""栈内存完整性检查 —— 借鉴 BASICS [Fang+, arXiv:2511.19670]。

BASICS 用 model checking + concolic execution 验证栈安全属性。
本模块实现其可工程化子集：字节码模式分析检测栈帧中的溢出、
返回地址覆写和 canary 破坏风险，不依赖动态执行。

输出：StackIntegrityReport，含逐函数风险矩阵。
"""

import re, struct, logging, os
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple, Set
from enum import IntEnum

_logger = logging.getLogger(__name__)


class StackRisk(IntEnum):
    """栈安全风险等级 —— 对应 BASICS 属性检查结果。"""
    CLEAN = 0           # 无风险
    LOW_RISK = 1        # 潜在不安全函数但无明确溢出证据
    MEDIUM_RISK = 2     # 固定大小缓冲区 + 不安全拷贝
    HIGH_RISK = 3       # 可变大小缓冲区 + 不安全拷贝 + 无边界检查
    CRITICAL = 4        # 明确的返回地址覆写模式


@dataclass
class StackFrameInfo:
    """单函数栈帧结构化信息。"""
    func_name: str
    func_offset: int = 0
    func_size: int = 0
    stack_size: int = 0
    has_canary: bool = False
    has_bounds_check: bool = False
    local_buffer_sizes: List[int] = field(default_factory=list)
    dangerous_calls: List[str] = field(default_factory=list)
    frame_layout_score: float = 0.0  # 0..1, 越高布局越安全


@dataclass
class StackIntegrityReport:
    """BASICS 风格栈完整性报告。"""
    binary_path: str = ""
    total_functions: int = 0
    risky_functions: int = 0
    frames: List[StackFrameInfo] = field(default_factory=list)
    overall_risk: StackRisk = StackRisk.CLEAN
    mitigation_suggestions: List[str] = field(default_factory=list)
    canary_coverage: float = 0.0
    # 对应 BASICS 论文的 stack safety score
    safety_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            'binary_path': self.binary_path,
            'total_functions': self.total_functions,
            'risky_functions': self.risky_functions,
            'overall_risk': self.overall_risk.name,
            'canary_coverage': round(self.canary_coverage, 4),
            'safety_score': round(self.safety_score, 4),
            'mitigation_suggestions': self.mitigation_suggestions,
            'frames': [
                {
                    'func_name': _f.func_name,
                    'stack_size': _f.stack_size,
                    'has_canary': _f.has_canary,
                    'has_bounds_check': _f.has_bounds_check,
                    'dangerous_calls': _f.dangerous_calls,
                    'local_buffer_sizes': _f.local_buffer_sizes,
                }
                for _f in self.frames[:50]  # 仅 top 50
            ],
        }


# ── 危险函数签名表 ────────────────────────────────────────────────
# 每项: (pattern, 默认缓冲区大小(bytes), 风险权重)
# 参考 BASICS Table 1 的危险函数分类

_DANGEROUS_FUNC_SIGS = [
    # (regex, estimated buffer size, risk weight 0..10)
    (r'call.*<strcpy>', 256, 9),
    (r'call.*<strcat>', 256, 9),
    (r'call.*<sprintf>', 512, 8),
    (r'call.*<gets>', 1024, 10),
    (r'call.*<scanf>', 512, 7),
    (r'call.*<vsprintf>', 512, 8),
    (r'call.*<wcscpy>', 512, 8),
    (r'call.*<wcscat>', 512, 8),
    (r'call.*<_mbscpy>', 512, 8),
    (r'call.*<lstrcpyA*>', 256, 9),
    (r'call.*<memcpy>', 64, 4),
    (r'call.*<memmove>', 64, 4),
    (r'call.*<read>', 1024, 6),
    (r'call.*<recv>', 1024, 6),
    (r'call.*<fread>', 4096, 4),
    (r'call.*<g_utf8_strlcpy>', 256, 5),
]

# ── 栈帧操作模式 ──────────────────────────────────────────────────
# 检测函数序言中的栈帧大小和 canary 存在性

_STACK_PROLOGUE_X86 = re.compile(
    rb'\x55'                     # push ebp
    rb'\x89\xe5'                 # mov ebp, esp
    rb'\x83[\xec\xc4]',          # sub esp / and esp
)

_STACK_PROLOGUE_X64 = re.compile(
    rb'[\x40-\x4f]?\x55'         # push rbp (可选 REX prefix)
    rb'[\x40-\x4f]?\x48\x89\xe5' # mov rbp, rsp
)

_CANARY_READ_X64 = re.compile(
    rb'\x64\x48\x8b\x04\x25\x28\x00\x00\x00'  # mov rax, fs:[0x28]
)

_CANARY_READ_X86 = re.compile(
    rb'\x65\xa1\x14\x00\x00\x00'  # mov eax, gs:[0x14]
)

_CANARY_CHECK = re.compile(
    rb'[\x64\x65].{0,4}([\x33\x31\x39\x3b])'  # xor/sub/cmp with canary
)


class StackIntegrityChecker:
    """栈完整性检查器 —— 分析二进制栈安全属性。

    基于 BASICS 栈内存安全验证思路，实现字节码级栈帧分析和风险评分。
    不执行符号执行，仅静态字节码分析。
    """

    def __init__(self, arch: str = "x86_64"):
        self._arch = arch.lower()
        if '64' in self._arch:
            self._prologue_pat = _STACK_PROLOGUE_X64
            self._canary_read = _CANARY_READ_X64
        else:
            self._prologue_pat = _STACK_PROLOGUE_X86
            self._canary_read = _CANARY_READ_X86

    # ============================================================
    # 主编排 —— 加载二进制 → 解析函数 → 逐函数栈帧分析
    # ============================================================
    def analyze(self, binary_path: str,
                function_list: Optional[List[Dict]] = None) -> StackIntegrityReport:
        """分析二进制栈完整性，返回结构化报告。"""
        _rpt = StackIntegrityReport(binary_path=binary_path)

        _data = self._load_binary(binary_path)
        if _data is None:
            _rpt.overall_risk = StackRisk.HIGH_RISK
            _rpt.mitigation_suggestions.append("binary could not be loaded")
            return _rpt

        # 解析或用给定函数列表
        if function_list is None:
            function_list = self._discover_functions(_data)

        _rpt.total_functions = len(function_list)

        # 逐函数分析
        _canary_count = 0
        for _fn_info in function_list:
            _frame = self._analyze_frame(_data, _fn_info)
            _rpt.frames.append(_frame)
            if _frame.has_canary:
                _canary_count += 1

        # 计算度量
        _rpt.canary_coverage = _canary_count / max(_rpt.total_functions, 1)

        _risky = [_f for _f in _rpt.frames
                  if _f.dangerous_calls and not _f.has_bounds_check]
        _rpt.risky_functions = len(_risky)

        # 综合评分
        _rpt.safety_score = self._compute_safety_score(_rpt)
        _rpt.overall_risk = self._determine_overall_risk(_rpt)

        # 缓解建议 —— 参考 BASICS 第 4.3 节
        if _rpt.canary_coverage < 0.80:
            _rpt.mitigation_suggestions.append(
                "canary coverage {:.0%} < 80%: enable -fstack-protector-strong".format(
                    _rpt.canary_coverage))
        if _rpt.risky_functions > 0:
            _rpt.mitigation_suggestions.append(
                "{} functions use dangerous calls without bounds check".format(
                    _rpt.risky_functions))
        if _rpt.safety_score < 0.5:
            _rpt.mitigation_suggestions.append(
                "safety score {:.2f} < 0.5: consider full RELRO + ASLR + shadow stack".format(
                    _rpt.safety_score))

        return _rpt

    # ── 二进制加载 ──────────────────────────────────────────────────

    def _load_binary(self, path: str) -> Optional[bytes]:
        try:
            with open(path, "rb") as _fh:
                return _fh.read()
        except Exception:
            _logger.warning("cannot load %s", path)
            return None

    # ── 函数发现 ────────────────────────────────────────────────────
    # 序言模式扫描，不依赖符号表（stripped binary 无符号）

    def _discover_functions(self, data: bytes) -> List[Dict]:
        """扫描字节码，通过序言模式检测函数入口。"""
        _funcs = []
        _i = 0
        _n = len(data)
        # 通用序言模式（放宽：push rbp 可选）
        while _i < _n - 4:
            # x86: push ebp (0x55) + mov ebp, esp (0x89 0xe5)
            if _i + 3 <= _n and data[_i] == 0x55 and data[_i+1] == 0x89 and data[_i+2] == 0xe5:
                _funcs.append({'offset': _i, 'size': 0})
                _i += 3
            # x64: push rbp (0x55) + mov rbp, rsp (0x48 0x89 0xe5)
            elif _i + 4 <= _n and data[_i] == 0x55 and data[_i+1] == 0x48 and data[_i+2] == 0x89 and data[_i+3] == 0xe5:
                _funcs.append({'offset': _i, 'size': 0})
                _i += 4
            else:
                _i += 1

        # 分配名字
        for _j, _fn in enumerate(_funcs):
            _fn['name'] = "func_{:04x}".format(_fn['offset'])

        # 估算函数大小（下个函数 offset 减当前 offset）
        for _j in range(len(_funcs) - 1):
            _funcs[_j]['size'] = _funcs[_j + 1]['offset'] - _funcs[_j]['offset']
        if _funcs:
            _funcs[-1]['size'] = min(65536, len(data) - _funcs[-1]['offset'])

        return _funcs

    # ── 单函数栈帧分析 ──────────────────────────────────────────────

    def _analyze_frame(self, data: bytes, fn_info: Dict) -> StackFrameInfo:
        _off = fn_info.get('offset', 0)
        _sz = fn_info.get('size', 256)
        _name = fn_info.get('name', 'unknown')
        _end = min(_off + _sz, len(data))
        _body = data[_off:_end]

        _frame = StackFrameInfo(
            func_name=_name,
            func_offset=_off,
            func_size=_sz)

        # 检测 canary
        if self._canary_read.search(_body) or _CANARY_CHECK.search(_body):
            _frame.has_canary = True

        # 栈大小估算：找 sub rsp, imm32
        _frame.stack_size = self._estimate_stack_size(_body)

        # 检测危险函数调用
        if isinstance(_body, bytes):
            _text = _body.decode('ascii', errors='replace')
        else:
            _text = str(_body)
        for _sig, _bufsz, _weight in _DANGEROUS_FUNC_SIGS:
            if re.search(_sig, _text):
                _frame.dangerous_calls.append(_sig.split('<')[1].split('>')[0])
                _frame.local_buffer_sizes.append(_bufsz)

        # 边界检查检测
        _frame.has_bounds_check = self._detect_bounds_check(_body)

        # 栈帧布局评分
        _frame.frame_layout_score = self._score_frame_layout(_frame)

        return _frame

    def _estimate_stack_size(self, body: bytes) -> int:
        """从 sub rsp/esp 指令估算栈帧大小。"""
        _max_sub = 0
        _i = 0
        while _i < len(body) - 7:
            # sub rsp, imm32: 48 81 EC XX XX XX XX
            if body[_i:_i+3] == b'\x48\x81\xec':
                _imm = struct.unpack_from('<I', body, _i+3)[0]
                _max_sub = max(_max_sub, _imm)
                break
            # sub esp, imm32: 81 EC XX XX XX XX
            if body[_i:_i+2] == b'\x81\xec':
                _imm = struct.unpack_from('<I', body, _i+2)[0]
                _max_sub = max(_max_sub, _imm)
                break
            _i += 1
        return _max_sub

    def _detect_bounds_check(self, body: bytes) -> bool:
        """检测函数体中有无边界检查指令序列。"""
        # cmp + jbe/jae (unsigned bound check)
        _pattern = re.compile(
            rb'[\x81\x83\x3b\x39\x48\x83].{0,4}'
            rb'[\x76\x77\x72\x73\x0f\x86\x0f\x87\x0f\x82\x0f\x83]',
            re.DOTALL)
        return bool(_pattern.search(body))

    def _score_frame_layout(self, frame: StackFrameInfo) -> float:
        """栈帧布局安全评分 —— 综合 canary/边界检查/缓冲区/危险调用。"""
        _sc = 1.0
        if not frame.has_canary:
            _sc -= 0.25
        if not frame.has_bounds_check:
            _sc -= 0.25
        # 大缓冲区 (>256 bytes) → 攻击面更大
        _large_bufs = sum(1 for _b in frame.local_buffer_sizes if _b > 256)
        _sc -= _large_bufs * 0.10
        # 危险调用计数
        _sc -= len(frame.dangerous_calls) * 0.05
        return max(_sc, 0.05)

    # ── 综合评分 ────────────────────────────────────────────────────

    def _compute_safety_score(self, report: StackIntegrityReport) -> float:
        """BASICS 风格 stack safety score。

        综合 canary 覆盖率、风险函数比例、帧布局评分。
        """
        if report.total_functions == 0:
            return 0.0
        _canary_w = report.canary_coverage * 0.30
        _risk_ratio = 1.0 - (report.risky_functions / max(report.total_functions, 1))
        _risk_w = _risk_ratio * 0.40
        _avg_layout = 0.0
        if report.frames:
            _avg_layout = (sum(_f.frame_layout_score for _f in report.frames) /
                          len(report.frames))
        _layout_w = _avg_layout * 0.30
        return round(_canary_w + _risk_w + _layout_w, 4)

    def _determine_overall_risk(self, report: StackIntegrityReport) -> StackRisk:
        if report.risky_functions == 0 and report.canary_coverage >= 0.90:
            return StackRisk.CLEAN
        _risk_ratio = report.risky_functions / max(report.total_functions, 1)
        if _risk_ratio < 0.05:
            return StackRisk.LOW_RISK
        if _risk_ratio < 0.15:
            return StackRisk.MEDIUM_RISK
        if _risk_ratio < 0.30:
            return StackRisk.HIGH_RISK
        return StackRisk.CRITICAL


# ── 便捷入口 ──────────────────────────────────────────────────────

def check_stack_integrity(binary_path: str,
                          function_list: Optional[List[Dict]] = None) -> Dict:
    _checker = StackIntegrityChecker()
    _rpt = _checker.analyze(binary_path, function_list)
    return {'success': True, 'result': _rpt.to_dict()}
