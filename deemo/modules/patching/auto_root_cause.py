"""根因分析引擎。输入 crash dump 和 sanitizer 报告，输出结构化漏洞评估。"""

import re, os, json, logging, hashlib
import datetime as _dt
from enum import IntEnum
from collections import OrderedDict

_log = logging.getLogger(__name__)

name = "AutoRootCauseAnalyzer"
function_name = ""

# ── crash 类型分类体系 ──────────────────────────────────────────────────

_CRASH_PATTERNS = {
    "SEGFAULT_ON_ADDRESS": [
        (re.compile(r"signal\s*11|SIGSEGV|segmentation\s+fault", re.I), 0.85),
        (re.compile(r"fault\s+addr\s+0x0+$", re.I), 0.95),            # 空指针解引用
        (re.compile(r"fault\s+addr\s+0x[0-9a-f]{1,6}$", re.I), 0.70), # 低地址访问
    ],
    "STACK_BUFFER_OVERFLOW": [
        (re.compile(r"stack-buffer-overflow", re.I), 0.95),
        (re.compile(r"WRITE\s+of\s+size\s+\d+\s+at", re.I), 0.50),
        (re.compile(r"__asan_report_store", re.I), 0.90),
    ],
    "HEAP_BUFFER_OVERFLOW": [
        (re.compile(r"heap-buffer-overflow", re.I), 0.95),
        (re.compile(r"__asan_report_load.*after.*free|heap-use-after-free", re.I), 0.70),
    ],
    "USE_AFTER_FREE": [
        (re.compile(r"use-after-free|heap-use-after-free", re.I), 0.95),
        (re.compile(r"freed\s+by\s+thread|previously\s+allocated", re.I), 0.80),
    ],
    "INTEGER_OVERFLOW": [
        (re.compile(r"integer\s+overflow|__ubsan_handle.*overflow", re.I), 0.95),
        (re.compile(r"signed\s+integer\s+overflow", re.I), 0.90),
    ],
    "DOUBLE_FREE": [
        (re.compile(r"double\s+free", re.I), 0.95),
        (re.compile(r"free\(\):\s+invalid\s+pointer|double free or corruption", re.I), 0.85),
    ],
    "FORMAT_STRING": [
        (re.compile(r"fmt.*vulnerability|format\s+string|__printf_chk", re.I), 0.80),
    ],
    "NULL_DEREFERENCE": [
        (re.compile(r"null\s+(pointer\s+)?deref", re.I), 0.95),
        (re.compile(r"access\s+violation.*reading.*0x0+", re.I), 0.90),
        (re.compile(r"(?:PC|pc|eip|rip)\s*[=:]\s*0x0+\b", re.I), 0.85),
    ],
    "TYPE_CONFUSION": [
        (re.compile(r"type\s+confusion|bad_cast|dynamic_cast.*failed", re.I), 0.85),
    ],
    "STACK_EXHAUSTION": [
        (re.compile(r"stack\s+(overflow|exhausted|exceeds)", re.I), 0.90),
        (re.compile(r"alloca.*big|__chkstk", re.I), 0.70),
    ],
}

# ── 寄存器状态启发式 ────────────────────────────────────────────────────
# 8 条规则，覆盖 x86_64 和 arm64（x0-x30, sp, lr, pc）

_REGISTER_RULES = [
    # (条件判断, 解译文本, 置信增量)
    (
        lambda regs: regs.get('rip', '0').lower() in ('0x0', '0x00000000', '0', '00000000'),
        "instruction pointer is NULL: control-flow hijack or indirect call through NULL",
        0.20
    ),
    (
        lambda regs: _parse_hex(regs.get('rsp')) is not None and
                     _parse_hex(regs.get('rbp')) is not None and
                     _parse_hex(regs['rsp']) > _parse_hex(regs['rbp']),
        "RSP > RBP: stack pointer is above frame pointer (stack pivot detected)",
        0.25
    ),
    (
        lambda regs: any(
            0x41000000 <= _parse_hex(regs.get(r, '0')) <= 0x42000000
            for r in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9']
            if _parse_hex(regs.get(r)) is not None
        ),
        "register holds value near 0x41: possible heap spray corruption",
        0.30
    ),
    (
        lambda regs: _parse_hex(regs.get('rip', '0')) and
                     not (0 <= _parse_hex(regs['rip']) <= 0x7FFFFFFFFFFF),
        "RIP points to non-canonical address: indirect jump corruption",
        0.35
    ),
    (
        lambda regs: _parse_hex(regs.get('rdi')) == 0x0 and
                     'rax' in regs,
        "RDI = NULL with RAX set: likely failed allocation check leading to NULL deref",
        0.15
    ),
    # ── arm64 专用规则 ──────────────────────────────────────────
    (
        lambda regs: _parse_hex(regs.get('pc', '0')) in (0x0, 0) or
                     _parse_hex(regs.get('lr', '0')) in (0x0, 0),
        "ARM64 PC or LR is NULL: indirect branch to zero — likely control-flow hijack",
        0.30
    ),
    (
        lambda regs: _parse_hex(regs.get('sp')) is not None and
                     _parse_hex(regs.get('sp')) < 0x1000,
        "ARM64 SP near zero: stack pointer underflow — possible stack exhaustion or pivot",
        0.20
    ),
    (
        lambda regs: regs.get('x0', '') != '' and
                     _parse_hex(regs.get('x0')) == 0x0 and
                     any(_parse_hex(regs.get(r)) is not None and
                         _parse_hex(regs.get(r)) > 0 for r in ['x1','x2','x3']),
        "ARM64 x0=NULL with x1-x3 populated: likely failed function return → NULL propagation",
        0.15
    ),
]


def _parse_hex(val):
    if val is None:
        return None
    try:
        if isinstance(val, int):
            return val
        return int(str(val), 16)
    except (ValueError, TypeError):
        return None


# ── 严重度与可利用性评级 ──────────────────────────────────────────────

class VulnerabilitySeverity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def _missing_(cls, value):
        return cls.INFO


class Exploitability(IntEnum):
    NONE = 0
    UNLIKELY = 1
    POSSIBLE = 2
    LIKELY = 3
    CONFIRMED = 4


class CWEDatabase:
    _DB = {
        "STACK_BUFFER_OVERFLOW": ("CWE-121", "Stack-based Buffer Overflow"),
        "HEAP_BUFFER_OVERFLOW": ("CWE-122", "Heap-based Buffer Overflow"),
        "USE_AFTER_FREE": ("CWE-416", "Use After Free"),
        "DOUBLE_FREE": ("CWE-415", "Double Free"),
        "NULL_DEREFERENCE": ("CWE-476", "NULL Pointer Dereference"),
        "FORMAT_STRING": ("CWE-134", "Use of Externally-Controlled Format String"),
        "INTEGER_OVERFLOW": ("CWE-190", "Integer Overflow or Wraparound"),
        "TYPE_CONFUSION": ("CWE-843", "Access of Resource Using Incompatible Type"),
        "STACK_EXHAUSTION": ("CWE-770", "Allocation of Resources Without Limits or Throttling"),
        "SEGFAULT_ON_ADDRESS": ("CWE-682", "Incorrect Calculation"),
    }

    @staticmethod
    def lookup(crash_type):
        return CWEDatabase._DB.get(crash_type, ("CWE-0", "Unknown"))


# ── crash 签名哈希 ──────────────────────────────────────────────────────
# 双轨 hash：exact hash 精确去重，fuzzy hash 同类聚类。
# Fuzzy hash 截取 call stack frame 的函数名 + offset（剔除地址），
# 对抗 ASLR 导致的地址漂移。参考 arXiv crash dedup 方案。

def _crash_exact_hash(crash_type, fault_addr, stack_trace):
    """SHA-256 精确 hash — 输入决定输出，零碰撞容忍，精确去重。"""
    h = hashlib.sha256()
    h.update(crash_type.encode() if crash_type else b'unknown')
    h.update(str(fault_addr).encode())
    for frame in (stack_trace or [])[:10]:
        h.update(str(frame).encode())
    return h.hexdigest()[:16]


def _crash_fuzzy_hash(crash_type, stack_trace):
    """Fuzzy hash — 函数名+偏移，剥离绝对地址。同漏洞跨 ASLR 布局产出一致 hash。"""
    h = hashlib.sha256()
    h.update(crash_type.encode() if crash_type else b'unknown')
    for frame in (stack_trace or [])[:10]:
        stripped = re.sub(r'0x[0-9a-fA-F]+', 'ADDR', str(frame))
        stripped = re.sub(r'\+0x[0-9a-fA-F]+', '+OFFSET', stripped)
        h.update(stripped.encode())
    return h.hexdigest()[:16]


# ── crash 聚类 ─────────────────────────────────────────────────────────

class CrashCluster:
    """同类 crash 聚合器 — 跟踪同一根因的多次崩溃。
    Fuzzy hash 一致 → 归入同一 cluster。"""

    def __init__(self):
        self._clusters = {}  # fuzzy_hash → VulnerabilityContext 列表

    def add(self, ctx):
        fh = _crash_fuzzy_hash(ctx.crash_type, ctx.stack_trace)
        if fh not in self._clusters:
            self._clusters[fh] = []
        self._clusters[fh].append(ctx)
        return fh, len(self._clusters[fh])

    def get_cluster(self, fuzzy_hash):
        return self._clusters.get(fuzzy_hash, [])

    def stats(self):
        return {
            'total_clusters': len(self._clusters),
            'largest_cluster': max((len(v) for v in self._clusters.values()), default=0),
            'avg_cluster_size': sum(len(v) for v in self._clusters.values()) / max(len(self._clusters), 1),
        }

    def to_dict(self):
        return {
            str(k): [v.to_dict() for v in lst]
            for k, lst in self._clusters.items()
        }


# ── 能力分类 ────────────────────────────────────────────────────────────
# crash type + register state → exploit primitive 集合。
# 快速 triage：crash 可控性 → weaponize 所需 primitive 清单。

_CAPABILITY_MAP = {
    'USE_AFTER_FREE':       ['heap_feng_shui', 'info_leak'],
    'HEAP_BUFFER_OVERFLOW': ['heap_feng_shui', 'write_primitive', 'info_leak'],
    'STACK_BUFFER_OVERFLOW': ['write_primitive', 'control_flow_hijack', 'stack_pivot'],
    'FORMAT_STRING':         ['write_primitive', 'read_primitive', 'info_leak'],
    'DOUBLE_FREE':           ['heap_feng_shui', 'write_primitive'],
    'INTEGER_OVERFLOW':      ['write_primitive', 'control_flow_hijack'],
    'NULL_DEREFERENCE':      ['info_leak'],
    'TYPE_CONFUSION':        ['write_primitive', 'control_flow_hijack', 'info_leak'],
    'STACK_EXHAUSTION':      [],
    'SEGFAULT_ON_ADDRESS':   ['info_leak'],
}


def triage_capabilities(ctx):
    """VulnerabilityContext → 所需 exploit capability 列表。"""
    caps = _CAPABILITY_MAP.get(ctx.crash_type, [])
    # null deref 且 RIP=0 → 攻击者已获控制流劫持
    if ctx.crash_type == 'NULL_DEREFERENCE':
        rip = ctx.registers.get('rip', ctx.registers.get('pc', ''))
        if rip in ('0x0', '0x00000000', '0', '00000000'):
            caps = ['control_flow_hijack', 'info_leak']
    return caps


# ── 分析数据类型 ───────────────────────────────────────────────────────

class VulnerabilityContext:
    def __init__(self):
        self.crash_info = {}
        self.crash_type = ""
        self.confidence = 0.0
        self.faulting_instruction = ""
        self.faulting_address = 0
        self.registers = {}
        self.stack_trace = []
        self.cwe_id = ""
        self.cwe_description = ""
        self.exact_hash = ""
        self.fuzzy_hash = ""
        self.capabilities_required = []

    def to_dict(self):
        return OrderedDict([
            ('crash_type', self.crash_type),
            ('confidence', round(self.confidence, 3)),
            ('faulting_instruction', self.faulting_instruction),
            ('faulting_address', hex(self.faulting_address) if self.faulting_address else ''),
            ('cwe_id', self.cwe_id),
            ('cwe_description', self.cwe_description),
            ('registers', self.registers),
            ('stack_trace', self.stack_trace),
            ('exact_hash', self.exact_hash),
            ('fuzzy_hash', self.fuzzy_hash),
            ('capabilities_required', self.capabilities_required),
        ])


class AnalysisReport:
    def __init__(self):
        self.vulnerabilities = []
        self.severity_distribution = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        self.generated_at = _dt.datetime.now(_dt.timezone.utc).isoformat()
        self.binary_path = ""
        self.target_binary = ""
        self.analysis_id = hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        self.summary = {}
        self.function_name = ""
        self.function_address = 0

    def add_vuln(self, ctx):
        self.vulnerabilities.append(ctx)
        sev = _severity_for_type(ctx.crash_type)
        self.severity_distribution[sev.name.lower()] += 1

    def to_dict(self):
        return OrderedDict([
            ('analysis_id', self.analysis_id),
            ('generated_at', self.generated_at),
            ('binary_path', self.binary_path),
            ('target_binary', self.target_binary),
            ('function_name', self.function_name),
            ('function_address', hex(self.function_address) if self.function_address else ''),
            ('summary', self.summary),
            ('severity_distribution', self.severity_distribution),
            ('vulnerabilities', [v.to_dict() for v in self.vulnerabilities]),
        ])


def _severity_for_type(crash_type):
    critical_types = {'USE_AFTER_FREE', 'HEAP_BUFFER_OVERFLOW', 'TYPE_CONFUSION'}
    high_types = {'STACK_BUFFER_OVERFLOW', 'DOUBLE_FREE', 'FORMAT_STRING', 'NULL_DEREFERENCE'}
    if crash_type in critical_types:
        return VulnerabilitySeverity.CRITICAL
    if crash_type in high_types:
        return VulnerabilitySeverity.HIGH
    if crash_type in ('INTEGER_OVERFLOW', 'SEGFAULT_ON_ADDRESS'):
        return VulnerabilitySeverity.MEDIUM
    return VulnerabilitySeverity.INFO


def _assess_exploitability(crash_type, context):
    if crash_type in ('USE_AFTER_FREE', 'HEAP_BUFFER_OVERFLOW', 'TYPE_CONFUSION'):
        return Exploitability.LIKELY
    if crash_type in ('STACK_BUFFER_OVERFLOW', 'FORMAT_STRING'):
        return Exploitability.LIKELY
    if crash_type == 'NULL_DEREFERENCE':
        # NULL 解引用通常仅导致拒绝服务，非代码执行 —
        # 除非 mmap(0x0) 可行
        if context.registers.get('rip', '') in ('0x0', '0x00000000'):
            return Exploitability.LIKELY
        return Exploitability.UNLIKELY
    return Exploitability.POSSIBLE


# ── 主分析器 ──────────────────────────────────────────────────────────

class AutoRootCauseAnalyzer:
    def __init__(self):
        self._cluster = CrashCluster()

    def analyze(self, crash):
        """根因分析入口。

        输入格式:
          - dict: signal, registers, stack_trace, fault_addr, description, type
          - str: asan/ubsan 输出文件路径或 gdb backtrace
          - str: 原始 crash 日志文本
        """
        report = AnalysisReport()
        context = VulnerabilityContext()

        # 输入归一化为 dict
        if isinstance(crash, str):
            if os.path.isfile(crash):
                with open(crash, 'r', encoding='utf-8', errors='replace') as fh:
                    crash_text = fh.read()
                report.binary_path = crash
                report.target_binary = crash
            else:
                crash_text = crash
            crash_dict = self._parse_crash_text(crash_text)
        elif isinstance(crash, dict):
            crash_dict = crash
            report.binary_path = crash_dict.get('binary_path', '')
            report.target_binary = crash_dict.get('binary_path', '')
        else:
            crash_dict = {}

        # 展开结构化字段
        context.crash_info = crash_dict
        context.registers = crash_dict.get('registers', {})
        context.faulting_address = _parse_hex(crash_dict.get('fault_addr', '0')) or 0
        context.stack_trace = crash_dict.get('stack_trace', [])
        if isinstance(context.stack_trace, str):
            context.stack_trace = context.stack_trace.split('\n')

        # 模式匹配归类 crash type
        crash_text_for_matching = crash_dict.get('description', '') + ' ' + \
            crash_dict.get('signal', '') + ' ' + \
            crash_dict.get('type', '') + ' ' + \
            json.dumps(crash_dict)

        best_type = 'UNKNOWN'
        best_confidence = 0.0
        for ctype, patterns in _CRASH_PATTERNS.items():
            for pat, weight in patterns:
                if pat.search(crash_text_for_matching):
                    if weight > best_confidence:
                        best_confidence = weight
                        best_type = ctype

        # 寄存器启发式精炼分类
        # 2026-08-02: 空 registers 时跳过寄存器规则 — 默认 fake 值 'rip':'0'
        # 不应触发 NULL_DEREFERENCE。
        if context.registers and len(context.registers) > 0:
            for condition, interpretation, boost in _REGISTER_RULES:
                try:
                    if condition(context.registers):
                        if best_type == 'UNKNOWN':
                            best_type = 'NULL_DEREFERENCE' if 'null' in interpretation.lower() else best_type
                        best_confidence = min(1.0, best_confidence + boost)
                except Exception:
                    _log.debug("register rule suppressed", exc_info=True)

        context.crash_type = best_type
        context.confidence = best_confidence
        cwe_id, cwe_desc = CWEDatabase.lookup(best_type)
        context.cwe_id = cwe_id
        context.cwe_description = cwe_desc

        # 解析故障指令
        context.faulting_instruction = crash_dict.get('faulting_instruction', '') or \
            crash_dict.get('instruction', '') or \
            self._guess_faulting_instruction(context.stack_trace[0] if context.stack_trace else '')

        # crash 签名计算
        context.exact_hash = _crash_exact_hash(context.crash_type, context.faulting_address, context.stack_trace)
        context.fuzzy_hash = _crash_fuzzy_hash(context.crash_type, context.stack_trace)

        # 能力分类标记
        context.capabilities_required = triage_capabilities(context)

        # 聚类登记
        self._cluster.add(context)

        report.add_vuln(context)
        report.function_name = context.stack_trace[0] if context.stack_trace else "unknown"
        report.summary = {
            'crash_type': context.crash_type,
            'confidence': context.confidence,
            'exploitability': _assess_exploitability(context.crash_type, context).name,
            'cwe': context.cwe_id,
            'total_vulnerabilities': len(report.vulnerabilities),
            'exact_hash': context.exact_hash,
            'fuzzy_hash': context.fuzzy_hash,
            'capabilities_required': context.capabilities_required,
        }

        return report

    def cluster_stats(self):
        """当前 crash 聚合统计快照。"""
        return self._cluster.stats()

    def get_similar_crashes(self, fuzzy_hash):
        """按 fuzzy_hash 查询同 cluster 的 crash 记录。"""
        return self._cluster.get_cluster(fuzzy_hash)

    def _parse_crash_text(self, text):
        result = {}

        # ASAN 错误类型及故障地址
        m = re.search(r'(\w[\w-]+)\s+on\s+address\s+(0x[0-9a-f]+)', text, re.I)
        if m:
            result['type'] = m.group(1)
            result['fault_addr'] = m.group(2)

        # 信号编号提取
        m = re.search(r'(?:signal|SIG)\s*(\w+)', text, re.I)
        if m:
            result['signal'] = m.group(1)

        # 寄存器转储解析
        regs = {}
        for line in text.split('\n'):
            # x86_64 寄存器
            m = re.search(
                r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15'
                r'|eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|rip)'
                r'\s*[:=]\s*(0x[0-9a-f]+|[0-9a-f]+)',
                line, re.I
            )
            if m:
                regs[m.group(1).lower()] = m.group(2)

            # arm64 寄存器 (GDB info registers 格式)
            m_arm = re.search(
                r'(x0|x1|x2|x3|x4|x5|x6|x7|x8|x9|x10|x11|x12|x13|x14|x15'
                r'|x16|x17|x18|x19|x20|x21|x22|x23|x24|x25|x26|x27|x28'
                r'|x29|fp|lr|sp|pc|cpsr)'
                r'\s+0x([0-9a-f]+)',
                line, re.I
            )
            if m_arm:
                regs[m_arm.group(1).lower()] = '0x' + m_arm.group(2)

            # GDB format: "rax            0x0      0"
            m_gdb = re.search(
                r'(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15'
                r'|eax|ebx|ecx|edx|esi|edi|ebp|esp|eip|rip|eflags|cs|ss|ds|es|fs|gs)'
                r'\s+(0x[0-9a-f]+|[0-9a-f]+)',
                line, re.I
            )
            if m_gdb:
                rname = m_gdb.group(1).lower()
                if rname not in regs:  # 优先保留 := 格式，GDB 表格式次之
                    regs[rname] = m_gdb.group(2)

        if regs:
            result['registers'] = regs

        # 栈回溯提取
        trace_lines = []
        in_trace = False
        blank_after_trace = 0
        for line in text.split('\n'):
            if re.search(r'(backtrace|stack trace|call stack|#0)', line, re.I):
                in_trace = True
                blank_after_trace = 0
            if in_trace:
                if re.match(r'\s*#\d+', line) or re.search(r'0x[0-9a-f]+\s+in\s+', line, re.I):
                    trace_lines.append(line.strip())
                    blank_after_trace = 0
                elif trace_lines and line.strip() == '':
                    # GDB backtrace 帧间可含空行 — 容忍最多 2 行后判定 trace 结束
                    blank_after_trace += 1
                    if blank_after_trace > 2:
                        in_trace = False
                elif trace_lines and line.strip():
                    # trace 内容后的非空非 trace 行 → 结束
                    if not re.match(r'\s*#\d+', line) and not re.search(r'0x[0-9a-f]+\s+in\s+', line, re.I):
                        in_trace = False
        if trace_lines:
            result['stack_trace'] = trace_lines

        # 原始描述 (截断至 4 KiB)
        result['description'] = text[:4096]

        return result

    def _guess_faulting_instruction(self, trace_line):
        if not trace_line:
            return ''
        m = re.search(r'(?:mov|call|jmp|lea|add|sub|cmp|test|xor|push|pop|ret|syscall|int)\s+[^\s,]+',
                      trace_line, re.I)
        return m.group(0) if m else trace_line[:80]


# ── 向后兼容模块级别名 ──────────────────────────────────────────────

RootCauseAnalysis = AnalysisReport

analyze_root_cause = AutoRootCauseAnalyzer().analyze


def format_root_cause_report(report):
    if hasattr(report, 'to_dict'):
        report = report.to_dict()
    elif hasattr(report, '__dict__'):
        report = report.__dict__

    lines = []
    lines.append("=" * 60)
    lines.append("ROOT CAUSE ANALYSIS REPORT")
    lines.append("=" * 60)
    if isinstance(report, dict):
        summary = report.get('summary', {})
        lines.append(f"  Crash Type:   {summary.get('crash_type', 'Unknown')}")
        lines.append(f"  Confidence:   {summary.get('confidence', 0):.1%}")
        lines.append(f"  Exploitability: {summary.get('exploitability', 'Unknown')}")
        lines.append(f"  CWE:          {summary.get('cwe', 'N/A')}")
        if summary.get('exact_hash'):
            lines.append(f"  Exact Hash:   {summary['exact_hash']}")
        if summary.get('fuzzy_hash'):
            lines.append(f"  Fuzzy Hash:   {summary['fuzzy_hash']}")
        caps = summary.get('capabilities_required', [])
        if caps:
            lines.append(f"  Capabilities: {', '.join(caps)}")
    return '\n'.join(lines)
