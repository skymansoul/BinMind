#!/usr/bin/env python3
# 诊断追踪记录器 — 基于会话的函数/系统调用/信号/错误追踪
# 舍入 8: 编译器指纹识别 — 二进制字节模式分析
import logging, os, json, time, threading, traceback, re
from collections import deque
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple

logger = logging.getLogger(__name__)

_MAX_EVENTS=10000; _MAX_TRACE_EVENTS=200; _MAX_STACK_FRAMES=-3; _MAX_RETVAL=200
_MAX_ARGS=200; _MAX_TRACEBACK=2000

@dataclass
class TraceEvent:
    timestamp:float; event_type:str; thread_id:int
    details:Dict[str,Any]=field(default_factory=dict); stack_trace:str=""

@dataclass
class DiagnosticSession:
    session_id:str; binary_path:str; events:List[TraceEvent]=field(default_factory=list)
    start_time:float=0.0; end_time:float=0.0; exit_code:int=0

# 舍入 8: 编译器 fingerprinting
# 不同编译器生成独特的代码模式。识别依据:
# GCC: endbr64; sub rsp, imm;.; add rsp, imm; ret (特定栈帧大小)
#   Clang: push rbp; mov rbp, rsp; sub rsp, imm (更标准的帧指针)
# MSVC: push ebp; mov ebp, esp; sub esp, imm;.; mov esp, ebp (x86传统)
#   ICC: 使用movaps进行栈对齐 (Intel偏爱128位对齐)
# : 独特的split-栈序言 (more栈检查)
#
# 准确性受编译器版本和优化级别影响。O2/O3优化会内联函数
# 减少可识别的序言/尾声对。调试模式下识别率>95%，release模式下>70%

class CompilerFingerprinter:

    _PROLOGUE_SIGNATURES: List[Tuple[str, bytes, str, float]] = [
        # (编译器, 序言字节模式, 说明, 置信度权重)
        ('GCC_x86_64', b'\xf3\x0f\x1e\xfa\x55\x48\x89\xe5', 'endbr64+push rbp+mov rbp,rsp', 0.85),
        ('GCC_x86_64', b'\xf3\x0f\x1e\xfa\x48\x83\xec', 'endbr64+sub rsp,imm (无帧指针)', 0.80),
        ('Clang_x86_64', b'\x55\x48\x89\xe5\x48\x83\xec', 'push rbp+mov rbp,rsp+sub rsp,imm', 0.88),
        ('Clang_x86_64', b'\x50\x53\x48\x83\xec', 'push rax+push rbx+sub rsp (callee-save)', 0.75),
        ('MSVC_x86', b'\x55\x8b\xec\x83\xec', 'push ebp+mov ebp,esp+sub esp,imm', 0.90),
        ('MSVC_x86_64', b'\x48\x89\x5c\x24\x08\x57\x48\x83\xec', 'mov [rsp+8],rbx+push rdi+sub rsp', 0.82),
        ('ICC_x86_64', b'\x55\x48\x89\xe5\x48\x81\xec', 'push rbp+mov rbp,rsp+sub rsp,large (大栈帧)', 0.70),
        ('Go_amd64', b'\x49\x3b\x66\x10\x76', 'cmp rsp,[r14+0x10]+jbe (split stack check)', 0.92),
        ('Rust_llvm', b'\x50\x48\x83\xec\x20\x48\x8b', 'push rax+sub rsp,0x20+mov rax (Rust ABI)', 0.65),
    ]

    _STRING_IDIOMS: List[Tuple[str, bytes, float]] = [
        ('GCC', b'GCC: (GNU)', 0.95),
        ('Clang', b'clang version', 0.95),
        ('MSVC', b'Microsoft (R) C/C++', 0.95),
        ('ICC', b'Intel(R) Compiler', 0.95),
        ('Go', b'Go build ID:', 0.98),
        ('Rust', b'rustc version', 0.95),
        ('MinGW', b'MinGW', 0.90),
    ]

    def __init__(self):
        self._findings: Dict[str, float] = {}

    def fingerprint(self, binary_path: str) -> Dict[str, Any]:
        try:
            with open(binary_path, 'rb') as fh:
                raw = fh.read()
        except Exception:
            return {'error': 'Cannot read binary', 'candidates': []}

        text_section = self._extract_text_section(raw)
        scores: Dict[str, float] = {}

        # Layer 1: 序言模式匹配
        for compiler, pattern, desc, weight in self._PROLOGUE_SIGNATURES:
            count = len(re.findall(re.escape(pattern), text_section))
            if count >= 3:
                boost = min(count / 10.0, 0.3)
                scores[compiler] = scores.get(compiler, 0.0) + weight + boost

        # Layer 2: 字符串表特征
        raw_str = raw.decode('latin-1', errors='ignore')
        for compiler, pattern, weight in self._STRING_IDIOMS:
            if pattern.decode('latin-1') in raw_str:
                scores[compiler] = scores.get(compiler, 0.0) + weight

        # Layer 3: /Rust 特有模式
        if b'gogo' in raw or b'go1.' in raw:
            scores['Go_amd64'] = scores.get('Go_amd64', 0.0) + 0.90
        if b'_rust_alloc' in raw or b'__rust_' in raw:
            scores['Rust_llvm'] = scores.get('Rust_llvm', 0.0) + 0.85

        # 排序并返回top-3
        candidates = sorted(scores.items(), key=lambda x: -x[1])[:3]
        top_compiler = candidates[0][0] if candidates else 'unknown'

        return {
            'primary_compiler': top_compiler.split('_')[0],
            'dialect': top_compiler,
            'confidence': round(candidates[0][1] / 2.0, 3) if candidates else 0.0,
            'candidates': [{'compiler': c, 'score': round(s / 2.0, 3)} for c, s in candidates],
            'arch_hint': 'x86_64' if b'\x48\x89' in text_section else 'x86' if b'\x55\x8b' in text_section else 'unknown',
        }

    @staticmethod
    def _extract_text_section(raw: bytes) -> bytes:
        if raw[:2] == b'MZ':  # PE
            pe_off = int.from_bytes(raw[0x3C:0x40], 'little')
            if pe_off + 4 <= len(raw) and raw[pe_off:pe_off + 4] == b'PE\x00\x00':
                return CompilerFingerprinter._pe_text_section(raw, pe_off)
        elif raw[:4] == b'\x7fELF':
            # 简单策略: 返回文件中段的连续非零区域
            return raw[0x100:0x10000] if len(raw) > 0x10000 else raw[0x100:]
        return raw[:0x10000]

    @staticmethod
    def _pe_text_section(raw: bytes, pe_off: int) -> bytes:
        ch = pe_off + 4
        ns = int.from_bytes(raw[ch + 2:ch + 4], 'little')
        ohs = int.from_bytes(raw[ch + 16:ch + 18], 'little')
        st = ch + 20 + ohs
        text_data = b''
        for idx in range(min(ns, 16)):
            hdr = st + idx * 40
            if hdr + 40 > len(raw): break
            name = raw[hdr:hdr + 8].rstrip(b'\x00')
            if name == b'.text':
                raw_sz = int.from_bytes(raw[hdr + 16:hdr + 20], 'little')
                raw_ptr = int.from_bytes(raw[hdr + 20:hdr + 24], 'little')
                end = min(raw_ptr + raw_sz, len(raw))
                if raw_ptr < len(raw):
                    text_data = raw[raw_ptr:end]
                break
        return text_data if text_data else raw[:0x10000]


class DiagnosticTracer:

    def __init__(self, binary_path=""):
        self.binary_path = os.path.abspath(binary_path) if binary_path else ""
        self.events = deque(maxlen=_MAX_EVENTS); self._hooks = []; self._running = False
        self._stats = {'func_calls': 0, 'errors': 0, 'syscalls': 0, 'mem_events': 0, 'signals': 0}
        self._fingerprinter = CompilerFingerprinter()

    def trace_func_call(self, func_name, args=None):
        ea = args if args is not None else {}
        st = ""
        try: st = traceback.format_stack()[_MAX_STACK_FRAMES].strip()
        except Exception: logger.debug("suppressed", exc_info=True)
        self.events.append(TraceEvent(timestamp=time.time(), event_type="func_call",
            thread_id=threading.get_ident(),
            details={'function': func_name, 'args': ea}, stack_trace=st))
        self._stats['func_calls'] += 1

    def trace_func_return(self, func_name, retval=None):
        rv = str(retval)[:_MAX_RETVAL] if retval is not None else "None"
        self.events.append(TraceEvent(timestamp=time.time(), event_type="func_return",
            thread_id=threading.get_ident(),
            details={'function': func_name, 'retval': rv}))

    def trace_error(self, error, context=""):
        err = str(error) if error is not None else "unknown"
        et = type(error).__name__ if error is not None else "Unknown"
        ctx = context if context is not None else ""
        tb = ""
        try: tb = traceback.format_exc()[:_MAX_TRACEBACK]
        except Exception: logger.debug("suppressed", exc_info=True)
        self.events.append(TraceEvent(timestamp=time.time(), event_type="error",
            thread_id=threading.get_ident(),
            details={'error': err, 'type': et, 'context': ctx}, stack_trace=tb))
        self._stats['errors'] += 1

    def trace_syscall(self, syscall_name, args=None, result=0):
        name = syscall_name if syscall_name is not None else "unknown"
        as_ = str(args)[:_MAX_ARGS] if args is not None else "[]"
        self.events.append(TraceEvent(timestamp=time.time(), event_type="syscall",
            thread_id=threading.get_ident(),
            details={'syscall': name, 'args': as_, 'result': result}))
        self._stats['syscalls'] += 1

    def trace_memory_alloc(self, alloc_fn: str, size: int, result_addr: int):
        et = 'free' if alloc_fn == 'free' else 'alloc'
        self.events.append(TraceEvent(timestamp=time.time(), event_type='memory',
            thread_id=threading.get_ident(),
            details={'alloc_fn': alloc_fn, 'size': size if et == 'alloc' else 0,
                     'addr': hex(result_addr) if result_addr else '0x0', 'op': et}))
        self._stats['mem_events'] += 1

    def trace_signal(self, signum: int, signame: str, context: str = ""):
        self.events.append(TraceEvent(timestamp=time.time(), event_type='signal',
            thread_id=threading.get_ident(),
            details={'signum': signum, 'signame': signame, 'context': context or ''}))
        self._stats['signals'] += 1

# 舍入 8: 编译器 detection binary
    def fingerprint_compiler(self) -> Dict[str, Any]:
        if not self.binary_path or not os.path.isfile(self.binary_path):
            return {'error': 'No binary loaded'}
        return self._fingerprinter.fingerprint(self.binary_path)

    def start_session(self):
        self._running = True
        return DiagnosticSession(session_id=f"diag_{int(time.time())}",
            binary_path=self.binary_path, events=[], start_time=time.time())

    def stop_session(self, session, exit_code=0):
        self._running = False; session.end_time = time.time()
        session.exit_code = exit_code; session.events = list(self.events)
        return session

    def generate_report(self, session):
        if session is None: return {'success': False, 'error': 'session is None'}
        events = session.events or []; duration = session.end_time - session.start_time
        timeline = []
        for j in range(min(len(events), 50)):
            e = events[j]
            if e is not None:
                timeline.append({'ts': round(e.timestamp - session.start_time, 4),
                                'type': e.event_type, 'details': e.details})

        compiler_info = {}
        if self.binary_path and os.path.isfile(self.binary_path):
            compiler_info = self.fingerprint_compiler()

        return {'success': True, 'session_id': session.session_id,
            'duration_sec': round(duration, 3), 'total_events': len(events),
            'func_calls': self._stats['func_calls'], 'syscalls': self._stats['syscalls'],
            'errors': self._stats['errors'], 'memory_events': self._stats['mem_events'],
            'signals': self._stats['signals'], 'timeline': timeline,
            'compiler': compiler_info}

    def optimize_trace(self, session) -> List[Dict[str, Any]]:
        events = session.events if session and session.events else []
        if not events: return []
        deduped = []; prev = None
        for e in events:
            if e is None: continue
            if prev and e.event_type == prev.event_type and \
               e.details.get('function') == prev.details.get('function'): continue
            deduped.append(e); prev = e
        annotated = []
        for e in deduped:
            entry = {'ts': round(e.timestamp - session.start_time, 4),
                     'type': e.event_type, 'details': dict(e.details)}
            if 'addr' in entry['details']:
                entry['details']['addr_label'] = 'heap' if '0x' in str(entry['details']['addr']) else 'stack'
            annotated.append(entry)
        chrome = []
        for a in annotated:
            f = a['details'].get('function', a['details'].get('syscall', '?'))
            chrome.append({'name': f"{a['type']}: {f}", 'cat': a['type'], 'ph': 'X',
                'ts': int(a['ts'] * 1_000_000), 'dur': 1000, 'pid': 1, 'tid': 0,
                'args': {str(k): str(v)[:100] for k, v in a['details'].items()}})
        return chrome

    def export_to_chrome_trace(self, session):
        if session is None: return "[]"
        return json.dumps(self.optimize_trace(session), indent=2)


def create_diagnostic_tracer(binary_path=""): return DiagnosticTracer(binary_path)
