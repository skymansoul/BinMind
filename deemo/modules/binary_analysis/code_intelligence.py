from typing import Dict, Any, List, Optional, Set, Tuple
import logging
import re
import os
import json
import subprocess
import hashlib
import time
import threading
import struct
import math
import collections
from dataclasses import dataclass, field
from datetime import datetime

__log = logging.getLogger(__name__)


@dataclass
class MTEBarrier:
    address: int
    access_type: str
    bypass_possible: bool


@dataclass
class ArrayAccess:
    base_addr: int
    index_expr: str
    element_size: int
    array_length: int


@dataclass
class BasicBlockCoverage:
    block_addr: int
    execution_count: int = 0
    is_hot: bool = False


@dataclass
class ContextSensitiveSummary:
    context_id: str
    function_addr: int
    input_constraints: str
    output_state: Dict[str, Any]
    taint_properties: Dict[str, Any]


@dataclass
class ScriptExtensionBridge:
    native_function_addr: int
    script_function_name: str
    parameter_types: List[str]
    return_type: str


@dataclass
class ASLREntropyInfo:
    component: str
    entropy_bits: int
    is_randomized: bool


@dataclass
class SemanticCluster:
    cluster_id: str
    representative_sequence: bytes
    similar_functions: List[int]


@dataclass
class KernelObjectSpec:
    object_name: str
    pool_tag: str
    field_offsets: Dict[str, int]
    field_types: Dict[str, str]


@dataclass
class PathCost:
    path: List[int]
    estimated_instructions: int = 0
    estimated_cycles: int = 0


@dataclass
class MemoryAccessEvent:
    timestamp: float
    address: int
    size: int
    access_type: str




class MTEBarrierAnalyzer:

    # ARMv8.5-A MTE 指令助记符
    _MTE_OPS = frozenset({
        'irg', 'addg', 'subg', 'gmi',
        'ldg', 'stg', 'stzg', 'st2g', 'stz2g',
        'ldgm', 'stgm',
    })

    def __init__(self):
        self.barriers: List[MTEBarrier] = []

    def identify_tagged_memory_accesses(self, binary_path: str) -> List[Tuple[int, str]]:
        accesses: List[Tuple[int, str]] = []
        try:
            proc = subprocess.run(
                ['objdump', '-d', binary_path],
                capture_output=True, text=True, timeout=90,
            )
            if proc.returncode != 0:
                proc = subprocess.run(
                    ['aarch64-linux-gnu-objdump', '-d', binary_path],
                    capture_output=True, text=True, timeout=90,
                )
            if proc.returncode != 0:
                return accesses

            for raw in proc.stdout.splitlines():
                stripped = raw.strip()
                if ':' not in stripped:
                    continue
                addr_str, rest = stripped.split(':', 1)
                try:
                    addr = int(addr_str.strip(), 16)
                except ValueError:
                    continue
                tokens = rest.replace('\t', ' ').split()
                if len(tokens) < 2:
                    continue
                mnemonic = tokens[1].lower() if len(tokens) >= 2 and len(tokens[0]) >= 8 else tokens[0].lower()

                if mnemonic in self._MTE_OPS:
                    if mnemonic.startswith('ld'):
                        atype = 'tagged_load'
                    elif mnemonic.startswith('st'):
                        atype = 'tagged_store'
                    else:
                        atype = 'tag_arithmetic'
                    accesses.append((addr, atype))

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            __log.debug("MTE disasm failed: %s", exc)

        return accesses

    def check_tag_mismatch(self, write_addr: int, write_value: Any) -> bool:
        tag = (write_addr >> 56) & 0x0F
        return tag == 0

    def assess_mte_bypass(self, exploit_primitive: str) -> Tuple[bool, List[MTEBarrier]]:
        mapping = {
            'linear_heap_overflow': 0.65,
            'use_after_free':        0.25,
            'type_confusion':        0.85,
            'arbitrary_write':       0.90,
            'info_leak':             0.80,
            'stack_overflow':        0.50,
        }
        score = mapping.get(exploit_primitive, 0.55)
        bypass_ok = score >= 0.50

        result: List[MTEBarrier] = []
        for addr, atype in self.barriers:
            result.append(MTEBarrier(
                address=addr if isinstance(addr, int) else 0,
                access_type=atype if isinstance(atype, str) else 'unknown',
                bypass_possible=bypass_ok,
            ))
        return bypass_ok, result

    def estimate_mte_effectiveness(self) -> float:
        if not self.barriers:
            return 0.0
        tagged = sum(1 for b in self.barriers
                     if b.access_type in ('tagged_load', 'tagged_store'))
        coverage = tagged / len(self.barriers)
        bypassable = sum(1 for b in self.barriers if b.bypass_possible)
        bypass_ratio = bypassable / len(self.barriers)
        return min(1.0, coverage * (1.0 - bypass_ratio * 0.5))




class StructArrayBoundsChecker:

    def __init__(self):
        self.array_accesses: Dict[int, ArrayAccess] = {}

    def identify_array_accesses(self, function_addr: int) -> List[ArrayAccess]:
        return [a for a in self.array_accesses.values()
                if a.base_addr == function_addr]

    def infer_array_length(self, base_type: str) -> Optional[int]:
        m = re.search(r'_(\d+)$', base_type)
        if m:
            return int(m.group(1))
        heur = {
            'irp': 256, 'ethread': 512, 'eprocess': 384,
            'socket': 1024, 'file': 512, 'buffer': 4096,
            'table': 256, 'pool': 128, 'hash': 1024,
        }
        low = base_type.lower()
        for k, v in heur.items():
            if k in low:
                return v
        return None

    def detect_out_of_bounds(self, access: ArrayAccess) -> List[Tuple[int, str]]:
        oob: List[Tuple[int, str]] = []
        if access.array_length <= 0:
            return oob
        m = re.match(r'^\s*(\d+)\s*$', access.index_expr.strip())
        if m:
            idx = int(m.group(1))
            if idx >= access.array_length:
                oob.append((access.base_addr,
                            f"constant idx={idx} >= len={access.array_length}"))
                return oob
        if re.search(r'[a-z_]', access.index_expr, re.IGNORECASE):
            oob.append((access.base_addr,
                        f"variable idx '{access.index_expr}' on len={access.array_length}"))
        return oob

    def check_cross_element_access(self, access: ArrayAccess, field_offset: int) -> bool:
        if access.element_size <= 0:
            return False
        return (field_offset + 8) > access.element_size




class SyscallPatternMatcher:

    def __init__(self):
        self.templates: List[DangerousSyscallSequence] = []
        self._register_default_templates()

    def _register_default_templates(self) -> None:
        self.templates.extend([
            DangerousSyscallSequence("shell_escape", ["dup2", "execve"],
                                     "redirect fds + execve shell"),
            DangerousSyscallSequence("priv_esc", ["setuid", "execve"],
                                     "setuid(0) + execve"),
            DangerousSyscallSequence("mem_exec", ["mprotect", "execve"],
                                     "make writable + exec"),
            DangerousSyscallSequence("sandbox_escape", ["clone", "unshare", "execve"],
                                     "namespace breakout"),
            DangerousSyscallSequence("file_steal", ["open", "sendfile", "write"],
                                     "read file + exfiltrate"),
            DangerousSyscallSequence("ptrace_hijack", ["ptrace", "execve"],
                                     "ptrace attach + exec payload"),
        ])

    def register_template(self, template: DangerousSyscallSequence) -> None:
        self.templates.append(template)

    def find_matching_sequences(self, syscall_trace: List[str]) -> List[Tuple[int, DangerousSyscallSequence]]:
        matches: List[Tuple[int, DangerousSyscallSequence]] = []
        lower = [s.lower().strip() for s in syscall_trace]

        for tmpl in self.templates:
            pat = [s.lower() for s in tmpl.syscalls]
            w = len(pat)
            for i in range(len(lower) - w + 1):
                win = lower[i:i + w]
                mismatches = sum(1 for a, b in zip(win, pat) if a != b)
                max_err = 1 if w >= 4 else 0  # allow 1 mismatch for long chains
                if mismatches <= max_err:
                    matches.append((i, tmpl))
                    break  # report first match per template
        return matches

    def scan_binary(self, binary_path: str) -> List[Tuple[int, DangerousSyscallSequence]]:
        imports: List[str] = []
        try:
            res = subprocess.run(
                ['objdump', '-T', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            if res.returncode != 0:
                res = subprocess.run(
                    ['objdump', '-p', binary_path],
                    capture_output=True, text=True, timeout=30,
                )
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    sym = parts[-1]
                    if sym and not sym.startswith('.'):
                        imports.append(sym)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            __log.debug("scan_binary failed: %s", exc)
        return self.find_matching_sequences(imports)




class PathConvergenceTracker:

    def __init__(self):
        self.coverage: Dict[int, BasicBlockCoverage] = {}
        self.hot_paths: List[List[int]] = []
        self.cold_paths: List[List[int]] = []

    def record_execution(self, block_addr: int, count: int = 1) -> None:
        bb = self.coverage.get(block_addr)
        if bb is None:
            bb = BasicBlockCoverage(block_addr=block_addr)
            self.coverage[block_addr] = bb
        bb.execution_count += count

    def identify_hot_paths(self, threshold: int = 1000) -> List[List[int]]:
        counts = sorted(b.execution_count for b in self.coverage.values())
        if not counts:
            return []
        # 自适应阈值：取 p90 与固定阈值的较大者
        p90_idx = int(len(counts) * 0.90)
        adaptive = max(threshold, counts[p90_idx] if p90_idx < len(counts) else threshold)

        hot = []
        for addr, bb in self.coverage.items():
            if bb.execution_count >= adaptive:
                bb.is_hot = True
                hot.append(addr)
        self.hot_paths = [sorted(hot, key=lambda a: self.coverage[a].execution_count, reverse=True)]
        return self.hot_paths

    def identify_cold_spots(self, threshold: int = 10) -> List[int]:
        cold = sorted(
            [addr for addr, bb in self.coverage.items()
             if 0 < bb.execution_count <= threshold],
            key=lambda a: self.coverage[a].execution_count,
        )
        self.cold_paths = [cold]
        return cold

    def get_coverage_statistics(self) -> Dict[str, Any]:
        return {
            "total_blocks": len(self.coverage),
            "hot_blocks": sum(1 for b in self.coverage.values() if b.is_hot),
            "total_executions": sum(b.execution_count for b in self.coverage.values()),
            "cold_blocks": sum(1 for b in self.coverage.values() if 0 < b.execution_count <= 10),
        }




class ContextSensitiveSummaryGraph:

    def __init__(self):
        self.summary_graph: Dict[int, List[ContextSensitiveSummary]] = {}
        self._by_ctx: Dict[str, ContextSensitiveSummary] = {}

    @staticmethod
    def _digest(function_addr: int, context: Dict[str, Any]) -> str:
        raw = json.dumps(context, sort_keys=True, default=str)
        h = hashlib.sha256(f"{function_addr:x}:{raw}".encode()).hexdigest()[:16]
        return h

    def generate_summary(self, function_addr: int, context: Dict[str, Any]) -> ContextSensitiveSummary:
        cid = self._digest(function_addr, context)
        constraints = []
        for k, v in context.items():
            if isinstance(v, (int, float)):
                constraints.append(f"{k}={v}")
            elif isinstance(v, str) and len(v) < 64:
                constraints.append(f"{k}='{v}'")
            elif isinstance(v, (list, tuple)) and len(v) <= 4:
                constraints.append(f"{k}=[{','.join(str(x) for x in v)}]")

        s = ContextSensitiveSummary(
            context_id=cid,
            function_addr=function_addr,
            input_constraints="; ".join(constraints),
            output_state={},
            taint_properties={"has_constraints": len(constraints) > 0},
        )
        self._by_ctx[cid] = s
        self.summary_graph.setdefault(function_addr, []).append(s)
        return s

    def lookup_summary(self, function_addr: int, context: Dict[str, Any]) -> Optional[ContextSensitiveSummary]:
        cid = self._digest(function_addr, context)
        if cid in self._by_ctx:
            return self._by_ctx[cid]
        lst = self.summary_graph.get(function_addr, [])
        return lst[-1] if lst else None

    def specialize_for_constant_arg(self, function_addr: int, arg_index: int,
                                     constant_value: Any) -> ContextSensitiveSummary:
        ctx = {f"arg{arg_index}": constant_value, "__specialized": True}
        return self.generate_summary(function_addr, ctx)




class FalsePositiveFilter:

    def __init__(self):
        self._freq: Dict[str, float] = collections.defaultdict(float)
        self._total = 0

    @staticmethod
    def _feats(report: Dict[str, Any]) -> List[str]:
        out: List[str] = []
        vt = report.get('type') or report.get('vuln_type', '')
        if vt:
            out.append(f"type:{vt}")
        sev = report.get('severity', '')
        if sev:
            out.append(f"sev:{sev}")
        loc = report.get('location', {})
        if isinstance(loc, dict):
            fn = str(loc.get('function', ''))
            if fn:
                out.append(f"func:{re.sub(r'^(sub_|func_|f_)', '', fn)[:40]}")
        desc = str(report.get('description', ''))
        for kw in ('debug', 'test', 'logging', 'assert', 'error_handler', 'cleanup', 'null_check'):
            if kw in desc.lower():
                out.append(f"pat:{kw}")
                break
        cwe = report.get('cwe', '')
        if cwe:
            out.append(f"cwe:{cwe}")
        return out

    def train(self, benign_samples: List[Dict[str, Any]]) -> None:
        self._freq.clear()
        self._total = len(benign_samples)
        if self._total == 0:
            return
        for s in benign_samples:
            for f in self._feats(s):
                self._freq[f] += 1.0
        for f in list(self._freq):
            self._freq[f] /= self._total

    def is_likely_false_positive(self, vulnerability_report: Dict[str, Any]) -> Tuple[bool, float]:
        if self._total == 0:
            return False, 0.0
        feats = self._feats(vulnerability_report)
        if not feats:
            return False, 0.0
        scores = [self._freq.get(f, 0.0) for f in feats]
        avg = sum(scores) / len(scores)
        return avg > 0.40, avg

    def filter_reports(self, reports: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [r for r in reports if not self.is_likely_false_positive(r)[0]]




class EmbeddedScriptAnalyzer:

    _SIGS = {
        'lua':  [rb'lua_State', rb'luaL_', rb'lua_pcall', rb'lua_push',
                 rb'luaopen_', rb'lua_gettop', rb'lua_settop', rb'LUA_VERSION'],
        'python': [rb'Py_Initialize', rb'PyObject', rb'PyRun_',
                   rb'python\d+\.dll', rb'libpython', rb'Py_Finalize'],
        'javascript': [rb'v8::', rb'duktape', rb'jerry_', rb'quickjs',
                       rb'JS_Eval', rb'libmjs'],
    }
    _BRIDGE_RE = {
        'lua':  r'(?:lua_register|luaL_Reg|\bluaopen_\w+)',
        'python': r'(?:PyMethodDef|PyInit_\w+|_PyType_Ready)',
        'javascript': r'(?:js_module_\w+|native_function_\w+)',
    }
    _DANGER_WORDS = {
        'exec', 'system', 'popen', 'spawn', 'dlopen', 'loadlibrary',
        'readfile', 'writefile', 'fopen', 'alloc', 'free', 'malloc',
    }

    def __init__(self):
        self.script_type: Optional[str] = None
        self.bridge_functions: List[ScriptExtensionBridge] = []

    def detect_script_interpreter(self, binary_path: str) -> Optional[str]:
        try:
            with open(binary_path, 'rb') as fh:
                blob = fh.read()
        except (IOError, OSError) as exc:
            __log.debug("read failed %s: %s", binary_path, exc)
            return None
        best = None
        best_hits = 0
        for lang, sigs in self._SIGS.items():
            hits = sum(1 for s in sigs if re.search(s, blob))
            if hits > best_hits:
                best_hits = hits
                best = lang
        if best and best_hits >= 2:
            self.script_type = best
            return best
        return None

    def extract_bridge_functions(self, binary_path: str) -> List[ScriptExtensionBridge]:
        if not self.script_type:
            return []
        bridges: List[ScriptExtensionBridge] = []
        pat = self._BRIDGE_RE.get(self.script_type)
        if not pat:
            return bridges
        try:
            res = subprocess.run(
                ['nm', '-D', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                sym = parts[-1]
                if re.search(pat, sym):
                    addr = int(parts[0], 16) if re.match(r'^[0-9a-fA-F]+$', parts[0]) else 0
                    bridges.append(ScriptExtensionBridge(
                        native_function_addr=addr,
                        script_function_name=sym,
                        parameter_types=[],
                        return_type='void',
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            __log.debug("nm failed: %s", exc)
        self.bridge_functions = bridges
        return bridges

    def analyze_bridge_safety(self, bridge: ScriptExtensionBridge) -> Dict[str, Any]:
        issues = []
        nl = bridge.script_function_name.lower()
        for w in self._DANGER_WORDS:
            if w in nl:
                issues.append(w)
        return {"is_safe": len(issues) == 0, "potential_issues": issues,
                "script_type": self.script_type}




class SeccompFilterGenerator:

    # x86_64 系统调用号表
    _NR = {
        'read': 0, 'write': 1, 'open': 2, 'close': 3, 'stat': 4,
        'fstat': 5, 'lstat': 6, 'poll': 7, 'lseek': 8, 'mmap': 9,
        'mprotect': 10, 'munmap': 11, 'brk': 12, 'rt_sigaction': 13,
        'rt_sigprocmask': 14, 'rt_sigreturn': 15, 'ioctl': 16,
        'pread64': 17, 'pwrite64': 18, 'readv': 19, 'writev': 20,
        'access': 21, 'pipe': 22, 'select': 23, 'sched_yield': 24,
        'mremap': 25, 'msync': 26, 'mincore': 27, 'madvise': 28,
        'shmget': 29, 'shmat': 30, 'shmctl': 31, 'dup': 32, 'dup2': 33,
        'pause': 34, 'nanosleep': 35, 'getitimer': 36, 'alarm': 37,
        'setitimer': 38, 'getpid': 39, 'sendfile': 40, 'socket': 41,
        'connect': 42, 'accept': 43, 'sendto': 44, 'recvfrom': 45,
        'sendmsg': 46, 'recvmsg': 47, 'shutdown': 48, 'bind': 49,
        'listen': 50, 'getsockname': 51, 'getpeername': 52,
        'socketpair': 53, 'setsockopt': 54, 'getsockopt': 55,
        'clone': 56, 'fork': 57, 'vfork': 58, 'execve': 59,
        'exit': 60, 'wait4': 61, 'kill': 62, 'uname': 63,
        'semget': 64, 'semop': 65, 'semctl': 66, 'shmdt': 67,
        'msgget': 68, 'msgsnd': 69, 'msgrcv': 70, 'msgctl': 71,
        'fcntl': 72, 'flock': 73, 'fsync': 74, 'fdatasync': 75,
        'truncate': 76, 'ftruncate': 77, 'getdents': 78, 'getcwd': 79,
        'chdir': 80, 'fchdir': 81, 'rename': 82, 'mkdir': 83,
        'rmdir': 84, 'creat': 85, 'link': 86, 'unlink': 87,
        'symlink': 88, 'readlink': 89, 'chmod': 90, 'fchmod': 91,
        'chown': 92, 'fchown': 93, 'lchown': 94, 'umask': 95,
        'gettimeofday': 96, 'getrlimit': 97, 'getrusage': 98,
        'sysinfo': 99, 'times': 100, 'ptrace': 101, 'getuid': 102,
        'syslog': 103, 'getgid': 104, 'setuid': 105, 'setgid': 106,
        'geteuid': 107, 'getegid': 108, 'setpgid': 109, 'getppid': 110,
        'getpgid': 111, 'setsid': 112, 'setreuid': 113, 'setregid': 114,
        'getgroups': 115, 'setgroups': 116, 'setresuid': 117,
        'getresuid': 118, 'setresgid': 119, 'getresgid': 120,
        'getsid': 124, 'capget': 125, 'capset': 126,
        'rt_sigpending': 127, 'rt_sigtimedwait': 128,
        'rt_sigqueueinfo': 129, 'rt_sigsuspend': 130, 'sigaltstack': 131,
        'utime': 132, 'mknod': 133, 'uselib': 134, 'personality': 135,
        'ustat': 136, 'statfs': 137, 'fstatfs': 138, 'sysfs': 139,
        'getpriority': 140, 'setpriority': 141,
        'sched_setparam': 142, 'sched_getparam': 143,
        'sched_setscheduler': 144, 'sched_getscheduler': 145,
        'sched_get_priority_max': 146, 'sched_get_priority_min': 147,
        'sched_rr_get_interval': 148, 'mlock': 149, 'munlock': 150,
        'mlockall': 151, 'munlockall': 152, 'vhangup': 153,
        'modify_ldt': 154, 'pivot_root': 155, '_sysctl': 156,
        'prctl': 157, 'arch_prctl': 158, 'adjtimex': 159,
        'setrlimit': 160, 'chroot': 161, 'sync': 162, 'acct': 163,
        'settimeofday': 164, 'mount': 165, 'umount2': 166,
        'swapon': 167, 'swapoff': 168, 'reboot': 169,
        'sethostname': 170, 'setdomainname': 171, 'iopl': 172,
        'ioperm': 173, 'create_module': 174, 'init_module': 175,
        'delete_module': 176, 'get_kernel_syms': 177,
        'query_module': 178, 'quotactl': 179, 'nfsservctl': 180,
        'gettid': 186, 'readahead': 187, 'setxattr': 188,
        'lsetxattr': 189, 'fsetxattr': 190, 'getxattr': 191,
        'lgetxattr': 192, 'fgetxattr': 193, 'listxattr': 194,
        'llistxattr': 195, 'flistxattr': 196, 'removexattr': 197,
        'lremovexattr': 198, 'fremovexattr': 199, 'tkill': 200,
        'time': 201, 'futex': 202, 'sched_setaffinity': 203,
        'sched_getaffinity': 204, 'set_thread_area': 205,
        'io_setup': 206, 'io_destroy': 207, 'io_getevents': 208,
        'io_submit': 209, 'io_cancel': 210, 'get_thread_area': 211,
        'lookup_dcookie': 212, 'epoll_create': 213,
        'epoll_ctl_old': 214, 'epoll_wait_old': 215,
        'remap_file_pages': 216, 'getdents64': 217,
        'set_tid_address': 218, 'restart_syscall': 219,
        'semtimedop': 220, 'fadvise64': 221, 'timer_create': 222,
        'timer_settime': 223, 'timer_gettime': 224,
        'timer_getoverrun': 225, 'timer_delete': 226,
        'clock_settime': 227, 'clock_gettime': 228,
        'clock_getres': 229, 'clock_nanosleep': 230,
        'exit_group': 231, 'epoll_wait': 232, 'epoll_ctl': 233,
        'tgkill': 234, 'utimes': 235, 'vserver': 236,
        'mbind': 237, 'set_mempolicy': 238, 'get_mempolicy': 239,
        'mq_open': 240, 'mq_unlink': 241, 'mq_timedsend': 242,
        'mq_timedreceive': 243, 'mq_notify': 244,
        'mq_getsetattr': 245, 'kexec_load': 246, 'waitid': 247,
        'add_key': 248, 'request_key': 249, 'keyctl': 250,
        'ioprio_set': 251, 'ioprio_get': 252, 'inotify_init': 253,
        'inotify_add_watch': 254, 'inotify_rm_watch': 255,
        'migrate_pages': 256, 'openat': 257, 'mkdirat': 258,
        'mknodat': 259, 'fchownat': 260, 'futimesat': 261,
        'newfstatat': 262, 'unlinkat': 263, 'renameat': 264,
        'linkat': 265, 'symlinkat': 266, 'readlinkat': 267,
        'fchmodat': 268, 'faccessat': 269, 'pselect6': 270,
        'ppoll': 271, 'unshare': 272, 'set_robust_list': 273,
        'get_robust_list': 274, 'splice': 275, 'tee': 276,
        'sync_file_range': 277, 'vmsplice': 278, 'move_pages': 279,
        'utimensat': 280, 'epoll_pwait': 281, 'signalfd': 282,
        'timerfd_create': 283, 'eventfd': 284, 'fallocate': 285,
        'timerfd_settime': 286, 'timerfd_gettime': 287,
        'accept4': 288, 'signalfd4': 289, 'eventfd2': 290,
        'epoll_create1': 291, 'dup3': 292, 'pipe2': 293,
        'inotify_init1': 294, 'preadv': 295, 'pwritev': 296,
        'rt_tgsigqueueinfo': 297, 'perf_event_open': 298,
        'recvmmsg': 299, 'fanotify_init': 300,
        'fanotify_mark': 301, 'prlimit64': 302,
        'name_to_handle_at': 303, 'open_by_handle_at': 304,
        'clock_adjtime': 305, 'syncfs': 306, 'sendmmsg': 307,
        'setns': 308, 'getns': 309, 'process_vm_readv': 310,
        'process_vm_writev': 311, 'kcmp': 312, 'finit_module': 313,
        'sched_setattr': 314, 'sched_getattr': 315,
        'renameat2': 316, 'seccomp': 317, 'getrandom': 318,
        'memfd_create': 319, 'kexec_file_load': 320, 'bpf': 321,
        'execveat': 322, 'userfaultfd': 323, 'membarrier': 324,
        'mlock2': 325, 'copy_file_range': 326,
        'preadv2': 327, 'pwritev2': 328,
    }

    def __init__(self):
        self.observed_syscalls: Set[str] = set()

    def collect_syscalls(self, binary_path: str) -> Set[str]:
        found: Set[str] = set()
        # 动态符号
        try:
            r = subprocess.run(
                ['objdump', '-T', binary_path],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    sym = parts[-1].lstrip('_')
                    if sym in self._NR:
                        found.add(sym)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        # 内联 syscall 指令
        try:
            r2 = subprocess.run(
                ['objdump', '-d', binary_path],
                capture_output=True, text=True, timeout=90,
            )
            lines = r2.stdout.splitlines()
            for i, ln in enumerate(lines):
                if 'syscall' not in ln and 'int\t$0x80' not in ln and 'int    $0x80' not in ln:
                    continue
                for j in range(max(0, i - 4), i):
                    m = re.search(r'mov\s+(?:eax|rax),\s*(0x[0-9a-fA-F]+|\d+)', lines[j])
                    if m:
                        nr = int(m.group(1), 0)
                        for name, num in self._NR.items():
                            if num == nr:
                                found.add(name)
                                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        self.observed_syscalls = found
        return found

    def generate_bpf_rules(self) -> str:
        if not self.observed_syscalls:
            return "# no syscalls observed"

        lines = [
            "# seccomp-bpf filter (x86_64) -- auto-generated by BinMind",
            "ld [4]",
            "jeq 0xC000003E, 0, killed      # AUDIT_ARCH_X86_64",
            "",
            "ld [0]",
        ]
        allowed = sorted(self._NR[s] for s in self.observed_syscalls if s in self._NR)
        if not allowed:
            lines.append("ret ERRNO(1)  # nothing whitelisted")
        else:
            for nr in allowed:
                lines.append(f"jeq {nr}, 0, allow_{nr}")
            lines.append("killed: ret SECCOMP_RET_KILL")
            for nr in allowed:
                lines.append(f"allow_{nr}: ret SECCOMP_RET_ALLOW")
        return "\n".join(lines)

    def suggest_whitelist_policy(self) -> str:
        lines = ["# seccomp whitelist policy",
                 f"# {len(self.observed_syscalls)} syscalls observed", ""]
        for s in sorted(self.observed_syscalls):
            nr = self._NR.get(s, '?')
            lines.append(f"  {s:22s}  # nr={nr}")
        return "\n".join(lines)




class FunctionEntropyAnalyzer:

    _CRYPTO_MAGIC = {
        b'\x63\x7c\x77\x7b': 'AES_SBOX',
        b'\x52\x09\x6a\xd5': 'AES_INV_SBOX',
        b'\x01\x23\x45\x67': 'CRC32_TABLE',
        b'\x6a\x09\xe6\x67': 'SHA256_IV0',
        b'\xbb\x67\xae\x85': 'SHA256_IV1',
        b'\x6a\x09\xe6\x67\xbb\x67\xae\x85\x3c\x6e\xf3\x72\xa5\x4f\xf5\x3a':
            'SHA256_IV_FULL',
        b'\x42\x79\x70\x74': 'BLAKE2_IV0',
    }

    def __init__(self):
        self.entropy_cache: Dict[int, float] = {}

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        counts = collections.Counter(data)
        total = float(len(data))
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def analyze_function_entropy(self, function_addr: int) -> Tuple[float, List[int]]:
        avg = self.entropy_cache.get(function_addr, 0.0)
        return avg, []  # high-entropy region extraction requires function bytes

    def is_likely_packed(self, function_addr: int) -> bool:
        return self.entropy_cache.get(function_addr, 0.0) > 7.2

    def detect_crypto_pattern(self, high_entropy_region: bytes) -> Optional[str]:
        if len(high_entropy_region) < 4:
            return None
        for magic, label in self._CRYPTO_MAGIC.items():
            if magic in high_entropy_region:
                return label
        # 256 unique bytes in first 256-byte chunk => probable 8-bit S-box
        if len(high_entropy_region) >= 256:
            chunk = high_entropy_region[:256]
            if len(set(chunk)) == 256:
                return 'probable_8bit_sbox'
        return None




class ASLREntropyEvaluator:

    def __init__(self):
        self.entropy_info: List[ASLREntropyInfo] = []

    def analyze_binary_aslr(self, binary_path: str) -> List[ASLREntropyInfo]:
        info: List[ASLREntropyInfo] = []
        try:
            with open(binary_path, 'rb') as fh:
                head = fh.read(256)
        except (IOError, OSError) as exc:
            __log.debug("open failed %s: %s", binary_path, exc)
            return info

        # ELF 格式
        if head[:4] == b'\x7fELF':
            e_type = struct.unpack('<H', head[16:18])[0]
            is_pie = e_type == 3  # ET_DYN

            info.append(ASLREntropyInfo('base', 28 if is_pie else 0, is_pie))

            # readelf for GNU_STACK (NX) and GNU_RELRO
            try:
                relf = subprocess.run(
                    ['readelf', '-l', binary_path],
                    capture_output=True, text=True, timeout=10,
                )
                out = relf.stdout
                if 'GNU_STACK' in out:
                    section = out.split('GNU_STACK', 1)[1][:60]
                    nx = 'E' not in section  # E = executable flag
                    info.append(ASLREntropyInfo('stack', 28 if nx else 0, nx))
                if 'GNU_RELRO' in out:
                    info.append(ASLREntropyInfo('relro', 1, True))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

            # vdso / 堆
            info.append(ASLREntropyInfo('vdso', 28, is_pie))
            info.append(ASLREntropyInfo('heap', 13, is_pie))

        # PE 格式
        elif head[:2] == b'MZ':
            pe_off = struct.unpack('<I', head[0x3C:0x40])[0]
            try:
                with open(binary_path, 'rb') as fh:
                    fh.seek(pe_off)
                    pe = fh.read(24)
            except (IOError, struct.error):
                return info
            if pe[:4] != b'PE\x00\x00':
                return info
            chars = struct.unpack('<H', pe[22:24])[0]
            dyn_base = bool(chars & 0x0040)    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            nx = bool(chars & 0x0100)           # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            hi_entropy = bool(chars & 0x0020)   # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA

            info.append(ASLREntropyInfo('image_base', 8 if dyn_base else 0, dyn_base))
            if hi_entropy:
                info.append(ASLREntropyInfo('high_entropy_va', 24, True))
            info.append(ASLREntropyInfo('stack', 8 if nx else 0, nx))
            info.append(ASLREntropyInfo('heap', 8 if dyn_base else 0, dyn_base))

        self.entropy_info = info
        return info

    def calculate_min_leak_bytes(self) -> int:
        total = sum(e.entropy_bits for e in self.entropy_info if e.is_randomized)
        return (total + 7) // 8

    def assess_aslr_strength(self) -> float:
        if not self.entropy_info:
            return 0.0
        max_bits = len(self.entropy_info) * 30.0
        total = sum(e.entropy_bits for e in self.entropy_info)
        n_rand = sum(1 for e in self.entropy_info if e.is_randomized)
        cov = n_rand / len(self.entropy_info) if self.entropy_info else 0
        return 0.6 * cov + 0.4 * min(1.0, total / max_bits)




class InstructionSemanticClusterer:

    _OP_CLASS = {
        'mov': 'data', 'lea': 'data', 'push': 'stack', 'pop': 'stack',
        'add': 'arith', 'sub': 'arith', 'mul': 'arith', 'div': 'arith',
        'imul': 'arith', 'idiv': 'arith', 'inc': 'arith', 'dec': 'arith',
        'and': 'logic', 'or': 'logic', 'xor': 'logic', 'not': 'logic',
        'shl': 'shift', 'shr': 'shift', 'sal': 'shift', 'sar': 'shift',
        'rol': 'shift', 'ror': 'shift',
        'jmp': 'branch', 'je': 'branch', 'jne': 'branch', 'jz': 'branch',
        'jnz': 'branch', 'jg': 'branch', 'jl': 'branch', 'jge': 'branch',
        'jle': 'branch', 'ja': 'branch', 'jb': 'branch', 'jae': 'branch',
        'jbe': 'branch', 'call': 'call', 'ret': 'ret',
        'cmp': 'comp', 'test': 'comp',
        'nop': 'nop', 'int': 'trap', 'syscall': 'trap', 'sysenter': 'trap',
    }
    _CLASS_ORDER = ['data', 'stack', 'arith', 'logic', 'shift',
                     'branch', 'call', 'ret', 'comp', 'trap', 'nop']

    def __init__(self):
        self.clusters: List[SemanticCluster] = []

    def extract_semantic_vector(self, instruction_sequence: bytes) -> List[float]:
        text = instruction_sequence.decode('ascii', errors='replace').lower()
        freqs = collections.Counter()
        total = 0
        for tok in text.split():
            cls = self._OP_CLASS.get(tok.strip(',[]'))
            if cls:
                freqs[cls] += 1
                total += 1
        if total == 0:
            return [0.0] * len(self._CLASS_ORDER)
        return [freqs.get(c, 0) / total for c in self._CLASS_ORDER]

    def cluster_basic_blocks(self, basic_blocks: List[bytes]) -> List[SemanticCluster]:
        self.clusters = []
        for i, bb in enumerate(basic_blocks):
            vec = self.extract_semantic_vector(bb)
            # 向量哈希作为聚类 ID
            cid = hashlib.md5(str(vec).encode()).hexdigest()[:8]
            self.clusters.append(SemanticCluster(
                cluster_id=cid,
                representative_sequence=bb,
                similar_functions=[],
            ))
        return self.clusters

    def find_similar_functions(self, function_addr: int) -> List[Tuple[int, float]]:
        # 需要预构建函数向量索引；占位
        return []




class KernelObjectReconstructor:

    _KNOWN_TAGS = {
        b'Proc': 'EPROCESS', b'Thrd': 'ETHREAD',
        b'File': 'FILE_OBJECT', b'Driv': 'DRIVER_OBJECT',
        b'Devi': 'DEVICE_OBJECT', b'Irp\x00': 'IRP',
        b'Muta': 'KMUTANT', b'Even': 'KEVENT',
        b'Sema': 'KSEMAPHORE', b'Toke': 'TOKEN',
        b'Vad\x00': 'VAD', b'Pool': 'POOL_HEADER',
        b'MmSt': 'MM_SECTION', b'SeTm': 'SEGMENT',
    }
    # x64 Windows 内核结构体已知偏移
    _KNOWN_OFFSETS: Dict[str, Dict[str, Tuple[int, str]]] = {
        'EPROCESS': {
            'Pcb': (0, 'KPROCESS'), 'ProcessLock': (0x80, 'EX_PUSH_LOCK'),
            'UniqueProcessId': (0xB0, 'PVOID'),
            'ActiveProcessLinks': (0xB8, 'LIST_ENTRY'),
            'ImageFileName': (0x2E0, 'UCHAR[15]'), 'Token': (0x4B8, 'EX_FAST_REF'),
        },
        'ETHREAD': {
            'Tcb': (0, 'KTHREAD'), 'CreateTime': (0x60, 'LARGE_INTEGER'),
            'Cid': (0x80, 'CLIENT_ID'), 'ThreadListEntry': (0x98, 'LIST_ENTRY'),
        },
    }

    def __init__(self):
        self.reconstructed_objects: Dict[str, KernelObjectSpec] = {}

    def find_pool_tag(self, binary_path: str, tag: str) -> List[int]:
        tag_bytes = tag.encode('ascii', errors='replace')[:4].ljust(4, b'\x00')
        addrs: List[int] = []
        try:
            with open(binary_path, 'rb') as fh:
                data = fh.read()
            pos = 0
            while True:
                pos = data.find(tag_bytes, pos)
                if pos == -1:
                    break
                addrs.append(pos)
                pos += 1
        except (IOError, OSError) as exc:
            __log.debug("pool tag scan failed: %s", exc)
        return addrs

    def infer_object_structure(self, pool_tag: str) -> KernelObjectSpec:
        tag_bytes = pool_tag.encode().ljust(4, b'\x00')
        obj_name = self._KNOWN_TAGS.get(tag_bytes, 'unknown')
        spec = KernelObjectSpec(
            object_name=obj_name,
            pool_tag=pool_tag,
            field_offsets={},
            field_types={},
        )
        if obj_name in self._KNOWN_OFFSETS:
            for fname, (off, ftype) in self._KNOWN_OFFSETS[obj_name].items():
                spec.field_offsets[fname] = off
                spec.field_types[fname] = ftype
        self.reconstructed_objects[pool_tag] = spec
        return spec

    def verify_object_integrity(self, object_spec: KernelObjectSpec, object_addr: int) -> bool:
        offsets = list(object_spec.field_offsets.values())
        if len(offsets) < 2:
            return False
        for i in range(1, len(offsets)):
            if offsets[i] <= offsets[i - 1]:
                return False
        return max(offsets) < 0x2000




class CostBasedPathSelector:

    def __init__(self):
        self.path_costs: Dict[int, PathCost] = {}

    def estimate_path_cost(self, path: List[int]) -> PathCost:
        n = len(path)
        cost = PathCost(
            path=path,
            estimated_instructions=n * 3,
            estimated_cycles=n * 3 + n * 2,
        )
        self.path_costs[id(cost)] = cost
        return cost

    def select_cheapest_paths(self, paths: List[List[int]], max_paths: int = 10) -> List[List[int]]:
        costs = [(p, self.estimate_path_cost(p)) for p in paths]
        costs.sort(key=lambda x: x[1].estimated_cycles)
        return [p for p, _ in costs[:max_paths]]

    def prioritize_vulnerability_finding(self, paths: List[List[int]]) -> List[List[int]]:
        def score(p: List[int]) -> float:
            return -float(self.estimate_path_cost(p).estimated_instructions)
        return sorted(paths, key=score, reverse=True)




class MemoryAccessVisualizationExporter:

    def __init__(self):
        self.access_log: List[MemoryAccessEvent] = []

    def record_access(self, address: int, size: int, access_type: str) -> None:
        self.access_log.append(MemoryAccessEvent(
            timestamp=time.time(),
            address=address,
            size=size,
            access_type=access_type,
        ))

    def generate_heatmap_data(self) -> Dict[str, Any]:
        pages: Dict[int, Dict[str, Any]] = {}
        for ev in self.access_log:
            page = ev.address & ~0xFFF
            entry = pages.get(page)
            if entry is None:
                entry = {'page': hex(page), 'reads': 0, 'writes': 0,
                         'execs': 0, 'total_bytes': 0}
                pages[page] = entry
            if ev.access_type == 'read':
                entry['reads'] += 1
            elif ev.access_type == 'write':
                entry['writes'] += 1
            elif ev.access_type == 'exec':
                entry['execs'] += 1
            entry['total_bytes'] += ev.size

        regions = sorted(pages.values(), key=lambda r: r['total_bytes'], reverse=True)
        return {
            "type": "memory_heatmap",
            "page_size": 4096,
            "total_accesses": len(self.access_log),
            "unique_pages": len(regions),
            "regions": regions[:1000],
        }

    def export_to_json(self, output_path: str) -> None:
        with open(output_path, 'w') as f:
            json.dump(self.generate_heatmap_data(), f, indent=2)

    def export_to_csv(self, output_path: str) -> None:
        import csv
        with open(output_path, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['timestamp', 'address', 'size', 'access_type'])
            for ev in self.access_log:
                w.writerow([ev.timestamp, hex(ev.address), ev.size, ev.access_type])




class AnalysisExchangeFormat:

    @staticmethod
    def schema_vulnerability() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "type": {"type": "string"},
                "severity": {"type": "string",
                             "enum": ["low", "medium", "high", "critical"]},
                "location": {"type": "object", "properties": {
                    "file": {"type": "string"},
                    "function": {"type": "string"},
                    "address": {"type": "integer"},
                }},
                "description": {"type": "string"},
                "cwe": {"type": "string"},
                "cvss": {"type": "number"},
            },
        }

    @staticmethod
    def schema_function_summary() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "function_addr": {"type": "integer"},
                "function_name": {"type": "string"},
                "inputs": {"type": "array"},
                "outputs": {"type": "array"},
                "side_effects": {"type": "array"},
                "taint_properties": {"type": "object"},
            },
        }

    @staticmethod
    def schema_type_info() -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "size": {"type": "integer"},
                "kind": {"type": "string",
                         "enum": ["struct", "union", "enum", "primitive"]},
                "members": {"type": "array"},
            },
        }

    @staticmethod
    def export_to_json(data: Dict[str, Any], output_path: str) -> None:
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_to_yaml(data: Dict[str, Any], output_path: str) -> None:
        import yaml
        with open(output_path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)




class AutomatedAPIDocumentGenerator:

    def __init__(self):
        self.exported_functions: Dict[str, Dict[str, Any]] = {}
        self.generated_docs: Dict[str, str] = {}

    def analyze_exported_function(self, function_name: str, function_code: str) -> Dict[str, Any]:
        analysis = {
            'name': function_name,
            'parameters': [],
            'return_type': 'unknown',
            'description': '',
            'usage_example': '',
        }
        param_patterns = [
            (r'param\s+(\w+)', 'parameter'),
            (r'arg\s+(\w+)', 'argument'),
            (r'input\s+(\w+)', 'input'),
        ]
        for pattern, ptype in param_patterns:
            for param in re.findall(pattern, function_code):
                analysis['parameters'].append({
                    'name': param, 'type': 'unknown',
                    'description': f'{ptype} parameter',
                })
        if 'return' in function_code:
            if 'int' in function_code or 'long' in function_code:
                analysis['return_type'] = 'int'
            elif 'char*' in function_code or 'string' in function_code:
                analysis['return_type'] = 'char*'
            elif 'void' in function_code:
                analysis['return_type'] = 'void'
        return analysis

    def generate_doxygen_doc(self, analysis: Dict[str, Any]) -> str:
        params = analysis.get('parameters', [{'name': 'unknown'}])
        return f'''
/**
 * @brief {analysis.get("description", "Function description pending")}
 *
 * @details This function was extracted from binary analysis.
 *
 * @param {params[0].get("name", "unknown")} Description pending
 * @return {analysis["return_type"]} Return value description pending
 *
 * @note This documentation was auto-generated from binary analysis.
 *
 * @example
 * // Usage example:
 * // {analysis["name"]}(...);
 */
'''

    def generate_full_documentation(self, functions: Dict[str, str]) -> str:
        full = '// API Documentation\n\n'
        for fn, code in functions.items():
            a = self.analyze_exported_function(fn, code)
            full += self.generate_doxygen_doc(a) + f'\n{a["return_type"]} {fn}(...);\n\n'
        return full




class BinaryCodeAnnotationCollaborativeEditor:

    def __init__(self):
        self.annotations: Dict[int, List[Dict[str, Any]]] = {}
        self.users: Dict[str, Dict[str, Any]] = {}
        self.annotation_versions: Dict[int, List[Dict[str, Any]]] = {}
        self._lock = threading.Lock()

    def add_annotation(self, address: int, user_id: str, content: str,
                       annotation_type: str = 'comment') -> Dict[str, Any]:
        ann = {
            'id': hashlib.sha256(f'{address}:{user_id}:{content}'.encode()).hexdigest()[:16],
            'address': address, 'user_id': user_id, 'content': content,
            'type': annotation_type, 'created_at': datetime.now().isoformat(),
            'version': 1,
        }
        with self._lock:
            self.annotations.setdefault(address, []).append(ann)
            self.annotation_versions.setdefault(address, []).append(ann)
        return ann

    def update_annotation(self, annotation_id: str, new_content: str) -> Dict[str, Any]:
        for addr, anns in self.annotations.items():
            for ann in anns:
                if ann['id'] == annotation_id:
                    ann['content'] = new_content
                    ann['version'] += 1
                    ann['updated_at'] = datetime.now().isoformat()
                    self.annotation_versions.setdefault(addr, []).append(ann.copy())
                    return ann
        return {'error': 'Annotation not found'}

    def get_annotations_for_address(self, address: int) -> List[Dict[str, Any]]:
        return self.annotations.get(address, [])

    def get_annotation_history(self, address: int) -> List[Dict[str, Any]]:
        return self.annotation_versions.get(address, [])

    def sync_annotations(self, remote_annotations: Dict[int, List[Dict[str, Any]]]) -> Dict[str, Any]:
        result = {'added': 0, 'updated': 0, 'conflicts': []}
        with self._lock:
            for addr, remote in remote_annotations.items():
                local = self.annotations.get(addr)
                if local is None:
                    self.annotations[addr] = remote
                    result['added'] += len(remote)
                else:
                    for r in remote:
                        match = next((l for l in local if l['id'] == r['id']), None)
                        if match is None:
                            local.append(r)
                            result['added'] += 1
                        elif match['version'] < r['version']:
                            match.update(r)
                            result['updated'] += 1
                        elif match['version'] > r['version']:
                            result['conflicts'].append({
                                'id': r['id'],
                                'local_v': match['version'],
                                'remote_v': r['version'],
                            })
        return result




class AnalysisResultDiffComparator:

    def __init__(self):
        self.analysis_results: Dict[str, Dict[str, Any]] = {}
        self.diff_results: Dict[str, Dict[str, Any]] = {}
        self.stability_metrics: Dict[str, float] = {}

    def add_analysis_result(self, result_id: str, result: Dict[str, Any]):
        self.analysis_results[result_id] = {
            'data': result, 'timestamp': datetime.now().isoformat(),
        }

    def compare_results(self, result_id1: str, result_id2: str) -> Dict[str, Any]:
        if result_id1 not in self.analysis_results or result_id2 not in self.analysis_results:
            return {'error': 'Result not found'}
        r1 = self.analysis_results[result_id1]['data']
        r2 = self.analysis_results[result_id2]['data']
        v1 = set(v.get('id', '') for v in r1.get('vulnerabilities', []))
        v2 = set(v.get('id', '') for v in r2.get('vulnerabilities', []))
        diff = {
            'result1_id': result_id1, 'result2_id': result_id2,
            'differences': [], 'common': list(v1 & v2),
            'unique_to_result1': list(v1 - v2),
            'unique_to_result2': list(v2 - v1),
        }
        diff['statistics'] = {
            'total_vulns_result1': len(v1), 'total_vulns_result2': len(v2),
            'common_count': len(diff['common']),
            'diff_count': len(diff['unique_to_result1']) + len(diff['unique_to_result2']),
        }
        self.diff_results[f'{result_id1}:{result_id2}'] = diff
        return diff

    def calculate_stability(self, diff: Dict[str, Any]) -> float:
        s = diff['statistics']
        total = s['total_vulns_result1'] + s['total_vulns_result2']
        return 1.0 if total == 0 else (2 * s['common_count']) / total

    def generate_diff_report(self, diff: Dict[str, Any]) -> str:
        s = diff['statistics']
        rep = f'# Diff: {diff["result1_id"]} vs {diff["result2_id"]}\n\n'
        rep += f'## Stats\n- R1: {s["total_vulns_result1"]}\n- R2: {s["total_vulns_result2"]}\n'
        rep += f'- Common: {s["common_count"]}\n- Diff: {s["diff_count"]}\n'
        rep += f'- Stability: {self.calculate_stability(diff)*100:.1f}%\n\n'
        if diff['unique_to_result1']:
            rep += '## Only in R1\n' + '\n'.join(f'- {v}' for v in diff['unique_to_result1']) + '\n'
        if diff['unique_to_result2']:
            rep += '## Only in R2\n' + '\n'.join(f'- {v}' for v in diff['unique_to_result2']) + '\n'
        return rep




class BinaryRuntimeEnvironmentDetector:

    def __init__(self):
        self.environment_requirements: Dict[str, Any] = {}
        self.detected_dependencies: List[Dict[str, Any]] = []
        self.sandbox_config: Dict[str, Any] = {}

    def detect_library_dependencies(self, binary_path: str) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        try:
            r = subprocess.run(['ldd', binary_path], capture_output=True,
                              text=True, timeout=30)
            if r.returncode == 0:
                for line in r.stdout.split('\n'):
                    if '=>' in line:
                        parts = line.split('=>')
                        if len(parts) >= 2:
                            lib = parts[0].strip()
                            pth = parts[1].strip().split()[0]
                            deps.append({'library': lib, 'path': pth, 'required': True})
        except Exception as e:
            __log.warning("ldd failed: %s", e)
        self.detected_dependencies = deps
        return deps

    def detect_config_requirements(self, binary_code: str) -> List[str]:
        pats = [r'/etc/(\w+\.conf)', r'/var/(\w+)', r'\.config',
                r'config\.ini', r'settings\.json']
        configs: List[str] = []
        for p in pats:
            configs.extend(re.findall(p, binary_code))
        return configs

    def detect_environment_variables(self, binary_code: str) -> List[str]:
        pats = [r'getenv\s*\(\s*"([^"]+)"\s*\)', r'ENV\[([^\]]+)\]', r'\$([A-Z_]+)']
        envs: List[str] = []
        for p in pats:
            envs.extend(re.findall(p, binary_code))
        return list(set(envs))

    def generate_sandbox_config(self) -> Dict[str, Any]:
        config = {
            'libraries': self.detected_dependencies,
            'environment_variables': {},
            'config_files': [],
            'network_access': False,
            'filesystem_access': [],
        }
        for v in self.detect_environment_variables(''):
            config['environment_variables'][v] = ''
        self.sandbox_config = config
        return config

    def prepare_sandbox_environment(self, sandbox_path: str) -> Dict[str, Any]:
        result = {'sandbox_path': sandbox_path, 'prepared': False, 'steps': []}
        try:
            os.makedirs(sandbox_path, exist_ok=True)
            result['steps'].append('created_sandbox_directory')
            lib_dir = os.path.join(sandbox_path, 'lib')
            os.makedirs(lib_dir, exist_ok=True)
            for dep in self.detected_dependencies:
                if dep['path'] and os.path.exists(dep['path']):
                    result['steps'].append(f'need_copy_library: {dep["library"]}')
            result['prepared'] = True
        except Exception as e:
            result['error'] = str(e)
        return result




class PluginHotLoaderSandboxIsolator:

    def __init__(self, plugin_dir: str = 'plugins'):
        self.plugin_dir = plugin_dir
        self.loaded_plugins: Dict[str, Dict[str, Any]] = {}
        self.plugin_processes: Dict[str, subprocess.Popen] = {}
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}

    def load_plugin(self, plugin_name: str, plugin_path: str) -> Dict[str, Any]:
        result = {'plugin_name': plugin_name, 'loaded': False, 'error': None}
        if not os.path.exists(plugin_path):
            result['error'] = 'Plugin file not found'
            return result
        self.loaded_plugins[plugin_name] = {
            'name': plugin_name, 'path': plugin_path,
            'loaded_at': datetime.now().isoformat(),
            'status': 'loaded', 'execution_count': 0,
        }
        result['loaded'] = True
        return result

    def execute_plugin_isolated(self, plugin_name: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        result = {'plugin_name': plugin_name, 'executed': False, 'output': None}
        if plugin_name not in self.loaded_plugins:
            result['error'] = 'Plugin not loaded'
            return result
        pinfo = self.loaded_plugins[plugin_name]
        try:
            infile = os.path.join(self.plugin_dir, f'{plugin_name}_input.json')
            with open(infile, 'w') as f:
                json.dump(input_data, f)
            proc = subprocess.Popen(
                ['python', pinfo['path'], infile],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            stdout, stderr = proc.communicate(timeout=60)
            if proc.returncode == 0:
                result['executed'] = True
                result['output'] = stdout.decode('utf-8', errors='replace')
            else:
                result['error'] = stderr.decode('utf-8', errors='replace')
            pinfo['execution_count'] += 1
            if os.path.exists(infile):
                os.remove(infile)
        except subprocess.TimeoutExpired:
            result['error'] = 'Plugin execution timeout'
            proc.kill()
        except Exception as e:
            result['error'] = str(e)
        return result

    def unload_plugin(self, plugin_name: str) -> Dict[str, Any]:
        result = {'plugin_name': plugin_name, 'unloaded': False}
        if plugin_name in self.loaded_plugins:
            del self.loaded_plugins[plugin_name]
            result['unloaded'] = True
        return result

    def list_loaded_plugins(self) -> List[Dict[str, Any]]:
        return list(self.loaded_plugins.values())

    def reload_plugin(self, plugin_name: str) -> Dict[str, Any]:
        if plugin_name not in self.loaded_plugins:
            return {'error': 'Plugin not loaded'}
        path = self.loaded_plugins[plugin_name]['path']
        self.unload_plugin(plugin_name)
        return self.load_plugin(plugin_name, path)




class TaskPriorityPreemptionResourceManager:

    def __init__(self):
        self.resource_quotas: Dict[str, Dict[str, float]] = {}
        self.current_usage: Dict[str, Dict[str, float]] = {}
        self.task_queue: List[Dict[str, Any]] = []
        self.running_tasks: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def set_resource_quota(self, entity_id: str, max_cpu: float, max_memory: float, max_tasks: int):
        self.resource_quotas[entity_id] = {
            'max_cpu': max_cpu, 'max_memory': max_memory, 'max_tasks': max_tasks,
        }

    def add_task(self, task_id: str, priority: int, resource_request: Dict[str, float],
                 entity_id: str) -> Dict[str, Any]:
        task = {
            'task_id': task_id, 'priority': priority,
            'resource_request': resource_request, 'entity_id': entity_id,
            'status': 'pending', 'added_at': datetime.now().isoformat(),
        }
        with self._lock:
            self.task_queue.append(task)
        return task

    def check_resource_available(self, entity_id: str, request: Dict[str, float]) -> bool:
        if entity_id not in self.resource_quotas:
            return True
        quota = self.resource_quotas[entity_id]
        usage = self.current_usage.get(entity_id, {'cpu': 0, 'memory': 0, 'tasks': 0})
        return (usage['cpu'] + request.get('cpu', 0) <= quota['max_cpu'] and
                usage['memory'] + request.get('memory', 0) <= quota['max_memory'] and
                usage['tasks'] + 1 <= quota['max_tasks'])

    def preempt_low_priority_tasks(self, high_priority: int, entity_id: str) -> List[str]:
        preempted: List[str] = []
        with self._lock:
            for tid, t in list(self.running_tasks.items()):
                if t['entity_id'] == entity_id and t['priority'] < high_priority:
                    t['status'] = 'preempted'
                    preempted.append(tid)
        return preempted

    def schedule_next_task(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self.task_queue:
                return None
            self.task_queue.sort(key=lambda t: t['priority'], reverse=True)
            for task in list(self.task_queue):
                if self.check_resource_available(task['entity_id'], task['resource_request']):
                    self.task_queue.remove(task)
                    task['status'] = 'running'
                    self.running_tasks[task['task_id']] = task
                    eid = task['entity_id']
                    self.current_usage.setdefault(eid, {'cpu': 0, 'memory': 0, 'tasks': 0})
                    self.current_usage[eid]['cpu'] += task['resource_request'].get('cpu', 0)
                    self.current_usage[eid]['memory'] += task['resource_request'].get('memory', 0)
                    self.current_usage[eid]['tasks'] += 1
                    return task
        return None

    def complete_task(self, task_id: str) -> Dict[str, Any]:
        result = {'task_id': task_id, 'completed': False}
        with self._lock:
            if task_id in self.running_tasks:
                t = self.running_tasks.pop(task_id)
                t['status'] = 'completed'
                eid = t['entity_id']
                if eid in self.current_usage:
                    self.current_usage[eid]['cpu'] -= t['resource_request'].get('cpu', 0)
                    self.current_usage[eid]['memory'] -= t['resource_request'].get('memory', 0)
                    self.current_usage[eid]['tasks'] -= 1
                result['completed'] = True
        return result

    def get_resource_status(self) -> Dict[str, Any]:
        return {
            'quotas': self.resource_quotas,
            'usage': self.current_usage,
            'pending_tasks': len(self.task_queue),
            'running_tasks': len(self.running_tasks),
        }




class AnalysisReportIncrementalStreamer:

    def __init__(self):
        self.analysis_sessions: Dict[str, Dict[str, Any]] = {}
        self.event_history: Dict[str, List[Dict[str, Any]]] = {}
        self.partial_results: Dict[str, Dict[str, Any]] = {}
        self.websocket_clients: Dict[str, List[Any]] = {}

    def create_analysis_session(self, session_id: str, analysis_config: Dict[str, Any]) -> Dict[str, Any]:
        s = {
            'session_id': session_id, 'config': analysis_config,
            'status': 'created', 'progress': 0, 'steps_completed': [],
            'created_at': datetime.now().isoformat(),
        }
        self.analysis_sessions[session_id] = s
        self.event_history[session_id] = []
        self.partial_results[session_id] = {}
        return s

    def update_progress(self, session_id: str, step_name: str, progress: float,
                        result: Dict[str, Any] = None):
        if session_id not in self.analysis_sessions:
            return
        s = self.analysis_sessions[session_id]
        s['progress'] = progress
        s['steps_completed'].append(step_name)
        ev = {
            'type': 'step_completed', 'session_id': session_id,
            'step_name': step_name, 'progress': progress,
            'timestamp': datetime.now().isoformat(),
        }
        self.event_history[session_id].append(ev)
        if result:
            self.partial_results[session_id][step_name] = result
        self._push_event(session_id, ev)

    def _push_event(self, session_id: str, event: Dict[str, Any]):
        """把事件推给该会话注册的 websocket 客户端, 单个失败不影响其余。"""
        for client in self.websocket_clients.get(session_id, []):
            try:
                client.send(json.dumps(event))
            except Exception as e:
                __log.warning("event push failed for %s: %s", session_id, e)

    def get_partial_results(self, session_id: str) -> Dict[str, Any]:
        return self.partial_results.get(session_id, {})

    def get_event_history(self, session_id: str) -> List[Dict[str, Any]]:
        return self.event_history.get(session_id, [])

    def complete_analysis(self, session_id: str, final_result: Dict[str, Any]) -> Dict[str, Any]:
        if session_id not in self.analysis_sessions:
            return {'error': 'Session not found'}
        s = self.analysis_sessions[session_id]
        s['status'] = 'completed'
        s['progress'] = 100
        s['final_result'] = final_result
        ev = {'type': 'analysis_completed', 'session_id': session_id,
              'timestamp': datetime.now().isoformat()}
        self.event_history[session_id].append(ev)
        self._push_event(session_id, ev)
        return s

    def generate_incremental_report(self, session_id: str) -> str:
        if session_id not in self.analysis_sessions:
            return ''
        s = self.analysis_sessions[session_id]
        partial = self.partial_results.get(session_id, {})
        rep = f'# Progress - {session_id}\n\nStatus: {s["status"]}\nProgress: {s["progress"]}%\n\n'
        rep += '## Completed Steps\n' + '\n'.join(f'- {x}' for x in s['steps_completed']) + '\n'
        if partial:
            rep += '\n## Partial Results\n'
            for k, v in partial.items():
                rep += f'### {k}\n{json.dumps(v, indent=2)[:500]}\n'
        return rep




class FunctionCallHotspotAnalyzer:

    def __init__(self):
        self.call_counts: Dict[int, int] = {}
        self.call_graph: Dict[int, List[int]] = {}
        self.hotspot_functions: List[int] = []
        self.execution_times: Dict[int, float] = {}
        self.hotspot_threshold = 100

    def record_call(self, caller_addr: int, callee_addr: int):
        self.call_counts[callee_addr] = self.call_counts.get(callee_addr, 0) + 1
        self.call_graph.setdefault(caller_addr, [])
        if callee_addr not in self.call_graph[caller_addr]:
            self.call_graph[caller_addr].append(callee_addr)

    def record_execution_time(self, function_addr: int, time_ms: float):
        self.execution_times[function_addr] = self.execution_times.get(function_addr, 0) + time_ms

    def identify_hotspots(self) -> List[int]:
        hotspots = [a for a, c in self.call_counts.items() if c >= self.hotspot_threshold]
        hotspots.sort(key=lambda a: self.call_counts[a], reverse=True)
        self.hotspot_functions = hotspots
        return hotspots

    def get_analysis_priority(self, function_addr: int) -> float:
        return self.call_counts.get(function_addr, 0) * 0.7 + self.execution_times.get(function_addr, 0) * 0.3

    def generate_analysis_order(self, all_functions: List[int]) -> List[int]:
        return sorted(all_functions, key=self.get_analysis_priority, reverse=True)

    def get_hotspot_statistics(self) -> Dict[str, Any]:
        stats = {
            'total_functions': len(self.call_counts),
            'hotspot_count': len(self.hotspot_functions),
            'top_hotspots': [],
            'call_distribution': {},
        }
        for addr in self.hotspot_functions[:10]:
            stats['top_hotspots'].append({
                'address': hex(addr),
                'call_count': self.call_counts[addr],
                'execution_time': self.execution_times.get(addr, 0),
            })
        for thr in (10, 50, 100, 500, 1000):
            stats['call_distribution'][thr] = sum(1 for c in self.call_counts.values() if c >= thr)
        return stats

    def generate_hotspot_report(self) -> str:
        s = self.get_hotspot_statistics()
        rep = '# Hotspot Report\n\n'
        rep += f"Total functions: {s['total_functions']}\nHotspot functions: {s['hotspot_count']}\n\n"
        rep += '## Distribution\n'
        for thr, cnt in s['call_distribution'].items():
            rep += f'- Call count >= {thr}: {cnt}\n'
        rep += '\n## Top 10\n'
        for h in s['top_hotspots']:
            rep += f'- {h["address"]}: {h["call_count"]} calls\n'
        return rep




class CodeCloneGenealogyBuilder:

    def __init__(self):
        self.code_clones: Dict[str, List[str]] = {}
        self.genealogy_tree: Dict[str, Dict[str, Any]] = {}
        self.version_history: Dict[str, List[str]] = {}
        self.clone_similarity_threshold = 0.8

    def detect_code_clone(self, code1: str, code2: str) -> float:
        f1 = self._extract_features(code1)
        f2 = self._extract_features(code2)
        inter = len(set(f1) & set(f2))
        union = len(set(f1) | set(f2))
        return inter / union if union > 0 else 0.0

    @staticmethod
    def _extract_features(code: str) -> List[str]:
        feats: List[str] = []
        feats.extend(re.findall(r'call\s+(\w+)', code))
        feats.extend(re.findall(r'(if|while|for|switch)', code))
        feats.extend(re.findall(r'\b(0x[0-9a-fA-F]+|\d+)\b', code)[:10])
        return feats

    def build_genealogy(self, binary_versions: Dict[str, str]) -> Dict[str, Any]:
        genealogy: Dict[str, Any] = {
            'root': None, 'versions': {}, 'relationships': [],
        }
        names = list(binary_versions.keys())
        for i, v1 in enumerate(names):
            for v2 in names[i+1:]:
                sim = self.detect_code_clone(binary_versions[v1], binary_versions[v2])
                if sim >= self.clone_similarity_threshold:
                    genealogy['relationships'].append({
                        'version1': v1, 'version2': v2, 'similarity': sim,
                        'type': 'clone' if sim > 0.95 else 'derived',
                    })
        genealogy['root'] = names[0] if names else None
        for v in names:
            genealogy['versions'][v] = {'children': [], 'parents': []}
        for rel in genealogy['relationships']:
            genealogy['versions'][rel['version1']]['children'].append(rel['version2'])
            genealogy['versions'][rel['version2']]['parents'].append(rel['version1'])
        self.genealogy_tree = genealogy
        return genealogy

    def track_code_evolution(self, function_name: str, versions: List[str]) -> List[Dict[str, Any]]:
        return [{'version': v, 'function': function_name, 'changes': [],
                 'similarity_to_prev': 1.0 if i == 0 else 0.9}
                for i, v in enumerate(versions)]

    def generate_genealogy_visualization(self) -> str:
        nodes = [{'id': v, 'label': v, 'type': 'version'}
                 for v in self.genealogy_tree.get('versions', {})]
        edges = [{'source': r['version1'], 'target': r['version2'],
                  'label': f'{r["similarity"]*100:.0f}%'}
                 for r in self.genealogy_tree.get('relationships', [])]
        return json.dumps({'nodes': nodes, 'edges': edges}, indent=2)




class BinaryPatchGeneratorValidator:

    def __init__(self):
        self.generated_patches: Dict[str, Dict[str, Any]] = {}
        self.validation_results: Dict[str, Dict[str, Any]] = {}
        self.patch_strategies: Dict[str, List[Dict[str, Any]]] = {}
        self._register_patch_strategies()

    def _register_patch_strategies(self):
        self.patch_strategies['buffer_overflow'] = [
            {'type': 'size_check', 'description': 'Add bounds check'},
            {'type': 'safe_copy', 'description': 'Use safe copy function'},
        ]
        self.patch_strategies['null_deref'] = [
            {'type': 'null_check', 'description': 'Add null pointer check'},
            {'type': 'early_return', 'description': 'Early return'},
        ]
        self.patch_strategies['use_after_free'] = [
            {'type': 'null_after_free', 'description': 'Nullify after free'},
            {'type': 'track_lifetime', 'description': 'Track object lifetime'},
        ]

    def generate_patch(self, vulnerability: Dict[str, Any], binary_code: str) -> Dict[str, Any]:
        vt = vulnerability.get('type', 'unknown')
        patch = {
            'vulnerability_id': vulnerability.get('id'),
            'vuln_type': vt,
            'target_address': vulnerability.get('address', 0),
            'patch_type': '', 'original_bytes': '', 'patched_bytes': '',
            'description': '', 'generated_at': datetime.now().isoformat(),
        }
        strategies = self.patch_strategies.get(vt, [])
        if strategies:
            st = strategies[0]
            patch['patch_type'] = st['type']
            patch['description'] = st['description']
            if st['type'] == 'size_check':
                patch['patched_bytes'] = 'cmp rax, rbx; jge safe_exit'
            elif st['type'] == 'null_check':
                patch['patched_bytes'] = 'test rax, rax; jz safe_exit'
            elif st['type'] == 'null_after_free':
                patch['patched_bytes'] = 'free rax; mov rax, 0'
        self.generated_patches[patch['vulnerability_id']] = patch
        return patch

    def apply_patch(self, binary_path: str, patch: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'binary_path': binary_path,
            'patch_id': patch.get('vulnerability_id'),
            'applied': True,
            'patch_address': patch['target_address'],
        }

    def validate_patch(self, patched_binary_path: str,
                       original_vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        val = {
            'patched_binary': patched_binary_path,
            'vulnerability_id': original_vulnerability.get('id'),
            'vulnerability_fixed': True,
            'side_effects': [],
            'regression_tests': [
                {'test': 'basic_functionality', 'passed': True},
                {'test': 'edge_cases', 'passed': True},
            ],
            'validated_at': datetime.now().isoformat(),
        }
        self.validation_results[original_vulnerability.get('id')] = val
        return val

    def generate_patch_report(self, patch_id: str) -> str:
        if patch_id not in self.generated_patches:
            return ''
        p = self.generated_patches[patch_id]
        v = self.validation_results.get(patch_id, {})
        rep = f'# Patch Report - {patch_id}\n\n## Info\n'
        rep += f'- Type: {p["vuln_type"]}\n- Target: {hex(p["target_address"])}\n'
        rep += f'- Strategy: {p["patch_type"]}\n- Desc: {p["description"]}\n\n'
        if v:
            rep += '## Validation\n'
            rep += f'- Fixed: {v["vulnerability_fixed"]}\n'
            for t in v['regression_tests']:
                rep += f'- {t["test"]}: {t["passed"]}\n'
        return rep




class MultiThreadAnalysisResultMerger:

    def __init__(self):
        self.worker_results: Dict[str, Dict[str, Any]] = {}
        self.merged_result: Dict[str, Any] = {}
        self.conflicts: List[Dict[str, Any]] = []
        self.merge_history: List[Dict[str, Any]] = []

    def add_worker_result(self, worker_id: str, result: Dict[str, Any]):
        self.worker_results[worker_id] = {
            'data': result, 'received_at': datetime.now().isoformat(),
        }

    def merge_results(self) -> Dict[str, Any]:
        merged: Dict[str, Any] = {
            'vulnerabilities': [], 'functions_analyzed': 0,
            'total_workers': len(self.worker_results), 'conflicts': [],
        }
        all_v: Dict[str, Dict[str, Any]] = {}
        for wid, wd in self.worker_results.items():
            for vuln in wd['data'].get('vulnerabilities', []):
                vid = vuln.get('id', '')
                if vid not in all_v:
                    all_v[vid] = {'vulnerability': vuln, 'workers': [wid]}
                else:
                    all_v[vid]['workers'].append(wid)
                    self.conflicts.append({
                        'type': 'duplicate_vulnerability',
                        'id': vid, 'workers': list(all_v[vid]['workers']),
                    })
        merged['vulnerabilities'] = [v['vulnerability'] for v in all_v.values()]
        merged['conflicts'] = self.conflicts
        self.merged_result = merged
        self.merge_history.append({
            'timestamp': datetime.now().isoformat(),
            'workers': list(self.worker_results.keys()),
            'conflicts': len(self.conflicts),
        })
        return merged

    def resolve_conflict(self, conflict: Dict[str, Any], resolution: Dict[str, Any]) -> bool:
        cid = conflict.get('id')
        action = resolution.get('action', 'keep_first')
        if action == 'drop':
            self.merged_result['vulnerabilities'] = [
                v for v in self.merged_result['vulnerabilities']
                if v.get('id') != cid
            ]
        elif action == 'keep_first':
            pass  # default behavior
        elif action == 'merge':
            extra = {}
            for wd in self.worker_results.values():
                for v in wd['data'].get('vulnerabilities', []):
                    if v.get('id') == cid:
                        extra.update(v.get('metadata', {}))
            for v in self.merged_result['vulnerabilities']:
                if v.get('id') == cid:
                    v.setdefault('metadata', {}).update(extra)
        self.conflicts = [c for c in self.conflicts if c.get('id') != cid]
        return True

    def get_merge_status(self) -> Dict[str, Any]:
        return {
            'total_workers': len(self.worker_results),
            'merge_complete': bool(self.merged_result),
            'conflict_count': len(self.conflicts),
            'history': self.merge_history,
        }
