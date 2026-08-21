"""
race condition分析module (Race Condition Analyzer)

功能:
    1. identifybinary代码中的并发访问mode (多thread/signal处理器/中断context)
    2. 分析锁获取/释放序列, 检测死锁、双重锁定、遗漏解锁
    3. 检测 TOCTOU (Time-of-Check-Time-of-Use) 漏洞
    4. 计算竞态时间窗口 (check 与 use 之间的指令数/估计execute时间)
    5. 生成race condition风险报告, 包含exploit difficultyevaluate

core technology:
    - based on Capstone/IDA disassembly的指令级分析
    - call graph遍历定位共享资源访问点
    - 锁配对分析 (lock/unlock, wait/signal)
    - data flow analysis追踪 check 结果到 use 点
    - TOCTOU modematch: 安全check → 资源操作
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)



class RaceConditionType:
    """race conditiontype"""
    TOCTOU = "toctou"
    DOUBLE_FETCH = "double_fetch"
    LOCK_ORDER_INVERSION = "lock_inversion"
    MISSING_LOCK = "missing_lock"
    DOUBLE_LOCK = "double_lock"
    SIGNAL_RACE = "signal_race"
    USE_AFTER_FREE_RACE = "uaf_race"
    SHARED_MEMORY_RACE = "shared_mem_race"
    INTERRUPT_RACE = "interrupt_race"
    OTHER = "other"

class ExploitDifficulty:
    """exploit difficulty"""
    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    EXTREME = "extreme"
    THEORETICAL = "theoretical"


@dataclass
class InstructionInfo:
    address: int
    mnemonic: str
    operands: str = ""
    size: int = 0
    bytes_hex: str = ""
    comment: str = ""
    """指令info"""

class CriticalSection:
    """临界区description"""
    __slots__ = ('start_addr', 'end_addr', 'lock_type', 'lock_var',
                 'protected_resource', 'instructions')
    def __init__(self, start_addr: int, end_addr: int, lock_type: str = "",
                 lock_var: str = "", protected_resource: str = "",
                 instructions: Optional[List[InstructionInfo]] = None):
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.lock_type = lock_type
        self.lock_var = lock_var
        self.protected_resource = protected_resource
        self.instructions = instructions if instructions is not None else []


class LockPair:
    """锁配对"""
    __slots__ = ('lock_addr', 'unlock_addr', 'lock_type', 'lock_var',
                 'is_balanced', 'intermediate_calls')
    def __init__(self, lock_addr: int, unlock_addr: int, lock_type: str = "",
                 lock_var: str = "", is_balanced: bool = True,
                 intermediate_calls: Optional[List[str]] = None):
        self.lock_addr = lock_addr
        self.unlock_addr = unlock_addr
        self.lock_type = lock_type
        self.lock_var = lock_var
        self.is_balanced = is_balanced
        self.intermediate_calls = intermediate_calls if intermediate_calls is not None else []


class TOCTOUPattern:
    """TOCTOU mode实例"""
    __slots__ = ('check_addr', 'use_addr', 'checked_condition', 'used_resource',
                 'window_instructions', 'estimated_window_ms', 'intervening_calls',
                 'func_name', 'is_exploitable', 'is_syscall_gap')
    def __init__(self, check_addr: int, use_addr: int, checked_condition: str = "",
                 used_resource: str = "", window_instructions: int = 0,
                 estimated_window_ms: float = 0.0,
                 intervening_calls: Optional[List[str]] = None,
                 func_name: str = "", is_exploitable: bool = False,
                 is_syscall_gap: bool = False):
        self.check_addr = check_addr
        self.use_addr = use_addr
        self.checked_condition = checked_condition
        self.used_resource = used_resource
        self.window_instructions = window_instructions
        self.estimated_window_ms = estimated_window_ms
        self.intervening_calls = intervening_calls if intervening_calls is not None else []
        self.func_name = func_name
        self.is_exploitable = is_exploitable
        self.is_syscall_gap = is_syscall_gap


class RaceConditionFinding:
    """race condition发现"""
    __slots__ = ('finding_id', 'race_type', 'func_name', 'severity',
                 'description', 'patterns', 'lock_pairs', 'shared_resources',
                 'exploit_difficulty', 'remediation', 'cwe_id', 'references')
    def __init__(self, finding_id: str, race_type: RaceConditionType,
                 func_name: str, severity: str, description: str,
                 patterns: Optional[List[TOCTOUPattern]] = None,
                 lock_pairs: Optional[List[LockPair]] = None,
                 shared_resources: Optional[List[str]] = None,
                 exploit_difficulty: ExploitDifficulty = ExploitDifficulty.THEORETICAL,
                 remediation: str = "", cwe_id: str = "",
                 references: Optional[List[str]] = None):
        self.finding_id = finding_id
        self.race_type = race_type
        self.func_name = func_name
        self.severity = severity
        self.description = description
        self.patterns = patterns if patterns is not None else []
        self.lock_pairs = lock_pairs if lock_pairs is not None else []
        self.shared_resources = shared_resources if shared_resources is not None else []
        self.exploit_difficulty = exploit_difficulty
        self.remediation = remediation
        self.cwe_id = cwe_id
        self.references = references if references is not None else []

    def to_dict(self) -> Dict[str, Any]:
        return {
            'finding_id': self.finding_id,
            'race_type': self.race_type.value,
            'func_name': self.func_name,
            'severity': self.severity,
            'description': self.description,
            'patterns_count': len(self.patterns),
            'patterns': [
                {
                    'check_addr': hex(p.check_addr),
                    'use_addr': hex(p.use_addr),
                    'checked_condition': p.checked_condition,
                    'used_resource': p.used_resource,
                    'window_instructions': p.window_instructions,
                    'estimated_window_ms': p.estimated_window_ms,
                    'intervening_calls': p.intervening_calls,
                    'func_name': p.func_name,
                    'is_exploitable': p.is_exploitable,
                    'is_syscall_gap': p.is_syscall_gap
                }
                for p in self.patterns
            ],
            'lock_pairs': [
                {
                    'lock_addr': hex(lp.lock_addr),
                    'unlock_addr': hex(lp.unlock_addr),
                    'lock_type': lp.lock_type,
                    'lock_var': lp.lock_var,
                    'is_balanced': lp.is_balanced,
                    'intermediate_calls': lp.intermediate_calls
                }
                for lp in self.lock_pairs
            ],
            'shared_resources': self.shared_resources,
            'exploit_difficulty': self.exploit_difficulty.value,
            'remediation': self.remediation,
            'cwe_id': self.cwe_id,
            'references': self.references
        }


class LockAnalyzer:
    """锁使用analyzer

    identifybinary中的加锁/解锁mode:
    - pthread_mutex_lock/unlock
    - spin_lock/spin_unlock (内核)
    - EnterCriticalSection/LeaveCriticalSection (Windows)
    - custom锁 (如 atomic test-and-set loop)
    """

    LOCK_FUNCTIONS = {
        'pthread_mutex_lock', 'pthread_mutex_unlock',
        'pthread_rwlock_rdlock', 'pthread_rwlock_wrlock', 'pthread_rwlock_unlock',
        'pthread_spin_lock', 'pthread_spin_unlock',
        'spin_lock', 'spin_unlock', 'spin_lock_irqsave', 'spin_unlock_irqrestore',
        'mutex_lock', 'mutex_unlock', 'mutex_lock_interruptible',
        'down', 'up', 'down_interruptible', 'up_read', 'down_read',
        'EnterCriticalSection', 'LeaveCriticalSection',
        'TryEnterCriticalSection', 'DeleteCriticalSection',
        'AcquireSRWLockExclusive', 'AcquireSRWLockShared',
        'ReleaseSRWLockExclusive', 'ReleaseSRWLockShared',
        'std::mutex::lock', 'std::mutex::unlock',
        '__sync_lock_test_and_set', '__sync_lock_release',
        'omp_set_lock', 'omp_unset_lock',
    }

    LOCK_ACQUIRE_KEYWORDS = {'lock', 'enter', 'down', 'acquire', 'wait', 'trylock'}
    LOCK_RELEASE_KEYWORDS = {'unlock', 'leave', 'up', 'release', 'post', 'signal'}

    def __init__(self):
        self._lock_pairs: Dict[str, List[LockPair]] = defaultdict(list)

    @classmethod
    def is_lock_acquire(cls, name: str) -> bool:
        nl = name.lower()
        return any(kw in nl for kw in cls.LOCK_ACQUIRE_KEYWORDS)

    @classmethod
    def is_lock_release(cls, name: str) -> bool:
        nl = name.lower()
        return any(kw in nl for kw in cls.LOCK_RELEASE_KEYWORDS)

    def find_lock_pairs(self, calls: List[Tuple[int, str]],
                        func_name: str) -> List[LockPair]:
        """从函数调用序列中找出锁配对"""
        pairs: List[LockPair] = []
        lock_stack: List[Tuple[int, str]] = []

        for addr, call_name in calls:
            if self.is_lock_acquire(call_name):
                lock_stack.append((addr, call_name))
            elif self.is_lock_release(call_name):
                if lock_stack:
                    lock_addr, lock_call = lock_stack.pop()
                    pairs.append(LockPair(
                        lock_addr=lock_addr,
                        unlock_addr=addr,
                        lock_type=self._infer_lock_type(lock_call),
                        lock_var=self._extract_lock_var(call_name),
                        is_balanced=True
                    ))
                else:
                    pairs.append(LockPair(
                        lock_addr=0,
                        unlock_addr=addr,
                        lock_type="unknown",
                        lock_var=self._extract_lock_var(call_name),
                        is_balanced=False
                    ))

        for lock_addr, lock_call in lock_stack:
            pairs.append(LockPair(
                lock_addr=lock_addr,
                unlock_addr=0,
                lock_type=self._infer_lock_type(lock_call),
                lock_var=self._extract_lock_var(lock_call),
                is_balanced=False
            ))

        self._lock_pairs[func_name] = pairs
        return pairs

    def _infer_lock_type(self, call_name: str) -> str:
        nl = call_name.lower()
        if 'mutex' in nl:
            return 'mutex'
        if 'spin' in nl:
            return 'spinlock'
        if 'rwlock' in nl or 'srwlock' in nl:
            return 'rwlock'
        if 'semaphore' in nl or 'down' in nl or 'up' in nl:
            return 'semaphore'
        if 'critical' in nl:
            return 'critical_section'
        if 'atomic' in nl or 'test_and_set' in nl:
            return 'atomic'
        return 'unknown'

    @staticmethod
    def _extract_lock_var(call_name: str) -> str:
        m = re.search(r'[(&]\s*(\w+)\s*[)]', call_name)
        return m.group(1) if m else call_name


class SharedResourceDetector:
    """共享资源访问检测

    identify以下mode:
    - 全局变量写入 (可能在多thread/中断context中被同时访问)
    - file操作 (open/read/write 对同一file)
    - memory映射区域 (mmap/shmget)
    - network socket 操作
    - 硬件寄存器访问 (I/O ports, MMIO)
    """

    GLOBAL_ACCESS_PATTERNS = [
        r'mov\s+.*\[(rip\s*\+\s*)?0x[0-9a-f]+\]',
        r'str\s+\w+,\s*\[.*\]',
        r'sw\s+\w+,\s*\d+\(\$gp\)',
    ]

    SHARED_RESOURCE_APIS = {
        'file': {'open', 'fopen', 'openat', 'CreateFile', 'NtCreateFile',
                 'read', 'write', 'fread', 'fwrite', 'ReadFile', 'WriteFile',
                 'lseek', 'fseek', 'ftruncate', 'fallocate'},
        'memory': {'mmap', 'munmap', 'shmget', 'shmat', 'shmdt', 'shmctl',
                   'MapViewOfFile', 'UnmapViewOfFile', 'VirtualAlloc',
                   'malloc', 'calloc', 'realloc', 'free', 'mprotect'},
        'socket': {'socket', 'bind', 'listen', 'accept', 'connect',
                   'send', 'recv', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg',
                   'WSASocket', 'WSASend', 'WSARecv'},
        'ipc': {'pipe', 'mkfifo', 'msgget', 'msgsnd', 'msgrcv',
                'semget', 'semop', 'semctl'},
        'signal': {'signal', 'sigaction', 'sigprocmask', 'pthread_sigmask',
                   'kill', 'raise', 'alarm'},
        'thread': {'pthread_create', 'pthread_join', 'pthread_detach',
                   'CreateThread', 'WaitForSingleObject', 'WaitForMultipleObjects',
                   'std::thread', 'fork', 'clone', 'execve'},
    }

    def __init__(self):
        self._shared_accesses: Dict[str, Dict[str, List[int]]] = defaultdict(
            lambda: defaultdict(list))

    def classify_api(self, api_name: str) -> Optional[str]:
        """将 API 归类到资源类别"""
        nl = api_name.lower()
        for category, apis in self.SHARED_RESOURCE_APIS.items():
            for api in apis:
                if api.lower() == nl:
                    return category
        return None

    def detect_shared_accesses(self, func_name: str,
                               calls: List[Tuple[int, str]]) -> Dict[str, List[int]]:
        result: Dict[str, List[int]] = defaultdict(list)
        for addr, call in calls:
            clean = call.split('.')[-1].split('::')[-1]
            category = self.classify_api(clean)
            if category:
                result[category].append(addr)
        self._shared_accesses[func_name] = result
        return result


class TOCTOUDetector:
    """TOCTOU mode检测器

    检测典型 TOCTOU mode:
    1. check + use mode: 先checkcondition, 后在假设condition仍成立下使用资源
       - if (access(file, R_OK) == 0) { fd = open(file, O_RDONLY); }
    2. 双重取 (double fetch): 内核mode下两次从用户空间复制同一data
       - copy_from_user(&val1, user_ptr, size); ... copy_from_user(&val2, user_ptr, size);
    3. 竞态窗: 安全check (如权限check) 与资源操作之间可能存在的时间窗口
    """

    CHECK_PATTERNS = {
        'access_check': r'\b(access|faccessat|euidaccess)\s*\(',
        'stat_check': r'\b(stat|lstat|fstat|stat64|__xstat)\s*\(',
        'permission_check': r'\b(GetSecurityDescriptor|CheckTokenMembership|IsUserAdmin|SeAccessCheck)\s*\(',
        'null_check': r'\bif\s*\(\s*\w+\s*==\s*(?:NULL|nullptr|0)\s*\)',
        'bounds_check': r'\bif\s*\(\s*\w+\s*[<>]=?\s*\w+\s*\)',
        'type_check': r'\bif\s*\(\s*\w+\s*!=\s*\w+\s*\)',
        'capability_check': r'\b(capable|ns_capable|has_capability)\s*\(',
        'uid_check': r'\b(getuid|geteuid|current_uid)\s*\(',
    }

    USE_PATTERNS = {
        'file_use': r'\b(open|openat|creat|fopen|open64)\s*\(',
        'mem_use': r'\b(memcpy|memmove|strcpy|strcat|sprintf|read|write)\s*\(',
        'ptr_use': r'[*\-&]\s*\w+\s*=|->\w+\s*=|\[\w+\]\s*=',
        'ioctl_use': r'\b(ioctl|DeviceIoControl)\s*\(',
        'copy_from_user': r'\bcopy_from_user\s*\(',
        'copy_to_user': r'\bcopy_to_user\s*\(',
    }

    def detect(self, func_name: str,
               instructions: List[InstructionInfo],
               calls: List[Tuple[int, str]],
               estimated_cycles_per_instr: float = 2.0,
               cpu_freq_ghz: float = 3.0) -> List[TOCTOUPattern]:
        """
        检测函数中的 TOCTOU mode
        """
        patterns: List[TOCTOUPattern] = []

        check_addrs: List[Tuple[int, str, str]] = []
        use_addrs: List[Tuple[int, str, str]] = []

        for addr, call_name in calls:
            for check_type, pattern in self.CHECK_PATTERNS.items():
                if re.search(pattern, call_name, re.IGNORECASE):
                    check_addrs.append((addr, check_type, call_name))
                    break
            for use_type, pattern in self.USE_PATTERNS.items():
                if re.search(pattern, call_name, re.IGNORECASE):
                    use_addrs.append((addr, use_type, call_name))
                    break

        for c_addr, c_type, c_detail in check_addrs:
            subsequent_uses = [(addr, utype, udetail)
                              for addr, utype, udetail in use_addrs
                              if addr > c_addr]
            for u_addr, u_type, u_detail in subsequent_uses:
                window_instrs = sum(
                    1 for instr in instructions
                    if c_addr <= instr.address <= u_addr
                )
                window_ms = (window_instrs * estimated_cycles_per_instr /
                            (cpu_freq_ghz * 1000))

                exploitable = (
                    window_instrs > 5 and
                    window_ms < 100 and
                    'syscall' not in u_detail.lower()
                )
                is_syscall = any(
                    'syscall' in u_detail.lower() or 'int 0x80' in u_detail.lower()
                    for _, _, u_detail in [(u_addr, u_type, u_detail)]
                )

                pattern = TOCTOUPattern(
                    check_addr=c_addr,
                    use_addr=u_addr,
                    checked_condition=f"{c_type}: {c_detail}",
                    used_resource=f"{u_type}: {u_detail}",
                    window_instructions=window_instrs,
                    estimated_window_ms=round(window_ms, 3),
                    intervening_calls=[],
                    func_name=func_name,
                    is_exploitable=exploitable,
                    is_syscall_gap=is_syscall
                )
                patterns.append(pattern)

        copy_from_user_calls = [
            (addr, name) for addr, name in calls
            if 'copy_from_user' in name.lower()
        ]
        if len(copy_from_user_calls) >= 2:
            for i in range(len(copy_from_user_calls) - 1):
                a1, n1 = copy_from_user_calls[i]
                for j in range(i + 1, len(copy_from_user_calls)):
                    a2, n2 = copy_from_user_calls[j]
                    window_instrs = sum(
                        1 for instr in instructions
                        if a1 <= instr.address <= a2
                    )
                    patterns.append(TOCTOUPattern(
                        check_addr=a1,
                        use_addr=a2,
                        checked_condition="double_fetch: " + n1,
                        used_resource="double_fetch: " + n2,
                        window_instructions=window_instrs,
                        estimated_window_ms=round(
                            window_instrs * estimated_cycles_per_instr /
                            (cpu_freq_ghz * 1000), 3),
                        intervening_calls=[],
                        func_name=func_name,
                        is_exploitable=True,
                        is_syscall_gap=False
                    ))

        return patterns


class ExploitDifficultyEstimator:
    """exploit difficultyevaluate器"""

    @staticmethod
    def estimate(patterns: List[TOCTOUPattern],
                 lock_issues: int) -> ExploitDifficulty:
        if not patterns:
            return ExploitDifficulty.THEORETICAL

        min_window = min((p.estimated_window_ms for p in patterns), default=0)
        exploitable_count = sum(1 for p in patterns if p.is_exploitable)

        score = 0
        if min_window < 1:
            score += 30
        elif min_window < 10:
            score += 20
        elif min_window < 100:
            score += 10
        elif min_window < 1000:
            score += 5

        score += exploitable_count * 10
        score += lock_issues * 8

        if score >= 40:
            return ExploitDifficulty.TRIVIAL
        elif score >= 25:
            return ExploitDifficulty.EASY
        elif score >= 15:
            return ExploitDifficulty.MODERATE
        elif score >= 8:
            return ExploitDifficulty.HARD
        elif score >= 3:
            return ExploitDifficulty.EXTREME
        return ExploitDifficulty.THEORETICAL


class RaceConditionAnalyzer:
    """race conditionanalyzer (main class)"""

    CWE_MAPPING = {
        RaceConditionType.TOCTOU: "CWE-367",
        RaceConditionType.DOUBLE_FETCH: "CWE-367",
        RaceConditionType.MISSING_LOCK: "CWE-667",
        RaceConditionType.DOUBLE_LOCK: "CWE-833",
        RaceConditionType.LOCK_ORDER_INVERSION: "CWE-833",
        RaceConditionType.USE_AFTER_FREE_RACE: "CWE-416",
        RaceConditionType.SIGNAL_RACE: "CWE-364",
        RaceConditionType.SHARED_MEMORY_RACE: "CWE-366",
    }

    def __init__(self,
                 cpu_freq_ghz: float = 3.0,
                 cycles_per_instr: float = 2.0):
        self.cpu_freq_ghz = cpu_freq_ghz
        self.cycles_per_instr = cycles_per_instr
        self.lock_analyzer = LockAnalyzer()
        self.resource_detector = SharedResourceDetector()
        self.toctou_detector = TOCTOUDetector()
        self.difficulty_estimator = ExploitDifficultyEstimator()
        self._findings: List[RaceConditionFinding] = []
        self._finding_counter = 0

    def _next_id(self) -> str:
        self._finding_counter += 1
        return f"RACE-{self._finding_counter:04d}"

    def analyze(self,
                func_name: str,
                instructions: Optional[List[InstructionInfo]] = None,
                calls: Optional[List[Tuple[int, str]]] = None,
                decompiled_code: str = "",
                **kwargs) -> List[RaceConditionFinding]:
        """
        对单functionsexecuterace condition分析
        """
        if instructions is None:
            instructions = []
        if calls is None:
            calls = []

        findings: List[RaceConditionFinding] = []

        lock_pairs = self.lock_analyzer.find_lock_pairs(calls, func_name)
        unbalanced = [lp for lp in lock_pairs if not lp.is_balanced]
        if unbalanced:
            for lp in unbalanced:
                if lp.unlock_addr == 0:
                    finding = RaceConditionFinding(
                        finding_id=self._next_id(),
                        race_type=RaceConditionType.MISSING_LOCK,
                        func_name=func_name,
                        severity="high",
                        description=f"锁 {lp.lock_var} 在 0x{lp.lock_addr:x} 处获取后未释放",
                        lock_pairs=[lp],
                        exploit_difficulty=ExploitDifficulty.MODERATE,
                        remediation=f"确保在函数所有path中释放锁 {lp.lock_var}",
                        cwe_id="CWE-667"
                    )
                    findings.append(finding)

        shared = self.resource_detector.detect_shared_accesses(func_name, calls)
        shared_count = sum(len(addrs) for addrs in shared.values())
        if shared_count >= 2:
            shared_resources = [f"{cat}({len(addrs)} accesses)"
                              for cat, addrs in shared.items()]
            has_file_race = 'file' in shared and len(shared.get('file', [])) >= 2
            has_mem_race = 'memory' in shared and len(shared.get('memory', [])) >= 2

            race_type = RaceConditionType.SHARED_MEMORY_RACE
            severity = "medium"
            if has_file_race:
                race_type = RaceConditionType.TOCTOU
                severity = "high"

            finding = RaceConditionFinding(
                finding_id=self._next_id(),
                race_type=race_type,
                func_name=func_name,
                severity=severity,
                description=f"函数访问 {shared_count} 个共享资源访问点, 可能存在并发data竞争",
                shared_resources=shared_resources,
                lock_pairs=[lp for lp in lock_pairs if lp.lock_type],
                exploit_difficulty=ExploitDifficulty.MODERATE,
                remediation="考虑使用适当的锁 or 原子操作保护共享资源访问",
                cwe_id="CWE-362"
            )
            findings.append(finding)

        toctou_patterns = self.toctou_detector.detect(
            func_name, instructions, calls,
            cpu_freq_ghz=self.cpu_freq_ghz,
            estimated_cycles_per_instr=self.cycles_per_instr
        )
        if toctou_patterns:
            exploitable = [p for p in toctou_patterns if p.is_exploitable]
            severity = "critical" if exploitable else "medium"

            difficulty = self.difficulty_estimator.estimate(
                toctou_patterns, len(unbalanced))

            finding = RaceConditionFinding(
                finding_id=self._next_id(),
                race_type=RaceConditionType.TOCTOU,
                func_name=func_name,
                severity=severity,
                description=f"detected {len(toctou_patterns)} 个 TOCTOU mode "
                           f"({len(exploitable)} 个可被利用), "
                           f"最小窗口 {min(p.estimated_window_ms for p in toctou_patterns):.3f}ms",
                patterns=toctou_patterns[:20],
                shared_resources=shared_resources,
                exploit_difficulty=difficulty,
                remediation=(
                    "1. 在 check 和 use 之间使用filedescription符而非path名\n"
                    "2. 使用 fstat 替代 stat 后再 open\n"
                    "3. 在 check 和 use 之间获取file锁\n"
                    "4. 对内核代码: 使用 copy_from_user 一次到内核buffer"
                ),
                cwe_id="CWE-367",
                references=["CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition"]
            )
            findings.append(finding)

        if decompiled_code:
            decomp_findings = self._analyze_decompiled(func_name, decompiled_code)
            findings.extend(decomp_findings)

        self._findings.extend(findings)
        return findings

    def _analyze_decompiled(self, func_name: str,
                            code: str) -> List[RaceConditionFinding]:
        """based on反compile代码的static analysis"""
        findings: List[RaceConditionFinding] = []

        signal_race_patterns = [
            (r'signal\s*\(\s*\w+,\s*\w+\s*\)', 'signal handler registration'),
            (r'sigaction\s*\(', 'sigaction registration'),
        ]
        for pattern, desc in signal_race_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(RaceConditionFinding(
                    finding_id=self._next_id(),
                    race_type=RaceConditionType.SIGNAL_RACE,
                    func_name=func_name,
                    severity="medium",
                    description=f"detectedsignal处理register: {desc}",
                    remediation="signal处理器内仅使用 async-signal-safe 函数",
                    cwe_id="CWE-364"
                ))
                break

        lock_calls = re.findall(r'(?:pthread_)?mutex_lock|EnterCriticalSection|spin_lock',
                                code, re.IGNORECASE)
        if len(lock_calls) >= 2:
            unlocks = re.findall(r'(?:pthread_)?mutex_unlock|LeaveCriticalSection|spin_unlock',
                                code, re.IGNORECASE)
            if len(lock_calls) > len(unlocks):
                findings.append(RaceConditionFinding(
                    finding_id=self._next_id(),
                    race_type=RaceConditionType.DOUBLE_LOCK,
                    func_name=func_name,
                    severity="high",
                    description=f"可能的双重锁定: {len(lock_calls)} 次锁定 vs {len(unlocks)} 次解锁",
                    remediation="check所有代码path, 确保每次 lock 都有对应的 unlock",
                    cwe_id="CWE-833"
                ))

        return findings

    def analyze_multiple(self,
                         func_specs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """批量分析多functions"""
        all_findings: List[Dict[str, Any]] = []
        for spec in func_specs:
            func_name = spec.get('name', spec.get('func_name', 'unknown'))
            findings = self.analyze(
                func_name=func_name,
                instructions=spec.get('instructions', []),
                calls=spec.get('calls', []),
                decompiled_code=spec.get('decompiled_code', '')
            )
            all_findings.extend([f.to_dict() for f in findings])

        severity_counts = defaultdict(int)
        for f in self._findings:
            severity_counts[f.severity] += 1

        return {
            'success': True,
            'total_findings': len(all_findings),
            'severity_distribution': dict(severity_counts),
            'findings': all_findings,
            'stats': {
                'functions_analyzed': len(func_specs),
                'toctou_patterns': sum(
                    1 for f in self._findings
                    if f.race_type == RaceConditionType.TOCTOU),
                'lock_issues': sum(
                    1 for f in self._findings
                    if f.race_type in (RaceConditionType.MISSING_LOCK,
                                       RaceConditionType.DOUBLE_LOCK,
                                       RaceConditionType.LOCK_ORDER_INVERSION)),
            }
        }

    def generate_report(self) -> Dict[str, Any]:
        """生成race conditionanalysis report"""
        if not self._findings:
            return {'success': True, 'report': {
                'summary': '未发现race condition',
                'findings': [],
                'risk_level': 'none'
            }}

        critical = sum(1 for f in self._findings if f.severity == 'critical')
        high = sum(1 for f in self._findings if f.severity == 'high')
        medium = sum(1 for f in self._findings if f.severity == 'medium')
        low = sum(1 for f in self._findings if f.severity == 'low')

        if critical > 0:
            risk = 'critical'
        elif high > 2:
            risk = 'high'
        elif high > 0 or medium > 2:
            risk = 'medium'
        elif medium > 0:
            risk = 'low'
        else:
            risk = 'info'

        return {
            'success': True,
            'report': {
                'summary': f'发现 {len(self._findings)} 个race condition: '
                          f'{critical} critical, {high} high, {medium} medium, {low} low',
                'risk_level': risk,
                'findings': [f.to_dict() for f in self._findings],
                'recommendations': list(set(
                    f.remediation for f in self._findings if f.remediation
                ))
            }
        }


def analyze_race_conditions(func_specs: List[Dict[str, Any]],
                            **kwargs) -> Dict[str, Any]:
    """
    race condition分析入口函数
    """
    analyzer = RaceConditionAnalyzer(
        cpu_freq_ghz=kwargs.get('cpu_freq_ghz', 3.0),
        cycles_per_instr=kwargs.get('cycles_per_instr', 2.0)
    )
    result = analyzer.analyze_multiple(func_specs)
    report = analyzer.generate_report()
    result['report'] = report['report']
    return result


__all__ = [
    "RaceConditionAnalyzer",
    "RaceConditionType",
    "ExploitDifficulty",
    "TOCTOUPattern",
    "RaceConditionFinding",
    "LockAnalyzer",
    "TOCTOUDetector",
    "analyze_race_conditions"
]
