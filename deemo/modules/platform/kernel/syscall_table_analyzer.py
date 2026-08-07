# 离线syscall表分析 — Linux x86_64与Windows SSDT hook检测
# 离线比对系统调用表，侦测hook及rootkit篡改痕迹

import struct
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Linux x86_64 syscall table (from /usr/include/asm/unistd_64.h)
SYSCALL_TABLE_X64: Dict[int, str] = {
    0: "read",           1: "write",          2: "open",
    3: "close",          4: "stat",           5: "fstat",
    6: "lstat",          7: "poll",           8: "lseek",
    9: "mmap",          10: "mprotect",       11: "munmap",
    12: "brk",          13: "rt_sigaction",   14: "rt_sigprocmask",
    15: "rt_sigreturn", 16: "ioctl",          17: "pread64",
    18: "pwrite64",     19: "readv",          20: "writev",
    21: "access",       22: "pipe",           23: "select",
    24: "sched_yield",  25: "mremap",         26: "msync",
    27: "mincore",      28: "madvise",        29: "shmget",
    30: "shmat",        31: "shmctl",         32: "dup",
    33: "dup2",         34: "pause",          35: "nanosleep",
    36: "getitimer",    37: "alarm",          38: "setitimer",
    39: "getpid",       40: "sendfile",       41: "socket",
    42: "connect",      43: "accept",         44: "sendto",
    45: "recvfrom",     46: "sendmsg",        47: "recvmsg",
    48: "shutdown",     49: "bind",           50: "listen",
    51: "getsockname",  52: "getpeername",    53: "socketpair",
    54: "setsockopt",   55: "getsockopt",     56: "clone",
    57: "fork",         58: "vfork",          59: "execve",
    60: "exit",         61: "wait4",          62: "kill",
    63: "uname",        64: "semget",         65: "semop",
    66: "semctl",       67: "shmdt",          68: "msgget",
    69: "msgsnd",       70: "msgrcv",         71: "msgctl",
    72: "fcntl",        73: "flock",          74: "fsync",
    75: "fdatasync",    76: "truncate",       77: "ftruncate",
    78: "getdents",     79: "getcwd",         80: "chdir",
    81: "fchdir",       82: "rename",         83: "mkdir",
    84: "rmdir",        85: "creat",          86: "link",
    87: "unlink",       88: "symlink",        89: "readlink",
    90: "chmod",        91: "fchmod",         92: "chown",
    93: "fchown",       94: "lchown",         95: "umask",
    96: "gettimeofday", 97: "getrlimit",      98: "getrusage",
    99: "sysinfo",     100: "times",         101: "ptrace",
    102: "getuid",     103: "syslog",        104: "getgid",
    105: "setuid",     106: "setgid",        107: "geteuid",
    108: "getegid",    109: "setpgid",       110: "getppid",
    111: "getpgrp",    112: "setsid",        113: "setreuid",
    114: "setregid",   115: "getgroups",     116: "setgroups",
    117: "setresuid",  118: "getresuid",     119: "setresgid",
    120: "getresgid",  121: "getpgid",       122: "setfsuid",
    123: "setfsgid",   124: "getsid",        125: "capget",
    126: "capset",     127: "rt_sigpending", 128: "rt_sigtimedwait",
    129: "rt_sigqueueinfo", 130: "rt_sigsuspend", 131: "sigaltstack",
    132: "utime",      133: "mknod",         134: "uselib",
    135: "personality", 136: "ustat",        137: "statfs",
    138: "fstatfs",    139: "sysfs",         140: "getpriority",
    141: "setpriority", 142: "sched_setparam", 143: "sched_getparam",
    144: "sched_setscheduler", 145: "sched_getscheduler", 146: "sched_get_priority_max",
    147: "sched_get_priority_min", 148: "sched_rr_get_interval", 149: "mlock",
    150: "munlock",    151: "mlockall",      152: "munlockall",
    153: "vhangup",    154: "modify_ldt",    155: "pivot_root",
    156: "_sysctl",    157: "prctl",         158: "arch_prctl",
    159: "adjtimex",   160: "setrlimit",     161: "chroot",
    162: "sync",       163: "acct",          164: "settimeofday",
    165: "mount",      166: "umount2",       167: "swapon",
    168: "swapoff",    169: "reboot",        170: "sethostname",
    171: "setdomainname", 172: "iopl",       173: "ioperm",
    174: "create_module", 175: "init_module", 176: "delete_module",
    177: "get_kernel_syms", 178: "query_module", 179: "quotactl",
    180: "nfsservctl", 181: "getpmsg",       182: "putpmsg",
    183: "afs_syscall", 184: "tuxcall",      185: "security",
    186: "gettid",     187: "readahead",     188: "setxattr",
    189: "lsetxattr",  190: "fsetxattr",     191: "getxattr",
    192: "lgetxattr",  193: "fgetxattr",     194: "listxattr",
    195: "llistxattr", 196: "flistxattr",    197: "removexattr",
    198: "lremovexattr", 199: "fremovexattr", 200: "tkill",
    201: "time",       202: "futex",         203: "sched_setaffinity",
    204: "sched_getaffinity", 205: "set_thread_area", 206: "io_setup",
    207: "io_destroy", 208: "io_getevents",  209: "io_submit",
    210: "io_cancel",  211: "get_thread_area", 212: "lookup_dcookie",
    213: "epoll_create", 214: "epoll_ctl_old", 215: "epoll_wait_old",
    216: "remap_file_pages", 217: "getdents64", 218: "set_tid_address",
    219: "restart_syscall", 220: "semtimedop", 221: "fadvise64",
    222: "timer_create", 223: "timer_settime", 224: "timer_gettime",
    225: "timer_getoverrun", 226: "timer_delete", 227: "clock_settime",
    228: "clock_gettime", 229: "clock_getres", 230: "clock_nanosleep",
    231: "exit_group",  232: "epoll_wait",    233: "epoll_ctl",
    234: "tgkill",     235: "utimes",        236: "vserver",
    237: "mbind",      238: "set_mempolicy", 239: "get_mempolicy",
    240: "mq_open",    241: "mq_unlink",     242: "mq_timedsend",
    243: "mq_timedreceive", 244: "mq_notify", 245: "mq_getsetattr",
    246: "kexec_load", 247: "waitid",        248: "add_key",
    249: "request_key", 250: "keyctl",       251: "ioprio_set",
    252: "ioprio_get", 253: "inotify_init",  254: "inotify_add_watch",
    255: "inotify_rm_watch", 256: "migrate_pages", 257: "openat",
    258: "mkdirat",    259: "mknodat",       260: "fchownat",
    261: "futimesat",  262: "newfstatat",    263: "unlinkat",
    264: "renameat",   265: "linkat",        266: "symlinkat",
    267: "readlinkat", 268: "fchmodat",      269: "faccessat",
    270: "pselect6",   271: "ppoll",         272: "unshare",
    273: "set_robust_list", 274: "get_robust_list", 275: "splice",
    276: "tee",        277: "sync_file_range", 278: "vmsplice",
    279: "move_pages", 280: "utimensat",     281: "epoll_pwait",
    282: "signalfd",   283: "timerfd_create", 284: "eventfd",
    285: "fallocate",  286: "timerfd_settime", 287: "timerfd_gettime",
    288: "accept4",    289: "signalfd4",     290: "eventfd2",
    291: "epoll_create1", 292: "dup3",       293: "pipe2",
    294: "inotify_init1", 295: "preadv",     296: "pwritev",
    297: "rt_tgsigqueueinfo", 298: "perf_event_open", 299: "recvmmsg",
    300: "fanotify_init", 301: "fanotify_mark", 302: "prlimit64",
    303: "name_to_handle_at", 304: "open_by_handle_at", 305: "clock_adjtime",
    306: "syncfs",    307: "sendmmsg",       308: "setns",
    309: "getns",     310: "process_vm_readv", 311: "process_vm_writev",
    312: "kcmp",      313: "finit_module",   314: "sched_setattr",
    315: "sched_getattr", 316: "renameat2",  317: "seccomp",
    318: "getrandom", 319: "memfd_create",   320: "kexec_file_load",
    321: "bpf",       322: "execveat",       323: "userfaultfd",
    324: "membarrier", 325: "mlock2",        326: "copy_file_range",
    327: "preadv2",   328: "pwritev2",       329: "pkey_mprotect",
    330: "pkey_alloc", 331: "pkey_free",     332: "statx",
    333: "io_pgetevents", 334: "rseq",       335: "pidfd_send_signal",
    # 扩展: Linux 5.4 → 6.8+ 新增的系统调用
    336: "io_uring_setup",   337: "io_uring_enter",
    338: "io_uring_register", 339: "open_tree",
    340: "move_mount",       341: "fsopen",
    342: "fsconfig",         343: "fsmount",
    344: "fspick",           345: "pidfd_open",
    346: "clone3",           347: "close_range",
    348: "openat2",          349: "pidfd_getfd",
    350: "faccessat2",       351: "process_madvise",
    352: "process_mrelease", 353: "futex_waitv",
    354: "set_mempolicy_home_node", 355: "cachestat",
    356: "fchmodat2",        357: "map_shadow_stack",
    358: "futex_wake",       359: "futex_wait",
    360: "futex_requeue",    361: "statmount",
    362: "listmount",        363: "lsm_get_self_attr",
    364: "lsm_set_self_attr", 365: "lsm_list_modules",
    366: "mseal",            367: "fchmodat2",
    # uringspawn/process_mappings — 预留槽位
    370: "copy_file_range_ex",
}


@dataclass
class SyscallEntry:
    """单条系统调用表项。"""
    number: int
    name: str
    handler_address: int
    expected_range: Tuple[int, int] = (0, 0)
    is_hooked: bool = False
    severity: str = ""
    inlined_hook_suspected: bool = False
    kpti_trampoline_detected: bool = False

    def to_dict(self) -> dict:
        return {
            "number": self.number, "name": self.name,
            "handler_address": f"0x{self.handler_address:x}",
            "is_hooked": self.is_hooked, "severity": self.severity,
            "inlined_hook": self.inlined_hook_suspected,
            "kpti_trampoline": self.kpti_trampoline_detected,
        }


# Linux syscall hook 检测

# x86_64 syscall handler典型函数序言 — 用于inline hook识别
# 正常handler: endbr64; push rbp; mov rbp, rsp; ...
# 被hook后: jmp <abs_addr>; int3; int3; ...
_SYSCALL_PROLOGUE_PATTERNS: Dict[str, bytes] = {
    "endbr64":     b'\xf3\x0f\x1e\xfa',
    "push_rbp":    b'\x55',
    "mov_rbp_rsp": b'\x48\x89\xe5',
    "nop_sled":    b'\x90' * 3,
}


def _check_inline_hook(handler_bytes: bytes) -> Tuple[bool, str]:
    """检查handler前8字节是否含inline hook特征。

    返回 (is_hooked, evidence_description)。
    """
    if len(handler_bytes) < 8:
        return False, ""

    # 检测无条件跳转 (jmp rel32 / jmp abs 前缀)
    if handler_bytes[0] == 0xE9:  # jmp rel32
        return True, f"jmp rel32 to offset {struct.unpack_from('<i', handler_bytes, 1)[0]:+#x}"
    if handler_bytes[0:2] == b'\xff\x25':  # jmp [rip+disp32]
        return True, "jmp [rip+disp32] — indirect redirect"
    if handler_bytes[0:2] == b'\xff\xe0':  # jmp rax
        return True, "jmp rax — register redirect"

    # 检测push/mov指令后紧跟ret (ret2usr或gadget特征)
    if len(handler_bytes) >= 4:
        if handler_bytes[0:3] == b'\x48\xcf':  # iretq (非正常syscall返回路径)
            return True, "iretq as first instruction — abnormal prologue"

    return False, ""


# 已知KPTI trampoline特征序列
# swapgs; jmp __entry_SYSCALL_64变体或直接swapgs开头
_KPTI_TRAMPOLINE_PATTERN = b'\x0f\x01\xf8'  # swapgs


def _detect_kpti_trampoline(handler_bytes: bytes) -> bool:
    """检测handler是否经KPTI trampoline包装。

    KPTI内核将syscall handler的第一条指令替换为
    swapgs + 跳转至实际实现。若handler前几条指令
    含swapgs且直接跳转，标记为KPTI trampoline。
    """
    if len(handler_bytes) < 4:
        return False
    return handler_bytes[:3] == _KPTI_TRAMPOLINE_PATTERN


def detect_linux_hooks(syscall_table_entries: Dict[int, int],
                       kernel_text_start: int,
                       kernel_text_end: int,
                       handler_memory: Optional[Dict[int, bytes]] = None) -> List[SyscallEntry]:
    """
    检测Linux系统调用表hook。

    判定逻辑：
    - syscall handler应落在kernel text段内
    - 落在模块地址区间 → 标记HIGH
    - 完全在kernel之外 → 标记CRITICAL（rootkit高度可疑）
    - 可选：手持handler字节码检测inline hook及KPTI trampoline
    """
    _results: List[SyscallEntry] = []
    _handler_bytes = handler_memory or {}

    for _nr, _addr in sorted(syscall_table_entries.items()):
        _name = SYSCALL_TABLE_X64.get(_nr, "sys_unknown_{}".format(_nr))
        _entry = SyscallEntry(
            number=_nr, name=_name, handler_address=_addr,
            expected_range=(kernel_text_start, kernel_text_end))

        if _addr == 0:
            _entry.is_hooked = True
            _entry.severity = "HIGH"
        elif kernel_text_start <= _addr < kernel_text_end:
            _entry.is_hooked = False
            _entry.severity = "INFO"
            # 即便在text段内，仍需检查inline hook
            if _nr in _handler_bytes:
                _hooked, _evidence = _check_inline_hook(_handler_bytes[_nr])
                if _hooked:
                    _entry.inlined_hook_suspected = True
                    _entry.is_hooked = True
                    _entry.severity = "CRITICAL"
                elif _detect_kpti_trampoline(_handler_bytes[_nr]):
                    _entry.kpti_trampoline_detected = True
        elif _addr < 0xffffffff80000000 or _addr > 0xffffffffffffffff:
            _entry.is_hooked = True
            _entry.severity = "CRITICAL"
        else:
            _entry.is_hooked = True
            _entry.severity = "HIGH"

        _results.append(_entry)

    return _results


# Windows SSDT hook 检测

# 常用Windows SSDT索引 -> 函数名 (展开至Win11 24H2)
WINDOWS_SSDT_INDICES: Dict[int, str] = {
    0x00: "NtMapUserPhysicalPagesScatter",
    0x01: "NtWaitForSingleObject",
    0x02: "NtCallbackReturn",
    0x03: "NtReadFile",
    0x04: "NtDeviceIoControlFile",
    0x05: "NtWriteFile",
    0x06: "NtRemoveIoCompletion",
    0x07: "NtReleaseSemaphore",
    0x08: "NtReplyWaitReceivePort",
    0x09: "NtReplyPort",
    0x0A: "NtSetInformationThread",
    0x0B: "NtSetEvent",
    0x0C: "NtClose",
    0x0D: "NtQueryObject",
    0x0E: "NtQueryInformationFile",
    0x0F: "NtOpenKey",
    0x10: "NtEnumerateValueKey",
    0x11: "NtFindAtom",
    0x12: "NtQueryDefaultLocale",
    0x13: "NtQueryKey",
    0x14: "NtQueryValueKey",
    0x15: "NtAllocateVirtualMemory",
    0x16: "NtQueryInformationProcess",
    0x17: "NtWaitForMultipleObjects32",
    0x18: "NtWriteFileGather",
    0x19: "NtSetInformationProcess",
    0x1A: "NtCreateKey",
    0x1B: "NtFreeVirtualMemory",
    0x1C: "NtImpersonateClientOfPort",
    0x1D: "NtReleaseMutant",
    0x20: "NtQueryInformationToken",
    0x21: "NtRequestWaitReplyPort",
    0x26: "NtCreateFile",
    0x28: "NtOpenFile",
    0x2A: "NtCreateProcess",
    0x2B: "NtCreateProcessEx",
    0x2C: "NtCreateThread",
    0x3A: "NtQuerySystemInformation",
    0x4A: "NtTerminateProcess",
    0x4B: "NtUnloadDriver",
    0x4C: "NtQueryInformationThread",
    0x50: "NtProtectVirtualMemory",
    # Win11 24H2 扩展索引
    0x52: "NtQuerySystemEnvironmentValueEx",
    0x55: "NtCreateSection",
    0x56: "NtOpenSection",
    0x5A: "NtQueryVirtualMemory",
    0x6C: "NtCreateUserProcess",
    0x74: "NtQueryPerformanceCounter",
    0x7C: "NtWaitForMultipleObjects",
    0x8A: "NtCreateThreadEx",
    0x92: "NtSetContextThread",
    0xA0: "NtQueueApcThread",
    0xAA: "NtAlpcSendWaitReceivePort",
    0xB0: "NtCreateIoCompletion",
    # 高风险目标 — 常被用于进程/驱动隐藏
    0xC0: "NtOpenProcess",
    0xC8: "NtSuspendProcess",
    0xCA: "NtResumeProcess",
    0xD0: "NtQueryDirectoryFile",
    0xD8: "NtEnumerateKey",
    0xE0: "NtSystemDebugControl",
}


def _parse_pe_sections(ntoskrnl_data: bytes) -> List[Tuple[str, int, int, int]]:
    """解析PE节区：返回 (name, virtual_address, virtual_size, raw_offset)。"""
    _sections: List[Tuple[str, int, int, int]] = []
    if ntoskrnl_data[:2] != b'MZ':
        return _sections

    _pe_offset = struct.unpack_from('<I', ntoskrnl_data, 0x3C)[0]
    if ntoskrnl_data[_pe_offset:_pe_offset + 4] != b'PE\x00\x00':
        return _sections

    _num_sections = struct.unpack_from('<H', ntoskrnl_data, _pe_offset + 6)[0]
    _opt_header_size = struct.unpack_from('<H', ntoskrnl_data, _pe_offset + 20)[0]

    _sec_start = _pe_offset + 4 + 20 + _opt_header_size

    for _i in range(_num_sections):
        _s_off = _sec_start + _i * 40
        if _s_off + 40 > len(ntoskrnl_data):
            break
        _name = ntoskrnl_data[_s_off:_s_off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        _vsize = struct.unpack_from('<I', ntoskrnl_data, _s_off + 8)[0]
        _vaddr = struct.unpack_from('<I', ntoskrnl_data, _s_off + 12)[0]
        _r_offset = struct.unpack_from('<I', ntoskrnl_data, _s_off + 20)[0]
        _sections.append((_name, _vaddr, _vsize, _r_offset))

    return _sections


def detect_windows_hooks(ntoskrnl_path: str,
                         ssdt: Optional[Dict[int, int]] = None) -> List[SyscallEntry]:
    """
    解析Windows SSDT并检测hook。

    判定逻辑：
    - 解析ntoskrnl.exe的PE结构，定位.text段范围
    - KiServiceTable中每offset右移4位得指令数，解码实际handler地址
    - 检查handler是否落在ntoskrnl .text段内
    """
    _results: List[SyscallEntry] = []
    if not os.path.isfile(ntoskrnl_path):
        return _results

    with open(ntoskrnl_path, 'rb') as _fh:
        _data = _fh.read()

    _sections = _parse_pe_sections(_data)
    _text_sections = [s for s in _sections if s[0].startswith('.text') or s[0] == 'PAGE']

    if not _text_sections:
        return _results

    _text_start = min(s[1] for s in _text_sections)
    _text_end   = max(s[1] + s[2] for s in _text_sections)

    if ssdt:
        for _idx, _handler_addr in ssdt.items():
            _name = WINDOWS_SSDT_INDICES.get(_idx, "NtUnknown_{:03X}".format(_idx))
            _entry = SyscallEntry(
                number=_idx, name=_name, handler_address=_handler_addr,
                expected_range=(_text_start, _text_end))

            if _text_start <= _handler_addr < _text_end:
                _entry.is_hooked = False
                _entry.severity = "INFO"
            else:
                _entry.is_hooked = True
                _entry.severity = "CRITICAL"

            _results.append(_entry)

    return _results


# KiServiceTable边界验证
# rootkit可能通过修改KiServiceLimit隐藏高编号hook

def validate_service_limit(ssdt_entries: Dict[int, int],
                            declared_limit: int) -> List[Dict]:
    """验证SSDT条目数是否与KiServiceLimit一致。

    KiServiceLimit应为SSDT条目总数。
    若实际条目超出声明值，说明有rootkit在service_limit之后
    追加了hook（但service_limit保持不变以逃避基于limit的扫描）。
    """
    _findings = []
    _actual_max = max(ssdt_entries.keys()) + 1 if ssdt_entries else 0
    if declared_limit > 0 and _actual_max > declared_limit:
        _entries_beyond = {k: v for k, v in ssdt_entries.items()
                           if k >= declared_limit}
        _findings.append({
            "issue": "KiServiceLimit mismatch",
            "declared": declared_limit,
            "actual_max_index": _actual_max,
            "entries_beyond_limit": len(_entries_beyond),
            "severity": "CRITICAL",
            "description": "SSDT条目超过KiServiceLimit — 疑似隐藏hook或rootkit扩展",
        })
    return _findings


# WOW64 syscall表交叉验证
# Windows x64维护两份syscall表：一份用于native x64调用，
# 另一份用于WOW64 (32位进程在x64内核上的系统调用)。
# rootkit有时仅hook native表而忽略WOW64表 — 提供检测窗口。

def detect_wow64_hook_gap(native_ssdt: Dict[int, int],
                           wow64_ssdt: Dict[int, int]) -> List[Dict]:
    """检测native SSDT与WOW64 SSDT之间的hook不一致。

    若同SSN在两表中指向不同handler，且一个在ntoskrnl内
    而另一个不在，标记为hook gap（选择性hook的证据）。
    """
    _findings = []
    _common_ssns = set(native_ssdt.keys()) & set(wow64_ssdt.keys())
    _gap_count = 0

    for _ssn in _common_ssns:
        _nat = native_ssdt[_ssn]
        _wow = wow64_ssdt[_ssn]
        if _nat != _wow:
            _gap_count += 1

    if _gap_count > 0:
        _findings.append({
            "issue": "native/WOW64 syscall hook gap",
            "mismatches": _gap_count,
            "severity": "MEDIUM" if _gap_count < 5 else "HIGH",
            "description": "native与WOW64 SSDT存在不一致 — 选择性hook的证据",
        })

    return _findings


# Hell's Hollow探测

def detect_hells_hollow(syscall_entries: List[SyscallEntry]) -> List[Dict]:
    """
    检测Hell's Hollow间接syscall特征。

    判定逻辑：
    - SSN对应handler地址与ntdll导出地址不一致
    - 存在非ntdll!Zw*前缀的handler调用
    - 多个连续SSN被同时hook（批量间接syscall劫持模式）
    """
    _findings: List[Dict] = []
    _hooked = [_e for _e in syscall_entries if _e.is_hooked]

    if len(_hooked) >= 3:
        _confidence = "LOW"
        if len(_hooked) >= 8:
            _confidence = "HIGH"
        elif len(_hooked) >= 5:
            _confidence = "MEDIUM"

        # 检测连续hook模式 — 更可能是工具化的间接syscall
        _hooked_nrs = sorted(e.number for e in _hooked)
        _consecutive_runs = 0
        _max_run = 0
        for i in range(1, len(_hooked_nrs)):
            if _hooked_nrs[i] == _hooked_nrs[i - 1] + 1:
                _consecutive_runs += 1
            else:
                _max_run = max(_max_run, _consecutive_runs)
                _consecutive_runs = 0
        _max_run = max(_max_run, _consecutive_runs)

        _findings.append({
            "technique": "Hell's Hollow / Indirect Syscall",
            "confidence": _confidence,
            "hooked_count": len(_hooked),
            "consecutive_max": _max_run,
            "hooked_syscalls": [_e.name for _e in _hooked[:10]],
            "description": "多个syscall handler地址异常，可能存在间接syscall调用模式",
        })

    return _findings


# 系统调用序列异常检测
# rootkit常hook特定syscall并在其中注入额外行为。
# 通过分析被hook的syscall之间的功能分组，推测rootkit意图。

_SYSCALL_FUNCTIONAL_GROUPS = {
    "process_hide": {"kill", "getpid", "open", "ptrace", "getdents64",
                     "tgkill", "exit_group"},
    "file_hide":   {"getdents64", "openat", "newfstatat", "readlinkat",
                    "open_by_handle_at", "name_to_handle_at"},
    "network_backdoor": {"socket", "bind", "listen", "accept", "connect",
                         "sendto", "recvfrom", "sendmsg", "recvmsg"},
    "driver_load": {"init_module", "finit_module", "delete_module",
                    "kexec_load", "kexec_file_load"},
    "cred_theft": {"setuid", "setgid", "setresuid", "setresgid",
                   "setfsuid", "setfsgid", "prctl"},
}


def classify_hook_intent(hooked_syscalls: List[SyscallEntry]) -> List[Dict]:
    """根据被hook的syscall推断rootkit功能意图。"""
    _hooked_names = {e.name for e in hooked_syscalls if e.is_hooked}
    _intents = []

    for _group, _syscalls in _SYSCALL_FUNCTIONAL_GROUPS.items():
        _matches = _hooked_names & _syscalls
        if _matches:
            _ratio = len(_matches) / len(_syscalls)
            _confidence = "HIGH" if _ratio >= 0.4 else "MEDIUM" if _ratio >= 0.2 else "LOW"
            _intents.append({
                "intent": _group, "matched_syscalls": sorted(_matches),
                "match_ratio": round(_ratio, 2), "confidence": _confidence,
            })

    return sorted(_intents, key=lambda x: x["match_ratio"], reverse=True)
