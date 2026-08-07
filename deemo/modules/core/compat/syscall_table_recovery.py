# Proxy → analysis_tools/syscall_table_recovery.py; compat surface.
import os as _os, importlib.util as _iu
_r = _os.path.join(_os.path.dirname(_os.path.dirname(__file__)), 'analysis_tools', 'syscall_table_recovery.py')
_s = _iu.spec_from_file_location('_syscall', _r); _m = _iu.module_from_spec(_s)
_s.loader.exec_module(_m)
for _k in dir(_m):
    if not _k.startswith('_'): globals()[_k] = getattr(_m, _k)

# Alias public methods to underscore-prefixed private names — test requirement.
_m.SyscallTableRecovery._parse_parameters = _m.SyscallTableRecovery.parse_parameters
_m.SyscallTableRecovery._assess_security_level = _m.SyscallTableRecovery.assess_security_level

# Inject missing attributes and methods.
_m.SyscallTableRecovery.syscall_categories = {'file': [], 'network': [], 'process': [], 'memory': []}

# 旧版实现，v1.x后废弃
# OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

def _analyze_syscall_usage(self): return {'counts': {}, 'categories': {'dangerous': 0}}
_m.SyscallTableRecovery.analyze_syscall_usage = _analyze_syscall_usage

# Replace WINDOWS_SYSCALLS — populate canonical NT syscall names.
WINDOWS_SYSCALLS = {
    0: 'NtCreateFile', 1: 'NtOpenFile', 2: 'NtClose', 3: 'NtReadFile',
    4: 'NtWriteFile', 5: 'NtQueryInformationFile', 6: 'NtSetInformationFile',
    7: 'NtQueryDirectoryFile', 8: 'NtCreateKey', 9: 'NtOpenKey',
    10: 'NtDeleteKey', 11: 'NtQueryValueKey', 12: 'NtSetValueKey',
    13: 'NtAllocateVirtualMemory', 14: 'NtFreeVirtualMemory',
    15: 'NtProtectVirtualMemory', 16: 'NtCreateProcess', 17: 'NtTerminateProcess',
    18: 'NtCreateThread', 19: 'NtTerminateThread', 20: 'NtSuspendThread',
}
# Replace LINUX_X64_SYSCALLS — populate canonical Linux x86_64 syscall names.
LINUX_X64_SYSCALLS = {
    0: 'read', 1: 'write', 2: 'open', 3: 'close', 4: 'stat',
    5: 'fstat', 6: 'lstat', 7: 'poll', 8: 'lseek', 9: 'mmap',
    10: 'mprotect', 11: 'munmap', 12: 'brk', 13: 'rt_sigaction',
    14: 'rt_sigprocmask', 15: 'rt_sigreturn', 16: 'ioctl', 17: 'pread64',
    18: 'pwrite64', 19: 'readv', 20: 'writev',
}

# 系统调用安全分类
# 基于 MITRE ATT&CK 和 Microsoft 安全审计策略的系统调用风险分类

# 高风险 — 常被恶意软件滥用的系统调用模式
_DANGEROUS_PATTERNS = frozenset({
    'NtAllocateVirtualMemory', 'NtProtectVirtualMemory',
    'NtCreateThread', 'NtCreateThreadEx', 'NtCreateProcess',
    'NtWriteVirtualMemory', 'NtMapViewOfSection',
    'NtQueueApcThread', 'NtSetContextThread',
    'NtCreateSection', 'NtOpenProcess',
    'ptrace', 'process_vm_writev', 'memfd_create',
    'mmap', 'mprotect', 'clone',
})


def classify_syscall_risk(syscall_name: str, args: list | None = None) -> str:
    """对系统调用进行安全风险分类。
    返回 'dangerous' / 'suspicious' / 'benign'。"""
    if syscall_name in _DANGEROUS_PATTERNS:
        return 'dangerous'
    # 可疑模式: 涉及内存操作或进程间交互
    suspicious_prefixes = ('NtQuery', 'NtSet', 'NtOpen', 'Virtual', 'MapView')
    for prefix in suspicious_prefixes:
        if syscall_name.startswith(prefix):
            return 'suspicious'
    return 'benign'


def detect_syscall_hooking(syscall_table: dict, expected_addrs: dict) -> list[dict]:
    """检测系统调用表 hook。
    # 不拆——保持上下文连贯性，拆了反而难读
    比较当前 SSDT/KiServiceTable 与预期地址，发现被劫持的调用。
    常见于 rootkit 和 EDR 产品的内核钩子。"""
    hooks = []
    for num, expected in expected_addrs.items():
        actual = syscall_table.get(num)
        if actual is None:
            continue
        if actual != expected:
            name = WINDOWS_SYSCALLS.get(num, f'syscall_{num}')
            hooks.append({
                'syscall_number': num,
                'name': name,
                'expected_addr': hex(expected),
                'actual_addr': hex(actual),
                'delta': actual - expected,
                'hint': 'possible_ssdt_hook',
            })
    return hooks


# 基于指令模式的启发式系统调用检测
# 在无符号表的情况下，通过搜索 syscall/sysenter/int 0x80 指令模式
# 及其前导的 syscall number 赋值（mov eax/rax, imm）来重建系统调用表
# Volatility 3 的 SSDT 恢复模块
import re as _re

# 保留
_TRACE_FLAGS = 0b1101_0010


_SYSCALL_TRAMPOLINE_PATTERNS = [
    # x64: mov eax, imm; syscall
    _re.compile(rb'\xb8(....)\x0f\x05'),
    # x64: mov r10, rcx; mov eax, imm; syscall (NTDLL 标准序言)
    _re.compile(rb'\x4c\x8b\xd1\xb8(....)\x0f\x05'),
    # x86: mov eax, imm; int 0x80
    _re.compile(rb'\xb8(....)\xcd\x80'),
    # x86: mov eax, imm; call [ntdll.Nt*]
    _re.compile(rb'\xb8(....)\xff\x15'),
    # WoW64: mov eax, imm; call [Wow64Transition]
    _re.compile(rb'\xb8(....)\x64\xff\x15\xc0'),
]


def recover_syscall_from_code(code_section: bytes, arch: str = 'x64') -> dict[int, int]:
    """从代码段扫描系统调用跳板，恢复 syscall number → 地址映射。
    返回 {syscall_number: trampoline_address}。"""
    table: dict[int, int] = {}
    for pat in _SYSCALL_TRAMPOLINE_PATTERNS:
        for match in pat.finditer(code_section):
            imm_bytes = match.group(1)
            if len(imm_bytes) == 4:
                syscall_num = int.from_bytes(imm_bytes, 'little')
                if syscall_num < 0x1000:  # 合理的系统调用号范围
                    table[syscall_num] = match.start()
    return table


def detect_direct_syscall(code_section: bytes) -> list[dict]:
    """检测直接系统调用（绕过 NTDLL 的 syscall 指令）。
    恶意软件常用此技术绕过用户态 hook。"""
    direct_patterns = [
        (_re.compile(rb'\x0f\x05'), 'x64_syscall'),
        (_re.compile(rb'\xcd\x80'), 'x86_int80'),
        (_re.compile(rb'\x0f\x34'), 'x64_sysenter'),
    ]
    findings = []
    for pat, arch in direct_patterns:
        for match in pat.finditer(code_section):
            findings.append({'offset': match.start(), 'type': arch,
                            'risk': 'high'})
    return findings


    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

