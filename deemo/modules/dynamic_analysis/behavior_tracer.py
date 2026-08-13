# behavior_tracer.py — dynamic API-call-sequence profiler
# Categorises sequences into behaviour profiles: file, network, process, registry.

import re
import json
from collections import OrderedDict, Counter
from enum import IntFlag

name = "BehaviorTracer"
module = "behavior_tracer"

# ── API taxonomy ───────────────────────────────────────────────────────────
_FILE_OPS = {
    'CreateFile', 'OpenFile', 'ReadFile', 'WriteFile', 'DeleteFile',
    'fopen', 'fread', 'fwrite', 'fclose', 'open', 'read', 'write',
    'close', 'creat', 'unlink', 'remove', 'rename', 'NtCreateFile',
    'NtReadFile', 'NtWriteFile', 'ZwCreateFile', 'ZwReadFile',
    'SetFilePointer', 'LockFile', 'UnlockFile', 'MoveFile',
    'CopyFile', 'GetFileSize', 'FindFirstFile', 'FindNextFile',
}

_NETWORK_OPS = {
    'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',
    'sendto', 'recvfrom', 'WSAStartup', 'WSASocket', 'WSASend',
    'WSARecv', 'getaddrinfo', 'gethostbyname', 'gethostbyaddr',
    'URLDownloadToFile', 'InternetOpen', 'InternetConnect',
    'InternetReadFile', 'HttpSendRequest', 'HttpOpenRequest',
    'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest',
    'WinHttpSendRequest', 'WinHttpReceiveResponse',
}

_PROCESS_OPS = {
    'CreateProcess', 'CreateProcessAsUser', 'CreateProcessWithLogon',
    'CreateProcessWithToken', 'OpenProcess', 'TerminateProcess',
    'system', 'popen', 'exec', 'fork', 'WinExec', 'ShellExecute',
    'NtCreateProcess', 'NtTerminateProcess', 'CreateThread',
    'CreateRemoteThread', 'NtCreateThread', 'QueueUserAPC',
}

_REGISTRY_OPS = {
    'RegOpenKey', 'RegCreateKey', 'RegSetValue', 'RegDeleteValue',
    'RegQueryValue', 'RegCloseKey', 'RegEnumKey', 'RegEnumValue',
    'NtOpenKey', 'NtCreateKey', 'NtSetValueKey', 'NtQueryValueKey',
}

_MEMORY_OPS = {
    'VirtualAlloc', 'VirtualFree', 'VirtualProtect', 'NtAllocateVirtualMemory',
    'NtProtectVirtualMemory', 'mprotect', 'mmap', 'munmap', 'HeapCreate',
    'HeapAlloc', 'HeapFree', 'malloc', 'free', 'realloc',
}

_CRYPTO_OPS = {
    'CryptEncrypt', 'CryptDecrypt', 'CryptHashData', 'CryptAcquireContext',
    'BCryptEncrypt', 'BCryptDecrypt', 'EVP_EncryptInit', 'EVP_DecryptInit',
}

# ── types ──────────────────────────────────────────────────────────────────
class BehaviorCategory(IntFlag):
    NONE = 0
    FILE_IO = 1 << 0
    NETWORK = 1 << 1
    PROCESS = 1 << 2
    REGISTRY = 1 << 3
    MEMORY_MANIP = 1 << 4
    CRYPTO = 1 << 5

    @property
    def label(self):
        return self.name.lower().replace('_', ' ')

CATEGORY_MAP = [
    (_FILE_OPS, BehaviorCategory.FILE_IO),
    (_NETWORK_OPS, BehaviorCategory.NETWORK),
    (_PROCESS_OPS, BehaviorCategory.PROCESS),
    (_REGISTRY_OPS, BehaviorCategory.REGISTRY),
    (_MEMORY_OPS, BehaviorCategory.MEMORY_MANIP),
    (_CRYPTO_OPS, BehaviorCategory.CRYPTO),
]

_MALICIOUS_CHAINS = [
    # RAT: network -> file -> process
    ([BehaviorCategory.NETWORK, BehaviorCategory.FILE_IO, BehaviorCategory.PROCESS], 0.9),
    # dropper: file write + process create
    ([BehaviorCategory.FILE_IO, BehaviorCategory.PROCESS], 0.7),
    # ransomware: file scan + crypto + file write
    ([BehaviorCategory.FILE_IO, BehaviorCategory.CRYPTO, BehaviorCategory.FILE_IO], 0.95),
    # process injection: memory alloc + process + memory protect
    ([BehaviorCategory.MEMORY_MANIP, BehaviorCategory.PROCESS], 0.85),
]

MALICIOUS_BEHAVIOR_PATTERNS = _MALICIOUS_CHAINS


class ApiCall:
    __slots__ = ('name', 'category', 'args', 'retval', 'timestamp')

    def __init__(self, name="", args=None, retval=None, timestamp=None):
        self.name = name
        self.args = args or []
        self.retval = retval
        self.timestamp = timestamp
        self.category = _classify_single(name)

    def __repr__(self):
        return f"<ApiCall {self.name}({len(self.args)} args)>"

class TraceResult:
    """Container returned after tracing a binary."""
    def __init__(self):
        self.calls = []
        self.categories_detected = BehaviorCategory.NONE
        self.malicious_score = 0.0
        self.behavior_summary = OrderedDict()
        self.anomalies = []

    def to_dict(self):
        return {
            'total_calls': len(self.calls),
            'categories': [c.label for c in BehaviorCategory if c & self.categories_detected],
            'malicious_score': self.malicious_score,
            'summary': self.behavior_summary,
            'anomalies': self.anomalies,
        }


# old alias
BehaviorSequence = TraceResult


def _classify_single(api_name):
    name_lower = api_name.lower()
    for op_set, cat in CATEGORY_MAP:
        if name_lower.rsplit('.', 1)[-1] in op_set or name_lower in op_set:
            return cat
    return BehaviorCategory.NONE


def _extract_sequence_category(calls):
    """Find the ordered sequence of unique behavior categories."""
    seen = set()
    seq = []
    for c in calls:
        if c.category != BehaviorCategory.NONE and c.category not in seen:
            seen.add(c.category)
            seq.append(c.category)
    return seq


def _sliding_window_match(seq, pattern, window_len):
    """Sliding-window partial-order match for malicious behavior."""
    pat_len = len(pattern)
    for start in range(len(seq) - pat_len + 1):
        window = seq[start:start + pat_len]
        if all(p in window for p in pattern):
            return True
    return False


# ── main tracer ────────────────────────────────────────────────────────────

class BehaviorTracer:
    """Dynamic API-call-sequence behaviour classifier."""

    def __init__(self, sensitivity=0.5):
        self.sensitivity = sensitivity

    def trace(self, binary):
        """Trace API calls from binary or call list."""
        result = TraceResult()

        if isinstance(binary, list):
            calls = binary
        elif isinstance(binary, str):
            # Try parsing as JSON trace log
            try:
                with open(binary, 'r') as fh:
                    raw = json.load(fh)
                calls = [ApiCall(**item) if isinstance(item, dict) else
                         ApiCall(name=str(item)) for item in raw]
            except (json.JSONDecodeError, FileNotFoundError):
                calls = []
        else:
            calls = []

        result.calls = calls

        if not calls:
            return result

        # Aggregate categories
        cat_flags = BehaviorCategory.NONE
        cat_counts = Counter()
        for c in calls:
            cat_flags |= c.category
            if c.category != BehaviorCategory.NONE:
                cat_counts[c.category.label] += 1
        result.categories_detected = cat_flags
        result.behavior_summary = OrderedDict(cat_counts.most_common())

        # Malicious scoring via weighted pattern matching
        seq = _extract_sequence_category(calls)
        max_score = 0.0
        for pattern, weight in _MALICIOUS_CHAINS:
            if _sliding_window_match(seq, pattern, len(pattern)):
                max_score = max(max_score, weight)

        # Bonus: detect anomalies (excessive registry + process in short window)
        proc_hits = cat_counts.get('process', 0)
        reg_hits = cat_counts.get('registry', 0)
        if proc_hits >= 3 and reg_hits >= 5:
            result.anomalies.append(
                'high process+registry activity (persistence indicator)')
            max_score = max(max_score, 0.6)

        net_hits = cat_counts.get('network', 0)
        mem_hits = cat_counts.get('memory_manip', 0)
        if net_hits >= 2 and mem_hits >= 2:
            result.anomalies.append(
                'network + memory manipulation (C2/injection pattern)')
            max_score = max(max_score, 0.8)

        result.malicious_score = round(min(max_score, 1.0), 2)
        return result
