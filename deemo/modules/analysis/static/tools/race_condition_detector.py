# 2026-07-30
import re
from typing import List, Dict, Tuple, Set, Optional
from collections import defaultdict


class RaceConditionDetector:
    """TOCTOU, lock ordering, signal handler race, kernel double-fetch detection"""

    # ---- 初始化: TOCTOU API对 + 锁API + 信号API ----

    def __init__(self):
        # TOCTOU check-use API pairs
        self._toctou_pairs = [
            # (check, use) - check存在性/权限，use直接操作（无原子性保证）
            # POSIX
            ('access', 'open'),
            ('_access', '_open'),
            ('access', 'fopen'),
            ('stat', 'open'),
            ('lstat', 'open'),
            ('stat', 'fopen'),
            ('stat', 'unlink'),
            ('stat', 'rename'),
            ('stat', 'chmod'),
            ('fstat', 'fchmod'),
            ('lstat', 'symlink'),
            ('readlink', 'symlink'),
            # Windows
            ('GetFileAttributesA', 'CreateFileA'),
            ('GetFileAttributesW', 'CreateFileW'),
            ('FindFirstFileA', 'DeleteFileA'),
            ('FindFirstFileW', 'DeleteFileW'),
            ('PathFileExistsA', 'CreateFileA'),
            ('GetFileSecurity', 'SetFileSecurity'),
            # 文件存在检查后操作
            ('PathFileExists', 'CreateFile'),
            ('FileExists', 'ReadFile'),
            # 权限检查后提权操作
            ('IsUserAnAdmin', 'RegCreateKey'),
            ('CheckTokenMembership', 'CreateProcessAsUser'),
            ('GetTokenInformation', 'DuplicateToken'),
        ]

        # Lock API patterns
        self._lock_apis = {
            'acquire': [
                'pthread_mutex_lock', 'pthread_rwlock_wrlock',
                'pthread_rwlock_rdlock', 'EnterCriticalSection',
                'AcquireSRWLockExclusive', 'AcquireSRWLockShared',
                'WaitForSingleObject', 'WaitForMultipleObjects',
                'KeWaitForSingleObject', 'KeWaitForMutexObject',
                'spin_lock', 'mutex_lock', 'read_lock', 'write_lock',
                'down', 'down_interruptible', 'mutex_lock_interruptible',
            ],
            'release': [
                'pthread_mutex_unlock', 'pthread_rwlock_unlock',
                'LeaveCriticalSection', 'ReleaseSRWLockExclusive',
                'ReleaseSRWLockShared', 'ReleaseMutex',
                'KeReleaseMutex', 'spin_unlock', 'mutex_unlock',
                'read_unlock', 'write_unlock', 'up',
            ],
        }

        # 信号处理相关API
        self._signal_apis = [
            'signal', 'sigaction', 'sigprocmask', 'pthread_sigmask',
            'sigwait', 'sigwaitinfo', 'sigtimedwait',
            'SetConsoleCtrlHandler', 'SetUnhandledExceptionFilter',
        ]

        # 可能导致信号处理race的函数（非async-signal-safe）
        self._unsafe_in_signal = [
            'printf', 'fprintf', 'malloc', 'free', 'pthread_mutex_lock',
            'pthread_mutex_unlock', 'lock', 'unlock', 'open', 'close',
            'read', 'write', 'strcpy', 'strcat', 'memcpy',
            'EnterCriticalSection', 'LeaveCriticalSection',
        ]

    # ---- TOCTOU检测: check->use API对分析 ----

    def detect_toctou(self, imports: Dict[str, List[str]]) -> List[Dict]:
        _findings = []
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            _ml = _mod.lower()
            for _f in _funcs:
                _flat_name = _f.lower()
                _imp_flat.add(_flat_name)

        for _check, _use in self._toctou_pairs:
            _chk_lower = _check.lower()
            _use_lower = _use.lower()
            _chk_found = any(_chk_lower in _imp for _imp in _imp_flat)
            _use_found = any(_use_lower in _imp for _imp in _imp_flat)

            if _chk_found and _use_found:
                _conf = 0.65
                # Windows TOCTOU pattern is more exploitable
                if 'fileattribute' in _chk_lower or 'pathfile' in _chk_lower:
                    _conf = 0.75

                _findings.append({
                    'type': 'toctou',
                    'check_api': _check,
                    'use_api': _use,
                    'confidence': _conf,
                    'severity': 'MEDIUM',
                    'description': f'TOCTOU race: {_check} (check) -> {_use} (use)',
                })

        return _findings

    # //// 锁顺序检测 (死锁/双重锁) ////

    def detect_lock_issues(self, strings: List[str],
                            imports: Dict[str, List[str]]) -> List[Dict]:
        _findings = []
        _strs_text = ' '.join(strings)
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        _acquire_found = []
        _release_found = []
        for _api in self._lock_apis['acquire']:
            if any(_api.lower() in _imp for _imp in _imp_flat):
                _acquire_found.append(_api)
        for _api in self._lock_apis['release']:
            if any(_api.lower() in _imp for _imp in _imp_flat):
                _release_found.append(_api)

        # 双重锁检测: 两个acquire之间无release
        if len(_acquire_found) >= 2:
            _acquire_funcs = [a.strip() for a in _acquire_found]
            if len(_acquire_funcs) >= 2 and len(_release_found) < len(_acquire_funcs):
                _findings.append({
                    'type': 'potential_deadlock',
                    'severity': 'HIGH',
                    'confidence': 0.5,
                    'acquire_apis': _acquire_funcs[:5],
                    'release_apis': _release_found[:5],
                    'description': 'Multiple lock acquire APIs without sufficient release - potential deadlock',
                })

        # 双重锁（同一锁被同一线程重复acquire）
        for _acq in _acquire_found:
            _pattern = f"{_acq}.*{_acq}"
            if re.search(_pattern, _strs_text):
                _findings.append({
                    'type': 'double_lock',
                    'lock_api': _acq,
                    'severity': 'HIGH',
                    'confidence': 0.55,
                    'description': f'Possible double lock on {_acq}',
                })

        return _findings

    # ===== 信号处理Race检测 =====

    def detect_signal_races(self, strings: List[str],
                             imports: Dict[str, List[str]]) -> List[Dict]:
        _findings = []
        _strs_text = ' '.join(strings)
        _imp_flat = set()
        for _mod, _funcs in imports.items():
            for _f in _funcs:
                _imp_flat.add(_f.lower())

        # 有信号处理器注册？
        _has_signal_handler = False
        for _api in self._signal_apis:
            if _api.lower() in _strs_text.lower():
                _has_signal_handler = True
                break

        if not _has_signal_handler:
            for _api in self._signal_apis:
                if any(_api.lower() in _imp for _imp in _imp_flat):
                    _has_signal_handler = True
                    break

        if _has_signal_handler:
            # 检查信号处理器中使用了非async-signal-safe函数
            _unsafe_found = []
            for _api in self._unsafe_in_signal:
                if _api.lower() in _strs_text.lower():
                    _unsafe_found.append(_api)
                elif any(_api.lower() in _imp for _imp in _imp_flat):
                    _unsafe_found.append(_api)

            if _unsafe_found:
                _findings.append({
                    'type': 'signal_handler_race',
                    'severity': 'MEDIUM',
                    'confidence': min(len(_unsafe_found) / 5.0, 0.8),
                    'unsafe_apis_in_handler': _unsafe_found[:8],
                    'description': 'Signal handler may call non-async-signal-safe functions',
                })

        # 信号与锁的竞争
        _sig_and_lock = False
        for _sig in self._signal_apis:
            for _lock in self._lock_apis['acquire'] + self._lock_apis['release']:
                if _sig.lower() in _strs_text.lower() and _lock.lower() in _strs_text.lower():
                    _sig_and_lock = True
                    break

        if _sig_and_lock:
            _findings.append({
                'type': 'signal_lock_race',
                'severity': 'HIGH',
                'confidence': 0.6,
                'description': 'Signal handler + lock usage detected - potential deadlock in signal context',
            })

        return _findings

    # ---- 内核Double-Fetch模式检测 ----

    def detect_double_fetch(self, strings: List[str],
                             imports: Dict[str, List[str]]) -> List[Dict]:
        """
        Kernel double-fetch pattern: 同一用户态地址以copy_from_user读取两次，
        第一次校验，第二次使用，但两次读取之间值可能被另一个线程修改
        """
        _findings = []
        _strs_text = ' '.join(strings)

        # copy_from_user/get_user pattern
        _copy_patterns = [
            (r'copy_from_user.*copy_from_user', 'Double copy_from_user to same buffer'),
            (r'get_user.*get_user', 'Double get_user to same variable'),
            (r'copy_from_user.*ProbeForRead', 'copy_from_user + ProbeForRead (TOCTOU in kernel)'),
            (r'ProbeForWrite.*copy_to_user', 'ProbeForWrite + copy_to_user'),
            (r'MmUserProbeAddress', 'Legacy MmUserProbeAddress usage'),
        ]

        for _pat, _desc in _copy_patterns:
            if re.search(_pat, _strs_text, re.I | re.DOTALL):
                _findings.append({
                    'type': 'kernel_double_fetch',
                    'severity': 'HIGH',
                    'confidence': 0.6,
                    'pattern': _desc,
                    'description': f'Potential kernel double-fetch: {_desc}',
                })

        # __user annotation + access_ok
        if re.search(r'access_ok.*copy_from_user', _strs_text, re.I | re.DOTALL):
            if re.search(r'copy_from_user.*access_ok', _strs_text, re.I | re.DOTALL):
                _findings.append({
                    'type': 'kernel_double_fetch',
                    'severity': 'MEDIUM',
                    'confidence': 0.5,
                    'pattern': 'access_ok + copy_from_user sequence',
                    'description': 'access_ok validation pattern - check for double-fetch between validations',
                })

        return _findings

    # //// 综合分析入口 ////

    def analyze(self, strings: List[str] = None,
                imports: Dict[str, List[str]] = None) -> Dict:
        if strings is None:
            strings = []
        if imports is None:
            imports = {}

        _toctou = self.detect_toctou(imports)
        _lock = self.detect_lock_issues(strings, imports)
        _sig = self.detect_signal_races(strings, imports)
        _df = self.detect_double_fetch(strings, imports)

        _all = _toctou + _lock + _sig + _df

        _severity = 'LOW'
        if any(f.get('severity') == 'HIGH' for f in _all):
            _severity = 'HIGH'
        elif any(f.get('severity') == 'MEDIUM' for f in _all):
            _severity = 'MEDIUM'

        return {
            'findings': _all,
            'total_findings': len(_all),
            'overall_severity': _severity,
            'categories': {
                'toctou': len(_toctou),
                'lock_issues': len(_lock),
                'signal_races': len(_sig),
                'double_fetch': len(_df),
            },
        }
