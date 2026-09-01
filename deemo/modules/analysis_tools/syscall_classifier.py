import os
import logging
import pickle
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ThreatCategory(Enum):
    RANSOMWARE = "ransomware"
    TROJAN = "trojan"
    BACKDOOR = "backdoor"
    MINER = "miner"
    SPYWARE = "spyware"
    ADWARE = "adware"
    DOWNLOADER = "downloader"
    DROPPER = "dropper"
    WORM = "worm"
    BENIGN = "benign"
    UNKNOWN = "unknown"

class SyscallSequence:
    __slots__ = ('pid', 'calls', 'timestamps',)

    def __init__(self, pid, calls, timestamps=None):
        self.pid = pid
        self.calls = calls
        self.timestamps = timestamps

    def __post_init__(self):
        if self.timestamps is None:
            self.timestamps = []

@dataclass
class ClassificationResult:
    category: ThreatCategory
    confidence: float
    score: float
    features: Dict[str, float]
    explanation: str

@dataclass
class SyscallPattern:
    name: str
    pattern: List[str]
    category: ThreatCategory
    weight: float = 1.0

class SyscallClassifier:
    MALICIOUS_PATTERNS = [
        SyscallPattern('ransomware_file_ops',
            ['CreateFile', 'WriteFile', 'EncryptFile', 'DeleteFile', 'MoveFile'],
            ThreatCategory.RANSOMWARE, 1.5),
        SyscallPattern('ransomware_network',
            ['Connect', 'Send', 'Recv', 'HttpSendRequest'],
            ThreatCategory.RANSOMWARE, 1.0),
        SyscallPattern('miner_cpu',
            ['CreateThread', 'CreateRemoteThread', 'Sleep', 'QueryPerformanceCounter'],
            ThreatCategory.MINER, 1.2),
        SyscallPattern('miner_network',
            ['Connect', 'Recv', 'Send', 'getaddrinfo'],
            ThreatCategory.MINER, 1.0),
        SyscallPattern('backdoor_listen',
            ['socket', 'bind', 'listen', 'accept'],
            ThreatCategory.BACKDOOR, 1.5),
        SyscallPattern('backdoor_exec',
            ['CreateProcess', 'WinExec', 'ShellExecute'],
            ThreatCategory.BACKDOOR, 1.3),
        SyscallPattern('spyware_keyboard',
            ['GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx'],
            ThreatCategory.SPYWARE, 1.5),
        SyscallPattern('spyware_screenshot',
            ['BitBlt', 'GetDC', 'CreateDC', 'PrintWindow'],
            ThreatCategory.SPYWARE, 1.2),
        SyscallPattern('downloader_http',
            ['HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'WriteFile'],
            ThreatCategory.DOWNLOADER, 1.5),
        SyscallPattern('downloader_file',
            ['CreateFile', 'WriteFile', 'CreateProcess'],
            ThreatCategory.DOWNLOADER, 1.0),
        SyscallPattern('trojan_inject',
            ['OpenProcess', 'VirtualAllocEx', 'WriteProcessMemory', 'CreateRemoteThread'],
            ThreatCategory.TROJAN, 1.5),
        SyscallPattern('trojan_persistence',
            ['RegSetValue', 'CreateService', 'ScheduleJob'],
            ThreatCategory.TROJAN, 1.3),
        SyscallPattern('worm_spread',
            ['NetShareEnum', 'NetUseAdd', 'CopyFile', 'CreateProcess'],
            ThreatCategory.WORM, 1.5),
        SyscallPattern('benign_gui',
            ['CreateWindow', 'ShowWindow', 'UpdateWindow', 'DispatchMessage'],
            ThreatCategory.BENIGN, 1.0),
        SyscallPattern('benign_file',
            ['ReadFile', 'WriteFile', 'CloseHandle'],
            ThreatCategory.BENIGN, 0.8),
    ]

    DANGEROUS_SYSCALLS = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'OpenProcess', 'CreateProcess', 'WinExec', 'ShellExecute',
        'HttpSendRequest', 'InternetReadFile', 'URLDownloadToFile',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'BitBlt',
        'RegSetValue', 'CreateService', 'ScheduleJob',
        'EncryptFile', 'DeleteFile', 'MoveFile',
        'socket', 'bind', 'listen', 'accept', 'connect',
    ]

    def __init__(self, model_path: str = None):
        self.model_path = model_path
        self.patterns = self.MALICIOUS_PATTERNS
        self.scores: Dict[ThreatCategory, float] = {}
        self._init_scores()

    def _init_scores(self):
        for category in ThreatCategory:
            self.scores[category] = 0.0

    def _calculate_pattern_match(self, syscalls: List[str], pattern: SyscallPattern) -> float:
        matched = sum(1 for c in pattern.pattern if c.lower() in [s.lower() for s in syscalls])
        return (matched / len(pattern.pattern)) * pattern.weight if matched else 0.0

    def _extract_features(self, syscalls: List[str]) -> Dict[str, float]:
        n = len(syscalls) if syscalls else 1
        dc = sum(1 for c in syscalls if c.lower() in [d.lower() for d in self.DANGEROUS_SYSCALLS])
        nc = sum(1 for c in syscalls if any(net in c.lower() for net in ['socket', 'bind', 'listen', 'accept', 'connect', 'send', 'recv', 'HttpOpenRequest', 'HttpSendRequest', 'InternetReadFile', 'getaddrinfo']))
        fc = sum(1 for c in syscalls if any(f in c.lower() for f in ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile', 'MoveFile', 'CopyFile']))
        pc = sum(1 for c in syscalls if any(p in c.lower() for p in ['CreateProcess', 'OpenProcess', 'CreateRemoteThread', 'TerminateProcess']))
        rc = sum(1 for c in syscalls if any(r in c.lower() for r in ['RegOpenKey', 'RegSetValue', 'RegCreateKey', 'RegDeleteKey']))
        return {'dangerous_call_ratio': dc / n, 'network_call_ratio': nc / n,
                'file_call_ratio': fc / n, 'process_call_ratio': pc / n, 'reg_call_ratio': rc / n}

    def _classify_by_patterns(self, syscalls: List[str]) -> Tuple[ThreatCategory, float]:
        self._init_scores()
        for p in self.patterns:
            s = self._calculate_pattern_match(syscalls, p)
            if s > 0:
                self.scores[p.category] += s
        mx = max(self.scores.values())
        if mx == 0:
            return ThreatCategory.UNKNOWN, 0.0
        total = sum(self.scores.values())
        return max(self.scores, key=self.scores.get), mx / total if total > 0 else 0.0

    def _generate_explanation(self, category: ThreatCategory, features: Dict[str, float]) -> str:
        parts = []
        if features['dangerous_call_ratio'] > 0.3:
            parts.append(f"High-risk syscall ratio ({features['dangerous_call_ratio']:.2f})")
        if features['network_call_ratio'] > 0.2:
            parts.append(f"Elevated network activity ({features['network_call_ratio']:.2f})")
        if features['process_call_ratio'] > 0.1:
            parts.append(f"Excessive process manipulation ({features['process_call_ratio']:.2f})")
        if features['reg_call_ratio'] > 0.1:
            parts.append(f"Unusual registry access volume ({features['reg_call_ratio']:.2f})")
        if not parts:
            parts.append("Pattern-based signature match — no feature threshold exceeded.")
        return f"Result: {category.value}. Basis: {'; '.join(parts)}"

    def classify(self, syscalls: List[str]) -> ClassificationResult:
        if not syscalls:
            return ClassificationResult(ThreatCategory.UNKNOWN, 0.0, 0.0, {}, "Empty syscall list received — nothing to classify.")
        features = self._extract_features(syscalls)
        cat, conf = self._classify_by_patterns(syscalls)
        return ClassificationResult(cat, conf, self.scores[cat], features, self._generate_explanation(cat, features))

    def classify_sequence(self, sequence: SyscallSequence) -> ClassificationResult:
        return self.classify(sequence.calls)

    def batch_classify(self, sequences: List[SyscallSequence]) -> List[ClassificationResult]:
        return [self.classify(s.calls) for s in sequences]

    def get_malicious_probability(self, syscalls: List[str]) -> float:
        result = self.classify(syscalls)
        malicious = [ThreatCategory.RANSOMWARE, ThreatCategory.TROJAN, ThreatCategory.BACKDOOR,
                     ThreatCategory.MINER, ThreatCategory.SPYWARE, ThreatCategory.DOWNLOADER,
                     ThreatCategory.DROPPER, ThreatCategory.WORM]
        return result.confidence if result.category in malicious else 0.0

    def train(self, training_data: List[Tuple[List[str], ThreatCategory]]):
        logger.info(f"Training data loaded: {len(training_data)} samples.")

    def save_model(self, path: str):
        try:
            with open(path, 'wb') as f:
                pickle.dump({'patterns': self.patterns, 'dangerous_syscalls': self.DANGEROUS_SYSCALLS}, f)
            logger.info(f"Model persisted: {path}")
        except Exception as e:
            logger.error(f"Persistence failed: {e}")

    def load_model(self, path: str):
        try:
            with open(path, 'rb') as f:
                self.patterns = pickle.load(f).get('patterns', self.patterns)
            logger.info(f"Model restored: {path}")
        except Exception as e:
            logger.error(f"Restoration failed: {e}")

    def get_analysis_summary(self, syscalls: List[str]) -> Dict[str, Any]:
        r = self.classify(syscalls)
        return {'category': r.category.value, 'confidence': r.confidence, 'score': r.score,
                'malicious_probability': self.get_malicious_probability(syscalls),
                'features': r.features, 'explanation': r.explanation}
