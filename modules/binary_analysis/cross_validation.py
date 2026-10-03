#!/usr/bin/env python3
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import List, Set

logger = logging.getLogger(__name__)


@dataclass
class ValidationFinding:
    type: str
    description: str
    static_confidence: float = 0.0
    dynamic_confidence: float = 0.0
    agreement_score: float = 0.0


@dataclass
class CrossValidationResult:
    success: bool
    findings: List[ValidationFinding]
    static_findings: int = 0
    dynamic_findings: int = 0
    confirmed: int = 0
    agreement_rate: float = 0.0


class SyscallPredictor:

    _SYSCALL_PATTERNS = [
        (r'\bexecve\b|\bexecl\b|\bsystem\b', 'exec'),
        (r'\bopen\b|\bfopen\b|\bopenat\b', 'open'),
        (r'\bread\b|\bfread\b|\bpread\b', 'read'),
        (r'\bwrite\b|\bfwrite\b|\bpwrite\b', 'write'),
        (r'\bconnect\b|\bsocket\b|\bbind\b', 'network'),
        (r'\bmmap\b|\bmprotect\b|\bmunmap\b', 'memory_map'),
        (r'\bfork\b|\bclone\b|\bvfork\b', 'process_create'),
    ]

    def __init__(self, binary_path: str):
        self._binary_path = binary_path

    def predict(self) -> Set[str]:
        predicted = set()
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; pD $SS @ $S; q', self._binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            disasm = r.stdout.lower()
            for pattern, category in self._SYSCALL_PATTERNS:
                if re.search(pattern, disasm, re.IGNORECASE):
                    predicted.add(category)
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return predicted


class DynamicObserver:

    def __init__(self, binary_path: str):
        self._binary_path = binary_path

    def observe(self, timeout: int = 10) -> Set[str]:
        observed = set()
        try:
            r = subprocess.run(
                ['strace', '-f', '-e', 'trace=all', self._binary_path],
                capture_output=True, text=True, timeout=timeout,
                encoding='utf-8', errors='replace'
            )
            output = r.stderr.lower()
            if 'exec' in output:
                observed.add('exec')
            if 'open' in output:
                observed.add('open')
            if 'read' in output:
                observed.add('read')
            if 'write' in output:
                observed.add('write')
            if 'connect' in output or 'socket' in output:
                observed.add('network')
            if 'mmap' in output:
                observed.add('memory_map')
            if 'fork' in output or 'clone' in output:
                observed.add('process_create')
        except FileNotFoundError:
            pass
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return observed


class CrossValidator:

    def __init__(self, binary_path: str):
        self._binary_path = os.path.abspath(binary_path)
        self._predictor = SyscallPredictor(binary_path)
        self._observer = DynamicObserver(binary_path)

    def run(self) -> CrossValidationResult:
        predicted = self._predictor.predict()
        observed = self._observer.observe()

        findings = []
        confirmed = predicted & observed
        static_only = predicted - observed
        dynamic_only = observed - predicted

        for cat in confirmed:
            findings.append(ValidationFinding(
                type='confirmed', description=f'{cat}: static prediction = dynamic observation',
                static_confidence=0.8, dynamic_confidence=1.0, agreement_score=1.0
            ))
        for cat in static_only:
            findings.append(ValidationFinding(
                type='false_positive',
                description=f'{cat}: static-only, not observed dynamically',
                static_confidence=0.5, dynamic_confidence=0.0, agreement_score=0.0
            ))
        for cat in dynamic_only:
            findings.append(ValidationFinding(
                type='new',
                description=f'{cat}: dynamic-only, not predicted statically',
                static_confidence=0.0, dynamic_confidence=1.0, agreement_score=0.0
            ))

        agreement = len(confirmed) / max(1, len(predicted | observed))
        return CrossValidationResult(
            success=True, findings=findings,
            static_findings=len(predicted), dynamic_findings=len(observed),
            confirmed=len(confirmed), agreement_rate=round(agreement, 2)
        )


def create_cross_validator(binary_path: str) -> CrossValidator:
    return CrossValidator(binary_path)
