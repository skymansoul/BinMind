import logging
import os
import re
import json
import subprocess
import hashlib
from dataclasses import dataclass, field
from typing import Dict
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DeadCodeRegion:
    start_address: int
    end_address: int
    size: int
    is_reachable: bool = False
    activation_condition: Optional[str] = None
    func_name: str = ""
    danger_score: float = 0.0
    dangerous_calls: List[str] = field(default_factory=list)


@dataclass
class AnalysisResult:
    success: bool
    dead_regions: List[DeadCodeRegion]
    reachable_count: int = 0
    total_functions: int = 0
    dead_function_count: int = 0
    high_risk_count: int = 0


class DeadCodeAnalyzer:
    """Dead code reachability analyzer -- discover hidden attack surface."""

    DANGEROUS_APIS = {
        "system", "execve", "popen", "strcpy", "sprintf", "gets",
        "memcpy", "mprotect", "mmap", "ptrace", "fork", "dlopen",
        "WriteProcessMemory", "CreateRemoteThread", "WinExec",
    }

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.dead_regions: List[DeadCodeRegion] = []
        self._all_funcs: Dict[str, Dict] = {}
        self._xrefs: Dict[str, Set[str]] = {}
        self._called_funcs: Set[str] = set()

    def _collect_functions(self) -> Dict[str, Dict]:
        funcs = {}
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aflj;q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            data = json.loads(r.stdout) if r.stdout.strip() else []
            for f in data:
                name = f.get('name', '')
                if name:
                    funcs[name] = {
                        'offset': f.get('offset', 0),
                        'size': f.get('size', 0),
                        'ninstr': f.get('ninstr', 0),
                    }
        except Exception as e:
            logger.warning("Function collection failed: %s", e)
        self._all_funcs = funcs
        return funcs

    def _collect_xrefs(self) -> Dict[str, Set[str]]:
        xrefs: Dict[str, Set[str]] = {}
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'axtj;q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            if r.stdout.strip():
                data = json.loads(r.stdout)
                for entry in data:
                    ref = entry.get('name', '')
                    addr_from = entry.get('from', 0)
                    if ref:
                        if ref not in xrefs:
                            xrefs[ref] = set()
                        xrefs[ref].add(str(addr_from))
        except Exception:
            logger.debug("suppressed", exc_info=True)

        if not xrefs:
            xrefs = self._xrefs_fallback()
        self._xrefs = xrefs
        return xrefs

    def _xrefs_fallback(self) -> Dict[str, Set[str]]:
        xrefs: Dict[str, Set[str]] = {}
        for fname in self._all_funcs:
            try:
                r = subprocess.run(
                    ['r2', '-q', '-c', f'axt @ {fname};q', self.binary_path],
                    capture_output=True, text=True, timeout=10,
                    encoding='utf-8', errors='replace'
                )
                callers = set()
                for line in r.stdout.split('\n'):
                    m = re.match(r'.*\s+(0x[0-9a-f]+)\s', line)
                    if m:
                        callers.add(m.group(1))
                if callers:
                    xrefs[fname] = callers
                if fname not in xrefs:
                    xrefs[fname] = set()
            except Exception:
                xrefs[fname] = set()
        return xrefs

    def _analyze_function_danger(self, func_name: str, offset: int,
                                  size: int) -> Tuple[float, List[str]]:
        dangerous_found = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', f'pD {size} @ {offset};q', self.binary_path],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace'
            )
            disasm = r.stdout.lower()
            for api in self.DANGEROUS_APIS:
                if api.lower() in disasm:
                    dangerous_found.append(api)
        except Exception:
            logger.debug("suppressed", exc_info=True)

        score = min(1.0, len(dangerous_found) * 0.25)
        if any(a in dangerous_found for a in ["system", "execve", "mprotect"]):
            score = max(score, 0.8)
        return score, dangerous_found

    def _build_called_set(self):
        self._called_funcs = set()
        entry_funcs = {"main", "_start", "entry", "start", "WinMain",
                        "mainCRTStartup", "DllMain", "DriverEntry"}
        for fname in self._all_funcs:
            if fname in entry_funcs or "main" in fname.lower():
                self._called_funcs.add(fname)
            if fname in self._xrefs and len(self._xrefs[fname]) > 0:
                self._called_funcs.add(fname)

    def analyze(self) -> List[DeadCodeRegion]:
        logger.info("Collecting function info...")
        self._collect_functions()
        logger.info("Found %d functions", len(self._all_funcs))

        logger.info("Collecting cross references...")
        self._collect_xrefs()
        self._build_called_set()

        self.dead_regions = []
        for fname, info in self._all_funcs.items():
            offset = info.get('offset', 0)
            size = info.get('size', 0)
            if size == 0:
                continue
            is_dead = fname not in self._called_funcs
            end_addr = offset + size

            danger, dangerous_calls = (0.0, [])
            activation = None
            if is_dead:
                danger, dangerous_calls = self._analyze_function_danger(
                    fname, offset, size
                )
                if danger > 0:
                    activation = (
                        "Can redirect control flow to %s by hijacking "
                        "function pointers in the call chain (e.g. GOT overwrite)"
                    ) % fname

            region = DeadCodeRegion(
                start_address=offset,
                end_address=end_addr,
                size=size,
                is_reachable=not is_dead,
                activation_condition=activation,
                func_name=fname,
                danger_score=danger,
                dangerous_calls=dangerous_calls,
            )
            self.dead_regions.append(region)

        dead_count = sum(1 for r in self.dead_regions if not r.is_reachable)
        logger.info(
            "Analysis complete: %d functions, %d dead code regions",
            len(self.dead_regions), dead_count
        )
        return self.dead_regions

    def find_hidden_attack_surface(self) -> List[DeadCodeRegion]:
        dead = [r for r in self.dead_regions if not r.is_reachable]
        hidden = sorted(dead, key=lambda r: r.danger_score, reverse=True)
        for r in hidden:
            if r.danger_score > 0.3:
                logger.warning(
                    "Hidden attack surface: %s @ 0x%x "
                    "danger score=%.2f, "
                    "dangerous calls=%s",
                    r.func_name, r.start_address,
                    r.danger_score, r.dangerous_calls
                )
        return hidden

    def run(self) -> AnalysisResult:
        self.analyze()
        reachable = sum(1 for r in self.dead_regions if r.is_reachable)
        dead = sum(1 for r in self.dead_regions if not r.is_reachable)
        high_risk = sum(
            1 for r in self.dead_regions
            if not r.is_reachable and r.danger_score > 0.3
        )
        return AnalysisResult(
            success=True,
            dead_regions=self.dead_regions,
            reachable_count=reachable,
            total_functions=len(self._all_funcs),
            dead_function_count=dead,
            high_risk_count=high_risk,
        )


def create_dead_code_analyzer(binary_path: str) -> DeadCodeAnalyzer:
    return DeadCodeAnalyzer(binary_path)
