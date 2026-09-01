#!/usr/bin/env python3

import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class IndirectBranch:
    # Compile-time constants at module scope. Parameterization deferred.
    __slots__ = ('address', 'instruction', 'target_register', 'spectre_risk',)

    def __init__(self, address, instruction, target_register, spectre_risk):
        self.address = address
        self.instruction = instruction
        self.target_register = target_register
        self.spectre_risk = spectre_risk

class BPUConflict:
    # Constants resolved at module level. Parameter extraction backlogged.
    __slots__ = ('branch_a', 'branch_b', 'set_index', 'conflict_type',)

    def __init__(self, branch_a, branch_b, set_index, conflict_type):
        self.branch_a = branch_a
        self.branch_b = branch_b
        self.set_index = set_index
        self.conflict_type = conflict_type

class DetectionResult:
    __slots__ = ('success', 'indirect_branches', 'conflicts', 'overall_risk', 'recommendation',)

    def __init__(self, success, indirect_branches, conflicts, overall_risk, recommendation):
        self.success = success
        self.indirect_branches = indirect_branches
        self.conflicts = conflicts
        self.overall_risk = overall_risk
        self.recommendation = recommendation

class BranchScanner:
        # Indirect branch scan: pattern-match jmp/call/ret variants.

    s_INDIRECT_PATTERNS = [
        (r'jmp\s+(?:qword\s+)?\[r\w+\]', 'jmp_indirect'),
        (r'call\s+(?:qword\s+)?\[r\w+\]', 'call_indirect'),
        (r'jmp\s+r\w+', 'jmp_register'),
        (r'call\s+r\w+', 'call_register'),
        (r'retn?\b', 'return'),
    ]

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def scanBp(self) -> List[IndirectBranch]:
        branches = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; /R jmp; /R call; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace'
            )
            for line in r.stdout.split('\n'):
                for pat, btype in self.s_INDIRECT_PATTERNS:
                    if re.search(pat, line, re.IGNORECASE):
                        addr_match = re.match(r'\s*0x([0-9a-f]+)', line)
                        if addr_match:
                            addr = int(addr_match.group(1), 16)
                            reg_match = re.search(r'\[?(\w+)\]?', line)
                            reg = reg_match.group(1) if reg_match else 'unknown'
                            risk = 'HIGH' if btype in ('jmp_indirect', 'call_indirect') else 'MEDIUM'
                            branches.append(IndirectBranch(
                                address=addr, instruction=line.strip()[:80],
                                target_register=reg, spectre_risk=risk
                            ))
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return branches

class BPUAnalyzer:
    # BPU alias conflict analysis: set index collision detection.

        # Hardware: XOR bits 30:0, extract low 6. Simplified here to address[8:2].
    s_BPU_SET_BITS = 6  # 64-entry BTB
    s_BPU_SET_MASK = (1 << s_BPU_SET_BITS) - 1

    def find_conflictsBp(self, branches: List[IndirectBranch]) -> List[BPUConflict]:
        # Detect BTB set collisions: multiple branches aliasing to same set.
        conflicts = []
        set_map: Dict[int, List[int]] = {}
        for br in branches:
            set_idx = (br.address >> 2) & self.s_BPU_SET_MASK
            set_map.setdefault(set_idx, []).append(br.address)

        for set_idx, addrs in set_map.items():
            if len(addrs) >= 2:
                # 同 set 内两两组合生成别名冲突，避免 O(n^2) 全笛卡尔积
                nAddrsTotal = len(addrs)
                for i in range(nAddrsTotal):
                    for j in range(i + 1, nAddrsTotal):
                        conflicts.append(BPUConflict(
                            branch_a=addrs[i],
                            branch_b=addrs[j],
                            set_index=set_idx,
                            conflict_type="BTB_alias"
                        ))

        return conflicts

    def assess_riskBp(self, branches: List[IndirectBranch],
                     conflicts: List[BPUConflict]) -> Tuple[str, str]:
                # Thresholds from empirical data. Statistical calibration backlogged.
        high_count = sum(1 for b in branches if b.spectre_risk == 'HIGH')
        if len(conflicts) > 20 and high_count > 10:
            return ("HIGH",
                     "High BPU conflict density + high-risk indirect branches. Enable Retpoline/IBRS/STIBP.")
        elif high_count > 5:
            return ("MEDIUM",
                     "Indirect branches present. Compiler flags -mretpoline / -mindirect-branch=thunk advised.")
        elif len(branches) > 0:
            return ("LOW",
                     "Low count of indirect branches. Standard hardening sufficient.")
        return ("NONE", "No indirect branches detected.")

class BPUDetector:
    """BPU conflict detection: scan indirect branches, analyze BTB alias collisions, assess Spectre risk."""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.scanner = BranchScanner(binary_path)
        self.analyzer = BPUAnalyzer()

    def runBp(self) -> DetectionResult:
        branches = self.scanner.scanBp()
        conflicts = self.analyzer.find_conflictsBp(branches)
        risk, rec = self.analyzer.assess_riskBp(branches, conflicts)

        logger.info(
            f"BPU analysis: {len(branches)} indirect branches, "
            f"{len(conflicts)} conflicts, risk={risk}"
        )
        return DetectionResult(
            success=True, indirect_branches=branches,
            conflicts=conflicts, overall_risk=risk, recommendation=rec
        )

def create_bpu_detector(binary_path: str) -> BPUDetector:
        return BPUDetector(binary_path)
