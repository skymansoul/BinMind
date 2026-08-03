#!/usr/bin/env python3

import logging, os, re, subprocess, math as _math
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

class IndirectBranch:
    __slots__ = ('address', 'instruction', 'target_register', 'spectre_risk',)
    def __init__(self, address, instruction, target_register, spectre_risk):
        self.address = address; self.instruction = instruction
        self.target_register = target_register; self.spectre_risk = spectre_risk

class BPUConflict:
    __slots__ = ('branch_a', 'branch_b', 'set_index', 'conflict_type',)
    def __init__(self, branch_a, branch_b, set_index, conflict_type):
        self.branch_a = branch_a; self.branch_b = branch_b
        self.set_index = set_index; self.conflict_type = conflict_type

class DetectionResult:
    __slots__ = ('success', 'indirect_branches', 'conflicts', 'overall_risk',
                 'recommendation', 'spectre_v1_count', 'spectre_v2_count',)
    def __init__(self, success, indirect_branches, conflicts, overall_risk,
                 recommendation, v1=0, v2=0):
        self.success = success; self.indirect_branches = indirect_branches
        self.conflicts = conflicts; self.overall_risk = overall_risk
        self.recommendation = recommendation
        self.spectre_v1_count = v1; self.spectre_v2_count = v2

class BranchScanner:
    s_INDIRECT_PATTERNS = [
        (r'jmp\s+(?:qword\s+)?\[r\w+\]', 'jmp_indirect'),
        (r'call\s+(?:qword\s+)?\[r\w+\]', 'call_indirect'),
        (r'jmp\s+r\w+', 'jmp_register'),
        (r'call\s+r\w+', 'call_register'),
        (r'retn?\b', 'return'),
    ]
    s_RSB_UNDERFLOW_PATTERN = re.compile(r'(push\s+r\w+.*ret)\s*;', re.DOTALL)
    # Spectre v1 特征: 条件分支 + 后续数组访问 + flush/reload 窗口
    _SPECTRE_V1_PAT = re.compile(
        rb'(?:cmp|test)\s+.*\n.{0,50}(?:mov.*\[r\w+\+r\w+|movzx)', re.DOTALL)
    # Spectre v2 特征: 间接分支 + 无 retpoline 防护
    _SPECTRE_V2_PAT = re.compile(rb'jmp\s+\[r\w+\]|call\s+\[r\w+\]', re.I)

    def __init__(self, binary_path: str): self.binary_path = binary_path

    def scanBp(self) -> List[IndirectBranch]:
        branches = []
        try:
            r = subprocess.run(
                ['r2', '-q', '-c', 'aaaa; /R jmp; /R call; q', self.binary_path],
                capture_output=True, text=True, timeout=120,
                encoding='utf-8', errors='replace')
            for line in r.stdout.split('\n'):
                for pat, btype in self.s_INDIRECT_PATTERNS:
                    if re.search(pat, line, re.IGNORECASE):
                        addr_match = re.match(r'\s*0x([0-9a-f]+)', line)
                        if not addr_match: continue
                        addr = int(addr_match.group(1), 16)
                        reg_match = re.search(r'\[?(\w+)\]?', line)
                        reg = reg_match.group(1) if reg_match else 'unknown'
                        risk = 'HIGH' if btype in ('jmp_indirect','call_indirect') else 'MEDIUM'
                        branches.append(IndirectBranch(
                            address=addr, instruction=line.strip()[:80],
                            target_register=reg, spectre_risk=risk))
        except Exception: logger.debug("suppressed", exc_info=True)
        return branches

    def detect_rsb_underflow(self, disasm: str) -> List[int]:
        underflows = []
        for m in self.s_RSB_UNDERFLOW_PATTERN.finditer(disasm):
            addr_match = re.match(r'\s*0x([0-9a-f]+)', m.group())
            if addr_match: underflows.append(int(addr_match.group(1), 16))
        return underflows

    def classify_spectre_variant(self, code_section: bytes) -> Tuple[int, int]:
        """将检测到的 Spectre 模式分类为 v1 (bounds 检查 bypass) 或 v2 (BTB poisoning)
        返回 (v1_count, v2_count)"""
        v1 = len(self._SPECTRE_V1_PAT.findall(code_section))
        v2 = len(self._SPECTRE_V2_PAT.findall(code_section))
        return v1, v2

class BPUAnalyzer:
    s_BPU_SET_BITS = 6; s_BPU_SET_MASK = (1 << s_BPU_SET_BITS) - 1

    def find_conflictsBp(self, branches: List[IndirectBranch]) -> List[BPUConflict]:
        conflicts = []
        set_map: Dict[int, List[int]] = {}
        for br in branches:
            set_idx = (br.address >> 2) & self.s_BPU_SET_MASK
            set_map.setdefault(set_idx, []).append(br.address)
        for set_idx, addrs in set_map.items():
            n = len(addrs)
            if n >= 2:
                for i in range(n):
                    for j in range(i + 1, n):
                        conflicts.append(BPUConflict(
                            branch_a=addrs[i], branch_b=addrs[j],
                            set_index=set_idx, conflict_type="BTB_alias"))
        return conflicts

    def find_aliasing_gadgets(self, branches: List[IndirectBranch],
                               target_addr: int) -> List[IndirectBranch]:
        target_set = (target_addr >> 2) & self.s_BPU_SET_MASK
        return [br for br in branches
                if (br.address >> 2) & self.s_BPU_SET_MASK == target_set
                and br.address != target_addr]

    def assess_riskBp(self, branches: List[IndirectBranch],
                      conflicts: List[BPUConflict],
                      v1_count: int, v2_count: int) -> Tuple[str, str]:
        high_count = sum(1 for b in branches if b.spectre_risk == 'HIGH')
        # Spectre v1 + v2 组合威胁——最高风险级别
        if v1_count > 0 and v2_count > 0:
            return ("CRITICAL", "Spectre v1 + v2 both present. Full mitigation required: "
                    "lfence after bounds check (v1) + Retpoline/IBRS (v2).")
        if len(conflicts) > 20 and high_count > 10:
            return ("HIGH", "High BPU conflict density. Enable Retpoline/IBRS/STIBP.")
        elif high_count > 5:
            return ("MEDIUM", "Indirect branches present. -mretpoline advised.")
        elif len(branches) > 0:
            return ("LOW", "Low indirect branch count. Standard hardening sufficient.")
        return ("NONE", "No indirect branches detected.")

class BPUDetector:
    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.scanner = BranchScanner(binary_path); self.analyzer = BPUAnalyzer()

    def runBp(self) -> DetectionResult:
        branches = self.scanner.scanBp()
        conflicts = self.analyzer.find_conflictsBp(branches)
        # 读取.text 段进行 Spectre 变种分类
        v1, v2 = 0, 0
        try:
            with open(self.binary_path, 'rb') as fh:
                code = fh.read(0x100000)  # 首 1MB 代码段
            v1, v2 = self.scanner.classify_spectre_variant(code)
        except Exception: pass
        risk, rec = self.analyzer.assess_riskBp(branches, conflicts, v1, v2)
        logger.info(
            f"BPU analysis: {len(branches)} branches, {len(conflicts)} conflicts, "
            f"v1={v1} v2={v2}, risk={risk}")
        return DetectionResult(
            success=True, indirect_branches=branches, conflicts=conflicts,
            overall_risk=risk, recommendation=rec, v1=v1, v2=v2)

    def find_spectre_v2_aliases(self, target_addr: int) -> List[IndirectBranch]:
        return self.analyzer.find_aliasing_gadgets(self.scanner.scanBp(), target_addr)

def create_bpu_detector(binary_path: str) -> BPUDetector:
    return BPUDetector(binary_path)
