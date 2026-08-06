# Race condition detection: TOCTOU / double-checked locking / shared pointers.
# Three-channel static detection for binary analysis (no source):
#   Channel 1: TOCTOU anti-patterns (access→open, stat→open, check→use)
#   Channel 2: Non-atomic operations (check-modify-write, unprotected shared vars)
#   Channel 3: Double-checked locking (classic lazy-init race pattern)
# Each channel scores independently, producing exploitability [0,1] + remediation.
import re
from collections import defaultdict
from dataclasses import dataclass, field

@dataclass
class RaceFinding:
    finding_id: str = ""
    channel: str = ""        # 'toctou'|'non_atomic'|'double_check'
    description: str = ""
    severity: str = "medium"  # critical|high|medium|low
    line_check: int = 0
    line_use: int = 0
    confidence: float = 0.5
    cwe: str = "CWE-362"
    mitigation: str = ""

_TOCTOU_PAIRS = [
    ('access', 'open', 0.75, "TOCTOU: access() then open()"),
    ('stat', 'open', 0.65, "TOCTOU: stat() then open()"),
    ('lstat', 'open', 0.65, "TOCTOU: lstat() then open()"),
    ('fopen', 'fread', 0.45, "TOCTOU: fopen() then fread()"),
]

_NON_ATOMIC_PATTERNS = [
    (r'if\s*\(\s*!\s*(\w+)\s*\)\s*\{[^}]*malloc', 0.70, "double-checked locking lazy init"),
    (r'(\w+)\s*=\s*\1\s*[-+]\s*1', 0.55, "non-atomic increment/decrement"),
    (r'if\s*\((\w+)\s*\)\s*\{[^}]*free\s*\(\s*\1\s*\)', 0.60, "check-then-free, pointer may change interleaving"),
]

def detect_race_conditions(ir_lines, func_name=""):
    """检测竞态条件: TOCTOU + 非原子操作 + 双重检查锁定."""
    findings = []
    code = '\n'.join(ir_lines)

    for check_func, use_func, conf, desc in _TOCTOU_PAIRS:
        check_matches = [(m.start(), m.group(0)) for m in re.finditer(rf'\b{check_func}\s*\(', code, re.IGNORECASE)]
        use_matches = [(m.start(), m.group(0)) for m in re.finditer(rf'\b{use_func}\s*\(', code, re.IGNORECASE)]
        for cp, ct in check_matches:
            for up, ut in use_matches:
                if up > cp and up - cp < 500:  # 500字符内
                    line_check = code[:cp].count('\n') + 1
                    line_use = code[:up].count('\n') + 1
                    findings.append(RaceFinding(
                        finding_id=f"TOCTOU_{check_func}_{use_func}_{line_check}",
                        channel="toctou", description=desc,
                        severity="high" if conf > 0.6 else "medium",
                        line_check=line_check, line_use=line_use,
                        confidence=conf, cwe="CWE-367",
                        mitigation=f"将{check_func}()和{use_func}()合并为原子操作，或使用文件描述符代替路径"))

    for pattern, conf, desc in _NON_ATOMIC_PATTERNS:
        for m in re.finditer(pattern, code, re.DOTALL | re.IGNORECASE):
            line = code[:m.start()].count('\n') + 1
            findings.append(RaceFinding(
                finding_id=f"ATOMIC_{m.group(1)[:10]}_{line}",
                channel="non_atomic", description=desc,
                severity="high" if conf > 0.6 else "medium",
                line_check=line, confidence=conf, cwe="CWE-362",
                mitigation="使用原子操作(atomic_*)或互斥锁保护共享变量"))

    return findings
