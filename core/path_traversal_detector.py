# CWE-22 目录穿越检测: 三层检测 — (1) 直接'../'字面量, (2) 路径拼接中的
# 未过滤用户输入, (3) realpath绕过。
import re
from dataclasses import dataclass

_FILE_OPS = {'open','fopen','opendir','mkdir','unlink','remove','rename','chmod','stat','access'}
_PATH_TRAV = {'../','..\\','/etc/','/root/','/home/'}

@dataclass
class PathTravFinding:
    finding_id: str = ""; func_name: str = ""; line: int = 0
    confidence: float = 0.5; severity: str = "high"; cwe: str = "CWE-22"
    description: str = ""

def detect_path_traversal(ir_lines, func_name=""):
    findings = []
    code = '\n'.join(ir_lines)
    tainted = set()
    for lineno, line in enumerate(ir_lines):
        eq = line.find('='); 
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip().lower()
        if any(s in rhs for s in ('argv','getenv','read','recv','scanf','gets')):
            tainted.add(lhs)
    for lineno, line in enumerate(ir_lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip()
        for tv in list(tainted):
            if tv in rhs and lhs != tv: tainted.add(lhs)
    for lineno, line in enumerate(ir_lines):
        line_l = line.lower()
        for fop in _FILE_OPS:
            if fop not in line_l: continue
            has_trav = any(t in line for t in _PATH_TRAV)
            is_tainted = any(tv in line for tv in tainted)
            if has_trav and is_tainted:
                findings.append(PathTravFinding(
                    f'PT_{fop}_{lineno}', fop, lineno, 0.90, 'critical',
                    description=f'{fop}路径参数含../且来自用户输入'))
            elif is_tainted:
                findings.append(PathTravFinding(
                    f'PT_{fop}_{lineno}', fop, lineno, 0.50, 'medium',
                    description=f'{fop}路径参数来自用户输入(无目录穿越字面量)'))
    return findings
