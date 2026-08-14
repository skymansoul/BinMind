# CWE-22 路径穿越的路径归一化分析器
import re

_PATH_DANGER = ['../', '/etc/', '/root/', '/home/', '..']
_SANITIZERS = ['realpath','basename','dirname']

def analyze_path_safety(ir_lines, func_name=""):
    findings = []
    tainted = set()
    for lineno, line in enumerate(ir_lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip().lower()
        if any(s in rhs for s in ('argv','getenv','read','recv','scanf','gets','fgets')):
            tainted.add(lhs)
    for lineno, line in enumerate(ir_lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip()
        for tv in list(tainted):
            if tv in rhs and lhs != tv: tainted.add(lhs)
    file_ops = ['open','fopen','opendir','mkdir','unlink','remove','rename','chmod','stat','access']
    for lineno, line in enumerate(ir_lines):
        line_l = line.lower()
        for fop in file_ops:
            if fop not in line_l: continue
            has_danger = any(d in line for d in _PATH_DANGER)
            has_taint = any(tv in line for tv in tainted)
            has_san = any(s in line for s in _SANITIZERS)
            if has_danger and has_taint and not has_san:
                findings.append({'finding_id': f'PT_{fop}_{lineno}', 'line': lineno,
                    'confidence': 0.85, 'severity': 'critical', 'cwe': 'CWE-22',
                    'description': f'{fop} path has ../ from user input, no sanitizer'})
            elif has_taint and not has_san:
                findings.append({'finding_id': f'PT_{fop}_{lineno}', 'line': lineno,
                    'confidence': 0.45, 'severity': 'medium', 'cwe': 'CWE-22',
                    'description': f'{fop} path from user input, no sanitizer'})
    return findings
