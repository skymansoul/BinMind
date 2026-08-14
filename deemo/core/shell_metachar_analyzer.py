# CWE-78 命令注入的 shell 元字符污点传播分析器
# 追踪危险 shell 字符 (|;&) 从用户输入到 exec/sink 函数的传播
import re

_SHELL_DANGER = {
    ';': 'cmd_sep', '|': 'pipe', '&': 'background',
    '$(': 'cmd_sub', r'$\(': 'cmd_sub2', '&&': 'logical_and',
    '||': 'logical_or', '>': 'redirect_out', '<': 'redirect_in',
}

def trace_shell_metachars(ir_lines, func_name=""):
    findings = []
    code = chr(10).join(ir_lines)
    tainted_positions = set()
    for lineno, line in enumerate(ir_lines):
        for src in ('argv','getenv','read','recv','scanf','gets','fgets','socket','accept'):
            if src not in line.lower(): continue
            for mc in _SHELL_DANGER:
                if mc in line: tainted_positions.add(lineno)
    for lineno, line in enumerate(ir_lines):
        if not any(cmd in line.lower() for cmd in ('system','popen','exec','shell')): continue
        meta_found = [(mc, desc) for mc, desc in _SHELL_DANGER.items() if mc in line]
        if not meta_found: continue
        taint_distance = min((lineno - tp for tp in tainted_positions if tp < lineno), default=999)
        conf = 0.90 if taint_distance < 5 else (0.60 if taint_distance < 20 else 0.30)
        findings.append({
            'finding_id': f'SHELL_{lineno}', 'line': lineno,
            'metachars': [m[0] for m in meta_found],
            'taint_distance': taint_distance, 'confidence': conf,
            'severity': 'critical' if conf > 0.7 else 'high',
            'cwe': 'CWE-78',
            'description': f'Shell metachars at L{lineno}, taint_dist={taint_distance}',
        })
    return findings
