# Double-free detection via string-scan of free(free( sequences
from __future__ import annotations
from typing import List

def detect_double_free(code, func=''):
    """检测双重释放: 同一变量被free两次, 中间无重新分配."""
    findings = []
    free_calls = []
    i = 0
    while True:
        idx = code.find('free(', i)
        if idx < 0: break
        start = idx + 5
        end = code.find(')', start)
        if end < 0: break
        var = code[start:end].strip()
        # 清洗: 去除 ->x 后缀, 保留基础变量名
        if '->' in var:
            var = var.split('->')[0]
        if '.' in var and not var.startswith('.'):
            var = var.split('.')[0]
        free_calls.append({'var': var, 'start': int(idx), 'end': int(end + 1)})
        i = end + 1

    for a in range(len(free_calls)):
        for b in range(a + 1, len(free_calls)):
            fa, fb = free_calls[a], free_calls[b]
            if fa['var'] != fb['var'] or fa['var'] in ('', 'NULL', 'nullptr'):
                continue
            v = fa['var']
            between = code[fa['end']:fb['start']]
            # 中间有重新分配 → 不算 double-free
            if any(p in between for p in (v+'=malloc', v+'=calloc', v+'=realloc',
                                            v+' = malloc', v+' = calloc')):
                continue
            findings.append({
                'type': 'double-free', 'function': func, 'variable': v,
                'severity': 'Critical', 'cwe': 'CWE-415', 'confidence': 0.9,
                'description': f'double-free: {v} freed at pos {fa["start"]} and {fb["start"]}',
            })
    return findings
