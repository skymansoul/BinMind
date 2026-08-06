# [DEPRECATED] — 功能已迁移至 modules/info/analysis/double_free_analyzer.py 或 src/double_free_analyzer.py
# 若确认无外部引用, 可安全删除
# Double-free detection via string-scan of free(free( sequences
from __future__ import annotations
from typing import List

def detect_double_free(code, func=''):
    """同一变量两次free且中间无realloc — double-free."""
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

    # 分支路径上的条件double-free
    free_positions = []
    pos = 0
    while True:
        idx = code.find('free(', pos)
        if idx < 0: break
        end = code.find(')', idx)
        if end < 0: break
        var = code[idx+5:end].strip()
        free_positions.append((var, idx))
        pos = end + 1
    for i in range(len(free_positions)):
        for j in range(i+1, len(free_positions)):
            if free_positions[i][0] == free_positions[j][0]:
                v = free_positions[i][0]
                between = code[free_positions[i][1]:free_positions[j][1]]
                if (v+'=malloc') not in between and (v+'=realloc') not in between:
                    findings.append({
                        'type':'double-free','function':func,'variable':v,
                        'severity':'Critical','cwe':'CWE-415','confidence':0.85,
                        'description':'double-free (branch): '+v+' freed in both paths',
                    })

    return findings
