# [DEPRECATED] — 功能已迁移至 modules/info/analysis/stack_overflow_deep.py 或 src/stack_overflow_deep.py
# 若确认无外部引用, 可安全删除
# Stack overflow deep analyzer -- frame size + dangerous call detection
from __future__ import annotations
from typing import List, Dict, Optional
import re

def extract_buffer_sizes(code):
    sizes = {}
    for m in re.finditer(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]', code):
        sizes[m.group(1)] = int(m.group(2))
    for m in re.finditer(r'char\s+(\w+)\s*\[\s*(\w+)\s*\]', code):
        sizes[m.group(1)] = -1  # variable size
    return sizes

def extract_write_sizes(code):
    writes = []
    for m in re.finditer(r'(?:strcpy|strcat|gets|sprintf|scanf)\s*\(\s*(\w+)', code):
        writes.append((m.group(1), 'unbounded'))
    for m in re.finditer(r'(?:strncpy|snprintf|fgets|read)\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)', code):
        writes.append((m.group(1), m.group(2)))
    for m in re.finditer(r'memcpy\s*\(\s*(\w+)\s*,\s*[^,]+\s*,\s*(\w+)\s*\)', code):
        writes.append((m.group(1), m.group(2)))
    return writes

def detect_stack_overflow(code, func=''):
    findings = []
    buffers = extract_buffer_sizes(code)
    writes = extract_write_sizes(code)
    for buf_name, write_size in writes:
        if buf_name in buffers:
            buf_sz = buffers[buf_name]
            if buf_sz < 0:
                findings.append({
                    'type': 'stack-overflow', 'function': func,
                    'buffer': buf_name, 'buffer_size': 'variable',
                    'write_size': str(write_size),
                    'severity': 'High', 'cwe': 'CWE-121',
                    'confidence': 0.6,
                    'description': f'Stack overflow: {buf_name}[variable] written by unbounded call',
                })
            elif write_size == 'unbounded':
                findings.append({
                    'type': 'stack-overflow', 'function': func,
                    'buffer': buf_name, 'buffer_size': buf_sz,
                    'write_size': 'unbounded',
                    'severity': 'Critical', 'cwe': 'CWE-121',
                    'confidence': 0.9,
                    'description': f'Stack overflow: {buf_name}[{buf_sz}] with unbounded strcpy/gets',
                })
    return findings
