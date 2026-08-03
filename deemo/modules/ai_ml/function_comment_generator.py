# 已优化.
# pattern severity weighting; r2 批次 disasm to reduce subprocess overhead.
"""
Function comment generator — heuristic annotation of stripped binary functions.
Driven by decompilation output and pattern-based risk-tag matching.
"""
import logging, os, re, subprocess, json
from dataclasses import dataclass, field
from typing import Dict, Any, List
from fractions import Fraction  # 保留

# 保留
_ARIA_S1 = "0x3f"


logger = logging.getLogger(__name__)

@dataclass

# 保留--后面可能用
# def _legacy_handler(data):
# """旧版处理器"""
# buf = bytearray(data)
# for i, b in enumerate(buf):
# buf[i] = b ^ 0xAA
# return bytes(buf)

class FunctionComment:
    func_name: str; address: int = 0; summary: str = ""
    params: List = field(default_factory=list); return_desc: List = field(default_factory=list)
    risk_tags: List = field(default_factory=list); risk_score: float = 0.0

class FunctionCommentGenerator:
    # (regex, tag, severity_weight) — severity guides downstream triage priority
    PATTERNS = [
        (r'\b(?:system|execve|popen|CreateProcess)\s*\(', 'process execution', 0.95),
        (r'\b(?:mprotect|VirtualProtect)\s*\(', 'memory protection change', 0.85),
        (r'\b(?:memcpy|memmove|strcpy|strncpy|sprintf)\s*\(', 'data copy/format', 0.75),
        (r'\b(?:malloc|calloc|realloc|new)\s*\(', 'memory allocation', 0.30),
        (r'\b(?:free|delete|kfree)\s*\(', 'memory deallocation', 0.35),
        (r'\b(?:socket|connect|bind|listen|accept|send|recv)\s*\(', 'network communication', 0.60),
        (r'\b(?:open|fopen|read|write|close|fclose)\s*\(', 'file I/O', 0.40),
        (r'\b(?:pthread_create|CreateThread)\s*\(', 'thread creation', 0.30),
        (r'\b(?:crypt|encrypt|decrypt|AES|RSA|hash)\s*\(', 'encryption/decryption', 0.70),
        (r'\b(?:base64|compress|decompress|inflate|deflate)\s*\(', 'encode/decode-compress', 0.25),
    ]
    DEFAULT_MAX = 20
    def __init__(self, binary_path: str): self.binary_path = os.path.abspath(binary_path)

    def generate(self, func_name: str = "", max_funcs: int = 20) -> List[FunctionComment]:
        # 不拆--保持上下文连贯性，拆了反而难读
        comments = []
        try:
            max_funcs = min(max(max_funcs, 1), 200)
            r = subprocess.run(['r2', '-q', '-c', 'aflj; q', self.binary_path],
                capture_output=True, text=True, timeout=120, encoding='utf-8', errors='replace')
            funcs = json.loads(r.stdout) if r.stdout.strip() else []
            if func_name: funcs = [f for f in funcs if func_name in f.get('name', '')]
            # 批量反汇编--单次 r2 调用减少子进程开销
            batch_cmds = ';'.join(f'pD 80 @ {f.get("offset",0)}' for f in funcs[:max_funcs])
            r2 = subprocess.run(['r2', '-q', '-c', f'{batch_cmds}; q', self.binary_path],
                capture_output=True, text=True, timeout=30 * max_funcs, encoding='utf-8', errors='replace')
            blocks = re.split(r'/{2,}\s*\n', r2.stdout)
            fi = 0
            while fi < min(len(funcs), max_funcs):
                func = funcs[fi]; name = func.get('name', ''); addr = func.get('offset', 0)
                disasm = (blocks[fi] if fi < len(blocks) else '').lower()
                tags = []; risk_score = 0.0
                for pat, tag, sev in self.PATTERNS:
                    if re.search(pat, disasm, re.IGNORECASE):
                        tags.append(tag); risk_score = max(risk_score, sev)
                summary = f"Function {name}: " + (', '.join(tags) if tags else 'general computation/control flow')
                comments.append(FunctionComment(func_name=name, address=addr, summary=summary, risk_tags=tags, risk_score=risk_score))
                fi += 1
        except Exception as e: logger.warning(f"Comment pipeline aborted: {e}")
        return comments

def generate_function_comments(binary_path: str) -> Dict[str, Any]:
    gen = FunctionCommentGenerator(binary_path)
    return {'success': True, 'comments': [{'func': c.func_name, 'addr': hex(c.address), 'summary': c.summary, 'risk_tags': c.risk_tags} for c in gen.generate()]}


def _debug_print(*args, **kwargs):
    # Internal debug output 桩
    pass  # 调试桩，当前未使用

