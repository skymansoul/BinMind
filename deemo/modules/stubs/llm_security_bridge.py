# llm_security_bridge.py — 安全分析桥接层
# 推理能力与传统二进制分析工具链之间的桥接。
# PwnGPT (ACL 2025) — 自动利用构造
# ClearAgent (LMPL 2025) — 自主体二进制分析
# Getting pwn'd (ESEC/FSE 2023) — 渗透测试
# ReSym (2024) — stripped binary 符号恢复
# Static Binary Taint Analysis (2024)
# NYU CTF Bench (2025) — 安全能力基准
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

@_dc
class LLMAnalysisResult:
    query_type: str                 # 'decompile' | 'name_function' | 'find_vuln' | 'generate_exploit'
    model: str = 'unknown'
    raw_response: str = ''
    structured_output: dict = _field(default_factory=dict)
    confidence: float = 0.0
    tokens_used: int = 0

# PwnGPT 风格多阶段分析
# PwnGPT (ACL 2025) 三阶段: Analysis → Generation → Verification
# 此处提供本地预处理器，减少远程调用次数

def preprocess_for_llm(function_asm: str, arch: str = 'x86_64') -> dict:
    """为模型分析准备函数上下文。
    PwnGPT: 静态分析 + 结构化输入。
    ClearAgent: 自主体迭代需要丰富的上下文。"""
    import re as _re
    # 提取API调用列表（PwnGPT关键特征）
    api_calls = _re.findall(r'call\s+(\S+)', function_asm, _re.IGNORECASE)
    # 识别栈帧大小（ClearAgent需要内存布局上下文）
    stack_ops = _re.findall(r'sub\s+rsp,\s*(0x[0-9a-fA-F]+)', function_asm)
    frame_size = int(stack_ops[0], 16) if stack_ops else 0
    # 控制流复杂度 — 分支/跳转指令数
    branches = len(_re.findall(r'\b(jmp|je|jne|jg|jl|jge|jle|ja|jb|jae|jbe)\b',
                               function_asm, _re.IGNORECASE))
    return {
        'api_calls': api_calls[:20],
        'frame_size': frame_size,
        'branch_count': branches,
        'instruction_count': len(function_asm.split('\n')),
        'arch': arch,
    }

# NYU CTF Bench 评测维度
# 五大能力维度: vulnerability_discovery, exploit_generation,
#   reverse_engineering, cryptography, forensics
_CTF_CATEGORIES = {
    'pwn': 'exploit_generation',
    'rev': 'reverse_engineering',
    'crypto': 'cryptography',
    'forensics': 'forensics',
    'web': 'vulnerability_discovery',
}

def estimate_task_difficulty(challenge_desc: str) -> dict:
    """基于NYU CTF Bench分类估算题目难度。
    返回 {'category': str, 'estimated_difficulty': 'easy'|'medium'|'hard'}。"""
    desc_lower = challenge_desc.lower()
    # 关键词 → 难度
    keywords = desc_lower.split()
    has_mitigation = any(w in keywords for w in
        ('pie', 'aslr', 'canary', 'nx', 'relro', 'full-relro', 'seccomp', 'sandbox'))
    has_complex_type = any(w in keywords for w in
        ('heap', 'uaf', 'kernel', 'race', 'double', 'tcache', 'fastbin'))
    if has_mitigation and has_complex_type:
        difficulty = 'hard'
    elif has_mitigation or has_complex_type:
        difficulty = 'medium'
    else:
        difficulty = 'easy'

    for short, full in _CTF_CATEGORIES.items():
        if short in desc_lower:
            return {'category': full, 'estimated_difficulty': difficulty}
    return {'category': 'unknown', 'estimated_difficulty': difficulty}
