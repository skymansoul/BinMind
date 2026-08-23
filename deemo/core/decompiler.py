# core/decompiler.py - 反编译接口 (radare2 / Ghidra 回退 + LLM 辅助审查)

import json
import logging
import os
import re
import subprocess
import tempfile
from typing import Dict, List, Optional

from config import (
    DEFAULT_DECOMPILER, R2_PATH, SUBPROCESS_TIMEOUT,
    GHIDRA_TIMEOUT, OPENAI_API_KEY, AI_PROVIDER, LLM_ENDPOINTS,
)
from modules.llm_client import is_ai_configured, call_llm_simple

logger = logging.getLogger(__name__)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)


def _run_radare2(binary_path: str, commands: List[str], timeout: int = 300) -> str:
    cmd = [R2_PATH, '-q', '-e', 'scr.color=false', '-e', 'scr.interactive=false']
    for c in commands:
        cmd.extend(['-c', c])
    cmd.append(binary_path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding='utf-8', errors='replace',
                              timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ''
    except FileNotFoundError:
        logger.warning("radare2 not found at %s", R2_PATH)
        return ''


def list_functions(binary_path: str) -> List[str]:
    """返回 r2 发现的全部函数名。"""
    raw = _run_radare2(binary_path, ['aa', 'afl'], timeout=60)
    funcs = []
    for line in raw.splitlines():
        # afl output: addr size name
        parts = strip_ansi(line).split()
        if len(parts) >= 3:
            funcs.append(parts[-1])
    return funcs


def decompile_function(binary_path: str, func_name: str,
                       decompiler: str = None) -> Dict:
    """反编译单个函数, 返回 {name, pseudocode, raw_asm}。

    decompiler='auto' 时先试 r2, 失败回退 Ghidra。
    """
    if decompiler is None:
        decompiler = DEFAULT_DECOMPILER

    result = {
        'name': func_name,
        'pseudocode': '',
        'raw_asm': '',
        'decompiler': decompiler,
    }

    if decompiler in ('auto', 'r2'):
        # try r2 decompiler
        raw = _run_radare2(binary_path, ['aa', f's {func_name}', 'pdc'], timeout=120)
        result['pseudocode'] = strip_ansi(raw)
        raw_asm = _run_radare2(binary_path, ['aa', f's {func_name}', 'pdf'], timeout=60)
        result['raw_asm'] = strip_ansi(raw_asm)
        if result['pseudocode'].strip():
            result['decompiler'] = 'r2'
            return result

    if decompiler in ('auto', 'ghidra'):
        ghidra_result = _decompile_ghidra(binary_path, func_name)
        if ghidra_result:
            result['pseudocode'] = ghidra_result.get('pseudocode', '')
            result['decompiler'] = 'ghidra'
            return result

    return result


def _decompile_ghidra(binary_path: str, func_name: str) -> Optional[Dict]:
    """Ghidra headless 反编译; 未配置 GHIDRA_HOME 时返回 None。"""
    try:
        ghidra_home = os.environ.get('GHIDRA_HOME', '')
        if not ghidra_home:
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            analyze_headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
            cmd = [
                analyze_headless,
                tmpdir, 'TempProject',
                '-import', binary_path,
                '-postScript', 'DecompileFunction.java', func_name,
            ]
            subprocess.run(cmd, capture_output=True, timeout=GHIDRA_TIMEOUT)
            # 脚本产物: <func_name>.c
            out_file = os.path.join(tmpdir, f'{func_name}.c')
            if os.path.isfile(out_file):
                with open(out_file, encoding='utf-8') as fh:
                    return {'pseudocode': fh.read(), 'source': 'ghidra'}
    except Exception as err:
        logger.debug("ghidra headless failed for %s: %s", func_name, err)
    return None


# AI 辅助分析

_AI_SYSTEM_PROMPT = """You are a binary reverse-engineering expert.
Analyze the provided decompiled C code for security vulnerabilities.
Report buffer overflows, format string bugs, integer overflows,
use-after-free, double-free, race conditions, and logic flaws.
For each vulnerability found, provide:
- type: the vulnerability class
- severity: Critical/High/Medium/Low
- location: function name or address
- description: what makes this exploitable
- cwe: the CWE number if applicable
Output as JSON with a "vulnerabilities" array."""


# 启发式危险函数模式, 降级模拟分析时用于推断候选漏洞
_DANGER_PATTERNS = [
    (re.compile(r'\bstrcpy\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'strcpy 无边界检查', 'High'),
    (re.compile(r'\bstrcat\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'strcat 无边界检查', 'High'),
    (re.compile(r'\bgets\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-242', 'gets 为不安全函数', 'Critical'),
    (re.compile(r'\bsprintf\s*\(', re.IGNORECASE), 'format_string',
     'CWE-134', 'sprintf 潜在格式化字符串漏洞', 'High'),
    (re.compile(r'\bprintf\s*\([^)]*%[^\)]*\)', re.IGNORECASE), 'format_string',
     'CWE-134', 'printf 含格式化占位符', 'Medium'),
    (re.compile(r'\bmemcpy\s*\(', re.IGNORECASE), 'buffer_overflow',
     'CWE-120', 'memcpy 需检查长度参数', 'Medium'),
    (re.compile(r'\bfree\s*\(', re.IGNORECASE), 'use_after_free',
     'CWE-416', 'free 后需置空指针', 'Low'),
    (re.compile(r'\bmalloc\s*\(', re.IGNORECASE), 'integer_overflow',
     'CWE-190', 'malloc 参数需检查整数溢出', 'Low'),
    (re.compile(r'\bsystem\s*\(', re.IGNORECASE), 'command_injection',
     'CWE-78', 'system 调用需检查输入来源', 'High'),
]


def _heuristic_analyze(func_name: str, pseudocode: str) -> Dict:
    """启发式模拟分析: 基于危险函数模式推断候选漏洞, 返回结构化结果。

    无 LLM 配置时作为降级路径, 保证管道拿到非空 findings。
    """
    vulns = []
    for pat, vtype, cwe, desc, severity in _DANGER_PATTERNS:
        for m in pat.finditer(pseudocode):
            vulns.append({
                'type': vtype,
                'severity': severity,
                'location': func_name,
                'description': desc,
                'cwe': cwe,
                'evidence_snippet': pseudocode[max(0, m.start() - 20):m.end() + 20],
            })

    return {
        'function': func_name,
        'vulnerabilities': vulns,
        'summary': f'启发式模拟分析: 识别 {len(vulns)} 个候选漏洞' if vulns
                   else '启发式模拟分析: 未发现明显危险函数调用',
        'pseudocode': pseudocode,
        'simulation': True,
        'analysis_mode': 'heuristic_fallback',
    }


def ai_analyze_function(func_name: str, pseudocode: str,
                        binary_info: Dict = None) -> Dict:
    """LLM 审查反编译代码, 走 modules.llm_client 统一入口。

    未配置 AI 时降级为启发式模拟分析, 返回带 simulation 标记的结构化结果。
    """
    if not pseudocode or not pseudocode.strip():
        return {'function': func_name, 'vulnerabilities': [], 'summary': ''}

    # 未配置 AI 凭据时降级为启发式模拟, 不返回空结果
    if not is_ai_configured():
        logger.info("AI 未配置, 函数 %s 降级为启发式模拟分析", func_name)
        return _heuristic_analyze(func_name, pseudocode)

    context = f'Arch: {binary_info.get("arch", "unknown")}, ' \
              f'Format: {binary_info.get("format", "unknown")}' \
              if binary_info else ''

    user_prompt = f"""Analyze this decompiled function for vulnerabilities.

Binary context: {context}
Function: {func_name}

```c
{pseudocode[:8000]}
```

Report vulnerabilities as JSON."""

    try:
        result = call_llm_simple(
            prompt=user_prompt,
            system_prompt=_AI_SYSTEM_PROMPT,
            temperature=0.3,
        )

        # 统一入口返回 simulation=True 时降级为启发式
        if result.get('simulation'):
            logger.info("LLM 调用进入模拟模式, 函数 %s 降级为启发式分析", func_name)
            heuristic = _heuristic_analyze(func_name, pseudocode)
            heuristic['llm_error'] = result.get('error', '')
            return heuristic

        response = result.get('text', '')
        findings = result.get('findings', [])

        if findings:
            return {
                'function': func_name,
                'vulnerabilities': findings,
                'summary': f'LLM 分析: 识别 {len(findings)} 个漏洞',
                'pseudocode': pseudocode,
                'simulation': False,
                'model': result.get('model', ''),
            }

        # LLM 返回但未解析出 findings, 尝试原始 JSON 提取
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            parsed = json.loads(json_match.group(0))
            parsed['function'] = func_name
            parsed['pseudocode'] = pseudocode
            parsed['simulation'] = False
            return parsed

        return {
            'function': func_name,
            'vulnerabilities': [],
            'summary': response[:200] if response else 'LLM 未返回有效内容',
            'pseudocode': pseudocode,
            'simulation': False,
        }
    except Exception as e:
        logger.warning("AI analysis failed for %s: %s, 降级为启发式", func_name, e)
        heuristic = _heuristic_analyze(func_name, pseudocode)
        heuristic['llm_error'] = str(e)
        return heuristic
