"""
Decompiler interface. Talks to radare2, Ghidra, or IDA.
The AI-assisted decompilation path is handled here.
"""

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
from core.ai_backends import query_llm

logger = logging.getLogger(__name__)


def strip_ansi(text: str) -> str:
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def _run_radare2(binary_path: str, commands: List[str], timeout: int = 300) -> str:
    cmd = [R2_PATH, '-q', '-e', 'io.color=false']
    for c in commands:
        cmd.extend(['-c', c])
    cmd.append(binary_path)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ''
    except FileNotFoundError:
        logger.warning("radare2 not found at %s", R2_PATH)
        return ''


def list_functions(binary_path: str) -> List[str]:
    """Return all function names via radare2."""
    raw = _run_radare2(binary_path, ['afl'], timeout=60)
    funcs = []
    for line in raw.splitlines():
        # afl output: addr size name
        parts = strip_ansi(line).split()
        if len(parts) >= 3:
            funcs.append(parts[-1])
    return funcs


def decompile_function(binary_path: str, func_name: str,
                       decompiler: str = None) -> Dict:
    """
    Decompile a single function. Returns {name, pseudocode, raw_asm}.
    If the decompiler is 'auto', tries r2 first, then Ghidra.
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
        raw = _run_radare2(binary_path, [f's {func_name}', 'pdc'], timeout=120)
        result['pseudocode'] = strip_ansi(raw)
        raw_asm = _run_radare2(binary_path, [f's {func_name}', 'pdf'], timeout=60)
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
    """Attempt Ghidra headless decompilation."""
    try:
        import subprocess
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
            # read output from script
            out_file = os.path.join(tmpdir, f'{func_name}.c')
            if os.path.isfile(out_file):
                with open(out_file) as fh:
                    return {'pseudocode': fh.read(), 'source': 'ghidra'}
    except Exception:
        pass
    return None


# ---- AI-assisted analysis ----

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


def ai_analyze_function(func_name: str, pseudocode: str,
                        binary_info: Dict = None) -> Dict:
    """
    Ask an LLM to review decompiled code for vulnerabilities.
    Falls back gracefully if no API key is configured.
    """
    if not pseudocode or not pseudocode.strip():
        return {'function': func_name, 'vulnerabilities': [], 'summary': ''}

    if not OPENAI_API_KEY:
        return {
            'function': func_name,
            'vulnerabilities': [],
            'summary': '(no API key configured)',
            'pseudocode': pseudocode,
        }

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
        response = query_llm(
            system=_AI_SYSTEM_PROMPT,
            user=user_prompt,
            model=None,  # use default
            temperature=0.3,
        )
        # try to extract JSON from response
        json_match = re.search(r'\{[\s\S]*\}', response)
        if json_match:
            parsed = json.loads(json_match.group(0))
            parsed['function'] = func_name
            parsed['pseudocode'] = pseudocode
            return parsed
        return {
            'function': func_name,
            'vulnerabilities': [],
            'summary': response[:200],
            'pseudocode': pseudocode,
        }
    except Exception as e:
        logger.warning("AI analysis failed for %s: %s", func_name, e)
        return {
            'function': func_name,
            'vulnerabilities': [],
            'error': str(e),
            'pseudocode': pseudocode,
        }
