"""
栈canary绕过路径检测 -- 识别可泄露/绕过栈canary的代码模式。

设计理由:
  单纯检测栈溢出+canary存在是不够的。攻击者可通过以下方式绕过canary:
    1. 信息泄露: printf/vsprintf泄露栈内容(含canary值)
    2. 逐字节爆破: fork子进程中canary不变, 可逐字节猜测(TCP服务器场景)
    3. 覆写__stack_chk_fail的GOT条目——拦截canary校验失败
    4. 非连续溢出: 仅覆写返回地址而保留canary(通过结构体中的数组)

检测这些模式将单纯的\"canary存在→不可利用\"判断提升为
\"canary存在但有泄露路径→可利用\"的精细分级。

  - Bittau et al., IEEE S&P 2014, "Hacking Blind" — BROP逐字节爆破技术
  - Fritsch, 2023, "Stack Canary Bypass Techniques Survey"
"""
import re
from typing import Dict, List, Tuple

# canary泄露模式: printf类函数使用%p/%x/%s等可能泄露栈上数据
_CANARY_LEAK_PATTERNS = [
    (r'printf\s*\([^)]*%[pxs]', 'printf_format_leak'),
    (r'(?:write|send|fwrite)\s*\(\s*\d+\s*,\s*\w+\s*,\s*\d+', 'raw_stack_write'),
    (r'(?:memcpy|memmove)\s*\([^,]+,\s*[\w\]\[]+\s*,\s*\d+', 'stack_memcpy_out'),
]

# fork模式: fork()后canary在父子进程间共享, 可逐字节爆破
_FORK_PATTERN = re.compile(r'\bfork\s*\(')
# __stack_chk_fail的GOT覆写检测——若能任意写则可拦截canary失败
_CHK_FAIL_GOT = re.compile(r'__stack_chk_fail')

def detect_canary_bypass(pseudocode: str, func_name: str = "",
                         has_canary: bool = False) -> List[Dict]:
    """检测绕过canary保护的潜在路径。

    Returns:
      [{bypass_type, confidence, description, exploitation_strategy}, ...]
    """
    findings = []

    if not has_canary:
        return findings

    # 1. 信息泄露——格式化字符串泄露栈内容
    for pattern, ptype in _CANARY_LEAK_PATTERNS:
        for m in re.finditer(pattern, pseudocode):
            findings.append({
                'bypass_type': f'canary_leak_{ptype}',
                'function': func_name,
                'confidence': 0.60,
                'description': (
                    f'Potential canary leak via {ptype} at '
                    f'\"{m.group(0)[:80]}\" in {func_name}'
                ),
                'exploitation_strategy': (
                    'Leak canary value via format string / stack read → '
                    'craft payload with correct canary → overwrite return address'
                ),
            })

    # 2. fork场景——子进程canary不变
    if _FORK_PATTERN.search(pseudocode):
        findings.append({
            'bypass_type': 'fork_canary_reuse',
            'function': func_name,
            'confidence': 0.55,
            'description': (
                f'fork() detected in {func_name} — child process inherits '
                f'parent canary, enabling byte-by-byte brute force'
            ),
            'exploitation_strategy': (
                'fork server: overwrite one byte → crash → child dies, parent '
                'canary unchanged → repeat for each canary byte (256 tries max per byte)'
            ),
        })

    # 3. __stack_chk_fail引用——攻击面指示
    if _CHK_FAIL_GOT.search(pseudocode):
        findings.append({
            'bypass_type': 'chk_fail_reference',
            'function': func_name,
            'confidence': 0.30,
            'description': (
                f'__stack_chk_fail referenced in {func_name} — potential '
                f'GOT overwrite target if arbitrary write primitive exists'
            ),
            'exploitation_strategy': (
                'Overwrite __stack_chk_fail@GOT with ret/NOP → canary '
                'check effectively disabled → overflow without detection'
            ),
        })

    return findings

def assess_canary_risk(pseudocode: str, func_name: str = "",
                       has_canary: bool = False) -> Tuple[str, float, List[Dict]]:
    """综合评估canary保护的实际有效性。

    Returns:
      (risk_level, bypass_likelihood, bypass_findings)
      risk_level: 'protected' | 'leakable' | 'bypassable'
    """
    findings = detect_canary_bypass(pseudocode, func_name, has_canary)

    if not has_canary:
        return 'unprotected', 1.0, findings

    if not findings:
        return 'protected', 0.10, []

    # 有泄露路径 → canary保护弱化
    max_conf = max((f['confidence'] for f in findings), default=0)
    if max_conf >= 0.55:
        return 'leakable', max_conf, findings
    else:
        return 'protected', 0.25, findings
