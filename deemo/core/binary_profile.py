"""
二进制程序画像 —— 生成 pwnpasi 风格的综合性安全分析画像。

整合 checksec 保护检测、PLT/GOT 扫描、libc 版本识别、ROP gadget 统计和
静态危险函数分析，输出一份结构化的"程序安全画像"字典。

设计意图: 替代 pwnpasi 的独立 checksec+plt+libc 手动收集流程，
提供机器可读的一体化输出，同时生成人类可读的摘要供 LLM context 注入。

画像包含六维度:
  1. 元数据 (架构/位数/格式/大小)
  2. 保护机制矩阵 (NX/PIE/Canary/RELRO/FORTIFY/ASLR/RWX)
  3. 导入表与可攻击面 (危险函数清单+PLT地址)
  4. libc 依赖与关键偏移
  5. ROP gadget 库存统计
  6. 潜在利用路径建议

参考:
  - pwnpasi (GitHub, 2023), "PWN PASI: Automated Exploit Generation Pipeline"
  - Xu et al., 2024, USENIX Security, "MOBE: Multi-Objective Binary Exploitation"
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

from config import R2_PATH

_log = logging.getLogger(__name__)


def build_binary_profile(
    binary_path: str,
    checksec: Optional[Dict[str, Any]] = None,
    plt_entries: Optional[List[Dict[str, Any]]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
    dangerous_imports: Optional[List[Dict[str, Any]]] = None,
    gadgets: Optional[List[Dict[str, Any]]] = None,
    suspect_strings: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    生成完整的二进制安全画像。

    接受可选的中间分析结果以避免重复计算。
    若未提供某个子结果，则按需惰性调用对应模块采集。

    Args:
        binary_path:     二进制文件路径
        checksec:        core.checksec.detect_checksec() 的结果
        plt_entries:     core.plt_scanner.scan_plt() 的结果
        libc_info:       core.libc_identifier.identify_libc() 的结果
        dangerous_imports: core.static_analysis.scan_imports() 的结果
        gadgets:         plugins.rop_tools.find_gadgets() 的结果
        suspect_strings: core.static_analysis.find_suspicious_strings() 的结果

    Returns:
        结构化画像字典，可直接注入 pipeline result['binary_profile']
    """
    if not os.path.isfile(binary_path):
        return {'error': f'file not found: {binary_path}', 'path': binary_path}

    # 元数据
    from core.binary_info import get_binary_info
    binfo = get_binary_info(binary_path)
    profile: Dict[str, Any] = {
        'binary_path': binary_path,
        'filename': os.path.basename(binary_path),
        'format': binfo.get('format', 'unknown'),
        'arch': binfo.get('arch', 'unknown'),
        'bits': binfo.get('bits', 64),
        'size_bytes': binfo.get('size', 0),
    }

    # 保护机制
    if checksec is None:
        try:
            from core.checksec import detect_checksec
            checksec = detect_checksec(binary_path)
        except ImportError:
            checksec = {}
    profile['checksec'] = checksec

    # 攻击面: PLT + 危险函数
    if plt_entries is None:
        try:
            from core.plt_scanner import scan_plt, find_exploitable_functions
            plt_entries = scan_plt(binary_path)
            exploitable = find_exploitable_functions(plt_entries)
        except ImportError:
            plt_entries = []
            exploitable = []
    else:
        try:
            from core.plt_scanner import find_exploitable_functions
            exploitable = find_exploitable_functions(plt_entries)
        except ImportError:
            exploitable = []

    profile['plt_count'] = len(plt_entries)
    profile['exploitable_imports'] = exploitable
    profile['dangerous_imports'] = dangerous_imports or []

    # libc 依赖
    if libc_info is None:
        try:
            from core.libc_identifier import identify_libc
            libc_info = identify_libc(binary_path)
        except ImportError:
            libc_info = {}
    profile['libc'] = libc_info

    # ROP 资源
    if gadgets is None:
        try:
            from plugins.rop_tools import find_gadgets
            gadgets = find_gadgets(binary_path, arch=binfo.get('arch', 'x86-64'))
        except ImportError:
            gadgets = []
    profile['gadget_count'] = len(gadgets)
    profile['gadgets'] = gadgets[:50]  # 截断避免输出过大
    profile['gadget_types'] = _summarize_gadget_types(gadgets)

    # 可疑字符串
    if suspect_strings is None:
        try:
            from core.static_analysis import scan_strings, find_suspicious_strings
            strings = scan_strings(binary_path)
            suspect_strings = find_suspicious_strings(strings)
        except ImportError:
            suspect_strings = []
    profile['suspect_strings'] = suspect_strings[:20]

    # 利用难度评估
    profile['exploit_difficulty'] = _assess_exploit_difficulty(profile)
    profile['recommended_approach'] = _recommend_approach(profile)

    return profile


def _summarize_gadget_types(gadgets: List[Dict[str, Any]]) -> Dict[str, int]:
    """统计各类 ROP gadget 的数量分布。"""
    counts: Dict[str, int] = {}
    for g in gadgets:
        t = g.get('type', 'unknown')
        counts[t] = counts.get(t, 0) + 1
    return counts


def _assess_exploit_difficulty(profile: Dict[str, Any]) -> str:
    """
    基于保护机制的利用难度评估。

    规则:
      - 无 NX → 直接 shellcode → Easy
      - NX 但无 PIE 且无 Canary + 有 system@PLT → Easy (ret2libc)
      - NX + PIE 但无 Canary → Medium (需 info leak)
      - NX + PIE + Canary + Full RELRO → Hard (需多个 primitive 组合)
    """
    cs = profile.get('checksec', {})
    score = 0
    if cs.get('nx', True):
        score += 1
    if cs.get('pie', True):
        score += 1
    if cs.get('canary', True):
        score += 1
    if cs.get('relro', 'none') == 'full':
        score += 1

    if score == 0:
        return 'trivial'
    if score <= 1:
        return 'easy'
    if score <= 2:
        return 'medium'
    if score <= 3:
        return 'hard'
    return 'very_hard'


def _recommend_approach(profile: Dict[str, Any]) -> List[str]:
    """基于画像推荐利用策略。"""
    approaches = []
    cs = profile.get('checksec', {})
    exploitable = profile.get('exploitable_imports', [])

    has_system = any(
        e['name'] == 'system' for e in exploitable
    )
    has_puts = any(e['name'] == 'puts' for e in exploitable)
    gadgets = profile.get('gadget_types', {})

    if not cs.get('nx', True):
        approaches.append('shellcode-injection (NX disabled)')

    if has_system:
        if not cs.get('pie', True):
            approaches.append('ret2libc (system@PLT + "/bin/sh" string)')
        else:
            approaches.append('ret2libc (leak PIE base then system@PLT)')

    if 'pop_rdi' in gadgets and has_puts:
        approaches.append('ret2plt (puts@PLT → leak libc → system)')

    if gadgets.get('syscall', 0) > 0 and 'pop_rax' in gadgets:
        approaches.append('SROP / sigreturn-oriented programming')

    if not cs.get('canary', True):
        approaches.append('direct-stack-overflow (no canary)')
    else:
        approaches.append('stack-overflow (require canary leak first)')

    if cs.get('relro', 'none') != 'full':
        approaches.append('GOT overwrite (partial RELRO)')

    return approaches


def profile_summary_for_report(profile: Dict[str, Any]) -> str:
    """
    生成画像的 Markdown 文本摘要，供报告嵌入。

    Args:
        profile: build_binary_profile() 的返回值

    Returns:
        Markdown 格式的画像摘要
    """
    cs = profile.get('checksec', {})
    libc = profile.get('libc', {})

    lines = [
        f"### Binary Profile: `{profile.get('filename', '?')}`",
        '',
        f"| Property | Value |",
        f"|----------|-------|",
        f"| Architecture | {profile.get('arch', '?')} ({profile.get('bits', 64)}-bit) |",
        f"| Format | {profile.get('format', '?')} |",
        f"| Size | {profile.get('size_bytes', 0):,} bytes |",
        f"| NX | {'✓' if cs.get('nx') else '✗'} |",
        f"| PIE | {'✓' if cs.get('pie') else '✗'} |",
        f"| Canary | {'✓' if cs.get('canary') else '✗'} |",
        f"| RELRO | {cs.get('relro', '?')} |",
        f"| FORTIFY | {'✓' if cs.get('fortify') else '✗'} |",
        f"| RWX Segments | {'✓ DANGEROUS' if cs.get('rwx_segments') else '✗'} |",
        f"| PLT Entries | {profile.get('plt_count', 0)} |",
        f"| Exploitable Imports | {len(profile.get('exploitable_imports', []))} |",
        f"| ROP Gadgets | {profile.get('gadget_count', 0)} |",
        f"| libc Version | {libc.get('version', 'unknown')} |",
        f"| Exploit Difficulty | **{profile.get('exploit_difficulty', '?').upper()}** |",
        '',
    ]

    # 可攻击面
    exploitable = profile.get('exploitable_imports', [])
    if exploitable:
        lines.append('**Exploitable Functions:**')
        for e in exploitable[:10]:
            lines.append(
                f"- `{e['name']}` @ PLT `{hex(e.get('plt_addr', 0))}` — "
                f"{e.get('risk_category', '?')} [{e.get('risk_severity', '?')}]"
            )
        lines.append('')

    # 推荐策略
    approaches = profile.get('recommended_approach', [])
    if approaches:
        lines.append('**Recommended Approaches:**')
        for a in approaches:
            lines.append(f"- {a}")
        lines.append('')

    return '\n'.join(lines)
