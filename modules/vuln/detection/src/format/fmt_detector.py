"""格式化字符串漏洞检测器 — 反汇编 + .rodata 解析 + rip链追踪 + 三分类."""

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from .taint_format_checker import TaintFormatChecker, FormatVulnClass
    from .fmt_arg_verifier import FormatArgVerifier, ArgMatchVerdict
except ImportError:
    from taint_format_checker import TaintFormatChecker, FormatVulnClass
    from fmt_arg_verifier import FormatArgVerifier, ArgMatchVerdict


def disassemble_elf(elf_path: Path) -> List[Tuple[str, List[str], List[int]]]:
    """反汇编 ELF → [(func_name, [insns], [addrs])]."""
    r = subprocess.run(
        ['objdump', '-d', '-M', 'intel', str(elf_path)],
        capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return []
    current_func = ''
    current_insns: List[str] = []
    current_addrs: List[int] = []
    functions = []
    for line in r.stdout.split('\n'):
        line = line.rstrip()
        if not line:
            continue
        if line.endswith('>:') and not line.startswith(' '):
            if current_insns:
                functions.append((current_func, current_insns, current_addrs))
            current_func = line.strip('<:>').split('<')[-1].rstrip('>:')
            current_insns = []
            current_addrs = []
            continue
        if ':\t' in line and not line.startswith('Disassembly'):
            parts = line.split(':\t', 1)
            try:
                addr = int(parts[0].strip(), 16)
                instr = parts[1].split('\t')[-1].strip()
            except ValueError:
                continue
            current_insns.append(instr)
            current_addrs.append(addr)
    if current_insns:
        functions.append((current_func, current_insns, current_addrs))
    return functions


def extract_rodata_strings(elf_path: Path) -> Dict[int, str]:
    """从 ELF .rodata/.rdata 段提取可打印字符串 (objdump -s 解析)."""
    strings: Dict[int, str] = {}
    for section in ('.rodata', '.rdata'):
        r = subprocess.run(
            ['objdump', '-s', '-j', section, str(elf_path)],
            capture_output=True, text=True, timeout=15)
        if r.returncode != 0:
            continue
        for line in r.stdout.split('\n'):
            if ':' not in line or len(line) < 15:
                continue
            m = re.match(r'\s*([0-9a-f]+)\s+([0-9a-f ]{35})', line)
            if not m:
                continue
            addr_base = int(m.group(1), 16)
            hex_data = m.group(2).replace(' ', '')
            try:
                raw = bytes.fromhex(hex_data)
            except ValueError:
                continue
            printable = ''
            for i, b in enumerate(raw):
                if 0x20 <= b < 0x7f:
                    printable += chr(b)
                else:
                    if len(printable) >= 3:
                        strings[addr_base + i - len(printable)] = printable
                    printable = ''
            if len(printable) >= 3:
                strings[addr_base + len(raw) - len(printable)] = printable
    return strings


def detect_fmt_vuln(insns: List[str], addrs: List[int],
                    rodata_strs: Dict[int, str]) -> dict:
    """格式化字符串漏洞检测 (基础版): 找 printf-family → 判断格式源."""
    findings = []
    printf_calls = {'printf', 'fprintf', 'sprintf', 'snprintf',
                    'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
                    'syslog', 'wprintf'}

    for i, (instr, addr) in enumerate(zip(insns, addrs)):
        parts = instr.split()
        if len(parts) < 2:
            continue
        mnem = parts[0].lower()
        if mnem != 'call':
            continue
        called = parts[1].lower().strip('<>@')
        if not any(pf in called for pf in printf_calls):
            continue

        fmt_is_constant = False
        fmt_is_tainted = True
        fmt_content = ''

        for j in range(max(0, i - 5), i):
            prev_parts = insns[j].split()
            if len(prev_parts) < 3:
                continue
            if prev_parts[0].lower() not in ('mov', 'lea', 'movabs'):
                continue
            dst = prev_parts[1].strip(',').lower()
            if dst not in ('rdi', 'rcx', 'edi', 'ecx'):
                continue
            if 'rip' in insns[j].lower() or 'lea' in insns[j].lower():
                m = re.search(r'rip\s*[-+]\s*(0x[0-9a-fA-F]+)',
                             insns[j].lower())
                if m:
                    fmt_is_constant = True
                    fmt_is_tainted = False
            m = re.search(r'(0x[0-9a-fA-F]+)', prev_parts[2].lower())
            if m:
                ref_addr = int(m.group(1), 16)
                if ref_addr in rodata_strs:
                    fmt_is_constant = True
                    fmt_is_tainted = False
                    fmt_content = rodata_strs[ref_addr][:80]
            break

        has_write = '%n' in fmt_content if fmt_content else False

        if fmt_is_tainted:
            conf = 0.92
            desc = 'fmt_string_vuln: format from variable (user-controllable)'
        elif has_write:
            conf = 0.75
            desc = 'fmt_write_capable: constant format with %n'
        else:
            continue

        findings.append({
            'type': 'FORMAT_STRING', 'addr': addr,
            'func': called,
            'fmt_is_constant': fmt_is_constant,
            'fmt_is_tainted': fmt_is_tainted,
            'has_write': has_write,
            'confidence': conf, 'desc': desc,
        })

    return {
        'findings': findings,
        'n_findings': len(findings),
        'detected': len(findings) > 0,
    }


def detect_fmt_vuln_enhanced(insns: List[str], addrs: List[int],
                             rodata_strs: Dict[int, str]) -> dict:
    """增强检测 — TaintFormatChecker 三分类 + FormatArgVerifier 参数验证."""
    findings = []
    taint_checker = TaintFormatChecker()
    arg_verifier = FormatArgVerifier()
    printf_calls = {'printf', 'fprintf', 'sprintf', 'snprintf',
                    'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
                    'syslog', 'wprintf', '__mingw_printf'}

    for i, (instr, addr) in enumerate(zip(insns, addrs)):
        # 按 objdump 格式（含十六进制字节）正确切分指令
        instr_parts = instr.split(maxsplit=1)
        if len(instr_parts) < 2:
            continue
        mnem = instr_parts[0].lower()
        if mnem != 'call':
            continue
        called = instr_parts[1].lower().strip('<>@')
        if not any(pf in called for pf in printf_calls):
            continue

        # 阶段1: 单次前向扫描 — 收集 rip 加载 + 找格式源指令
        fmt_is_constant = False
        fmt_is_tainted = True
        fmt_content = ''
        pre_call_insns: List[Tuple[str, str, int]] = []
        rip_loaded: Dict[str, Tuple[int, int]] = {}  # reg → (lea_addr, rip_off)
        fmt_src_instrs: list = []  # [(mnem, ops, insn_text, addr), ...]

        for j in range(max(0, i - 6), i):
            prev_instr = insns[j]
            prev_parts = prev_instr.split(maxsplit=1)
            prev_mnem = prev_parts[0].lower() if prev_parts else ''
            prev_ops = prev_parts[1] if len(prev_parts) > 1 else ''
            pre_call_insns.append((prev_mnem, prev_ops, addrs[j]))

            # 跟踪 rip 加载 + 覆写
            if prev_mnem in ('lea', 'mov', 'movabs'):
                dst = prev_ops.split(',')[0].strip().lower() if ',' in prev_ops else ''
                if 'rip' in prev_instr.lower():
                    m = re.search(r'rip\s*([-+])\s*(0x[0-9a-fA-F]+)',
                                 prev_instr.lower())
                    if m:
                        rip_off = (1 if m.group(1) == '+' else -1) * int(m.group(2), 0)
                        rip_loaded[dst] = (addrs[j], rip_off)
                else:
                    rip_loaded.pop(dst, None)
            elif prev_mnem == 'call':
                rip_loaded.pop('rax', None)
                rip_loaded.pop('eax', None)

            # 收集所有写入 rcx/rdi 的指令用于格式源分析
            if prev_mnem in ('mov', 'lea', 'movabs'):
                dst = prev_ops.split(',')[0].strip().lower() if ',' in prev_ops else ''
                if dst in ('rdi', 'rcx', 'edi', 'ecx'):
                    fmt_src_instrs.append((prev_mnem, prev_ops, prev_instr, addrs[j]))

        # 阶段1b: 检查所有 rcx/rdi 写入 — 任一条来自 rip → 常量
        for prev_mnem, prev_ops, prev_instr, prev_addr in fmt_src_instrs:
                if 'rip' in prev_instr.lower():
                    m2 = re.search(r'rip\s*[-+]\s*(0x[0-9a-fA-F]+)',
                                  prev_instr.lower())
                    if m2:
                        fmt_is_constant = True
                        fmt_is_tainted = False
                if not fmt_is_constant and prev_mnem == 'mov':
                    src = prev_ops.split(',')[1].strip().lower() if ',' in prev_ops else ''
                    if src in rip_loaded:
                        fmt_is_constant = True
                        fmt_is_tainted = False
                        lea_addr, rip_off = rip_loaded[src]
                        abs_addr = lea_addr + 7 + rip_off
                        if abs_addr in rodata_strs:
                            fmt_content = rodata_strs[abs_addr][:80]
                m2 = re.search(r'(0x[0-9a-fA-F]+)', prev_ops.lower())
                if m2:
                    ref_addr = int(m2.group(1), 16)
                    if ref_addr in rodata_strs:
                        fmt_is_constant = True
                        fmt_is_tainted = False
                        fmt_content = rodata_strs[ref_addr][:80]

        taint_result = taint_checker.classify(
            call_addr=addr,
            function_name=called,
            format_string=fmt_content if fmt_content else '<variable>',
            format_is_constant=fmt_is_constant,
            format_is_tainted=fmt_is_tainted,
        )

        arg_result = None
        if fmt_content:
            arg_result = arg_verifier.verify(
                fmt_content, addr, pre_call_insns, called)
        has_write = '%n' in fmt_content if fmt_content else False

        vuln_class = taint_result.vuln_class
        if vuln_class == FormatVulnClass.FORMAT_STRING_VULN:
            conf = 0.92
            desc = 'FORMAT_STRING_VULN: user-controllable format string'
        elif vuln_class == FormatVulnClass.FORMAT_WRITE_CAPABLE:
            conf = 0.70
            desc = 'FORMAT_WRITE_CAPABLE: constant format with %n'
        elif vuln_class == FormatVulnClass.INFORMATION_LEAK:
            conf = 0.55
            desc = 'INFORMATION_LEAK: tainted data in printf args'
        else:
            # SAFE — 但若参数验证发现不足, 仍可能是漏洞
            if (arg_result and
                arg_result.verdict == ArgMatchVerdict.TOO_FEW_ARGS):
                vuln_class = FormatVulnClass.INFORMATION_LEAK
                conf = 0.60
                desc = (f'INFORMATION_LEAK: format needs {arg_result.expected_args} '
                        f'args, only {arg_result.actual_args} provided')
            else:
                continue  # 安全 — 跳过

        arg_info = None
        if arg_result:
            arg_info = {'expected': arg_result.expected_args,
                       'actual': arg_result.actual_args,
                       'verdict': arg_result.verdict.name}

        findings.append({
            'type': 'FORMAT_STRING', 'addr': addr,
            'func': called, 'vuln_class': vuln_class.value,
            'fmt_is_constant': fmt_is_constant,
            'fmt_is_tainted': fmt_is_tainted,
            'fmt_content': fmt_content[:60] if fmt_content else '',
            'has_write': has_write,
            'confidence': conf, 'desc': desc,
            'arg_check': arg_info,
        })

    return {
        'findings': findings,
        'n_findings': len(findings),
        'detected': len(findings) > 0,
    }
