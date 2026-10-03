import logging
import re
from typing import Dict, Any, Tuple, List

logger = logging.getLogger(__name__)


REGISTER_PATTERNS = [
    re.compile(r'([a-zA-Z][a-zA-Z0-9]{1,3})\s*=\s*(0x[0-9a-fA-F]+)'),
    re.compile(r'([a-zA-Z][a-zA-Z0-9]{1,3})\s*:\s*(0x[0-9a-fA-F]+)'),
    re.compile(r'([a-zA-Z][a-zA-Z0-9]{1,3})\s+(0x[0-9a-fA-F]+)'),
    re.compile(r'\$\{?([a-zA-Z][a-zA-Z0-9]{1,3})\}?\s*=\s*(0x[0-9a-fA-F]+)'),
]

REGISTER_NAMES = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'rip', 'eflags', 'cs', 'ss', 'ds', 'es', 'fs', 'gs',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
    'eip', 'flags', 'ax', 'bx', 'cx', 'dx', 'si', 'di', 'sp', 'bp'
}


def parse_registers_from_text(text: str) -> Dict[str, str]:
    registers = {}

    if not text:
        return registers

    lines = text.split('\n')

    for line in lines:
        line = line.strip()
        if not line:
            continue

        for pattern in REGISTER_PATTERNS:
            matches = pattern.findall(line)
            for reg_name, reg_value in matches:
                reg_name_lower = reg_name.lower()

                if reg_name_lower in REGISTER_NAMES:
                    registers[reg_name_lower] = reg_value
                elif reg_name in REGISTER_NAMES:
                    registers[reg_name] = reg_value

    return registers


def heuristic_analysis(crash_data: Dict[str, Any]) -> Dict[str, Any]:
    result = {
        'crash_type': 'Unknown',
        'vulnerability_type': 'Unknown',
        'analysis': '',
        'exploitability': 'Unknown',
        'difficulty': 'Unknown',
        'recommendations': []
    }

    try:
        registers = {}
        if 'registers' in crash_data:
            if isinstance(crash_data['registers'], dict):
                registers = {k.lower(): v for k, v in crash_data['registers'].items()}
            elif isinstance(crash_data['registers'], str):
                registers = parse_registers_from_text(crash_data['registers'])

        fault_instruction = crash_data.get('fault_instruction', '')
        stack_trace = crash_data.get('stack_trace', '')
        if isinstance(stack_trace, list):
            stack_trace = ' '.join(str(frame) for frame in stack_trace)

        rip = registers.get('rip') or registers.get('eip') or ''
        rsp = registers.get('rsp') or registers.get('esp') or ''

        try:
            rip_val = int(str(rip), 16) if isinstance(rip, str) and '0x' in rip else 0
        except (ValueError, TypeError):
            rip_val = 0

        if rip_val:
            if '41414141' in str(rip) or '42424242' in str(rip) or 'deadbeef' in str(rip).lower():
                result['crash_type'] = 'Controlled RIP - Memory Corruption'
                result['vulnerability_type'] = 'Stack Buffer Overflow or Use-After-Free'
                result['exploitability'] = 'High'
                result['difficulty'] = 'Easy'
                result['analysis'] = 'RIP 被可控数据覆盖，表明存在内存破坏漏洞'
                result['recommendations'] = [
                    '确认偏移量',
                    '检查是否有 Canary 保护',
                    '寻找 ROP gadgets'
                ]

        crash_text = str(crash_data).lower()

        if 'sigsegv' in crash_text or 'segmentation fault' in crash_text:
            result['crash_type'] = 'Segmentation Fault'
            if '41414141' in crash_text or 'aaaa' in crash_text.lower():
                result['vulnerability_type'] = 'Memory Corruption'
                result['exploitability'] = 'Medium'

        if 'sigabrt' in crash_text or 'abort' in crash_text:
            result['crash_type'] = 'Abort Signal'
            if 'stack smashing' in crash_text or '__stack_chk_fail' in stack_trace.lower():
                result['vulnerability_type'] = 'Stack Overflow (Detected by Canary)'
                result['analysis'] = '栈溢出被 Canary 保护检测到'
                result['exploitability'] = 'Low (if canary cannot be leaked)'
                result['difficulty'] = 'Hard'
                result['recommendations'] = [
                    '尝试泄露 Canary 值',
                    '寻找格式化字符串漏洞',
                    '检查是否存在信息泄露'
                ]

        if '%n' in crash_text or '%x%x%x%x' in crash_text:
            result['vulnerability_type'] = 'Format String Vulnerability'
            result['analysis'] = '发现格式化字符串模式'
            result['exploitability'] = 'High'
            result['recommendations'] = [
                '确认格式化字符串可控',
                '尝试读取内存',
                '尝试写入内存'
            ]

        if 'double free' in crash_text:
            result['vulnerability_type'] = 'Double Free'
            result['crash_type'] = 'Heap Corruption'
            result['exploitability'] = 'Medium'

        if 'use-after-free' in crash_text:
            result['vulnerability_type'] = 'Use-After-Free'
            result['crash_type'] = 'Use-After-Free'
            result['exploitability'] = 'High'

        if 'heap' in crash_text and ('corrupt' in crash_text or 'overflow' in crash_text):
            result['vulnerability_type'] = 'Heap Corruption'
            result['crash_type'] = 'Heap Overflow/Corruption'
            result['exploitability'] = 'Medium'

        logger.info(f"启发式分析完成，判断漏洞类型: {result['vulnerability_type']}")

    except Exception as e:
        logger.error(f"启发式分析出错: {e}")

    return result


def _heuristic_detect_types(text: str) -> Tuple[str, str]:
    text_lower = text.lower()

    crash_types = [
        ('Segmentation Fault', ['segmentation fault', 'sigsegv', 'segfault']),
        ('Abort', ['sigabrt', 'abort', 'stack smashing']),
        ('Bus Error', ['sigbus', 'bus error']),
        ('Floating Point Exception', ['sigfpe', 'floating point']),
    ]

    vuln_types = [
        ('Stack Buffer Overflow', ['stack overflow', '栈溢出', 'buffer overflow']),
        ('Format String', ['format string', '格式化字符串']),
        ('Heap Overflow', ['heap overflow', '堆溢出']),
        ('Use-After-Free', ['use-after-free', '使用后释放']),
        ('Double Free', ['double free']),
        ('Memory Corruption', ['memory corruption', '内存损坏']),
    ]

    crash_type = 'Unknown'
    for name, patterns in crash_types:
        if any(p in text_lower for p in patterns):
            crash_type = name
            break

    vuln_type = 'Unknown'
    for name, patterns in vuln_types:
        if any(p in text_lower for p in patterns):
            vuln_type = name
            break

    return crash_type, vuln_type


def _heuristic_extract_analysis(text: str) -> str:
    lines = text.strip().split('\n')
    analysis_lines = []

    for line in lines:
        line = line.strip()
        if line and not line.startswith('```') and not line.startswith('#'):
            analysis_lines.append(line)
        if len(analysis_lines) >= 10:
            break

    analysis = ' '.join(analysis_lines)
    return analysis[:1000] if len(analysis) > 1000 else analysis


def _heuristic_detect_exploitability(text: str) -> str:
    text_lower = text.lower()

    if 'high' in text_lower or '高' in text_lower:
        return 'High'
    elif 'medium' in text_lower or '中' in text_lower:
        return 'Medium'
    elif 'low' in text_lower or '低' in text_lower:
        return 'Low'
    return 'Unknown'


def _heuristic_detect_difficulty(text: str) -> str:
    text_lower = text.lower()

    if 'easy' in text_lower or '简单' in text_lower:
        return 'Easy'
    elif 'hard' in text_lower or '困难' in text_lower:
        return 'Hard'
    elif 'medium' in text_lower or '中等' in text_lower:
        return 'Medium'
    return 'Unknown'


def _heuristic_extract_recommendations(text: str) -> List[str]:
    recommendations = []

    lines = text.split('\n')
    for line in lines:
        line = line.strip()
        if line.startswith('-') or line.startswith('*') or line.startswith('•'):
            rec = line[1:].strip()
            if rec:
                recommendations.append(rec)
        elif line.startswith('建议') or line.startswith('recommend'):
            rec = line.split(':', 1)[-1].strip()
            if rec:
                recommendations.append(rec)

    return recommendations[:5]
