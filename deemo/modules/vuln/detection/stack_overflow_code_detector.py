# 代码级栈溢出检测器 - 输入反编译伪代码文本, 输出类型化 finding。
# 主流水线 direct 消费 pseudocode, 此检测器不依赖二进制/ELF,
# 定位与 Flawfinder/CPPcheck 同类: 危险写函数 + 栈数组声明作正交约束。
# 参考: Flawfinder (David A. Wheeler) 危险函数静态标记;
#       CPPcheck `bufferAccessOutOfBounds` 的"栈数组声明大小作为边界"判定思路。
# 与二进制的 StackBoundInferrer(地址/栈偏移驱动) 互补, 此处只做源码级规则标记。

import re
from typing import Dict, List


# 危险写原语 - (CWE, 默认置信度)
# unbounded 类写入无长度参数, 伪代码级无法证明不越界, 直接记候选。
_UNBOUNDED_WRITE = {
    'gets': ('CWE-122', 0.85),
    'strcpy': ('CWE-121', 0.78),
    'strcat': ('CWE-121', 0.72),
    'sprintf': ('CWE-121', 0.72),
    'vsprintf': ('CWE-121', 0.72),
    'strncpy': ('CWE-121', 0.60),
}

# 显式长度原语: 长度可静态判为常量且 <= 声明大小时过滤, 否则记低置信候选。
_LENGTH_WRITE = ('memcpy', 'memmove', 'read', 'recv', 'recvfrom', 'fread')

# 用户可控来源标记, 命中提升置信度。
_TAINT_SRC = re.compile(
    r'\b(read|recv|recvfrom|recvmsg|fgets|scanf|gets|argv|getenv|fread)\s*\(')


def _buffer_decls(code: str) -> Dict[str, int]:
    """提取栈数组声明: 返回 {数组名: 声明大小(常量)或 -1(非常量)}."""
    buffers = {}
    # 形如: char name[64] / char name[n] / int buf[SIZE]
    pat = re.compile(
        r'\b(?:unsigned\s+)?(?:char|int|short|long|float|double|uint8_t|size_t)'
        r'\s+(\w+)\s*\[\s*([^\]]+?)\s*\]')
    for m in pat.finditer(code):
        name, size = m.group(1).strip(), m.group(2).strip()
        if name in buffers:
            continue
        if re.fullmatch(r'\d+', size):
            buffers[name] = int(size)
        else:
            buffers[name] = -1
    return buffers


def detect_stack_overflow_code(code: str, func_name: str = "",
                               include_len_write: bool = True) -> List[Dict]:
    """对单函数伪代码做栈溢出规则检测。

    参数:
        code: 反编译伪代码(或 C 源码)文本。
        func_name: 函数名, 写回 finding 的 function 字段。
        include_len_write: 是否纳入 memcpy/read 等显式长度原语判定, 默认开启。

    返回 finding 列表; 每条含
    {type, rule_id, function, target, line, severity, cwe,
     confidence, verdict, description, evidence}。
    """
    findings: List[Dict] = []
    buffers = _buffer_decls(code)
    if not buffers:
        return findings

    taint_src = _TAINT_SRC.search(code) is not None

    for lineno, raw in enumerate(code.split('\n'), 1):
        line = raw.strip()
        if not line or line.startswith('//'):
            continue

        for buf, size in buffers.items():
            if not re.search(rf'\b{buf}\b', line):
                continue
            flagged = False

            # 无界写原语
            for fname, (cwe, conf) in _UNBOUNDED_WRITE.items():
                if re.search(rf'\b{fname}\s*\(\s*(?:&)?{buf}\s*[,)]', line):
                    findings.append(_mk_stack_finding(
                        func_name, buf, lineno, fname, size,
                        cwe=cwe,
                        confidence=min(1.0, conf + (0.10 if taint_src else 0.0))))
                    flagged = True
                    break

            if not flagged and include_len_write:
                _check_len_write(line, buf, size, taint_src, func_name,
                                 lineno, findings)
    return findings


def _mk_stack_finding(func_name, buf, lineno, fname, size,
                      cwe, confidence) -> Dict:
    size_note = f"声明确认 {size} 字节" if size > 0 else "声明大小非常量"
    return {
        "type": "stack-overflow",
        "rule_id": f"SO-{fname.upper()}",
        "function": func_name,
        "target": buf,
        "line": lineno,
        "severity": "High" if confidence >= 0.75 else "Medium",
        "cwe": cwe,
        "confidence": round(confidence, 3),
        "verdict": "POSSIBLE",
        "description": (
            f"{fname} 写入疑似栈缓冲区 {buf} (L{lineno}), {size_note}, "
            f"伪代码级无法证明写入长度不越界"),
        "evidence": f"{fname}({buf}, ...) @ L{lineno}",
    }


def _check_len_write(line, buf, size, taint_src, func_name, lineno,
                     findings) -> bool:
    """检测 memcpy/read 等显式长度写: 长度常量且 <= 声明大小时忽略, 否则候选。"""
    for fname in _LENGTH_WRITE:
        m = re.search(rf'\b{fname}\s*\([^)]*\b{buf}\b[^,)]*,\s*[^,)]*,\s*([^,)]+)\)', line)
        if not m:
            continue
        length = m.group(1).strip()
        # 常量长度且已有声明大小: 可判定安全则跳过
        if re.fullmatch(r'\d+', length):
            n = int(length)
            if size > 0 and n <= size:
                return False
            conf = 0.55  # 常量但超过声明大小, 明确越界
        else:
            conf = 0.50  # 非常量长度, 源可控则略提权
            if taint_src:
                conf += 0.08
        findings.append(_mk_stack_finding(
            func_name, buf, lineno, fname, size,
            cwe="CWE-121", confidence=conf))
        return True
    return False


def analyze_stack_batch(code_map: Dict[str, str],
                        include_len_write: bool = True) -> Dict[str, List[Dict]]:
    """批量入口: {函数名: 伪代码} → {函数名: findings}。"""
    return {
        name: detect_stack_overflow_code(code, name, include_len_write)
        for name, code in code_map.items()
    }


__all__ = ["detect_stack_overflow_code", "analyze_stack_batch"]
