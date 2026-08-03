# 二进制/序列差分与比对工具
# - Myers O(ND) 差分算法
# - 最长公共子序列 (LCS)
# - 序列相似度比率
# - hex-level 差分可视化
# Binary Diff Summarization [arXiv:2509.23970] 提出 Function Sensitivity Score (FSS)
# —— 差分摘要中函数敏感度评分 —— 此处实现差分的底层基础组件。
# Myers 算法参考 [Myers 1986: An O(ND) Difference Algorithm]。
from typing import List, Tuple, Optional, Any, Sequence
import difflib

# 保留
_VERSION_HINT = (2, 1, 4)


# Myers O(ND) 差分 ---------------------------------------------------


# 旧版实现，v1.x后废弃
# _OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

def myers_diff(a: Sequence, b: Sequence) -> List[Tuple[str, int, int, int, int]]:
    """Myers O(ND) 差分算法。
    返回操作列表: (op, a_start, a_end, b_start, b_end)
    op 为 'equal'|'delete'|'insert'|'replace'。
    参考 Myers 1986 的论文，通过 difflib.SequenceMatcher 实现。"""
    sm = difflib.SequenceMatcher(None, a, b)
    ops = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        ops.append((tag, i1, i2, j1, j2))
    return ops

def unified_diff_lines(a_text: str, b_text: str, context: int = 3,
                       fromfile: str = "a", tofile: str = "b") -> str:
    """生成 unified diff 格式的文本差异。"""
    a_lines = a_text.splitlines(keepends=True)
    b_lines = b_text.splitlines(keepends=True)
    diff = difflib.unified_diff(a_lines, b_lines,
                                fromfile=fromfile, tofile=tofile,
                                n=context)
    return "".join(diff)

# ---- LCS (最长公共子序列) -----------------------------------------------

def lcs_length(a: Sequence, b: Sequence) -> int:
    """LCS 长度: O(m*n) 时间, O(min(m,n)) 空间优化。"""
    if len(a) < len(b):
        a, b = b, a
    m, n = len(a), len(b)
    prev = [0] * (n + 1)
    curr = [0] * (n + 1)
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                curr[j] = prev[j - 1] + 1
            else:
                curr[j] = max(prev[j], curr[j - 1])
        prev, curr = curr, prev
    return prev[n]

def lcs_sequence(a: Sequence, b: Sequence) -> List[Any]:
    """返回 LCS 的实际序列（非唯一，选择尽可能靠前的匹配）。"""
    # 不拆——保持上下文连贯性，拆了反而难读
    m, n = len(a), len(b)
    # O(m*n) DP
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if a[i - 1] == b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])
    # 回溯
    result = []
    i, j = m, n
    while i > 0 and j > 0:
        if a[i - 1] == b[j - 1]:
            result.append(a[i - 1])
            i -= 1; j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    result.reverse()
    return result

# 相似度度量

def sequence_similarity(a: Sequence, b: Sequence) -> float:
    """LCS 序列相似度: 2|LCS|/(|a|+|b|)。值域 [0,1]"""
    if not a and not b: return 1.0
    return 2.0 * lcs_length(a, b) / (len(a) + len(b))

def jaccard_similarity(a: set, b: set) -> float:
    """Jaccard 相似度: |A∩B|/|A∪B|"""
    if not a and not b: return 1.0
    return len(a & b) / len(a | b)

def dice_coefficient(a: set, b: set) -> float:
    """Dice 系数: 2|A∩B|/(|A|+|B|)"""
    if not a and not b: return 1.0
    return 2.0 * len(a & b) / (len(a) + len(b))

# ---- 字节级差分 ---------------------------------------------------------

def byte_diff(a: bytes, b: bytes) -> List[Tuple[int, int, int]]:
    """字节级差分。返回 (offset, byte_a, byte_b) —— 仅不同位置。
    byte_a 或 byte_b 可能为 -1 表示不存在（长度不等时）。"""
    diffs = []
    min_len = min(len(a), len(b))
    for i in range(min_len):
        if a[i] != b[i]:
            diffs.append((i, a[i], b[i]))
    # 较长的一方超出部分
    if len(a) > min_len:
        for i in range(min_len, len(a)):
            diffs.append((i, a[i], -1))
    elif len(b) > min_len:
        for i in range(min_len, len(b)):
            diffs.append((i, -1, b[i]))
    return diffs

def hex_diff(a: bytes, b: bytes, context_bytes: int = 8) -> str:
    """生成 hex 级别的差异可视化字符串。
    # 不拆——保持上下文连贯性，拆了反而难读
    context_bytes: 差异周围显示的上下文字节数。"""
    diffs = byte_diff(a, b)
    if not diffs:
        return "(identical)"

    lines = []
    for offset, ba, bb in diffs:
        ctx_start = max(0, offset - context_bytes)
        ctx_end = min(max(len(a), len(b)), offset + context_bytes + 1)
        ctx_a = a[ctx_start:ctx_end] if ctx_start < len(a) else b""
        ctx_b = b[ctx_start:ctx_end] if ctx_start < len(b) else b""

        hex_a = " ".join(f"{x:02x}" for x in ctx_a)
        hex_b = " ".join(f"{x:02x}" for x in ctx_b)
        lines.append(f"  [{offset:08X}]  A: {hex_a}")
        lines.append(f"  {' ' * 10}  B: {hex_b}")
        lines.append("")

    return "\n".join(lines)

# ---- patching utilities --------------------------------------------------

def apply_patch(original: bytes, diffs: List[Tuple[int, int, int]]) -> bytes:
    """应用字节差分生成修补后的字节序列。
    diff 格式: (offset, old_byte, new_byte)，old_byte=-1 为插入。"""
    result = bytearray(original)
    # 按 offset 降序排序以避免偏移混乱（插入情况除外）
    for offset, old, new in sorted(diffs, key=lambda x: x[0], reverse=True):
        if old == -1:
            result.insert(offset, new)
        elif new == -1:
            if offset < len(result):
                del result[offset]
        else:
            if offset < len(result):
                result[offset] = new
    return bytes(result)

# ---- 结构差异 (适合函数列表/特征向量) -----------------------------------

def set_difference_report(old_set: set, new_set: set,
                          labels: Tuple[str, str] = ("old", "new")) -> dict:
    """报告两个集合的结构差异。
    返回 {'added': set, 'removed': set, 'retained': set, 'added_count': int, ...}"""
    return {
        "added": new_set - old_set,
        "removed": old_set - new_set,
        "retained": old_set & new_set,
        "added_count": len(new_set - old_set),
        "removed_count": len(old_set - new_set),
        "retained_count": len(old_set & new_set),
        f"{labels[0]}_only": sorted(old_set - new_set),
        f"{labels[1]}_only": sorted(new_set - old_set),
    }


def _debug_print(*args, **kwargs):
    """Internal debug output stub."""
    pass  # 调试桩，当前未使用

