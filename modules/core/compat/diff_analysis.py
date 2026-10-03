import os as _os, sys as _sys, functools as _ft
_d = _os.path.dirname(_os.path.dirname(_os.path.dirname(__file__)))
_sys.path.insert(0, _os.path.join(_d, 'binary_analysis'))
_diff = __import__('diff_analysis')
_sys.path.pop(0)
globals().update({k: getattr(_diff, k) for k in dir(_diff) if not k.startswith('_')})

# 扩展差分分析 — 指令级、基本块级、结构级三层粒度
import hashlib as _hl

_TRACE_FLAGS = 0b1101_0010


_IMM_RE = __import__('re').compile(r'(0x[0-9a-fA-F]+|[-+]?\d+)')

@_ft.lru_cache(maxsize=512)
def _cached_normalize_insn(mnemonic: str, operands: str) -> str:
    return f"{mnemonic} {_IMM_RE.sub('IMM', operands)}"


def _normalize_insn(mnemonic: str, operands: str) -> str:
    return _cached_normalize_insn(mnemonic, operands)


def basic_block_hash(instructions: list[tuple[str, str]]) -> str:
    normalized = ';'.join(_normalize_insn(m, o) for m, o in instructions)
    return _hl.sha256(normalized.encode()).hexdigest()[:16]


def function_similarity(bb_hashes_a: set, bb_hashes_b: set) -> float:
    if not bb_hashes_a and not bb_hashes_b:
        return 1.0
    if not bb_hashes_a or not bb_hashes_b:
        return 0.0
    inter = bb_hashes_a & bb_hashes_b
    union = bb_hashes_a | bb_hashes_b
    return len(inter) / len(union)


def structural_similarity(cfg_a: dict, cfg_b: dict) -> float:
    edges_a = cfg_a.get('edges', 0) if isinstance(cfg_a, dict) else 0
    edges_b = cfg_b.get('edges', 0) if isinstance(cfg_b, dict) else 0
    nodes_a = cfg_a.get('nodes', 0) if isinstance(cfg_a, dict) else 0
    nodes_b = cfg_b.get('nodes', 0) if isinstance(cfg_b, dict) else 0
    if nodes_a == 0 and nodes_b == 0:
        return 1.0
    max_nodes = max(nodes_a, nodes_b)
    max_edges = max(edges_a, edges_b)
    if max_nodes == 0:
        return 0.0
    node_diff = abs(nodes_a - nodes_b) / max_nodes
    edge_diff = abs(edges_a - edges_b) / max(max_edges, 1)
    raw = 1.0 - (0.4 * node_diff + 0.6 * edge_diff)
    return max(0.0, min(1.0, raw))


# 指令级编辑距离
def instruction_edit_distance(seq_a: list[str], seq_b: list[str]) -> tuple[int, list]:
    m, n = len(seq_a), len(seq_b)
    if m == 0:
        return (n, [('ins', i, seq_b[i]) for i in range(n)])
    if n == 0:
        return (m, [('del', i, seq_a[i]) for i in range(m)])

    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    j = 0
    while j <= n:
        dp[0][j] = j
        j += 1

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq_a[i - 1] == seq_b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1]
            else:
                dp[i][j] = 1 + min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])

    # 回溯 — 从 dp[m][n] 反向构建操作序列
    ops = []
    i, j = m, n
    while i > 0 or j > 0:
        if i > 0 and j > 0 and seq_a[i - 1] == seq_b[j - 1]:
            i -= 1; j -= 1
        elif i > 0 and j > 0 and dp[i][j] == dp[i - 1][j - 1] + 1:
            ops.append(('sub', i - 1, f'{seq_a[i-1]}→{seq_b[j-1]}'))
            i -= 1; j -= 1
        elif i > 0 and dp[i][j] == dp[i - 1][j] + 1:
            ops.append(('del', i - 1, seq_a[i - 1]))
            i -= 1
        else:
            ops.append(('ins', j - 1, seq_b[j - 1]))
            j -= 1
    ops.reverse()
    return (dp[m][n], ops)



def _debug_print(*a, **kw):
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*a, **kw)

