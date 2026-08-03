"""
依赖图构建与污点传播路径追踪。

设计意图 (对应CRYPTBARA, ASE 2025的依赖上下文思想):
  密钥误用判定不能只看模式命中点本身 — 硬编码密钥/IV/盐是否为真误用取决于它
  在数据流中的角色: 是否从密钥生成点(SOURCE)出发、经变换(TRANSFORM)、抵达加密
  调用点(SINK)。本模块在二进制层面以"API字符串共现+偏移邻近"近似数据流,
  构建有向依赖图, 并以BFS最短路径输出从密钥生成点到加密调用点的调用链摘要。

边界条件:
  - 不做完整符号执行; 节点以文件偏移为坐标, 边表示偏移邻近的启发式数据流。
  - 命中点无邻近上下文时路径为空, 由上层启发式按低置信度处理。
  - 大文件依赖窗口受限, 边数受link_dist与最大连接数约束, 避免路径爆炸。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class NodeType(str, Enum):
    """依赖图节点类别 — 数据流角色分类."""
    SOURCE = 'source'        # 密钥生成/加载API (RAND_bytes, EVP_BytesToKey...)
    TRANSFORM = 'transform'  # 密钥变换/拷贝API (memcpy, key schedule...)
    CONSTANT = 'constant'    # 硬编码候选常量 (模式命中锚点)
    SINK = 'sink'            # 加密初始化/更新调用API (EVP_EncryptInit...)


# ── API目录 ──
# 依据CRYPTBARA的依赖上下文分类: 密钥生成点(source)/变换(transform)/
# 加密调用点(sink)。字符串匹配一律小写前缀/子串, 兼容大小写混淆与符号修饰。

KEY_GEN_APIS: Tuple[str, ...] = (
    'rand_bytes', 'rand_priv_bytes', 'rand_pseudo_bytes',
    'evp_bytes_to_key', 'evp_pkey_new', 'evp_pkey_ctx_new',
    'pkcs5_pbkdf2_hmac', 'pkcs5_pbkdf2',
    'bcryptgenrandom', 'cryptgenrandom', 'cryptgenkey',
    'keygenerator', 'newsecure.random', 'new_secure_random',
    'sodium_randombytes', 'randombytes_buf', 'randombytes',
    'os.urandom', 'secrets.token_bytes', 'newrandom',
    'getrandom', 'arc4random',
)

KEY_LOAD_APIS: Tuple[str, ...] = (
    'secretkeyspec', 'secretkeyfactory', 'readkey', 'loadkey',
    'evp_readkey', 'pem_read', 'd2i_privatekey', 'd2i_pubkey',
    'importkey', 'setkey', 'set_key', 'derivekey', 'derive_key',
    'keyfromdata', 'key_from_data',
)

TRANSFORM_APIS: Tuple[str, ...] = (
    'memcpy', 'memmove', 'copymemory', 'movememory',
    'expandkey', 'key_schedule', 'aes_set_key', 'aes_key_setup',
    'schedule_key', 'round_keys', 'xor', 'transform',
)

CIPHER_INIT_APIS: Tuple[str, ...] = (
    'evp_encryptinit', 'evp_decryptinit', 'evp_cipherinit',
    'evp_encryptinit_ex', 'evp_decryptinit_ex', 'evp_cipherinit_ex',
    'aes_set_encrypt_key', 'aes_set_decrypt_key',
    'bcryptencrypt', 'bcryptdecrypt', 'cryptencrypt', 'cryptdecrypt',
    'cipher.getinstance', 'cipher.init', 'cipher_do',
    'aes/ecb', 'aes/cbc', 'aes/ctr', 'aes/gcm', 'des/ecb', 'des/cbc',
    'aes_encrypt', 'aes_decrypt', 'des_encrypt', 'des_decrypt',
    'gcm_init', 'chacha20_init', 'chacha_encrypt',
    'crypto_secretbox_easy', 'crypto_box_easy', 'crypto_aead_encrypt',
    'crypto_aead_decrypt', 'encrypt', 'decrypt', 'cccrypt',
)

CIPHER_UPDATE_APIS: Tuple[str, ...] = (
    'evp_encryptupdate', 'evp_encryptfinal', 'evp_decryptupdate',
    'evp_decryptfinal', 'evp_cipherupdate', 'evp_cipherfinal',
    'cipher.dofinal', 'cipher.update', 'crypt_update', 'crypt_final',
)


def classify_api(text: str) -> Optional[NodeType]:
    """将API字符串分类为依赖图节点类型; 无法识别返回None.

    匹配顺序: 密钥生成/加载→SOURCE, 加密初始化/更新→SINK,
    变换→TRANSFORM。同一字符串命中多类时按上述优先级取首个类别。
    """
    if not text:
        return None
    low = text.lower()
    if any(pat in low for pat in KEY_GEN_APIS) or any(pat in low for pat in KEY_LOAD_APIS):
        return NodeType.SOURCE
    if any(pat in low for pat in CIPHER_INIT_APIS) or any(pat in low for pat in CIPHER_UPDATE_APIS):
        return NodeType.SINK
    if any(pat in low for pat in TRANSFORM_APIS):
        return NodeType.TRANSFORM
    return None


@dataclass
class GraphNode:
    """依赖图节点 — 某个偏移处的某个数据流角色."""
    node_id: int
    offset: int
    node_type: NodeType
    label: str
    api: str = ""
    category: str = ""       # 误用类别 (STATIC_IV / WEAK_KEY / ...)
    severity: str = ""
    confidence: float = 0.0


@dataclass
class GraphEdge:
    """有向边 — 低偏移→高偏移, 近似正向数据流."""
    src: int
    dst: int
    flow: str = 'neighborhood'


@dataclass
class TaintPath:
    """从密钥生成点到加密调用点途经命中锚点的有序节点序列."""
    nodes: List[GraphNode] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        for n in self.nodes:
            if n.node_type == NodeType.CONSTANT:
                parts.append("[{}@{}]".format(n.label, hex(n.offset)))
            else:
                api = n.api or n.label
                parts.append("{}@{}".format(api, hex(n.offset)))
        return " → ".join(parts)


class DependencyGraph:
    """有向依赖图: 邻接表存储, BFS最短路径追踪."""

    def __init__(self) -> None:
        self.nodes: Dict[int, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._adj: Dict[int, List[int]] = {}
        self._next_id = 0

    def add_node(self, node: GraphNode) -> int:
        self.nodes[node.node_id] = node
        self._adj.setdefault(node.node_id, [])
        return node.node_id

    def new_node(self, offset: int, node_type: NodeType, label: str,
                 **kw) -> int:
        """创建节点并返回整数id — 与add_edge(src, dst)的id语义一致."""
        nid = self._next_id
        self._next_id += 1
        node = GraphNode(node_id=nid, offset=offset, node_type=node_type,
                         label=label, **kw)
        self.add_node(node)
        return nid

    def add_edge(self, src: int, dst: int, flow: str = 'neighborhood') -> None:
        if src == dst:
            return
        if dst in self._adj.get(src, []):
            return
        self.edges.append(GraphEdge(src, dst, flow))
        self._adj.setdefault(src, []).append(dst)

    def out_neighbors(self, node_id: int) -> List[int]:
        return list(self._adj.get(node_id, []))

    def nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def shortest_path(self, src_ids: List[int], dst_ids: List[int],
                      blocked: Optional[int] = None) -> List[int]:
        """BFS求src_ids中任意节点到dst_ids中任意节点的最短路径.

        设计意图: BFS保证最短跳数; blocked用于分段搜索时排除重复节点,
        保证上游路径+锚点+下游路径三段串联不重叠。
        """
        if not src_ids or not dst_ids:
            return []
        target = set(dst_ids)
        visited = set()
        prev: Dict[int, int] = {}
        from collections import deque
        dq = deque()
        for s in src_ids:
            if blocked is not None and s == blocked:
                continue
            visited.add(s)
            dq.append(s)
        found = None
        while dq:
            cur = dq.popleft()
            if cur in target:
                found = cur
                break
            for nxt in self.out_neighbors(cur):
                if blocked is not None and nxt == blocked:
                    continue
                if nxt not in visited:
                    visited.add(nxt)
                    prev[nxt] = cur
                    dq.append(nxt)
        if found is None:
            return []
        path = [found]
        while path[-1] in prev:
            path.append(prev[path[-1]])
        path.reverse()
        return path


def build_dependency_graph(
    data: bytes,
    strings: List[Tuple[int, str]],
    misuses,
    window: int = 4096,
    link_dist: int = 2048,
    max_links: int = 8,
) -> Tuple[DependencyGraph, List[Optional[int]]]:
    """从模式命中列表构建依赖图.

    参数:
      data:      二进制原始字节
      strings:   [(偏移, 可打印字符串)]列表
      misuses:  crypto_misuse.Misuse可迭代对象
      window:   锚点邻近窗口 (字节)
      link_dist: 建边最大间距 (字节)
      max_links: 每个节点向后连接节点数上限

    返回:
      (graph, anchor_ids) — anchor_ids与misuses逐位对齐, 聚合命中(地址=0)
      对应锚点id为None。
    """
    graph = DependencyGraph()
    anchor_ids: List[Optional[int]] = []

    # 1. 模式命中 → 常量锚点节点
    for mu in misuses:
        try:
            off = int(mu.address, 16)
        except (ValueError, TypeError):
            off = -1
        if off <= 0:
            anchor_ids.append(None)
            continue
        nid = graph.new_node(
            off, NodeType.CONSTANT, mu.type,
            api=mu.api, category=mu.type, severity=mu.severity)
        anchor_ids.append(nid)

    # 2. API字符串 → 源/变换/汇节点
    for off, text in strings:
        nt = classify_api(text)
        if nt is not None:
            graph.new_node(off, nt, text, api=text.split('(')[0][:60])

    # 3. 按偏移排序后建链式边 (低偏移 → 高偏移)
    ordered = sorted(graph.nodes.values(), key=lambda n: (n.offset, n.node_id))
    n = len(ordered)
    for i in range(n):
        cur = ordered[i]
        hops = 0
        for j in range(i + 1, n):
            nxt = ordered[j]
            if nxt.offset - cur.offset > link_dist:
                break
            graph.add_edge(cur.node_id, nxt.node_id, 'neighborhood')
            hops += 1
            if hops >= max_links:
                break

    return graph, anchor_ids


def trace_dependency_paths(
    graph: DependencyGraph,
    anchor_id: int,
    max_nodes: int = 8,
) -> TaintPath:
    """追踪经过锚点的完整依赖路径.

    设计意图: 分两段BFS —
      (a) 从上游SOURCE/TRANSFORM节点到锚点 (密钥来源侧);
      (b) 从锚点到下游SINK/TRANSFORM节点 (加密使用侧)。
    两段串联即调用链摘要; 任一侧缺失时保留已找到的半段。
    """
    anchor = graph.nodes.get(anchor_id)
    if anchor is None:
        return TaintPath()

    upstream_src = [n.node_id for n in graph.nodes_by_type(NodeType.SOURCE)]
    upstream_tr  = [n.node_id for n in graph.nodes_by_type(NodeType.TRANSFORM)]
    downstream_sink = [n.node_id for n in graph.nodes_by_type(NodeType.SINK)]
    downstream_tr   = [n.node_id for n in graph.nodes_by_type(NodeType.TRANSFORM)]

    up_ids = graph.shortest_path(upstream_src + upstream_tr, [anchor_id])
    down_ids = graph.shortest_path([anchor_id], downstream_sink + downstream_tr)

    path_nodes: List[GraphNode] = []
    for nid in up_ids[:-1]:            # 排除锚点自身 (up_ids末端即锚点)
        if nid == anchor_id:
            continue
        if len(path_nodes) >= max_nodes // 2:
            break
        path_nodes.append(graph.nodes[nid])
    path_nodes.append(anchor)
    for nid in down_ids[1:]:           # 排除锚点自身 (down_ids首端即锚点)
        if nid == anchor_id:
            continue
        if len(path_nodes) >= max_nodes:
            break
        path_nodes.append(graph.nodes[nid])
    return TaintPath(nodes=path_nodes)


def summarize_call_chain(path: TaintPath) -> str:
    """输出可读调用链摘要 — CRYPTBARA依赖上下文的文本化表示."""
    if not path.nodes:
        return ""
    return path.summary()
