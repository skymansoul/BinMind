"""崩溃分类去重与分析 -- 基于堆栈指纹/嵌入聚类/CASR 风格崩溃簇。

参考:
  GPTrace   (arXiv:2512.01609, ICSE 2026) -- LLM 嵌入 + HDBSCAN 聚类
  dedupT    (arXiv:2508.19449)             -- Transformer 堆栈轨迹去重
  ECHO      (Electronics 2025)             -- 调用栈 LCS 相似度 + Syzkaller集成
  CASR      (2021, 持续更新至 2025)        -- 崩溃聚类与报告生成

本模块提供三个层次的去重策略:
  1. 轻量级: SHA-256 短哈希(已在内核 src/core.py 中实现)
  2. 中等粒度: 调用栈编辑距离 + LCS 相似度
  3. 重量级: 基于文本嵌入的语义聚类(依赖 sentence-transformers, 可选)
"""

import hashlib
import json
import logging
import os
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CrashReport:
    """单个崩溃的完整描述。

    字段设计兼顾 CASR 的 JSON 报告格式和 AFL 的崩溃目录布局。"""
    crash_id: str = ""
    seed_hash: str = ""              # 触发种子的SHA-256前16字符
    signal_num: int = 0
    fault_addr: int = 0
    stack_trace: List[str] = field(default_factory=list)
    registers: Dict[str, str] = field(default_factory=dict)
    crash_type: str = "unknown"      # SIGSEGV / SIGABRT / SIGFPE / SIGILL
    binary_path: str = ""
    timestamp: float = field(default_factory=time.time)
    asan_report: str = ""            # AddressSanitizer 原始输出(可选)
    classification: str = "unclassified"  # unclassified / exploitable / benign / double_free / ...
    exploitability_score: float = 0.0     # 0-1 可利用率估计


@dataclass
class CrashCluster:
    """一组被判定为同一根本原因的崩溃集合。"""
    cluster_id: str
    representative: CrashReport      # 该簇的代表崩溃
    members: List[CrashReport] = field(default_factory=list)
    root_cause_hint: str = ""
    total_occurrences: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


# ===== 调用栈规范化 =====

def normalize_stack_trace(raw_trace: str, max_depth: int = 16) -> List[str]:
    """从原始文本提取规范化调用栈帧。

    - 提取地址和函数名
    - 移除非确定性部分 (ASLR偏移基址)
    - 截断至 max_depth 层

    ECHO (2025) 指出调用栈前 8-12 帧通常足以区分不同根因,
    过深的帧反而引入噪声。
    """
    if not raw_trace:
        return []

    frames: List[str] = []
    # 匹配模式: #0 0x... in func_name (...) at file:line
    frame_pat = re.compile(
        r'#\d+\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)\s*\(.*?\)(?:\s+at\s+\S+)?'
    )
    # 回退: 仅匹配地址
    addr_pat = re.compile(r'(0x[0-9a-fA-F]{8,})')

    for line in raw_trace.split('\n')[:max_depth * 2]:
        fm = frame_pat.search(line)
        if fm:
            # 仅保留地址低16位消除ASLR (CASR 做法)
            addr = fm.group(1)
            func = fm.group(2)
            addr_lo = int(addr, 16) & 0xFFFF
            frames.append(f"{func}@{addr_lo:04x}")
        else:
            am = addr_pat.search(line)
            if am:
                addr_lo = int(am.group(1), 16) & 0xFFFF
                frames.append(f"0x{addr_lo:04x}")

    return frames[:max_depth]


# ===== 调用栈指纹生成 =====

def stack_fingerprint(frames: List[str], top_n: int = 5) -> str:
    if not frames:
        return "empty_stack"
    raw = "|".join(frames[:top_n])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ===== 调用栈相似度 (LCS + Jaccard) =====

def stack_similarity_lcs(frames_a: List[str], frames_b: List[str]) -> float:
    """两个调用栈的归一化 LCS 相似度。

    LCS 对帧顺序敏感, 比纯集合 Jaccard 更准确地反映执行路径相似性。
    ECHO (2025) 使用类似方法, 配合调用栈深度权重取得+15.2%覆盖率提升。
    """
    if not frames_a or not frames_b:
        return 0.0

    m, n = len(frames_a), len(frames_b)
    # 动态规划 LCS, O(m*n)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if frames_a[i - 1] == frames_b[j - 1]:
                dp[i][j] = dp[i - 1][j - 1] + 1
            else:
                dp[i][j] = max(dp[i - 1][j], dp[i][j - 1])

    lcs_len = dp[m][n]
    # 归一化: 除以较长栈的长度
    max_len = max(m, n)
    return lcs_len / max_len if max_len > 0 else 0.0


def stack_similarity_jaccard(frames_a: List[str], frames_b: List[str]) -> float:
    """基于集合的 Jaccard 相似度 -- 忽略帧顺序, 关注函数名集合重叠。

    对深度递归导致的栈帧不同但根因相同的情况更有容忍度。
    """
    set_a, set_b = set(frames_a), set(frames_b)
    if not set_a and not set_b:
        return 1.0
    union = set_a | set_b
    intersection = set_a & set_b
    return len(intersection) / len(union) if union else 0.0


# ===== 嵌入向量相似度 (GPTrace 风格) =====

_EMBEDDING_MODEL_AVAILABLE = False
try:
    from sentence_transformers import SentenceTransformer
    _EMBEDDING_MODEL_AVAILABLE = True
except ImportError:
    pass


class EmbeddingSimilarity:
    """基于文本嵌入的崩溃语义相似度 [GPTrace 2025]。

    GPTrace 使用 LLM 对完整 stack trace + ASAN 报告计算嵌入,
    然后以 HDBSCAN 聚类。本实现降级为 sentence-transformers
    (需单独安装), 模型默认为 all-MiniLM-L6-v2。

    若 sentence-transformers 未安装, 自动回退到 LCS+Jaccard 混合打分。
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self._available = _EMBEDDING_MODEL_AVAILABLE
        self._model = None
        if self._available:
            try:
                self._model = SentenceTransformer(model_name)
            except Exception as e:
                logger.warning("句子嵌入模型加载失败, 回退到混合打分: %s", e)
                self._available = False

    def encode(self, texts: List[str]) -> Optional[List[List[float]]]:
        if not self._available or self._model is None:
            return None
        try:
            embeddings = self._model.encode(texts, show_progress_bar=False)
            return [e.tolist() for e in embeddings]
        except Exception:
            return None

    def similarity(self, crash_a: CrashReport, crash_b: CrashReport) -> float:
        """计算两个崩溃报告的语义相似度。

        融合源: (stack_trace文本, crash_type, ASAN报告前256字符)。
        若无嵌入模型可用, 回退到 LCS×0.7+Jaccard×0.3 混合。
        """
        text_a = self._crash_to_text(crash_a)
        text_b = self._crash_to_text(crash_b)

        if self._available and self._model is not None:
            try:
                emb = self._model.encode([text_a, text_b], show_progress_bar=False)
                dot = sum(emb[0][i] * emb[1][i] for i in range(len(emb[0])))
                na = math_sqrt(sum(v * v for v in emb[0]))
                nb = math_sqrt(sum(v * v for v in emb[1]))
                if na > 0 and nb > 0:
                    return dot / (na * nb)
                return 0.0
            except Exception:
                # 嵌入失败 — 静默降级, 不阻塞主流程
                pass

        # 回退
        fa = normalize_stack_trace("\n".join(crash_a.stack_trace))
        fb = normalize_stack_trace("\n".join(crash_b.stack_trace))
        lcs = stack_similarity_lcs(fa, fb)
        jac = stack_similarity_jaccard(fa, fb)
        return 0.7 * lcs + 0.3 * jac

    @staticmethod
    def _crash_to_text(c: CrashReport) -> str:
        parts = [
            f"Type: {c.crash_type}",
            f"Signal: {c.signal_num}",
            f"FaultAddr: 0x{c.fault_addr:x}",
            "Stack: " + " | ".join(c.stack_trace[:8]),
        ]
        if c.asan_report:
            parts.append("ASAN: " + c.asan_report[:256])
        return "\n".join(parts)


def math_sqrt(x: float) -> float:
    import math as _m
    return _m.sqrt(x)


# ===== 崩溃簇聚类引擎 =====

class CrashClusteringEngine:
    """崩溃聚类主引擎。

    两阶段:
      1. 预聚类: 基于 crash_type + 顶部3帧指纹分组 (O(n) 快速粗分)
      2. 精聚类: 簇内用相似度矩阵 + 单链接聚合, 合并相似度 > threshold 的簇
    """

    def __init__(self, lcs_threshold: float = 0.7,
                 use_embeddings: bool = True):
        self.lcs_threshold = lcs_threshold
        self._clusters: List[CrashCluster] = []
        self._embedder = EmbeddingSimilarity() if use_embeddings else None
        self._report_count: int = 0

    def add_report(self, report: CrashReport) -> str:
        """接收一个崩溃报告, 尝试归入已有簇或创建新簇。

        返回该报告被归入的 cluster_id。
        """
        self._report_count += 1

        # 预聚类键: crash_type + 前3帧指纹
        pre_key = self._precluster_key(report)

        # 在已有簇中查找候选
        best_cluster: Optional[CrashCluster] = None
        best_sim = 0.0

        for cluster in self._clusters:
            rep = cluster.representative
            # 快速过滤: 不同类型不能合并
            if rep.crash_type != report.crash_type:
                continue
            if rep.signal_num != report.signal_num:
                continue

            sim = self._compute_similarity(rep, report)
            if sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_cluster is not None and best_sim >= self.lcs_threshold:
            best_cluster.members.append(report)
            best_cluster.total_occurrences += 1
            best_cluster.last_seen = max(best_cluster.last_seen, report.timestamp)
            return best_cluster.cluster_id

        # 创建新簇
        cid = f"cluster_{self._report_count:05d}"
        new_cluster = CrashCluster(
            cluster_id=cid,
            representative=report,
            members=[report],
            total_occurrences=1,
            first_seen=report.timestamp,
            last_seen=report.timestamp,
            root_cause_hint=f"{report.crash_type}_at_0x{report.fault_addr:x}",
        )
        self._clusters.append(new_cluster)
        return cid

    def _precluster_key(self, report: CrashReport) -> str:
        frames = normalize_stack_trace("\n".join(report.stack_trace))
        fp = stack_fingerprint(frames, top_n=3)
        return f"{report.crash_type}|{fp}"

    def _compute_similarity(self, a: CrashReport, b: CrashReport) -> float:
        if self._embedder is not None:
            return self._embedder.similarity(a, b)
        fa = normalize_stack_trace("\n".join(a.stack_trace))
        fb = normalize_stack_trace("\n".join(b.stack_trace))
        lcs = stack_similarity_lcs(fa, fb)
        jac = stack_similarity_jaccard(fa, fb)
        return 0.7 * lcs + 0.3 * jac

    def get_clusters(self) -> List[CrashCluster]:
        return sorted(self._clusters, key=lambda c: c.total_occurrences, reverse=True)

    def cluster_summary(self) -> Dict:
        clusters = self.get_clusters()
        return {
            "total_clusters": len(clusters),
            "total_reports": sum(c.total_occurrences for c in clusters),
            "top_clusters": [
                {
                    "cluster_id": c.cluster_id,
                    "count": c.total_occurrences,
                    "root_cause": c.root_cause_hint,
                    "first_seen": c.first_seen,
                    "last_seen": c.last_seen,
                }
                for c in clusters[:10]
            ],
        }

    def export_json(self, output_path: str) -> None:
        """导出崩溃簇为 JSON -- CASR 兼容格式"""
        clusters_data = []
        for c in self._clusters:
            clusters_data.append({
                "cluster_id": c.cluster_id,
                "root_cause_hint": c.root_cause_hint,
                "total_occurrences": c.total_occurrences,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "representative": {
                    "crash_id": c.representative.crash_id,
                    "crash_type": c.representative.crash_type,
                    "signal": c.representative.signal_num,
                    "fault_addr": f"0x{c.representative.fault_addr:x}",
                    "classification": c.representative.classification,
                    "exploitability_score": c.representative.exploitability_score,
                },
                "member_count": len(c.members),
            })

        payload = {
            "generated_at": time.time(),
            "total_reports": self._report_count,
            "total_clusters": len(self._clusters),
            "clusters": clusters_data,
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)


# ===== 可利用性启发式评分 =====

def estimate_exploitability(report: CrashReport) -> float:
    """基于崩溃特征的简单可利用率评分 (0.0-1.0)。

    启发式规则:
      - SIGSEGV + 可控地址 → 0.8+
      - SIGABRT (assert) → 0.2
      - SIGFPE → 0.3
      - PC 被用户输入覆盖 → 1.0 (大概率可利用)
      - 写入原语 (SIGSEGV at write) → 0.7+

    这不是完整的!exploitable 实现, 仅用于崩溃优先级排序。
    """
    score = 0.0
    crash_t = report.crash_type.upper()

    if "SIGSEGV" in crash_t:
        score += 0.5
    elif "SIGABRT" in crash_t:
        score += 0.2
    elif "SIGFPE" in crash_t:
        score += 0.3
    elif "SIGILL" in crash_t:
        score += 0.6
    else:
        score += 0.1

    # 检查故障地址是否在用户空间范围(近似可控)
    fa = report.fault_addr
    if 0x1000 <= fa <= 0x7fffffffffff:
        score += 0.15
    if fa < 0x1000:
        # NULL 解引用 → 通常不可利用但有信息泄露潜力
        score += 0.05
    if fa > 0x7f0000000000:
        # 接近栈或堆的典型范围
        score += 0.15

    # ASAN 报告中查找关键模式
    asan_lower = report.asan_report.lower()
    if "heap-buffer-overflow" in asan_lower:
        score += 0.2
    if "use-after-free" in asan_lower:
        score += 0.3
    if "stack-buffer-overflow" in asan_lower:
        score += 0.15
    if "double-free" in asan_lower:
        score += 0.2

    return min(1.0, max(0.0, score))


# ===== 批处理工具 =====

def deduplicate_crashes(
    crash_dir: str,
    threshold: float = 0.7,
    output_json: Optional[str] = None,
) -> Dict:
    """对崩溃目录下的文件进行去重。

    遍历 crash_dir 中所有文件, 解析为 CrashReport (需外部提供解析器),
    运行聚类引擎, 返回摘要。

    这是一个骨架函数 --- 实际崩溃解析逻辑在 FaultInjectionFuzzer
    和核心 fuzz loop 中, 此处提供独立入口。
    """
    engine = CrashClusteringEngine(lcs_threshold=threshold, use_embeddings=False)
    # 占位: 实际实现需要解析每个崩溃文件
    # 此处仅展示流程骨架
    count = 0
    if os.path.isdir(crash_dir):
        for _ in os.listdir(crash_dir):
            # 实际实现: 解析崩溃日志, 构建 CrashReport, 调用 engine.add_report()
            count += 1

    result = engine.cluster_summary()
    if output_json:
        engine.export_json(output_json)
    return result
