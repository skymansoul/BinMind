# 多特征融合注意力评分器——文本特征与CPG结构特征加权融合，
# 以注意力权重实现可解释漏洞打分。
#
# 对应论文CodeSAGE 以代码属性图为输入，
# 用注意力机制融合多种特征表达。本模块实现其简化可运行版本——
# 文本n-gram哈希嵌入+CPG结构统计，softmax注意力分配组间权重。
#
# 设计意图:
# 纯文本嵌入难以捕捉跨函数数据流；结构特征(圈复杂度、sink可达性、
#     DFG路径长度)提供互补证据。
# 注意力权重=组间证据强度归一化，使最终分数可解释。
# numpy可选：缺失时退化为纯Python向量运算，保证无外部依赖可运行。

import logging
import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:
    import numpy as _np
    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False

# 危险关键字表——文本特征的风险先验
_RISK_KEYWORDS: Dict[str, float] = {
    "strcpy": 0.9, "strcat": 0.9, "sprintf": 0.9, "gets": 0.95, "system": 0.9,
    "memcpy": 0.6, "strncpy": 0.4, "snprintf": 0.2, "scanf": 0.5, "popen": 0.85,
    "execve": 0.8, "free": 0.35, "malloc": 0.3, "realloc": 0.35, "alloca": 0.5,
    "read": 0.25, "recv": 0.3, "send": 0.2, "printf": 0.3,
}

_EMBED_DIM = 256          # 哈希嵌入维度
_NGRAM = 3                # 字符n-gram阶数


@dataclass
class TextFeatures:
    """文本层特征。"""
    length: int
    token_count: int
    identifier_count: int
    numeric_constant_count: int
    comment_lines: int
    risk_keyword_density: float             # 危险关键字出现频次密度
    risk_keyword_score: float               # 加权风险先验(0..1)
    has_pointer_arith: bool                 # 指针/下标运算指示
    strict_inequality_count: int = 0        # 严格不等式(>/<)计数——边界感知
    embedding: Optional[List[float]] = None


@dataclass
class StructureFeatures:
    """CPG结构层特征。"""
    node_count: int
    edge_count: int
    function_count: int
    branch_count: int
    sink_count: int
    max_cyclomatic: float
    dfg_path_count: int
    dfg_path_avg_len: float
    cf_path_count: int
    sink_reachable: bool


@dataclass
class FusionResult:
    """融合打分结果——含可解释注意力权重。"""
    fused_score: float
    attention_weights: Dict[str, float]     # {"text": w, "structure": w}
    text_score: float
    structure_score: float
    feature_importance: Dict[str, float]
    model_used: str = "multi_feature_fusion"


def _hash_ngrams(text: str, dim: int = _EMBED_DIM, n: int = _NGRAM) -> List[int]:
    """字符n-gram哈希词袋向量——纯Python实现。

    算法依据:
      特征哈希 将无穷n-gram空间映射到固定
      维度，避免显式词典；符号哈希抵消偶发冲突偏差。
    """
    vec = [0] * dim
    text_l = text.lower()
    for i in range(len(text_l) - n + 1):
        gram = text_l[i:i + n]
        h = hash(gram) % (2 ** 31)
        idx = h % dim
        sign = 1 if (h >> 15) & 1 else -1
        vec[idx] += sign
    return vec


def _dot(a: Sequence[float], b: Sequence[float]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _l2(a: Sequence[float]) -> float:
    return math.sqrt(sum(x * x for x in a))


def extract_text_features(code: str) -> TextFeatures:
    """从源码文本提取文本层特征。"""
    code = code or ""
    length = len(code)
    tokens = re.findall(r'[A-Za-z_]\w*', code)
    identifiers = [t for t in tokens if t not in _RISK_KEYWORDS]
    nums = re.findall(r'\b[0-9]+\b', code)
    comment_lines = sum(1 for line in code.splitlines()
                        if line.strip().startswith(("//", "#")))
    risk_hits = [t for t in tokens if t in _RISK_KEYWORDS]
    density = len(risk_hits) / max(len(tokens), 1)
    risk_score = sum(_RISK_KEYWORDS.get(t, 0.0) for t in risk_hits)
    risk_score = min(1.0, risk_score)
    pointer_arith = bool(re.search(r'\b[a-z_]\w*\s*\[\s*[^\]]+\]', code)
                         or re.search(r'\b[a-z_]\w*\s*\+\+\s*\b', code))
    strict_ineq = len(re.findall(r'[<>](?!=)', code))
    emb = _hash_ngrams(code)
    return TextFeatures(
        length=length, token_count=len(tokens),
        identifier_count=len(identifiers),
        numeric_constant_count=len(nums),
        comment_lines=comment_lines,
        risk_keyword_density=round(density, 4),
        risk_keyword_score=round(risk_score, 4),
        has_pointer_arith=pointer_arith,
        strict_inequality_count=strict_ineq,
        embedding=emb)


def extract_structure_features(cpg: Any,
                               function_names: Optional[Sequence[str]] = None,
                               max_cyclomatic: int = 1) -> StructureFeatures:
    """从CPG提取结构层特征。

    边界条件:
      cpg为None或不可用时返回全零结构特征，融合退化为纯文本打分。
    """
    if cpg is None:
        return StructureFeatures(0, 0, 0, 0, 0, 0.0, 0, 0.0, 0, False)

    stats = cpg.stats() if hasattr(cpg, "stats") else {}
    node_count = int(stats.get("nodes", 0))
    edge_count = int(stats.get("edges", 0))
    fn_count = int(stats.get("functions", 0))
    sink_count = int(stats.get("sink_count", 0))

    branch_count = 0
    max_cyc = 0.0
    dfg_paths = 0
    dfg_path_len_sum = 0.0
    cf_paths = 0
    sink_reachable = sink_count > 0

    fn_ids: List[int] = []
    if function_names:
        fn_ids = [cpg.functions[n] for n in function_names if n in cpg.functions]
    else:
        fn_ids = [fid for fid in cpg.function_ids()
                  if not cpg.node(fid).attrs.get("is_external")]

    from modules.vuln.detection.cpg_path_serializer import (
        extract_control_paths, extract_dataflow_paths)

    for fid in fn_ids:
        descendants = []
        stack = [fid]
        seen = {fid}
        while stack:
            cur = stack.pop()
            descendants.append(cur)
            for e in cpg.out_edges(cur):
                if e.kind.value == "ast" and e.dst not in seen:
                    seen.add(e.dst)
                    stack.append(e.dst)
        branch_count += sum(1 for nid in descendants
                            if cpg.node(nid).kind.value == "branch")
        if hasattr(cpg, "cyclomatic_complexity"):
            max_cyc = max(max_cyc, float(cpg.cyclomatic_complexity(fid)))
        dp = extract_dataflow_paths(cpg, fid)
        dfg_paths += len(dp)
        dfg_path_len_sum += sum(len(p) for p in dp)
        cf_paths += len(extract_control_paths(cpg, fid))

    dfg_path_avg = dfg_path_len_sum / max(dfg_paths, 1)
    return StructureFeatures(
        node_count=node_count, edge_count=edge_count,
        function_count=fn_count, branch_count=branch_count,
        sink_count=sink_count,
        max_cyclomatic=round(max_cyc, 3),
        dfg_path_count=dfg_paths,
        dfg_path_avg_len=round(dfg_path_avg, 3),
        cf_path_count=cf_paths,
        sink_reachable=sink_reachable)


def text_risk_score(code: str) -> float:
    """纯文本风险分(0..1)——供无LLM/无CPG场景的兜底。

    边界感知:
      严格不等式(>/<)数量作为弱边界检查指示——使反事实边界偏移扰动
      能反映到文本分数上。
    """
    tf = extract_text_features(code)
    if tf.length == 0:
        return 0.0
    score = tf.risk_keyword_score * 0.7 + tf.risk_keyword_density * 2.0
    score = min(1.0, score)
    # 指针运算与数组索引小幅加成
    if tf.has_pointer_arith:
        score = min(1.0, score + 0.05)
    # 严格不等式作弱边界指示
    score = min(1.0, score + min(0.08, tf.strict_inequality_count * 0.02))
    return round(score, 4)


def structural_risk_score(cpg: Any,
                          function_names: Optional[Sequence[str]] = None) -> float:
    """CPG结构风险先验(0..1)。

    算法依据:
      sink可达(0.5)+圈复杂度正则项+DFG路径证据——借鉴CodeSAGE
      以图结构统计作为漏洞先验的思路。
    """
    sf = extract_structure_features(cpg, function_names)
    if sf.node_count == 0:
        return 0.0
    score = 0.0
    if sf.sink_reachable:
        score += 0.5
    score += min(1.0, sf.max_cyclomatic / 10.0) * 0.25
    score += min(1.0, sf.dfg_path_count / 5.0) * 0.15
    score += min(1.0, sf.branch_count / 6.0) * 0.10
    return round(min(1.0, score), 4)


def _softmax(values: List[float]) -> List[float]:
    """数值稳定softmax——减最大值防溢出。"""
    if not values:
        return []
    m = max(values)
    exps = [math.exp(v - m) for v in values]
    total = sum(exps)
    if total <= 0:
        return [1.0 / len(values)] * len(values)
    return [e / total for e in exps]


class FeatureAttentionFuser:
    """多特征融合注意力融合器。

    设计意图:
      将文本特征证据强度与结构特征证据强度各自映射为注意力分数，
      经softmax得组间权重，再加权合成最终分数——注意力权重即解释性
      (CodeSAGE注意力融合机制)。
    """

    def __init__(self, text_weight_bias: float = 0.55,
                 struct_bias: float = 0.45):
        self._text_bias = text_weight_bias      # 文本组先验权重
        self._struct_bias = struct_bias         # 结构组先验权重

    def _text_attention(self, tf: TextFeatures, text_score: float) -> float:
        """文本组注意力分数——证据强度与文本风险分正相关。"""
        if tf.length == 0:
            return 0.0
        evidence = (tf.risk_keyword_score * 0.5
                    + text_score * 0.3
                    + min(1.0, tf.token_count / 200.0) * 0.2)
        return evidence

    def _struct_attention(self, sf: StructureFeatures, struct_score: float) -> float:
        """结构组注意力分数——sink可达与图规模主导。"""
        if sf.node_count == 0:
            return 0.0
        evidence = (struct_score * 0.6
                    + min(1.0, sf.sink_count / 3.0) * 0.3
                    + min(1.0, sf.dfg_path_count / 4.0) * 0.1)
        return evidence

    def fuse(self, text_score: float, structure_score: float,
             text_features: Optional[TextFeatures] = None,
             structure_features: Optional[StructureFeatures] = None,
             confidence: Optional[float] = None) -> FusionResult:
        """融合打分。

        注意力计算: 先验权重+证据强度->softmax->组间权重。
        confidence为外部信号(如LLM自报置信度)时，对融合分做保守缩放
        ——高置信外部证据可信时放大，否则向0.5中值收缩。
        """
        tf = text_features or extract_text_features("")
        sf = structure_features or extract_structure_features(None)

        t_att = self._text_attention(tf, text_score)
        s_att = self._struct_attention(sf, structure_score)

        # 先验权重混合证据强度
        raw_t = self._text_bias * 0.5 + t_att * 0.5
        raw_s = self._struct_bias * 0.5 + s_att * 0.5
        w_text, w_struct = _softmax([raw_t, raw_s])

        fused = w_text * text_score + w_struct * structure_score
        if confidence is not None:
            # 置信调制: conf>0.5时向两端拉伸，否则向中值收缩
            fused = 0.5 + (fused - 0.5) * (0.4 + 0.6 * max(0.0, min(1.0, confidence)))

        importance = {
            "risk_keyword_score": tf.risk_keyword_score,
            "risk_keyword_density": tf.risk_keyword_density,
            "token_count": tf.token_count,
            "sink_count": sf.sink_count,
            "max_cyclomatic": sf.max_cyclomatic,
            "dfg_path_count": sf.dfg_path_count,
            "sink_reachable": float(sf.sink_reachable),
        }
        return FusionResult(
            fused_score=round(min(1.0, max(0.0, fused)), 4),
            attention_weights={"text": round(w_text, 4),
                               "structure": round(w_struct, 4)},
            text_score=round(text_score, 4),
            structure_score=round(structure_score, 4),
            feature_importance=importance)


def text_similarity(code_a: str, code_b: str) -> float:
    """文本嵌入余弦相似度——用于反事实变体的语义近似判断。

    算法依据:
      哈希嵌入向量化后取余弦；numpy可用时走向量化路径，否则纯Python。
    """
    va, vb = _hash_ngrams(code_a), _hash_ngrams(code_b)
    if _HAS_NUMPY:
        na, nb = _np.array(va, dtype=_np.float64), _np.array(vb, dtype=_np.float64)
        denom = (float(_np.linalg.norm(na)) * float(_np.linalg.norm(nb)))
        if denom <= 0:
            return 0.0
        return round(float(float(na @ nb) / denom), 4)
    denom = _l2(va) * _l2(vb)
    if denom <= 0:
        return 0.0
    return round(_dot(va, vb) / denom, 4)


def fuse_detection_scores(text_score: float, structure_score: float,
                          text_features: Optional[TextFeatures] = None,
                          structure_features: Optional[StructureFeatures] = None
                          ) -> FusionResult:
    """便捷函数——融合文本与结构风险分。"""
    return FeatureAttentionFuser().fuse(
        text_score, structure_score, text_features, structure_features)


def analyze_cpg_risk(cpg: Any, source_text: str = "",
                     function_names: Optional[Sequence[str]] = None) -> FusionResult:
    """端到端结构+文本风险分析——无需LLM的纯统计路径。"""
    text_score = text_risk_score(source_text)
    struct_score = structural_risk_score(cpg, function_names)
    tf = extract_text_features(source_text) if source_text else None
    sf = extract_structure_features(cpg, function_names)
    return FeatureAttentionFuser().fuse(text_score, struct_score, tf, sf)
