# features.py：可解释特征提取（Interpretable Feature Extraction）
#
# 对应论文:
# Beyond Embeddings: Interpretable Feature Extraction for Binary Code
#   Similarity - [待验证]
#
# 设计意图:
# 端到端嵌入(embedding)是黑盒-它能给出相似度分数，却无法回答"为何相似"
#   本模块在反编译伪代码文本上提取结构化语义特征:
# (1) 调用模式 call patterns - 被调函数集合 + 实参个数分布
# (2) 常量统计 constants - 整型/十六进制常量的量级与位宽分布
# (3) CFG 形态 cfg morphology - 控制块类型分布、嵌套深度、圈复杂度
# (4) 字符串引用 string refs - 字符串字面量及其语义分类
# 这些特征既可向量化供下游 ANN 排序，又可序列化为 JSON 供人工审计
# 从而把"相似性判定"从不可解释的分数降级为可审计的证据链
#
# 边界条件:
#   反编译输出是编译器生成的 C 近似，含类型转换、指针运算与库调用；
#   解析采用保守的正则 + 可选的结构化伪代码提升，任何解析失败均回退为
# 空特征而非抛异常，保证审计流水线不中断

import hashlib
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 伪代码解析中需要排除的"伪调用"：控制流关键字与类型关键字
# 这些 token 后面紧跟 '('，但不是函数调用
_CALL_EXCLUDE = frozenset({
    'if', 'else', 'while', 'for', 'switch', 'case', 'return', 'sizeof',
    'do', 'goto', 'continue', 'break', 'int', 'char', 'void', 'long',
    'short', 'unsigned', 'signed', 'float', 'double', 'const', 'static',
    'struct', 'union', 'enum', 'typedef', 'default', 'restrict',
})

_CALL_RE = re.compile(r'\b([A-Za-z_]\w*)\s*\(')
_HEX_INT_RE = re.compile(r'0[xX][0-9a-fA-F]+')
_DEC_INT_RE = re.compile(r'(?<![0-9a-fA-FxX])(?:-)?\b\d+\b')
_STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_FORMAT_SPEC_RE = re.compile(r'%[-+ #0-9.*]*[diouxXeEfgGcspn%]')
_URL_RE = re.compile(r'[a-zA-Z][a-zA-Z0-9+.-]*://|www\.')
_PATH_RE = re.compile(r'^[A-Za-z]:[\\/]|^/|\.(so|dll|dylib|exe|ini|conf|log|txt)$', re.IGNORECASE)

# 各语义维度的相似度权重；设计上允许外部配置覆盖(见 InterpretableSimilarity)
_DEFAULT_WEIGHTS: Dict[str, float] = {
    'calls': 0.30,
    'constants': 0.25,
    'cfg': 0.25,
    'strings': 0.20,
}


@dataclass
class CallPattern:
    """单个调用点的模式：被调函数名与实参个数"""
    callee: str
    arg_count: int = 0
    call_count: int = 1


@dataclass
class ConstantStats:
    """常量统计：按位宽分桶，辅助识别 magic number 与哨兵值

    value_hist 记录常量具体值（去重后的字符串形式）→ 出现次数
    使相似性对"具体魔数"敏感而非仅对位宽敏感；小常量在代码中
    常见（循环步长、布尔旗标），位宽直方图会把它们坍缩到同一桶
    需要值级直方图补充判别力
    """
    hex_count: int = 0
    dec_count: int = 0
    bit_width_hist: Dict[str, int] = field(default_factory=dict)
    value_hist: Dict[str, int] = field(default_factory=dict)
    sentinel_values: List[int] = field(default_factory=list)
    magnitude_sum: float = 0.0


@dataclass
class StringRef:
    """字符串引用：字面量、长度与语义分类"""
    literal: str
    length: int
    categories: List[str] = field(default_factory=list)


@dataclass
class CfgMorphology:
    """CFG 形态：控制块类型分布、最大嵌套深度、圈复杂度近似"""
    block_type_hist: Dict[str, int] = field(default_factory=dict)
    max_nesting_depth: int = 0
    cyclomatic_complexity: int = 1
    branch_factor: float = 0.0


@dataclass
class FunctionFeature:
    """一个函数/二进制片段的结构化语义特征集合"""
    function_name: str = ''
    call_patterns: List[CallPattern] = field(default_factory=list)
    constant_stats: ConstantStats = field(default_factory=ConstantStats)
    cfg_morphology: CfgMorphology = field(default_factory=CfgMorphology)
    string_refs: List[StringRef] = field(default_factory=list)
    source_hash: str = ''          # 原文的确定性指纹，用于去重

    # 序列化：人工审计入口。返回完全 JSON 可序列化的字典
    def to_dict(self) -> Dict[str, Any]:
        return {
            'function_name': self.function_name,
            'source_hash': self.source_hash,
            'calls': [{
                'callee': p.callee,
                'arg_count': p.arg_count,
                'call_count': p.call_count,
            } for p in sorted(self.call_patterns, key=lambda x: x.callee)],
            'constants': {
                'hex_count': self.constant_stats.hex_count,
                'dec_count': self.constant_stats.dec_count,
                'bit_width_hist': dict(self.constant_stats.bit_width_hist),
                'value_hist': dict(self.constant_stats.value_hist),
                'sentinel_values': sorted(self.constant_stats.sentinel_values)[:32],
            },
            'cfg': {
                'block_type_hist': dict(self.cfg_morphology.block_type_hist),
                'max_nesting_depth': self.cfg_morphology.max_nesting_depth,
                'cyclomatic_complexity': self.cfg_morphology.cyclomatic_complexity,
                'branch_factor': round(self.cfg_morphology.branch_factor, 4),
            },
            'strings': [{
                'literal': s.literal[:256],
                'length': s.length,
                'categories': s.categories,
            } for s in self.string_refs[:64]],
        }

    # 稠密嵌入：固定 64 维，供 ANNIndex / 聚类等下游数值算法使用
    # 维度划分为 4 组各 16 维，分别对应四类语义特征的有损哈希桶
    def to_vector(self, dim: int = 64) -> List[float]:
        if dim % 4 != 0:
            dim = 64
        bucket = dim // 4
        vec = [0.0] * dim

        # 调用模式：被调函数名哈希到桶
        for p in self.call_patterns:
            idx = int(hashlib.md5(p.callee.encode()).hexdigest(), 16) % bucket
            vec[idx] += p.call_count

        # 常量统计：具体值哈希到桶（魔数敏感）；无值直方图时退化为位宽桶
        if self.constant_stats.value_hist:
            for val, cnt in self.constant_stats.value_hist.items():
                idx = int(hashlib.md5(val.encode()).hexdigest(), 16) % bucket
                vec[bucket + idx] += cnt
        else:
            total_const = sum(self.constant_stats.bit_width_hist.values()) or 1.0
            for width, cnt in self.constant_stats.bit_width_hist.items():
                width_key = int(width) if str(width).isdigit() else 0
                idx = (width_key % bucket)
                vec[bucket + idx] += cnt / total_const

        # 字符串引用：语义分类哈希到桶
        for s in self.string_refs:
            cat = '|'.join(s.categories) if s.categories else 'plain'
            idx = int(hashlib.md5(cat.encode()).hexdigest(), 16) % bucket
            vec[bucket * 2 + idx] += 1.0

        # CFG 形态：块类型分布哈希到桶
        for bt, cnt in self.cfg_morphology.block_type_hist.items():
            idx = int(hashlib.md5(bt.encode()).hexdigest(), 16) % bucket
            vec[bucket * 3 + idx] += cnt

        # L2 归一化，保持尺度可比
        norm = sum(x * x for x in vec) ** 0.5 or 1.0
        return [x / norm for x in vec]


class FeatureExtractor:
    """从反编译伪代码文本中提取 FunctionFeature

    算法依据:
    调用模式/常量/字符串引用经正则扫描伪代码文本；
    CFG 形态优先使用 structured_pseudocode 模块的结构化提升结果
    (块类型、嵌套深度)，失败时回退为关键字启发式
    """

    def extract(self, pseudocode: Optional[str], function_name: str = '') -> FunctionFeature:
        code = pseudocode or ''
        feats = FunctionFeature(function_name=function_name)
        feats.source_hash = hashlib.sha256(code.encode(errors='replace')).hexdigest()[:16]
        if not code.strip():
            return feats

        feats.call_patterns = self._extract_calls(code, function_name)
        feats.constant_stats = self._extract_constants(code)
        feats.cfg_morphology = self._extract_cfg(code, function_name)
        feats.string_refs = self._extract_strings(code)
        return feats

    # 调用模式：捕获 "name(" 并统计实参顶层逗号个数
    # 排除控制流/类型关键字与函数自身(定义头)
    def _extract_calls(self, code: str, function_name: str) -> List[CallPattern]:
        counter: Dict[str, List[int]] = {}
        # 移除函数定义头行，避免把 "void foo(int a)" 当作调用
        stripped = self._strip_signature_line(code, function_name)
        for m in _CALL_RE.finditer(stripped):
            callee = m.group(1)
            if callee in _CALL_EXCLUDE or callee == function_name:
                continue
            arg_text = self._match_parens(stripped, m.end() - 1)
            arg_count = self._count_top_level_commas(arg_text)
            entry = counter.setdefault(callee, [0, 0])
            entry[0] += 1
            entry[1] = arg_count  # 记录最后一次观察的实参个数
        return [CallPattern(callee=c, call_count=n, arg_count=a)
                for c, (n, a) in counter.items()]

    def _extract_constants(self, code: str) -> ConstantStats:
        stats = ConstantStats()
        hexes = _HEX_INT_RE.findall(code)
        # 排除 0/1：二者是循环计数器与布尔旗标的样板常量，含它们会稀释判别力
        decs = [d for d in _DEC_INT_RE.findall(code)
                if d not in ('0', '1')]
        stats.hex_count = len(hexes)
        stats.dec_count = len(decs)
        width_counter: Counter[int] = Counter()
        value_counter: Counter[str] = Counter()
        for tok in hexes:
            width = max(1, (len(tok) - 2) * 4)   # 每字节 4 bit
            width_counter[width] += 1
            val = int(tok, 16)
            stats.magnitude_sum += abs(val)
            value_counter[str(val)] += 1
            if val in (0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF,
                       0x8000000000000000, 0x41414141):
                stats.sentinel_values.append(val)
        for tok in decs:
            try:
                val = int(tok, 10)
            except ValueError:
                continue
            width = max(1, val.bit_length())
            width_counter[width] += 1
            stats.magnitude_sum += abs(val)
            value_counter[str(val)] += 1
        stats.value_hist = dict(value_counter.most_common(64))
        # 聚合到位宽分桶 8/16/32/64
        for w, cnt in width_counter.items():
            if w <= 8:
                bucket = '8'
            elif w <= 16:
                bucket = '16'
            elif w <= 32:
                bucket = '32'
            else:
                bucket = '64'
            stats.bit_width_hist[bucket] = stats.bit_width_hist.get(bucket, 0) + cnt
        return stats

    def _extract_strings(self, code: str) -> List[StringRef]:
        refs: List[StringRef] = []
        for m in _STRING_RE.finditer(code):
            raw = m.group(1)
            literal = bytes(raw, 'utf-8', errors='replace').decode(
                'unicode_escape', errors='replace')
            cats: List[str] = []
            if _FORMAT_SPEC_RE.search(literal):
                cats.append('format_string')
            if _URL_RE.search(literal):
                cats.append('url')
            if _PATH_RE.search(literal):
                cats.append('path')
            if not cats:
                cats.append('plain')
            refs.append(StringRef(literal=literal, length=len(literal), categories=cats))
        return refs

    def _extract_cfg(self, code: str, function_name: str) -> CfgMorphology:
        # 优先使用结构化伪代码提升，获得精确块类型分布与嵌套深度
        try:
            from modules.analysis.decompiler.structured_pseudocode import (
                generate_structured_pseudocode,
            )
            sp = generate_structured_pseudocode(code, function_name)
            blocks: List[Any] = []
            stack: List[Any] = [sp.root_block] if sp.root_block else []
            while stack:
                b = stack.pop()
                if b is None:
                    continue
                blocks.append(b)
                stack.extend(b.children or [])
            hist: Dict[str, int] = Counter()
            for b in blocks:
                bt = getattr(b, 'block_type', None)
                bt = getattr(bt, 'value', None) or str(bt) or 'block'
                hist[bt] += 1
            depth = max((getattr(b, 'indent_level', 0) or 0) for b in blocks) if blocks else 0
            decision_count = sum(hist.get(k, 0) for k in
                                 ('if', 'while', 'for', 'switch', 'case', 'do_while'))
            # 结构化提升可能因伪代码格式差异退化为单根块(无任何决策块)
            # 此时若原文含控制流关键字，则改用关键字启发式以保持判别力
            if decision_count == 0 and len(blocks) <= 1:
                if any(re.search(r'\b' + kw + r'\b', code)
                       for kw in ('if', 'while', 'for', 'switch', 'case')):
                    logger.debug("结构化伪代码退化，回退关键字启发式 CFG")
                    return self._extract_cfg_heuristic(code)
            return CfgMorphology(
                block_type_hist=dict(hist),
                max_nesting_depth=depth,
                cyclomatic_complexity=1 + decision_count,
                branch_factor=round(decision_count / max(1, len(blocks)), 4),
            )
        except Exception as e:  # noqa: BLE001 - 回退路径，不影响主流水线
            logger.debug("structured_pseudocode 不可用，回退关键字启发式: %s", e)
            return self._extract_cfg_heuristic(code)

    def _extract_cfg_heuristic(self, code: str) -> CfgMorphology:
        """关键字启发式 CFG 提取：无结构化提升依赖时的降级路径"""
        hist: Dict[str, int] = {}
        for kw in ('if', 'else', 'while', 'for', 'switch', 'case', 'do'):
            hist[kw] = len(re.findall(r'\b' + kw + r'\b', code))
        max_depth = 0
        depth = 0
        for ch in code:
            if ch == '{':
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == '}':
                depth = max(0, depth - 1)
        decision_count = sum(hist[k] for k in ('if', 'while', 'for', 'switch', 'case'))
        return CfgMorphology(
            block_type_hist=hist,
            max_nesting_depth=max_depth,
            cyclomatic_complexity=1 + decision_count,
            branch_factor=round(decision_count / max(1, len(re.findall(r';', code))), 4),
        )

    # 文本工具
    @staticmethod
    def _strip_signature_line(code: str, function_name: str) -> str:
        """移除函数定义头行，它看起来像调用 'name(.)'"""
        lines = code.splitlines()
        if lines:
            first = lines[0]
            if function_name and re.search(r'\b' + re.escape(function_name) + r'\s*\(', first):
                return '\n'.join(lines[1:])
        return code

    @staticmethod
    def _match_parens(text: str, open_idx: int) -> str:
        """从 '(' 位置向后匹配平衡括号，返回括号内的文本"""
        depth = 0
        i = open_idx
        while i < len(text):
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    return text[open_idx + 1:i]
            i += 1
        return ''

    @staticmethod
    def _count_top_level_commas(text: str) -> int:
        """统计顶层逗号数（跳过嵌套括号/字符串），加一为实参个数"""
        if not text.strip():
            return 0
        depth = 0
        in_str = False
        count = 0
        for ch in text:
            if in_str:
                if ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == '(':
                depth += 1
            elif ch == ')':
                depth = max(0, depth - 1)
            elif ch == ',' and depth == 0:
                count += 1
        return count + 1


class SimilarityReport:
    """可解释相似性报告：总体分数 + 各维度分数 + 审计解释"""

    def __init__(self, overall: float, dim_scores: Dict[str, float],
                 audit: Dict[str, List[str]], weights: Dict[str, float]):
        self.overall = overall
        self.dim_scores = dim_scores
        self.audit = audit
        self.weights = weights

    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_similarity': round(self.overall, 4),
            'dimension_scores': {k: round(v, 4) for k, v in self.dim_scores.items()},
            'weights': self.weights,
            'audit': self.audit,
        }


class InterpretableSimilarity:
    """可解释相似性判定

    对应论文: Beyond Embeddings
    差异点: 论文端到端黑盒嵌入；本实现叠加结构化特征，逐维度给出
    可审计的相似度证据，供安全分析人员复核而非盲信分数
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = {**_DEFAULT_WEIGHTS, **(weights or {})}

    def compare(self, fa: FunctionFeature, fb: FunctionFeature) -> SimilarityReport:
        scores = {
            'calls': self._calls_sim(fa, fb),
            'constants': self._constants_sim(fa, fb),
            'cfg': self._cfg_sim(fa, fb),
            'strings': self._strings_sim(fa, fb),
        }
        audit = {
            'calls': self._audit_calls(fa, fb),
            'constants': self._audit_constants(fa, fb),
            'cfg': self._audit_cfg(fa, fb),
            'strings': self._audit_strings(fa, fb),
        }
        total = sum(self.weights.get(k, 0.0) * v for k, v in scores.items())
        weight_sum = sum(self.weights.get(k, 0.0) for k in scores)
        overall = total / max(1e-9, weight_sum)
        return SimilarityReport(overall, scores, audit, dict(self.weights))

    # 各维度相似度
    @staticmethod
    def _calls_sim(fa: FunctionFeature, fb: FunctionFeature) -> float:
        set_a = {p.callee for p in fa.call_patterns}
        set_b = {p.callee for p in fb.call_patterns}
        if not set_a and not set_b:
            return 1.0
        inter = len(set_a & set_b)
        union = len(set_a | set_b)
        return inter / max(1, union)

    @staticmethod
    def _constants_sim(fa: FunctionFeature, fb: FunctionFeature) -> float:
        ha = fa.constant_stats.bit_width_hist
        hb = fb.constant_stats.bit_width_hist
        if not ha and not hb and not fa.constant_stats.value_hist \
                and not fb.constant_stats.value_hist:
            return 1.0
        width_sim = InterpretableSimilarity._hist_cosine(ha, hb) \
            if (ha or hb) else 1.0
        va = set(fa.constant_stats.value_hist)
        vb = set(fb.constant_stats.value_hist)
        if not va and not vb:
            value_sim = 1.0
        else:
            value_sim = len(va & vb) / max(1, len(va | vb))
        # 值级 Jaccard 更能区分具体魔数；位宽余弦用于无值直方图的退化输入
        return 0.6 * value_sim + 0.4 * width_sim

    @staticmethod
    def _cfg_sim(fa: FunctionFeature, fb: FunctionFeature) -> float:
        ha = fa.cfg_morphology.block_type_hist
        hb = fb.cfg_morphology.block_type_hist
        hist_sim = InterpretableSimilarity._hist_cosine(ha, hb) if (ha or hb) else 1.0
        depth_sim = 1.0 - abs(fa.cfg_morphology.max_nesting_depth -
                              fb.cfg_morphology.max_nesting_depth) / 16.0
        return 0.6 * hist_sim + 0.4 * max(0.0, depth_sim)

    @staticmethod
    def _strings_sim(fa: FunctionFeature, fb: FunctionFeature) -> float:
        set_a = {s.literal for s in fa.string_refs}
        set_b = {s.literal for s in fb.string_refs}
        if not set_a and not set_b:
            return 1.0
        inter = len(set_a & set_b)
        union = len(set_a | set_b)
        return inter / max(1, union)

    @staticmethod
    def _hist_cosine(ha: Dict[str, int], hb: Dict[str, int]) -> float:
        keys = set(ha) | set(hb)
        if not keys:
            return 1.0
        dot = sum(ha.get(k, 0) * hb.get(k, 0) for k in keys)
        na = sum(v * v for v in ha.values()) ** 0.5
        nb = sum(v * v for v in hb.values()) ** 0.5
        if na == 0 or nb == 0:
            return 0.0
        return dot / (na * nb)

    # 审计解释：把分数翻译为人类可读的差异描述
    @staticmethod
    def _audit_calls(fa: FunctionFeature, fb: FunctionFeature) -> List[str]:
        set_a = {p.callee for p in fa.call_patterns}
        set_b = {p.callee for p in fb.call_patterns}
        only_a = sorted(set_a - set_b)
        only_b = sorted(set_b - set_a)
        common = sorted(set_a & set_b)
        lines = [f"共同被调函数 {len(common)} 个: {common[:8]}"]
        if only_a:
            lines.append(f"A 独有调用: {only_a[:8]}")
        if only_b:
            lines.append(f"B 独有调用: {only_b[:8]}")
        return lines

    @staticmethod
    def _audit_constants(fa: FunctionFeature, fb: FunctionFeature) -> List[str]:
        ha = fa.constant_stats.bit_width_hist
        hb = fb.constant_stats.bit_width_hist
        lines = [f"A 位宽分布 {dict(ha)}，B 位宽分布 {dict(hb)}"]
        va = set(fa.constant_stats.value_hist)
        vb = set(fb.constant_stats.value_hist)
        if va or vb:
            lines.append(f"A 魔数值 {sorted(va)[:8]}，B 魔数值 {sorted(vb)[:8]}")
        if ha.get('64') or hb.get('64'):
            lines.append("存在 64 位常量-可能是地址/指针或大整数")
        return lines

    @staticmethod
    def _audit_cfg(fa: FunctionFeature, fb: FunctionFeature) -> List[str]:
        return [
            f"A 圈复杂度 {fa.cfg_morphology.cyclomatic_complexity}，"
            f"B 圈复杂度 {fb.cfg_morphology.cyclomatic_complexity}",
            f"A 最大嵌套 {fa.cfg_morphology.max_nesting_depth}，"
            f"B 最大嵌套 {fb.cfg_morphology.max_nesting_depth}",
        ]

    @staticmethod
    def _audit_strings(fa: FunctionFeature, fb: FunctionFeature) -> List[str]:
        set_a = {s.literal for s in fa.string_refs}
        set_b = {s.literal for s in fb.string_refs}
        return [
            f"共同字符串引用 {len(set_a & set_b)} 个",
            f"A 独有 {len(set_a - set_b)} 个，B 独有 {len(set_b - set_a)} 个",
        ]


__all__ = [
    'CallPattern',
    'ConstantStats',
    'StringRef',
    'CfgMorphology',
    'FunctionFeature',
    'FeatureExtractor',
    'SimilarityReport',
    'InterpretableSimilarity',
]
