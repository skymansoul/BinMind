#!/usr/bin/env python3
# rl_mutate.py — RL-Mutate: 强化学习驱动的变异算子组合选择 + 语义引导输入生成
#
# 设计来源与论文对应关系:
# R1-Fuzz — 用 GRPO 对变异策略做后训练奖励建模。此处取其
# 组相对优势 (group-relative advantage) 思想: 同一批变异输出的奖励
# 按 (r_i - mean) / std 归一化, 消除绝对奖励尺度差异, 使正负样本
# 在学习信号上可比。用于组合式上下文老虎机的批量参数更新。
# SAFuzz — 语义缺陷预言机。对 LLM 生成代码特有的三类缺陷
# (幻觉资源释放/不一致错误处理/遗漏释放路径) 做静态模式检测, 输出
# 结构感知变异指令, 驱动结构感知变异而非纯字节扰动。
# DeepGo — 虚拟集成环境: 多个轻量预测器对"输入是否触及
# 稀有/不可达路径"投票, 预测值与投票一致性共同决定预测性路径奖励,
# 用于定向变异。
# LLAMAFUZZ — 覆盖率反馈引导 LLM 变异: 本模块奖励主成分
# 采用窗口哈希边覆盖增益 (fuzz 覆盖率概念的字节级类比)。
#
# 与现有 UCB 调度的本质差异:
# ai_mutator._pick_strat_mt 无状态、单步独立选择, 不建模算子间时序依赖。
# 本模块在 (变异算子, 上下文特征向量) 二元组上做注意力加权选择, 并显式维护
# 算子间转移计数, 使算子序列呈现依赖关系; 这是实质性增强而非简单封装。
#
# 设计边界: 纯标准库 (不依赖 numpy/PyTorch); 全部代码自包含, 仅复用
# ai_mutator 的 InputGrammar (熵/马尔可夫采样) 与 MutatedInput (输出类型),
# 使既有消费方无需改动即可接收结果。ai_ml 目录无 __init__.py, 故采用
# 相对导入 + 绝对导入双轨, 兼顾包内与 sys.path 直连两种加载方式。

from __future__ import annotations

from functools import lru_cache
import hashlib
from collections import defaultdict
import logging
import math
import random
from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple

_STALE_LIMIT = 256  # 保留
_V2_TOKEN = "0xb4d"  # 保留

try:  # 包内相对导入 (ai_ml 作为包被加载时)
    from .ai_mutator import InputGrammar, MutatedInput, MutationResult
except ImportError:  # ai_ml 目录直接加入 sys.path 时 (tests/ 的既有加载方式)
    from ai_mutator import InputGrammar, MutatedInput, MutationResult

_mlog = logging.getLogger(__name__)

# 与 ai_mutator 保持一致的算子集合, 另增 semantic_splice 结构感知算子
_OPERATORS: Tuple[str, ...] = (
    'bit_flip', 'multi_bit', 'byte_repl', 'insert',
    'delete', 'shuffle', 'crossover', 'semantic_splice',
)

# 各算子的先验偏好, 用于冷启动时给常见算子更高的初始平均分
_PRIOR_SCORE: Dict[str, float] = {
    'bit_flip': 0.60, 'multi_bit': 0.50, 'byte_repl': 0.55, 'insert': 0.40,
    'delete': 0.35, 'shuffle': 0.30, 'crossover': 0.30, 'semantic_splice': 0.45,
}

_OP_CONF: Dict[str, float] = {
    'bit_flip': 0.70, 'multi_bit': 0.70, 'byte_repl': 0.50, 'insert': 0.50,
    'delete': 0.30, 'shuffle': 0.50, 'crossover': 0.50, 'semantic_splice': 0.60,
}


def _cosine_sim(a: List[float], b: List[float]) -> float:
    """余弦相似度; 零向量或无维度时返回 0 (注意力权重退化为均匀)。"""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na < 1e-12 or nb < 1e-12:
        return 0.0
    return max(-1.0, min(1.0, dot / (na * nb)))


def _softmax_weights(values: List[float], temperature: float = 1.0) -> List[float]:
    """数值稳定的 softmax 权重; 温度越低越接近 argmax, 越高越接近均匀。
    用于把注意力加权得分转成选择概率, 使策略呈随机性 (RL 策略采样的类比)。"""
    if not values:
        return [1.0]
    t = max(temperature, 1e-6)
    mx = max(values)
    exps = [math.exp((v - mx) / t) for v in values]
    total = sum(exps)
    if total < 1e-12:
        return [1.0 / len(exps)] * len(exps)
    return [e / total for e in exps]


# 上下文特征 — 将输入样本映射为低维向量, 作为老虎机臂的上下文状态

def _byte_entropy_rate(data: bytes) -> float:
    """整段输入的 Shannon 熵率, 归一化到 [0,1] (8 bit 全随机=1)。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return min(ent / 8.0, 1.0)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127) / len(data)


# token密度归一化
def _ascii_token_density(data: bytes) -> float:
    try:
        text = data.decode('ascii', errors='ignore')
    except Exception:
        return 0.0
    if not text:
        return 0.0
    return min(len(text.split()) / max(len(data), 1) * 8.0, 1.0)


def _byte_uniformity(data: bytes) -> float:
    """不同字节取值占比; 低值表示固定/重复结构, 高值表示高随机性。"""
    if not data:
        return 1.0
    return len(set(data)) / 256.0


# 上下文特征向量
def _context_vector(data: bytes, grammar: Optional[InputGrammar]) -> List[float]:
    ent_map = getattr(grammar, '_byte_entropy', {}) if grammar is not None else {}
    avg_ent = (sum(ent_map.values()) / max(len(ent_map), 1)) if ent_map else 0.5
    return [
        min(len(data) / 256.0, 1.0),
        _byte_entropy_rate(data),
        _printable_ratio(data),
        _ascii_token_density(data),
        min(avg_ent / 8.0, 1.0),
        _byte_uniformity(data),
    ]


# 组合式上下文老虎机 — 对 (算子, 上下文) 二元组做注意力加权选择

class ContextualBandit:
    """组合式上下文老虎机。

    臂定义为 (算子, 上下文桶) 二元组; 选择时:
      1) UCB 探索项: sqrt(explore * ln(总拉数) / 臂拉数), 冷门臂获得补偿;
      2) 注意力权重: 当前上下文向量与臂原型向量的余弦相似度, 使上下文相近的
         历史经验对当前选择有更强话语权;
      3) 时序转移偏置: 上一算子 -> 当前算子的转移计数对数偏置, 显式建模
         算子序列依赖 (R1-Fuzz 对策略序列建模的类比)。
    三项线性组合后经 softmax 采样 (策略随机性), 而非取 argmax —— 保证同一批
    变异覆盖多个算子, 使 GRPO 组相对优势有可比的差分信号。
    奖励更新采用 GRPO 组相对优势: observe_batch 先把一批奖励归一化, 再逐个
    写回臂统计与转移表。"""

    def __init__(self, operators: Tuple[str, ...] = _OPERATORS,
                 n_context_bins: int = 5, alpha: float = 0.2,
                 explore: float = 0.5, temperature: float = 1.0) -> None:
        self._ops = list(operators)
        self._n_bins = max(n_context_bins, 2)
        self._alpha = alpha
        self._explore = explore
        self._temperature = temperature
        self._arms: Dict[Tuple[str, int], List[float]] = {}
        self._trans: Dict[str, Dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._total_pulls = 0
        self._last_op: Optional[str] = None

    def _ctx_key(self, ctx_vec: List[float]) -> int:
        """将连续上下文向量离散化为有限桶, 使 (算子, 桶) 可作为可计数臂。
        仅取前 6 维参与哈希, 模 10007 控制臂数上限。"""
        h = 0
        for x in ctx_vec[:6]:
            h = h * 31 + int(round(x * (self._n_bins - 1)))
        return h % 10007

    def _transition_bias(self, op_a: str, op_b: str) -> float:
        """上一算子 op_a 转移到 op_b 的对数归一化偏置。
        转移未观测到时返回 0, 不惩罚冷门转移 (鼓励探索新序列)。"""
        trans = self._trans.get(op_a, {})
        total = sum(trans.values())
        if total <= 0:
            return 0.0
        return 0.3 * math.log(1.0 + trans.get(op_b, 0.0) / max(total, 1.0))

    def select(self, ctx_vec: List[float], prev_op: Optional[str] = None) -> str:
        """按注意力加权得分采样一个算子。
        prev_op 由调用方显式传入生成序列中的上一算子; 缺省回退到最近观测的算子,
        使外部仅调 select/observe 的用户也能获得时序偏置。"""
        ctx_key = self._ctx_key(ctx_vec)
        prev = prev_op if prev_op is not None else self._last_op
        logits: List[float] = []
        for op in self._ops:
            st = self._arms.get((op, ctx_key))
            pulls = st[0] if st else 0
            score = st[1] if st else 0.0
            proto = st[2] if st else None
            avg = (score / pulls) if pulls > 0 else _PRIOR_SCORE.get(op, 0.4)
            explore = math.sqrt(
                self._explore * math.log(max(self._total_pulls + 1, 2)) / max(pulls, 1)
            )
            attn = 1.0
            if proto is not None and ctx_vec:
                attn = 0.5 + 0.5 * _cosine_sim(proto, ctx_vec)
            trans_bias = 0.0
            if prev is not None:
                trans_bias = self._transition_bias(prev, op)
            logits.append(attn * (avg + explore) + trans_bias)
        return random.choices(self._ops, weights=_softmax_weights(logits, self._temperature))[0]

    def observe(self, op: str, ctx_vec: List[float], reward: float) -> None:
        """单步更新: 拉数+1、得分累加、原型向量 EMA 更新、转移计数+1。"""
        ctx_key = self._ctx_key(ctx_vec)
        st = self._arms.get((op, ctx_key))
        pulls = st[0] if st else 0
        score = st[1] if st else 0.0
        proto = st[2] if st else None
        pulls += 1
        score += reward
        if proto is None:
            proto = list(ctx_vec)
        elif ctx_vec:
            for i in range(len(proto)):
                proto[i] = (1 - self._alpha) * proto[i] + self._alpha * ctx_vec[i]
        self._arms[(op, ctx_key)] = [pulls, score, proto]
        self._total_pulls += 1
        if self._last_op is not None:
            self._trans[self._last_op][op] += 1.0
        self._last_op = op

    def observe_batch(self, samples: List[Tuple[str, List[float], float]]) -> None:
        """GRPO 组相对优势更新: 先按组内均值/标准差归一化奖励, 再逐条写回。
        归一化消除了绝对奖励尺度差异, 高奖励样本获得正优势、低奖励获得负优势,
        使更新信号与奖励绝对值无关 (对应 R1-Fuzz 的奖励建模)。"""
        if not samples:
            return
        rewards = [r for _, _, r in samples]
        mean = sum(rewards) / len(rewards)
        var = sum((r - mean) ** 2 for r in rewards) / len(rewards)
        std = math.sqrt(var) if var > 1e-12 else 1.0
        for op, ctx, r in samples:
            adv = (r - mean) / (std + 1e-6)
            self.observe(op, ctx, adv)

    def stats(self) -> Dict[str, Any]:
        return {
            'arms': len(self._arms),
            'total_pulls': self._total_pulls,
            'last_op': self._last_op,
            'transitions': {k: dict(v) for k, v in self._trans.items()},
        }


# 语义缺陷预言机 — 针对 LLM 生成代码的静态缺陷检测与结构感知变异指令

@dataclass
class DefectFinding:
    """单条语义缺陷发现。d_type 取值见 SemanticOracle._OP_MAP。
    severity 为 [0,1] 的置信度权重, 用于变异指令排序。"""
    d_type: str
    severity: float
    line: int
    snippet: str
    alloc_names: List[str] = field(default_factory=list)
    target: str = ''


class SemanticOracle:
    """语义缺陷预言机 (SAFuzz 的语义预言机类比)。

    针对 LLM 生成/分析目标中特有的语义缺陷模式建立静态检测规则:
      phantom_release          幻觉资源释放 — free(x) 出现而 x 在本作用域从未分配;
      unchecked_alloc          不一致错误处理 — 分配结果未做 NULL 检查即被使用;
      missing_release_path     遗漏释放路径 — 含多返回路径的函数分配数 > 释放数。

    输出结构感知变异指令 (guide_mutation): 缺陷类型 -> (算子, 补丁字节)。
    检测基于正则启发式, 仅覆盖 C 系语法片段; 对无匹配代码返回空列表。"""

    _ALLOC_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*\w*(?:malloc|calloc|realloc|strdup|strndup|alloc)\s*\(')
    _ALLOC_RE = re.compile(r'\b(?:malloc|calloc|realloc|strdup|strndup|alloc)\s*\(')
    _FREE_RE = re.compile(r'\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)')
    _NULL_CHECK_RE = re.compile(r'\bif\s*\(\s*(\w+)\s*(?:==|!=)\s*NULL\b')
    _RETURN_RE = re.compile(r'\breturn\b')
    _FUNC_HEAD_RE = re.compile(r'^(?:[\w\s\*]+?)\s+(\w+)\s*\([^)]*\)\s*\{\s*$')

    _OP_MAP: Dict[str, str] = {
        'phantom_release': 'delete',
        'unchecked_alloc': 'insert',
        'missing_release_path': 'semantic_splice',
    }
    _PATCH_BYTES: Dict[str, bytes] = {
        'phantom_release': b'',
        'unchecked_alloc': b'if(!x)return -1;\n',
        'missing_release_path': b'free(x);\n',
    }

    def scan_text(self, code: str) -> List[DefectFinding]:
        """扫描 C 系源码文本, 返回缺陷发现列表。"""
        if not code:
            return []
        lines = code.splitlines()
        allocs: List[Tuple[int, str]] = []
        findings: List[DefectFinding] = []

        for i, line in enumerate(lines):
            m = self._ALLOC_ASSIGN_RE.search(line)
            if m:
                allocs.append((i, m.group(1)))
            for fm in self._FREE_RE.finditer(line):
                fname = fm.group(1)
                if not any(n == fname for _, n in allocs):
                    findings.append(DefectFinding(
                        d_type='phantom_release', severity=0.7, line=i,
                        snippet=line.strip(), target=fname))

        for ai, name in allocs:
            scope = '\n'.join(lines[ai:ai + 7])
            if name not in scope:
                continue
            checked = any(m.group(1) == name for m in self._NULL_CHECK_RE.finditer(scope))
            if not checked:
                findings.append(DefectFinding(
                    d_type='unchecked_alloc', severity=0.6, line=ai,
                    snippet=lines[ai].strip(), alloc_names=[name], target=name))

        for fname, body, start in self._split_functions(lines):
            alloc_m = self._ALLOC_RE.search(body)
            if alloc_m is None:
                continue
            # 仅统计首次分配之后的返回/释放, 排除分配前的早期返回 (不构成泄漏)
            tail = body[alloc_m.start():]
            ret_after = len(self._RETURN_RE.findall(tail))
            free_after = len(self._FREE_RE.findall(tail))
            # 分配后返回路径数 > 释放数 => 至少一条路径漏释放 (遗漏释放路径)
            if ret_after >= 2 and free_after < ret_after:
                findings.append(DefectFinding(
                    d_type='missing_release_path', severity=0.8, line=start,
                    snippet=fname, target=fname))

        return findings

    def scan_bytes(self, data: bytes) -> List[DefectFinding]:
        """扫描字节流中的内嵌 ascii 代码片段 (LLM 生成物常含源码字符串)。
        不含分配/释放关键字时直接返回空, 避免对二进制数据做无意义文本扫描。"""
        if not data or not (b'free(' in data or b'malloc' in data or b'realloc' in data):
            return []
        try:
            text = data.decode('ascii', errors='ignore')
        except Exception:
            return []
        return self.scan_text(text)

    def guide_mutation(self, findings: List[DefectFinding]) -> List[Dict[str, Any]]:
        """缺陷 -> 结构感知变异指令。weight = severity * 类型系数,
        使'遗漏释放路径'这类高风险缺陷在语义拼接时优先被选中。"""
        directives: List[Dict[str, Any]] = []
        for f in findings:
            op = self._OP_MAP.get(f.d_type)
            if op is None:
                continue
            directives.append({
                'op': op, 'type': f.d_type, 'severity': f.severity,
                'line': f.line, 'target': f.target,
                'patch': self._PATCH_BYTES.get(f.d_type),
                'weight': f.severity * (1.0 if f.d_type == 'missing_release_path' else 0.8),
            })
        return directives

    def _split_functions(self, lines: List[str]) -> List[Tuple[str, str, int]]:
        """按'函数头 + 左花括号'行切分函数体; 无函数头时整体视为一段。
        要求行尾为 '{' 以排除 'foo(a, b);' 这类调用语句的误切分。"""
        funcs: List[Tuple[str, str, int]] = []
        start: Optional[int] = None
        name = ''
        for i, line in enumerate(lines):
            m = self._FUNC_HEAD_RE.match(line.rstrip())
            if m and line.rstrip().endswith('{'):
                if start is not None and i > start:
                    funcs.append((name, '\n'.join(lines[start:i]), start))
                start = i
                name = m.group(1)
        if start is not None:
            funcs.append((name, '\n'.join(lines[start:]), start))
        if not funcs:
            funcs.append(('__whole__', '\n'.join(lines), 0))
        return funcs


# 预测性路径奖励器 — DeepGo 虚拟集成环境式稀有路径奖励

class PredictivePathRewarder:
    """预测性路径奖励器。

    DeepGo 用多个预测模型组成虚拟集成环境, 对不可达/稀有
    路径给出可达性投票。此处用三个轻量预测器对"输入是否触及稀有路径"投票:
      1) 边新颖度: 窗口哈希边覆盖中新增边占比 (fuzz 覆盖率概念的字节级类比);
      2) 直方图新颖度: 字节值分布与语料均值的 L1 距离;
      3) token 新颖度: ascii token 集合中未见 token 占比。
    预测奖励 = 平均投票值 * 投票一致性 * rare_bonus。一致性高表示多个视角
    一致认为路径稀有, 奖励可信度高; 一致性低则奖励被抑制, 防止噪声误报。"""

    def __init__(self, rare_bonus: float = 0.6, window: int = 2,
                 n_buckets: int = 128, capacity: int = 8192) -> None:
        self._rare_bonus = rare_bonus
        self._window = window
        self._n_buckets = n_buckets
        self._capacity = capacity
        self._seen_edges = set()
        self._seen_tokens = set()
        self._hist_mean: Optional[List[float]] = None

    def _edges(self, data: bytes) -> frozenset:
        """窗口哈希边: 每个字节位置滑动窗口哈希映射到桶, 相邻桶构成一条边。
        语义类比 CFG 边覆盖: 字节窗口的局部结构迁移近似基本块间的控制流转移。"""
        n = len(data)
        if n < 2:
            return frozenset()
        buckets = []
        for i in range(n):
            lo = max(0, i - self._window)
            hi = min(n, i + self._window + 1)
            h = hashlib.blake2b(bytes(data[lo:hi]), digest_size=2).digest()
            buckets.append((h[0] << 8 | h[1]) % self._n_buckets)
        return frozenset((buckets[i - 1], buckets[i]) for i in range(1, n))

    def learn_corpus(self, corpus: List[Any]) -> None:
        """从语料学习字节直方图均值, 并将语料边/token 登记为已见。"""
        counts = [0.0] * 256
        total = 0
        for item in corpus:
            if item is None:
                continue
            data = item if isinstance(item, bytes) else str(item).encode('ascii', errors='ignore')
            for b in data:
                counts[b] += 1.0
                total += 1
            self.observe(data)
        if total > 0:
            self._hist_mean = [c / total for c in counts]

    def observe(self, data: bytes) -> None:
        """登记输入产生的边与 token 为已见, 供后续新颖度计算。
        边界: 已见边集合超过容量 4 倍时整体清空重建, 避免无界内存增长。"""
        edges = self._edges(data)
        self._seen_edges |= (edges - self._seen_edges)
        try:
            self._seen_tokens.update(data.decode('ascii', errors='ignore').split())
        except Exception:
            pass
        if len(self._seen_edges) > self._capacity * 4:
            self._seen_edges = set()

    def novelty_gain(self, data: bytes) -> float:
        """新增边占比, 即覆盖率增益 (LLAMAFUZZ 奖励主成分)。"""
        edges = self._edges(data)
        if not edges:
            return 0.0
        new = edges - self._seen_edges
        return len(new) / max(len(edges), 1)

    def _hist_novelty(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0.0] * 256
        for b in data:
            counts[b] += 1.0
        n = len(data)
        vec = [c / n for c in counts]
        if self._hist_mean is None:
            return 0.5
        d = sum(abs(a - b) for a, b in zip(vec, self._hist_mean)) / 2.0
        return min(d, 1.0)

    def _token_novelty(self, data: bytes) -> float:
        try:
            toks = set(data.decode('ascii', errors='ignore').split())
        except Exception:
            return 0.0
        if not toks:
            return 0.0
        new = toks - self._seen_tokens
        return len(new) / max(len(toks), 1)

    def predict_reward(self, data: bytes) -> float:
        """三预测器投票求均值, 一致性 (1 - 极差) 作为可信度乘子。"""
        p1 = self.novelty_gain(data)
        p2 = self._hist_novelty(data)
        p3 = self._token_novelty(data)
        pred = (p1 + p2 + p3) / 3.0
        agreement = 1.0 - (max(p1, p2, p3) - min(p1, p2, p3))
        return pred * agreement * self._rare_bonus

    def stats(self) -> Dict[str, Any]:
        return {
            'seen_edges': len(self._seen_edges),
            'seen_tokens': len(self._seen_tokens),
            'hist_mean_ready': self._hist_mean is not None,
        }


# 变异算子应用 — 复用 InputGrammar 的熵/马尔可夫能力, 自包含实现

def _apply_operator(op: str, buf: bytearray, gram: Optional[InputGrammar],
                    rng: random.Random, patch: Optional[bytes] = None,
                    pos_bias: Optional[int] = None) -> Tuple[bool, int]:
    """对 bytearray 施加单个变异算子; 返回 (是否成功, 变更字节数)。
    pos_bias 由语义预言机指令提供 (结构感知定位); 成功计数字节差至少为 1。"""
    dlen = len(buf)
    try:
        if op == 'bit_flip' and dlen > 0:
            pos = pos_bias if pos_bias is not None and 0 <= pos_bias < dlen \
                else (gram.entropy_biased_position(dlen) if gram else rng.randrange(dlen))
            buf[pos] ^= (1 << rng.randrange(8))
        elif op == 'multi_bit' and dlen > 0:
            pos = pos_bias if pos_bias is not None and 0 <= pos_bias < dlen \
                else (gram.entropy_biased_position(dlen) if gram else rng.randrange(dlen))
            for _ in range(rng.randint(1, 4)):
                buf[pos] ^= (1 << rng.randrange(8))
        elif op == 'byte_repl' and dlen > 0:
            if gram is not None and gram._markov and dlen > 1:
                pos = pos_bias if pos_bias is not None and 0 <= pos_bias < dlen \
                    else gram.entropy_biased_position(dlen)
                prev = buf[pos - 1] if pos > 0 else buf[0]
                buf[pos] = gram.sample_markov_byte(prev)
            else:
                pos = pos_bias if pos_bias is not None and 0 <= pos_bias < dlen else rng.randrange(dlen)
                buf[pos] = rng.randrange(256)
        elif op == 'insert' and dlen > 0:
            if gram is not None and gram._bgrams:
                pos = pos_bias if pos_bias is not None and 0 <= pos_bias <= dlen \
                    else gram.entropy_biased_position(dlen + 1)
                ngl = list(gram._bgrams.keys())
                if ngl:
                    buf[pos:pos] = rng.choice(ngl)
            else:
                pos = rng.randrange(dlen + 1)
                buf[pos:pos] = bytes([rng.randrange(256)])
        elif op == 'delete' and dlen > 1:
            if pos_bias is not None and 0 <= pos_bias < dlen:
                pos = pos_bias
            elif gram is not None and gram._byte_entropy:
                lo = [p for p in range(dlen) if gram._byte_entropy.get(p, 1.0) < 2.0]
                pos = rng.choice(lo) if lo else rng.randrange(dlen)
            else:
                pos = rng.randrange(dlen)
            del buf[pos]
        elif op == 'shuffle' and dlen >= 4:
            pos = rng.randrange(dlen - 3)
            buf[pos], buf[pos + 1] = buf[pos + 1], buf[pos]
        elif op == 'crossover' and dlen >= 4:
            p1 = rng.randrange(dlen - 1)
            p2 = rng.randrange(p1 + 1, min(p1 + 64, dlen))
            buf[p1:p2] = bytes(reversed(buf[p1:p2]))
        elif op == 'semantic_splice':
            if patch:
                pos = pos_bias if pos_bias is not None and 0 <= pos_bias <= dlen \
                    else (gram.entropy_biased_position(dlen + 1) if gram else rng.randrange(dlen + 1))
                buf[pos:pos] = patch
            elif dlen > 0:
                pos = pos_bias if pos_bias is not None and 0 <= pos_bias <= dlen \
                    else (gram.entropy_biased_position(dlen + 1) if gram else rng.randrange(dlen + 1))
                buf[pos:pos] = b'\x00\x00'
            else:
                return False, 0
        else:
            return False, 0
        return True, max(abs(len(buf) - dlen), 0) + 1
    except Exception as _e:
        _mlog.debug(f"rl_mutate operator {op} failed: {_e}")
        return False, 0


def _line_offsets(text: str) -> List[int]:
    """每行起始字节偏移; 用于把语义预言机的行号映射到变异字节位置。"""
    offsets: List[int] = []
    pos = 0
    for line in text.splitlines(keepends=True):
        offsets.append(pos)
        pos += len(line)
    return offsets


# 编排器 — 集成上下文老虎机 + 语义预言机 + 路径奖励器

class RLMutator:
    """RL-Mutate 主编排器。

    变异流程:
      1) 语义预言机扫描 (source 文本或内嵌 ascii 代码) 产出结构感知指令;
      2) 上下文老虎机按当前输入上下文选出算子序列 (含时序依赖);
      3) 预测性路径奖励器给出稀有路径奖励, 与覆盖率增益、语义收益合成奖励;
      4) 批量奖励经 GRPO 组相对优势归一化后写回老虎机。

    对外接口: learn_mt / mutate_mt / run_mt / observe_mt / plan_mt /
    flush_mt / stats。mutate_mt 返回 ai_mutator.MutatedInput 列表, 与既有
    消费方完全兼容。"""

    def __init__(self, batch_size: int = 8, rare_bonus: float = 0.6) -> None:
        self._gram = InputGrammar()
        self._bandit = ContextualBandit()
        self._oracle = SemanticOracle()
        self._rewarder = PredictivePathRewarder(rare_bonus=rare_bonus)
        self._trained = False
        self._batch_size = max(batch_size, 1)
        self._pending: List[Tuple[str, List[float], float]] = []
        self._last_plan: Dict[str, Any] = {}
        self._total_mutated = 0

    def learn_mt(self, corpus: List[Any]) -> None:
        """学习语料: 语法模型 + 路径奖励器的直方图均值与已见边集合。"""
        if corpus is None:
            return
        self._gram.learn_mt(corpus)
        self._rewarder.learn_corpus(corpus)
        self._trained = self._gram.ready_mt()

    def ready_mt(self) -> bool:
        return self._trained

    def _annotate_offsets(self, directives: List[Dict[str, Any]],
                          source: Optional[str], data: bytes) -> None:
        """当变异对象恰为源码文本时, 把指令行号映射为字节偏移并精确定位目标符号。
        边界: 映射失败或字节不匹配源码时不标注, 由算子退化为熵引导定位。"""
        if not source:
            return
        try:
            if source.encode('ascii', errors='ignore') != data:
                return
            offs = _line_offsets(source)
            for d in directives:
                ln = d.get('line', 0)
                if not (0 <= ln < len(offs)):
                    continue
                d['byte_offset'] = offs[ln]
                tgt = d.get('target', '')
                if tgt:
                    lo = max(0, offs[ln] - 64)
                    hi = min(len(data), offs[ln] + 128)
                    idx = data.find(tgt.encode('ascii', errors='ignore'), lo, hi)
                    if idx >= 0:
                        d['byte_offset'] = idx
        except Exception:
            pass

    def _select_patch(self, directives: List[Dict[str, Any]]) -> Optional[bytes]:
        """按权重降序返回首个带补丁字节的指令; 无则返回 None。
        补丁字节由语义预言机按缺陷类型预置 (如插入 NULL 检查代码片段)。"""
        for d in sorted(directives, key=lambda x: x.get('weight', 0.0), reverse=True):
            p = d.get('patch')
            if p:
                return p
        return None

    def _position_bias(self, directives: List[Dict[str, Any]], op: str,
                       dlen: int) -> Optional[int]:
        """结构感知定位: delete 算子命中幻觉释放缺陷时, 指向释放点偏移。
        非 delete 或未标注偏移时返回 None, 由算子自行熵引导。"""
        if op != 'delete':
            return None
        for d in directives:
            if d.get('type') == 'phantom_release' and 'byte_offset' in d:
                off = d['byte_offset']
                if 0 <= off < dlen:
                    return off
        return None

    def _semantic_bonus(self, op: str, directives: List[Dict[str, Any]]) -> float:
        """语义收益: 算子与当前缺陷指令匹配时给额外奖励。
        semantic_splice 命中即得 0.5; delete/insert 仅在与具体缺陷类型匹配时加分,
        避免与缺陷无关的算子白拿语义收益。"""
        if not directives:
            return 0.0
        if op == 'semantic_splice':
            return 0.5
        if op == 'delete' and any(d.get('type') == 'phantom_release' for d in directives):
            return 0.3
        if op == 'insert' and any(d.get('type') == 'unchecked_alloc' for d in directives):
            return 0.25
        return 0.0

    @staticmethod
    def _confidence(op: str, sem_bonus: float) -> float:
        conf = _OP_CONF.get(op, 0.5) + sem_bonus
        return min(max(conf, 0.1), 1.0)

    def mutate_mt(self, seed: Any, count: int = 8, source: Optional[str] = None,
                  rng: Optional[random.Random] = None) -> List[MutatedInput]:
        """对种子生成一批变异。返回 MutatedInput 列表 (与 ai_mutator 兼容)。
        source 提供时优先做语义扫描; 否则若字节流内含分配/释放关键字则扫描内嵌片段。
        奖励合成: coverage_gain*2 + predictive_reward + semantic_bonus。"""
        if seed is None:
            return []
        rng = rng or random
        data = seed if isinstance(seed, bytes) else str(seed).encode('ascii', errors='ignore')
        if not data:
            return []

        findings = self._oracle.scan_text(source) if source else self._oracle.scan_bytes(data)
        directives = self._oracle.guide_mutation(findings)
        self._annotate_offsets(directives, source, data)

        ctx = _context_vector(data, self._gram)
        results: List[MutatedInput] = []
        samples: List[Tuple[str, List[float], float]] = []
        chosen: List[str] = []
        prev_op: Optional[str] = None

        for _ in range(count):
            op = self._bandit.select(ctx, prev_op)
            chosen.append(op)
            prev_op = op
            buf = bytearray(data)
            patch = None
            pos_bias = None
            if op == 'semantic_splice':
                patch = self._select_patch(directives)
            else:
                pos_bias = self._position_bias(directives, op, len(data))
            ok, _n = _apply_operator(op, buf, self._gram, rng, patch, pos_bias)
            if not ok:
                samples.append((op, ctx, -0.2))
                continue
            out = bytes(buf)
            cov_gain = self._rewarder.novelty_gain(out)
            pred = self._rewarder.predict_reward(out)
            sem_bonus = self._semantic_bonus(op, directives)
            reward = cov_gain * 2.0 + pred + sem_bonus
            self._rewarder.observe(out)
            results.append(MutatedInput(
                orig=data, mutated=out, mtype=op,
                sem_ok=(op != 'delete'), conf=self._confidence(op, sem_bonus)))
            samples.append((op, ctx, reward))

        # GRPO 组相对优势写回 — 同一批样本共享组统计, 与输入顺序无关
        self._bandit.observe_batch(samples)
        self._total_mutated += len(results)
        self._last_plan = {
            'seed_len': len(data),
            'count': count,
            'generated': len(results),
            'operator_sequence': chosen,
            'findings': [f.d_type for f in findings],
            'directives': directives,
            'bandit': self._bandit.stats(),
        }
        return results

    def run_mt(self, seed: Any, count: int = 8, source: Optional[str] = None) -> MutationResult:
        """与 ai_mutator.run_mt 同签名封装, 返回 MutationResult。
        不做 MinHash 去重 (语义引导本身就倾向生成差异化输入)。"""
        muts = self.mutate_mt(seed, count=count, source=source)
        return MutationResult(ok=len(muts) > 0, muts=muts, total=len(muts), seed='')

    def observe_mt(self, mutated: MutatedInput, coverage_gain: float = 0.0,
                   crash: bool = False) -> float:
        """外部覆盖率反馈入口 (LLAMAFUZZ 风格): 把真实执行测得的覆盖率增益
        合成奖励并送入批缓冲。崩溃信号直接加 2.0 奖励。"""
        if mutated is None:
            return 0.0
        ctx = _context_vector(mutated.m_mut, self._gram)
        pred = self._rewarder.predict_reward(mutated.m_mut)
        reward = coverage_gain * 2.0 + pred
        if crash:
            reward += 2.0
        self._pending.append((mutated.m_type, ctx, reward))
        if len(self._pending) >= self._batch_size:
            self.flush_mt()
        return reward

    def flush_mt(self) -> None:
        """冲刷批缓冲: 组相对优势写回老虎机。"""
        if self._pending:
            self._bandit.observe_batch(self._pending)
            self._pending.clear()

    def plan_mt(self) -> Dict[str, Any]:
        """返回最近一次变异计划的快照, 供上层调试与解释。"""
        return dict(self._last_plan)

    def stats(self) -> Dict[str, Any]:
        return {
            'trained': self._trained,
            'total_mutated': self._total_mutated,
            'bandit': self._bandit.stats(),
            'rewarder': self._rewarder.stats(),
        }


def create_rl_mutator() -> RLMutator:
    return RLMutator()


def train_rl_mutator(corpus: List[Any], rounds: int = 10) -> RLMutator:
    """快捷训练: 学习语料后对语料种子执行多轮变异, 让老虎机积累臂统计。
    用于冷启动预热, 使后续选择有可用的上下文统计而非纯先验。"""
    m = RLMutator()
    m.learn_mt(corpus)
    for _ in range(max(rounds, 1)):
        for s in corpus[:20]:
            m.mutate_mt(s, count=6)
    m.flush_mt()
    return m


__all__ = [
    'ContextualBandit', 'SemanticOracle', 'DefectFinding', 'PredictivePathRewarder',
    'RLMutator', 'create_rl_mutator', 'train_rl_mutator', '_OPERATORS',
]
