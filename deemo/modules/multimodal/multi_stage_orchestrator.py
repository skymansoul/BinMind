"""多阶段漏洞利用编排器。

链式攻击编排：管理 recon → exploit → post-exploit → cleanup 生命周期。
阶段间依赖关系通过 Kahn 拓扑排序解析，支持并行阶段调度。
三种执行策略：sequential（线性）、parallel_layer（层内并行）、best_effort（失败继续）。
支持 subprocess 真实执行、目标类型感知过滤、链式模糊变异、动态策略自选。
"""
from enum import Enum
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
import logging
import json
import time
import hashlib
import subprocess
import signal
import threading
import random
import tempfile
import os
import shutil
import math

logger = logging.getLogger(__name__)

_EPS: float = 1e-9

# 枚举定义
class ExploitStage(Enum):
    RECON = "recon"
    EXPLOIT = "exploit"
    POST = "post"
    CLEANUP = "cleanup"


class ChainStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    CHECKPOINTED = "checkpointed"
    TIMED_OUT = "timed_out"


class ExecutionStrategy(Enum):
    SEQUENTIAL = "sequential"
    PARALLEL_LAYER = "parallel_layer"
    BEST_EFFORT = "best_effort"
    AUTO = "auto"


class VulnerabilityType(Enum):
    STACK_OVERFLOW = "stack_overflow"
    HEAP_OVERFLOW = "heap_overflow"
    FORMAT_STRING = "format_string"
    USE_AFTER_FREE = "use_after_free"
    INTEGER_OVERFLOW = "integer_overflow"


class TargetType(Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    WEB = "web"
    EMBEDDED = "embedded"


# 步骤执行输出 — 捕获单步骤的完整执行轨迹
@dataclass
class StepOutput:
    action: str
    stdout: str = ""
    stderr: str = ""
    exit_code: int = -1
    timed_out: bool = False
    elapsed_seconds: float = 0.0


# 阶段能力注册 — 每个阶段声明的能力用于前置校验
@dataclass
class StageCapability:
    name: str
    required_tools: List[str] = field(default_factory=list)
    target_types: List[TargetType] = field(default_factory=list)
    timeout_seconds: float = 60.0
    retry_count: int = 1


# 链步骤定义
@dataclass
class ChainStep:
    stage: ExploitStage
    action: str = ""
    payload: Optional[str] = None
    pre_conditions: List[str] = field(default_factory=list)
    post_conditions: List[str] = field(default_factory=list)
    timeout_seconds: float = 30.0
    retry_on_fail: bool = False
    produces: List[str] = field(default_factory=list)
    applicable_targets: List[TargetType] = field(default_factory=list)
    shell_command: Optional[str] = None
    fuzzable: bool = False

    def satisfied(self, ctx: Dict[str, Any]) -> bool:
        """检查前置条件在上下文中是否全部满足。"""
        for cond in self.pre_conditions:
            if cond not in ctx:
                return False
        return True

    def applies_to(self, target_type: Optional[TargetType]) -> bool:
        if not self.applicable_targets:
            return True
        if target_type is None:
            return True
        return target_type in self.applicable_targets

    def fuzz_variants(self, n: int = 5) -> List[str]:
        """生成 shell_command 的模糊变异版本。

        仅在 fuzzable=True 且 shell_command 非空时产出版本。
        变异策略：占位符替换 (0x00→0x01)、空格→制表符、编码转换。
        """
        if not self.fuzzable or not self.shell_command:
            return []
        variants: List[str] = []
        base = self.shell_command
        # 变异 1: null-byte 占位替换为相邻值
        if '{null_byte}' in base:
            for b in range(1, 5):
                variants.append(base.replace('{null_byte}', f'\\x{b:02x}'))
        # 变异 2: 空格→制表符/换行
        if ' ' in base:
            variants.append(base.replace(' ', '\t'))
        # 变异 3: payload 大小写混淆
        if '{payload}' in base:
            variants.append(base.replace('{payload}', '{PAYLOAD}'))
        # 变异 4: 参数顺序交换
        parts = base.split()
        if len(parts) >= 3:
            _swapped = parts[:]
            _swapped[1], _swapped[2] = _swapped[2], _swapped[1]
            variants.append(' '.join(_swapped))
        variants = variants[:n]
        # 去重
        seen: set = set()
        return [v for v in variants if not (v in seen or seen.add(v))]


# 攻击链
class AttackChain:
    def __init__(self, name: str = ""):
        self.name = name
        self.steps: List[ChainStep] = []
        self.deadline_seconds: Optional[float] = None

    def add_step(self, s: ChainStep) -> None:
        self.steps.append(s)

    @property
    def stage_count(self) -> Dict[ExploitStage, int]:
        tally: Dict[ExploitStage, int] = defaultdict(int)
        for s in self.steps:
            tally[s.stage] += 1
        return dict(tally)

    def estimated_duration(self) -> float:
        """各 step timeout 之和 + 10% buffer，作为链预估执行时长。"""
        return sum(s.timeout_seconds for s in self.steps) * 1.1

    def complexity(self) -> Dict[str, Any]:
        """McCabe 风格依赖图复杂度度量。

        edges = 前置条件总数，nodes = 步骤数。
        环路数 = edges - nodes + 2*components（连通分量）。
        高复杂度链 (>10 边) 建议拆分。
        """
        n = len(self.steps)
        e = sum(len(s.pre_conditions) for s in self.steps)
        components = 1  # 假设连通
        cyclomatic = max(0, e - n + 2 * components)
        return {
            'nodes': n,
            'edges': e,
            'cyclomatic': cyclomatic,
            'density': round(e / max(1, n * (n - 1)), 3),
            'estimated_duration': round(self.estimated_duration(), 1)
        }

    def success_rate_estimate(self) -> float:
        """基于链结构的启发式成功率估算。

        复杂度越高、步骤越多、前置条件越密集 → 成功率越低。
        公式: exp(-0.15 * cyclomatic) * exp(-0.05 * len(steps))
        """
        comp = self.complexity()
        return round(math.exp(-0.15 * comp['cyclomatic'])
                     * math.exp(-0.05 * comp['nodes']), 3)


# 依赖解析器 — Kahn 算法处理阶段间依赖，检测环路
class DependencyResolver:
    """对有向无环依赖图做拓扑排序，输出可并行执行的阶段批次。

    若检测到环路，不抛异常，而是将环内节点并入同一批次执行——
    在 exploit 链中对应互相依赖的阶段（如 recon 和 exploit 交替）仍需尝试执行。
    """

    def resolve(self, steps: List[ChainStep]) -> List[List[ChainStep]]:
        # 按 action 建立索引
        idx_map: Dict[str, int] = {}
        for i, s in enumerate(steps):
            idx_map[s.action] = i

        n = len(steps)
        in_degree = [0] * n
        adj: List[List[int]] = [[] for _ in range(n)]

        for i, s in enumerate(steps):
            for pre in s.pre_conditions:
                if pre in idx_map:
                    j = idx_map[pre]
                    adj[j].append(i)
                    in_degree[i] += 1

        q = deque([i for i in range(n) if in_degree[i] == 0])
        layers: List[List[ChainStep]] = []
        visited = 0

        while q:
            batch: List[ChainStep] = []
            for _ in range(len(q)):
                u = q.popleft()
                batch.append(steps[u])
                visited += 1
                for v in adj[u]:
                    in_degree[v] -= 1
                    if in_degree[v] == 0:
                        q.append(v)
            layers.append(batch)

        # 环路处理：剩余未访问节点放入最后一层
        if visited < n:
            remainder = [steps[i] for i in range(n) if in_degree[i] > 0]
            layers.append(remainder)

        return layers


# 脚本生成器 — 占位符插值 + payload 嵌入
class ScriptGenerator:
    """将 ChainStep 列表转换为可执行脚本。

    内置占位符替换: {payload}, {target}, {stage_name}。
    生产环境可替换为 Jinja2 或自定义 DSL。
    """

    _BOILERPLATE = (
        "# Auto-generated exploit chain\n"
        "# WARNING: review before execution\n\n"
        "import sys\n"
        "def _execute():\n"
    )

    def __init__(self):
        self._template_cache: Dict[str, str] = {}

    def generate(self, chain: AttackChain, target_info: Dict[str, Any]) -> str:
        lines = [self._BOILERPLATE]
        ctx: Dict[str, Any] = {}

        for step in chain.steps:
            lines.append(f"    # Stage: {step.stage.value} | {step.action}")
            if step.payload:
                interpolated = step.payload.format(
                    target=target_info.get('host', 'localhost'),
                    stage_name=step.stage.value,
                    **target_info
                )
                lines.append(f"    {interpolated}")
            else:
                lines.append(f"    # No payload for {step.action}")
            lines.append(f"    ctx_{step.action} = True  # post-condition marker")
            ctx[step.action] = True
            for post in step.post_conditions:
                ctx[post] = True
                lines.append(f"    ctx_{post} = True")

        lines.append("    return 0\n")
        lines.append("if __name__ == '__main__':\n")
        lines.append("    sys.exit(_execute())")
        return "\n".join(lines)


# 检查点 — 长链执行中断后恢复
@dataclass
class Checkpoint:
    chain_name: str
    last_completed_action: str
    executed_actions: List[str]
    context_snapshot: Dict[str, Any]
    timestamp: str
    checksum: str = ""

    def to_json(self) -> str:
        return json.dumps({
            'chain_name': self.chain_name,
            'last_completed_action': self.last_completed_action,
            'executed_actions': self.executed_actions,
            'context_snapshot': {k: str(v)[:200] for k, v in self.context_snapshot.items()},
            'timestamp': self.timestamp,
            'checksum': self.checksum
        })

    @classmethod
    def from_json(cls, raw: str) -> 'Checkpoint':
        d = json.loads(raw)
        return cls(**{k: d[k] for k in ['chain_name', 'last_completed_action',
                       'executed_actions', 'context_snapshot', 'timestamp', 'checksum']})


# 编排结果与编排器
@dataclass
class OrchestrationResult:
    success: bool = False
    chain: Optional[AttackChain] = None
    executed_steps: int = 0
    failed_step: Optional[str] = None
    output_log: str = ""
    artifacts: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: float = 0.0
    checkpoints: List[Checkpoint] = field(default_factory=list)
    step_outputs: List[StepOutput] = field(default_factory=list)


# ChainOrchestrator 提取至 src.chain_orchestrator_core
# 此处 import 用于向后兼容；模块级重导出。
from .src.chain_orchestrator_core import ChainOrchestrator  # noqa: E402


# 链差异对比 — 计算两条攻击链的最小变更集
# 基于 action 集合的对称差 + 依赖图编辑距离

def chain_diff(chain_a: AttackChain, chain_b: AttackChain) -> Dict[str, Any]:
    """对比两条链的差异，返回最小变更操作。

    操作类型: added（B有A无）、removed（A有B无）、modified（同名但属性不同）。
    """
    _a_actions = {s.action: s for s in chain_a.steps}
    _b_actions = {s.action: s for s in chain_b.steps}
    _a_set = set(_a_actions.keys())
    _b_set = set(_b_actions.keys())

    _added = [_b_actions[a] for a in (_b_set - _a_set)]
    _removed = [_a_actions[a] for a in (_a_set - _b_set)]
    _common = _a_set & _b_set

    _modified: List[Dict[str, Any]] = []
    for _action in _common:
        _sa, _sb = _a_actions[_action], _b_actions[_action]
        _changes: Dict[str, Tuple] = {}
        if _sa.stage != _sb.stage:
            _changes['stage'] = (_sa.stage.value, _sb.stage.value)
        if _sa.shell_command != _sb.shell_command:
            _changes['shell_command'] = (_sa.shell_command, _sb.shell_command)
        if set(_sa.pre_conditions) != set(_sb.pre_conditions):
            _changes['pre_conditions'] = (_sa.pre_conditions, _sb.pre_conditions)
        if set(_sa.post_conditions) != set(_sb.post_conditions):
            _changes['post_conditions'] = (_sa.post_conditions, _sb.post_conditions)
        if _changes:
            _modified.append({'action': _action, 'changes': _changes})

    return {
        'added': len(_added), 'removed': len(_removed), 'modified': len(_modified),
        'added_actions': [_s.action for _s in _added],
        'removed_actions': [_s.action for _s in _removed],
        'modified_details': _modified,
        'similarity': round(len(_common) / max(1, len(_a_set | _b_set)), 3),
    }


# 链策略注释 — 基于链特征预测最优策略及可能失败模式

def annotate_chain(chain: AttackChain) -> Dict[str, Any]:
    """分析攻击链特征，输出策略建议与风险标注。

    基于链复杂度、步骤密度、fuzzable 比例、shell 执行比例
    四维特征做启发式最佳策略推荐及风险预警。
    """
    comp = chain.complexity()
    n = comp['nodes']
    fuzzable_ratio = sum(1 for s in chain.steps if s.fuzzable) / max(1, n)
    shell_ratio = sum(1 for s in chain.steps if s.shell_command) / max(1, n)

    # 风险标注
    risks: List[str] = []
    if n >= 10:
        risks.append('high_step_count')
    if comp['cyclomatic'] >= 5:
        risks.append('complex_dependency_graph')
    if fuzzable_ratio > 0.5:
        risks.append('heavy_fuzzing_overhead')
    if shell_ratio > 0.8:
        risks.append('full_shell_execution')
    if not risks:
        risks.append('low_risk')

    # 策略建议
    if n <= 3 and comp['cyclomatic'] <= 1:
        suggestion = 'SEQUENTIAL'
    elif fuzzable_ratio > 0.3:
        suggestion = 'BEST_EFFORT'
    elif shell_ratio > 0.7 and comp['cyclomatic'] >= 2:
        suggestion = 'PARALLEL_LAYER'
    else:
        suggestion = 'AUTO'

    return {
        'suggested_strategy': suggestion,
        'risk_flags': risks,
        'features': {
            'step_count': n,
            'cyclomatic': comp['cyclomatic'],
            'fuzzable_ratio': round(fuzzable_ratio, 3),
            'shell_ratio': round(shell_ratio, 3),
            'estimated_duration': comp['estimated_duration'],
        }
    }


# 向后兼容别名
MultiStageOrchestrator = ChainOrchestrator


@dataclass
class Capability:
    def __init__(self, name: str = ""):
        self.name = name


# 模块级占位引用 — 外部可能有未迁移的 import
VulnerabilityNode = None
ExploitChainStep = None
ExploitChain = None
ChainAnalysisResult = None
orchestrate_exploit_chain = None


# MCTS链规划 — 蒙特卡洛树搜索选择最优步骤序列
# Silver et al. Mastering Chess and Shogi by Self-Play... AlphaZero.
#       Science 2018. + Browne et al. A Survey of MCTS Methods. 2012.
# exploit chain 视为决策树：每个节点=一个步骤，边=执行结果。
# MCTS 在步骤序列空间中探索，通过 UCB 权衡探索 vs 利用。

class MCTSChainPlanner:
    """蒙特卡洛树搜索链规划器。

    四步迭代: Selection → Expansion → Simulation → Backpropagation。
    UCB1 公式: score = avg_success + c_puct * sqrt(log(N_parent) / N_child)
    """

    def __init__(self, exploration_weight: float = 1.4, n_simulations: int = 100):
        self.c_puct = exploration_weight
        self.n_sims = n_simulations
        self._tree: Dict[str, Dict] = {}  # node_id → {visits, total_reward, actions}

    def plan(self, steps: List[ChainStep],
             target_info: Optional[Dict[str, Any]] = None,
             max_steps: int = 10) -> List[str]:
        """MCTS规划: 返回最优步骤顺序（action名列表）。

        每轮模拟从根节点出发:
        - 选择: 沿树下降，选 UCB1 最大的子节点
        - 扩展: 到达叶节点后，展开一个未尝试的步骤
        - 模拟: 随机完成剩余步骤，评估最终奖励
        - 反向传播: 将奖励沿路径回溯更新统计
        """
        if not steps:
            return []

        _action_names = [s.action for s in steps]
        self._tree = {'root': {'visits': 0, 'total_reward': 0.0, 'children': {}}}

        for _sim in range(self.n_sims):
            _path = ['root']
            _node = 'root'
            _available = set(_action_names) - set(_path)

            # Selection + Expansion
            while _node in self._tree and self._tree[_node].get('children') is not None:
                _children = self._tree[_node]['children']
                if not _children:
                    break
                # UCB1 选择
                _best_action = None
                _best_ucb = -float('inf')
                _log_parent = math.log(max(1, self._tree[_node]['visits']))
                for _act, _child_id in _children.items():
                    if _child_id not in self._tree:
                        continue
                    _child = self._tree[_child_id]
                    _exploit = _child['total_reward'] / max(1, _child['visits'])
                    _explore = self.c_puct * math.sqrt(_log_parent / max(1, _child['visits']))
                    _ucb = _exploit + _explore
                    if _ucb > _best_ucb:
                        _best_ucb = _ucb
                        _best_action = _act
                if _best_action is None or _best_action not in _children:
                    break
                _node = _children[_best_action]
                _path.append(_best_action)
                _available.discard(_best_action)

            # Expansion: 展开一个新动作
            if _available and len(_path) < max_steps:
                _next_act = next(iter(_available))
                _new_id = f"node_{_next_act}_{_sim}"
                if 'children' not in self._tree[_node]:
                    self._tree[_node]['children'] = {}
                self._tree[_node]['children'][_next_act] = _new_id
                self._tree[_new_id] = {'visits': 0, 'total_reward': 0.0, 'children': {}}
                _path.append(_next_act)
                _node = _new_id

            # Simulation: 评估当前路径的奖励
            _reward = self._rollout(_path, steps, target_info)

            # Backpropagation
            for _nid in _path:
                if _nid in self._tree:
                    self._tree[_nid]['visits'] += 1
                    self._tree[_nid]['total_reward'] += _reward

        # 提取最优路径
        _best_path = self._extract_best_path()
        return _best_path

    def _rollout(self, path: List[str], steps: List[ChainStep],
                  target_info: Optional[Dict[str, Any]] = None) -> float:
        """模拟执行: 启发式评估路径成功概率。

        考虑因素: 步骤前置条件满足度、shell命令可靠性、
        fuzzable 步骤的变异成功率。
        """
        _score = 1.0
        _step_map = {s.action: s for s in steps}
        _completed = set()

        for _act in path:
            if _act not in _step_map:
                continue
            _step = _step_map[_act]
            # 前置条件满足度
            _pre_satisfied = sum(1 for _pre in _step.pre_conditions
                                if _pre in _completed or _pre in [_step.action for _step in
                                [s for s in steps if s.action in path[:path.index(_act)]]])
            _total_pre = max(1, len(_step.pre_conditions))
            _pre_factor = _pre_satisfied / _total_pre

            # Shell命令可靠性（模拟执行有不确定性）
            _shell_factor = 0.95 if _step.shell_command else 1.0

            # Fuzzable步骤成功率
            _fuzz_factor = 0.85 if _step.fuzzable else 1.0

            _step_success = _pre_factor * _shell_factor * _fuzz_factor
            _score *= max(0.1, _step_success)
            _completed.add(_act)

        return _score

    def _extract_best_path(self) -> List[str]:
        """从搜索树中提取被访问次数最多的路径。"""
        _node = 'root'
        _path: List[str] = []
        _max_depth = 20

        while _node in self._tree and _max_depth > 0:
            _children = self._tree[_node].get('children', {})
            if not _children:
                break
            _best_act = max(_children.keys(),
                          key=lambda a: self._tree.get(_children[a], {}).get('visits', 0))
            _path.append(_best_act)
            _node = _children[_best_act]
            _max_depth -= 1

        return _path


# 贝叶斯优化 — fuzzing payload参数自动调优
# Snoek et al. Practical Bayesian Optimization of ML Algorithms. NIPS 2012.
# 高斯过程代理模型 + Expected Improvement (EI) 采集函数。
# 在连续参数空间（payload大小、超时、变异强度）中搜索最优配置。

class BayesianPayloadOptimizer:
    """贝叶斯优化器: 在高维 payload 参数空间中高效搜索。

    适用于: NOP sled 长度、shellcode 编码方式选择、timeout 设置等。
    使用 GP 代理 + EI 采集，比 Grid Search 少 5-10x 评估次数。
    """

    def __init__(self, param_bounds: Dict[str, Tuple[float, float]],
                 n_initial: int = 5):
        self.bounds = param_bounds  # {param_name: (min, max)}
        self.n_initial = n_initial
        self._X: List[List[float]] = []  # 已评估参数组合
        self._y: List[float] = []        # 对应得分
        self._param_order = list(param_bounds.keys())
        self._n_dims = len(self._param_order)

    def _rbf_kernel(self, x1: List[float], x2: List[float],
                     length_scale: float = 1.0) -> float:
        """RBF 核: k(x, x') = exp(-0.5 * ||x-x'||² / l²)"""
        _sq_dist = sum((x1[i]-x2[i])**2 for i in range(len(x1)))
        return math.exp(-0.5 * _sq_dist / (length_scale**2))

    def suggest(self) -> Dict[str, float]:
        """返回下一个建议评估的参数组合。"""
        if len(self._X) < self.n_initial:
            # 初始随机采样
            _params = {}
            for _i, _key in enumerate(self._param_order):
                _lo, _hi = self.bounds[_key]
                _params[_key] = _lo + random.random() * (_hi - _lo)
            return _params

        # Expected Improvement 最大化
        _best_y = max(self._y) if self._y else 0.0
        _n_candidates = 50
        _candidates: List[List[float]] = []
        for _ in range(_n_candidates):
            _cand = [self.bounds[_key][0] + random.random() *
                     (self.bounds[_key][1] - self.bounds[_key][0])
                     for _key in self._param_order]
            _candidates.append(_cand)

        _best_ei = -float('inf')
        _best_cand = _candidates[0]
        for _cand in _candidates:
            # 简化GP预测: 加权平均
            if self._X:
                _k_self = [[self._rbf_kernel(self._X[i], self._X[j])
                           for j in range(len(self._X))] for i in range(len(self._X))]
                _k_pred = [self._rbf_kernel(_cand, self._X[i]) for i in range(len(self._X))]
                # 伪逆预测
                _mean_pred = sum(_k_pred[i]*self._y[i] for i in range(len(self._y))) / max(1, sum(_k_pred))
                _var_pred = max(0.01, 1.0 - sum(kp*kp for kp in _k_pred)/max(1, len(self._X)))
            else:
                _mean_pred = 0.5
                _var_pred = 1.0

            # EI = (μ - y_best) * Φ(z) + σ * φ(z)
            _std = math.sqrt(_var_pred)
            if _std < _EPS:
                continue
            _z = (_mean_pred - _best_y) / _std
            # 标准正态 CDF (sigmoid 近似)
            _cdf = 1.0 / (1.0 + math.exp(-1.702 * _z))
            _pdf = math.exp(-0.5 * _z * _z) / math.sqrt(2.0 * math.pi)
            _ei = (_mean_pred - _best_y) * _cdf + _std * _pdf

            if _ei > _best_ei:
                _best_ei = _ei
                _best_cand = _cand

        return {self._param_order[i]: round(_best_cand[i], 4)
                for i in range(self._n_dims)}

    def observe(self, params: Dict[str, float], score: float):
        """记录一次评估结果。"""
        _vec = [params.get(_key, 0.0) for _key in self._param_order]
        self._X.append(_vec)
        self._y.append(score)

    def best_params(self) -> Dict[str, float]:
        """返回当前观测到的最优参数。"""
        if not self._y:
            return {}
        _best_idx = max(range(len(self._y)), key=lambda i: self._y[i])
        return {self._param_order[i]: round(self._X[_best_idx][i], 4)
                for i in range(self._n_dims)}
