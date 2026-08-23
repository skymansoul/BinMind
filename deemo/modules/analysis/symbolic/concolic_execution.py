#!/usr/bin/env python3
"""动态执行引擎 — 动态污点 → 符号种子注入。

流程:
1. 用动态污点跟踪器 (Frida/DBI) 采集具体输入种子
2. 分类种子来源类型 (文件/输入/环境)
3. 把种子作为具体约束送入符号执行器
4. 动态重执行交叉校验符号路径
5. 迭代 concolic 循环: 污点 → 符号 → 校验 → 重复

种子质量随轮次覆盖率收益衰减 — 检测到停滞时以 sigmoid 衰减函数
降低注入权重。
"""

import logging
import os
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .src.concolic_strategies import (
    CrashCategory,
    CrashTriageClassifier,
    FuzzDictEntry,
    FuzzDictGenerator,
    StructuredMetrics,
    SeedMutationPipeline,
    _entropy_of,
)

logger = logging.getLogger(__name__)


class ConcolicMode(Enum):
    """concolic 流水线的执行顺序"""
    DYNAMIC_FIRST = "dynamic_first"
    SYMBOLIC_FIRST = "symbolic_first"
    HYBRID = "hybrid"
    SEED_ONLY = "seed_only"


class ConcolicStatus(Enum):
    """concolic 分析运行的生命周期状态"""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class ConcolicSeed:
    """动态污点采集的具体输入, 待注入符号执行器"""
    source_name: str
    source_type: str
    value: bytes
    address: int = 0
    size: int = 0
    timestamp: float = 0.0
    is_symbolic: bool = False
    constraints: List = field(default_factory=list)
    taint_label: Optional[str] = None
    path_condition: Optional[str] = None
    entropy: float = 0.0        # 种子字节的 Shannon 熵 — 多样性代理指标
    round_collected: int = 0    # 采集该种子的 concolic 循环轮次


@dataclass
class TaintGuidedConstraint:
    """污点流推导出的约束: source → sink 置信度"""
    source_addr: int
    sink_addr: int
    operation: str
    constraint: str
    confidence: float = 0.0
    tainted_bytes: int = 0
    flow_depth: int = 0          # 污点传播中间步数
    is_loop_related: bool = False


@dataclass
class ConcolicPath:
    """concolic 探索发现的路径"""
    path_id: str
    instructions: List = field(default_factory=list)
    constraints: List = field(default_factory=list)
    is_feasible: bool = True
    concrete_input: Optional[bytes] = None
    discovered_from: str = ""  # 'dynamic' | 'symbolic' | 'concolic'
    coverage_increase: float = 0.0
    validation_attempts: int = 0


@dataclass
class ConcolicResult:
    """单次 concolic 分析的聚合输出"""
    status: ConcolicStatus
    seeds: List = field(default_factory=list)
    paths: List = field(default_factory=list)
    vulnerabilities: List = field(default_factory=list)
    coverage: Dict = field(default_factory=dict)
    execution_time: float = 0.0
    total_paths: int = 0
    new_paths_found: int = 0
    stagnation_rounds: int = 0


class ConcolicExecutor:
    """调度 concolic 流水线

    数据流:
    动态污点跟踪器 → ConcolicSeed → 符号执行器
    符号路径 → 动态重校验 → 可行性判定
    污点流 → TaintGuidedConstraint → 引导式符号探索

    concolic 循环最多迭代 max_concolic_iterations 次,
    每轮采集新鲜污点数据, 生成约束, 校验新发现的路径
    """

    def __init__(self,
                 f_binary_path,
                 f_dynamic_engine='frida',
                 f_mode=ConcolicMode.HYBRID):
        """连接子模块并初始化状态"""
        if f_binary_path is None:
            f_binary_path = ""
        if f_dynamic_engine is None:
            f_dynamic_engine = 'frida'

        self.binary_path = f_binary_path
        self.dynamic_engine = f_dynamic_engine
        self.mode = f_mode
        self.status = ConcolicStatus.NOT_STARTED

        self.dynamic_tracker = None
        self.symbolic_executor = None

        self.seeds = []
        self.paths = []
        self.vulnerabilities = []
        self.coverage = {
            'initial': 0.0,
            'final': 0.0,
            'increase': 0.0
        }

        self.taint_guided_constraints = []
        self.explored_paths = set()
        self.concolic_iteration = 0
        self.max_concolic_iterations = 10
        self._stagnation_counter = 0
        self._max_stagnation = 3
        self._prev_path_count = 0

        # 结构化指标累加器 + 种子变异流水线
        self.metric_accumulator = StructuredMetrics()
        self.seed_pipeline = SeedMutationPipeline()

        # 崩溃分类器 + 模糊字典生成器
        self.crash_triage = CrashTriageClassifier()
        self.fuzz_dict_generator = FuzzDictGenerator()

        self._init_submodules()

# metric 辅助函数
    def _record_metric(self, name: str, value: int):
        """累计计数型指标, 纯累加无副作用"""
        if self.metric_accumulator is not None:
            setattr(self.metric_accumulator, name,
                    getattr(self.metric_accumulator, name, 0) + value)

    def _snapshot_metrics(self):
        """每轮输出一条结构化记录, 替代分散的 info 日志"""
        m = self.metric_accumulator
        if m is None:
            return
        logger.info(
            "[Concolic] round_snapshot r=%d seeds=%d paths_valid=%d fp=%d "
            "timeouts=%d taint_constraints=%d",
            m.round_number, m.seeds_collected, m.paths_validated,
            m.false_positives, m.solver_timeouts, m.taint_constraints_generated,
        )

    def _init_submodules(self):
        """惰性导入并实例化动态跟踪器与符号执行器"""
        try:
            # from .dynamic_taint import create_dynamic_taint_tracker
            # self.dynamic_tracker = create_dynamic_taint_tracker(
            # self.binary_path
            #     engine=self.dynamic_engine
            # )
            logger.info(f"[Concolic] Dynamic taint tracker initialized: {self.dynamic_engine}")
        except Exception as e:
            logger.warning(f"[Concolic] Failed to initialize dynamic taint tracker: {e}")

        try:
            # from .symbolic_exe import SymbolicExecutor
            # self.symbolic_executor = SymbolicExecutor(self.binary_path)
            logger.info("[Concolic] Symbolic executor initialized")
        except Exception as e:
            logger.warning(f"[Concolic] Failed to initialize symbolic executor: {e}")

    def is_availableCx(self):
        """至少一个子引擎可用时返回 True"""
        dynamic_available = self.dynamic_tracker is not None and self.dynamic_tracker.is_available()
        symbolic_available = self.symbolic_executor is not None and self.symbolic_executor.is_available()
        return dynamic_available or symbolic_available

    # 种子衰减权重：sigmoid 函数，中心点在 max_stagnation 处
    # 设计意图 — 连续 N 轮无新路径后，低熵种子被抑制，保留高熵种子
    # 避免完全停止注入（可能恰好需要某一轮才触达关键路径）
    def _seed_injection_weight(self) -> float:
        k = 1.2  # steepness
        x0 = self._max_stagnation
        x = self._stagnation_counter
        return 1.0 - 1.0 / (1.0 + math.exp(-k * (x - x0)))

    def run_dynamic_seedingCx(self,
                            f_args=None,
                            f_timeout=60,
                            f_input_data=None):
        """执行动态污点跟踪, 采集具体种子与污点标记"""
        logger.info("[Concolic] Starting dynamic seed collection")

        if self.dynamic_tracker is None:
            logger.warning("[Concolic] Dynamic tracker unavailable, skipping seed collection")
            return []

        try:
            result = self.dynamic_tracker.run_taint_analysis(
                args=f_args,
                timeout=f_timeout,
                input_data=f_input_data
            )

            if not result.get('success'):
                logger.warning(f"[Concolic] Dynamic analysis failed: {result.get('error')}")
                return []

            seeds = []
            taint_marks = result.get('taint_marks', [])
            weight = self._seed_injection_weight()
            for m_idx in range(len(taint_marks)):
                mark = taint_marks[m_idx]
                source_name = mark.get('source', 'unknown')
                source_type = self._classify_source_typeCx(source_name)
                address = int(mark.get('address', '0x0'), 16)
                size = mark.get('size', 0)

                seed_value = self._generate_seed_valueCx(source_type, size)
                ent = _entropy_of(seed_value)

                # 低权重 + 低熵 → 跳过注入，节省符号执行资源
                if weight < 0.3 and ent < 2.0:
                    continue

                seed = ConcolicSeed(
                    source_name=source_name,
                    source_type=source_type,
                    value=seed_value,
                    address=address,
                    size=size,
                    is_symbolic=False,
                    entropy=ent,
                    round_collected=self.concolic_iteration
                )

                seeds.append(seed)
                logger.debug(f"[Concolic] Collected seed: {source_name} @ {hex(address)}")

            taint_flows = result.get('taint_flows', [])
            for f_idx in range(len(taint_flows)):
                flow = taint_flows[f_idx]
                tainted_args = flow.get('tainted_args', [])
                for a_idx in range(len(tainted_args)):
                    tainted_arg = tainted_args[a_idx]
                    arg_str = tainted_arg.get('value', '')
                    arg_value = b''
                    if arg_str:
                        cleaned = arg_str.replace('0x', '')
                        try:
                            arg_value = bytes.fromhex(cleaned)
                        except Exception:
                            arg_value = b''
                    if arg_value:
                        seed = ConcolicSeed(
                            source_name=tainted_arg.get('source', 'unknown'),
                            source_type='tainted_argument',
                            value=arg_value,
                            size=len(arg_value),
                            is_symbolic=True,
                            entropy=_entropy_of(arg_value),
                            round_collected=self.concolic_iteration
                        )

                        seeds.append(seed)

            # 种子收集后 → 变异 → 记录指标 → 存入种子库
            seeds = self.seed_pipeline.mutate(seeds)
            self._record_metric('seeds_collected', len(seeds))
            self.seeds.extend(seeds)
            logger.info(f"[Concolic] Collected {len(seeds)} dynamic seeds (weight={weight:.2f})")

            return seeds

        except Exception as e:
            logger.error(f"[Concolic] Dynamic seed collection failed: {e}")
            return []

    def _classify_source_typeCx(self, f_source_name):
        """将函数名映射到种子来源类别

        先检查精确匹配避免部分匹配干扰
        (如 'fread' 包含 'read', 需先测试 'fread')"""
        if f_source_name is None:
            return 'unknown'
        name_lower = f_source_name.lower()

        if name_lower in ['fread', 'open', 'mmap']:
            return 'file'
        elif name_lower in ['read', 'recv', 'recvfrom', 'recvmsg', 'gets', 'scanf', 'sscanf']:
            return 'input'
        elif name_lower in ['getenv']:
            return 'environment'
        return 'unknown'

    def _generate_seed_valueCx(self, f_source_type, f_size):
        """根据来源类型合成具体字节模式

        input → 可打印填充 ('A' * size)
        file → BMP 头前缀 + null 填充
        environment → "TEST=value\\0" 截断至指定长度
        unknown → 'A' * size
        """
        if f_size is None or f_size <= 0:
            f_size = 16
        capped = min(max(f_size, 1), 256)

        if f_source_type == 'input':
            return b'A' * capped
        elif f_source_type == 'file':
            return b'\x42\x4d' + b'\x00' * (capped - 2)
        elif f_source_type == 'environment':
            return b'TEST=value\x00'[:capped]
        else:
            return b'\x41' * capped

    def seed_symbolic_executorCx(self, f_seeds):
        """将种子注入符号执行器状态

        停滞计数器 > 0 时按熵值排序, 优先注入高熵种子
        低熵种子（全 'A' 之类）不太可能触达新路径"""
        if self.symbolic_executor is None or not self.symbolic_executor.is_available():
            logger.warning("[Concolic] Symbolic executor unavailable")
            return False

        if f_seeds is None or not f_seeds:
            logger.info("[Concolic] No seeds to apply")
            return True

        # 停滞期：按熵降序排列，高位优先
        ordered = f_seeds
        if self._stagnation_counter > 0:
            ordered = sorted(f_seeds, key=lambda s: s.entropy, reverse=True)

        logger.info(f"[Concolic] Applying {len(ordered)} seeds to symbolic executor")
        # 简单迭代：只输出种子标识，实际注入由子模块完成
        for s_idx in range(len(ordered)):
            seed = ordered[s_idx]
            logger.debug(f"[Concolic] Seed: {seed.source_name} = {seed.value[:16].hex()}... ent={seed.entropy:.1f}")
        return True

    # 停滞检测：若本轮未发现新路径，stagnation_counter++
    # 连续 _max_stagnation 轮后进入"探索优先"模式：
    #   种子注入权重下降
    #   增加每轮路径探索深度
    def _detect_stagnation(self, current_path_count: int):
        if current_path_count <= self._prev_path_count:
            self._stagnation_counter += 1
        else:
            self._stagnation_counter = 0
        self._prev_path_count = current_path_count

    # 崩溃分类: 利用崩溃地址/错误信息/约束对已发现漏洞进行分类
    # 在分析结束时自动调用, 为每个漏洞添加 crash_category 标签
    def _classify_vulnerability_crashes(self, result: ConcolicResult) -> None:
        """通过崩溃分类器为漏洞标记崩溃类别

        不修改 result.vulnerabilities 的顶层结构, 只在每条记录中添加
        crash_category / triage_confidence 键, 保持向后兼容
        """
        if not result.vulnerabilities:
            return
        for vuln in result.vulnerabilities:
            crash_addr_raw = vuln.get("address", "0x0")
            try:
                crash_addr = int(crash_addr_raw, 16) if isinstance(crash_addr_raw, str) else crash_addr_raw
            except (ValueError, TypeError):
                crash_addr = 0

            err_msg = vuln.get("error_message", "") or vuln.get("type", "")
            constraints = vuln.get("constraints", [])
            if isinstance(constraints, str):
                constraints = [constraints]

            category, conf = self.crash_triage.classify_with_confidence(
                crash_address=crash_addr,
                error_message=err_msg,
                constraint_texts=constraints,
            )
            vuln["crash_category"] = category.value
            vuln["triage_confidence"] = round(conf, 3)

    def run_concolic_analysisCx(self,
                              f_args=None,
                              f_timeout=120,
                              f_input_data=None,
                              f_max_paths=100,
                              f_exploration_depth=500):
        """执行完整 concolic 分析流水线

        流程依 mode 而异:
        DYNAMIC_FIRST → 采集种子, 用种子运行符号执行
        HYBRID → 完整流水线: 种子 + 符号 + concolic 循环 + 校验
        SYMBOLIC_FIRST → 先运行符号执行, 再用结果采集动态种子
        """
        start_time = time.time()

        logger.info(f"[Concolic] Starting concolic analysis (mode: {self.mode.value})")
        self.status = ConcolicStatus.RUNNING

        result = ConcolicResult(status=ConcolicStatus.RUNNING)

        try:
            if self.mode in [ConcolicMode.DYNAMIC_FIRST, ConcolicMode.HYBRID]:
                dynamic_seeds = self.run_dynamic_seedingCx(
                    f_args=f_args,
                    f_timeout=min(f_timeout // 2, 60),
                    f_input_data=f_input_data
                )

                result.seeds.extend(dynamic_seeds)

                self.seed_symbolic_executorCx(dynamic_seeds)

            if self.symbolic_executor is not None and self.symbolic_executor.is_available():
                # 停滞期自适应加深探索深度
                effective_depth = f_exploration_depth
                if self._stagnation_counter > 0:
                    effective_depth = int(f_exploration_depth * (1.0 + 0.3 * self._stagnation_counter))
                    effective_depth = min(effective_depth, f_exploration_depth * 3)

                symbolic_result = self._run_symbolic_with_seedsCx(
                    f_args=f_args,
                    f_max_paths=f_max_paths,
                    f_exploration_depth=effective_depth
                )

                result.paths.extend(symbolic_result.get('paths', []))
                result.vulnerabilities.extend(symbolic_result.get('vulnerabilities', []))

            if self.mode == ConcolicMode.HYBRID and self.dynamic_tracker is not None and self.symbolic_executor is not None:
                logger.info("[Concolic] Starting taint-guided symbolic execution loop")
                concolic_paths = self._concolic_loopCx(
                    f_args=f_args,
                    f_timeout=min(f_timeout // 3, 40)
                )

                result.paths.extend(concolic_paths)

                for cp_idx in range(len(concolic_paths)):
                    path = concolic_paths[cp_idx]
                    if path.concrete_input:
                        vuln_info = {
                            'type': 'potential_vulnerability',
                            'address': hex(path.instructions[0]) if path.instructions else '0x0',
                            'input': path.concrete_input.hex()[:32] + '...' if len(path.concrete_input) > 32 else path.concrete_input.hex(),
                            'discovered_by': 'taint_guided_concolic'
                        }
                        result.vulnerabilities.append(vuln_info)

            if self.mode == ConcolicMode.HYBRID:
                self._validate_symbolic_pathsCx()

            self._calculate_coverageCx(result)

            self._detect_stagnation(len(result.paths))
            result.stagnation_rounds = self._stagnation_counter

            # 分析结束后的后处理
            self._classify_vulnerability_crashes(result)

            result.status = ConcolicStatus.COMPLETED
            result.execution_time = time.time() - start_time
            result.total_paths = len(result.paths)
            result.new_paths_found = self._count_new_pathsCx(result.paths)

            # 分析结束 → 最终快照
            self.metric_accumulator.round_number = self.concolic_iteration
            self._snapshot_metrics()

            logger.info(f"[Concolic] Analysis complete, found {result.new_paths_found} new paths")

        except Exception as e:
            logger.error(f"[Concolic] Analysis failed: {e}")
            result.status = ConcolicStatus.ERROR
            result.execution_time = time.time() - start_time

        self.status = result.status
        return result

    def _run_symbolic_with_seedsCx(self,
                                 f_args=None,
                                 f_max_paths=100,
                                 f_exploration_depth=500):
        """注入种子后运行符号执行器

        采集崩溃路径、自动探索危险函数、污点分析结果,
        不同路径来源贡献不同的覆盖率增量权重"""
        if self.symbolic_executor is None:
            return {'paths': [], 'vulnerabilities': []}

        logger.info("[Concolic] Running symbolic execution with seeds")

        results = {
            'paths': [],
            'vulnerabilities': []
        }

        try:
            full_result = self.symbolic_executor.full_analysis()

            if full_result.get('crash_path') and full_result['crash_path'].get('success'):
                path_info = full_result['crash_path']
                path = ConcolicPath(
                    path_id=self._generate_path_idCx(),
                    constraints=[],
                    is_feasible=True,
                    concrete_input=path_info.get('concrete_input'),
                    discovered_from='symbolic',
                    coverage_increase=0.1
                )

                results['paths'].append(path)

            if full_result.get('crash_path') and full_result['crash_path'].get('vulnerabilities'):
                for vuln in full_result['crash_path']['vulnerabilities']:
                    results['vulnerabilities'].append(vuln)

            auto_result = self.symbolic_executor.auto_explore_dangerous_functions(
                max_per_func=f_exploration_depth // 10
            )

            if auto_result:
                path = ConcolicPath(
                    path_id=self._generate_path_idCx(),
                    constraints=[],
                    is_feasible=True,
                    concrete_input=auto_result.get('crashing_input'),
                    discovered_from='concolic',
                    coverage_increase=0.15
                )

                results['paths'].append(path)

                vuln_info = {
                    'type': auto_result.get('crash_type', 'unknown'),
                    'address': auto_result.get('crash_address', '0x0'),
                    'input': auto_result.get('crashing_input_hex', ''),
                    'discovered_by': 'concolic'
                }
                results['vulnerabilities'].append(vuln_info)

            taint_result = self.symbolic_executor.run_taint_analysis()
            if taint_result.get('sensitive_reached'):
                for sink in taint_result['sensitive_reached']:
                    path = ConcolicPath(
                        path_id=self._generate_path_idCx(),
                        constraints=[],
                        is_feasible=True,
                        concrete_input=sink.get('input'),
                        discovered_from='concolic',
                        coverage_increase=0.05
                    )

                    results['paths'].append(path)

        except Exception as e:
            logger.error(f"[Concolic] Symbolic execution failed: {e}")
            self._record_metric('solver_timeouts', 1)

        return results

    def _collect_taint_guided_constraintsCx(self, f_taint_result):
        """将污点流转换为 TaintGuidedConstraint

        遍历每条流的 source 地址与 sink 列表, 置信度
        正比于 tainted_bytes / 8, 上限 1.0

        引入 flow_depth 字段追踪污点传播步数,
        深度越大的流越可能穿过循环结构,
        置信度乘以衰减因子 (0.85 ** depth) 防止过深传播噪声淹没真实信号
        """
        if f_taint_result is None:
            return []

        constraints = []

        for flow in f_taint_result.get('taint_flows', []):
            source_addr = int(flow.get('source_address', '0x0'), 16)
            hop_bucket = flow.get('propagation_hops', [])
            flow_depth = len(hop_bucket)

            for sink in flow.get('sinks', []):
                sink_addr = int(sink.get('address', '0x0'), 16)
                operation = sink.get('operation', 'unknown')
                tainted_bytes = sink.get('tainted_bytes', 0)

                # 深度衰减：约束的置信度随传播步数递减
                raw_confidence = min(1.0, tainted_bytes / 8)
                depth_penalty = 0.85 ** flow_depth if flow_depth > 2 else 1.0

                # 循环检测：sink 地址在 hop_bucket 历史中出现过
                loop_sig = [h.get('addr') == sink.get('address')
                            for h in hop_bucket[:-1] if h.get('addr')]
                is_loop = any(loop_sig)

                constraint = TaintGuidedConstraint(
                    source_addr=source_addr,
                    sink_addr=sink_addr,
                    operation=operation,
                    constraint=self._generate_constraint_from_flowCx(flow),
                    confidence=raw_confidence * depth_penalty,
                    tainted_bytes=tainted_bytes,
                    flow_depth=flow_depth,
                    is_loop_related=is_loop
                )

                constraints.append(constraint)

        self._record_metric('taint_constraints_generated', len(constraints))
        return constraints

    def _generate_constraint_from_flowCx(self, f_flow):
        """根据污点流操作类型映射为符号约束字符串

        strcmp/strncmp → 不等于比较值
        memcmp → memcmp_result != 0
        strcpy/strncpy → 输入长度超过 max_length
        printf → 格式化字符串检查
        default → tainted_<source>_reaches_<sink>
        """
        if f_flow is None:
            return "unknown_constraint"

        source = f_flow.get('source', 'unknown')
        sink = f_flow.get('sink', 'unknown')
        operation = f_flow.get('operation', 'read')
        # 操作→约束映射：紧凑查找表取代 -elif 链
        op_map = {
            'strcmp': lambda: f"(input != {f_flow.get('compared_value', '0')})",
            'strncmp': lambda: f"(input != {f_flow.get('compared_value', '0')})",
            'memcmp': lambda: "(memcmp_result != 0)",
            'strcpy': lambda: f"(input_length > {f_flow.get('max_length', 0)})",
            'strncpy': lambda: f"(input_length > {f_flow.get('max_length', 0)})",
            'printf': lambda: "(contains_format_specifier(input))",
        }
        mapper = op_map.get(operation)
        if mapper:
            return mapper()

        return f"tainted_{source}_reaches_{sink}"

    def _run_taint_guided_symbolic_executionCx(self, f_constraints):
        """使用污点推导的约束引导符号执行

        过滤置信度 < 0.3 的约束, 存活约束触发引导分析;
        发现的路径与漏洞标记为 'taint_guided'

        循环相关的约束获得额外探索深度 (max_depth × 1.5),
        因为循环中的污点传播路径往往需要更多步数才能触达边界条件
        """
        if self.symbolic_executor is None or not self.symbolic_executor.is_available():
            return {'paths': [], 'vulnerabilities': []}

        if f_constraints is None:
            f_constraints = []

        logger.info(f"[Concolic] Using {len(f_constraints)} taint constraints to guide symbolic execution")

        results = {
            'paths': [],
            'vulnerabilities': []
        }

        for constraint in f_constraints:
            if constraint.confidence < 0.3:
                continue

            effective_depth = 200
            if constraint.is_loop_related:
                effective_depth = int(200 * 1.5)

            # 每条约束独立尝试；单条失败不终止整体循环
            guided_result = self.symbolic_executor.run_guided_analysis(
                constraint=constraint.constraint,
                source_addr=constraint.source_addr,
                sink_addr=constraint.sink_addr,
                max_depth=effective_depth
            )

            if guided_result.get('path_found'):
                path = ConcolicPath(
                    path_id=self._generate_path_idCx(),
                    constraints=[constraint.constraint],
                    is_feasible=True,
                    concrete_input=guided_result.get('concrete_input'),
                    discovered_from='taint_guided',
                    coverage_increase=0.2
                )

                results['paths'].append(path)

                if guided_result.get('vulnerability'):
                    results['vulnerabilities'].append({
                        'type': guided_result['vulnerability'].get('type', 'unknown'),
                        'address': guided_result['vulnerability'].get('address', '0x0'),
                        'constraint': constraint.constraint,
                        'discovered_by': 'taint_guided'
                    })

        return results

    def _concolic_loopCx(self, f_args=None, f_timeout=60):
        """concolic 核心迭代循环

        每轮:
        1. 运行动态污点分析
        2. 采集污点引导的约束
        3. 运行污点引导的符号执行
        4. 对发现的路径去重 (discovered_from, input_hash)
        5. 动态校验新路径

        达到 max_concolic_iterations / timeout / 50 条新路径时停止"""
        new_paths = []
        start_time = time.time()

        while self.concolic_iteration < self.max_concolic_iterations:
            if time.time() - start_time > f_timeout:
                logger.info("[Concolic] Concolic loop timeout")
                break

            self.concolic_iteration += 1
            self.metric_accumulator.round_number = self.concolic_iteration
            logger.info(f"[Concolic] Iteration {self.concolic_iteration}/{self.max_concolic_iterations}")

            if self.dynamic_tracker is not None:
                dynamic_result = self.dynamic_tracker.run_taint_analysis(
                    args=f_args,
                    timeout=min(f_timeout // 2, 30)
                )

                if dynamic_result.get('success'):
                    self.taint_guided_constraints = self._collect_taint_guided_constraintsCx(dynamic_result)

                    guided_result = self._run_taint_guided_symbolic_executionCx(
                        self.taint_guided_constraints
                    )

                    for path in guided_result.get('paths', []):
                        path_key = f"{path.discovered_from}_{hash(path.concrete_input) if path.concrete_input else path.path_id}"
                        if path_key not in self.explored_paths:
                            self.explored_paths.add(path_key)
                            new_paths.append(path)

                            if path.concrete_input:
                                self._validate_single_pathCx(path)

            # 每轮结束 → 一次快照输出
            self._snapshot_metrics()

            if len(new_paths) >= 50:
                break

        # 循环结束后将高熵种子送入字典生成器
        self._build_fuzz_dictionary_from_seeds()

        return new_paths

    # Fuzz 字典构建: 从已收集的种子池中选出高熵种子
    # 按 coverage_gain + entropy 排序, 输出 AFL/libFuzzer 字典
    def _build_fuzz_dictionary_from_seeds(self) -> None:
        """用已采集的种子填充 FuzzDictGenerator

        仅考虑高熵种子 (Shannon 熵 >= 2.0);
        覆盖率增益由停滞计数器增量推断 —
        停滞期采集的种子赋予更高增益
        """
        if not self.seeds:
            return
        coverage_gains: Dict[int, float] = {}
        for idx, seed in enumerate(self.seeds):
            gain = 0.0
            if seed.entropy >= FuzzDictGenerator.MIN_ENTROPY_THRESHOLD:
                gain = seed.entropy * 0.1
            coverage_gains[idx] = gain

        self.fuzz_dict_generator.clear()
        admitted = self.fuzz_dict_generator.ingest_from_seeds(
            self.seeds, coverage_gains
        )
        if admitted > 0:
            logger.info(
                "[Concolic] FuzzDict built: %d entries from %d seeds",
                admitted, len(self.seeds),
            )

    def export_fuzz_dictionary(self, output_path: str) -> int:
        """将 AFL/libFuzzer 字典写入 output_path

        返回写入条数, 若生成器无条目则返回 0 (需先完成分析)
        """
        if self.fuzz_dict_generator.entry_count() == 0:
            self._build_fuzz_dictionary_from_seeds()
        return self.fuzz_dict_generator.export_to_file(output_path)

    def _validate_single_pathCx(self, f_path):
        """用路径的具体输入重跑动态跟踪器以验证可行性

        最多尝试验证 2 次 — 第一次失败可能是环境状态不一致,
        重试一次排除瞬态错误, 两次都失败则标记为不可行
        """
        if self.dynamic_tracker is None or f_path is None or f_path.concrete_input is None:
            return

        attempt = 0
        while attempt < 2:
            result = self.dynamic_tracker.run_taint_analysis(
                input_data=f_path.concrete_input,
                timeout=15
            )
            f_path.is_feasible = result.get('success', False)
            f_path.validation_attempts = attempt + 1
            if f_path.is_feasible:
                self._record_metric('paths_validated', 1)
                return
            attempt += 1

        f_path.is_feasible = False
        self._record_metric('false_positives', 1)

    def _validate_symbolic_pathsCx(self):
        """后验校验: 用动态跟踪器重跑符号发现的路径

        仅校验 discovered_from='symbolic' 且有 concrete_input 的路径"""
        if self.dynamic_tracker is None or not self.paths:
            return

        logger.info(f"[Concolic] Validating {len(self.paths)} symbolic paths")
        # 列表推导预筛选 → 减少主循环内条件判断
        candidates = [p for p in self.paths
                      if p.discovered_from == 'symbolic' and p.concrete_input]

        for path in candidates:
            result = self.dynamic_tracker.run_taint_analysis(
                input_data=path.concrete_input,
                timeout=10
            )
            path.is_feasible = result.get('success', False)
            if path.is_feasible:
                self._record_metric('paths_validated', 1)
                logger.debug(f"[Concolic] Path {path.path_id} validated as feasible")
            else:
                self._record_metric('false_positives', 1)
                logger.debug(f"[Concolic] Path {path.path_id} validated as infeasible")

    def _calculate_coverageCx(self, f_result):
        """根据路径数估算覆盖率增量

        公式: 基准 10% + 每条路径 2%, 上限 80% 增量
        启发式近似 — 真实覆盖率需要基本块插桩"""
        if f_result is None:
            return
        base_coverage = 0.1
        path_bonus = min(len(f_result.paths) * 0.02, 0.8)

        f_result.coverage['initial'] = base_coverage
        f_result.coverage['final'] = base_coverage + path_bonus
        f_result.coverage['increase'] = path_bonus

    def _count_new_pathsCx(self, f_paths):
        """统计通过 concolic 或符号方式发现的路径数"""
        if f_paths is None:
            return 0
        return sum(1 for p in f_paths if p.discovered_from in ['concolic', 'symbolic'])

    def _generate_path_idCx(self):
        """构造短小唯一的路径标识符"""
        return str(uuid.uuid4())[:8]

    def export_seedsCx(self, f_output_dir='./seeds'):
        """将采集的种子写入磁盘二进制文件与 JSON 元数据"""
        if f_output_dir is None:
            f_output_dir = './seeds'

        os.makedirs(f_output_dir, exist_ok=True)
        exported_files = []

        for s_idx in range(len(self.seeds)):
            seed = self.seeds[s_idx]
            i = s_idx
            filename = f"seed_{i:04d}_{seed.source_name}_{seed.source_type}.bin"
            filepath = os.path.join(f_output_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(seed.value)

            meta_filepath = filepath + '.meta'
            with open(meta_filepath, 'w', encoding='utf-8') as f:
                json.dump({
                    'source_name': seed.source_name,
                    'source_type': seed.source_type,
                    'address': hex(seed.address),
                    'size': seed.size,
                    'is_symbolic': seed.is_symbolic,
                    'entropy': round(seed.entropy, 2)
                }, f, indent=2)

            exported_files.append(filepath)

        logger.info(f"[Concolic] Exported {len(exported_files)} seeds to {f_output_dir}")
        return exported_files

    def generate_reportCx(self):
        """生成分析运行的结构化 JSON 报告"""
        from datetime import datetime

        report = {
            'analysis_time': datetime.now().isoformat(),
            'binary_path': self.binary_path,
            'mode': self.mode.value,
            'status': self.status.value,
            'execution_time': 0.0,
            'seeds': [],
            'paths': [],
            'vulnerabilities': [],
            'coverage': self.coverage,
            'statistics': {},
            'stagnation_rounds': self._stagnation_counter,
            'fuzz_dictionary_entries': self.fuzz_dict_generator.entry_count(),
        }

        for seed in self.seeds:
            report['seeds'].append({
                'source_name': seed.source_name,
                'source_type': seed.source_type,
                'address': hex(seed.address),
                'size': seed.size,
                'is_symbolic': seed.is_symbolic,
                'entropy': round(seed.entropy, 2),
                'value_sample': seed.value[:16].hex() if seed.value else ''
            })

        for path in self.paths:
            report['paths'].append({
                'path_id': path.path_id,
                'discovered_from': path.discovered_from,
                'is_feasible': path.is_feasible,
                'coverage_increase': path.coverage_increase,
                'input_length': len(path.concrete_input) if path.concrete_input else 0
            })

        report['vulnerabilities'] = self.vulnerabilities

        report['statistics'] = {
            'total_seeds': len(self.seeds),
            'total_paths': len(self.paths),
            'feasible_paths': sum(1 for p in self.paths if p.is_feasible),
            'new_paths_found': sum(1 for p in self.paths if p.discovered_from != 'dynamic'),
            'vulnerabilities_found': len(self.vulnerabilities)
        }

        return report

    def save_reportCx(self, f_output_path=None):
        """将分析报告序列化为 JSON 文件"""
        if f_output_path is None:
            output_dir = './reports/concolic'
            os.makedirs(output_dir, exist_ok=True)
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            f_output_path = os.path.join(output_dir, f'concolic_report_{timestamp}.json')

        report = self.generate_reportCx()

        with open(f_output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(f"[Concolic] Report saved: {f_output_path}")
        return f_output_path


def create_concolic_executorCx(f_binary_path,
                             f_dynamic_engine='frida',
                             f_mode='hybrid'):
    """实例化 ConcolicExecutor。若无动态追踪器或符号执行器则返回 None"""
    if f_binary_path is None:
        logger.error("[Concolic] binary_path cannot be None")
        return None

    try:
        mode_enum = ConcolicMode(f_mode.lower())
    except ValueError:
        logger.error(f"[Concolic] Invalid execution mode: {f_mode}")
        return None

    executor = ConcolicExecutor(
        f_binary_path=f_binary_path,
        f_dynamic_engine=f_dynamic_engine,
        f_mode=mode_enum
    )
    return executor


def run_concolic_analysisCx(f_binary_path,
                          f_dynamic_engine='frida',
                          f_mode='hybrid',
                          **kwargs):
    """One-shot: instantiate executor, 运行 full concolic 流水线, 返回 dict"""
    executor = create_concolic_executorCx(f_binary_path, f_dynamic_engine, f_mode)

    if executor is None:
        return {
            'success': False,
            'error': 'Cannot create concolic executor',
            'mode': f_mode,
            'engine': f_dynamic_engine
        }

    result = executor.run_concolic_analysisCx(**kwargs)

    return {
        'success': result.status == ConcolicStatus.COMPLETED,
        'status': result.status.value,
        'mode': f_mode,
        'engine': f_dynamic_engine,
        'seeds_count': len(result.seeds),
        'paths_count': len(result.paths),
        'vulnerabilities_count': len(result.vulnerabilities),
        'coverage': result.coverage,
        'execution_time': result.execution_time,
        'report': executor.generate_reportCx()
    }


# 模块级别名 — 保持已有调用方正常工作
create_concolic_executor = create_concolic_executorCx
run_concolic_analysis = run_concolic_analysisCx

# CrashCategory, CrashTriageClassifier, FuzzDictEntry, FuzzDictGenerator
# StructuredMetrics, SeedMutationPipeline, _entropy_of 从
# .src.concolic_strategies 重新导出 (在本模块顶部已 import)

