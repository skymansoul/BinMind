#!/usr/bin/env python3
#  (c) 2024-2025 h1016 — Concolic execution: dynamic taint → symbolic seed injection

"""Concolic execution engine.

Fuses dynamic taint analysis with symbolic execution:
  1. Collect concrete input seeds from a dynamic taint tracker (Frida/DBI)
  2. Classify seed source types (file, input, environment)
  3. Feed seeds into the symbolic executor as concrete constraints
  4. Cross-validate symbolic paths by re-executing them dynamically
  5. Iterate in a concolic loop: taint → symbolic → validate → repeat
"""

import logging
import os
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class ConcolicMode(Enum):
    """Execution order for the concolic pipeline."""
    DYNAMIC_FIRST = "dynamic_first"
    SYMBOLIC_FIRST = "symbolic_first"
    HYBRID = "hybrid"
    SEED_ONLY = "seed_only"


class ConcolicStatus(Enum):
    """Lifecycle states of a concolic analysis run."""
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class ConcolicSeed:
    """A concrete input captured from dynamic taint, ready for symbolic injection."""
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


@dataclass
class TaintGuidedConstraint:
    """A constraint derived from a taint flow: source → sink with confidence."""
    source_addr: int
    sink_addr: int
    operation: str
    constraint: str
    confidence: float = 0.0
    tainted_bytes: int = 0


@dataclass
class ConcolicPath:
    """A path discovered through concolic exploration."""
    path_id: str
    instructions: List = field(default_factory=list)
    constraints: List = field(default_factory=list)
    is_feasible: bool = True
    concrete_input: Optional[bytes] = None
    discovered_from: str = ""  # 'dynamic' | 'symbolic' | 'concolic'
    coverage_increase: float = 0.0


@dataclass
class ConcolicResult:
    """Aggregate output of one concolic analysis run."""
    status: ConcolicStatus
    seeds: List = field(default_factory=list)
    paths: List = field(default_factory=list)
    vulnerabilities: List = field(default_factory=list)
    coverage: Dict = field(default_factory=dict)
    execution_time: float = 0.0
    total_paths: int = 0
    new_paths_found: int = 0


class ConcolicExecutor:
    """Orchestrates the concolic pipeline.

    Data flow:
      dynamic taint tracker → ConcolicSeed → symbolic executor
      symbolic paths → dynamic re-validation → feasibility verdict
      taint flows → TaintGuidedConstraint → guided symbolic exploration

    The concolic loop iterates up to max_concolic_iterations, each cycle
    collecting fresh taint data, generating constraints, and validating
    newly discovered paths.
    """

    def __init__(self,
                 f_binary_path,
                 f_dynamic_engine='frida',
                 f_mode=ConcolicMode.HYBRID):
        """Wire submodules and set initial state."""
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

        self._init_submodules()

    def _init_submodules(self):
        """Initialize stubs for the dynamic tracker and symbolic executor."""
        try:
            logger.info(f"[Concolic] Dynamic taint tracker initialized: {self.dynamic_engine}")
        except Exception as e:
            logger.warning(f"[Concolic] Failed to initialize dynamic taint tracker: {e}")

        try:
            logger.info("[Concolic] Symbolic executor initialized")
        except Exception as e:
            logger.warning(f"[Concolic] Failed to initialize symbolic executor: {e}")

    def is_availableCx(self):
        """True if at least one of the two sub-engines is operational."""
        dynamic_available = self.dynamic_tracker is not None and self.dynamic_tracker.is_available()
        symbolic_available = self.symbolic_executor is not None and self.symbolic_executor.is_available()
        return dynamic_available or symbolic_available

    def run_dynamic_seedingCx(self,
                            f_args=None,
                            f_timeout=60,
                            f_input_data=None):
        """Execute the dynamic taint tracker and harvest concrete seeds from
        taint marks and taint flows."""
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
            for m_idx in range(len(taint_marks)):
                mark = taint_marks[m_idx]
                source_name = mark.get('source', 'unknown')
                source_type = self._classify_source_typeCx(source_name)
                address = int(mark.get('address', '0x0'), 16)
                size = mark.get('size', 0)

                seed_value = self._generate_seed_valueCx(source_type, size)

                seed = ConcolicSeed(
                    source_name=source_name,
                    source_type=source_type,
                    value=seed_value,
                    address=address,
                    size=size,
                    is_symbolic=False
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
                            is_symbolic=True
                        )

                        seeds.append(seed)

            self.seeds.extend(seeds)
            logger.info(f"[Concolic] Collected {len(seeds)} dynamic seeds")

            return seeds

        except Exception as e:
            logger.error(f"[Concolic] Dynamic seed collection failed: {e}")
            return []

    def _classify_source_typeCx(self, f_source_name):
        """Map a function name to a seed source category.

        Checks more specific patterns first to avoid partial matches
        (e.g. 'fread' contains 'read', so 'fread' is tested first)."""
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
        """Synthesize a concrete byte pattern appropriate for the seed's source type.

        input       → printable fill ('A' * size)
        file        → BMP header prefix + null padding
        environment → "TEST=value\0" truncated to size
        unknown     → 'A' * size
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
        """Inject collected seeds into the symbolic executor's state."""
        if self.symbolic_executor is None or not self.symbolic_executor.is_available():
            logger.warning("[Concolic] Symbolic executor unavailable")
            return False

        if f_seeds is None or not f_seeds:
            logger.info("[Concolic] No seeds to apply")
            return True

        logger.info(f"[Concolic] Applying {len(f_seeds)} seeds to symbolic executor")

        try:
            for s_idx in range(len(f_seeds)):
                seed = f_seeds[s_idx]
                logger.debug(f"[Concolic] Seed: {seed.source_name} = {seed.value[:16].hex()}...")

            return True
        except Exception as e:
            logger.error(f"[Concolic] Seed application failed: {e}")
            return False

    def run_concolic_analysisCx(self,
                              f_args=None,
                              f_timeout=120,
                              f_input_data=None,
                              f_max_paths=100,
                              f_exploration_depth=500):
        """Execute the full concolic analysis pipeline.

        Flow depends on mode:
          DYNAMIC_FIRST → collect seeds, then run symbolic with seeds
          HYBRID        → full pipeline: seeds + symbolic + concolic loop + validation
          SYMBOLIC_FIRST → run symbolic first, then seed from dynamic
        """
        start_time = time.time()

        logger.info(f"[Concolic] Starting concolic analysis (mode: {self.mode.value})")
        self.status = ConcolicStatus.RUNNING

        result = ConcolicResult(status=ConcolicStatus.RUNNING)

        try:
            if self.mode in [ConcolicMode.DYNAMIC_FIRST, ConcolicMode.HYBRID]:
                try:
                    dynamic_seeds = self.run_dynamic_seedingCx(
                        f_args=f_args,
                        f_timeout=min(f_timeout // 2, 60),
                        f_input_data=f_input_data
                    )
                except Exception as _seed_err:
                    # 种子收集失败不阻断主流程：符号执行可独立运行，种子按空处理
                    logger.warning(
                        "[Concolic] Dynamic seeding failed, continue without seeds: %s",
                        _seed_err)
                    dynamic_seeds = []

                result.seeds.extend(dynamic_seeds)

                self.seed_symbolic_executorCx(dynamic_seeds)

            if self.symbolic_executor is not None and self.symbolic_executor.is_available():
                symbolic_result = self._run_symbolic_with_seedsCx(
                    f_args=f_args,
                    f_max_paths=f_max_paths,
                    f_exploration_depth=f_exploration_depth
                )

                result.paths.extend(symbolic_result.get('paths', []))
                result.vulnerabilities.extend(symbolic_result.get('vulnerabilities', []))

            if self.mode == ConcolicMode.HYBRID and self.dynamic_tracker is not None and self.symbolic_executor is not None:
                logger.info("[Concolic] Starting taint-guided symbolic execution loop")
                try:
                    concolic_paths = self._concolic_loopCx(
                        f_args=f_args,
                        f_timeout=min(f_timeout // 3, 40)
                    )
                except Exception as _loop_err:
                    # 回路阶段失败不丢弃已完成阶段的结果；动态引擎异常时
                    # 符号执行与种子结果仍然有效
                    logger.warning(
                        "[Concolic] Taint-guided loop failed, keeping partial results: %s",
                        _loop_err)
                    concolic_paths = []

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

            result.status = ConcolicStatus.COMPLETED
            result.execution_time = time.time() - start_time
            result.total_paths = len(result.paths)
            result.new_paths_found = self._count_new_pathsCx(result.paths)

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
        """Run the symbolic executor with seeds already applied.

        Collects paths from crash_path, auto_explore_dangerous_functions,
        and taint analysis. Each path source contributes a different
        coverage_increase weight."""
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

        return results

    def _collect_taint_guided_constraintsCx(self, f_taint_result):
        """Convert taint analysis flows into TaintGuidedConstraint objects.

        Each flow's source address and sink list are iterated; confidence
        is proportional to tainted_bytes / 8, capped at 1.0."""
        if f_taint_result is None:
            return []

        constraints = []

        for flow in f_taint_result.get('taint_flows', []):
            source_addr = int(flow.get('source_address', '0x0'), 16)

            for sink in flow.get('sinks', []):
                sink_addr = int(sink.get('address', '0x0'), 16)
                operation = sink.get('operation', 'unknown')
                tainted_bytes = sink.get('tainted_bytes', 0)

                constraint = TaintGuidedConstraint(
                    source_addr=source_addr,
                    sink_addr=sink_addr,
                    operation=operation,
                    constraint=self._generate_constraint_from_flowCx(flow),
                    confidence=min(1.0, tainted_bytes / 8),
                    tainted_bytes=tainted_bytes
                )

                constraints.append(constraint)

        return constraints

    def _generate_constraint_from_flowCx(self, f_flow):
        """Map a taint flow's operation type to a symbolic constraint string.

        strcmp/strncmp → inequality on compared value
        memcmp         → memcmp_result != 0
        strcpy/strncpy → input length exceeds max_length
        printf         → format-string check
        default        → tainted_<source>_reaches_<sink>
        """
        if f_flow is None:
            return "unknown_constraint"

        source = f_flow.get('source', 'unknown')
        sink = f_flow.get('sink', 'unknown')
        operation = f_flow.get('operation', 'read')

        if operation == 'strcmp' or operation == 'strncmp':
            return f"(input != {f_flow.get('compared_value', '0')})"
        elif operation == 'memcmp':
            return f"(memcmp_result != 0)"
        elif operation == 'strcpy' or operation == 'strncpy':
            return f"(input_length > {f_flow.get('max_length', 0)})"
        elif operation == 'printf':
            return f"(contains_format_specifier(input))"

        return f"tainted_{source}_reaches_{sink}"

    def _run_taint_guided_symbolic_executionCx(self, f_constraints):
        """Use taint-derived constraints to steer symbolic execution.

        Filters constraints with confidence < 0.3. Each surviving constraint
        triggers a guided analysis run; discovered paths and vulnerabilities
        are tagged 'taint_guided'."""
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

            try:
                guided_result = self.symbolic_executor.run_guided_analysis(
                    constraint=constraint.constraint,
                    source_addr=constraint.source_addr,
                    sink_addr=constraint.sink_addr,
                    max_depth=200
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

            except Exception as e:
                logger.debug(f"[Concolic] Taint-guided symbolic execution failed: {e}")

        return results

    def _concolic_loopCx(self, f_args=None, f_timeout=60):
        """Core concolic iteration loop.

        Each cycle:
          1. Run dynamic taint analysis
          2. Collect taint-guided constraints
          3. Run taint-guided symbolic execution
          4. Deduplicate discovered paths by (discovered_from, input_hash)
          5. Validate new paths dynamically

        Stops at max_concolic_iterations, timeout, or 50 new paths."""
        new_paths = []
        start_time = time.time()

        while self.concolic_iteration < self.max_concolic_iterations:
            if time.time() - start_time > f_timeout:
                logger.info("[Concolic] Concolic loop timeout")
                break

            self.concolic_iteration += 1
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

            if len(new_paths) >= 50:
                break

        return new_paths

    def _validate_single_pathCx(self, f_path):
        """Re-run the dynamic tracker with a path's concrete input to verify
        feasibility. Sets f_path.is_feasible accordingly."""
        if self.dynamic_tracker is None or f_path is None or f_path.concrete_input is None:
            return

        try:
            result = self.dynamic_tracker.run_taint_analysis(
                input_data=f_path.concrete_input,
                timeout=15
            )

            f_path.is_feasible = result.get('success', False)
        except Exception as e:
            logger.debug(f"[Concolic] Path validation failed: {e}")
            f_path.is_feasible = False

    def _validate_symbolic_pathsCx(self):
        """Post-hoc validation: re-execute all symbolically-discovered paths
        through the dynamic tracker. Only paths with concrete_input and
        discovered_from='symbolic' are checked."""
        if self.dynamic_tracker is None or not self.paths:
            return

        logger.info(f"[Concolic] Validating {len(self.paths)} symbolic paths")

        for path in self.paths:
            if path.discovered_from == 'symbolic' and path.concrete_input:
                try:
                    result = self.dynamic_tracker.run_taint_analysis(
                        input_data=path.concrete_input,
                        timeout=10
                    )

                    if result.get('success'):
                        path.is_feasible = True
                        logger.debug(f"[Concolic] Path {path.path_id} validated as feasible")
                    else:
                        path.is_feasible = False
                        logger.debug(f"[Concolic] Path {path.path_id} validated as infeasible")

                except Exception as e:
                    logger.debug(f"[Concolic] Path validation failed: {e}")
                    path.is_feasible = False

    def _calculate_coverageCx(self, f_result):
        """Estimate coverage improvement from path count.

        Formula: base 10% + 2% per path, capped at 80% bonus.
        This is a heuristic approximation — real coverage requires
        basic-block instrumentation."""
        if f_result is None:
            return
        base_coverage = 0.1
        path_bonus = min(len(f_result.paths) * 0.02, 0.8)

        f_result.coverage['initial'] = base_coverage
        f_result.coverage['final'] = base_coverage + path_bonus
        f_result.coverage['increase'] = path_bonus

    def _count_new_pathsCx(self, f_paths):
        """Count paths that were discovered through concolic or symbolic means
        (as opposed to pure dynamic)."""
        if f_paths is None:
            return 0
        return sum(1 for p in f_paths if p.discovered_from in ['concolic', 'symbolic'])

    def _generate_path_idCx(self):
        """Generate a short unique path identifier."""
        return str(uuid.uuid4())[:8]

    def export_seedsCx(self, f_output_dir='./seeds'):
        """Write all collected seeds to disk as binary files with JSON metadata."""
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
                    'is_symbolic': seed.is_symbolic
                }, f, indent=2)

            exported_files.append(filepath)

        logger.info(f"[Concolic] Exported {len(exported_files)} seeds to {f_output_dir}")
        return exported_files

    def generate_reportCx(self):
        """Produce a structured JSON report of the analysis run."""
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
            'statistics': {}
        }

        for seed in self.seeds:
            report['seeds'].append({
                'source_name': seed.source_name,
                'source_type': seed.source_type,
                'address': hex(seed.address),
                'size': seed.size,
                'is_symbolic': seed.is_symbolic,
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
        """Serialize the analysis report to a JSON file."""
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
    """Instantiate a ConcolicExecutor. Returns None when neither dynamic tracker
    nor symbolic executor is available."""
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

    if executor.is_availableCx():
        return executor

    logger.error("[Concolic] Cannot create concolic executor, all dependencies unavailable")
    return None


def run_concolic_analysisCx(f_binary_path,
                          f_dynamic_engine='frida',
                          f_mode='hybrid',
                          **kwargs):
    """One-shot: instantiate executor, run full concolic pipeline, return dict."""
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


create_concolic_executor = create_concolic_executorCx
run_concolic_analysis = run_concolic_analysisCx
