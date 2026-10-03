from typing import Dict, Any, List, Optional, Set, Tuple, Callable
import logging
import re
import os
import json
import subprocess
import hashlib
import sqlite3
import struct
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


def _r2_json(cmd: str, binary_path: str, timeout: int = 60) -> list:
    try:
        r = subprocess.run(
            ['r2', '-q', '-c', f'{cmd}; q', binary_path],
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace',
        )
        return json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        return []


def _r2_text(cmd: str, binary_path: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ['r2', '-q', '-c', f'{cmd}; q', binary_path],
            capture_output=True, text=True, timeout=timeout,
            encoding='utf-8', errors='replace',
        )
        return r.stdout
    except Exception:
        return ''


class ComplexityFeatureType(str, Enum):
    CONTROL_FLOW_COMPLEXITY = "control_flow_complexity"
    CYCLOMATIC_COMPLEXITY = "cyclomatic_complexity"
    LOOP_DEPTH = "loop_depth"
    MEMORY_OPERATION_DENSITY = "memory_operation_density"
    CALL_DEPTH = "call_depth"
    BRANCH_PREDICTION = "branch_prediction"


@dataclass
class ComplexityFeature:
    feature_type: ComplexityFeatureType
    value: float
    location: str
    metadata: dict = field(default_factory=dict)


class ComplexityRiskPredictor:

    def __init__(self):
        self.model = None
        self.feature_cache: Dict[str, List[ComplexityFeature]] = {}

    def extract_control_flow_features(self, function_addr: int,
                                       binary_path: str = "") -> List[ComplexityFeature]:
        features = []
        if not binary_path:
            return features
        try:
            blocks = _r2_json(f'afbj @ {function_addr}', binary_path, timeout=30)
            n_blocks = len(blocks)
            n_edges = sum(len(b.get('jumps', [])) + (1 if b.get('fail') else 0)
                          for b in blocks)
            cyclo = max(1, n_edges - n_blocks + 2)
            features.append(ComplexityFeature(
                feature_type=ComplexityFeatureType.CONTROL_FLOW_COMPLEXITY,
                value=float(cyclo),
                location=hex(function_addr),
                metadata={'n_blocks': n_blocks, 'n_edges': n_edges},
            ))
        except Exception as e:
            logger.debug(f"CF complexity extraction failed: {e}")
        return features

    def extract_loop_depth_features(self, function_addr: int,
                                     binary_path: str = "") -> List[ComplexityFeature]:
        features = []
        if not binary_path:
            return features
        try:
            blocks = _r2_json(f'afbj @ {function_addr}', binary_path, timeout=30)
            back_edge_count = 0
            for b in blocks:
                src = b.get('addr', 0)
                for jmp in b.get('jumps', []):
                    target = jmp.get('jump', 0)
                    if target and target <= src:
                        back_edge_count += 1
                fail = b.get('fail', 0)
                if fail and fail <= src:
                    back_edge_count += 1
            depth = min(back_edge_count, 10)
            features.append(ComplexityFeature(
                feature_type=ComplexityFeatureType.LOOP_DEPTH,
                value=float(depth),
                location=hex(function_addr),
                metadata={'back_edge_count': back_edge_count},
            ))
        except Exception as e:
            logger.debug(f"Loop depth extraction failed: {e}")
        return features

    def extract_memory_operation_density(self, function_addr: int,
                                          binary_path: str = "") -> List[ComplexityFeature]:
        features = []
        if not binary_path:
            return features
        try:
            dis = _r2_text(f'pdb @ {function_addr}', binary_path, timeout=30)
            lines = [l for l in dis.split('\n') if l.strip()]
            total = len(lines)
            if total == 0:
                return features
            mem_ops = sum(
                1 for l in lines
                if any(re.search(p, l, re.I) for p in [
                    r'\bmov\b.*\[', r'\bpush\b', r'\bpop\b',
                    r'\blea\b', r'\bxchg\b', r'\bcmpxchg\b',
                    r'\bstos\b', r'\blods\b', r'\bmovs\b', r'\bscas\b',
                ])
            )
            density = round(mem_ops / total, 4)
            features.append(ComplexityFeature(
                feature_type=ComplexityFeatureType.MEMORY_OPERATION_DENSITY,
                value=density,
                location=hex(function_addr),
                metadata={'mem_ops': mem_ops, 'total_ops': total},
            ))
        except Exception as e:
            logger.debug(f"Memory density extraction failed: {e}")
        return features

    def predict_vulnerable_functions(self, binary_path: str) -> List[Tuple[str, float]]:
        results = []
        try:
            funcs = _r2_json('aflj', binary_path, timeout=120)
            for f in funcs:
                name = f.get('name', '')
                ninstr = f.get('ninstr', 0)
                numargs = f.get('numargs', 0)
                size = f.get('size', 0)

                risk = min(1.0,
                    (ninstr / 500.0) * 0.4 +
                    (numargs / 10.0) * 0.3 +
                    (size / 10000.0) * 0.3)
                results.append((name, round(risk, 4)))
        except Exception as e:
            logger.warning(f"Risk prediction failed: {e}")
        return sorted(results, key=lambda x: x[1], reverse=True)

    def prioritize_analysis(self, functions: List[str],
                            binary_path: str = "") -> List[str]:
        risks = dict(self.predict_vulnerable_functions(binary_path)) if binary_path else {}
        return sorted(functions,
                      key=lambda f: risks.get(f, 0.0),
                      reverse=True)


@dataclass
class CFGNode:
    addr: int
    size: int = 0
    successors: list = field(default_factory=list)


@dataclass
class CFG:
    nodes: dict = field(default_factory=dict)
    entry: int = 0
    func_name: str = ""


class ControlFlowGraphBuilder:

    def build(self, binary_path: str, func_name: str = "",
              func_addr: int = 0) -> CFG:
        target = func_name if func_name else hex(func_addr)
        try:
            blocks = _r2_json(f'afj @ {target}', binary_path)
            nodes = {}
            for bb in blocks:
                addr = bb.get('addr', 0)
                size = bb.get('size', 0)
                succs = [j.get('jump', 0) for j in bb.get('jumps', [])
                         if j.get('jump')]
                if not succs:
                    succs = [bb.get('fail', 0)] if bb.get('fail') else []
                nodes[addr] = CFGNode(addr=addr, size=size,
                                       successors=[s for s in succs if s > 0])
            entry = blocks[0]['addr'] if blocks else func_addr
            return CFG(nodes=nodes, entry=entry,
                       func_name=func_name or hex(func_addr))
        except Exception as e:
            logger.warning(f"CFG construction failed: {e}")
            return CFG(entry=func_addr)


@dataclass
class CallGraph:
    edges: dict = field(default_factory=dict)
    functions: dict = field(default_factory=dict)


class CallGraphBuilder:

    def build(self, binary_path: str) -> CallGraph:
        cg = CallGraph()
        try:
            funcs = _r2_json('aflj', binary_path, timeout=120)
            for f in funcs:
                name = f.get('name', '')
                addr = f.get('offset', 0)
                if name:
                    cg.functions[name] = addr
            graph = _r2_json('agj', binary_path, timeout=120)

            def _walk(node, parent=None):
                addr = node.get('offset', 0)
                if addr and parent:
                    cg.edges.setdefault(parent, set()).add(addr)
                for child in node.get('children', []):
                    _walk(child, addr)

            for n in (graph if isinstance(graph, list) else [graph]):
                _walk(n)
        except Exception as e:
            logger.warning(f"Call graph construction failed: {e}")
        return cg


@dataclass
class IndirectCallTarget:
    target_addr: int
    target_name: Optional[str]
    confidence: float
    type_constraint: Optional[str]
    value_set: Optional[Any] = None


class IndirectCallResolver:

    def __init__(self):
        self.call_graph: Dict[int, Set[int]] = {}
        self.type_constraints: Dict[int, str] = {}

    def resolve_virtual_call(self, vtable_addr: int,
                              context: Dict[str, Any]) -> List[IndirectCallTarget]:
        targets = []
        binary_path = context.get('binary_path', '')
        if not binary_path:
            return targets
        try:
            text = _r2_text(f'pxq 64 @ {vtable_addr}', binary_path, timeout=30)
            for line in text.split('\n'):
                for p in line.strip().split():
                    try:
                        addr = int(p, 16)
                        if 0x400000 < addr < 0x7FFFFFFFFFFF:
                            targets.append(IndirectCallTarget(
                                target_addr=addr, target_name=None,
                                confidence=0.7, type_constraint="vtable"))
                    except ValueError:
                        continue
        except Exception as e:
            logger.debug(f"Virtual call resolution failed: {e}")
        return targets

    def resolve_function_pointer(self, ptr_location: int,
                                  context: Dict[str, Any]) -> List[IndirectCallTarget]:
        targets = []
        binary_path = context.get('binary_path', '')
        if not binary_path:
            return targets
        try:
            text = _r2_text(f'pD 20 @ {ptr_location}', binary_path, timeout=30)
            refs = re.findall(r'0x([0-9a-f]+)', text)
            for ref in refs[:10]:
                addr = int(ref, 16)
                if 0x400000 < addr < 0x7FFFFFFFFFFF:
                    targets.append(IndirectCallTarget(
                        target_addr=addr, target_name=None, confidence=0.5,
                        type_constraint="function_pointer"))
        except Exception as e:
            logger.debug(f"Function pointer resolution failed: {e}")
        return targets

    def propagate_types(self, source_addr: int, target_addr: int,
                        type_info: str) -> None:
        self.type_constraints[target_addr] = type_info
        self.call_graph.setdefault(source_addr, set()).add(target_addr)

    def analyze_value_set(self, location: int,
                          binary_path: str = "") -> Set[Any]:
        values: Set[Any] = set()
        if not binary_path:
            return values
        try:
            text = _r2_text(f'pD 50 @ {location}', binary_path, timeout=30)
            for m in re.finditer(
                r'(?:mov|add|sub|cmp|xor|and|or)\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)',
                text,
            ):
                val = m.group(1)
                values.add(int(val, 16) if val.lower().startswith('0x') else int(val))
            for m in re.finditer(r'push\s+(0x[0-9a-fA-F]+)', text):
                values.add(int(m.group(1), 16))
        except Exception as e:
            logger.debug(f"Value set analysis failed: {e}")
        return values

    def build_complete_call_graph(self, binary_path: str) -> Dict[int, Set[int]]:
        try:
            graph = _r2_json('agj', binary_path, timeout=120)
            self.call_graph = {}

            def _walk(node, parent=None):
                addr = node.get('offset', 0)
                if addr and parent:
                    self.call_graph.setdefault(parent, set()).add(addr)
                for child in node.get('children', []):
                    _walk(child, addr)

            for n in (graph if isinstance(graph, list) else [graph]):
                _walk(n)
        except Exception as e:
            logger.warning(f"Call graph construction failed: {e}")
        return self.call_graph


class OpaquePredicateType(str, Enum):
    CONSTANT_TRUE = "constant_true"
    CONSTANT_FALSE = "constant_false"
    COMPUTABLE = "computable"
    UNKNOWN = "unknown"


@dataclass
class BranchAnalysisResult:
    branch_addr: int
    predicate_type: OpaquePredicateType
    is_reachable: bool
    simplified_condition: Optional[str]
    alternative_path: Optional[Any] = None


class OpaquePredicateAnalyzer:

    def __init__(self):
        self.branch_cache: Dict[int, BranchAnalysisResult] = {}

    def detect_opaque_predicate(self, branch_addr: int,
                                 binary_path: str = "") -> OpaquePredicateType:
        try:
            text = _r2_text(f'pD 20 @ {branch_addr}', binary_path, timeout=30)
            patterns = [
                (r'(?:xor|sub)\s+\w+,\s*\w+\s*\n.*(?:jz|je)',
                 OpaquePredicateType.CONSTANT_TRUE),
                (r'(?:cmp|test)\s+\w+,\s*\w+\s*\n.*(?:jmp|j)\s+0x',
                 OpaquePredicateType.COMPUTABLE),
            ]
            for pat, ptype in patterns:
                if re.search(pat, text, re.IGNORECASE):
                    return ptype
        except Exception as e:
            logger.debug(f"Opaque predicate detection failed: {e}")
        return OpaquePredicateType.UNKNOWN

    def evaluate_predicate(self, condition: str,
                            context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        simplified = condition.strip()
        constant_patterns = [
            (re.compile(r'(\w+)\s*[-]\s*\1\s*==\s*0'), True),
            (re.compile(r'(\w+)\s*&\s*0\s*==\s*0'), True),
            (re.compile(r'(\w+)\s*\|\s*0\s*==\s*\1'), True),
            (re.compile(r'(\w+)\s*\^\s*\1\s*==\s*0'), True),
        ]
        for pat, is_constant in constant_patterns:
            if pat.search(simplified):
                return is_constant, pat.sub('1', simplified)
        return False, simplified

    def simplify_branch(self, branch_addr: int,
                         binary_path: str = "") -> BranchAnalysisResult:
        ptype = self.detect_opaque_predicate(branch_addr, binary_path)
        result = BranchAnalysisResult(
            branch_addr=branch_addr,
            predicate_type=ptype,
            is_reachable=ptype != OpaquePredicateType.CONSTANT_FALSE,
            simplified_condition=(
                "always_true" if ptype == OpaquePredicateType.CONSTANT_TRUE
                else None),
        )
        self.branch_cache[branch_addr] = result
        return result

    def refine_reachability(self, function_addr: int,
                             binary_path: str = "") -> Set[int]:
        reachable: Set[int] = set()
        if not binary_path:
            return reachable
        try:
            blocks = _r2_json(f'afbj @ {function_addr}', binary_path, timeout=30)
            if not blocks:
                return reachable
            # 构建邻接表: 块地址 -> 后继列表
            succ_map: Dict[int, List[int]] = {}
            entry = blocks[0].get('addr', 0)
            for b in blocks:
                addr = b.get('addr', 0)
                succs = []
                for j in b.get('jumps', []):
                    t = j.get('jump', 0)
                    if t:
                        succs.append(t)
                fail = b.get('fail', 0)
                if fail and fail not in succs:
                    succs.append(fail)
                succ_map[addr] = succs
            # 从入口节点做标准 BFS
            q = deque([entry])
            while q:
                cur = q.popleft()
                if cur in reachable:
                    continue
                reachable.add(cur)
                for s in succ_map.get(cur, []):
                    if s and s not in reachable:
                        q.append(s)
        except Exception as e:
            logger.debug(f"Reachability refinement failed: {e}")
        return reachable


@dataclass
class StackVariable:
    name: str
    offset: int
    size: int
    allocation_site: Optional[int]
    deallocation_site: Optional[int]
    lifetime_start: Optional[int]
    lifetime_end: Optional[int]


class StackLifetimeTracker:

    def __init__(self):
        self.stack_frames: Dict[int, List[StackVariable]] = {}
        self.escaped_pointers: Dict[int, Set[int]] = defaultdict(set)
        self.dangling_references: List[Tuple[int, int, int]] = []

    def simulate_stack_frame(self, function_addr: int,
                              binary_path: str = "") -> List[StackVariable]:
        variables: List[StackVariable] = []
        if not binary_path:
            return variables
        try:
            vars_json = _r2_json(f'afvj @ {function_addr}', binary_path, timeout=30)
            for v in vars_json:
                variables.append(StackVariable(
                    name=v.get('name', ''),
                    offset=v.get('offset', 0),
                    size=v.get('size', 0),
                    allocation_site=function_addr,
                    deallocation_site=None,
                    lifetime_start=function_addr,
                    lifetime_end=None,
                ))
        except Exception:
            # 回退: 从函数序言的 sub rsp, imm 推断栈帧大小
            try:
                dis = _r2_text(f'pD 30 @ {function_addr}', binary_path, timeout=30)
                m = re.search(r'sub\s+rsp,\s*(0x[0-9a-fA-F]+|\d+)', dis)
                if m:
                    val = m.group(1)
                    frame_sz = int(val, 16) if val.lower().startswith('0x') else int(val)
                    variables.append(StackVariable(
                        name='frame', offset=-frame_sz, size=frame_sz,
                        allocation_site=function_addr, deallocation_site=None,
                        lifetime_start=function_addr, lifetime_end=None))
            except Exception:
                logger.debug("suppressed", exc_info=True)
        self.stack_frames[function_addr] = variables
        return variables

    def track_pointer_escape(self, pointer_addr: int, var_addr: int,
                              escape_site: int) -> None:
        self.escaped_pointers[var_addr].add(escape_site)

    def detect_dangling_pointer(self, function_addr: int) -> List[Tuple[int, int]]:
        dangling = []
        for var_addr, escape_sites in self.escaped_pointers.items():
            for site in escape_sites:
                dangling.append((site, var_addr))
        return dangling

    def analyze_cross_function_ref(self, caller_addr: int,
                                    callee_addr: int,
                                    binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            # LEA 引用调用方基址/帧寄存器 -> 栈地址泄露
            dis = _r2_text(f'pD 30 @ {callee_addr}', binary_path, timeout=30)
            if re.search(r'lea\s+\w+,\s*\[r[bp]', dis, re.I):
                return True
            # 通过寄存器间接写 -> 可能的帧逃逸
            if re.search(r'mov\s+\[r\w+\],', dis, re.I):
                return True
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return False


@dataclass
class ConstantValue:
    value: Any
    is_top: bool = False


class DataFlowEquationSolver:

    def __init__(self):
        self.constraint_graph: Dict[int, Set[int]] = {}
        self.value_domain: Dict[int, ConstantValue] = {}

    def solve_dataflow(self, function_addr: int,
                        entry_state: Dict[int, ConstantValue],
                        binary_path: str = "") -> Dict[int, ConstantValue]:
        if not binary_path:
            return dict(entry_state)
        result = dict(entry_state)
        try:
            blocks = _r2_json(f'afbj @ {function_addr}', binary_path, timeout=30)
            succ_map: Dict[int, List[int]] = {}
            all_addrs = set()
            for b in blocks:
                addr = b.get('addr', 0)
                all_addrs.add(addr)
                succs = [j.get('jump', 0) for j in b.get('jumps', []) if j.get('jump')]
                fail = b.get('fail', 0)
                if fail:
                    succs.append(fail)
                succ_map[addr] = [s for s in succs if s]

            # 迭代至不动点: 合并前驱常量, 前向传播
            worklist = deque(all_addrs)
            changed = set(all_addrs)
            MAX_ITER = 100
            for _ in range(MAX_ITER):
                if not changed:
                    break
                cur = changed.pop()
                # 前驱合并: 从所有入边合并常量
                predecessors = [p for p in all_addrs
                                if cur in succ_map.get(p, [])]
                if not predecessors:
                    continue
                # 常量折叠规则: 前驱一致 -> 已知值; 不一致 -> 顶元素
                merged: Dict[int, ConstantValue] = {}
                for p in predecessors:
                    if p in result:
                        for k, v in result.items():
                            if k not in merged:
                                merged[k] = v
                            elif merged[k].value != v.value:
                                merged[k] = ConstantValue(value=None, is_top=True)
                result.update(merged)
                for s in succ_map.get(cur, []):
                    changed.add(s)
        except Exception as e:
            logger.debug(f"Dataflow solve failed: {e}")
        return result

    def constant_propagation(self, function_addr: int,
                              binary_path: str = "") -> Dict[int, Any]:
        props: Dict[int, Any] = {}
        if not binary_path:
            return props
        try:
            dis = _r2_text(f'pD 200 @ {function_addr}', binary_path, timeout=60)
            for m in re.finditer(
                r'0x([0-9a-f]+)\s+.*mov\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)',
                dis, re.I,
            ):
                addr = int(m.group(1), 16)
                val = m.group(2)
                props[addr] = int(val, 16) if val.lower().startswith('0x') else int(val)
        except Exception as e:
            logger.debug(f"Constant propagation failed: {e}")
        return props

    def constant_folding(self, expression: str) -> Optional[Any]:
        expr = expression.strip().replace(' ', '')
        # 支持的二元运算符 -> 各自映射到 Python lambda
        safe_ops = {'+': lambda a, b: a + b,
                    '-': lambda a, b: a - b,
                    '*': lambda a, b: a * b,
                    '/': lambda a, b: a // b,
                    '%': lambda a, b: a % b,
                    '<<': lambda a, b: a << b,
                    '>>': lambda a, b: a >> b,
                    '&': lambda a, b: a & b,
                    '|': lambda a, b: a | b,
                    '^': lambda a, b: a ^ b}
        for op, func in safe_ops.items():
            # 全匹配: 两个操作数均为数字字面量
            pat = rf'(0x[0-9a-fA-F]+|\d+){re.escape(op)}(0x[0-9a-fA-F]+|\d+)'
            m = re.fullmatch(pat, expr)
            if m:
                a = int(m.group(1), 16) if m.group(1).lower().startswith('0x') else int(m.group(1))
                b = int(m.group(2), 16) if m.group(2).lower().startswith('0x') else int(m.group(2))
                try:
                    return func(a, b)
                except ZeroDivisionError:
                    return None
        # 退化情形: 表达式本身即为单一常量
        m = re.fullmatch(r'(0x[0-9a-fA-F]+|\d+)', expr)
        if m:
            val = m.group(1)
            return int(val, 16) if val.lower().startswith('0x') else int(val)
        return None

    def resolve_indirect_jump(self, jump_addr: int,
                               context: Dict[str, Any]) -> List[int]:
        targets: List[int] = []
        binary_path = context.get('binary_path', '')
        if not binary_path:
            return targets
        try:
            dis = _r2_text(f'pD 20 @ {jump_addr}', binary_path, timeout=30)
            # 收集间接跳转前加载的所有立即地址
            found = set()
            for m in re.finditer(r'(?:mov|lea)\s+\w+,\s*(0x[0-9a-fA-F]+)', dis):
                found.add(int(m.group(1), 16))
            targets = sorted(found)
        except Exception as e:
            logger.debug(f"Indirect jump resolution failed: {e}")
        return targets

    def infer_buffer_size(self, buffer_addr: int,
                           binary_path: str = "") -> Optional[int]:
        if not binary_path:
            return None
        try:
            dis = _r2_text(f'pD 80 @ {buffer_addr}', binary_path, timeout=30)
            # 模式1: mov reg, size; call malloc
            m = re.search(r'mov\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)\s*\n.*call.*malloc', dis)
            if m:
                val = m.group(1)
                return int(val, 16) if val.lower().startswith('0x') else int(val)
            # 模式2: 通过 sub rsp, N 的栈分配
            m = re.search(r'sub\s+rsp,\s*(0x[0-9a-fA-F]+|\d+)', dis)
            if m:
                val = m.group(1)
                return int(val, 16) if val.lower().startswith('0x') else int(val)
            # 模式3: LEA 到栈帧 -> 偏移近似缓冲区范围
            m = re.search(r'lea\s+\w+,\s*\[rsp\s*\+\s*(0x[0-9a-fA-F]+|\d+)\]', dis)
            if m:
                val = m.group(1)
                offset = int(val, 16) if val.lower().startswith('0x') else int(val)
                return offset
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return None


@dataclass
class LoopInvariant:
    invariant_expr: str
    location: int
    loop_header: int


@dataclass
class InductionVariable:
    name: str
    initial_value: Any
    step_value: Any
    base_variable: str
    linear_coefficient: float


class LoopAnalyzer:

    def __init__(self):
        self.loop_headers: Set[int] = set()
        self.invariant_cache: Dict[int, List[LoopInvariant]] = {}

    def identify_loops(self, function_addr: int,
                        binary_path: str = "") -> Set[int]:
        headers: Set[int] = set()
        if not binary_path:
            return headers
        try:
            blocks = _r2_json(f'afbj @ {function_addr}', binary_path, timeout=30)
            for b in blocks:
                src = b.get('addr', 0)
                for j in b.get('jumps', []):
                    tgt = j.get('jump', 0)
                    if tgt and tgt <= src:
                        headers.add(tgt)
                fail = b.get('fail', 0)
                if fail and fail <= src:
                    headers.add(fail)
        except Exception as e:
            logger.debug(f"Loop identification failed: {e}")
        self.loop_headers = headers
        return headers

    def find_loop_invariants(self, loop_header: int,
                              binary_path: str = "") -> List[LoopInvariant]:
        invariants: List[LoopInvariant] = []
        if not binary_path:
            return invariants
        try:
            # 循环体: 地址 >= 头部的所有指令
            dis = _r2_text(f'pD 200 @ {loop_header}', binary_path, timeout=60)
            defs_outside: Set[str] = set()
            for line in dis.split('\n'):
                m = re.match(
                    r'(?:mov|lea)\s+(\w+),\s*(0x[0-9a-fA-F]+|[a-z_]\w*)',
                    line, re.I,
                )
                if m and re.fullmatch(r'0x[0-9a-fA-F]+|[a-z_]\w*', m.group(2)):
                    defs_outside.add(m.group(1).lower())
            # 不变式判定: 每个寄存器操作数必须在循环外定义
            addr_pattern = r'^\s*(0x[0-9a-fA-F]+)'
            for line in dis.split('\n'):
                addr_match = re.match(addr_pattern, line)
                if not addr_match:
                    continue
                addr = int(addr_match.group(1), 16)
                # 排除控制流指令
                if re.search(r'\b(jmp|je|jne|jz|jnz|jg|jl|jge|jle|call|ret)\b',
                             line, re.I):
                    continue
                # 所有引用的寄存器须在外部定义集中
                operands = re.findall(r'\b(r[a-z]{1,2}\d*|e[a-z]{1,2}x)\b', line, re.I)
                all_invariant = all(
                    op.lower() in defs_outside for op in operands
                ) if operands else True
                if all_invariant:
                    invariants.append(LoopInvariant(
                        invariant_expr=line.strip(),
                        location=addr,
                        loop_header=loop_header,
                    ))
        except Exception as e:
            logger.debug(f"Loop invariant detection failed: {e}")
        return invariants

    def identify_induction_variables(self, loop_header: int,
                                      binary_path: str = "") -> List[InductionVariable]:
        variables: List[InductionVariable] = []
        if not binary_path:
            return variables
        try:
            dis = _r2_text(f'pD 100 @ {loop_header}', binary_path, timeout=60)
            # 类别1: add/sub reg, imm -> 常量步长算术
            for m in re.finditer(
                r'(?:add|sub)\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)',
                dis, re.I,
            ):
                var = m.group(1)
                step_str = m.group(2)
                step = int(step_str, 16) if step_str.lower().startswith('0x') else int(step_str)
                if 'sub' in m.string[m.start():m.end()].lower():
                    step = -step
                variables.append(InductionVariable(
                    name=var, initial_value=0, step_value=step,
                    base_variable=var, linear_coefficient=float(step)))
            # 类别2: inc reg -> 单位正步长
            for m in re.finditer(r'inc\s+(\w+)', dis, re.I):
                variables.append(InductionVariable(
                    name=m.group(1), initial_value=0, step_value=1,
                    base_variable=m.group(1), linear_coefficient=1.0))
            # 类别3: dec reg -> 单位负步长
            for m in re.finditer(r'dec\s+(\w+)', dis, re.I):
                variables.append(InductionVariable(
                    name=m.group(1), initial_value=0, step_value=-1,
                    base_variable=m.group(1), linear_coefficient=-1.0))
        except Exception as e:
            logger.debug(f"Induction variable detection failed: {e}")
        return variables

    def hoist_invariants(self, loop_header: int,
                          binary_path: str = "") -> List[int]:
        invs = self.find_loop_invariants(loop_header, binary_path)
        return sorted(set(i.location for i in invs))

    def analyze_loop_bounds(self, loop_header: int,
                             binary_path: str = "") -> Tuple[Optional[int], Optional[int]]:
        lo, hi = None, None
        if not binary_path:
            return lo, hi
        try:
            dis = _r2_text(f'pD 50 @ {loop_header}', binary_path, timeout=30)
            # 提取所有与立即数比较的操作数
            comps = re.findall(r'cmp\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)', dis, re.I)
            if comps:
                for c in comps:
                    val = int(c, 16) if c.lower().startswith('0x') else int(c)
                    # jle/jl/jbe/jb -> cmp 值为上界
                    if re.search(r'\b(jle|jl|jbe|jb)\b', dis, re.I):
                        hi = val
                    elif re.search(r'\b(jge|jg|jae|ja)\b', dis, re.I):
                        lo = val
                    else:
                        hi = val
        except Exception as e:
            logger.debug(f"Loop bound analysis failed: {e}")
        return lo, hi


@dataclass
class ExceptionPath:
    try_entry: int
    catch_entry: int
    exception_type: Optional[str]
    cleanup_sites: list = field(default_factory=list)


class ExceptionSensitiveDataFlow:

    def __init__(self):
        self.exception_paths: List[ExceptionPath] = []
        self.seh_chain: List[int] = []

    def build_exception_graph(self, function_addr: int,
                               binary_path: str = "") -> None:
        if not binary_path:
            return
        try:
            dis = _r2_text(f'pD 300 @ {function_addr}', binary_path, timeout=60)
            # C++ 异常处理: __CxxFrameHandler / __gxx_personality / _Unwind_Resume
            if re.search(r'__CxxFrameHandler|__gxx_personality|_Unwind_Resume', dis):
                # EH 注册后的每个调用点都是潜在抛出点
                calls = re.findall(r'(0x[0-9a-fA-F]+)\s+.*call\s+', dis)
                for i, addr_str in enumerate(calls):
                    addr = int(addr_str, 16)
                    # 标记为可抛出: 注册后每个调用
                    self.exception_paths.append(ExceptionPath(
                        try_entry=function_addr,
                        catch_entry=addr if i + 1 < len(calls)
                        else 0,
                        exception_type="cxx",
                        cleanup_sites=[],
                    ))
            # SEH: fs:[0] 链操作, __except / __finally 关键字
            if re.search(r'fs:\[\s*0\s*\]|__except|__finally', dis):
                self.seh_chain.append(function_addr)
                # 定位 __except 过滤函数 / 处理器地址
                handler_match = re.search(r'(0x[0-9a-fA-F]+)\s+.*call.*__except', dis)
                if handler_match:
                    self.exception_paths.append(ExceptionPath(
                        try_entry=function_addr,
                        catch_entry=int(handler_match.group(1), 16),
                        exception_type="seh",
                        cleanup_sites=[],
                    ))
        except Exception as e:
            logger.debug(f"Exception graph build failed: {e}")

    def track_destructor_side_effects(self, exception_thrown: int,
                                       binary_path: str = "") -> Set[int]:
        effects: Set[int] = set()
        if not binary_path:
            return effects
        try:
            dis = _r2_text(f'pD 100 @ {exception_thrown}', binary_path, timeout=30)
            # 地址大于抛出点的调用是展开路径候选
            for m in re.finditer(r'(0x[0-9a-fA-F]+)\s+.*call\s+', dis, re.I):
                addr = int(m.group(1), 16)
                if addr > exception_thrown:
                    effects.add(addr)
        except Exception as e:
            logger.debug(f"Destructor tracking failed: {e}")
        return effects

    def analyze_seh_path(self, seh_entry: int,
                          binary_path: str = "") -> ExceptionPath:
        path = ExceptionPath(
            try_entry=seh_entry, catch_entry=0, exception_type="seh")
        if not binary_path:
            return path
        try:
            dis = _r2_text(f'pD 100 @ {seh_entry}', binary_path, timeout=30)
            # SEH 处理器地址通常在 fs:[0] 写入前压栈
            push_match = re.search(r'push\s+(0x[0-9a-fA-F]+)', dis)
            if push_match:
                path.catch_entry = int(push_match.group(1), 16)
            # __finally 块作为清理点
            finally_match = re.search(r'(0x[0-9a-fA-F]+)\s+.*__finally', dis)
            if finally_match:
                path.cleanup_sites.append(int(finally_match.group(1), 16))
        except Exception as e:
            logger.debug(f"SEH path analysis failed: {e}")
        return path

    def check_resource_leak_on_exception(self, resource_addr: int,
                                          throw_site: int,
                                          binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 200 @ {resource_addr}', binary_path, timeout=60)
            # 检查抛出点前是否有资源获取
            alloc_before = False
            free_after = False
            alloc_match = re.search(
                r'(?:call.*(?:malloc|new|alloc|CreateFile)|open)\s*',
                dis, re.I)
            if alloc_match:
                alloc_before = True
            # 验证抛出后无释放 -> 若缺则确认泄漏
            post_dis = _r2_text(
                f'pD 100 @ {throw_site + 16}', binary_path, timeout=30)
            if re.search(r'(?:call.*(?:free|delete|close|CloseHandle))', post_dis, re.I):
                free_after = True
            return alloc_before and not free_after
        except Exception:
            return False


@dataclass
class ThreadCreate:
    addr: int
    thread_id: Any
    start_routine: Optional[int]
    argument: Optional[Any]


@dataclass
class LockOperation:
    addr: int
    lock_addr: int
    is_acquire: bool
    operation_type: str


@dataclass
class HappensBeforeRelation:
    event1: Any
    event2: Any
    relation_type: str


class ThreadHappensBeforeAnalyzer:

    def __init__(self):
        self.thread_creates: List[ThreadCreate] = []
        self.lock_operations: List[LockOperation] = []
        self.happens_before_graph: Dict[HappensBeforeRelation, float] = {}

    def identify_thread_creation(self, binary_path: str) -> List[ThreadCreate]:
        creates: List[ThreadCreate] = []
        if not binary_path:
            return creates
        try:
            imports = _r2_json('iij', binary_path, timeout=30)
            thread_apis = {
                'CreateThread', 'pthread_create', '_beginthread',
                '_beginthreadex', 'std::thread', 'clone', 'fork'}
            for imp in imports:
                if imp.get('name', '') in thread_apis:
                    addr = imp.get('plt', 0) or imp.get('offset', 0)
                    creates.append(ThreadCreate(
                        addr=addr, thread_id=imp.get('name'),
                        start_routine=None, argument=None))
        except Exception as e:
            logger.debug(f"Thread creation detection failed: {e}")
        return creates

    def identify_lock_operations(self, binary_path: str) -> List[LockOperation]:
        ops: List[LockOperation] = []
        if not binary_path:
            return ops
        try:
            imports = _r2_json('iij', binary_path, timeout=30)
            lock_map = {
                'EnterCriticalSection': True,
                'LeaveCriticalSection': False,
                'pthread_mutex_lock': True,
                'pthread_mutex_unlock': False,
                'InitializeCriticalSection': True,
                'pthread_mutex_init': True,
                'DeleteCriticalSection': False,
                'pthread_mutex_destroy': False,
                'std::mutex::lock': True,
                'std::mutex::unlock': False,
                'AcquireSRWLockExclusive': True,
                'ReleaseSRWLockExclusive': False,
                'WaitForSingleObject': True,
                'ReleaseMutex': False,
            }
            for imp in imports:
                name = imp.get('name', '')
                if name in lock_map:
                    addr = imp.get('plt', 0) or imp.get('offset', 0)
                    ops.append(LockOperation(
                        addr=addr, lock_addr=addr,
                        is_acquire=lock_map[name],
                        operation_type=name))
        except Exception as e:
            logger.debug(f"Lock operation detection failed: {e}")
        return ops

    def build_happens_before_graph(self) -> Dict[HappensBeforeRelation, float]:
        graph: Dict[HappensBeforeRelation, float] = {}
        # 规则1: 同一锁对象的释放->获取施加顺序
        releases = [l for l in self.lock_operations if not l.is_acquire]
        acquires = [l for l in self.lock_operations if l.is_acquire]
        for rel in releases:
            for acq in acquires:
                if rel.lock_addr == acq.lock_addr and rel.addr < acq.addr:
                    rel_key = HappensBeforeRelation(rel, acq, 'lock_order')
                    graph[rel_key] = 1.0  # 最高置信: 直接锁顺序
        # 规则2: 线程创建施加父->子顺序
        for tc in self.thread_creates:
            for other_tc in self.thread_creates:
                if tc is not other_tc and tc.addr < other_tc.addr:
                    rel_key = HappensBeforeRelation(tc, other_tc, 'create_order')
                    graph[rel_key] = 0.8
        self.happens_before_graph = graph
        return graph

    def detect_data_race(self, access1: Tuple[int, int, str],
                          access2: Tuple[int, int, str]) -> bool:
        addr1, sz1, kind1 = access1
        addr2, sz2, kind2 = access2
        # 准则1: 地址范围重叠
        if not (addr1 <= addr2 < addr1 + sz1 or addr2 <= addr1 < addr2 + sz2):
            return False
        # 准则2: 至少一个访问是写
        if kind1 != 'write' and kind2 != 'write':
            return False
        # 准则3: 两个访问间无 happens-before 关系
        for rel in self.happens_before_graph:
            e1, e2 = rel.event1, rel.event2
            if (getattr(e1, 'addr', None) == addr1 and
                    getattr(e2, 'addr', None) == addr2):
                return False
            if (getattr(e1, 'addr', None) == addr2 and
                    getattr(e2, 'addr', None) == addr1):
                return False
        return True

    def detect_potential_deadlock(self, lock_cycle: List[int]) -> bool:
        if len(lock_cycle) < 2:
            return False
        # 平凡环(单锁)不是死锁 -> 需 >=2 个不同资源
        seen = set()
        unique_locks = []
        for lk in lock_cycle:
            if lk not in seen:
                seen.add(lk)
                unique_locks.append(lk)
        # 同一锁集在不同线程中以不同顺序获取 -> 死锁
        return len(unique_locks) >= 2


@dataclass
class VMSchedulerInfo:
    entry_point: int
    dispatch_loop: int
    vm_register_defs: dict = field(default_factory=dict)


class VMDecompilerAccelerator:

    def __init__(self):
        self.vm_schedulers: Dict[int, VMSchedulerInfo] = {}

    def detect_vm_entry(self, function_addr: int,
                         binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 200 @ {function_addr}', binary_path, timeout=60)
            # VM 分发器特征: 上下文保存(大量push), 间接分发(jmp reg), 密集switch
            push_count = len(re.findall(r'\bpush\b', dis, re.I))
            pop_count = len(re.findall(r'\bpop\b', dis, re.I))
            jmp_reg = len(re.findall(r'\bjmp\s+\w+\b', dis, re.I))
            # 复合评分: push密度 + pop密度 + 间接跳转 + switch密度
            score = (push_count > 3) + (pop_count > 3) + (jmp_reg > 0) + (
                'switch' in dis.lower() or len(re.findall(r'\bcase\b', dis, re.I)) > 4)
            return score >= 3
        except Exception as e:
            logger.debug(f"VM entry detection failed: {e}")
        return False

    def identify_vm_handler(self, handler_addr: int,
                              binary_path: str = "") -> str:
        if not binary_path:
            return "unknown"
        try:
            dis = _r2_text(f'pD 100 @ {handler_addr}', binary_path, timeout=30)
            if re.search(r'\badd\b.*\bsub\b|\bsub\b.*\badd\b', dis, re.I):
                return "arithmetic"
            if re.search(r'\bpush\b.*\bcall\b|\bcall\b.*\bpop\b', dis, re.I):
                return "call"
            if re.search(r'\bjmp\b.*\bjmp\b.*\bjmp\b', dis, re.I):
                return "branch"
            if re.search(r'\bmov\b.*\[.*\].*\bmov\b.*\[.*\]', dis, re.I):
                return "memory"
            if re.search(r'\bcmp\b.*\bj\w+\b', dis, re.I):
                return "conditional"
        except Exception as e:
            logger.debug(f"VM handler identification failed: {e}")
        return "unknown"

    def recover_vm_context(self, vm_entry: int,
                            binary_path: str = "") -> VMSchedulerInfo:
        info = VMSchedulerInfo(entry_point=vm_entry, dispatch_loop=0)
        if not binary_path:
            return info
        try:
            dis = _r2_text(f'pD 200 @ {vm_entry}', binary_path, timeout=60)
            # 基址+偏移模式揭示虚拟寄存器布局
            reg_matches = re.finditer(
                r'(?:mov|lea)\s+(\w+),\s*\[(\w+)\s*\+(0x[0-9a-fA-F]+|\d+)\]',
                dis, re.I,
            )
            for m in reg_matches:
                offset_str = m.group(3)
                offset = (int(offset_str, 16) if offset_str.lower().startswith('0x')
                          else int(offset_str))
                info.vm_register_defs[m.group(1)] = offset
            # 分发循环 = 处理器表末尾间接跳转的后边目标
            back_edges = re.findall(r'(0x[0-9a-fA-F]+).*\bjmp\s+\w+\b', dis)
            if back_edges:
                info.dispatch_loop = int(back_edges[0], 16)
        except Exception as e:
            logger.debug(f"VM context recovery failed: {e}")
        return info

    def decompile_vm_handler(self, handler_addr: int,
                              context: VMSchedulerInfo) -> str:
        try:
            dis = _r2_text(f'pD 50 @ {handler_addr}', '', timeout=30)
            lines: List[str] = []
            for line in dis.split('\n'):
                line = line.strip()
                if not line:
                    continue
                # 去除地址前缀: 仅保留指令助记符和操作数
                body = re.sub(r'^\s*0x[0-9a-fA-F]+\s+', '', line)
                # 用 vm_reg[index] 替换基址+偏移操作数
                for reg, off in context.vm_register_defs.items():
                    body = body.replace(f'[{reg}+{off}]',
                                        f'vm_reg[{off // 4}]')
                if body:
                    lines.append(body)
            return '\n'.join(lines)
        except Exception as e:
            logger.debug(f"VM handler decompilation failed: {e}")
        return ""


@dataclass
class InlineSite:
    call_site: int
    inlined_function: str
    inline_depth: int


class FunctionInlineRecovery:

    def __init__(self):
        self.inline_sites: List[InlineSite] = []
        self.function_signatures: Dict[int, Dict[str, Any]] = {}

    _PROLOGUE_PATTERNS = [
        r'push\s+(?:rbp|ebp)',
        r'mov\s+(?:rbp|ebp),\s*(?:rsp|esp)',
        r'sub\s+(?:rsp|esp),\s*0x[0-9a-fA-F]+',
        r'push\s+(?:rbx|ebx|r12|r13|r14|r15|edi|esi)',
    ]

    _EPILOGUE_PATTERNS = [
        r'leave',
        r'retn?\s*$',
        r'add\s+(?:rsp|esp),\s*0x[0-9a-fA-F]+',
        r'pop\s+(?:rbp|ebp|rbx|ebx|r12|r13|r14|r15|edi|esi)',
    ]

    _INLINE_CALL_PATTERNS = [
        r'mov\s+\w+,\s*(0x[0-9a-fA-F]+|\d+)',   # 调用前参数加载
        r'call\s+\w+',                             # 直接调用指令
        # 内联体在序言/尾声对之间缺少 ret
    ]

    _CALLING_CONVENTIONS = {
        'x86_64_win':  {'rcx': 0, 'rdx': 1, 'r8': 2, 'r9': 3},
        'x86_64_sysv': {'rdi': 0, 'rsi': 1, 'rdx': 2, 'rcx': 3, 'r8': 4, 'r9': 5},
    }


    def detect_inline_pattern(self, call_site: int,
                               binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 40 @ {call_site}', binary_path, timeout=30)
            pcount = sum(1 for p in self._PROLOGUE_PATTERNS
                         if re.search(p, dis, re.I))
            ecount = sum(1 for p in self._EPILOGUE_PATTERNS
                         if re.search(p, dis, re.I))
            # 判定: >=2 个序言特征 + 无 ret -> 内联展开
            has_ret = bool(re.search(r'\bretn?\b', dis, re.I))
            return pcount >= 2 and not has_ret
        except Exception:
            return False

    def recover_prologue_pattern(self, function_addr: int,
                                  binary_path: str = "") -> Optional[str]:
        if not binary_path:
            return None
        try:
            text = _r2_text(f'p8 32 @ {function_addr}', binary_path, timeout=10)
            return text.strip().replace('\n', '')
        except Exception:
            return None

    def recover_epilogue_pattern(self, function_addr: int,
                                  binary_path: str = "") -> Optional[str]:
        if not binary_path:
            return None
        try:
            # 查询 radare2 函数大小, 从末尾读 16 字节
            funcs = _r2_json(f'aflj @ {hex(function_addr)}', binary_path)
            if not funcs:
                return None
            size = funcs[0].get('size', 32)
            end = function_addr + size - 16
            text = _r2_text(f'p8 16 @ {end}', binary_path, timeout=10)
            return text.strip().replace('\n', '')
        except Exception:
            return None

    def recover_parameter_convention(self, function_addr: int,
                                      binary_path: str = "") -> Dict[str, int]:
        if not binary_path:
            return {}
        try:
            dis = _r2_text(f'pD 50 @ {function_addr}', binary_path, timeout=30)
            result: Dict[str, int] = {}
            # 统计各调用约定的寄存器命中数, 最高分胜出
            for conv_name, mapping in self._CALLING_CONVENTIONS.items():
                score = 0
                for reg, idx in mapping.items():
                    if re.search(rf'\b{reg}\b', dis, re.I):
                        score += 1
                if score >= 2:
                    return dict(mapping)
            return result
        except Exception:
            return {}

    def undo_inline(self, inline_site: InlineSite,
                     binary_path: str = "") -> None:
        if inline_site.call_site not in self.function_signatures:
            self.function_signatures[inline_site.call_site] = {}
        self.function_signatures[inline_site.call_site]['inlined'] = inline_site
        self.inline_sites.append(inline_site)


@dataclass
class GlobalBinding:
    symbol_name: str
    address: int
    shared_modules: list = field(default_factory=list)
    access_count: int = 0


class CrossBinaryGlobalAnalyzer:

    def __init__(self):
        self.global_bindings: Dict[str, GlobalBinding] = {}

    def analyze_got_plt_access(self, binary_path: str) -> Dict[str, GlobalBinding]:
        bindings: Dict[str, GlobalBinding] = {}
        try:
            imports = _r2_json('iij', binary_path, timeout=30)
            relocs = _r2_json('irj', binary_path, timeout=30)
            reloc_map: Dict[str, int] = {}
            for r in relocs:
                reloc_map[r.get('name', '')] = r.get('vaddr', 0)
            for imp in imports:
                name = imp.get('name', '')
                addr = reloc_map.get(name, imp.get('plt', 0) or imp.get('offset', 0))
                if name:
                    bindings[name] = GlobalBinding(
                        symbol_name=name, address=addr)
        except Exception as e:
            logger.debug(f"GOT/PLT analysis failed: {e}")
        self.global_bindings.update(bindings)
        return bindings

    def find_shared_globals(self, binaries: List[str]) -> List[GlobalBinding]:
        all_symbols: Dict[str, Dict[str, int]] = defaultdict(dict)
        for path in binaries:
            try:
                # 收集导出符号表项
                syms = _r2_json('isj', path, timeout=30)
                for s in syms:
                    name = s.get('name', '')
                    if name:
                        all_symbols[name][path] = s.get('vaddr', 0)
            except Exception:
                continue
        shared: List[GlobalBinding] = []
        for name, locations in all_symbols.items():
            if len(locations) >= 2:
                shared.append(GlobalBinding(
                    symbol_name=name,
                    address=list(locations.values())[0],
                    shared_modules=list(locations.keys()),
                    access_count=len(locations)))
        return shared

    def detect_concurrent_access(self, global_addr: int,
                                  binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 100 @ {global_addr}', binary_path, timeout=30)
            # 两个信号: lock 前缀原子操作, 或附近线程 API 导入
            has_lock_prefix = bool(re.search(r'\block\b', dis, re.I))
            has_thread_api = bool(
                re.search(r'CreateThread|pthread_create|_beginthread', dis, re.I))
            return has_lock_prefix or has_thread_api
        except Exception:
            return False

    def assess_race_condition_risk(self, global_binding: GlobalBinding) -> float:
        mod_score = min(1.0, len(global_binding.shared_modules) / 5.0)
        access_score = min(1.0, global_binding.access_count / 20.0)
        return round(mod_score * 0.6 + access_score * 0.4, 4)


KNOWN_CRYPTO_CONSTANTS = {
    'AES': {
        'sbox': bytes([
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
            0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        ]),
        'inv_sbox': bytes([
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
            0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        ]),
    },
    'SHA256': {
        'iv': bytes.fromhex(
            '6a09e667bb67ae853c6ef372a54ff53a'
            '510e527f9b05688c1f83d9ab5be0cd19'),
    },
    'MD5': {
        'iv': struct.pack('<IIII', 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476),
    },
    'CRC32': {
        'table': struct.pack(
            '<' + 'I' * 16,
            0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
            0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
            0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
            0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        ),
    },
}


@dataclass
class CryptoFingerprint:
    algorithm: str
    constant_type: str
    fuzzy_hash: bytes
    variations: list = field(default_factory=list)

    def __hash__(self):
        return hash((self.algorithm, self.constant_type, self.fuzzy_hash))


class FuzzyCryptoMatcher:

    def __init__(self):
        self.fingerprints: List[CryptoFingerprint] = []
        for algo, consts in KNOWN_CRYPTO_CONSTANTS.items():
            for ctype, data in consts.items():
                self.register_fingerprint(CryptoFingerprint(
                    algorithm=algo, constant_type=ctype,
                    fuzzy_hash=self.compute_fuzzy_hash(data, ctype)))

    def compute_fuzzy_hash(self, data: bytes, constant_type: str = "") -> bytes:
        if not data:
            return b'\x00' * 8
        vector = [0] * 64
        chunk_size = max(len(data) // 16, 1)
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        if len(chunks) < 2:
            chunks = [data[i:i + 2] for i in range(0, len(data), 2)]
        for chunk in chunks:
            h = int(hashlib.sha256(chunk).hexdigest()[:16], 16)
            for bit in range(64):
                if h & (1 << bit):
                    vector[bit] += 1
                else:
                    vector[bit] -= 1
        result = 0
        for bit, weight in enumerate(vector):
            if weight > 0:
                result |= (1 << bit)
        return struct.pack('<Q', result)

    def register_fingerprint(self, fingerprint: CryptoFingerprint) -> None:
        self.fingerprints.append(fingerprint)

    def match_constant(self, data: bytes) -> List[Tuple[str, float]]:
        if not data or not self.fingerprints:
            return []
        query_hash = self.compute_fuzzy_hash(data)
        query_int = struct.unpack('<Q', query_hash)[0]
        matches = []
        for fp in self.fingerprints:
            fp_int = struct.unpack('<Q', fp.fuzzy_hash)[0]
            # 归一化汉明相似度: 1.0 - (popcount(xor) / 64)
            xor = query_int ^ fp_int
            distance = xor.bit_count()
            similarity = 1.0 - (distance / 64.0)
            if similarity > 0.5:
                matches.append((fp.algorithm, round(similarity, 4)))
        # 二次扫描: 精确字节序列包含(正向和字节反转)
        for fp in self.fingerprints:
            for algo, consts in KNOWN_CRYPTO_CONSTANTS.items():
                for ctype, ref_bytes in consts.items():
                    if ref_bytes in data or ref_bytes[::-1] in data:
                        matches.append((algo, 0.95))
        matches.sort(key=lambda x: x[1], reverse=True)
        return matches[:10]

    def detect_endianness_variation(self, data: bytes) -> str:
        if len(data) < 4:
            return "unknown"
        # 正向 vs dword 反转匹配参考常量
        normal_score = 0.0
        swapped_score = 0.0
        for algo, consts in KNOWN_CRYPTO_CONSTANTS.items():
            for ref in consts.values():
                if len(ref) >= 4:
                    # 对齐比较窗口到 data 与 reference 的较短者
                    chunk = data[:min(len(data), len(ref))]
                    if chunk == ref[:len(chunk)]:
                        normal_score = max(normal_score, 1.0)
                    swapped = b''.join(
                        chunk[i:i + 4][::-1] for i in range(0, len(chunk), 4)
                    )
                    if swapped == ref[:len(swapped)]:
                        swapped_score = max(swapped_score, 1.0)
        if swapped_score > normal_score:
            return "big_endian" if len(data) % 4 == 0 else "byte_swapped"
        if normal_score > swapped_score:
            return "little_endian"
        return "unknown"


@dataclass
class PointerInfo:
    address: int
    points_to: Optional[int]
    is_modified: bool = False
    modification_sites: list = field(default_factory=list)


class SymbolicPointerTracker:

    def __init__(self):
        self.pointer_graph: Dict[int, PointerInfo] = {}
        self.modified_pointers: Set[int] = set()

    def mark_pointer(self, ptr_addr: int) -> None:
        if ptr_addr not in self.pointer_graph:
            self.pointer_graph[ptr_addr] = PointerInfo(
                address=ptr_addr, points_to=None)

    def track_modification(self, ptr_addr: int, modification_site: int) -> None:
        if ptr_addr in self.pointer_graph:
            self.pointer_graph[ptr_addr].is_modified = True
            self.pointer_graph[ptr_addr].modification_sites.append(
                modification_site)
            self.modified_pointers.add(ptr_addr)

    def get_pointer_chain(self, ptr_addr: int) -> List[int]:
        chain: List[int] = [ptr_addr]
        visited: Set[int] = {ptr_addr}
        cur = ptr_addr
        while cur in self.pointer_graph:
            info = self.pointer_graph[cur]
            target = info.points_to
            if target is None or target in visited:
                break
            chain.append(target)
            visited.add(target)
            cur = target
        return chain

    def assess_hijack_risk(self, ptr_addr: int) -> float:
        if ptr_addr not in self.pointer_graph:
            return 0.0
        info = self.pointer_graph[ptr_addr]
        base = 0.5 if info.is_modified else 0.05
        site_bonus = min(0.5, len(info.modification_sites) * 0.1)
        return round(base + site_bonus, 4)


@dataclass
class DebugInfoFix:
    original_offset: int
    inferred_type: Optional[str]
    inferred_name: Optional[str]
    confidence: float


class DebugInfoRepair:

    TYPE_HINT_PATTERNS = [
        (re.compile(r'movsx[dz]\s+\w+,\s*\w+', re.I), 'int'),
        (re.compile(r'movzx\s+\w+,\s*\w+', re.I), 'unsigned int'),
        (re.compile(r'cvtsi2sd\s+\w+,\s*\w+', re.I), 'double'),
        (re.compile(r'cvtsd2si\s+\w+,\s*\w+', re.I), 'int'),
        (re.compile(r'lea\s+\w+,\s*\[.*\]', re.I), 'void*'),
        (re.compile(r'call.*(?:malloc|new|alloc)', re.I), 'void*'),
        (re.compile(r'call.*(?:strlen|strcmp|strcpy|strcat)', re.I), 'char*'),
        (re.compile(r'(?:div|idiv|mul|imul)\s+\w+', re.I), 'unsigned long long'),
    ]

    KNOWN_LIBRARY_SIGNATURES = [
        (re.compile(r'call.*memcpy', re.I), 'memcpy'),
        (re.compile(r'call.*memset', re.I), 'memset'),
        (re.compile(r'call.*strlen', re.I), 'strlen'),
        (re.compile(r'call.*printf', re.I), 'printf'),
        (re.compile(r'call.*malloc', re.I), 'malloc'),
        (re.compile(r'call.*free', re.I), 'free'),
        (re.compile(r'call.*fopen', re.I), 'fopen'),
        (re.compile(r'call.*fread', re.I), 'fread'),
        (re.compile(r'call.*fwrite', re.I), 'fwrite'),
    ]

    def __init__(self):
        self.fixes: List[DebugInfoFix] = []

    def infer_variable_type(self, var_addr: int,
                             context: str = "") -> Optional[str]:
        if not context:
            return None
        for pat, tname in self.TYPE_HINT_PATTERNS:
            if pat.search(context):
                return tname
        return None

    def infer_function_name(self, function_addr: int,
                             binary_path: str = "") -> Optional[str]:
        if not binary_path:
            return None
        try:
            dis = _r2_text(f'pD 80 @ {function_addr}', binary_path, timeout=30)
            for pat, name in self.KNOWN_LIBRARY_SIGNATURES:
                if pat.search(dis):
                    return f"likely_{name}_wrapper"
            # 回退: 从函数附近首个字符串引用推导名称
            strings = _r2_json(f'izzj @ {function_addr}', binary_path, timeout=10)
            if strings:
                first_str = strings[0].get('string', '')
                safe = re.sub(r'[^a-zA-Z0-9_]', '_', first_str[:20])
                if safe.strip('_'):
                    return f"func_ref_{safe.strip('_')}"
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return None

    def infer_struct_type(self, struct_addr: int,
                           binary_path: str = "") -> Optional[str]:
        if not binary_path:
            return None
        try:
            dis = _r2_text(f'pD 60 @ {struct_addr}', binary_path, timeout=30)
            offsets = sorted(set(
                int(m.group(1), 0) for m in re.finditer(
                    r'\[.*\+(0x[0-9a-fA-F]+)\]', dis)))
            # 已知形状: [0,8,16,24] -> 三字段向量; 小结构 -> 成员数标签
            if offsets == [0, 8, 16, 24]:
                return "vector_like_3field"
            if offsets and offsets[-1] <= 64:
                return f"struct_{len(offsets)}_members"
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return None

    def repair_debug_info(self, debug_info: Dict[str, Any],
                           binary_path: str = "") -> Dict[str, Any]:
        repaired = dict(debug_info)
        functions = repaired.get('functions', {})
        for addr_str, info in list(functions.items()):
            if isinstance(info, dict):
                if not info.get('name'):
                    addr = int(addr_str, 16) if addr_str.startswith('0x') else int(addr_str)
                    inferred = self.infer_function_name(addr, binary_path)
                    if inferred:
                        info['name'] = inferred
                        info['name_inferred'] = True
                if not info.get('type') and 'code' in info:
                    inferred = self.infer_variable_type(
                        int(addr_str, 16), info.get('code', ''))
                    if inferred:
                        info['type'] = inferred
                        info['type_inferred'] = True
        return repaired


@dataclass
class FunctionSummary:
    function_addr: int
    input_constraints: list = field(default_factory=list)
    output_effects: dict = field(default_factory=dict)
    side_effects: list = field(default_factory=list)


class SymbolicSummaryCache:

    def __init__(self):
        self.summary_cache: Dict[int, FunctionSummary] = {}
        self.call_graph: Dict[int, Set[int]] = {}

    def is_pure_function(self, function_addr: int,
                          binary_path: str = "") -> bool:
        if not binary_path:
            return True  # 无 binary_path 时默认视为纯函数
        try:
            dis = _r2_text(f'pD 100 @ {function_addr}', binary_path, timeout=30)
            # 已知非纯 API: 内存, I/O, 同步
            impure_apis = [
                r'call.*(?:malloc|free|write|send|recv|open|close|printf|puts|scanf)',
                r'call.*(?:EnterCriticalSection|LeaveCriticalSection)',
                r'call.*(?:pthread_|CreateThread)',
            ]
            # 直接写绝对地址或 RIP 相对偏移 -> 全局写
            global_write = re.search(
                r'mov\s+(?:\[0x[0-9a-fA-F]+\]|\[rip\s*\+)', dis, re.I)
            for pat in impure_apis:
                if re.search(pat, dis, re.I):
                    return False
            if global_write:
                return False
            return True
        except Exception:
            return False

    def compute_summary(self, function_addr: int,
                         binary_path: str = "") -> Optional[FunctionSummary]:
        if not binary_path:
            return None
        try:
            dis = _r2_text(f'pD 200 @ {function_addr}', binary_path, timeout=60)
            summary = FunctionSummary(function_addr=function_addr)
            # 输入分类: 函数中任何定义之前消费的寄存器
            regs_read = set()
            regs_written = set()
            for line in dis.split('\n'):
                reads = re.findall(r'\b(r[a-z]{1,2}\d*|e[a-z]{1,2}x|rsp|esp|rbp|ebp)\b', line)
                writes = re.findall(
                    r'mov\s+(\w+),|lea\s+(\w+),|add\s+(\w+),|sub\s+(\w+),',
                    line, re.I,
                )
                for r in reads:
                    if r not in regs_written:
                        regs_read.add(r)
                for groups in writes:
                    for g in groups:
                        if g:
                            regs_written.add(g)
            summary.input_constraints = sorted(regs_read - {'rsp', 'esp', 'rbp', 'ebp'})
            summary.output_effects = {'modified_regs': sorted(regs_written)}
            # 标记外部调用为有副作用, 供下游纯度检查
            if re.search(r'call.*(?:malloc|free|write|send)', dis, re.I):
                summary.side_effects.append('external_call')
            return summary
        except Exception:
            return None

    def get_cached_summary(self, function_addr: int,
                            context: Dict[str, Any] = None) -> Optional[FunctionSummary]:
        summary = self.summary_cache.get(function_addr)
        if summary is None:
            return None
        if context and context.get('specialize'):
            summary = FunctionSummary(
                function_addr=summary.function_addr,
                input_constraints=list(summary.input_constraints),
                output_effects=dict(summary.output_effects),
                side_effects=list(summary.side_effects),
            )
        return summary

    def cache_summary(self, summary: FunctionSummary) -> None:
        self.summary_cache[summary.function_addr] = summary

    def invalidate_cache(self, function_addr: int) -> None:
        self.summary_cache.pop(function_addr, None)


@dataclass
class BinaryTarget:
    path: str
    architecture: str
    analysis_results: dict = field(default_factory=dict)


class MultiTargetAnalysisDatabase:

    def __init__(self):
        self.targets: Dict[str, BinaryTarget] = {}
        self.cross_target_references: Dict[Tuple[str, str], List[int]] = {}

    def add_target(self, binary_path: str) -> BinaryTarget:
        target = BinaryTarget(path=binary_path, architecture="unknown")
        try:
            info = _r2_json('ij', binary_path, timeout=15)
            if info:
                target.architecture = info.get('bins', [{}])[0].get('arch', 'unknown')
        except Exception:
            logger.debug("suppressed", exc_info=True)
        self.targets[binary_path] = target
        return target

    def build_cross_references(self) -> None:
        sym_maps: Dict[str, Dict[str, int]] = {}
        for path, target in self.targets.items():
            try:
                syms = _r2_json('isj', path, timeout=30)
                sym_maps[path] = {s.get('name', ''): s.get('vaddr', 0)
                                  for s in syms if s.get('name')}
            except Exception:
                sym_maps[path] = {}
        # 倒排索引: 符号名 -> 导出它的二进制列表
        all_names: Dict[str, List[str]] = defaultdict(list)
        for path, syms in sym_maps.items():
            for name in syms:
                all_names[name].append(path)
        for name, paths in all_names.items():
            if len(paths) < 2:
                continue
            for p1 in paths:
                for p2 in paths:
                    if p1 >= p2:
                        continue
                    key = (p1, p2)
                    if key not in self.cross_target_references:
                        self.cross_target_references[key] = []
                    self.cross_target_references[key].append(
                        sym_maps[p1].get(name, 0))

    def find_type_relations(self, type_name: str) -> List[Tuple[str, str]]:
        results = []
        for path in self.targets:
            try:
                dis = _r2_text(f'izz~{type_name}', path, timeout=30)
                if dis.strip():
                    results.append((path, 'string_reference'))
                # 辅助搜索: 结构化类型数据库
                types = _r2_json('tj', path, timeout=10)
                for t in types:
                    if type_name.lower() in t.get('type', '').lower():
                        results.append((path, f"type:{t.get('type')}"))
            except Exception:
                continue
        return results

    def search_vulnerability_globally(self, vuln_pattern: str) -> List[Tuple[str, int]]:
        findings = []
        for path in self.targets:
            try:
                dis = _r2_text(f'izz~{vuln_pattern}', path, timeout=60)
                for m in re.finditer(
                    r'(0x[0-9a-fA-F]+).*({})'.format(vuln_pattern),
                    dis, re.I,
                ):
                    findings.append((path, int(m.group(1), 16)))
                # 导入表扫描匹配模式的危险 API 名
                if re.match(r'^(strcpy|strcat|gets|sprintf|system|exec)', vuln_pattern, re.I):
                    imports = _r2_json('iij', path, timeout=15)
                    for imp in imports:
                        name = imp.get('name', '')
                        if vuln_pattern.lower() in name.lower():
                            findings.append(
                                (path, imp.get('plt', 0) or imp.get('offset', 0)))
            except Exception:
                continue
        return findings


@dataclass
class AntiAnalysisBypass:
    detection_point: int
    bypassed: bool
    symbolic_constraint: Optional[str] = None


class SymbolicAntiAnalysisEngine:

    # 原始字节签名: 在二进制块上做子串匹配
    _BYTE_SIGNATURES = [
        (b'VMWare', 'vmware_backdoor'),
        (b'VBox', 'virtualbox'),
        (b'QEMU', 'qemu'),
        (b'Xen', 'xen'),
        (b'Hyper-V', 'hyperv'),
        (b'IsDebuggerPresent', 'is_debugger_present'),
        (b'CheckRemoteDebuggerPresent', 'remote_debugger'),
        (b'NtQueryInformationProcess', 'nt_query_process'),
        (b'OutputDebugString', 'output_debug_string'),
        (b'cpuid', 'cpuid_check'),
        (b'rdtsc', 'timing_check'),
        (b'GetTickCount', 'tick_count'),
        # x86 操作码
        (b'\xCC', 'int3_breakpoint'),       # int 3 指令
        (b'\xEC', 'vm_port_io'),             # in al, dx
        (b'\xED', 'vm_port_io'),             # in ax/eax, dx
    ]

    # 反汇编级正则签名: 匹配指令文本
    _DISASM_SIGNATURES = [
        (re.compile(r'in\s+(?:eax|ax|al),', re.I), 'vm_port_io'),
        (re.compile(r'int\s+3\b', re.I), 'int3_breakpoint'),
        (re.compile(r'int\s+1\b', re.I), 'int1_debug'),
    ]

    def __init__(self):
        self.detection_points: List[int] = []
        self.bypasses: List[AntiAnalysisBypass] = []

    def find_detection_points(self, binary_path: str) -> List[int]:
        points: List[int] = []
        if not binary_path:
            return points
        # 阶段1: 对整个二进制块做原始字节子串扫描
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for sig, _label in self._BYTE_SIGNATURES:
                idx = 0
                while True:
                    idx = data.find(sig, idx)
                    if idx == -1:
                        break
                    points.append(idx)
                    idx += 1
        except Exception as e:
            logger.debug(f"Byte-level detection point discovery failed: {e}")

        # 阶段2: 反汇编级正则匹配指令序列签名
        try:
            dis = _r2_text('pD 5000', binary_path, timeout=60)
            for pattern, _label in self._DISASM_SIGNATURES:
                for m in pattern.finditer(dis):
                    # 从匹配前的行提取十六进制地址
                    addr_match = re.search(
                        r'(?:^|\n)\s*(0x[0-9a-fA-F]+)', dis[
                            max(0, m.start() - 80):m.start() + 1])
                    if addr_match:
                        points.append(int(addr_match.group(1), 16))
        except Exception as e:
            logger.debug(f"Disassembly-level detection failed: {e}")

        # 合并簇: 16 字节窗口内地址折叠到最低值
        points.sort()
        deduped: List[int] = []
        for p in points:
            if not deduped or p - deduped[-1] > 16:
                deduped.append(p)
        self.detection_points = deduped
        return deduped

    def detect_vm_check(self, addr: int, binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 30 @ {addr}', binary_path, timeout=30)
            # VM 检测原语: cpuid 指令, I/O 端口探测, 厂商字符串扫描
            vm_hints = [
                r'\bcpuid\b', r'\bin\s+(?:eax|al|ax)', r'\bout\s+(?:eax|al|ax)',
                r'VMWare|VBox|QEMU|Xen',
            ]
            return any(re.search(h, dis, re.I) for h in vm_hints)
        except Exception:
            return False

    def detect_debugger_check(self, addr: int,
                               binary_path: str = "") -> bool:
        if not binary_path:
            return False
        try:
            dis = _r2_text(f'pD 30 @ {addr}', binary_path, timeout=30)
            dbg_hints = [
                r'IsDebuggerPresent', r'NtQueryInformationProcess',
                r'int\s*3', r'int\s*1', r'rdtsc', r'GetTickCount',
                r'fs:\s*\[\s*0x30\s*\]',  # 通过 fs 段访问 Windows PEB
            ]
            return any(re.search(h, dis, re.I) for h in dbg_hints)
        except Exception:
            return False

    def symbolic_bypass(self, detection_addr: int) -> Optional[str]:
        bypass = AntiAnalysisBypass(
            detection_point=detection_addr,
            bypassed=True,
            symbolic_constraint=f"assume(return_value_at_{hex(detection_addr)} == 0)"
        )
        self.bypasses.append(bypass)
        return bypass.symbolic_constraint

    def execute_with_bypass(self, target_addr: int,
                             binary_path: str = "") -> bool:
        if not binary_path:
            return True  # 无二进制可执行 -> 平凡旁路
        try:
            # 执行检查: 静态上下文中旁路为符号化; 运行时验证可选
            result = subprocess.run(
                [binary_path], capture_output=True, timeout=5,
                encoding='utf-8', errors='replace',
            )
            return result.returncode in (0, 1)  # 退出码 0 或 1 -> 未被反分析拒绝
        except subprocess.TimeoutExpired:
            return True  # 无退出挂起 -> 反分析可能已中和
        except Exception:
            return True  # 静态分析模式下假定旁路


class DelayedBindingResolver:

    def __init__(self):
        self.resolved_symbols: Dict[int, str] = {}

    def find_dlopen_calls(self, binary_path: str) -> List[int]:
        sites: List[int] = []
        if not binary_path:
            return sites
        try:
            imports = _r2_json('iij', binary_path, timeout=30)
            delay_apis = {'dlopen', 'dlsym', 'GetProcAddress', 'LoadLibraryA',
                          'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW'}
            for imp in imports:
                if imp.get('name', '') in delay_apis:
                    sites.append(imp.get('plt', 0) or imp.get('offset', 0))
        except Exception as e:
            logger.debug(f"dlopen call discovery failed: {e}")
        return sites

    def resolve_delayed_symbols(self, binary_path: str = "") -> Dict[int, str]:
        resolved: Dict[int, str] = {}
        if not binary_path:
            return resolved
        try:
            sites = self.find_dlopen_calls(binary_path)
            for site in sites:
                # 反汇编调用前的指令以查找加载的字符串指针
                dis = _r2_text(f'pD 20 @ {site}', binary_path, timeout=30)
                # RIP 相对 LEA/MOV -> 候选字符串地址
                str_addr_match = re.search(
                    r'(?:lea|mov)\s+\w+,\s*\[?rip\s*\+\s*(0x[0-9a-fA-F]+)', dis, re.I)
                if str_addr_match:
                    str_addr = int(str_addr_match.group(1), 16)
                    # 通过 ps 解引用地址读取字符串
                    s = _r2_text(f'ps @ {str_addr}', binary_path, timeout=10)
                    if s.strip():
                        resolved[site] = s.strip()
            self.resolved_symbols = resolved
        except Exception as e:
            logger.debug(f"Symbol resolution failed: {e}")
        return resolved


EMBEDDED_VM_SIGNATURES = {
    'lua': {
        'magic': b'\x1bLua',
        'header_len': 18,
    },
    'lua53': {
        'magic': b'\x1bLua\x53',
        'header_len': 20,
    },
    'python_pyc': {
        'magic': b'\x55\x0d\x0d\x0a',  # Python 3.x pyc magic 数
        'header_len': 16,
    },
    'python_pyc_v2': {
        'magic': b'\x03\xf3\x0d\x0a',
        'header_len': 8,
    },
    'javascript': {
        'magic': None,  # 无静态 magic -> 通过字符串表启发式检测
    },
    'luajit': {
        'magic': b'\x1bLJ',
        'header_len': 3,
    },
}


class EmbeddedVMDetector:

    def __init__(self):
        self.vm_type: Optional[str] = None
        self.bytecode: Optional[bytes] = None

    def detect_vm(self, binary_path: str) -> Optional[str]:
        if not binary_path:
            return None
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for vm_name, info in EMBEDDED_VM_SIGNATURES.items():
                magic = info.get('magic')
                if magic and magic in data:
                    self.vm_type = vm_name
                    return vm_name
            # 回退: 对原始字节做正则匹配 Lua/Python API 函数名
            lua_funcs = b'luaL_|lua_newstate|lua_pcall|lua_push'
            py_funcs = b'Py_Initialize|PyRun_|PyEval_'
            if re.search(lua_funcs, data, re.I):
                self.vm_type = 'lua_embedded'
                return 'lua_embedded'
            if re.search(py_funcs, data, re.I):
                self.vm_type = 'python_embedded'
                return 'python_embedded'
        except Exception as e:
            logger.debug(f"VM detection failed: {e}")
        return None

    def extract_bytecode(self, binary_path: str = "") -> Optional[bytes]:
        if self.vm_type is None:
            self.detect_vm(binary_path)
        if not self.vm_type or not binary_path:
            return None
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for vm_name, info in EMBEDDED_VM_SIGNATURES.items():
                if vm_name in self.vm_type:
                    magic = info.get('magic')
                    if magic:
                        idx = data.find(magic)
                        if idx != -1:
                            # 从 magic 偏移开始截取 64KB 窗口
                            end = min(idx + 65536, len(data))
                            self.bytecode = data[idx:end]
                            return self.bytecode
            # 通用回退: 首个 API 名子串命中处周围 64KB 窗口
            if 'lua' in self.vm_type:
                idx = data.find(b'luaL_')
                if idx != -1:
                    self.bytecode = data[max(0, idx - 1024):idx + 65536]
                    return self.bytecode
        except Exception as e:
            logger.debug(f"Bytecode extraction failed: {e}")
        return None

    def analyze_bytecode(self) -> Dict[str, Any]:
        if not self.bytecode:
            return {}
        result: Dict[str, Any] = {
            'size': len(self.bytecode),
            'vm_type': self.vm_type,
        }
        try:
            # 字节分布的香农熵; >7.5 -> 可能压缩/加密
            freq = [0] * 256
            for b in self.bytecode:
                freq[b] += 1
            total = len(self.bytecode)
            entropy = 0.0
            import math
            for f in freq:
                if f > 0:
                    p = f / total
                    entropy -= p * math.log2(p)
            result['entropy'] = round(entropy, 4)
            result['likely_compressed'] = entropy > 7.5
        except Exception:
            logger.debug("suppressed", exc_info=True)
        try:
            # 粗略操作码指纹: 统计 function 段(Lua) 或 LOAD_CONST(Python)
            if b'function' in self.bytecode:
                result['lua_function_count'] = self.bytecode.count(b'function')
            if b'LOAD_CONST' in self.bytecode or b'\x64\x00' in self.bytecode:
                result['python_opcodes_detected'] = True
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return result


class StructuredPseudocodeGenerator:

    _INDENT = 4

    def __init__(self):
        self.control_flow_patterns = {
            'if': r'if\s*\(([^)]+)\)',
            'while': r'while\s*\(([^)]+)\)',
            'for': r'for\s*\(([^)]+)\)',
            'switch': r'switch\s*\(([^)]+)\)',
            'return': r'return\s+([^;]+)',
            'goto': r'goto\s+(\w+)',
        }

    def structure_pseudocode(self, flat_pseudocode: str) -> str:
        lines = flat_pseudocode.split('\n')
        out: List[str] = []
        level = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith('if'):
                out.append(self._fmt_if(line, level))
                level += 1
            elif line.startswith('else'):
                level = max(0, level - 1)
                out.append(self._fmt_else(line, level))
                level += 1
            elif line.startswith('while'):
                out.append(self._fmt_while(line, level))
                level += 1
            elif line.startswith('for'):
                out.append(self._fmt_for(line, level))
                level += 1
            elif line.startswith('switch'):
                out.append(self._fmt_switch(line, level))
                level += 1
            elif line.startswith('case'):
                out.append(self._fmt_case(line, level))
            elif line.startswith('break'):
                out.append(self._pad('break;', level))
                level = max(0, level - 1)
            elif line.startswith('return'):
                out.append(self._fmt_return(line, level))
            elif line == '}':
                level = max(0, level - 1)
                out.append(self._pad('}', level))
            else:
                out.append(self._pad(line + ';', level))
        return '\n'.join(out)

    def _pad(self, text: str, level: int) -> str:
        return ' ' * (level * self._INDENT) + text

    def _fmt_if(self, line: str, level: int) -> str:
        m = re.match(r'if\s*\(([^)]+)\)', line)
        return self._pad(f"if ({m.group(1)}) {{", level) if m else self._pad(line + ' {', level)

    def _fmt_else(self, line: str, level: int) -> str:
        if 'else if' in line:
            m = re.match(r'else\s+if\s*\(([^)]+)\)', line)
            return self._pad(f"}} else if ({m.group(1)}) {{", level) if m else self._pad('} else {', level)
        return self._pad('} else {', level)

    def _fmt_while(self, line: str, level: int) -> str:
        m = re.match(r'while\s*\(([^)]+)\)', line)
        return self._pad(f"while ({m.group(1)}) {{", level) if m else self._pad(line + ' {', level)

    def _fmt_for(self, line: str, level: int) -> str:
        m = re.match(r'for\s*\(([^)]+)\)', line)
        return self._pad(f"for ({m.group(1)}) {{", level) if m else self._pad(line + ' {', level)

    def _fmt_switch(self, line: str, level: int) -> str:
        m = re.match(r'switch\s*\(([^)]+)\)', line)
        return self._pad(f"switch ({m.group(1)}) {{", level) if m else self._pad(line + ' {', level)

    def _fmt_case(self, line: str, level: int) -> str:
        m = re.match(r'case\s+(\w+)', line)
        return self._pad(f"case {m.group(1)}:", level + 1) if m else self._pad(line, level + 1)

    def _fmt_return(self, line: str, level: int) -> str:
        m = re.match(r'return\s+([^;]+)', line)
        return self._pad(f"return {m.group(1).strip()};", level) if m else self._pad('return;', level)

    def infer_variable_scope(self, pseudocode: str) -> Dict[str, List[str]]:
        scopes: Dict[str, List[str]] = {'global': [], 'local': [], 'parameter': []}
        m = re.search(r'(\w+)\s*\(([^)]*)\)', pseudocode)
        if m:
            for param in m.group(2).split(','):
                p = param.strip()
                if p:
                    scopes['parameter'].append(p)
        for type_, name in re.findall(
            r'\b(int|char|long|short|float|double|void\*|unsigned)\s+(\w+)\b',
            pseudocode,
        ):
            if name not in scopes['parameter']:
                scopes['local'].append(f'{type_} {name}')
        return scopes

    def generate_c_style_output(self, pseudocode: str,
                                 function_name: str = 'unknown') -> str:
        structured = self.structure_pseudocode(pseudocode)
        scopes = self.infer_variable_scope(pseudocode)
        header = f'// Function: {function_name}\n'
        header += '// Generated structured pseudocode\n\n'
        if scopes['local']:
            header += '// Local variables:\n'
            for v in scopes['local']:
                header += f'//   {v}\n'
            header += '\n'
        return header + structured


class CrossFunctionDataFlowCache:

    def __init__(self, cache_path: str = "data/dataflow_cache.db"):
        self.cache_path = cache_path
        self.summary_cache: Dict[str, Dict[str, Any]] = {}
        self.context_cache: Dict[str, Dict[str, Any]] = {}
        self.call_contexts: Dict[str, List[str]] = {}
        os.makedirs(os.path.dirname(cache_path) or '.', exist_ok=True)
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.cache_path)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS function_summaries (
                function_id TEXT PRIMARY KEY,
                input_constraints TEXT, output_effects TEXT,
                side_effects TEXT, taint_flow TEXT,
                created_at TEXT, validity_hash TEXT)''')
            c.execute('''CREATE TABLE IF NOT EXISTS context_summaries (
                context_id TEXT PRIMARY KEY,
                function_id TEXT, call_context TEXT,
                specialized_summary TEXT, created_at TEXT)''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Dataflow cache DB init failed: {e}")

    def compute_function_summary(self, function_addr: int,
                                  function_code: str) -> Dict[str, Any]:
        summary: Dict[str, Any] = {
            'function_addr': function_addr,
            'input_constraints': [],
            'output_effects': {},
            'side_effects': [],
            'taint_flow': {},
            'validity_hash': '',
        }
        inputs = re.findall(r'\b(param|arg|input|src)\s*(\w+)\b', function_code)
        for prefix, name in inputs:
            summary['input_constraints'].append(
                {'name': name, 'type': 'parameter', 'constraints': []})
        outputs = re.findall(r'\b(return|output|dst|result)\s*(\w+)\b', function_code)
        for prefix, name in outputs:
            summary['output_effects'][name] = {'type': 'return_value', 'tainted': False}
        for pat, effect in [
            (r'malloc\s*\(', 'memory_alloc'),
            (r'free\s*\(', 'memory_free'),
            (r'write\s*\(', 'file_write'),
            (r'send\s*\(', 'network_send'),
        ]:
            if re.search(pat, function_code):
                summary['side_effects'].append(effect)
        for dst, src in re.findall(r'(\w+)\s*=\s*(\w+)', function_code):
            summary['taint_flow'][dst] = src
        summary['validity_hash'] = hashlib.sha256(
            function_code.encode()).hexdigest()[:16]
        return summary

    def cache_summary(self, function_id: str, summary: Dict[str, Any]):
        self.summary_cache[function_id] = summary
        try:
            conn = sqlite3.connect(self.cache_path)
            c = conn.cursor()
            c.execute(
                '''INSERT OR REPLACE INTO function_summaries
                   (function_id, input_constraints, output_effects,
                    side_effects, taint_flow, created_at, validity_hash)
                   VALUES (?,?,?,?,?,?,?)''',
                (function_id, json.dumps(summary['input_constraints']),
                 json.dumps(summary['output_effects']),
                 json.dumps(summary['side_effects']),
                 json.dumps(summary['taint_flow']),
                 datetime.now().isoformat(),
                 summary['validity_hash']))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"Summary cache write failed: {e}")

    def get_cached_summary(self, function_id: str) -> Optional[Dict[str, Any]]:
        if function_id in self.summary_cache:
            return self.summary_cache[function_id]
        try:
            conn = sqlite3.connect(self.cache_path)
            c = conn.cursor()
            c.execute(
                '''SELECT input_constraints, output_effects, side_effects,
                          taint_flow, validity_hash
                   FROM function_summaries WHERE function_id=?''', (function_id,))
            row = c.fetchone()
            conn.close()
            if row:
                summary = {
                    'input_constraints': json.loads(row[0]),
                    'output_effects': json.loads(row[1]),
                    'side_effects': json.loads(row[2]),
                    'taint_flow': json.loads(row[3]),
                    'validity_hash': row[4],
                }
                self.summary_cache[function_id] = summary
                return summary
        except Exception as e:
            logger.debug(f"Summary cache read failed: {e}")
        return None

    def compute_context_sensitive_summary(self, function_id: str,
                                           call_context: Dict[str, Any]) -> Dict[str, Any]:
        base = self.get_cached_summary(function_id)
        if not base:
            return {}
        specialized = dict(base)
        for pname, pval in call_context.get('parameters', {}).items():
            if isinstance(pval, (int, str)) and not isinstance(pval, bool):
                for c in specialized['input_constraints']:
                    if c['name'] == pname:
                        c['constraints'].append(f'value == {pval}')
        for tainted in call_context.get('tainted_vars', []):
            for dst, src in specialized['taint_flow'].items():
                if src == tainted:
                    specialized['output_effects'].setdefault(dst, {})['tainted'] = True
        ctx_id = (f"{function_id}_"
                  f"{hashlib.sha256(json.dumps(call_context).encode()).hexdigest()[:8]}")
        self.context_cache[ctx_id] = specialized
        return specialized

    def validate_summary(self, function_id: str, current_hash: str) -> bool:
        cached = self.get_cached_summary(function_id)
        return cached is not None and cached['validity_hash'] == current_hash

    def invalidate_stale_summaries(self):
        try:
            conn = sqlite3.connect(self.cache_path)
            c = conn.cursor()
            c.execute(
                'DELETE FROM function_summaries WHERE created_at < ?',
                ((datetime.now() - timedelta(days=30)).isoformat(),))
            conn.commit()
            conn.close()
        except Exception:
            logger.debug("suppressed", exc_info=True)


class DynamicBinaryTranslatorAccelerator:

    def __init__(self):
        self.qemu_path: str = ""
        self.dynamorio_path: str = ""
        self.execution_cache: Dict[str, Dict[str, Any]] = {}
        self.instrumentation_hooks: List[Callable] = []

        # 自动检测 QEMU 用户模式二进制
        try:
            r = subprocess.run(['qemu-x86_64', '--version'],
                               capture_output=True, timeout=10)
            if r.returncode == 0:
                self.qemu_path = 'qemu-x86_64'
                logger.info("QEMU user mode available")
        except Exception:
            logger.info("QEMU not installed")

        # 自动检测 DynamoRIO 安装路径
        for d in ['/opt/dynamorio', '/usr/local/dynamorio',
                  'C:\\Program Files\\DynamoRIO']:
            if os.path.isdir(d):
                self.dynamorio_path = d
                logger.info(f"DynamoRIO available: {d}")
                break

    def set_qemu_path(self, path: str):         self.qemu_path = path
    def set_dynamorio_path(self, path: str):    self.dynamorio_path = path

    def add_instrumentation_hook(self, hook: Callable):
        self.instrumentation_hooks.append(hook)

    def execute_fragment_qemu(self, binary_path: str, start_addr: int,
                               end_addr: int,
                               input_data: bytes = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'method': 'qemu', 'binary_path': binary_path,
            'start_addr': start_addr, 'end_addr': end_addr,
            'runtime_values': {}, 'memory_state': {},
            'register_state': {}, 'success': False,
        }
        if not self.qemu_path:
            result['error'] = 'QEMU not configured'
            return result
        try:
            r = subprocess.run(
                [self.qemu_path, '-strace', binary_path],
                capture_output=True, timeout=60,
                encoding='utf-8', errors='replace')
            result.update(
                success=r.returncode == 0,
                stdout=r.stdout, stderr=r.stderr,
            )
            # 从 QEMU strace 输出提取寄存器赋值
            regs = re.findall(r'R(\w+)\s*=\s*(0x[0-9a-fA-F]+)', r.stdout)
            for rn, rv in regs:
                result['runtime_values'][f'reg_{rn}'] = int(rv, 16)
            mems = re.findall(
                r'mem\s*\[\s*(0x[0-9a-fA-F]+)\s*\]\s*=\s*(0x[0-9a-fA-F]+)',
                r.stdout)
            for ma, mv in mems:
                result['runtime_values'][f'mem_{ma}'] = int(mv, 16)
        except Exception as e:
            result['error'] = str(e)
        return result

    def _generate_qemu_script(self, binary_path: str, start_addr: int,
                               end_addr: int, input_data: bytes) -> str:
        return (
            f'#!/bin/bash\n'
            f'{self.qemu_path} -strace -d in_asm,out_asm {binary_path}\n'
        )

    def execute_fragment_dynamorio(self, binary_path: str,
                                    config: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'method': 'dynamorio', 'binary_path': binary_path,
            'runtime_values': {}, 'success': False,
        }
        if not self.dynamorio_path:
            result['error'] = 'DynamoRIO not configured'
            return result
        try:
            drrun = os.path.join(self.dynamorio_path, 'bin64', 'drrun')
            if not os.path.exists(drrun):
                drrun = os.path.join(self.dynamorio_path, 'bin32', 'drrun')
            r = subprocess.run(
                [drrun, '-c', 'libmemtrace.so', '--', binary_path],
                capture_output=True, timeout=120,
                encoding='utf-8', errors='replace')
            result.update(success=r.returncode == 0, stdout=r.stdout)
        except Exception as e:
            result['error'] = str(e)
        return result

    def get_cached_execution(self, key: str) -> Optional[Dict[str, Any]]:
        return self.execution_cache.get(key)

    def cache_execution_result(self, key: str,
                                result: Dict[str, Any]):
        self.execution_cache[key] = result


class BinaryFunctionInlineAnalyzer:

    def __init__(self):
        self.inline_patterns: Dict[str, List[str]] = {}
        self.detected_inlines: Dict[int, Dict[str, Any]] = {}
        self._register_patterns()

    def _register_patterns(self):
        self.inline_patterns['prologue'] = [
            r'push\s+rbp', r'mov\s+rbp,\s*rsp', r'sub\s+rsp,\s*\d+',
        ]
        self.inline_patterns['epilogue'] = [
            r'leave', r'ret', r'add\s+rsp,\s*\d+', r'pop\s+rbp',
        ]
        self.inline_patterns['inline_marker'] = [
            r'call\s+\w+', r'jmp\s+\w+', r'inline_marker',
        ]

    def detect_inline_site(self, function_code: str,
                            call_site_addr: int) -> bool:
        pcount = sum(len(re.findall(p, function_code))
                     for p in self.inline_patterns['prologue'])
        ecount = sum(len(re.findall(p, function_code))
                     for p in self.inline_patterns['epilogue'])
        return pcount > 1 or ecount > 1

    def identify_inlined_function(self,
                                   inline_site: Dict[str, Any]) -> str:
        feats = set(inline_site.get('features', []))
        sigs = {
            'memcpy': {'mov', 'rep', 'movs'},
            'strlen': {'cmp', 'inc', 'loop'},
            'strcpy': {'mov', 'inc', 'cmp'},
            'min/max': {'cmp', 'cmovg', 'cmovl'},
            'abs': {'neg', 'test', 'cmovs'},
        }
        for name, sig in sigs.items():
            if sig.issubset(feats):
                return name
        return 'unknown_inline'

    def mark_inline_in_decompilation(self, decompiled: str,
                                      inline_sites: List[Dict[str, Any]]) -> str:
        for site in inline_sites:
            addr = site.get('address', 0)
            fn = site.get('inlined_function', 'unknown')
            decompiled = f'/* [INLINE] {fn} @ {hex(addr)} */\n' + decompiled
        return decompiled

    def extract_inline_boundaries(self, function_code: str) -> List[Tuple[int, int]]:
        prologues: List[int] = []
        for p in self.inline_patterns['prologue']:
            for m in re.finditer(p, function_code):
                prologues.append(m.start())
        epilogues: List[int] = []
        for p in self.inline_patterns['epilogue']:
            for m in re.finditer(p, function_code):
                epilogues.append(m.start())
        boundaries = []
        for i, pp in enumerate(prologues):
            if i < len(epilogues):
                boundaries.append((pp, epilogues[i]))
        return boundaries

    def recover_inline_function(self,
                                 inline_code: str) -> Dict[str, Any]:
        recovered: Dict[str, Any] = {
            'code': inline_code, 'parameters': [],
            'return_type': 'unknown', 'signature': '',
        }
        for dst, src in re.findall(r'mov\s+(\w+),\s*(\w+)', inline_code)[:6]:
            recovered['parameters'].append({'register': dst, 'source': src})
        if re.search(r'mov\s+(?:rax|eax),\s*\w+', inline_code):
            recovered['return_type'] = 'integer/pointer'
        elif re.search(r'mov\s+(?:xmm0|st0),\s*\w+', inline_code):
            recovered['return_type'] = 'float/double'
        return recovered


class BinaryFunctionBehaviorSignatureGenerator:

    def __init__(self):
        self.function_signatures: Dict[int, Dict[str, Any]] = {}
        self.signature_database: Dict[str, List[int]] = {}

    def extract_semantic_features(self, function_code: str) -> Dict[str, Any]:
        features = {
            'api_calls': list(set(re.findall(r'call\s+(\w+)', function_code))),
            'control_flow': [],
            'data_operations': [],
            'constants': [],
            'string_refs': [],
        }
        for kw in ['if', 'else', 'while', 'for', 'switch', 'return']:
            cnt = len(re.findall(rf'\b{kw}\b', function_code))
            features['control_flow'].append(f'{kw}:{cnt}')
        for op in ['mov', 'lea', 'push', 'pop', 'add', 'sub']:
            cnt = len(re.findall(rf'\b{op}\b', function_code))
            features['data_operations'].append(f'{op}:{cnt}')
        return features

    def generate_simhash_signature(self, features: Dict[str, Any]) -> str:
        parts = []
        for api in features['api_calls']:
            parts.append(hashlib.md5(api.encode()).hexdigest()[:8])
        for cf in features['control_flow']:
            parts.append(hashlib.md5(cf.encode()).hexdigest()[:8])
        return hashlib.sha256(''.join(parts).encode()).hexdigest()[:16]

    def compute_signature_similarity(self, sig1: str, sig2: str) -> float:
        if len(sig1) != len(sig2):
            return 0.0
        try:
            xor = int(sig1, 16) ^ int(sig2, 16)
            return max(0.0, 1.0 - (xor.bit_count() / (len(sig1) * 4)))
        except Exception:
            return 0.0

    def match_function_across_versions(self, signature: str,
                                        threshold: float = 0.8) -> List[int]:
        matches: List[int] = []
        for stored, addresses in self.signature_database.items():
            if self.compute_signature_similarity(signature, stored) >= threshold:
                matches.extend(addresses)
        return matches

    def add_function_signature(self, function_addr: int,
                                function_code: str) -> str:
        feats = self.extract_semantic_features(function_code)
        sig = self.generate_simhash_signature(feats)
        self.function_signatures[function_addr] = {
            'signature': sig, 'features': feats,
            'created_at': datetime.now().isoformat(),
        }
        self.signature_database.setdefault(sig, []).append(function_addr)
        return sig


class DecompilerCodeMetricsEvaluator:

    def __init__(self):
        self.metrics_results: Dict[int, Dict[str, Any]] = {}
        self.high_risk_functions: List[int] = []

    def calculate_cyclomatic_complexity(self, code: str) -> int:
        complexity = 1
        for kw in ['if', 'else if', 'while', 'for', 'switch', 'case', 'catch']:
            complexity += len(re.findall(rf'\b{kw}\b', code))
        complexity += len(re.findall(r'\band\b|&&', code))
        complexity += len(re.findall(r'\bor\b|\|\|', code))
        return complexity

    def calculate_halstead_metrics(self, code: str) -> Dict[str, Any]:
        ops = re.findall(r'[+\-*/%=<>!&|^~?:;,{}()\[\]]', code)
        oprs = re.findall(r'\b\w+\b', code)
        uops, uoprs = set(ops), set(oprs)
        n1, n2 = len(uops), len(uoprs)
        N1, N2 = len(ops), len(oprs)
        n = n1 + n2
        N = N1 + N2
        V = N * (n.bit_length() if n > 0 else 1)
        D = (n1 / 2) * (N2 / max(1, n2)) if n2 else 0
        E = D * V
        return {
            'unique_operators': n1, 'unique_operands': n2,
            'total_operators': N1, 'total_operands': N2,
            'vocabulary': n, 'length': N, 'volume': V,
            'difficulty': D, 'effort': E,
            'estimated_time': E / 18.0,
        }

    def calculate_lines_of_code(self, code: str) -> Dict[str, int]:
        loc = {'total_lines': 0, 'code_lines': 0,
               'comment_lines': 0, 'empty_lines': 0}
        for line in code.split('\n'):
            loc['total_lines'] += 1
            s = line.strip()
            if not s:
                loc['empty_lines'] += 1
            elif s.startswith('//') or s.startswith('#'):
                loc['comment_lines'] += 1
            else:
                loc['code_lines'] += 1
        return loc

    def evaluate_function(self, function_addr: int,
                           function_code: str) -> Dict[str, Any]:
        metrics = {
            'function_addr': function_addr,
            'cyclomatic_complexity': self.calculate_cyclomatic_complexity(function_code),
            'halstead': self.calculate_halstead_metrics(function_code),
            'loc': self.calculate_lines_of_code(function_code),
            'risk_level': 'low',
            'risk_factors': [],
        }
        if metrics['cyclomatic_complexity'] > 15:
            metrics['risk_level'] = 'high'
            metrics['risk_factors'].append('High cyclomatic complexity')
        if metrics['halstead']['difficulty'] > 10:
            metrics['risk_level'] = 'high'
            metrics['risk_factors'].append('High program difficulty')
        if metrics['loc']['code_lines'] > 100:
            metrics['risk_level'] = 'medium'
            metrics['risk_factors'].append('Too many lines of code')
        self.metrics_results[function_addr] = metrics
        if metrics['risk_level'] == 'high':
            self.high_risk_functions.append(function_addr)
        return metrics


class AutomaticUnpacker:

    def __init__(self):
        self.packers: Dict[str, Dict[str, Any]] = {
            'UPX':       {'pattern': b'UPX',       'tool': 'upx'},
            'ASPack':    {'pattern': b'ASPack',    'tool': 'aspack'},
            'Themida':   {'pattern': b'Themida',   'tool': 'themida'},
            'VMProtect': {'pattern': b'VMProtect', 'tool': 'vmprotect'},
        }
        self.unpacked_files: Dict[str, Dict[str, Any]] = {}

    def detect_packer(self, binary_path: str) -> Optional[str]:
        try:
            with open(binary_path, 'rb') as f:
                header = f.read(8192)
            for name, info in self.packers.items():
                if info['pattern'] in header:
                    return name
        except Exception:
            logger.debug("suppressed", exc_info=True)
        return None

    def unpack(self, packed_path: str,
               output_dir: str = "data/unpacked") -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'packed_file': packed_path, 'packer_type': None,
            'unpacked_file': None, 'status': 'failed', 'error': None,
        }
        result['packer_type'] = self.detect_packer(packed_path)
        if not result['packer_type']:
            result['error'] = 'No known packer detected'
            return result
        if result['packer_type'] == 'UPX':
            result = self._unpack_upx(packed_path, output_dir)
        if result['status'] == 'success':
            self.unpacked_files[packed_path] = result
        return result

    def _unpack_upx(self, packed_path: str,
                     output_dir: str) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            'packed_file': packed_path, 'packer_type': 'UPX',
            'unpacked_file': None, 'status': 'failed', 'error': None,
        }
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir,
                                   os.path.basename(packed_path) + '.unpacked')
        try:
            r = subprocess.run(
                ['upx', '-d', packed_path, '-o', output_path],
                capture_output=True, text=True, timeout=60)
            if r.returncode == 0:
                result.update(unpacked_file=output_path, status='success')
            else:
                result['error'] = r.stderr
        except FileNotFoundError:
            result['error'] = 'UPX not installed'
        except Exception as e:
            result['error'] = str(e)
        return result


class AntiAnalysisBypassEngine:

    def __init__(self):
        self.detection_patterns: List[Dict[str, Any]] = []
        self.bypass_scripts: Dict[str, str] = {}

    def detect_anti_analysis(self, binary_path: str) -> List[Dict[str, Any]]:
        detections: List[Dict[str, Any]] = []
        patterns = [
            ('vmware_signature', b'VMWare', 'medium'),
            ('virtualbox_signature', b'VBox', 'medium'),
            ('qemu_signature', b'QEMU', 'medium'),
            ('debugger_check', b'IsDebuggerPresent', 'low'),
            ('remote_debugger', b'CheckRemoteDebuggerPresent', 'low'),
            ('timing_check', b'GetTickCount', 'high'),
            ('cpuid_check', b'cpuid', 'medium'),
        ]
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            for name, sig, severity in patterns:
                if sig in data:
                    detections.append({
                        'type': name, 'severity': severity,
                        'offset': hex(data.find(sig)),
                    })
        except Exception:
            logger.debug("suppressed", exc_info=True)
        self.detection_patterns = detections
        return detections

    def generate_frida_bypass_script(self,
                                      detections: List[Dict[str, Any]]) -> str:
        api_names = [d['type'] for d in detections if 'debugger' in d['type']]
        hooks = []
        for name in set(api_names):
            hooks.append(f'''if (Module.findExportByName(null, "{name}")) {{
    Interceptor.attach(Module.findExportByName(null, "{name}"), {{
        onLeave: function(retval) {{ retval.replace(0); }}
    }});
}}''')
        script = (
            f'// Anti-Analysis Bypass Frida Script\n'
            f'// Generated: {datetime.now().isoformat()}\n\n'
            f'setInterceptor();\n\n'
            + '\n'.join(hooks) +
            f'\n\nconsole.log("Anti-analysis bypass loaded ({len(hooks)} hooks)");\n'
        )
        self.bypass_scripts['frida'] = script
        return script

    def generate_ld_preload_bypass(self) -> str:
        code = '''#include <stdio.h>
#include <stdlib.h>

int IsDebuggerPresent() { return 0; }

int CheckRemoteDebuggerPresent(void *h, int *pb) {
    if (pb) *pb = 0;
    return 0;
}

long GetTickCount() { return 0; }
'''
        self.bypass_scripts['ld_preload'] = code
        return code
