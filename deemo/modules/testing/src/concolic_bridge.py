# Concolic执行桥接器 — 混合Fuzzing的轻量符号执行后端
# 提供fuzzer与SMT求解器的双向桥接: 从fuzzer获取触发新覆盖的输入，
# 对其执行路径分支条件做符号化，翻转约束生成穿透magic bytes等
# 复杂比较的新输入。参考Driller / QSYM / SAVIOR的混合执行范式。
#
# 文献:
#   Stephens et al. NDSS 2016, "Driller: Augmenting Fuzzing Through
#     Selective Symbolic Execution"
#   Yun et al. USENIX 2018, "QSYM: A Practical Concolic Execution Engine"
#   Chen & Chen. CCS 2019, "Angora: Efficient Fuzzing by Principled Search"
#   Poeplau & Francillon. USENIX 2020, "Symbolic Execution with SymCC"
#
# 设计策略: 不实现完整符号执行引擎（需中间语言和约束求解器绑定），
# 在Python层提供路径约束的收集、哈希、分支翻转和z3约束生成接口。
# 实际符号执行委托给外部工具 (angr/Triton/SymCC)。
import hashlib
import struct
from typing import List, Dict, Tuple, Optional, Set, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class PathConstraint:
    """单个分支条件: 在特定地址比较某段输入字节与常量/表达式的真/假分支。"""
    branch_addr: int                    # 分支指令地址
    taken: bool                         # 实际执行走向 (True/False)
    constraint_expr: str                # 约束字符串表示 (如 "input[0:4] < 0x1000")
    input_offset: int = 0               # 涉及的输入字节起始偏移
    input_size: int = 4                 # 涉及的长度 (字节)
    operand_value: int = 0              # 比较中的常量操作数
    comparison: str = "=="             # 比较类型: ==, !=, <, >, <=, >=

    def to_dict(self) -> Dict[str, Any]:
        return {
            'addr': hex(self.branch_addr),
            'taken': self.taken,
            'expr': self.constraint_expr,
            'offset': self.input_offset,
            'size': self.input_size,
            'value': hex(self.operand_value),
            'cmp': self.comparison,
        }


@dataclass
class SymbolicInput:
    """带符号标记的输入: 标记哪些字节是符号化的（可由求解器赋值）。

    其余字节保持具体值。
    """
    concrete: bytearray                 # 具体字节值
    symbolic_mask: List[bool]           # True=符号化, False=具体
    constraints: List[PathConstraint] = field(default_factory=list)

    def symbolic_offsets(self) -> List[int]:
        return [i for i, sym in enumerate(self.symbolic_mask) if sym]

    def concrete_only(self) -> bytes:
        return bytes(self.concrete)


class BranchConstraintCollector:
    """收集和索引执行路径上的分支约束。

    对外部符号执行工具提供:
    - 查询: 给定分支地址是否有约束记录
    - 翻转: 对某约束取反产生新目标路径条件
    - 新颖性判断: 翻转后的路径是否已被探索
    """

    def __init__(self):
        self._constraints: Dict[int, List[PathConstraint]] = defaultdict(list)
        self._path_signatures: Set[str] = set()
        self._branch_coverage: Set[int] = set()

    def record_branch(self, constraint: PathConstraint) -> None:
        self._constraints[constraint.branch_addr].append(constraint)
        self._branch_coverage.add(constraint.branch_addr)

    def record_path(self, constraints: List[PathConstraint]) -> None:
        """记录一条完整执行路径（约束列表）。"""
        sig = self._path_signature(constraints)
        self._path_signatures.add(sig)
        for c in constraints:
            self.record_branch(c)

    def negate_constraint(self, constraint: PathConstraint) -> PathConstraint:
        """翻转约束条件: 若原条件为 input[0:4] < 0x1000，
        翻转后为 input[0:4] >= 0x1000。
        """
        negated = PathConstraint(
            branch_addr=constraint.branch_addr,
            taken=not constraint.taken,
            constraint_expr="",
            input_offset=constraint.input_offset,
            input_size=constraint.input_size,
            operand_value=constraint.operand_value,
            comparison=self._negate_comparison(constraint.comparison),
        )
        negated.constraint_expr = self._build_expr(negated)
        return negated

    def _build_expr(self, c: PathConstraint) -> str:
        return f"input[{c.input_offset}:{c.input_offset + c.input_size}] {c.comparison} {hex(c.operand_value)}"

    @staticmethod
    def _negate_comparison(cmp: str) -> str:
        neg_map = {"==": "!=", "!=": "==", "<": ">=", "<=": ">",
                   ">": "<=", ">=": "<"}
        return neg_map.get(cmp, "!=")

    @staticmethod
    def _path_signature(constraints: List[PathConstraint]) -> str:
        """路径签名 = 分支地址序列 + taken方向。"""
        parts = [f"{c.branch_addr:x}:{1 if c.taken else 0}"
                 for c in constraints]
        return hashlib.sha256('|'.join(parts).encode()).hexdigest()[:16]

    def should_explore(self, negated: PathConstraint) -> bool:
        """翻转后的分支是否值得探索（该地址尚未被覆盖）。"""
        return negated.branch_addr not in self._branch_coverage

    def branch_frontier(self) -> List[PathConstraint]:
        """返回所有只走了一侧的分支（另一侧未探索的约束）。

        这些是需要符号执行求解的"边界"。
        """
        frontier = []
        for addr, constraints in self._constraints.items():
            taken_sides = {c.taken for c in constraints}
            # 只走了True或只走了False -> 另一侧是frontier
            if len(taken_sides) == 1:
                for c in constraints:
                    frontier.append(self.negate_constraint(c))
                    break  # 每个地址只加一次
        return frontier

    @property
    def unique_branches(self) -> int:
        return len(self._branch_coverage)

    @property
    def path_count(self) -> int:
        return len(self._path_signatures)


class ConcolicBridge:
    """混合fuzzing桥接器: 连接fuzzer和符号执行引擎。

    工作流:
    1. fuzzer发现使覆盖率增长的输入 -> 送入桥接器
    2. 桥接器调用符号执行引擎 (angr/Triton) 收集路径约束
    3. 对未探索分支翻转约束 -> 生成SMT查询
    4. 求解器产生新输入 -> 反馈到fuzzer种子池

    当前实现: Python层约束收集 + z3表达式构造。
    实际符号执行需外部引擎 (默认使用angr的Python API或
    通过subprocess调用SymCC编译的二进制)。
    """

    def __init__(self, target_binary: str = "",
                 solver_backend: str = "z3"):
        """
        solver_backend: "z3" (推荐) | "cvc5" | "yices" | "none"
           "none" = 仅收集约束，不实际求解
        """
        self._target = target_binary
        self._solver = solver_backend
        self._collector = BranchConstraintCollector()
        self._solved_inputs: Set[str] = set()  # 已求解输入的哈希
        self._solve_count = 0
        self._sovle_time_total = 0.0
        # 外部执行引擎回调: (input: bytes) -> List[PathConstraint]
        self._exec_callback: Optional[Callable] = None

    # 外部引擎绑定
    def set_executor(self, callback: Callable[[bytes], List[PathConstraint]]
                     ) -> None:
        """绑定外部符号执行回调。

        回调接收具体输入，返回从该输入执行中收集的PathConstraint列表。
        """
        self._exec_callback = callback

    # 约束收集
    def explore_input(self, input_data: bytes) -> List[PathConstraint]:
        in_hash = hashlib.sha256(input_data).hexdigest()
        if in_hash in self._solved_inputs:
            return []

        constraints = []
        if self._exec_callback:
            constraints = self._exec_callback(input_data)
            self._collector.record_path(constraints)

        self._solved_inputs.add(in_hash)
        return constraints

    # 分支翻转
    def generate_solve_targets(self) -> List[PathConstraint]:
        """获取当前未探索分支的翻转约束列表。

        每个翻转约束对应一个SMT求解目标。
        """
        return self._collector.branch_frontier()

    def build_z3_expr(self, constraint: PathConstraint) -> Optional[str]:
        """将PathConstraint转换为z3 SMT-LIB2格式字符串。

        用于将求解请求发送给外部z3进程。

        返回示例:
          (assert (bvult (concat ...) #x00001000))
        """
        sz = constraint.input_size
        off = constraint.input_offset
        val = constraint.operand_value

        # 构造输入符号变量
        sym_name = f"input_{off}_{sz}"
        sym_decl = f"(declare-const {sym_name} (_ BitVec {sz * 8}))"

        # 构造常量值
        const_val = f"#x{val:0{sz * 2}x}"

        # 映射比较操作符到SMT-LIB2
        smt_cmp = {
            "==": "=", "!=": "distinct",
            "<": "bvult", "<=": "bvule",
            ">": "bvugt", ">=": "bvuge",
        }.get(constraint.comparison, "=")

        if constraint.comparison in ("!=",):
            assertion = f"({smt_cmp} {sym_name} {const_val})"
        else:
            assertion = f"({smt_cmp} {sym_name} {const_val})"

        return f"{sym_decl}\n(assert {assertion})\n(check-sat)\n(get-model)"

    def solve_for_input(self, constraint: PathConstraint) -> Optional[bytes]:
        import subprocess
        import tempfile
        import os

        self._solve_count += 1
        smt_code = self.build_z3_expr(constraint)
        if smt_code is None:
            return None

        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.smt2', delete=False) as f:
                f.write(smt_code)
                smt_path = f.name

            import time as _t
            t0 = _t.perf_counter()
            result = subprocess.run(
                ['z3', smt_path],
                capture_output=True, text=True, timeout=30)
            self._sovle_time_total += _t.perf_counter() - t0

            os.unlink(smt_path)

            if 'unsat' in result.stdout.lower():
                return None
            if 'sat' in result.stdout.lower():
                return self._parse_z3_model(
                    result.stdout, constraint)
            return None
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None
        except OSError:
            # SMT文件写入失败，不可恢复
            return None

    @staticmethod
    def _parse_z3_model(output: str,
                        constraint: PathConstraint) -> Optional[bytes]:
        """从z3 get-model输出解析符号变量的具体赋值。

        格式: (define-fun input_0_4 () (_ BitVec 32) #x00001000)
        """
        import re
        pat = re.compile(
            r'define-fun\s+(\w+)\s*\(\)\s*.*?#x([0-9a-fA-F]+)')
        values = {}
        for m in pat.finditer(output):
            name = m.group(1)
            hex_val = m.group(2)
            values[name] = int(hex_val, 16)

        key = f"input_{constraint.input_offset}_{constraint.input_size}"
        if key in values:
            return values[key].to_bytes(
                constraint.input_size, 'big')
        return None

    # 双向反馈
    def fuzz_to_symbolic(self, interesting_inputs: List[bytes]
                         ) -> List[bytes]:
        """从fuzzer的有趣输入集中筛选 -> 符号执行 -> 产出新输入。

        返回可直接加入fuzzer种子池的新输入列表。
        """
        new_seeds = []
        for inp in interesting_inputs[:32]:  # 上限32以避免符号执行开销爆炸
            constraints = self.explore_input(inp)
            if not constraints:
                continue
            # 对每个未探索分支翻转并求解
            for c in self._collector.branch_frontier()[:8]:
                solved = self.solve_for_input(c)
                if solved and len(solved) > 0:
                    h = hashlib.sha256(solved).hexdigest()
                    if h not in self._solved_inputs:
                        new_seeds.append(solved)
                        self._solved_inputs.add(h)
        return new_seeds

    # 统计
    def stats(self) -> Dict[str, Any]:
        return {
            'unique_branches': self._collector.unique_branches,
            'explored_paths': self._collector.path_count,
            'frontier_size': len(self._collector.branch_frontier()),
            'solved_inputs': len(self._solved_inputs),
            'solve_attempts': self._solve_count,
            'solver_time_total_s': round(self._sovle_time_total, 3),
            'solver_backend': self._solver,
        }

    def reset(self) -> None:
        self._collector = BranchConstraintCollector()
        self._solved_inputs.clear()
        self._solve_count = 0
        self._sovle_time_total = 0.0


class MagicBytesBypassGenerator:
    """为ConcolicBridge提供魔数穿透的特定约束生成。

    常见场景: if (input[0:4] == 0x7F454C46) — ELF头部检查。
    对这类精确匹配约束做专门化处理: 直接生成满足比较的输入。

    参考Angora的字节级污点追踪和梯度下降求解。
    """

    @staticmethod
    def generate_satisfying_input(
            base: bytes, offset: int, size: int,
            target_value: int) -> Optional[bytes]:
        """生成一个在offset处满足==target_value的新输入。"""
        if offset + size > len(base):
            # 扩展输入
            extended = bytearray(base)
            extended.extend(b'\x00' * (offset + size - len(base)))
            base = bytes(extended)
        buf = bytearray(base)
        try:
            buf[offset:offset + size] = target_value.to_bytes(
                size, 'big')
        except OverflowError:
            buf[offset:offset + size] = target_value.to_bytes(
                size, 'little')
        return bytes(buf)

    @staticmethod
    def known_magic_values() -> Dict[str, Tuple[int, int, int]]:
        """返回已知文件魔数: {名称: (偏移, 大小, 值)}。"""
        return {
            'ELF': (0, 4, 0x7F454C46),
            'PNG': (0, 8, 0x89504E470D0A1A0A),
            'PE_MZ': (0, 2, 0x4D5A),
            'JPEG': (0, 3, 0xFFD8FF),
            'GIF87a': (0, 6, 0x474946383761),
            'GIF89a': (0, 6, 0x474946383961),
            'BZIP2': (0, 3, 0x425A68),
            'GZIP': (0, 3, 0x1F8B08),
            'PDF': (0, 4, 0x25504446),
            'ZIP': (0, 4, 0x504B0304),
            'RAR': (0, 4, 0x52617221),
            '7Z': (0, 6, 0x377ABCAF271C),
        }


def bridge_angr_to_constraints(angr_project,
                               input_data: bytes) -> List[PathConstraint]:
    """将angr项目上的执行结果转换为PathConstraint列表。

    外部引擎回调的参考实现模板。

    使用方式:
      bridge = ConcolicBridge()
      bridge.set_executor(
          lambda data: bridge_angr_to_constraints(proj, data))
    """
    constraints = []
    try:
        import angr  # type: ignore
        import claripy  # type: ignore
    except ImportError:
        return constraints

    # 创建带有符号输入的状态
    sym_input = claripy.BVS('input', len(input_data) * 8)
    state = angr_project.factory.entry_state(stdin=sym_input)

    # 约束具体输入的前缀以匹配执行路径
    for i, byte_val in enumerate(input_data):
        state.solver.add(
            sym_input.get_byte(i) == byte_val)

    simgr = angr_project.factory.simulation_manager(state)

    # 执行一步以收集约束
    try:
        simgr.step()
    except Exception:
        return constraints

    if simgr.active:
        active_state = simgr.active[0]
        for c in active_state.solver.constraints:
            # 将claripy约束转换为PathConstraint
            constraints.append(PathConstraint(
                branch_addr=active_state.addr,
                taken=True,
                constraint_expr=str(c),
                input_offset=0,
                input_size=len(input_data),
            ))

    return constraints
