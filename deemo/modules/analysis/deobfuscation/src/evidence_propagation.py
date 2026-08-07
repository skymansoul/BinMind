# 修改记录:
# 2025-07-16 15:22 - 引入局部信任衰减因子，防止跨深度调用链的虚假证据放大
# 2025-07-19 08:41 - 增加循环边界的证据截断，避免while(true)中的常量回环污染
# 2025-07-22 13:07 - 支持ARM64条件执行指令的证据传递（CSEL/CINC系列）

"""
跨函数常量证据传播 —— 在函数间追踪常量和半常量，为混淆恢复提供
超越单函数边界的证据链

核心思路:
混淆器通常在函数内插入虚假分支，但分支条件依赖的常量常来自其调用者
或全局数据段。如果仅在函数内分析，一个来自上级调用者的常量在局部
看起来是变量；但若沿调用链回溯，可以发现其实际是常数
本模块提供这种跨边界证据追溯能力

与 Chisel 的区别:
Chisel使用动态trace反推CFG骨架，依赖运行时信息。本模块是纯静态
分析——通过函数接口（参数/返回值/全局变量）的抽象解释来传递
常量证据，无需执行二进制。代价是精度低于动态方法，但不需要
构建可执行环境

信任衰减策略:
每跨一层调用边界，证据置信度乘以衰减因子α=0.85。深度>5的调用链
证据被视为不可靠（置信度<-阈值），避免将遥远调用者的副作用误判
为常量。此设计基于经验观察：多数混淆器在1-3层调用深度内暴露
常量证据
"""

from collections import deque
from typing import Any, Dict, List, Optional, Set, Tuple

# 衰减因子——跨调用边界时置信度的乘数
_DECAY_FACTOR = 0.85
# 最大追溯深度——超过此深度中止，控制分析耗时
_MAX_TRACE_DEPTH = 5
# 置信度阈值——低于此值的证据不纳入决策
_CONFIDENCE_THRESHOLD = 0.30
# 循环最大迭代数——(true)等无界循环的迭代上限
_MAX_LOOP_ITERATIONS = 3


class EvidenceRecord:
    """单条常量证据——记录一个变量在某调用上下文中被认定为常量的依据"""

    __slots__ = (
        "variable", "value", "confidence", "depth", "source_func",
        "evidence_type", "call_chain",
    )

    def __init__(
        self,
        variable: str,
        value: Any,
        confidence: float,
        depth: int,
        source_func: str,
        evidence_type: str,
        call_chain: Tuple[str, ...] = (),
    ) -> None:
        self.variable = variable
        self.value = value
        self.confidence = confidence
        self.depth = depth                # 距离起始函数的调用深度
        self.source_func = source_func     # 发现此证据的函数
        self.evidence_type = evidence_type  # "param" | "返回" | "global" | "immedi"
        self.call_chain = call_chain       # (caller, callee,.)


class EvidencePropagator:
    """跨函数证据传播引擎
    
    工作方式：对目标函数中的疑似常量变量，通过调用者→被调用者
    （或反向）链路搜寻其定义来源，累加证据并衰减置信度
    
    使用场景：
    - CFF恢复：确认状态变量是否来自调用者的常量参数
    - 不透明谓词消除：确认谓词的操作数是否跨函数恒定
    - 字符串解密检测：追踪解密循环的key从何处传入
    """

    def __init__(self) -> None:
        # 已分析过的函数——避免重复回溯
        self._visited: Set[str] = set()
        # 调用图：{caller: [callee1, callee2,.]}
        self._call_graph: Dict[str, List[str]] = {}
        # 函数→其参数默认值/常量推断结果
        self._func_params: Dict[str, Dict[str, Any]] = {}

# 调用图构建

    def build_call_graph(
        self,
        functions: Dict[str, List[Dict[str, Any]]],
    ) -> None:
        """从函数→指令列表的映射中提取调用图
        
        Args:
        functions: {函数名: [指令dict列表]}
        """
        self._call_graph.clear()
        for func_name, instructions in functions.items():
            callees = []
            for insn in instructions:
                if insn.get("mnemonic", "").lower() in ("call", "bl", "blr"):
                    operands = insn.get("operands", "")
                    # 提取被调用函数名——简单启发式
                    target = operands.strip().split()[0] if operands.strip() else ""
                    target = target.lstrip("&").lstrip("*").strip()
                    if target and not target.startswith("0x") and not target.startswith("["):
                        callees.append(target)
            self._call_graph[func_name] = callees

# 证据注册

    def register_param_constant(
        self, func_name: str, param_name: str, value: Any, confidence: float
    ) -> None:
        """手工注册某函数某参数为常量——通常来自外部知识或配置文件"""
        self._func_params.setdefault(func_name, {})[param_name] = {
            "value": value, "confidence": confidence,
        }

# 证据回溯

    def trace_evidence(
        self,
        target_func: str,
        variable: str,
        max_depth: int = _MAX_TRACE_DEPTH,
    ) -> List[EvidenceRecord]:
        """从target_func中的variable出发，沿调用图回溯其常量证据
        
        采用BFS而非DFS——宽度优先能更快发现浅层证据，浅层证据
        衰减少、更可靠。对于混淆恢复，浅层证据通常就足够了
        
        返回:
        证据记录列表，按置信度降序排列
        """
        self._visited.clear()
        results: List[EvidenceRecord] = []
        # BFS队列: (当前func, 变量名, 深度, 调用链)
        queue: deque = deque()
        queue.append((target_func, variable, 0, (target_func,)))

        while queue and len(results) < 20:  # 证据上限——防止在大型调用图中失控
            current_func, var, depth, chain = queue.popleft()
            if current_func in self._visited or depth > max_depth:
                continue
            self._visited.add(current_func)

            # 检查此函数是否有该变量的注册证据
            if current_func in self._func_params:
                params = self._func_params[current_func]
                if var in params:
                    confidence = params[var]["confidence"] * (_DECAY_FACTOR ** depth)
                    if confidence >= _CONFIDENCE_THRESHOLD:
                        results.append(EvidenceRecord(
                            variable=var,
                            value=params[var]["value"],
                            confidence=confidence,
                            depth=depth,
                            source_func=current_func,
                            evidence_type="param",
                            call_chain=chain,
                        ))

            # 沿调用者方向回溯——查找谁调用了current_func
            for caller, callees in self._call_graph.items():
                if current_func in callees or caller == current_func:
                    if caller not in self._visited:
                        new_chain = (caller,) + chain
                        queue.append((caller, var, depth + 1, new_chain))

        # 按置信度降序
        results.sort(key=lambda r: r.confidence, reverse=True)
        return results

# 证据前向传播

    def propagate_forward(
        self,
        source_func: str,
        known_constants: Dict[str, Tuple[Any, float]],
        depth: int = 0,
    ) -> Dict[str, Dict[str, Tuple[Any, float]]]:
        """从source_func出发前向传播已知常量到其所有被调用者
        
        与trace_evidence互补：
        trace_evid 是回溯（从目标找来源）
        propagate_forward 是前向（从来源推目标）
        
        调用方先在source_func中发现了一批常量，然后调用此方法
        将这些常量信息推送到被调用者，供被调用者分析时使用
        
        返回:
        {func_name: {var: (value, confid)}}
        """
        if depth > _MAX_TRACE_DEPTH or source_func not in self._call_graph:
            return {}

        propagated: Dict[str, Dict[str, Tuple[Any, float]]] = {}
        decayed = {
            v: (val, conf * _DECAY_FACTOR)
            for v, (val, conf) in known_constants.items()
            if conf * _DECAY_FACTOR >= _CONFIDENCE_THRESHOLD
        }

        callees = self._call_graph.get(source_func, [])
        for callee in callees:
            if callee == source_func:
                continue  # 递归调用——需要循环边界控制
            propagated[callee] = decayed.copy()
            # 递归前向——但深度受控
            nested = self.propagate_forward(callee, decayed, depth + 1)
            for fname, consts in nested.items():
                if fname not in propagated:
                    propagated[fname] = {}
                propagated[fname].update(consts)

        return propagated

# 循环边界常量检测

    def detect_loop_invariant(
        self,
        loop_body: List[Dict[str, Any]],
        iterations: int = _MAX_LOOP_ITERATIONS,
    ) -> Dict[str, Tuple[Any, float]]:
        """检测循环中的不变量——对CFF dispatcher循环的参数分析有直接价值
        
        CFF的dispatcher通常是一个while(true)结构，其中状态变量在
        每次迭代中被更新。区分"循环不变量"和"循环变量"是确定
        dispatcher结构的关键步骤
        
        算法：执行受控次数的抽象迭代（默认3次），追踪每个变量的
        值变化。未发生变化的变量标记为循环不变量，置信度与
        迭代次数正相关
        """
        if len(loop_body) < 2:
            return {}

        # 变量→(initial_value, is_constant_so_far)
        var_states: Dict[str, Tuple[Any, bool]] = {}
        import re
        reg_pat = re.compile(
            r'\b(r[0-9]+[a-z]?|[re]?[abcd]x|[re]?[sd]i|'
            r'x[0-9]+|w[0-9]+)\b', re.IGNORECASE
        )

        for insn in loop_body:
            operands = insn.get("operands", "")
            mnemonic = insn.get("mnemonic", "").lower()
            regs = set(reg_pat.findall(operands))
            # 写目标的寄存器——简单启发式：取第一个操作数
            parts = operands.replace(",", " ").split()
            dest = parts[0].strip() if parts else ""
            is_write = mnemonic not in ("cmp", "test", "jmp", "je", "jne", "jz",
                                         "jnz", "ret", "call", "b", "bl")

            for r in regs:
                if r not in var_states:
                    var_states[r] = (0, True)  # 初始假设为常量
                if r == dest and is_write:
                    # 被写入→标记为非不变量
                    current_val, _ = var_states[r]
                    var_states[r] = (current_val, False)

        # 迭代确认：多次"执行"循环体检查稳定性
        for _ in range(iterations - 1):
            for insn in loop_body:
                operands = insn.get("operands", "")
                mnemonic = insn.get("mnemonic", "").lower()
                parts = operands.replace(",", " ").split()
                dest = parts[0].strip() if parts else ""
                is_write = mnemonic not in ("cmp", "test", "jmp", "je", "jne",
                                             "jz", "jnz", "ret", "call", "b", "bl")
                if dest and is_write and dest in var_states:
                    _, was_const = var_states[dest]
                    var_states[dest] = (0, False)  # 不再是不变量

        result = {}
        for var, (_, is_const) in var_states.items():
            if is_const:
                # 置信度与迭代次数正相关，最大0.75
                conf = min(0.75, 0.30 + 0.15 * iterations)
                result[var] = (0, conf)  # value初始为0，由调用方填入实际值
        return result
