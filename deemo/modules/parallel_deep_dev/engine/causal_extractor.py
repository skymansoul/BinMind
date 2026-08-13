"""
创建: 2025-03-28
因果图静态边提取器 — 从 Python AST 提取 IMPORTS/CALLS/MUTATES/INHERITS/RAISES 依赖边。

本模块独立于 CausalGraph 数据结构，便于在不引入因果图依赖的前提下复用边提取逻辑。
提取器采用两遍遍历：第一遍收集 import 映射和类继承关系（建立符号→文件的解析上下文），
第二遍在已知上下文的前提下收集调用、赋值、异常边。
"""


import ast
from parallel_deep_dev.engine.causal_graph import CausalityEdge


def extract_edges(filepath: str) -> list[CausalityEdge]:
    """解析单个 Python 源文件，提取所有依赖边。

    边类型说明：
    - IMPORTS:  import X 或 from M import X → 被导入模块
    - CALLS:    func() 其中 func 来自导入的模块 → 调用目标
    - MUTATES:  obj.attr = val 其中 obj 来自导入 → 状态修改风险
    - INHERITS: class Sub(Base): Base 来自同一文件或导入 → 接口变更风险
    - RAISES:   raise ExcType(...) → 异常传播路径

    解析失败（语法错误、文件不可读）返回空列表——调用方自行处理。
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    edges: list[CausalityEdge] = []
    imports_map: dict[str, str] = {}

    # 第一遍：import 映射 + 类继承
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.asname or alias.name
                imports_map[name] = alias.name
                edges.append(CausalityEdge(
                    source=filepath, target=alias.name,
                    edge_type="IMPORTS", symbol=alias.name,
                    lineno=node.lineno,
                ))
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for alias in node.names:
                name = alias.asname or alias.name
                imports_map[name] = f"{node.module}.{alias.name}"
                edges.append(CausalityEdge(
                    source=filepath, target=node.module,
                    edge_type="IMPORTS", symbol=alias.name,
                    lineno=node.lineno,
                ))
        elif isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name):
                    edges.append(CausalityEdge(
                        source=filepath, target=base.id,
                        edge_type="INHERITS", symbol=node.name,
                        lineno=node.lineno,
                    ))

    # 第二遍：调用 + 赋值 + 异常（需 import 上下文）
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _resolve_call_name(node.func)
            if func_name and func_name in imports_map:
                edges.append(CausalityEdge(
                    source=filepath, target=imports_map[func_name],
                    edge_type="CALLS", symbol=func_name,
                    lineno=node.lineno,
                ))
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for attr_node in ast.walk(target):
                    if isinstance(attr_node, ast.Attribute):
                        base = _resolve_base(attr_node.value)
                        if base and base in imports_map:
                            edges.append(CausalityEdge(
                                source=filepath, target=imports_map[base],
                                edge_type="MUTATES", symbol=base,
                                lineno=node.lineno,
                            ))
        elif isinstance(node, ast.Raise):
            if node.exc is not None and isinstance(node.exc, ast.Call):
                exc_name = _resolve_call_name(node.exc.func)
                if exc_name:
                    edges.append(CausalityEdge(
                        source=filepath, target=exc_name,
                        edge_type="RAISES", symbol=exc_name,
                        lineno=node.lineno,
                    ))

    return edges


def _resolve_call_name(node: ast.expr) -> str:
    """从调用表达式解析函数名。处理 foo() 和 obj.method() 两种形式。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _resolve_base(node)
    return ""


def _resolve_base(node: ast.expr) -> str:
    """从属性链解析基对象名。obj.attr.sub → 'obj'。"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _resolve_base(node.value)
    return ""
