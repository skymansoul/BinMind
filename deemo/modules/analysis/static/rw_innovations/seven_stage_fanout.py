"""SevenStageFanout - 七阶段扇出审计 (stage 61).

以 alloc 变量为根, 沿赋值链 (var=alloc -> child_var) 构建 def-use 扇出树,
每层记录写点. 七阶段逐层审计: 从根到叶逐层计算守卫覆盖率 (受守卫写点/总写点),
所有层覆盖率 >= threshold 才判 safe; 任一层 < threshold 则 unsafe.
同时记录 fanout_depth (树深) 和 max_fanout (最大扇出宽度) 作为审计指标.
与 堆溢出误报抑制-APC 级联不同: 树形扇出聚合而非扁平聚合.

设计决策:
  - 分配变量为根, 沿赋值链扩展子节点构建扇出树
  - 每层独立计算守卫覆盖率, 逐层判定
  - _guarded 不仅检查行内 if/while/guard, 还向上回溯缩进范围内的守卫
  - 最多审计七层深度 (七阶段), 不足七层则审计到叶
"""

import re
from typing import List, Optional, Tuple


class _FanoutNode:
    """扇出树节点: var_name, writes(写点行号列表), children(子节点列表)."""

    def __init__(self, var_name: str):
        self.var_name = var_name
        self.writes: List[int] = []       # 写点所在行号(0基)
        self.children: List[_FanoutNode] = []
        self.guarded_count = 0
        self.total_count = 0


def _find_allocs(pseudocode: str) -> List[str]:
    """识别分配变量名."""
    pat = re.compile(
        r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(")
    return [m.group(1) for m in pat.finditer(pseudocode)]


def _indent(line: str) -> int:
    """计算行首缩进 (空格数, tab 按 4 计)."""
    count = 0
    for ch in line:
        if ch == ' ':
            count += 1
        elif ch == '\t':
            count += 4
        else:
            break
    return count


def _guarded(lines: List[str], idx: int) -> bool:
    """判断写点是否受守卫.
    不仅检查行内 if/while/guard, 还向上回溯检查当前行是否在
    缩进更浅的 if/while 块范围内 (缩进守卫检测).
    """
    line = lines[idx]
    # 行内守卫
    if "if" in line or "while" in line or "guard" in line:
        return True
    cur_indent = _indent(line)
    # 向上回溯: 找缩进更浅且含守卫关键词的行
    for j in range(idx - 1, -1, -1):
        prev = lines[j]
        if not prev.strip():
            continue
        prev_indent = _indent(prev)
        # 当前行缩进比前序行深, 且前序行含守卫关键词 -> 被包裹
        if cur_indent > prev_indent:
            if "if" in prev or "while" in prev or "guard" in prev:
                return True
        # 遇到缩进更浅或等深的非空行, 停止回溯
        if prev_indent <= cur_indent:
            break
    return False


# 写地址模式: 匹配 [addr] = val 或 mov [addr], val 两种伪代码风格
_WRITE_PAT = re.compile(r"\[([^\]]+)\]\s*[,=]")

# C 风格调式写: memcpy/memmove/memset/strcpy/strncpy(dst, ...) 第一参数为目标缓冲区
_CALL_WRITE_PAT = re.compile(
    r"\b(memcpy|memmove|memset|strcpy|strncpy)\s*\(\s*(\w+)\s*,")

# 完整分配模式: 捕获变量名/函数名/参数列表, 用于提取分配容量
_ALLOC_FULL_PAT = re.compile(
    r"\b(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(([^)]*)\)")

# 赋值链模式: child_var = rhs (排除 ==, <=, >=, != 等比较运算符)
_ASSIGN_PAT = re.compile(r"\b(\w+)\s*=\s*(?!=)(.+)")


def _try_int(s: str) -> Optional[int]:
    """尝试解析整数字面量, 失败返回 None."""
    s = s.strip()
    try:
        return int(s)
    except ValueError:
        return None


def _extract_alloc_size(pseudocode: str, var: str) -> Optional[str]:
    """提取分配变量的容量表达式."""
    for m in _ALLOC_FULL_PAT.finditer(pseudocode):
        if m.group(1) != var:
            continue
        func = m.group(2)
        parts = [a.strip() for a in m.group(3).split(",")]
        if func == "malloc":
            return parts[0] if parts else None
        if func == "calloc" and len(parts) == 2:
            return f"{parts[0]} * {parts[1]}"
        if func == "realloc" and len(parts) == 2:
            return parts[1]
        return m.group(3).strip()
    return None


def _extract_call_write_size(line: str, func_name: str) -> Optional[str]:
    """从调式写中提取写长参数."""
    m = re.search(re.escape(func_name) + r"\s*\(([^)]*)\)", line)
    if not m:
        return None
    args = [a.strip() for a in m.group(1).split(",")]
    if func_name in ("memcpy", "memmove", "memset", "strncpy") and len(args) >= 3:
        return args[2]
    # strcpy 无长度参数, 无法确定写长
    return None


def _find_loop_bound(
    lines: List[str], line_idx: int, loop_var: str
) -> Optional[str]:
    """向上查找循环变量的上界. for(var=0;var<N;...) → 返回 N."""
    pat = re.compile(
        r"\bfor\s*\(\s*" + re.escape(loop_var) +
        r"\s*=\s*\d+\s*;\s*" + re.escape(loop_var) + r"\s*<\s*(\w+)")
    for j in range(line_idx, -1, -1):
        m = pat.search(lines[j])
        if m:
            return m.group(1)
    return None


def _check_call_write_oob(
    alloc_expr: str, write_size: str
) -> Optional[bool]:
    """检查调式写是否越界. True=越界, False=界内, None=无法判定."""
    if not write_size or not write_size.strip():
        return None
    alloc_num = _try_int(alloc_expr)
    write_num = _try_int(write_size)
    # 两者均为常量: 直接比较
    if alloc_num is not None and write_num is not None:
        return write_num > alloc_num
    # 分配常量, 写长变量: 无法确定
    if alloc_num is not None:
        return None
    # 分配变量, 写长常量: 常量可能超过变量
    if write_num is not None:
        return True
    # 两者均为变量: 同一表达式则界内
    if alloc_expr.strip() == write_size.strip():
        return False
    # 分配为 "X * K", 写长为 "X": 写长小于分配
    am = re.match(r"(\w+)\s*\*\s*(\d+)", alloc_expr)
    if am and am.group(1).strip() == write_size.strip():
        return False
    return None


def _check_subscript_write_oob(
    alloc_expr: str, index_expr: str,
    lines: List[str], line_idx: int
) -> Optional[bool]:
    """检查下标写是否越界. True=越界, False=界内, None=无法判定."""
    alloc_num = _try_int(alloc_expr)
    # 下标为常量
    idx_num = _try_int(index_expr)
    if idx_num is not None:
        if alloc_num is not None:
            return idx_num >= alloc_num
        return None
    # 下标为 "var + const", 分配为 "var": 偏移必然越界
    im = re.match(r"(\w+)\s*\+\s*(\d+)", index_expr)
    if im:
        if alloc_expr.strip() == im.group(1):
            return True
        return None
    # 下标为 "var * K" (K>1): 步长写, 检查守卫上界与分配关系
    im2 = re.match(r"(\w+)\s*\*\s*(\d+)", index_expr)
    if im2:
        loop_var = im2.group(1)
        stride = int(im2.group(2))
        if stride > 1:
            guard_bound = _find_loop_bound(lines, line_idx, loop_var)
            if guard_bound and alloc_expr.strip() == guard_bound:
                return True
        return None
    # 下标为单变量: 查找循环守卫上界
    if re.match(r"^\w+$", index_expr.strip()):
        loop_var = index_expr.strip()
        guard_bound = _find_loop_bound(lines, line_idx, loop_var)
        if guard_bound:
            if alloc_expr.strip() == guard_bound:
                return False
            am = re.match(r"(\w+)\s*\*\s*(\d+)", alloc_expr)
            if am and am.group(1) == guard_bound:
                return False
        return None
    return None


def _build_fanout_tree(
    pseudocode: str, root_var: str
) -> _FanoutNode:
    """构建以 root_var 为根的 def-use 扇出树.
    沿赋值链 (child_var = expr containing parent_var) 逐层扩展子节点,
    每个节点记录引用其变量的写点行号.
    """
    lines = pseudocode.splitlines()
    root = _FanoutNode(root_var)
    visited = {root_var}
    frontier = [root]
    while frontier:
        node = frontier.pop(0)
        for i, line in enumerate(lines):
            # 汇编风格: 当前节点变量出现在写地址中 -> 记录写点
            if _WRITE_PAT.search(line) and re.search(
                r"\b" + re.escape(node.var_name) + r"\b", line
            ):
                node.writes.append(i)
            # C 风格: memcpy/memmove/memset/strcpy 等, 第一参数为目标缓冲区
            cm = _CALL_WRITE_PAT.search(line)
            if cm and cm.group(2) == node.var_name:
                node.writes.append(i)
            # 赋值链: child_var = expr 含 node.var_name -> 创建子节点
            m = _ASSIGN_PAT.search(line)
            if m:
                child_var = m.group(1)
                rhs = m.group(2)
                if child_var == node.var_name or child_var in visited:
                    continue
                if re.search(
                    r"\b" + re.escape(node.var_name) + r"\b", rhs
                ):
                    child = _FanoutNode(child_var)
                    node.children.append(child)
                    visited.add(child_var)
                    frontier.append(child)
    return root


def _check_write_oob(
    line: str, alloc_expr: str,
    lines: List[str], line_idx: int, var_name: str
) -> Optional[bool]:
    """判定单行写是否越界. True=越界, False=界内, None=无法判定.
    优先检查调式写 (memcpy 等), 再检查下标写.
    """
    # 调式写: memcpy/memmove/memset/strncpy(dst, src, n)
    cm = _CALL_WRITE_PAT.search(line)
    if cm and cm.group(2) == var_name:
        wsize = _extract_call_write_size(line, cm.group(1))
        return _check_call_write_oob(alloc_expr, wsize)
    # 下标写: buf[expr] = val 或 buf[expr], val
    wm = _WRITE_PAT.search(line)
    if wm and re.search(r"\b" + re.escape(var_name) + r"\b", line):
        idx_expr = wm.group(1).strip()
        return _check_subscript_write_oob(alloc_expr, idx_expr, lines, line_idx)
    return None


def _audit_layers(
    root: _FanoutNode, lines: List[str], threshold: float,
    alloc_size: Optional[str] = None
) -> Tuple[List[float], int, int]:
    """逐层审计扇出树 (最多七阶段).
    返回 (各层覆盖率列表, 审计深度, 最大扇出宽度).
    每层覆盖率 = 该层所有节点安全写点数 / 该层总写点数.
    安全写点 = 受守卫 或 经容量判定确认界内.
    """
    layer_coverages: List[float] = []
    max_fanout = 0
    current_layer = [root]
    depth = 0
    while current_layer and depth < 7:
        depth += 1
        next_layer: List[_FanoutNode] = []
        guarded_total = 0
        write_total = 0
        if len(current_layer) > max_fanout:
            max_fanout = len(current_layer)
        for node in current_layer:
            node.total_count = len(node.writes)
            node.guarded_count = 0
            for w in node.writes:
                line = lines[w]
                safe_write = _guarded(lines, w)
                # 若有分配容量, 尝试容量判定
                if not safe_write and alloc_size:
                    oob = _check_write_oob(
                        line, alloc_size, lines, w, node.var_name)
                    if oob is False:
                        # 确认界内写, 视为安全
                        safe_write = True
                if safe_write:
                    node.guarded_count += 1
            guarded_total += node.guarded_count
            write_total += node.total_count
            next_layer.extend(node.children)
        # 无写点的层视为完全覆盖
        coverage = guarded_total / write_total if write_total > 0 else 1.0
        layer_coverages.append(coverage)
        current_layer = next_layer
    return layer_coverages, depth, max_fanout


def _iter_nodes(root: _FanoutNode):
    """广度优先遍历所有节点 (用于统计总写点数)."""
    queue = [root]
    while queue:
        node = queue.pop(0)
        yield node
        queue.extend(node.children)


def run_seven_stage_fanout(
    pseudocode: str,
    func_name: str,
    existing_findings: Optional[List[dict]] = None,
    threshold: float = 0.9,
) -> List[dict]:
    """七阶段扇出审计. 返回 findings.
    构建 def-use 扇出树, 逐层审计守卫覆盖率,
    所有层覆盖率 >= threshold -> safe, 任一层 < threshold -> unsafe.
    """
    findings: List[dict] = []
    lines = pseudocode.splitlines()
    vars_ = _find_allocs(pseudocode)
    for var in vars_:
        root = _build_fanout_tree(pseudocode, var)
        alloc_size = _extract_alloc_size(pseudocode, var)
        coverages, fanout_depth, max_fanout = _audit_layers(
            root, lines, threshold, alloc_size
        )
        # 无任何写点则跳过
        total_writes = sum(n.total_count for n in _iter_nodes(root))
        if total_writes == 0:
            continue
        # 最终判定: 所有层覆盖率均 >= threshold -> safe
        all_safe = all(c >= threshold for c in coverages)
        verdict = "safe" if all_safe else "unsafe"
        min_cov = min(coverages) if coverages else 0.0
        findings.append({
            "type": "heap_overflow",
            "function": func_name or "unknown",
            "severity": "medium",
            "cwe": "CWE-122",
            "confidence": round(min(1.0, min_cov), 2),
            "description": (
                f"alloc_var={var} fanout_depth={fanout_depth} "
                f"max_fanout={max_fanout} "
                f"layer_coverages={[round(c, 2) for c in coverages]} "
                f"min_coverage={min_cov:.2f}"
            ),
            "verdict": verdict,
            "source": "seven_stage_fanout",
        })
    return findings


if __name__ == "__main__":
    demo = """\
p = malloc(64);
if (n <= 64) { mov [p+n], 0; }
  q = p + 8;
  mov [q], 0;
mov [p+8], 0;
"""
    out = run_seven_stage_fanout(demo, "demo")
    for item in out:
        print(item["description"], item["verdict"])
