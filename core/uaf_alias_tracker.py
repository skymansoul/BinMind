"""
UAF别名追踪器 — 指针别名分析, 用于use-after-free误报削减。
构建保守别名图: 标记共享同一堆对象的变量, 一处释放则标记全部别名,
区分"通过别名正确释放后的使用"(FP→滤除)与"错误释放路径上的使用"(TP→保留)。
别名关系需IR中的显式赋值边建立, 避免过度合并。
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class AliasGroup:
    """指向同一堆对象的一组变量。"""
    canonical: str                    # 代表变量名
    members: Set[str] = field(default_factory=set)
    alloc_site_idx: int = -1          # 分配点在IR中的行索引
    free_sites: List[int] = field(default_factory=list)
    use_sites: List[int] = field(default_factory=list)
    freed_correctly: bool = False     # 是否通过任一成员正确释放

    @property
    def has_uaf(self) -> bool:
        """是否存在真UAF: 所有free之后的use。"""
        if not self.free_sites:
            return False
        last_free = max(self.free_sites)
        return any(u > last_free for u in self.use_sites)

    @property
    def has_double_free(self) -> bool:
        return len(self.free_sites) >= 2

class UafAliasTracker:
    """UAF别名追踪器 — 构建别名图并过滤别名引入的误报。

    两遍算法:
      第一遍: 从IR识别指针赋值(p=q), 构建别名等价类。
      第二遍: 传播free/use事件到所有别名成员, 判定真UAF vs 别名误报。
    """

    # 指针赋值: q = p (p是heap指针, q获取同一对象)
    _PTR_ASSIGN_PAT = re.compile(
        r'(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*(\b[a-zA-Z_]\w{0,31}\b)\s*;?\s*$'
    )
    # malloc/calloc/realloc
    _ALLOC_PAT = re.compile(
        r'(?:(\b[a-zA-Z_]\w{0,31}\b)\s*=\s*)?'
        r'(malloc|calloc|realloc)\s*\(', re.IGNORECASE
    )
    # free(ptr)
    _FREE_PAT = re.compile(
        r'free\s*\(\s*(\b[a-zA-Z_]\w{0,31}\b)\s*\)', re.IGNORECASE
    )
    # 指针解引用/字段访问: ptr->field 或 *ptr 或 ptr[index]
    _USE_PAT = re.compile(
        r'(?:(\b[a-zA-Z_]\w{0,31}\b)\s*->|'
        r'\*\s*(\b[a-zA-Z_]\w{0,31}\b)|'
        r'(\b[a-zA-Z_]\w{0,31}\b)\s*\[)',
    )

    def __init__(self):
        self._groups: Dict[str, AliasGroup] = {}

    def analyze(self, ir_lines: List[str]) -> Dict[str, AliasGroup]:
        """主入口: 分析IR行, 返回别名组。

        返回 {canonical_var: AliasGroup} 映射。
        """
        self._groups.clear()

        # 第一遍: 识别分配和别名关系
        for idx, line in enumerate(ir_lines):
            self._find_alloc(line, idx)
            self._find_alias(line)

        # 第二遍: 传播free/use事件
        for idx, line in enumerate(ir_lines):
            self._find_free(line, idx)
            self._find_use(line, idx)

        # 终态判定
        for group in self._groups.values():
            if group.free_sites:
                group.freed_correctly = True

        return self._groups

    def _find_alloc(self, line: str, idx: int):
        m = self._ALLOC_PAT.search(line)
        if not m:
            return
        var = m.group(1)
        if not var:
            return
        var = var.strip()
        group = AliasGroup(canonical=var, alloc_site_idx=idx)
        group.members.add(var)
        self._groups[var] = group

    def _find_alias(self, line: str):
        """q = p → q 是 p 的别名."""
        m = self._PTR_ASSIGN_PAT.search(line)
        if not m:
            return
        lhs = m.group(1)
        rhs = m.group(2)
        # 查找rhs所属的别名组
        rhs_group = self._find_group_for(rhs)
        if rhs_group is None:
            return
        # 将lhs加入同一组
        rhs_group.members.add(lhs)
        # 同时注册lhs→组的映射
        if lhs not in self._groups:
            self._groups[lhs] = rhs_group

    def _find_free(self, line: str, idx: int):
        m = self._FREE_PAT.search(line)
        if not m:
            return
        var = m.group(1).strip()
        group = self._find_group_for(var)
        if group is not None:
            group.free_sites.append(idx)

    def _find_use(self, line: str, idx: int):
        """检测指针解引用使用。只记录真正的解引用, 忽略赋值和比较。"""
        # 跳过赋值行 (ptr = expr)
        if re.search(r'\b\w+\s*=\s*', line) and '->' not in line and '[' not in line:
            return
        # 跳过比较行 (if ptr == NULL / ptr != NULL)
        if re.search(r'(==|!=)\s*(NULL|nullptr|0)', line):
            return
        # 跳过free行 (已在_find_free处理)
        if 'free' in line.lower():
            return

        for m in self._USE_PAT.finditer(line):
            used_var = m.group(1) or m.group(2) or m.group(3)
            if not used_var:
                continue
            group = self._find_group_for(used_var.strip())
            if group is not None:
                group.use_sites.append(idx)

    def _find_group_for(self, var: str) -> Optional[AliasGroup]:
        """查找变量所属的别名组。先精确匹配, 再搜索所有组成员。"""
        if var in self._groups:
            return self._groups[var]
        for group in self._groups.values():
            if var in group.members:
                return group
        return None

    def get_uaf_findings(self) -> List[dict]:
        """返回过滤后的UAF发现 (排除别名误报)。

        过滤规则:
          - 同一别名组内, 若free发生在最后一次use之前 → 真UAF, 保留
          - 同一别名组内, 若free发生在最后一次use之后 → 安全, 滤除
          - 若通过别名成员free (q=ptr; free(q)) → 安全, 滤除
        """
        findings = []
        for canonical, group in self._groups.items():
            if not group.free_sites:
                continue
            if group.has_uaf:
                # 真UAF: free之后仍有use
                last_free = max(group.free_sites)
                uaf_uses = [u for u in group.use_sites if u > last_free]
                findings.append({
                    'canonical_var': canonical,
                    'aliases': list(group.members),
                    'alloc_line': group.alloc_site_idx,
                    'free_lines': group.free_sites,
                    'uaf_use_lines': uaf_uses,
                    'is_double_free': group.has_double_free,
                    'verdict': 'TP',
                    'confidence': 0.80 if uaf_uses else 0.40,
                })
            elif group.has_double_free:
                findings.append({
                    'canonical_var': canonical,
                    'aliases': list(group.members),
                    'alloc_line': group.alloc_site_idx,
                    'free_lines': group.free_sites,
                    'uaf_use_lines': [],
                    'is_double_free': True,
                    'verdict': 'TP',
                    'confidence': 0.90,
                })

        return findings

    def filter_uaf_candidates(self, raw_findings: List[dict]) -> List[dict]:
        """过滤原始UAF发现列表, 移除别名导致的误报。

        对每个原始发现:
          若变量属于某个别名组且组内free由同一组成员执行
          → 这是别名路径的合法操作, 可能不是真UAF
          → 降低置信度 (不直接删除, 保守处理)
        """
        if not self._groups:
            return raw_findings

        filtered = []
        for f in raw_findings:
            ptr_name = f.get('pointer_name', f.get('ptr_var', ''))
            if not ptr_name:
                filtered.append(f)
                continue

            group = self._find_group_for(ptr_name)
            if group is None:
                filtered.append(f)
                continue

            # 别名组存在: 检查是否是别名路径导致的FP
            if len(group.members) > 1:
                # 多个成员指向同一对象
                free_lines = group.free_sites
                use_lines = [u for u in group.use_sites]

                # 若所有use都在最后一次free之前 → 合法使用
                if free_lines and use_lines:
                    last_free = max(free_lines)
                    post_free_uses = [u for u in use_lines if u > last_free]
                    if not post_free_uses:
                        # 无free后的use → 过滤此FP
                        # 但保守: 降置信度而非删除
                        f['confidence'] = f.get('confidence', 0.5) * 0.4
                        f['alias_filtered'] = True
                        f['alias_note'] = (
                            f'All uses before free (aliases: {group.members})'
                        )
                    else:
                        f['alias_confirmed'] = True
                        f['alias_note'] = (
                            f'Post-free uses: {post_free_uses}'
                        )

            filtered.append(f)
        return filtered
