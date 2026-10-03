"""SI-CTA: 跨类型别名追踪.

与原 SizeIdentity 的本质区别:
  原 SizeIdentity 在 call 指令处清空 volatile reg, 跨函数链 ID 丢失.
  SI-CTA 通过函数摘要保留跨函数链 ID, 使跨函数的 alloc-write
  同根同源判定不因 call 边界而中断.
"""
import re
from typing import Dict, List, Optional, Set, Tuple


class CrossTypeAliasTracker:
    """跨类型别名追踪器, 通过函数摘要保留跨函数链 ID."""

    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'aligned_alloc'}
    _VOLATILE_REGS = {
        'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11',
        'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5',
    }

    def __init__(self):
        self._next_chain = 1
        self._alloc_chains: Dict[str, int] = {}
        self._sink_chains: Dict[str, int] = {}
        self._var_chain: Dict[str, int] = {}
        # 函数摘要: {func_name: {param_idx: chain_propagation_rule}}
        self._func_summaries: Dict[str, dict] = {}

    def new_chain(self) -> int:
        cid = self._next_chain
        self._next_chain += 1
        return cid

    def bind_alloc(self, site_id: str, size_expr: str,
                   chain_id: int = None) -> int:
        """绑定分配点到链."""
        if chain_id is None:
            chain_id = self.new_chain()
        self._alloc_chains[site_id] = chain_id
        self._var_chain[site_id] = chain_id
        return chain_id

    def bind_sink(self, access_id: str, size_expr: str,
                 chain_id: int = None) -> int:
        """绑定写入点到链."""
        if chain_id is None:
            chain_id = self.new_chain()
        self._sink_chains[access_id] = chain_id
        self._var_chain[access_id] = chain_id
        return chain_id

    def add_summary(self, func_name: str, param_chain_map: dict):
        """注册函数摘要: 参数索引 → 链 ID 传播规则."""
        self._func_summaries[func_name] = param_chain_map

    def on_call(self, func_name: str, args: list,
                summaries: dict = None) -> Dict[str, int]:
        """call 时通过函数摘要保留跨函数链 ID.

        返回: {reg_name: chain_id} 寄存器到链 ID 的映射.
        """
        result = {}

        # 合并传入的摘要
        all_summaries = dict(self._func_summaries)
        if summaries:
            all_summaries.update(summaries)

        summary = all_summaries.get(func_name)
        if summary:
            # 有函数摘要: 按摘要传播链 ID
            for param_idx, rule in summary.items():
                if isinstance(param_idx, str):
                    param_idx = int(param_idx)
                if param_idx < len(args):
                    arg = args[param_idx].strip()
                    arg_chain = self._var_chain.get(arg)
                    if arg_chain and rule != 'new':
                        # 传播到返回值寄存器 rax
                        result['rax'] = arg_chain
                        # 也传播到对应的参数寄存器
                        param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
                        if param_idx < len(param_regs):
                            result[param_regs[param_idx]] = arg_chain
        else:
            # 无摘要: rax 分配新链 ID (原 SizeIdentity 行为)
            result['rax'] = self.new_chain()

        # 清空其他 volatile 寄存器 (除了已传播的)
        for reg in self._VOLATILE_REGS:
            if reg not in result:
                result[reg] = 0  # 0 表示链 ID 丢失

        return result

    def check_same_chain(self, alloc_id: str, sink_id: str) -> Tuple[bool, int]:
        """返回 (is_same, chain_id)."""
        alloc_chain = self._alloc_chains.get(alloc_id, 0)
        sink_chain = self._sink_chains.get(sink_id, 0)
        if alloc_chain == 0 or sink_chain == 0:
            return (False, 0)
        if alloc_chain == sink_chain:
            return (True, alloc_chain)
        return (False, 0)

    def _propagate_alias(self, dst: str, src: str):
        """别名传播: dst 继承 src 的链 ID."""
        src_chain = self._var_chain.get(src)
        if src_chain:
            self._var_chain[dst] = src_chain

    def analyze_pseudocode(self, pseudocode: str) -> list:
        """从伪代码分析跨类型别名."""
        findings = []
        if not pseudocode:
            return findings

        for lineno, raw in enumerate(pseudocode.split('\n'), 1):
            line = raw.strip()
            if not line or line.startswith('//'):
                continue

            # 分配: p = malloc(n) / char *p = (char *)malloc(n)
            # 兼容 C 风格类型声明与强转前缀, 否则 bind_alloc 不执行导致
            # 后续 memcpy 判定拿到 alloc_chain=0 而误产 cross_chain_alert
            m = re.match(
                r'(?:\w+\s*\*+\s*)?(\w+)\s*=\s*'
                r'(?:\(\s*[\w\s\*]+\s*\)\s*)?'
                r'(malloc|calloc|realloc|aligned_alloc)\s*\(([^)]*)\)',
                line, re.IGNORECASE)
            if m:
                var, func, args = m.groups()
                chain_id = self.bind_alloc(var, args.split(',')[0].strip())
                continue

            # 别名: q = p / q = p + offset / q = &p[i]
            m2 = re.match(r'(\w+)\s*=\s*(\w+)\s*(?:[+\-\[\].&].*)?$', line)
            if m2:
                dst = m2.group(1)
                src = m2.group(2)
                if src in self._var_chain:
                    self._propagate_alias(dst, src)
                continue

            # 函数调用
            m3 = re.match(r'(\w+)\s*=\s*(\w+)\s*\(([^)]*)\)', line)
            if m3:
                dst, func, args_str = m3.groups()
                args = [a.strip() for a in args_str.split(',') if a.strip()]
                reg_map = self.on_call(func, args)
                rax_chain = reg_map.get('rax', 0)
                if rax_chain:
                    self._var_chain[dst] = rax_chain
                continue

            # 写入: memcpy(p, src, n)
            m4 = re.match(r'(memcpy|strcpy|memmove|strncpy|memset)\s*\((\w+),\s*(\w+)(?:,\s*(\w+))?',
                           line, re.IGNORECASE)
            if m4:
                func, dst, src, size = m4.groups()
                dst_chain = self._var_chain.get(dst, 0)
                # 检查同链
                alloc_chain = self._alloc_chains.get(dst, 0)
                if alloc_chain and dst_chain == alloc_chain:
                    findings.append({
                        'type': 'same_chain_safe',
                        'line': lineno,
                        'var': dst,
                        'chain_id': alloc_chain,
                        'reason': 'alloc 和 write 同链, 判安全',
                    })
                elif not alloc_chain and not dst_chain:
                    # 分配链与写入链均未知, 证据不足不发告警
                    pass
                else:
                    findings.append({
                        'type': 'cross_chain_alert',
                        'line': lineno,
                        'var': dst,
                        'alloc_chain': alloc_chain,
                        'write_chain': dst_chain,
                        'reason': 'alloc 和 write 不同链, 需进一步检查',
                    })

        return findings

    @property
    def alloc_chains(self) -> Dict[str, int]:
        return dict(self._alloc_chains)

    @property
    def sink_chains(self) -> Dict[str, int]:
        return dict(self._sink_chains)
