# stub_capability_graph.py — 能力图分析
# 将依赖图中的桩模块按功能语义聚类为"能力簇"，
# 评估每个簇的实现完备度，指导"先实现哪个能力"的决策。
#
# 方法:
#   1. 标签推断: 从模块名/函数名/文档中提取能力标签
#      (fuzzing, exploit, network, crypto, binary, decompile, analysis, ...)
#   2. 标签传播: 沿依赖图的边传播标签 — 若 A 依赖 B 且 A 标签为 X，
#      则 B 也获得 X 标签（B 是 X 能力的组成部分）
#   3. 聚类: 共享标签的连通子图形成能力簇
#   4. 评分: 簇就绪度 = 已实现成员数 / 总成员数
#      簇重要性 = Σ 成员调用量 × 成员依赖深度
#      优先实现 = 重要性 × (1 - 就绪度)
import os as _os
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field


# 能力标签体系
_CAPABILITY_LEXICON = {
    'fuzzing': ['fuzz', 'mutate', 'generate_input', 'coverage', 'afl',
                'libfuzzer', 'format_fuzzer'],
    'exploit': ['exploit', 'rop', 'gadget', 'shellcode', 'payload',
               'heap_exploit', 'uaf', 'stack_overflow', 'concolic'],
    'network': ['network', 'traffic', 'packet', 'protocol', 'dpi',
               'ids_rule', 'snort', 'suricata', 'decrypt'],
    'crypto': ['crypto', 'encrypt', 'decrypt', 'hash', 'sign',
              'certificate', 'key_material', 'signing'],
    'binary': ['binary', 'elf', 'pe', 'mach_o', 'loader', 'format',
              'lifecycle', 'unvirtualize', 'decompile'],
    'malware': ['malware', 'cluster', 'yara', 'unobfuscate', 'string',
               'obfuscate', 'packer', 'anti_analysis'],
    'kernel': ['kernel', 'syscall', 'vtable', 'driver', 'taint',
              'memory_object', 'kallsyms'],
    'firmware': ['firmware', 'iot', 'embedded', 'bootloader', 'fs_type'],
    'ai_ml': ['llm', 'gpu_kernel', 'jit', 'model', 'infer', 'neural',
             'embedding', 'ai_function'],
    'analysis': ['analyze', 'detect', 'scan', 'audit', 'diagnostics',
                'info_leak', 'attack_surface', 'attack_mapper'],
    'patching': ['patch', 'repair', 'auto_patch', 'diff', 'circular_ref'],
    'ci_cd': ['ci_integration', 'collaboration', 'trend_tracker',
             'multi_stage', 'distributed'],
}


@_dc
class CapabilityCluster:
    """一个能力簇 — 协同实现特定安全分析能力的桩模块集合。"""
    name: str                          # 主标签
    tags: list = _field(default_factory=list)
    modules: list = _field(default_factory=list)
    total_modules: int = 0
    implemented_modules: int = 0
    readiness: float = 0.0             # 就绪度 [0,1]
    importance: float = 0.0            # 重要性 [0,∞)
    priority: float = 0.0              # 优先实现分 = importance × (1-readiness)
    missing_modules: list = _field(default_factory=list)


class CapabilityAnalyzer:
    """能力图分析器。

    输出按优先级降序排列的能力簇列表，
    直接回答"实现哪组模块能最快解锁新能力"。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir

    def analyze(self) -> list[CapabilityCluster]:
        """执行完整能力图分析。"""
        # 1. 推断每个模块的能力标签
        module_tags = self._infer_tags()
        if not module_tags:
            return []

        # 2. 构建依赖图 + 标签传播
        tag_graph = self._build_tag_graph(module_tags)

        # 3. 按主标签聚类
        clusters = self._form_clusters(module_tags, tag_graph)

        # 4. 计算就绪度/重要性/优先级
        self._score_clusters(clusters)

        clusters.sort(key=lambda c: -c.priority)
        return clusters

    def _infer_tags(self) -> dict[str, set[str]]:
        """从模块名+函数名+文档推断每个模块的能力标签集。"""
        try:
            from modules.stubs.stub_contract import StubContractor
            ctor = StubContractor(stubs_dir=self.stubs_dir)
            contracts = ctor.scan_all()
        except ImportError:
            return {}

        module_tags = {}
        for name, contract in contracts.items():
            if name.startswith('stub_'):
                continue
            tags = set()
            # 模块名匹配
            name_lower = name.lower()
            for tag, keywords in _CAPABILITY_LEXICON.items():
                if any(kw in name_lower for kw in keywords):
                    tags.add(tag)
            # 函数名 + 文档匹配
            all_text = name_lower
            for fc in contract.functions:
                all_text += ' ' + fc.name.lower()
                if fc.doc_summary:
                    all_text += ' ' + fc.doc_summary.lower()
            for tag, keywords in _CAPABILITY_LEXICON.items():
                if any(kw in all_text for kw in keywords):
                    tags.add(tag)
            if tags:
                module_tags[name] = tags
        return module_tags

    def _build_tag_graph(self,
                         module_tags: dict[str, set[str]]) -> dict[str, set[str]]:
        """构建标签图并沿依赖边传播标签。

        传播规则: 若 A 依赖 B 且 A 有标签 X，则 B 也获得标签 X。
        这反映了一个事实: B 是 A 所代表能力的依赖项，
        因此 B 的实现也贡献于该能力。
        """
        # 初始化传播图（拷贝）
        propagated = {m: set(t) for m, t in module_tags.items()}

        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
        except ImportError:
            return propagated

        # 反向传播: 沿 imports_from 边（A→B 表示 A 依赖 B）
        changed = True
        while changed:
            changed = False
            for name, node in g.nodes.items():
                if name not in module_tags:
                    continue
                for dep in node.imports_from:
                    if dep not in propagated:
                        propagated[dep] = set()
                    before = len(propagated[dep])
                    propagated[dep] |= propagated.get(name, set())
                    if len(propagated[dep]) > before:
                        changed = True

        return propagated

    @staticmethod
    def _form_clusters(module_tags: dict[str, set[str]],
                       tag_graph: dict[str, set[str]]) -> list[CapabilityCluster]:
        """按主标签（出现频率最高的标签）聚类模块。

        一个模块可属于多个簇（若其有多标签）。
        """
        # 确定每个模块的主标签
        tag_members = _dd(list)
        for mod, tags in tag_graph.items():
            primary = CapabilityAnalyzer._primary_tag(tags, module_tags.get(mod, set()))
            if primary:
                tag_members[primary].append(mod)

        clusters = []
        for tag, members in sorted(tag_members.items()):
            clusters.append(CapabilityCluster(
                name=tag,
                tags=[tag],
                modules=sorted(members),
                total_modules=len(members),
            ))

        return clusters

    @staticmethod
    def _primary_tag(propagated: set[str],
                     own: set[str]) -> str | None:
        """选择主标签: 优先自身原有标签，其次传播标签中第一个。"""
        if own:
            return sorted(own)[0]
        if propagated:
            return sorted(propagated)[0]
        return None

    def _score_clusters(self, clusters: list[CapabilityCluster]) -> None:
        """计算每个簇的就绪度、重要性、优先级。"""
        try:
            from modules.stubs.stub_contract import StubContractor
            ctor = StubContractor(stubs_dir=self.stubs_dir)
        except ImportError:
            return

        for c in clusters:
            impl_count = 0
            total_importance = 0.0

            for mod in c.modules:
                contract = ctor.get(mod)
                if contract and contract.status in ('implemented', 'mixed'):
                    impl_count += 1

                # 重要性 = 调用量信号 + 依赖深度信号
                imp = self._module_importance(mod)
                total_importance += imp

                if contract and contract.status not in ('implemented', 'mixed'):
                    c.missing_modules.append(mod)

            c.implemented_modules = impl_count
            c.readiness = round(impl_count / max(c.total_modules, 1), 3)
            c.importance = round(total_importance, 3)
            c.priority = round(c.importance * (1.0 - c.readiness), 3)
            c.missing_modules.sort()

    def _module_importance(self, module_name: str) -> float:
        """单个模块的重要性: 依赖深度 + 调用量归一化。"""
        try:
            from modules.stubs.stub_dependency_graph import ModuleDependencyGraph
            g = ModuleDependencyGraph(stubs_dir=self.stubs_dir)
            g.build()
            node = g.nodes.get(module_name)
            depth = node.topo_depth if node else 0
            closure = len(node.depended_by) if node else 0
        except ImportError:
            depth, closure = 0, 0

        call_vol = 0
        try:
            from modules.stubs.stub_health_monitor import StubHealthMonitor
            mon = StubHealthMonitor()
            rec = getattr(mon, '_records', {}).get(module_name)
            if rec:
                call_vol = rec.call_count
        except ImportError:
            pass

        return (depth * 0.3 + min(closure, 10) * 0.5 + min(call_vol, 100) * 0.2) / 10.0

    def capability_report(self,
                          clusters: list[CapabilityCluster] = None) -> str:
        """生成 Markdown 能力图报告。"""
        if clusters is None:
            clusters = self.analyze()

        lines = ['# 能力图分析报告', '']
        lines.append('| 能力簇 | 就绪度 | 重要性 | 优先级 | 缺失模块 |')
        lines.append('|--------|-------:|-------:|-------:|----------|')
        for c in clusters:
            lines.append(
                f'| {c.name} | {c.readiness:.0%} '
                f'({c.implemented_modules}/{c.total_modules}) | '
                f'{c.importance:.2f} | {c.priority:.3f} | '
                f'{len(c.missing_modules)} |')

            # 对高优先级簇列出缺失模块
            if c.priority > 0.05 and c.missing_modules:
                missing_preview = ', '.join(c.missing_modules[:5])
                if len(c.missing_modules) > 5:
                    missing_preview += f' +{len(c.missing_modules)-5} more'
                lines.append(f'  - 缺失: {missing_preview}')

        return '\n'.join(lines)


__all__ = ['CapabilityCluster', 'CapabilityAnalyzer']
