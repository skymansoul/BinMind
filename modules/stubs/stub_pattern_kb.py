# stub_pattern_kb.py — 自监督实现模式知识库
# 从项目自身成功的桩实现中提取可复用模式，
# 新桩生成时检索最相似的历史模式作为起始模板。
#
# 方法:
#   1. 从 ProvenanceChain + 源码中提取成功实现的模式指纹
#   2. 指纹编码: 函数名 n-gram + 参数类型 + 返回类型 + 复杂度 + 模块名语义标签
#   3. 存储为 (fingerprint_vector, source_template, metrics)
#   4. 新合约到来时: 计算指纹 → 检索 top-k 最相似模式 → 适配为模板
#
# 知识库随每次成功实现自动增长，检索对象是"同项目内相似桩的实现模式"。
import ast as _ast
import hashlib as _hl
import json as _json
import os as _os
import re as _re
from collections import defaultdict as _dd
from dataclasses import dataclass as _dc, field as _field
from typing import Optional as _Opt

from modules.stubs.stub_contract import FuncContract as _FuncContract


@_dc
class PatternEntry:
    """单条可复用实现模式。"""
    pattern_id: str = ''         # 指纹哈希前 12 位
    module_name: str = ''
    func_name: str = ''
    # 指纹组件
    name_ngrams: list = _field(default_factory=list)
    param_types: list = _field(default_factory=list)
    return_type: str = ''
    complexity: str = 'low'
    # 实现模板（完整的函数源码）
    source_template: str = ''
    # 成功指标
    verification_ok: bool = False
    incoherence_rate: float = -1.0
    strategy: str = ''
    # 检索元数据
    usage_count: int = 0         # 被检索复用的次数


class PatternKB:
    """自监督实现模式知识库。

    持久化: stubs/_pattern_kb/patterns.json
    每个成功实现自动注册为新条目。
    检索用余弦相似度（基于指纹向量的二值化哈希）。
    """

    def __init__(self, stubs_dir: str = None):
        if stubs_dir is None:
            stubs_dir = _os.path.dirname(_os.path.abspath(__file__))
        self.stubs_dir = stubs_dir
        self.store_dir = _os.path.join(stubs_dir, '_pattern_kb')
        self._patterns: dict[str, PatternEntry] = {}
        self._ensure_loaded()

    def register(self, module_name: str, func_name: str,
                 source: str, contract: _FuncContract,
                 verification_ok: bool = False,
                 incoherence_rate: float = -1.0,
                 strategy: str = '') -> _Opt[PatternEntry]:
        """注册一条新的实现模式。

        source: 完整的模块源码或函数源码
        自动提取函数体部分作为模板
        """
        body = self._extract_body(source, func_name)
        if body is None or len(body) < 10:
            return None

        entry = PatternEntry(
            module_name=module_name,
            func_name=func_name,
            name_ngrams=self._name_ngrams(func_name),
            param_types=[p.annotation for p in contract.params
                        if p.kind not in ('varargs', 'varkw')],
            return_type=contract.return_ann,
            complexity=contract.complexity,
            source_template=body,
            verification_ok=verification_ok,
            incoherence_rate=incoherence_rate,
            strategy=strategy,
        )
        entry.pattern_id = self._fingerprint(entry)[:12]
        self._patterns[entry.pattern_id] = entry
        self._persist()
        return entry

    def retrieve(self, fc: _FuncContract,
                 k: int = 3) -> list[PatternEntry]:
        """检索与给定函数合约最相似的 k 条历史实现模式。

        相似度 = 名称 n-gram Jaccard × 0.3 + 参数类型一致率 × 0.4
                + 返回类型匹配 × 0.2 + 复杂度匹配 × 0.1
        """
        if not self._patterns:
            return []

        query_ngrams = set(self._name_ngrams(fc.name))
        query_types = [p.annotation for p in fc.params
                      if p.kind not in ('varargs', 'varkw')]
        query_ret = fc.return_ann
        query_cplx = fc.complexity

        scored = []
        for entry in self._patterns.values():
            # n-gram Jaccard
            entry_ngrams = set(entry.name_ngrams)
            jaccard = (len(query_ngrams & entry_ngrams) /
                      max(len(query_ngrams | entry_ngrams), 1))

            # 参数类型一致率
            type_match = self._type_match_rate(query_types, entry.param_types)

            # 返回类型
            ret_match = 1.0 if query_ret == entry.return_type else 0.0
            if not query_ret and not entry.return_type:
                ret_match = 0.5  # 两者都无注解 → 中性

            # 复杂度
            cplx_match = 1.0 if query_cplx == entry.complexity else 0.5

            score = (0.3 * jaccard + 0.4 * type_match +
                    0.2 * ret_match + 0.1 * cplx_match)

            if score > 0.3:
                scored.append((score, entry))

        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:k]]

    def adapt(self, fc: _FuncContract,
              template: PatternEntry) -> str:
        """将检索到的模式适配到新函数。

        适配操作:
          - 替换函数名为新名称
          - 保留原模板的错误处理模式
          - 调整参数引用
        """
        lines = template.source_template.splitlines()
        if not lines:
            return self._fallback_body(fc)

        adapted = []
        for line in lines:
            stripped = line.strip()
            # 跳过原函数的 def 行
            if stripped.startswith('def '):
                continue
            adapted.append(line)

        return '\n'.join(adapted) if adapted else self._fallback_body(fc)

    def size(self) -> int:
        return len(self._patterns)

    @staticmethod
    def _name_ngrams(name: str, n: int = 3) -> list[str]:
        """函数名 → 字符级 n-gram。"""
        s = name.lower()
        return [s[i:i+n] for i in range(max(1, len(s) - n + 1))]

    @staticmethod
    def _type_match_rate(a: list[str], b: list[str]) -> float:
        if not a and not b:
            return 0.5
        if not a or not b:
            return 0.0
        matches = 0
        for i in range(min(len(a), len(b))):
            if PatternKB._simple_base(a[i]) == PatternKB._simple_base(b[i]):
                matches += 1
        return matches / max(len(a), len(b))

    @staticmethod
    def _simple_base(ann: str) -> str:
        a = (ann or '').strip().lower()
        while a.startswith(('optional[', 'union[')):
            inner = a[a.index('[') + 1:]
            a = inner.split(',')[0].strip() if inner else ''
        m = _re.match(r'([a-z_][a-z0-9_]*)', a)
        return m.group(1) if m else ''

    @staticmethod
    def _fingerprint(entry: PatternEntry) -> str:
        payload = '|'.join([
            entry.module_name,
            entry.func_name,
            ','.join(entry.param_types),
            entry.return_type,
            entry.complexity,
        ])
        return _hl.sha256(payload.encode('utf-8')).hexdigest()

    @staticmethod
    def _extract_body(source: str, func_name: str) -> _Opt[str]:
        """从模块源码中提取指定函数的 body。"""
        try:
            tree = _ast.parse(source)
        except SyntaxError:
            return None
        for node in tree.body:
            if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                if node.name == func_name:
                    lines = source.splitlines()
                    if node.body:
                        start = node.body[0].lineno - 1
                        end = (node.end_lineno if hasattr(node, 'end_lineno')
                              else len(lines))
                        return '\n'.join(lines[start:end])
        return None

    @staticmethod
    def _fallback_body(fc: _FuncContract) -> str:
        return (f'    # TODO: pattern adaptation failed for {fc.name}\n'
                f'    raise NotImplementedError("stub {fc.name}")')

    def _ensure_loaded(self) -> None:
        path = _os.path.join(self.store_dir, 'patterns.json')
        if _os.path.isfile(path):
            try:
                with open(path, encoding='utf-8') as f:
                    data = _json.load(f)
                for item in data:
                    entry = PatternEntry(**item)
                    self._patterns[entry.pattern_id] = entry
            except (_json.JSONDecodeError, TypeError, OSError):
                pass

    def _persist(self) -> None:
        _os.makedirs(self.store_dir, exist_ok=True)
        path = _os.path.join(self.store_dir, 'patterns.json')
        data = [_dc_to_dict(e) for e in self._patterns.values()]
        with open(path, 'w', encoding='utf-8') as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)


def _dc_to_dict(e: PatternEntry) -> dict:
    return {
        'pattern_id': e.pattern_id,
        'module_name': e.module_name,
        'func_name': e.func_name,
        'name_ngrams': e.name_ngrams,
        'param_types': e.param_types,
        'return_type': e.return_type,
        'complexity': e.complexity,
        'source_template': e.source_template,
        'verification_ok': e.verification_ok,
        'incoherence_rate': e.incoherence_rate,
        'strategy': e.strategy,
        'usage_count': e.usage_count,
    }


__all__ = ['PatternEntry', 'PatternKB']
