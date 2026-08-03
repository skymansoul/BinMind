"""
DepLLM-Crypto — 依赖引导的LLM增强密码学误用检测子包。

研究基础:
  - CRYPTBARA (ASE 2025): 依赖上下文引导检测密码学API误用。
  - Beyond Static Pattern Matching? (arXiv:2407.16576): LLM时代重新审视
    模式匹配误用检测, 论证语义验证层可消解静态规则假阳性, 并给出无LLM基线。
  - Automatic Generation of a Cryptography Misuse Taxonomy Using LLMs
    (arXiv:2509.10814): LLM误用分类的低开销要求 → 判定缓存。
  - Evaluating LLMs in Detecting Secrets in Android Apps (arXiv:2510.18601):
    LLM与启发式在密钥/秘密检测中的互补经验。

子包组成:
  dependency_graph — 依赖图构建 + 污点传播路径追踪 (CRYPTBARA依赖上下文)
  symbol_table    — 跨编译单元常量折叠传播符号表
  heuristic       — 无LLM时的启发式置信度降级路径
  llm_validator   — 可选LLM语义验证层 (OpenAI兼容, 标准库实现)
  verdict_cache   — 判定结果LRU缓存
  pipeline        — 主流水线编排 (DepLLMCryptoAnalyzer / DepFinding)

向后兼容:
  from crypto.src.depllm import DepLLMCryptoAnalyzer 即可使用全部能力;
  亦可通过crypto.src懒加载访问 (见src/__init__.py末尾注册)。
"""

from .pipeline import (DepLLMCryptoAnalyzer, DepFinding, build_dependency_context,
                       detect_dep_llm_misuse, filter_findings)
from .dependency_graph import DependencyGraph, TaintPath, trace_dependency_paths
from .symbol_table import ModuleSymbolTable, ConstantSymbol
from .llm_validator import LLMValidator, LLMVerdict
from .verdict_cache import VerdictCache, Verdict

__all__ = [
    'DepLLMCryptoAnalyzer', 'DepFinding', 'build_dependency_context',
    'detect_dep_llm_misuse', 'filter_findings',
    'DependencyGraph', 'TaintPath', 'trace_dependency_paths',
    'ModuleSymbolTable', 'ConstantSymbol',
    'LLMValidator', 'LLMVerdict',
    'VerdictCache', 'Verdict',
]
