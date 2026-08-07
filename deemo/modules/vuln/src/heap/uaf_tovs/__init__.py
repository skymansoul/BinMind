"""TOVS — Branch-Sensitive Temporal Order Verification.

UAF 检测的误报抑制引擎. 核心方法论:
  1. 后支配时序验证: use 必须被 free 后支配才构成 UAF 候选,
     分支互斥/提前返回的线性序误配被过滤.
  2. 指针身份重定义验证: free 与 use 之间指针被重新赋值
     (新对象/常量/null) → 合法模式, 过滤.
  3. NULL 检查语义修正: cmp/test 不改变对象身份, NULL 检查
     不构成防护 (防止过度过滤导致的漏报).

与既有 DRIFT (src/uaf/) 的关系: DRIFT 做对象身份追踪与多阶段过滤,
本包聚焦"时序成立性"的形式化验证, 复用 pcfv 的 CFG/值流基础设施,
形成与 PCFV (堆溢出) 同源的路径敏感内存安全验证框架.

创建: 2026-04-25
"""
from .types import (TovsVerdict, TovsRule, Evidence, FreeUsePair,
                    PairVerdict)
from .free_use_pairs import extract_pairs
from .order_verify import OrderVerifier
from .redef_verify import RedefVerifier
from .engine import TovsEngine
from .pipeline import TovsReport, analyze_uaf_tovs

__all__ = [
    "TovsVerdict", "TovsRule", "Evidence", "FreeUsePair", "PairVerdict",
    "extract_pairs", "OrderVerifier", "RedefVerifier", "TovsEngine",
    "TovsReport", "analyze_uaf_tovs",
]
