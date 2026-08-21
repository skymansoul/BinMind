# coding: utf-8
#
"""
GASRI (Guard-Aware Size-Region Inference) — 堆溢出静态检测误报抑制。

核心思想:
  现有检测以"分配大小 vs 写入大小"的单点比较为主, 对寄存器/派生
  size 返回 0 后保守保留, 且不感知有界守卫与分配器对齐 padding,
  导致高误报。GASRI 将 size 参数的静态近似升级为值域 (Region),
  并通过守卫窗口提取、写入目标关联、分配器可用大小模型三级
  削减误报, 同时仅用"可证明安全"规则, 保障召回率。

模块划分:
  region.py   值域抽象域 (区间 + 来源分类 + 格运算)
  insn.py     objdump 文本解析
  abi.py      SysV/Win64 调用约定与危险函数签名
  defuse.py   反向定值链值域解析
  guards.py   支配守卫窗口提取
  link.py     写入目标→分配点关联
  usable.py   分配器可用大小模型
  verdict.py  级联判定引擎
  pipeline.py 管线编排与报告
  cli.py      命令行入口
"""

from .region import Region
from .pipeline import GASRIPipeline, GASRIReport, PairVerdict
from .verdict import VerdictEngine, VerdictResult

__all__ = [
    "Region", "GASRIPipeline", "GASRIReport", "PairVerdict",
    "VerdictEngine", "VerdictResult",
]
