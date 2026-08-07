"""
parallel_deep_dev — BinMind 深度创新并行开发包

用法:
  python -m parallel_deep_dev           # 完整执行
  python -m parallel_deep_dev --dry-run # 仅预览 prompt
  python -m parallel_deep_dev --workers 3  # 指定并行数

也可在代码中调用:
  from parallel_deep_dev.run import main
  main(dry_run=False, max_workers=5)
"""

from parallel_deep_dev.config import CONFIG
from parallel_deep_dev.run import main

__all__ = ["CONFIG", "main"]
