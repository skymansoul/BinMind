"""Hook 框架 — 允许在各管道阶段注入自定义分析步骤, 钩子为目录中的 Python 文件, 动态加载并按阶段上下文调用。"""

import importlib.util
import logging
import os
import sys
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)

STAGES = ('pre_unpack', 'post_unpack', 'pre_decompile', 'post_decompile',
          'pre_analysis', 'post_analysis', 'pre_report', 'post_report')


class HookManager:
    def __init__(self):
        self._hooks: Dict[str, List[Callable]] = {s: [] for s in STAGES}

    def load_dir(self, directory: str):
        """加载目录中全部 .py 文件作为 hook 模块。"""
        if not os.path.isdir(directory):
            return

        for fname in sorted(os.listdir(directory)):
            if not fname.endswith('.py') or fname.startswith('_'):
                continue

            fpath = os.path.join(directory, fname)
            try:
                spec = importlib.util.spec_from_file_location(
                    f'hook_{fname[:-3]}', fpath)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)

                for stage in STAGES:
                    fn = getattr(mod, stage, None)
                    if callable(fn):
                        self._hooks[stage].append(fn)
                        logger.debug("Hook %s registered for %s", fname, stage)
            except Exception:
                logger.warning("Failed to load hook %s", fname, exc_info=True)

    def run(self, stage: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """调用注册在指定阶段的所有 hook, 依次传递 ctx。"""
        if stage not in STAGES:
            raise ValueError(f"Unknown stage: {stage}")
        for hook in self._hooks[stage]:
            try:
                ctx = hook(ctx) or ctx
            except Exception:
                logger.warning("Hook %s failed at stage %s", hook.__name__, stage)
        return ctx


# 模块级单例
_manager: HookManager = None


def get_hook_manager() -> HookManager:
    global _manager
    if _manager is None:
        _manager = HookManager()
    return _manager
