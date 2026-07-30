"""
Hook framework. Allows injecting custom analysis steps at various
pipeline stages. Hooks are Python files in a directory; they get
loaded dynamically and called with stage-specific context.
"""

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
        """Load all .py files in `directory` as hook modules."""
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
        """Call all hooks registered for `stage`, passing `ctx` through them."""
        if stage not in STAGES:
            raise ValueError(f"Unknown stage: {stage}")
        for hook in self._hooks[stage]:
            try:
                ctx = hook(ctx) or ctx
            except Exception:
                logger.warning("Hook %s failed at stage %s", hook.__name__, stage)
        return ctx


# module-level singleton
_manager: HookManager = None


def get_hook_manager() -> HookManager:
    global _manager
    if _manager is None:
        _manager = HookManager()
    return _manager
