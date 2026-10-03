# 顶层包路由 — 测试收集基础设施
#
# 各模块测试以顶层 `src.xxx` 或 `tests.xxx` 形式导入本模块的 src/tests
# 子包，且各模块 conftest 将自身目录加入 sys.path。sys.modules 中的顶层
# 包首次导入即被缓存，全树收集时先导入的模块会污染后续模块的解析。
# 本文件提供两层保障：
#   1. 按测试模块逐个清除 src/tests 缓存，使每次导入重新解析；
#   2. 自定义 MetaPathFinder 按导入方文件位置路由 src/tests 到正确的子包，
#      不依赖 sys.path 顺序。

import importlib.abc
import importlib.machinery
import importlib.util
import os
import sys

import pytest

_ROUTED = ('src', 'tests', 'utils')


class _TopLevelRouter(importlib.abc.MetaPathFinder):
    """将顶层 `src`/`tests` 路由到调用方所在模块对应的子包。"""

    def find_spec(self, fullname, path, target=None):
        head = fullname.split('.', 1)[0]
        if head not in _ROUTED:
            return None
        caller = self._caller_file()
        if not caller:
            return None
        target_dir = self._locate_dir(caller, head)
        if not target_dir:
            return None
        init = os.path.join(target_dir, '__init__.py')
        if not os.path.exists(init):
            return None
        loader = importlib.machinery.SourceFileLoader(head, init)
        spec = importlib.util.spec_from_loader(
            head, loader, origin=init, is_package=True)
        spec.submodule_search_locations = [target_dir]
        return spec

    @staticmethod
    def _caller_file():
        f = sys._getframe(3)
        depth = 0
        while f is not None and depth < 12:
            cf = f.f_globals.get('__file__')
            if cf and str(cf).endswith('.py'):
                return os.path.abspath(str(cf))
            f = f.f_back
            depth += 1
        return None

    @staticmethod
    def _locate_dir(caller_file, name):
        parts = caller_file.replace('\\', '/').split('/')
        for i in range(len(parts) - 1):
            if parts[i] != 'modules':
                continue
            # 自 modules/<X>/ 向下查找最近的 name 子包
            base = i + 1
            for j in range(base, len(parts)):
                if parts[j] == name:
                    cand = '/'.join(parts[:j + 1])
                    if os.path.isdir(cand) and os.path.exists(
                            os.path.join(cand, '__init__.py')):
                        return cand
            # modules/<X>/ 下的顶层 name（如 modules/core/tests 或 modules/crypto/src）
            mod_dir = '/'.join(parts[:base + 1])
            cand = os.path.join(mod_dir, name)
            if os.path.isdir(cand) and os.path.exists(
                    os.path.join(cand, '__init__.py')):
                return cand
        return None


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config):
    if not any(isinstance(f, _TopLevelRouter) for f in sys.meta_path):
        sys.meta_path.insert(0, _TopLevelRouter())


@pytest.hookimpl(hookwrapper=True)
def pytest_pycollect_makemodule(module_path, parent):
    for _name in _ROUTED:
        for _k in [k for k in list(sys.modules)
                   if k == _name or k.startswith(_name + '.')]:
            del sys.modules[_k]
    outcome = yield
    return outcome.get_result()
