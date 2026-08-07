# coding: utf-8
# 创建: 2026-05-06  补齐 compat 模块自动发现与钩子注册桥接
"""
Compat 模块自动发现与钩子注册 — 扫描 compat/ 目录, 将分析模块包装为标准钩子,
推断读写键签名, 注册到 SchemaModel, 使 SmartPipeline 可使用真实分析模块.

此前 SmartPipeline 仅支持手工注册的玩具钩子. 本模块建立核心调度层与
compat/ 分析层的桥梁: 自动发现 → 签名推断 → 钩子包装 → SchemaModel 注册.
"""

import importlib
import inspect
import os
import pkgutil
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# compat 模块中可被包装为钩子的命名模式
_HOOK_CLASS_PATTERNS = [
    'Analyzer', 'Scanner', 'Extractor', 'Detector', 'Mapper',
    'Generator', 'Recovery', 'Identifier', 'Executor', 'Patcher',
    'Fuzzer', 'Normalizer', 'Clusterer', 'Reconstructor',
]

# 这些类的方法中, 名称匹配以下模式的会被用作钩子入口
_HOOK_METHOD_PATTERNS = [
    'analyze', 'scan', 'extract', 'detect', 'map', 'generate',
    'recover', 'identify', 'execute', 'run', 'process', 'load',
    'patch', 'fuzz', 'normalize', 'cluster', 'reconstruct',
]


def discover_compat_modules() -> List[str]:
    """扫描 modules.core.compat, 返回可导入的模块路径列表."""
    try:
        import modules.core.compat as compat_pkg
    except ImportError:
        return []
    modules = []
    compat_path = os.path.dirname(compat_pkg.__file__) if hasattr(compat_pkg, '__file__') else ''
    if not compat_path:
        return modules
    for _, name, is_pkg in pkgutil.iter_modules([compat_path]):
        if name.startswith('_'):
            continue
        if is_pkg:
            # 子包: 扫描其下的模块
            sub_path = os.path.join(compat_path, name)
            for _, sub_name, _ in pkgutil.iter_modules([sub_path]):
                if not sub_name.startswith('_'):
                    modules.append(f'modules.core.compat.{name}.{sub_name}')
        else:
            modules.append(f'modules.core.compat.{name}')
    return sorted(modules)


def _infer_keys_from_params(fn: Callable) -> Tuple[Set[str], Set[str]]:
    """从函数参数名推断读取键. 返回 (reads, writes)."""
    reads: Set[str] = set()
    try:
        sig = inspect.signature(fn)
    except (ValueError, TypeError):
        return set(), set()
    for name, param in sig.parameters.items():
        if name in ('self', 'cls', 'context', 'ctx', 'binary_path', 'path'):
            continue
        if param.default is not inspect.Parameter.empty:
            continue  # 有默认值 → 可选, 不推断为必需读取
        reads.add(name)
    return reads, set()


def _infer_keys_from_docstring(obj: Any) -> Tuple[Set[str], Set[str]]:
    """从文档字符串中提取可能的读写键. 启发式, 非精确."""
    doc = (obj.__doc__ or '')
    reads, writes = set(), set()
    # 简单模式匹配: "read X from context" / "write Y to context"
    import re
    for m in re.finditer(r'(?:reads?|consumes?|input|需要|读取)\s+[\'"]?(\w+)', doc, re.I):
        reads.add(m.group(1))
    for m in re.finditer(r'(?:writes?|produces?|output|产出|写入)\s+[\'"]?(\w+)', doc, re.I):
        writes.add(m.group(1))
    return reads, writes


def _wrap_as_hook(cls_or_fn: Any, method_name: str = '') -> Optional[Callable]:
    """将 compat 模块中的类/函数包装为标准钩子 (ctx → result_dict)."""
    if inspect.isclass(cls_or_fn):
        # 尝试用默认参数实例化, 调用指定方法
        try:
            instance = cls_or_fn()
        except (TypeError, ValueError):
            return None  # 需要构造参数, 无法自动包装

        if method_name and hasattr(instance, method_name):
            method = getattr(instance, method_name)
            if callable(method):
                def _hook(ctx: dict, _inst=instance, _meth=method) -> dict:
                    try:
                        result = _meth(ctx)
                        return result if isinstance(result, dict) else {'result': result}
                    except Exception:
                        return {}
                return _hook
        return None

    if callable(cls_or_fn):
        def _fn_hook(ctx: dict, _fn=cls_or_fn) -> dict:
            try:
                result = _fn(ctx)
                return result if isinstance(result, dict) else {'result': result}
            except Exception:
                return {}
        return _fn_hook

    return None


class HookRegistry:
    """Compat 模块钩子注册表 — 自动发现 + 包装 + 签名推断.

    用法:
      registry = HookRegistry()
      registry.discover_and_register()
      pool = registry.hook_pool       # {name: callable} — 喂给 SmartPipeline
      model = registry.schema_model   # SchemaModel — 喂给 PipelineSynthesizer
    """

    def __init__(self, compat_path: str = 'modules.core.compat'):
        self._compat_path = compat_path
        self._hooks: Dict[str, Callable] = {}
        self._signatures: Dict[str, Tuple[Set[str], Set[str]]] = {}
        self._schema_model = None  # 惰性创建

    def discover_and_register(self,
                              module_filter: Optional[Callable[[str], bool]] = None,
                              max_hooks: int = 50) -> 'HookRegistry':
        """扫描 compat 模块, 包装为钩子, 推断签名."""
        from modules.core.schema_inference import SchemaModel, HookSignature

        self._schema_model = SchemaModel()
        modules = discover_compat_modules()
        count = 0

        for mod_path in modules:
            if count >= max_hooks:
                break
            if module_filter and not module_filter(mod_path):
                continue
            count += self._register_module(mod_path)
        return self

    def _register_module(self, mod_path: str) -> int:
        try:
            mod = importlib.import_module(mod_path)
        except Exception:
            return 0
        from modules.core.schema_inference import HookSignature

        registered = 0
        base_name = mod_path.split('.')[-1]

        for attr_name in dir(mod):
            if attr_name.startswith('_'):
                continue
            obj = getattr(mod, attr_name)

            # 检查是否为可包装的类
            if inspect.isclass(obj) and obj.__module__ == mod.__name__:
                name_match = any(p in attr_name for p in _HOOK_CLASS_PATTERNS)
                if not name_match:
                    continue
                # 尝试找到可调用的方法
                for method_pat in _HOOK_METHOD_PATTERNS:
                    full_name = f'{base_name}.{attr_name}.{method_pat}'
                    hook = _wrap_as_hook(obj, method_pat)
                    if hook is not None:
                        self._hooks[full_name] = hook
                        reads, writes = _infer_keys_from_params(getattr(obj, method_pat))
                        doc_r, doc_w = _infer_keys_from_docstring(getattr(obj, method_pat))
                        reads |= doc_r
                        writes |= doc_w
                        self._signatures[full_name] = (reads, writes)
                        sig = HookSignature(hook_name=full_name)
                        sig.update(reads, writes)
                        self._schema_model._signatures[full_name] = sig
                        registered += 1
                        break

            # 检查是否为可包装的函数
            elif callable(obj) and not inspect.isclass(obj) and obj.__module__ == mod.__name__:
                name_match = any(p in attr_name for p in _HOOK_CLASS_PATTERNS)
                if name_match:
                    hook = _wrap_as_hook(obj)
                    if hook is not None:
                        full_name = f'{base_name}.{attr_name}'
                        self._hooks[full_name] = hook
                        reads, writes = _infer_keys_from_params(obj)
                        doc_r, doc_w = _infer_keys_from_docstring(obj)
                        reads |= doc_r
                        writes |= doc_w
                        self._signatures[full_name] = (reads, writes)
                        sig = HookSignature(hook_name=full_name)
                        sig.update(reads, writes)
                        self._schema_model._signatures[full_name] = sig
                        registered += 1

        return registered

    def manual_register(self, name: str, hook_fn: Callable,
                        reads: Optional[Set[str]] = None,
                        writes: Optional[Set[str]] = None) -> 'HookRegistry':
        """手动注册钩子 (用于非 compat 模块)."""
        self._hooks[name] = hook_fn
        r, w = reads or set(), writes or set()
        self._signatures[name] = (r, w)
        if self._schema_model is None:
            from modules.core.schema_inference import SchemaModel
            self._schema_model = SchemaModel()
        from modules.core.schema_inference import HookSignature
        sig = HookSignature(hook_name=name)
        sig.update(r, w)
        self._schema_model._signatures[name] = sig
        return self

    @property
    def hook_pool(self) -> Dict[str, Callable]:
        return dict(self._hooks)

    @property
    def schema_model(self):
        return self._schema_model

    @property
    def hook_count(self) -> int:
        return len(self._hooks)

    def signatures_summary(self) -> List[Dict[str, Any]]:
        return [{
            'name': name, 'reads': sorted(reads), 'writes': sorted(writes),
        } for name, (reads, writes) in sorted(self._signatures.items())]
