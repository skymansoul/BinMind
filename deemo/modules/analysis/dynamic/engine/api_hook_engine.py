# 2026-07-15
# API Hook 引擎 —— 拦截 API 调用，支持反调试/反虚拟机/时序对抗
# 设计思路：middleware 链式分发，优先级越低越先执行
# 内置常用的反-反调试和反-反虚拟机 hook

import re
import logging
import hashlib
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Any, Union, Set

_log = logging.getLogger(__name__)


class HookAction(Enum):
    CONTINUE = auto()        # 继续执行后续回调
    SKIP_ORIGINAL = auto()   # 跳过原始调用，使用 return_value
    MODIFY_ARGS = auto()     # 修改参数后继续
    DROP = auto()            # 丢弃本次调用


class HookEvent(Enum):
    PRE = auto()
    POST = auto()
    ERROR = auto()


@dataclass
class HookContext:
    """单次调用的分发上下文。"""
    api_name: str
    args: list = field(default_factory=list)
    module_name: str = ""
    action: HookAction = HookAction.CONTINUE
    return_value: Any = None
    error: Optional[BaseException] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HookDescriptor:
    """已注册 hook 的元数据与回调链。"""
    hook_id: str
    pattern: str
    pre: List[Callable] = field(default_factory=list)
    post: List[Callable] = field(default_factory=list)
    error: List[Callable] = field(default_factory=list)
    priority: int = 100
    module_filter: Optional[Union[Set[str], str]] = None
    enabled: bool = True


class HookRegistry:
    """
    管理所有 HookEntry 的注册/注销/查询
    使用缓存加速匹配 (api_name + module_name)
    """

    def __init__(self):
        self._hooks: List[HookDescriptor] = []
        self._match_cache: Dict[str, List[HookDescriptor]] = {}

    def register(self, hook_id: str, pattern: str, pre=None, post=None,
                 error=None, priority: int = 100,
                 module_filter: Optional[Union[Set[str], str]] = None) -> str:
        """注册 hook，返回 hook_id。"""
        descriptor = HookDescriptor(
            hook_id=hook_id,
            pattern=pattern,
            pre=list(pre) if pre else [],
            post=list(post) if post else [],
            error=list(error) if error else [],
            priority=priority,
            module_filter=module_filter,
        )
        self._hooks.append(descriptor)
        self._hooks.sort(key=lambda h: h.priority, reverse=True)
        self._match_cache.clear()
        return hook_id

    def unregister(self, hook_id: str) -> bool:
        before = len(self._hooks)
        self._hooks = [h for h in self._hooks if h.hook_id != hook_id]
        if len(self._hooks) != before:
            self._match_cache.clear()
            return True
        return False

    def enable(self, hook_id: str) -> bool:
        for h in self._hooks:
            if h.hook_id == hook_id:
                h.enabled = True
                self._match_cache.clear()
                return True
        return False

    def disable(self, hook_id: str) -> bool:
        for h in self._hooks:
            if h.hook_id == hook_id:
                h.enabled = False
                self._match_cache.clear()
                return True
        return False

    def list_hooks(self) -> List[Dict[str, Any]]:
        return [
            {
                'hook_id': h.hook_id,
                'pattern': h.pattern,
                'priority': h.priority,
                'enabled': h.enabled,
            }
            for h in self._hooks
        ]

    def _module_matches(self, descriptor: HookDescriptor, module_name: str) -> bool:
        if not descriptor.module_filter:
            return True
        if isinstance(descriptor.module_filter, (set, frozenset)):
            return module_name in descriptor.module_filter
        return bool(re.search(descriptor.module_filter, module_name or "", re.IGNORECASE))

    def get_hooks_for_api(self, api_name: str, module_name: str = "") -> List[HookDescriptor]:
        cache_key = f"{api_name}\x00{module_name}"
        if cache_key in self._match_cache:
            return self._match_cache[cache_key]

        matched = [
            h for h in self._hooks
            if h.enabled
            and re.search(h.pattern, api_name, re.IGNORECASE)
            and self._module_matches(h, module_name)
        ]
        self._match_cache[cache_key] = matched
        return matched

    def get_matches(self, api_name: str, module_name: str = "") -> List[HookDescriptor]:
        return self.get_hooks_for_api(api_name, module_name)

    def clear_cache(self) -> None:
        self._match_cache.clear()

    @property
    def count(self) -> int:
        return len([h for h in self._hooks if h.enabled])

    def __len__(self) -> int:
        return self.count


# 钩子 引擎

class HookEngine:
    """
    API 拦截分发器
    按优先级遍历匹配的 hook，按 action 决定后续行为
    """

    def __init__(self):
        self.registry = HookRegistry()
        self._stats: Dict[str, int] = {'total_calls': 0, 'skipped': 0}
        self._install_builtins()

    def dispatch_pre(self, api_name: str, args: Any,
                     module_name: str = "") -> HookContext:
        """执行 pre 回调链，返回处理后的上下文。"""
        ctx = HookContext(api_name=api_name, args=list(args or []), module_name=module_name)
        self._stats['total_calls'] = self._stats.get('total_calls', 0) + 1
        hooks = self.registry.get_hooks_for_api(api_name, module_name)
        for descriptor in hooks:
            for callback in descriptor.pre:
                try:
                    result = callback(ctx)
                except Exception:
                    _log.exception("pre callback %s 异常", descriptor.hook_id)
                    continue
                if result is HookAction.SKIP_ORIGINAL:
                    ctx.action = HookAction.SKIP_ORIGINAL
                    self._stats['skipped'] = self._stats.get('skipped', 0) + 1
                    return ctx
                if result is HookAction.DROP:
                    ctx.action = HookAction.DROP
                    return ctx
        return ctx

    def dispatch_post(self, ctx: HookContext, return_value: Any = None) -> HookContext:
        """执行 post 回调链。"""
        ctx.return_value = return_value
        hooks = self.registry.get_hooks_for_api(ctx.api_name, ctx.module_name)
        for descriptor in hooks:
            for callback in descriptor.post:
                try:
                    callback(ctx)
                except Exception:
                    _log.exception("post callback %s 异常", descriptor.hook_id)
        return ctx

    def dispatch_error(self, ctx: HookContext, exc: BaseException) -> HookContext:
        """执行 error 回调链。"""
        ctx.error = exc
        hooks = self.registry.get_hooks_for_api(ctx.api_name, ctx.module_name)
        for descriptor in hooks:
            for callback in descriptor.error:
                try:
                    callback(ctx)
                except Exception:
                    _log.exception("error callback %s 异常", descriptor.hook_id)
        return ctx

    def dispatch(self, api_name: str, args: Any,
                 module_name: str = "") -> tuple:
        """兼容入口：执行 pre 链并按 action 返回 (handled, result)。"""
        ctx = self.dispatch_pre(api_name, args, module_name)
        if ctx.action in (HookAction.SKIP_ORIGINAL, HookAction.DROP):
            return (True, ctx.return_value)
        return (False, ctx.args)

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.registry._hooks.clear()
        self.registry.clear_cache()
        return False

    def disable_hook(self, hook_id: str) -> bool:
        for h in self.registry._hooks:
            if h.hook_id == hook_id:
                h.enabled = False
                self.registry.clear_cache()
                return True
        return False

# 内置反调试 钩子s
    def _install_builtins(self):
        self._register_anti_debug()
        self._register_anti_vm()
        self._register_timing()

# 反调试
    def _register_anti_debug(self):
        def _block_is_debugger(ctx):
            ctx.return_value = False
            return HookAction.SKIP_ORIGINAL

        def _block_check_remote(ctx):
            ctx.return_value = False
            return HookAction.SKIP_ORIGINAL

        def _filter_nt_query_info(ctx):
            if len(ctx.args) >= 2 and ctx.args[1] in (7, 30, 31):
                ctx.return_value = 0
                return HookAction.SKIP_ORIGINAL
            return HookAction.CONTINUE

        def _block_ntset_info_thread(ctx):
            if len(ctx.args) >= 2 and ctx.args[1] == 0x11:
                ctx.return_value = 0
                return HookAction.SKIP_ORIGINAL
            return HookAction.CONTINUE

        anti_debug_hooks = [
            ("anti_debug_is_debugger", r"^IsDebuggerPresent$", _block_is_debugger, 10),
            ("anti_debug_check_remote", r"^CheckRemoteDebuggerPresent$", _block_check_remote, 10),
            ("anti_debug_query_info", r"^(Nt|Zw)QueryInformationProcess$", _filter_nt_query_info, 10, {"ntdll"}),
            ("anti_debug_set_thread", r"^NtSetInformationThread$", _block_ntset_info_thread, 10, {"ntdll"}),
        ]
        for spec in anti_debug_hooks:
            hook_id, pattern, cb, pri = spec[:4]
            mf = spec[4] if len(spec) > 4 else None
            self.registry.register(hook_id, pattern, pre=[cb], priority=pri, module_filter=mf)

# 反虚拟机
    def _register_anti_vm(self):
        def _fake_registry_vm(ctx):
            key_path = str(ctx.args[0]).lower() if ctx.args else ""
            vm_keys = ["vbox", "vmware", "qemu", "virtualbox", "parallels"]
            if any(vk in key_path for vk in vm_keys):
                ctx.return_value = 0
                return HookAction.SKIP_ORIGINAL
            return HookAction.CONTINUE

        def _fake_system_manufacturer(ctx):
            ctx.return_value = "Dell Inc."
            return HookAction.SKIP_ORIGINAL

        def _fake_mac_address(ctx):
            ctx.return_value = "00:1A:2B:3C:4D:5E"
            return HookAction.SKIP_ORIGINAL

        anti_vm_specs = [
            ("anti_vm_registry", r"^Reg(OpenKey|QueryValue)(Ex)?[AW]?$", _fake_registry_vm, 20),
            ("anti_vm_firmware", r"^GetSystemFirmwareTable$", _fake_system_manufacturer, 20),
            ("anti_vm_mac", r"^GetAdaptersInfo$", _fake_mac_address, 20),
        ]
        for hook_id, pattern, cb, pri in anti_vm_specs:
            self.registry.register(hook_id, pattern, pre=[cb], priority=pri)

# timing anti-anti
    def _register_timing(self):

        import time as _tmod
        _const_time = int(_tmod.time() * 1000)

        def _const_tick_count(ctx):
            ctx.return_value = _const_time
            return HookAction.SKIP_ORIGINAL

        def _const_perf_counter(ctx):
            ctx.return_value = _const_time * 10000
            return HookAction.SKIP_ORIGINAL

        def _const_rdtsc(ctx):
            ctx.return_value = _const_time * 1000
            return HookAction.SKIP_ORIGINAL

        timing_specs = [
            ("timing_tick", r"^GetTickCount(64)?$", _const_tick_count, 30),
            ("timing_perf", r"^QueryPerformanceCounter$", _const_perf_counter, 30),
            ("timing_rdtsc", r"^__rdtsc$", _const_rdtsc, 30),
        ]
        for hook_id, pattern, cb, pri in timing_specs:
            self.registry.register(hook_id, pattern, pre=[cb], priority=pri)


# ---- 便捷回调工厂 ----

def log_args_callback(prefix: str = "hook") -> Callable:
    """生成记录调用参数的 pre 回调。"""
    def _cb(ctx: HookContext):
        _log.info("%s: %s(%r)", prefix, ctx.api_name, ctx.args)
        return HookAction.CONTINUE
    return _cb


def return_override_callback(value: Any) -> Callable:
    """生成固定返回值回调。"""
    def _cb(ctx: HookContext):
        ctx.return_value = value
        return HookAction.SKIP_ORIGINAL
    return _cb


def arg_mutator_callback(index: int, value: Any) -> Callable:
    """生成修改指定参数的回调。"""
    def _cb(ctx: HookContext):
        if 0 <= index < len(ctx.args):
            ctx.args[index] = value
        return HookAction.CONTINUE
    return _cb


def conditional_skip(predicate: Callable, return_value: Any = None) -> Callable:
    """predicate(ctx) 为真时跳过原始调用。"""
    def _cb(ctx: HookContext):
        if predicate(ctx):
            ctx.return_value = return_value
            return HookAction.SKIP_ORIGINAL
        return HookAction.CONTINUE
    return _cb


# 便捷工厂
def create_default_engine() -> HookEngine:
    """创建预装全部内置 hook 的引擎"""
    return HookEngine()
