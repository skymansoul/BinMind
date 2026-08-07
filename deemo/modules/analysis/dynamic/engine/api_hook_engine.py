# 2026-07-15
# API Hook 引擎 —— 拦截 API 调用，支持反调试/反虚拟机/时序对抗
# 设计思路：middleware 链式分发，优先级越低越先执行
# 内置常用的反-反调试和反-反虚拟机 hook

import re
import logging
import hashlib
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Callable, Any

_log = logging.getLogger(__name__)


# 枚举与数据结构

class HookAction(Enum):
    CONTINUE = auto()        # 继续传递给下一个 hook
    SKIP_ORIGINAL = auto()   # 跳过原始调用，返回 result
    MODIFY_ARGS = auto()     # 修改参数后继续执行原始调用
    DROP = auto()            # 丢弃此次调用


@dataclass
class HookEntry:
    pattern: str                                    # API 名称匹配正则
    handler: Callable[..., Tuple[HookAction, Any]]  # (api_name, args, module) -> (action, result)
    priority: int = 100
    module_filter: Optional[str] = None  # 可选模块名正则
    enabled: bool = True
    hook_id: str = ""


# 钩子 注册表

class HookRegistry:
    """
    管理所有 HookEntry 的注册/注销/查询
    使用缓存加速匹配 (api_name + module_name)
    """

    def __init__(self):
        self._hooks: List[HookEntry] = []
        self._match_cache: Dict[str, List[HookEntry]] = {}
        self._hook_counter: int = 0

    def register(self, pattern: str, handler: Callable,
                 priority: int = 100, module_filter: Optional[str] = None) -> str:
        """注册 钩子, 返回 钩子_id"""
        self._hook_counter += 1
        hid = f"hook_{self._hook_counter}_{hashlib.md5(pattern.encode()).hexdigest()[:6]}"
        entry = HookEntry(
            pattern=pattern,
            handler=handler,
            priority=priority,
            module_filter=module_filter,
            hook_id=hid,
        )
        self._hooks.append(entry)
        self._hooks.sort(key=lambda h: h.priority)
        self._match_cache.clear()
        return hid

    def unregister(self, hook_id: str) -> bool:
        before = len(self._hooks)
        self._hooks = [h for h in self._hooks if h.hook_id != hook_id]
        if len(self._hooks) != before:
            self._match_cache.clear()
            return True
        return False

    # //// 获取匹配当前调用的所有 hook ////
    def get_matches(self, api_name: str, module_name: str = "") -> List[HookEntry]:
        cache_key = f"{api_name}\x00{module_name}"
        if cache_key in self._match_cache:
            return self._match_cache[cache_key]

        matched: List[HookEntry] = []
        for entry in self._hooks:
            if not entry.enabled:
                continue
            # 匹配 API 名
            if not re.search(entry.pattern, api_name, re.IGNORECASE):
                continue
            # 匹配模块名
            if entry.module_filter and module_name:
                if not re.search(entry.module_filter, module_name, re.IGNORECASE):
                    continue
            matched.append(entry)
        # 已按 priority 排序（寄存器 时排序）
        self._match_cache[cache_key] = matched
        return matched

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
        self._install_builtins()

# 分发器: 核心分发逻辑
    def dispatch(self, api_name: str, args: Any,
                 module_name: str = "") -> Tuple[bool, Any]:
        """
        遍历匹配的 钩子s, 返回 (handled, result)
        handled=True 表示被某 hook 截获，不应再调用原始函数
        """
        hooks = self.registry.get_matches(api_name, module_name)
        if not hooks:
            return (False, None)

        current_args = args
        for entry in hooks:
            try:
                action, result = entry.handler(api_name, current_args, module_name)
            except Exception:
                _log.exception("hook %s 异常, 跳过", entry.hook_id)
                continue

            if action == HookAction.DROP:
                return (True, None)
            elif action == HookAction.SKIP_ORIGINAL:
                return (True, result)
            elif action == HookAction.MODIFY_ARGS:
                current_args = result  # 处理器 返回新的 args
                # 继续下一个 hook
            elif action == HookAction.CONTINUE:
                continue

        # 所有 hook 都未截获 → 执行原始调用
        return (False, current_args)

# decorator 风格注册
    def hook(self, pattern: str, priority: int = 100,
             module_filter: Optional[str] = None):
        """@engine.钩子('IsDebuggerPresent') 装饰器"""
        def decorator(fn: Callable):
            self.registry.register(pattern, fn, priority, module_filter)
            return fn
        return decorator

# 启用/禁用
    def enable_hook(self, hook_id: str) -> bool:
        for h in self.registry._hooks:
            if h.hook_id == hook_id:
                h.enabled = True
                self.registry.clear_cache()
                return True
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

        def _block_is_debugger(api_name, args, module):
            """IsDebuggerPresent → 永远返回 False"""
            return (HookAction.SKIP_ORIGINAL, False)

        def _block_check_remote(api_name, args, module):
            """CheckRemoteDebuggerPresent → pbDebuggerPresent = False"""
            # args 可能是 (hProcess, pbDebuggerPresent)
            return (HookAction.SKIP_ORIGINAL, False)

        def _filter_nt_query_info(api_name, args, module):
            """NtQueryInformationProcess → 过滤 ProcessDebugPort / ProcessDebugObjectHandle"""
            if len(args) >= 2:
                info_class = args[1] if len(args) > 1 else 0
                # 7 = ProcessDebugPort, 30 = ProcessDebugObjectHandle, 31 = ProcessDebugFlags
                if info_class in (7, 30, 31):
                    return (HookAction.SKIP_ORIGINAL, 0)
            return (HookAction.CONTINUE, None)

        def _block_ntset_info_thread(api_name, args, module):
            """NtSetInformationThread → 拦截 HideFromDebugger (0x11)"""
            if len(args) >= 2 and args[1] == 0x11:
                return (HookAction.SKIP_ORIGINAL, 0)  # ThreadHideFromDebugger
            return (HookAction.CONTINUE, None)

        def _spoof_peb_being_debugged(api_name, args, module):
            """访问 PEB.BeingDebugged 的任何调用 → 返回 0"""
            return (HookAction.SKIP_ORIGINAL, 0)

        anti_debug_hooks = [
            (r"^IsDebuggerPresent$",             _block_is_debugger,          10),
            (r"^CheckRemoteDebuggerPresent$",    _block_check_remote,         10),
            (r"^NtQueryInformationProcess$",     _filter_nt_query_info,       10, r"ntdll"),
            (r"^ZwQueryInformationProcess$",     _filter_nt_query_info,       10, r"ntdll"),
            (r"^NtSetInformationThread$",        _block_ntset_info_thread,    10, r"ntdll"),
            (r"^NtQuerySystemInformation$",      _spoof_peb_being_debugged,  15),
        ]
        for spec in anti_debug_hooks:
            if len(spec) == 3:
                self.registry.register(spec[0], spec[1], spec[2])
            else:
                self.registry.register(spec[0], spec[1], spec[2], spec[3])

# 反虚拟机
    def _register_anti_vm(self):

        def _fake_registry_vm(api_name, args, module):
            """拦截注册表查询 VM 特征键"""
            if len(args) >= 1:
                key_path = str(args[0]).lower() if args else ""
                # 常见 VM 注册表路径
                vm_keys = ["vbox", "vmware", "qemu", "virtualbox", "parallels",
                          "system\\currentcontrolset\\services\\vbox",
                          "system\\currentcontrolset\\services\\vmware"]
                for vk in vm_keys:
                    if vk in key_path:
                        return (HookAction.SKIP_ORIGINAL, 0)  # 键不存在
            return (HookAction.CONTINUE, None)

        def _fake_system_manufacturer(api_name, args, module):
            """WMI / BIOS 查询 → 返回假的制造商信息"""
            return (HookAction.SKIP_ORIGINAL, "Dell Inc.")

        def _fake_mac_address(api_name, args, module):
            """Get适配器sInfo → 过滤 VM 特征 MAC (00:05:69, 00:0C:29, 00:50:56, 08:00:27)"""
            return (HookAction.SKIP_ORIGINAL, "00:1A:2B:3C:4D:5E")

        anti_vm_specs = [
            (r"^RegOpenKey(Ex)?[AW]?$",    _fake_registry_vm,        20),
            (r"^RegQueryValue(Ex)?[AW]?$", _fake_registry_vm,        20),
            (r"^GetSystemFirmwareTable$",  _fake_system_manufacturer, 20),
            (r"^GetAdaptersInfo$",         _fake_mac_address,         20),
        ]
        for pat, handler, pri in anti_vm_specs:
            self.registry.register(pat, handler, pri)

# timing anti-anti
    def _register_timing(self):

        import time as _tmod
        _const_time = int(_tmod.time() * 1000)

        def _const_get_tick_count(api_name, args, module):
            """GetTickCount / GetTickCount64 → 返回固定值，防止时间差检测"""
            return (HookAction.SKIP_ORIGINAL, _const_time)

        def _const_query_perf_counter(api_name, args, module):
            """Query性能Counter → 返回固定的单调增长"""
            return (HookAction.SKIP_ORIGINAL, _const_time * 10000)

        def _const_rdtsc(api_name, args, module):
            """RDTSC → 返回固定时间戳"""
            return (HookAction.SKIP_ORIGINAL, _const_time * 1000)

        def _block_sleep_skip(api_name, args, module):
            """NtDelayExecution / Sleep → 不让恶意代码用 sleep 检测加速"""
            return (HookAction.CONTINUE, None)  # 不阻止 sleep，但之前已固定时间

        timing_specs = [
            (r"^GetTickCount(64)?$",     _const_get_tick_count,    30),
            (r"^QueryPerformanceCounter$", _const_query_perf_counter, 30),
            (r"^__rdtsc$",               _const_rdtsc,             30),
            (r"^NtDelayExecution$",      _block_sleep_skip,        40, r"ntdll"),
        ]
        for spec in timing_specs:
            if len(spec) == 3:
                self.registry.register(spec[0], spec[1], spec[2])
            else:
                self.registry.register(spec[0], spec[1], spec[2], spec[3])


# 便捷工厂
def create_default_engine() -> HookEngine:
    """创建预装全部内置 hook 的引擎"""
    return HookEngine()
