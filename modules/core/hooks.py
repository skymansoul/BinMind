import logging
import os
import importlib.util
from typing import Dict, List, Any, Callable, Optional

logger = logging.getLogger(__name__)

HOOK_POINTS = {
    'pre_info_collect',
    'post_decompile',
    'pre_exploit_generate',
    'post_report',
    'pre_decompile',
    'post_analysis',
    'pre_crash_analysis',
    'post_crash_analysis'
}

class HookManager:
    """
    钩子管理器 — 从指定目录加载用户脚本, 按名称映射到预定义钩子点.
    钩子以 context dict 为入参, 返回值若为 dict 则合并写入上下文.
    """

    def __init__(self, hooks_dir: str = './hooks'):
        self.hooks_dir = hooks_dir
        self.registered_hooks: Dict[str, List[Callable]] = {}
        self._ensure_hooks_dir()
        self._load_hooks()

    def _ensure_hooks_dir(self):
        """若 hooks 目录缺失则创建之, 并写入默认示例脚本. 创建失败仅告警."""
        try:
            if not os.path.exists(self.hooks_dir):
                os.makedirs(self.hooks_dir)
                logger.info(f"创建 hooks 目录: {self.hooks_dir}")
                self._create_example_hook()
        except Exception as e:
            logger.warning(f"创建 hooks 目录失败: {e}")

    def _create_example_hook(self):
        """在hooks目录写入 example_hook.py 示例, 已存在则跳过."""
        example_path = os.path.join(self.hooks_dir, 'example_hook.py')
        if os.path.exists(example_path):
            return

        example_content = '''"""
示例钩子脚本 - 复制此文件并修改以创建自定义钩子

可用的钩子点:
- pre_info_collect(context): 信息收集前
- pre_decompile(context): 反编译前
- post_decompile(context): 反编译后
- post_analysis(context): AI 分析后
- pre_exploit_generate(context): 利用生成前
- post_report(context): 报告生成后
- pre_crash_analysis(context): 崩溃分析前
- post_crash_analysis(context): 崩溃分析后

context 字典包含:
- binary_path: 二进制文件路径
- function_name: 函数名（如适用）
- (其他钩子特定的上下文信息)
"""

import logging

logger = logging.getLogger(__name__)

def pre_info_collect(context):
    """信息收集前钩子"""
    binary_path = context.get('binary_path', 'unknown')
    logger.info(f"[Example Hook] 开始分析: {binary_path}")

def post_decompile(context):
    """反编译后钩子"""
    func_count = context.get('functions_analyzed', 0)
    logger.info(f"[Example Hook] 反编译完成，分析了 {func_count} 个函数")

def pre_exploit_generate(context):
    """利用生成前钩子"""
    vuln_type = context.get('vulnerability_type', 'unknown')
    logger.info(f"[Example Hook] 开始生成 {vuln_type} 类型的利用脚本")

def post_report(context):
    """报告生成后钩子"""
    reports = context.get('reports', {})
    for fmt, path in reports.items():
        logger.info(f"[Example Hook] 报告已生成: {fmt} -> {path}")
'''
        try:
            with open(example_path, 'w', encoding='utf-8') as f:
                f.write(example_content)
            logger.info(f"创建示例钩子脚本: {example_path}")
        except Exception as e:
            logger.warning(f"创建示例钩子失败: {e}")

    def _load_hooks(self):
        """遍历hooks目录, 加载所有非下划线前缀的 .py 文件."""
        if not os.path.exists(self.hooks_dir):
            return

        for filename in os.listdir(self.hooks_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                filepath = os.path.join(self.hooks_dir, filename)
                self._load_hook_file(filepath)

    def _load_hook_file(self, filepath: str):
        """以 spec_from_file_location 动态加载单个 .py 钩子, 将其中的钩子点映射函数注册到管理器."""
        try:
            filename = os.path.basename(filepath)
            module_name = f'user_hook_{os.path.splitext(filename)[0]}'

            spec = importlib.util.spec_from_file_location(module_name, filepath)
            if spec is None or spec.loader is None:
                logger.warning(f"无法加载钩子文件: {filepath}")
                return

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            for hook_point in HOOK_POINTS:
                if hasattr(module, hook_point):
                    hook_func = getattr(module, hook_point)
                    if callable(hook_func):
                        self._register_hook(hook_point, hook_func)
                        logger.info(f"注册钩子: {hook_point} ({filename})")

        except Exception as e:
            logger.warning(f"加载钩子文件失败 {filepath}: {e}")

    def _register_hook(self, hook_point: str, func: Callable):
        """将可调用对象追加到指定钩子点的回调列表."""
        if hook_point not in self.registered_hooks:
            self.registered_hooks[hook_point] = []
        self.registered_hooks[hook_point].append(func)

    def register_hook(self, hook_point: str, func: Callable) -> bool:
        """验证钩子点有效性后注册; 非法钩子点返回 False."""
        if hook_point not in HOOK_POINTS:
            logger.warning(f"无效的钩子点: {hook_point}")
            return False

        self._register_hook(hook_point, func)
        logger.info(f"手动注册钩子: {hook_point}")
        return True

    def run_hooks(self, hook_point: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """依次调用指定钩子点的全部注册函数; 返回 dict 的钩子可改写上下文, 异常仅告警不中断."""
        if context is None:
            context = {}

        if hook_point not in self.registered_hooks:
            return context

        logger.debug(f"运行钩子: {hook_point} ({len(self.registered_hooks[hook_point])} 个)")

        for hook_func in self.registered_hooks[hook_point]:
            try:
                result = hook_func(context)
                if result is not None and isinstance(result, dict):
                    context = result
            except Exception as e:
                logger.warning(f"钩子执行失败 {hook_point}: {e}")

        return context

    def get_registered_hooks(self) -> Dict[str, int]:
        """返回 {钩子点名: 注册函数数} 的快照."""
        return {point: len(funcs) for point, funcs in self.registered_hooks.items()}

    def clear_hooks(self):
        """清空全部注册记录."""
        self.registered_hooks.clear()
        logger.info("已清除所有钩子")

    def reload_hooks(self):
        """先清空再重新扫描加载所有钩子文件."""
        self.clear_hooks()
        self._load_hooks()
        logger.info("钩子已重新加载")


_hook_manager_instance: Optional[HookManager] = None

def get_hook_manager(hooks_dir: str = './hooks') -> HookManager:
    """模块级单例: 首次调用创建 HookManager, hooks_dir 变更时重建."""
    global _hook_manager_instance

    if _hook_manager_instance is None:
        _hook_manager_instance = HookManager(hooks_dir)
    elif _hook_manager_instance.hooks_dir != hooks_dir:
        logger.info(f"钩子目录变更: {_hook_manager_instance.hooks_dir} -> {hooks_dir}")
        _hook_manager_instance = HookManager(hooks_dir)

    return _hook_manager_instance


def run_hook(hook_point: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """便捷入口: 通过全局单例运行钩子, 异常退化为返回原 context."""
    try:
        manager = get_hook_manager()
        return manager.run_hooks(hook_point, context)
    except Exception as e:
        logger.debug(f"运行钩子失败 {hook_point}: {e}")
        return context or {}
