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
    插件钩子管理器 - 支持用户编写 Python 脚本作为钩子
    
    使用方式:
    1. 在 hooks 目录下创建 .py 文件
    2. 定义钩子函数，例如:
       def pre_decompile(context):
           logger.info(f"即将反编译: {context['binary_path']}")
       
       def post_analysis(context):
           logger.info(f"分析完成，发现 {len(context['vulnerabilities'])} 个漏洞")
    """
    
    def __init__(self, hooks_dir: str = './hooks'):
        self.hooks_dir = hooks_dir
        self.registered_hooks: Dict[str, List[Callable]] = {}
        self._ensure_hooks_dir()
        self._load_hooks()
    
    def _ensure_hooks_dir(self):
        """确保 hooks 目录存在"""
        try:
            if not os.path.exists(self.hooks_dir):
                os.makedirs(self.hooks_dir)
                logger.info(f"创建 hooks 目录: {self.hooks_dir}")
                self._create_example_hook()
        except Exception as e:
            logger.warning(f"创建 hooks 目录失败: {e}")
    
    def _create_example_hook(self):
        """创建示例钩子脚本"""
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
        """加载所有钩子脚本"""
        if not os.path.exists(self.hooks_dir):
            return
        
        for filename in os.listdir(self.hooks_dir):
            if filename.endswith('.py') and not filename.startswith('_'):
                filepath = os.path.join(self.hooks_dir, filename)
                self._load_hook_file(filepath)
    
    def _load_hook_file(self, filepath: str):
        """加载单个钩子文件"""
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
        """注册钩子函数"""
        if hook_point not in self.registered_hooks:
            self.registered_hooks[hook_point] = []
        self.registered_hooks[hook_point].append(func)
    
    def register_hook(self, hook_point: str, func: Callable) -> bool:
        """
        手动注册钩子函数
        
        Args:
            hook_point: 钩子点名称
            func: 钩子函数
            
        Returns:
            是否成功注册
        """
        if hook_point not in HOOK_POINTS:
            logger.warning(f"无效的钩子点: {hook_point}")
            return False
        
        self._register_hook(hook_point, func)
        logger.info(f"手动注册钩子: {hook_point}")
        return True
    
    def run_hooks(self, hook_point: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        运行指定钩子点的所有钩子
        
        Args:
            hook_point: 钩子点名称
            context: 传递给钩子的上下文字典
            
        Returns:
            可能被修改后的上下文字典
        """
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
        """
        获取所有已注册的钩子点及其数量
        
        Returns:
            字典: {hook_point: count}
        """
        return {point: len(funcs) for point, funcs in self.registered_hooks.items(})
    
    def clear_hooks(self):
        """清除所有已注册的钩子"""
        self.registered_hooks.clear()
        logger.info("已清除所有钩子")
    
    def reload_hooks(self):
        """重新加载所有钩子"""
        self.clear_hooks()
        self._load_hooks()
        logger.info("钩子已重新加载")


_hook_manager_instance: Optional[HookManager] = None

def get_hook_manager(hooks_dir: str = './hooks') -> HookManager:
    """
    获取钩子管理器单例
    
    Args:
        hooks_dir: hooks 目录路径
        
    Returns:
        HookManager 实例
    """
    global _hook_manager_instance
    
    if _hook_manager_instance is None:
        _hook_manager_instance = HookManager(hooks_dir)
    elif _hook_manager_instance.hooks_dir != hooks_dir:
        logger.info(f"钩子目录变更: {_hook_manager_instance.hooks_dir} -> {hooks_dir}")
        _hook_manager_instance = HookManager(hooks_dir)
    
    return _hook_manager_instance


def run_hook(hook_point: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    便捷函数：运行钩子（自动使用全局 HookManager）
    
    Args:
        hook_point: 钩子点名称
        context: 上下文字典
        
    Returns:
        可能被修改后的上下文
    """
    try:
        manager = get_hook_manager()
        return manager.run_hooks(hook_point, context)
    except Exception as e:
        logger.debug(f"运行钩子失败 {hook_point}: {e}")
        return context or {}
