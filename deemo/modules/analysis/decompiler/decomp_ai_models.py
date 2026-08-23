"""
decomp_ai_models.py：模型配置, 提示词模板, 反编译引擎
基础设施 constants

包含:
- system 提示词模板
- Model 温度参数 token limit defaults
- 反编译引擎 engine type constants
- String sanitization 工具集 (ANSI escape removal, function name 校验
Java/IDC string escaping)
- 钩子 system 回退 plugin loading
"""

import re
import os
import logging
import hashlib
import importlib.util
import uuid

from typing import Dict, Set, Any

logger = logging.getLogger(__name__)



AI_SYSTEM_PROMPT_ANALYSIS = (
    "你是一个资深的二进制安全研究员，专业分析二进制漏洞。"
)

AI_SYSTEM_PROMPT_FOLLOW_UP = (
    "你是一个资深的二进制安全研究员，专业分析二进制漏洞。"
    "请基于之前的对话上下文回答问题。"
)

# 模型配置

# 温度参数
AI_TEMPERATURE_ANALYSIS = 0.2
AI_TEMPERATURE_FOLLOW_UP = 0.3

AI_MAX_TOKENS_ANALYSIS = 4000
AI_MAX_TOKENS_FOLLOW_UP = 3000


ANSI_ESCAPE_PATTERN = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')


def strip_ansi_escape(text: str) -> str:
    if not text:
        return text
    return ANSI_ESCAPE_PATTERN.sub('', text)



try:
    from modules.core.hooks import run_hook, get_hook_manager, HOOK_POINTS
    HOOKS_AVAILABLE = True
except ImportError:
    try:
        from hooks import run_hook, get_hook_manager, HOOK_POINTS
        HOOKS_AVAILABLE = True
    except ImportError:
        HOOKS_AVAILABLE = False
        def run_hook(hook_point, context=None):
            return context or {}
        HOOK_POINTS: Set[str] = set()


def load_plugin_script(plugin_path: str) -> bool:
    # 加载自定义插件脚本路径并注册钩子函数，成功返回True
    logger.info(f"正在加载插件: {plugin_path}")

    if not HOOKS_AVAILABLE:
        logger.error("hooks 模块不可用，无法加载插件")
        return False

    try:
        if not os.path.exists(plugin_path):
            logger.error(f"插件文件不存在: {plugin_path}")
            return False

        filename = os.path.basename(plugin_path)
        logger.info(f"解析插件文件: {filename}")

        module_name = f'user_plugin_{os.path.splitext(filename)[0]}'

        spec = importlib.util.spec_from_file_location(module_name, plugin_path)
        if spec is None or spec.loader is None:
            logger.error(f"无法加载插件: {plugin_path}")
            return False

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        logger.info(f"插件模块已加载: {module_name}")

        manager = get_hook_manager()
        loaded_count = 0

        available_hooks = [h for h in HOOK_POINTS if hasattr(module, h) and callable(getattr(module, h))]
        logger.info(f"插件 {filename} 中定义的钩子: {available_hooks}")

        for hook_point in HOOK_POINTS:
            if hasattr(module, hook_point):
                hook_func = getattr(module, hook_point)
                if callable(hook_func):
                    manager.register_hook(hook_point, hook_func)
                    loaded_count += 1
                    logger.info(f"✓ 已注册钩子: {hook_point} ({filename})")

        if loaded_count > 0:
            logger.info(f"插件加载成功: {filename} ({loaded_count} 个钩子已注册)")
        else:
            logger.warning(f"插件 {filename} 中未找到任何有效的钩子函数，请检查钩子函数名是否正确")
            logger.info(f"可用的钩子点: {sorted(HOOK_POINTS)}")

        return loaded_count > 0

    except Exception as e:
        logger.error(f"加载插件失败 {plugin_path}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


DECOMPILER_RADARE2 = 'radare2'
DECOMPILER_GHIDRA = 'ghidra'
DECOMPILER_IDA = 'ida'
DECOMPILER_BINARYNINJA = 'binaryninja'
DECOMPILER_HOPPER = 'hopper'
DECOMPILER_AUTO = 'auto'


FUNCTION_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')

JAVA_STRING_ESCAPE_MAP = {
    '\\': '\\\\',
    '"': '\\"',
    "'": "\\'",
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
    '\b': '\\b',
    '\f': '\\f',
}


def sanitize_function_name(func_name: str) -> str:
    """
    清理函数名，防止命令注入，严格限制字符集

    只允许: 字母、数字、下划线、连字符、点号
    """
    if not func_name:
        return 'main'

    if not isinstance(func_name, str):
        logger.warning(f"函数名不是字符串类型: {type(func_name)}")
        return 'main'

    original_name = func_name.strip()

    if not original_name:
        return 'main'

    if FUNCTION_NAME_PATTERN.match(original_name):
        return original_name

    dangerous_chars = ['\n', '\r', ';', '&', '|', '`', '$', '(', ')', '<', '>', '?', '*', '[', ']', '{', '}']
    has_dangerous = any(c in original_name for c in dangerous_chars)
    if has_dangerous:
        logger.warning(f"检测到函数名中包含危险字符，已清理: {repr(original_name)}")

    sanitized = re.sub(r'[^\w\-_\.]', '_', original_name)
    sanitized = sanitized.strip('_')

    if not sanitized:
        return 'main'

    return sanitized


def escape_java_string(s: str) -> str:
    """安全地转义 Java 字符串中的特殊字符，防止脚本注入"""
    if not s:
        return ''

    result = []
    for c in s:
        if c in JAVA_STRING_ESCAPE_MAP:
            result.append(JAVA_STRING_ESCAPE_MAP[c])
        elif ord(c) < 32 or ord(c) > 126:
            result.append(f'\\u{ord(c):04x}')
        else:
            result.append(c)

    return ''.join(result)


def escape_idc_string(s: str) -> str:
    """
    安全地转义 IDA IDC 脚本中的字符串
    """
    if not s:
        return ''

    result = []
    for c in s:
        if c == '\\':
            result.append('\\\\')
        elif c == '"':
            result.append('\\"')
        elif c == "'":
            result.append("\\'")
        elif c == '\n':
            result.append('\\n')
        elif c == '\r':
            result.append('\\r')
        elif c == '\t':
            result.append('\\t')
        elif ord(c) < 32 or ord(c) > 126:
            result.append(f'\\x{ord(c):02x}')
        else:
            result.append(c)

    return ''.join(result)
