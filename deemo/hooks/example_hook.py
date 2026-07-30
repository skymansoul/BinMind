<<<<<<< HEAD
"""
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
=======
# example_hook.py — hook script template
# Copy to hooks/ directory, rename, and implement needed hooks.
# Context is passed as dict for type safety — kwargs silently swallowed typos.

"""
Supported hook points (in execution order):
  pre_info_collect     — before info collection
  post_info_collect    — after info collection
  pre_decompile        — before decompilation
  post_decompile       — after decompilation
  pre_analysis         — before AI analysis
  post_analysis        — after AI analysis
  pre_exploit_generate — before exploit generation
  post_exploit_generate— after exploit generation
  pre_crash_analysis   — before crash analysis
  post_crash_analysis  — after crash analysis
  post_report          — after report generation

Each hook: func(context: dict) -> None
Remove unused hook definitions — hook manager uses hasattr to skip missing ones.
>>>>>>> d81973a (精简冗余模块)
"""

import logging

<<<<<<< HEAD
logger = logging.getLogger(__name__)

def pre_info_collect(context):
    """信息收集前钩子"""
    binary_path = context.get('binary_path', 'unknown')
    logger.info(f"[Example Hook] 开始分析: {binary_path}")
=======
_logger = logging.getLogger(__name__)
>>>>>>> d81973a (精简冗余模块)

def post_decompile(context):
    """反编译后钩子"""
    func_count = context.get('functions_analyzed', 0)
    logger.info(f"[Example Hook] 反编译完成，分析了 {func_count} 个函数")

<<<<<<< HEAD
def pre_exploit_generate(context):
    """利用生成前钩子"""
    vuln_type = context.get('vulnerability_type', 'unknown')
    logger.info(f"[Example Hook] 开始生成 {vuln_type} 类型的利用脚本")

def post_report(context):
    """报告生成后钩子"""
    reports = context.get('reports', {})
    for fmt, path in reports.items():
        logger.info(f"[Example Hook] 报告已生成: {fmt} -> {path}")
=======
def _safe_get(ctx, key, default='unknown'):
    """Safe dict.get with null guard for context."""
    if ctx is None:
        return default
    val = ctx.get(key, default)
    return default if val is None else val


def pre_info_collect(context):
    bp = _safe_get(context, 'binary_path', 'unknown')
    _logger.info(f"[Example Hook] starting analysis: {bp}")


def post_decompile(context):
    n_func = _safe_get(context, 'functions_analyzed', 0)
    engine = _safe_get(context, 'decompiler_used', 'unknown')
    _logger.info(f"[Example Hook] decompile done — {n_func} functions, engine: {engine}")


def pre_exploit_generate(context):
    vt = _safe_get(context, 'vulnerability_type', 'unknown')
    if not vt or vt == 'unknown':
        _logger.warning("[Example Hook] vuln type unknown, exploit may fail")
    _logger.info(f"[Example Hook] generating exploit — type: {vt}")


def post_report(context):
    reports = _safe_get(context, 'reports', {})
    if not reports:
        _logger.warning("[Example Hook] no reports generated")
        return
    for fmt in reports:
        path = reports[fmt]
        if path:
            _logger.info(f"[Example Hook] report: {fmt} -> {path}")
>>>>>>> d81973a (精简冗余模块)
