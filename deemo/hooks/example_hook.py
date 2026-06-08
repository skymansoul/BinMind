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
