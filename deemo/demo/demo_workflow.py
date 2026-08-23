# 演示工具: 单样本全流程展示
# 流程: 静态画像 -> 规则检测 -> LLM 研判 -> 报告生成
# 用途: 竞赛展示, 接受一个样本路径, 调用主流水线输出演示报告

import argparse
import json
import os
import sys
import time

# 将项目根目录加入搜索路径, 保证 from core.pipeline import run_pipeline 可用
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from core.pipeline import run_pipeline


def _print_stage(title, elapsed=None):
    # 分隔线 + 阶段标题, 可选耗时
    bar = '=' * 60
    suffix = f' ({elapsed:.2f}s)' if elapsed is not None else ''
    print(f'\n{bar}\n  {title}{suffix}\n{bar}')


def _print_binary_info(binfo):
    # 输出静态画像摘要
    filename = binfo.get('filename', 'N/A')
    fmt = binfo.get('format', 'N/A')
    arch = binfo.get('arch', 'N/A')
    bits = binfo.get('bits', 'N/A')
    size = binfo.get('size', 0)
    protections = binfo.get('protections', {})
    imports = binfo.get('imports', {})
    dangerous = imports.get('dangerous_functions', [])

    print(f'  文件名:     {filename}')
    print(f'  格式:       {fmt}')
    print(f'  架构:       {arch} ({bits}-bit)')
    print(f'  大小:       {size} bytes')
    print(f'  保护状态:   NX={protections.get("nx", "?")} '
          f'PIE={protections.get("pie", "?")} '
          f'Canary={protections.get("canary", "?")}')
    if dangerous:
        print(f'  危险函数:   {", ".join(dangerous[:8])}')
    else:
        print('  危险函数:   无')


def _print_findings(result):
    # 输出规则检测 + LLM 研判结果摘要
    decomp = result.get('decomp_analysis', [])
    total_vulns = result.get('total_vulns', 0)
    reports = result.get('reports', {})

    print(f'  分析函数数: {len(decomp)}')
    print(f'  检出漏洞数: {total_vulns}')

    # 按类型聚合, 取前 5 种展示
    type_map = {}
    for r in decomp:
        analysis = r.get('analysis', r)
        for v in analysis.get('vulnerabilities', []):
            vtype = v.get('type', 'unknown')
            type_map[vtype] = type_map.get(vtype, 0) + 1

    if type_map:
        print('  漏洞类型分布 (前5):')
        for vtype, count in sorted(type_map.items(),
                                   key=lambda x: -x[1])[:5]:
            print(f'    {vtype}: {count}')

    # 报告文件路径
    if reports:
        print('  生成报告:')
        for fmt, path in reports.items():
            print(f'    [{fmt}] {path}')

    # LLM 研判摘要
    ai = result.get('ai_analysis')
    if ai:
        sim = ai.get('simulation', True)
        findings = ai.get('findings', [])
        print(f'  LLM 研判:   simulation={sim}, findings={len(findings)}')
    else:
        print('  LLM 研判:   未启用')


def run_demo(sample_path, output_dir=None):
    # 执行单样本完整流程
    if not os.path.isfile(sample_path):
        print(f'错误: 样本文件不存在: {sample_path}')
        sys.exit(1)

    total_start = time.time()

    # 阶段 1: 静态画像 (pipeline 内部自动完成 binary_info 采集)
    _print_stage('阶段 1/4: 静态画像')
    t0 = time.time()
    # pipeline 内部调用 get_binary_info 完成画像, 此处仅做文件校验
    stat = os.stat(sample_path)
    print(f'  样本路径:   {sample_path}')
    print(f'  文件大小:   {stat.st_size} bytes')
    _print_stage('静态画像完成', time.time() - t0)

    # 阶段 2-4: 规则检测 + LLM 研判 + 报告生成 (pipeline 单次调用)
    _print_stage('阶段 2-4: 规则检测 -> LLM 研判 -> 报告生成')
    t1 = time.time()
    try:
        result = run_pipeline(
            binary_path=sample_path,
            output_format='markdown',
            output_dir=output_dir,
        )
    except Exception as exc:
        print(f'错误: 流水线执行失败: {exc}')
        sys.exit(1)
    elapsed_pipeline = time.time() - t1

    # 输出静态画像详情
    binfo = result.get('binary_info', {})
    _print_stage('静态画像详情')
    _print_binary_info(binfo)

    # 输出检测结果
    _print_stage('检测结果')
    _print_findings(result)

    # 总结
    total_elapsed = time.time() - total_start
    _print_stage('演示完成')
    print(f'  流水线耗时:   {elapsed_pipeline:.2f}s')
    print(f'  总耗时:       {total_elapsed:.2f}s')

    # 输出 JSON 摘要到 stdout 供后续解析
    summary = {
        'sample_path': sample_path,
        'binary_info': {
            'filename': binfo.get('filename', 'N/A'),
            'format': binfo.get('format', 'N/A'),
            'arch': binfo.get('arch', 'N/A'),
            'bits': binfo.get('bits', 'N/A'),
        },
        'total_vulns': result.get('total_vulns', 0),
        'reports': result.get('reports', {}),
        'elapsed': result.get('elapsed', 0),
    }
    print(f'\n--- JSON 摘要 ---')
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    return result


def main():
    parser = argparse.ArgumentParser(
        description='BinMind 演示工具 — 单样本全流程展示')
    parser.add_argument(
        'sample', help='样本二进制文件路径')
    parser.add_argument(
        '--output-dir', default=None,
        help='报告输出目录 (默认由 pipeline 决定)')
    args = parser.parse_args()

    run_demo(args.sample, output_dir=args.output_dir)


if __name__ == '__main__':
    main()
