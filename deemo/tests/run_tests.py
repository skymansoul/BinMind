#!/usr/bin/env python3
# 注册表拆到_test_registry.py, 这里只留调度逻辑

import os
import sys
import unittest
import argparse as _argparse

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def get_default_files():
    """返回默认测试文件列表 — 从注册表获取，降级时返回硬编码列表"""
    try:
        from _test_registry import get_file_map, get_group
        return list(get_file_map().values())
    except ImportError:
        return ['test_config.py', 'test_binary_info.py', 'test_anti_analysis.py',
                'test_binary_rewriter.py', 'test_cfi_violation_checker.py',
                'test_code_signing.py']


def get_file_map():
    try:
        from _test_registry import get_file_map as _gfm
        return _gfm()
    except ImportError:
        return {}


def get_group(name):
    try:
        from _test_registry import get_group as _gg
        return _gg(name)
    except ImportError:
        return []


def main():
    """解析参数，收集测试文件，跑起来，打印结果"""
    parser = _build_arg_parser()
    args = parser.parse_args()

    selected = _collect_test_files(args)
    if not selected:
        all_defaults = get_default_files()
        selected = all_defaults[:6] if len(all_defaults) >= 6 else all_defaults
        print("[WARN] 没有通过参数指定测试，使用默认前6个文件")

    suite = _build_suite(selected)

    verbosity = 2 if args.verbose else 1
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)

    total = result.testsRun
    n_fail = len(result.failures)
    n_err = len(result.errors)
    n_skip = len(result.skipped)

    _print_summary(total, n_fail, n_err, n_skip)

    return {
        'passed': total - n_fail - n_err,
        'failed': n_fail,
        'errors': n_err,
    }


def _build_arg_parser():
    """构造argparse解析器"""
    p = _argparse.ArgumentParser(
        description='BinMind 测试套件 -- 跑指定的测试模块',
        epilog='不加参数默认跑前6个模块，用 --all 跑全部'
    )
    p.add_argument('--verbose', '-v', action='store_true',
                   help='详细输出')
    p.add_argument('--all', action='store_true',
                   help='运行所有已知测试文件（可能很慢）')

    # 批量组参数
    p.add_argument('--new_features', action='store_true', help='运行所有 --xxx_feature 对应的测试')
    p.add_argument('--security_analysis', action='store_true', help='安全分析批量测试')
    p.add_argument('--firmware_analysis', action='store_true', help='固件分析批量测试')
    p.add_argument('--core_infra', action='store_true', help='核心基础设施批量测试')
    p.add_argument('--exploit_evolution', action='store_true', help='利用进化批量测试')
    p.add_argument('--py_features', action='store_true', help='Python功能批量测试')
    p.add_argument('--advanced_features', action='store_true', help='高级功能批量测试')
    p.add_argument('--formal_verification', action='store_true', help='形式化验证批量测试')
    p.add_argument('--reverse_enhance', action='store_true', help='逆向增强批量测试')
    p.add_argument('--advanced_analysis', action='store_true', help='高级分析批量测试')

    # 单个模块参数 — 从注册表动态生成
    file_map = get_file_map()
    for param_key in sorted(file_map.keys()):
        p.add_argument(f'--{param_key}', action='store_true',
                       help=f'运行 {file_map[param_key]}')

    return p


def _collect_test_files(args):
    """根据解析结果决定跑哪些测试文件 — 优先级: --all > 批量组 > 单个参数"""
    out = []

    if args.all:
        return list(get_default_files())

    group_names = [
        'new_features', 'security_analysis', 'firmware_analysis',
        'core_infra', 'exploit_evolution', 'py_features',
        'advanced_features', 'formal_verification',
        'reverse_enhance', 'advanced_analysis',
    ]

    got_any = False
    for g_name in group_names:
        if getattr(args, g_name, False):
            if g_name == 'new_features':
                fmap = get_file_map()
                for fname in fmap.values():
                    if fname not in out:
                        out.append(fname)
            else:
                group_files = get_group(g_name)
                for f in group_files:
                    if f not in out:
                        out.append(f)
            got_any = True

    fmap = get_file_map()
    for param_key, fname in fmap.items():
        if getattr(args, param_key, False):
            if fname not in out:
                out.append(fname)
            got_any = True

    if got_any:
        return out

    return []


def _build_suite(file_list):
    """把文件列表转成unittest.TestSuite"""
    if not file_list or len(file_list) == 0:
        return unittest.TestSuite()

    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    n_loaded = 0
    n_missed = 0

    for i, fname in enumerate(file_list):
        fpath = os.path.join(_THIS_DIR, fname)
        if not os.path.exists(fpath):
            print(f"  [SKIP] {fname} -- 文件不存在")
            n_missed += 1
            continue

        try:
            tests = loader.discover(_THIS_DIR, pattern=fname)
            count_before = suite.countTestCases()
            suite.addTests(tests)
            added = suite.countTestCases() - count_before
            if added > 0:
                n_loaded += 1
                if i < 5 or i % 20 == 0:
                    print(f"  [OK] {fname} (+{added} tests)")
        except Exception as e:
            print(f"  [FAIL] {fname} 加载异常: {e}")
            continue

    print(f"\n共加载 {n_loaded} 个文件, 跳过 {n_missed} 个不存在")
    return suite


def _print_summary(total, n_fail, n_err, n_skip):
    """打印测试摘要"""
    print("")
    print("=" * 54)
    print("  测试完成")
    print("=" * 54)
    print(f"  总计: {total}  |  失败: {n_fail}  |  错误: {n_err}  |  跳过: {n_skip}")
    if n_fail == 0 and n_err == 0:
        print("  状态: PASS")


if __name__ == '__main__':
    import sys as _sys
    outcome = main()
    has_problems = outcome['failed'] > 0 or outcome['errors'] > 0
    _sys.exit(1 if has_problems else 0)
