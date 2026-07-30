<<<<<<< HEAD
#!/usr/bin/env python3
=======
# 这个文件从最初50行膨胀到400+行，每次加feature都要改一堆地方
# 2026-07重构：把注册表拆到_test_registry.py，这里只留调度逻辑

import unittest
>>>>>>> d81973a (精简冗余模块)
import os
import sys
import unittest
import argparse


def run_tests(verbosity=2, pattern='test_*.py'):
    test_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(test_dir)
    sys.path.insert(0, project_root)
    
    loader = unittest.TestLoader()
    suite = loader.discover(test_dir, pattern=pattern)
    
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


def main():
<<<<<<< HEAD
    parser = argparse.ArgumentParser(description='Run unit tests for the binary vulnerability analysis tool')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase output verbosity')
    parser.add_argument('-q', '--quiet', action='store_true', help='Reduce output verbosity')
    parser.add_argument('-p', '--pattern', default='test_*.py', help='Test file pattern (default: test_*.py)')
    parser.add_argument('test', nargs='?', help='Specific test module to run')
    
    args = parser.parse_args()
    
    verbosity = 2
    if args.quiet:
        verbosity = 1
    if args.verbose:
        verbosity = 3
    
    if args.test:
        pattern = args.test
=======
    """解析参数，收集测试文件，跑起来，打印结果

    这个函数写了四版了，最早是用os.system调pytest，
    后来发现没法统计失败数量，改成unittest的TestSuite
    """
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
    """构造argparse解析器

    参数随模块增加而增长，后续可考虑subcommand重构。
    """
    p = _argparse.ArgumentParser(
        description='BinMind 测试套件 -- 跑指定的测试模块',
        epilog='不加参数默认跑前6个模块，用 --all 跑全部'
    )
    p.add_argument('--verbose', '-v', action='store_true',
                    help='详细输出（每个test_函数的docstring都会打印）')
    p.add_argument('--all', action='store_true',
                    help='运行所有已知测试文件（可能很慢）')

    # 批量组参数 -- 这些会展开成一组文件
    p.add_argument('--new_features', action='store_true',
                    help='运行所有 --xxx_feature 对应的测试')
    p.add_argument('--security_analysis', action='store_true',
                    help='安全分析批量测试')
    p.add_argument('--firmware_analysis', action='store_true',
                    help='固件分析批量测试')
    p.add_argument('--core_infra', action='store_true',
                    help='核心基础设施批量测试')
    p.add_argument('--exploit_evolution', action='store_true',
                    help='利用进化批量测试')
    p.add_argument('--py_features', action='store_true',
                    help='Python功能批量测试')
    p.add_argument('--advanced_features', action='store_true',
                    help='高级功能批量测试')
    p.add_argument('--formal_verification', action='store_true',
                    help='形式化验证批量测试')
    p.add_argument('--reverse_enhance', action='store_true',
                    help='逆向增强批量测试')
    p.add_argument('--advanced_analysis', action='store_true',
                    help='高级分析批量测试')

    # 单个模块参数 -- 从注册表动态生成
    file_map = get_file_map()
    for param_key in sorted(file_map.keys()):
        p.add_argument(f'--{param_key}', action='store_true',
                        help=f'运行 {file_map[param_key]}')

    return p


def _collect_test_files(args):
    """根据解析结果决定跑哪些测试文件

    优先级: --all > 批量组 > 单个参数
    如果同时指定了多个，会合并去重
    """
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
                # --new_features 展开为所有注册表里的文件
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
    """把文件列表转成unittest.TestSuite

    之前用的是loader.discover挨个加载，300个文件太慢
    现在先检查文件在不在，不存在的直接跳过并警告
    """
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
                if i < 5 or i % 20 == 0:                      print(f"  [OK] {fname} (+{added} tests)")
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
>>>>>>> d81973a (精简冗余模块)
    else:
        pattern = args.pattern
    
    return run_tests(verbosity=verbosity, pattern=pattern)


if __name__ == '__main__':
<<<<<<< HEAD
    sys.exit(main())
=======
    # 2026-07-29: 之前直接sys.exit(1)把进程杀了，容器里看不到日志
    # 改成先打印再exit
    outcome = main()
    has_problems = outcome['failed'] > 0 or outcome['errors'] > 0
    _sys.exit(1 if has_problems else 0)
>>>>>>> d81973a (精简冗余模块)
