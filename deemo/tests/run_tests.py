import unittest
import os
import sys
import argparse

def run_selected_tests(test_files, verbose=False):
    """运行指定的测试文件"""
    suite = unittest.TestSuite()
    
    for test_file in test_files:
        test_path = os.path.join(os.path.dirname(__file__), test_file)
        if os.path.exists(test_path):
            try:
                loader = unittest.TestLoader()
                tests = loader.discover(os.path.dirname(__file__), pattern=test_file)
                suite.addTests(tests)
                print(f"加载测试文件: {test_file}")
            except Exception as e:
                print(f"加载测试文件失败 {test_file}: {e}")
        else:
            print(f"测试文件不存在: {test_file}")
    
    runner = unittest.TextTestRunner(verbosity=2 if verbose else 1)
    result = runner.run(suite)
    
    return {
        'passed': result.testsRun - len(result.failures) - len(result.errors),
        'failed': len(result.failures),
        'errors': len(result.errors),
        'total': result.testsRun
    }

def main():
    parser = argparse.ArgumentParser(description='运行测试套件')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    parser.add_argument('--all', action='store_true', help='运行所有测试')
    
    # 新增的六个功能测试参数（安全评估、隐私保护、硬件安全）
    parser.add_argument('--attack_surface', action='store_true', help='运行攻击面识别与风险排序测试')
    parser.add_argument('--poc_generator', action='store_true', help='运行漏洞验证PoC生成测试')
    parser.add_argument('--timing_side_channel', action='store_true', help='运行时间侧信道检测测试')
    parser.add_argument('--pii_scanner', action='store_true', help='运行PII与敏感数据泄露扫描测试')
    parser.add_argument('--enclave_analyzer', action='store_true', help='运行安全飞地二进制分析测试')
    parser.add_argument('--ota_diff', action='store_true', help='运行固件OTA差分更新分析测试')
    parser.add_argument('--new_features', action='store_true', help='运行所有新增功能测试')
    
    # ==================== 新增六项技术功能测试参数（第三轮）====================
    parser.add_argument('--reverse_report', action='store_true', help='运行LLM逆向报告生成测试')
    parser.add_argument('--string_decoder', action='store_true', help='运行字符串解码与解混淆测试')
    parser.add_argument('--deadlock_detector', action='store_true', help='运行多线程死锁检测测试')
    parser.add_argument('--config_extractor', action='store_true', help='运行配置凭据提取测试')
    parser.add_argument('--corruption_classifier', action='store_true', help='运行内存损坏分类测试')
    parser.add_argument('--code_visualizer', action='store_true', help='运行代码可视化测试')
    
    args = parser.parse_args()
    
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    TEST_FILES_MAP = {
        'attack_surface': 'test_attack_surface.py',
        'poc_generator': 'test_poc_generator.py',
        'timing_side_channel': 'test_timing_side_channel.py',
        'pii_scanner': 'test_pii_scanner.py',
        'enclave_analyzer': 'test_enclave_analyzer.py',
        'ota_diff': 'test_ota_diff_analyzer.py',
        # 新增六个功能测试
        'info_leak': 'test_info_leak_analyzer.py',
        'code_clone': 'test_code_clone_detector.py',
        'shellcode_encoder': 'test_shellcode_encoder.py',
        'call_graph': 'test_call_graph_enhancer.py',
        'func_summarizer': 'test_function_summarizer.py',
        'stack_pivot': 'test_stack_pivot.py',
        # ==================== 新增六项技术功能测试（第三轮）====================
        'reverse_report': 'test_reverse_report.py',
        'string_decoder': 'test_string_decoder.py',
        'deadlock_detector': 'test_deadlock_detector.py',
        'config_extractor': 'test_config_extractor.py',
        'corruption_classifier': 'test_corruption_classifier.py',
        'code_visualizer': 'test_code_visualizer.py',
    }
    
    test_files = [
        'test_kernel_exploit_gen.py',
        'test_type_confusion.py',
        'test_exploitdb_matcher.py',
        'test_deep_search.py',
        'test_wireless_analyzer.py',
        'test_logic_bomb_detector.py',
        'test_seh_analyzer.py',
        'test_ipc_analyzer.py',
        'test_debug_info.py',
        'test_embedded_script_extractor.py',
        'test_syscall_classifier.py',
        'test_struct_recovery.py',
        'test_vmi_analyzer.py',
        'test_binary_documenter.py',
        'test_code_signing.py',
        'test_anti_vm_bypass.py',
        'test_repack_detector.py',
        'test_rop_grader.py',
        'test_managed_code_analyzer.py',
        'test_sandbox_policy_gen.py',
        'test_patch_diff_locator.py',
        'test_concurrency_fuzzer.py',
        'test_exploit_transpiler.py',
        'test_malware_clustering.py',
        'test_heap_feng_shui.py',
        'test_dll_hijacking.py',
        'test_secure_boot_checker.py',
        'test_pmc_side_channel.py',
        'test_recompiler_check.py',
        'test_steganography_detector.py',
        # ==================== 新增六项技术功能测试文件 ====================
        # 功能1：函数级自动化去混淆与反混淆验证
        'test_deobfuscator.py',
        # 功能2：基于差异测试的漏洞发现（Differential Fuzzing）
        'test_differential_tester.py',
        # 功能3：工业控制系统协议解析与漏洞挖掘
        'test_ics_protocol_analyzer.py',
        # 功能4：二进制语义漏洞搜索引擎
        'test_semantic_search.py',
        # 功能5：基于AI的利用脚本自适应修复与迁移
        'test_exploit_adaptor.py',
        # 功能6：二进制生命周期管理与分析历史趋势跟踪
        'test_binary_lifecycle.py',
        # ==================== 新增六项技术功能测试（第二轮）====================
        # 功能1：自动化信息泄露发现与量化评估
        'test_info_leak_analyzer.py',
        # 功能2：二进制代码克隆检测与复用分析
        'test_code_clone_detector.py',
        # 功能3：Shellcode自适应编码与坏字符处理
        'test_shellcode_encoder.py',
        # 功能4：调用图增强与函数指针表恢复
        'test_call_graph_enhancer.py',
        # 功能5：基于模拟执行的函数摘要自动生成
        'test_function_summarizer.py',
        # 功能6：栈迁移与高级ROP组合策略生成
        'test_stack_pivot.py',
        # ==================== 新增六项技术功能测试（第三轮）====================
        # 功能1：基于LLM的自动化深度逆向分析报告生成
        'test_reverse_report.py',
        # 功能2：二进制字符串自动解码与解混淆
        'test_string_decoder.py',
        # 功能3：多线程死锁自动化检测
        'test_deadlock_detector.py',
        # 功能4：二进制内嵌配置与凭据自动提取
        'test_config_extractor.py',
        # 功能5：内存损坏模式自动分类
        'test_corruption_classifier.py',
        # 功能6：反编译代码自动生成流程图与结构图
        'test_code_visualizer.py',
    ]
    
    selected_tests = []
    if args.all:
        selected_tests = test_files
    elif args.new_features:
        selected_tests = list(TEST_FILES_MAP.values())
    else:
        for key, test_file in TEST_FILES_MAP.items():
            if getattr(args, key):
                selected_tests.append(test_file)
    
    if not selected_tests:
        selected_tests = test_files[:6]
    
    suite = unittest.TestSuite()
    
    for test_file in selected_tests:
        test_path = os.path.join(os.path.dirname(__file__), test_file)
        if os.path.exists(test_path):
            try:
                loader = unittest.TestLoader()
                tests = loader.discover(os.path.dirname(__file__), pattern=test_file)
                suite.addTests(tests)
                print(f"加载测试文件: {test_file}")
            except Exception as e:
                print(f"加载测试文件失败 {test_file}: {e}")
        else:
            print(f"测试文件不存在: {test_file}")
    
    print("\n" + "="*50)
    print("开始运行测试...")
    print("="*50 + "\n")
    
    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(suite)
    
    print("\n" + "="*50)
    print("测试总结")
    print("="*50)
    print(f"运行测试数: {result.testsRun}")
    print(f"失败: {len(result.failures)}")
    print(f"错误: {len(result.errors)}")
    print(f"跳过: {len(result.skipped)}")
    
    if result.failures or result.errors:
        return {'passed': result.testsRun - len(result.failures) - len(result.errors), 
                'failed': len(result.failures), 'errors': len(result.errors)}
    else:
        print("所有测试通过!")
        return {'passed': result.testsRun, 'failed': 0, 'errors': 0}

if __name__ == '__main__':
    results = main()
    sys.exit(1 if results['failed'] > 0 or results['errors'] > 0 else 0)
