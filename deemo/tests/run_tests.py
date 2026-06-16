import unittest
import os
import sys
import argparse

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
    
    # ==================== 新增三项功能测试参数（漏洞利用验证、补丁建议、威胁情报）====================
    parser.add_argument('--exploit_verifier', action='store_true', help='运行漏洞利用验证器测试')
    parser.add_argument('--patch_suggestion', action='store_true', help='运行智能补丁建议测试')
    parser.add_argument('--threat_intel', action='store_true', help='运行威胁情报关联测试')
    
    # ==================== 新增六项技术功能测试参数（eBPF分析、漏洞传播、密码误用、DSE绕过、内存注入、流量重放）====================
    parser.add_argument('--ebpf_analyzer', action='store_true', help='运行eBPF程序安全分析测试')
    parser.add_argument('--vuln_propagation', action='store_true', help='运行漏洞传播路径分析测试')
    parser.add_argument('--crypto_misuse', action='store_true', help='运行密码误用检测测试')
    parser.add_argument('--dse_bypass', action='store_true', help='运行DSE绕过检测测试')
    parser.add_argument('--memory_manipulation', action='store_true', help='运行内存注入检测测试')
    parser.add_argument('--traffic_replayer', action='store_true', help='运行网络流量重放测试')
    parser.add_argument('--security_analysis', action='store_true', help='运行所有安全分析功能测试')
    
    # ==================== 新增四项固件与嵌入式分析模块测试 ====================
    parser.add_argument('--mmio_responder', action='store_true', help='运行MMIO响应器测试')
    parser.add_argument('--interrupt_cfg', action='store_true', help='运行中断驱动控制流恢复测试')
    parser.add_argument('--sdr_analyzer', action='store_true', help='运行SDR信号处理二进制分析测试')
    parser.add_argument('--can_anomaly', action='store_true', help='运行CAN异常注入引擎测试')
    parser.add_argument('--firmware_analysis', action='store_true', help='运行所有固件与嵌入式分析测试')
    
    # ==================== 新增四项核心基础设施模块测试 ====================
    parser.add_argument('--ir_lifter', action='store_true', help='运行IR提升框架测试')
    parser.add_argument('--semantic_diff', action='store_true', help='运行语义差异分析测试')
    parser.add_argument('--hw_trace', action='store_true', help='运行硬件跟踪分析测试')
    parser.add_argument('--protocol_infer', action='store_true', help='运行协议逆向引擎测试')
    parser.add_argument('--core_infra', action='store_true', help='运行所有核心基础设施测试')
    
    # ==================== 新增四项利用自动化深度进化模块测试 ====================
    parser.add_argument('--algebraic_heap', action='store_true', help='运行内存布局代数化求解器测试')
    parser.add_argument('--gadget_composer', action='store_true', help='运行多类型Gadget组合器测试')
    parser.add_argument('--side_channel_validator', action='store_true', help='运行微架构侧信道验证测试')
    parser.add_argument('--exploit_adaptor_dynamic', action='store_true', help='运行多版本利用自适应测试')
    parser.add_argument('--exploit_evolution', action='store_true', help='运行所有利用自动化深度进化测试')
    
    # ==================== 新增六项技术功能测试参数（PyInstaller解包、行为追踪、伪代码解释、K8s扫描、Nuclei生成、内存取证）====================
    parser.add_argument('--pyinstaller_unpacker', action='store_true', help='运行PyInstaller/Nuitka解包测试')
    parser.add_argument('--behavior_tracer', action='store_true', help='运行行为追踪测试')
    parser.add_argument('--pseudocode_explainer', action='store_true', help='运行伪代码解释测试')
    parser.add_argument('--k8s_scanner', action='store_true', help='运行K8s扫描测试')
    parser.add_argument('--nuclei_generator', action='store_true', help='运行Nuclei模板生成测试')
    parser.add_argument('--memory_forensics', action='store_true', help='运行内存取证测试')
    parser.add_argument('--py_features', action='store_true', help='运行所有Python相关功能测试')
    
    # ==================== 新增四项ATT&CK映射、数字孪生、取证记录、视频渲染模块测试 ====================
    parser.add_argument('--attack_to_exploit', action='store_true', help='运行ATT&CK技术映射测试')
    parser.add_argument('--digital_twin', action='store_true', help='运行数字孪生风险评估测试')
    parser.add_argument('--forensic_recorder', action='store_true', help='运行取证记录测试')
    parser.add_argument('--exploit_video', action='store_true', help='运行利用视频渲染测试')
    parser.add_argument('--advanced_features', action='store_true', help='运行所有高级功能测试')
    
    # ==================== 新增三项形式化验证模块测试 ====================
    parser.add_argument('--contract_verifier', action='store_true', help='运行合约验证测试')
    parser.add_argument('--information_flow', action='store_true', help='运行信息流验证测试')
    parser.add_argument('--protocol_model', action='store_true', help='运行协议模型检查测试')
    parser.add_argument('--formal_verification', action='store_true', help='运行所有形式化验证测试')
    
    # ==================== 新增十项深度程序理解与逆向增强模块测试 ====================
    parser.add_argument('--type_inferrer', action='store_true', help='运行类型推断引擎测试')
    parser.add_argument('--dynamic_struct_prober', action='store_true', help='运行动态结构体探测测试')
    parser.add_argument('--precise_vtable', action='store_true', help='运行精确虚表恢复测试')
    parser.add_argument('--crypto_param_extractor', action='store_true', help='运行密码学参数提取测试')
    parser.add_argument('--vm_unvirtualizer', action='store_true', help='运行虚拟机反混淆测试')
    parser.add_argument('--string_unobfuscator', action='store_true', help='运行字符串反混淆测试')
    parser.add_argument('--memory_reconstructor', action='store_true', help='运行内存对象重构测试')
    parser.add_argument('--yara_auto_gen', action='store_true', help='运行YARA规则自动生成测试')
    parser.add_argument('--decompiler_enhancements', action='store_true', help='运行反编译增强测试')
    parser.add_argument('--auto_patcher', action='store_true', help='运行自动补丁测试')
    parser.add_argument('--reverse_enhance', action='store_true', help='运行所有深度程序理解与逆向增强测试')
    
    # ==================== 新增六项高级分析功能测试（漏洞策略、虚表恢复、绕过策略、测试生成、增量分析、ML边界检测） ====================
    parser.add_argument('--exploit_strategy', action='store_true', help='运行漏洞利用策略推荐测试')
    parser.add_argument('--cpp_vtbl_recovery', action='store_true', help='运行C++虚函数表恢复测试')
    parser.add_argument('--bypass_advisor', action='store_true', help='运行保护机制绕过策略测试')
    parser.add_argument('--test_generator', action='store_true', help='运行二进制测试生成测试')
    parser.add_argument('--incremental_analysis', action='store_true', help='运行增量分析缓存测试')
    parser.add_argument('--function_boundary', action='store_true', help='运行ML函数边界识别测试')
    parser.add_argument('--advanced_analysis', action='store_true', help='运行所有高级分析功能测试')
    
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
        # ==================== 新增三项功能测试（漏洞利用验证、补丁建议、威胁情报）====================
        'exploit_verifier': 'test_exploit_verifier.py',
        'patch_suggestion': 'test_patch_suggestion.py',
        'threat_intel': 'test_threat_intel.py',
        # ==================== 新增六项技术功能测试（eBPF分析、漏洞传播、密码误用、DSE绕过、内存注入、流量重放）====================
        'ebpf_analyzer': 'test_ebpf_analyzer.py',
        'vuln_propagation': 'test_vuln_propagation.py',
        'crypto_misuse': 'test_crypto_misuse.py',
        'dse_bypass': 'test_dse_bypass.py',
        'memory_manipulation': 'test_memory_manipulation.py',
        'traffic_replayer': 'test_traffic_replayer.py',
        # ==================== 新增四项固件与嵌入式分析模块测试 ====================
        'mmio_responder': 'test_mmio_responder.py',
        'interrupt_cfg': 'test_interrupt_aware_cfg.py',
        'sdr_analyzer': 'test_sdr_binary_analyzer.py',
        'can_anomaly': 'test_can_anomaly_injector.py',
        # ==================== 新增四项核心基础设施模块测试 ====================
        'ir_lifter': 'test_ir_lifter.py',
        'semantic_diff': 'test_semantic_diff.py',
        'hw_trace': 'test_hw_trace_analyzer.py',
        'protocol_infer': 'test_protocol_infer.py',
        # ==================== 新增四项利用自动化深度进化模块测试 ====================
        'algebraic_heap': 'test_algebraic_heap_solver.py',
        'gadget_composer': 'test_gadget_composer.py',
        'side_channel_validator': 'test_microarch_side_channel_validator.py',
        'exploit_adaptor_dynamic': 'test_exploit_adaptor_dynamic.py',
        # ==================== 新增六项技术功能测试（PyInstaller解包、行为追踪、伪代码解释、K8s扫描、Nuclei生成、内存取证）====================
        'pyinstaller_unpacker': 'test_pyinstaller_unpacker.py',
        'behavior_tracer': 'test_behavior_tracer.py',
        'pseudocode_explainer': 'test_pseudocode_explainer.py',
        'k8s_scanner': 'test_k8s_scanner.py',
        'nuclei_generator': 'test_nuclei_generator.py',
        'memory_forensics': 'test_memory_forensics.py',
        # ==================== 新增四项ATT&CK映射、数字孪生、取证记录、视频渲染模块测试 ====================
        'attack_to_exploit': 'test_attack_to_exploit.py',
        'digital_twin': 'test_digital_twin_risk.py',
        'forensic_recorder': 'test_forensic_path_recorder.py',
        'exploit_video': 'test_exploit_video_renderer.py',
        # ==================== 新增三项形式化验证模块测试 ====================
        'contract_verifier': 'test_binary_contract_verifier.py',
        'information_flow': 'test_information_flow_verifier.py',
        'protocol_model': 'test_protocol_model_checker.py',
        # ==================== 新增十项深度程序理解与逆向增强模块测试 ====================
        'type_inferrer': 'test_type_inferrer.py',
        'dynamic_struct_prober': 'test_dynamic_struct_prober.py',
        'precise_vtable': 'test_precise_vtable_recovery.py',          # 修复键名
        'crypto_param_extractor': 'test_crypto_param_extractor.py',
        'vm_unvirtualizer': 'test_vm_unvirtualizer.py',
        'string_unobfuscator': 'test_string_unobfuscator.py',
        'memory_reconstructor': 'test_memory_object_reconstructor.py', # 修复键名
        'yara_auto_gen': 'test_yara_auto_gen.py',
        'decompiler_enhancements': 'test_decompiler_enhancements.py',
        'auto_patcher': 'test_auto_patcher.py',
        # ==================== 新增六项高级分析功能测试（漏洞策略、虚表恢复、绕过策略、测试生成、增量分析、ML边界检测） ====================
        'exploit_strategy': 'test_exploit_strategy.py',
        'cpp_vtbl_recovery': 'test_cpp_vtbl_recovery.py',
        'bypass_advisor': 'test_bypass_advisor.py',
        'test_generator': 'test_test_generator.py',
        'incremental_analysis': 'test_incremental_analysis.py',
        'function_boundary': 'test_function_boundary.py',
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
        # ==================== 新增四项固件与嵌入式分析模块测试 ====================
        # 功能1：MMIO与端口I/O自动响应模型
        'test_mmio_responder.py',
        # 功能2：中断驱动的控制流恢复
        'test_interrupt_aware_cfg.py',
        # 功能3：SDR信号处理二进制分析
        'test_sdr_binary_analyzer.py',
        # 功能4：车内网络异常注入引擎
        'test_can_anomaly_injector.py',
        # ==================== 新增四项核心基础设施模块测试 ====================
        # 功能1：二进制到统一IR多级提升框架
        'test_ir_lifter.py',
        # 功能2：跨版本二进制语义差异分析引擎
        'test_semantic_diff.py',
        # 功能3：基于Intel PT/ARM ETM的硬件跟踪分析
        'test_hw_trace_analyzer.py',
        # 功能4：协议逆向工程引擎
        'test_protocol_infer.py',
        # ==================== 新增四项利用自动化深度进化模块测试 ====================
        # 功能1：内存布局代数化描述与求解
        'test_algebraic_heap_solver.py',
        # 功能2：多类型Gadget自动发现与组合
        'test_gadget_composer.py',
        # 功能3：微架构侧信道利用验证
        'test_microarch_side_channel_validator.py',
        # 功能4：多版本利用自适应
        'test_exploit_adaptor_dynamic.py',
        # ==================== 新增六项技术功能测试（PyInstaller解包、行为追踪、伪代码解释、K8s扫描、Nuclei生成、内存取证）====================
        'test_pyinstaller_unpacker.py',
        'test_behavior_tracer.py',
        'test_pseudocode_explainer.py',
        'test_k8s_scanner.py',
        'test_nuclei_generator.py',
        'test_memory_forensics.py',
        # ==================== 新增四项ATT&CK映射、数字孪生、取证记录、视频渲染模块测试 ====================
        'test_attack_to_exploit.py',
        'test_digital_twin_risk.py',
        'test_forensic_path_recorder.py',
        'test_exploit_video_renderer.py',
        # ==================== 新增三项形式化验证模块测试 ====================
        'test_binary_contract_verifier.py',
        'test_information_flow_verifier.py',
        'test_protocol_model_checker.py',
        # ==================== 新增十项深度程序理解与逆向增强模块测试 ====================
        'test_type_inferrer.py',
        'test_dynamic_struct_prober.py',
        'test_precise_vtable_recovery.py',
        'test_crypto_param_extractor.py',
        'test_vm_unvirtualizer.py',
        'test_string_unobfuscator.py',
        'test_memory_object_reconstructor.py',
        'test_yara_auto_gen.py',
        'test_decompiler_enhancements.py',
        'test_auto_patcher.py',
    ]
    
    selected_tests = []
    if args.all:
        selected_tests = test_files
    elif args.new_features:
        selected_tests = list(TEST_FILES_MAP.values())
    elif args.security_analysis:
        selected_tests = [
            'test_ebpf_analyzer.py',
            'test_vuln_propagation.py',
            'test_crypto_misuse.py',
            'test_dse_bypass.py',
            'test_memory_manipulation.py',
            'test_traffic_replayer.py',
        ]
    elif args.firmware_analysis:
        selected_tests = [
            'test_mmio_responder.py',
            'test_interrupt_aware_cfg.py',
            'test_sdr_binary_analyzer.py',
            'test_can_anomaly_injector.py',
        ]
    elif args.core_infra:
        selected_tests = [
            'test_ir_lifter.py',
            'test_semantic_diff.py',
            'test_hw_trace_analyzer.py',
            'test_protocol_infer.py',
        ]
    elif args.exploit_evolution:
        selected_tests = [
            'test_algebraic_heap_solver.py',
            'test_gadget_composer.py',
            'test_microarch_side_channel_validator.py',
            'test_exploit_adaptor_dynamic.py',
        ]
    elif args.py_features:
        selected_tests = [
            'test_pyinstaller_unpacker.py',
            'test_behavior_tracer.py',
            'test_pseudocode_explainer.py',
            'test_k8s_scanner.py',
            'test_nuclei_generator.py',
            'test_memory_forensics.py',
        ]
    elif args.advanced_features:
        selected_tests = [
            'test_attack_to_exploit.py',
            'test_digital_twin_risk.py',
            'test_forensic_path_recorder.py',
            'test_exploit_video_renderer.py',
        ]
    elif args.formal_verification:
        selected_tests = [
            'test_binary_contract_verifier.py',
            'test_information_flow_verifier.py',
            'test_protocol_model_checker.py',
        ]
    elif args.reverse_enhance:
        selected_tests = [
            'test_type_inferrer.py',
            'test_dynamic_struct_prober.py',
            'test_precise_vtable_recovery.py',
            'test_crypto_param_extractor.py',
            'test_vm_unvirtualizer.py',
            'test_string_unobfuscator.py',
            'test_memory_object_reconstructor.py',
            'test_yara_auto_gen.py',
            'test_decompiler_enhancements.py',
            'test_auto_patcher.py',
        ]
    elif args.advanced_analysis:
        selected_tests = [
            'test_exploit_strategy.py',
            'test_cpp_vtbl_recovery.py',
            'test_bypass_advisor.py',
            'test_test_generator.py',
            'test_incremental_analysis.py',
            'test_function_boundary.py',
        ]
    else:
        for key, test_file in TEST_FILES_MAP.items():
            if getattr(args, key, False):
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