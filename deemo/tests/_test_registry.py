
# 从run_tests.py拆分出来的注册表，集中管理测试文件映射
# key名与run_tests.py的参数联动

import os as _os
import sys as _sys

# 通过get_xxx()访问以保持封装
# 2026-06重构，避免直接暴露内部数据结构
_registry_cache = None  # lazy init


def _build_file_map():
    """构建测试名 -> 文件名的哈希表，O(1)查找

    O(1)查找，替代之前的if/elif链
    """
    # key: argparse的--参数名, value: 对应的test_文件
    out = {}

    # batch 1: 安全评估、隐私保护、硬件安全
    out['attack_surface'] = 'test_attack_surface.py'
    out['poc_generator'] = 'test_poc_generator.py'
    out['timing_side_channel'] = 'test_timing_side_channel.py'
    out['pii_scanner'] = 'test_pii_scanner.py'
    out['enclave_analyzer'] = 'test_enclave_analyzer.py'
    out['ota_diff'] = 'test_ota_diff_analyzer.py'

    # batch 2: 第二轮新增
    out['info_leak'] = 'test_info_leak_analyzer.py'
    out['code_clone'] = 'test_code_clone_detector.py'
    out['shellcode_encoder'] = 'test_shellcode_encoder.py'
    out['call_graph'] = 'test_call_graph_enhancer.py'
    out['func_summarizer'] = 'test_function_summarizer.py'
    out['stack_pivot'] = 'test_stack_pivot.py'

    # batch 3: 第三轮
    out['reverse_report'] = 'test_reverse_report.py'
    out['string_decoder'] = 'test_string_decoder.py'
    out['deadlock_detector'] = 'test_deadlock_detector.py'
    out['config_extractor'] = 'test_config_extractor.py'
    out['corruption_classifier'] = 'test_corruption_classifier.py'
    out['code_visualizer'] = 'test_code_visualizer.py'

    # batch 4: 利用验证、补丁、威胁情报
    out['exploit_verifier'] = 'test_exploit_verifier.py'
    out['patch_suggestion'] = 'test_patch_suggestion.py'
    out['threat_intel'] = 'test_threat_intel.py'

    # batch 5: 安全分析 (eBPF, 漏洞传播, 密码误用等)
    out['ebpf_analyzer'] = 'test_ebpf_analyzer.py'
    out['vuln_propagation'] = 'test_vuln_propagation.py'
    out['crypto_misuse'] = 'test_crypto_misuse.py'
    out['dse_bypass'] = 'test_dse_bypass.py'
    out['memory_manipulation'] = 'test_memory_manipulation.py'
    out['traffic_replayer'] = 'test_traffic_replayer.py'

    # batch 6: 固件与嵌入式
    out['mmio_responder'] = 'test_mmio_responder.py'
    out['interrupt_cfg'] = 'test_interrupt_aware_cfg.py'
    out['sdr_analyzer'] = 'test_sdr_binary_analyzer.py'
    out['can_anomaly'] = 'test_can_anomaly_injector.py'

    # batch 7: 核心基础设施
    out['ir_lifter'] = 'test_ir_lifter.py'
    out['semantic_diff'] = 'test_semantic_diff.py'
    out['hw_trace'] = 'test_hw_trace_analyzer.py'
    out['protocol_infer'] = 'test_protocol_infer.py'

    # batch 8: 利用自动化深度进化
    out['algebraic_heap'] = 'test_algebraic_heap_solver.py'
    out['gadget_composer'] = 'test_gadget_composer.py'
    out['side_channel_validator'] = 'test_microarch_side_channel_validator.py'
    out['exploit_adaptor_dynamic'] = 'test_exploit_adaptor_dynamic.py'

    # batch 9: Python相关功能
    out['pyinstaller_unpacker'] = 'test_pyinstaller_unpacker.py'
    out['behavior_tracer'] = 'test_behavior_tracer.py'
    out['pseudocode_explainer'] = 'test_pseudocode_explainer.py'
    out['k8s_scanner'] = 'test_k8s_scanner.py'
    out['nuclei_generator'] = 'test_nuclei_generator.py'
    out['memory_forensics'] = 'test_memory_forensics.py'

    # batch 10: ATT&CK、数字孪生、取证
    out['attack_to_exploit'] = 'test_attack_to_exploit.py'
    out['digital_twin'] = 'test_digital_twin_risk.py'
    out['forensic_recorder'] = 'test_forensic_path_recorder.py'
    out['exploit_video'] = 'test_exploit_video_renderer.py'

    # batch 11: 形式化验证
    out['contract_verifier'] = 'test_binary_contract_verifier.py'
    out['information_flow'] = 'test_information_flow_verifier.py'
    out['protocol_model'] = 'test_protocol_model_checker.py'

    # batch 12: 深度程序理解与逆向增强 (10项)
    out['type_inferrer'] = 'test_type_inferrer.py'
    out['dynamic_struct_prober'] = 'test_dynamic_struct_prober.py'
    out['precise_vtable'] = 'test_precise_vtable_recovery.py'
    out['crypto_param_extractor'] = 'test_crypto_param_extractor.py'
    out['vm_unvirtualizer'] = 'test_vm_unvirtualizer.py'
    out['string_unobfuscator'] = 'test_string_unobfuscator.py'
    out['memory_reconstructor'] = 'test_memory_object_reconstructor.py'
    out['yara_auto_gen'] = 'test_yara_auto_gen.py'
    out['decompiler_enhancements'] = 'test_decompiler_enhancements.py'
    out['auto_patcher'] = 'test_auto_patcher.py'

    # batch 13: 高级分析功能 (last batch from the original)
    out['exploit_strategy'] = 'test_exploit_strategy.py'
    out['cpp_vtbl_recovery'] = 'test_cpp_vtbl_recovery.py'
    out['bypass_advisor'] = 'test_bypass_advisor.py'
    out['test_generator'] = 'test_test_generator.py'
    out['incremental_analysis'] = 'test_incremental_analysis.py'
    out['function_boundary'] = 'test_function_boundary.py'

    return out


def _build_default_list():
    """返回默认跑的测试文件列表（前几个模块的）

    原本在run_tests.py里是个大list，拆出来方便改。
    顺序大致按照依赖关系排列，不确定的就放后面。
    """
    result = [
        # 内核利用与类型混淆
        'test_kernel_exploit_gen.py',
        'test_type_confusion.py',
        'test_exploitdb_matcher.py',
        'test_deep_search.py',
        # 无线与逻辑炸弹
        'test_wireless_analyzer.py',
        'test_logic_bomb_detector.py',
        # SEH与IPC
        'test_seh_analyzer.py',
        'test_ipc_analyzer.py',
        'test_debug_info.py',
        'test_embedded_script_extractor.py',
        # syscall与结构
        'test_syscall_classifier.py',
        'test_struct_recovery.py',
        'test_vmi_analyzer.py',
        # 文档化与签名
        'test_binary_documenter.py',
        'test_code_signing.py',
        # 反虚拟机与重打包
        'test_anti_vm_bypass.py',
        'test_repack_detector.py',
        # ROP与管理代码
        'test_rop_grader.py',
        'test_managed_code_analyzer.py',
        # sandbox与patch diff
        'test_sandbox_policy_gen.py',
        'test_patch_diff_locator.py',
        # 并发与利用转译
        'test_concurrency_fuzzer.py',
        'test_exploit_transpiler.py',
        # 恶意软件聚类与堆风水
        'test_malware_clustering.py',
        'test_heap_feng_shui.py',
        # DLL劫持与安全启动
        'test_dll_hijacking.py',
        'test_secure_boot_checker.py',
        # 侧信道与重编译器
        'test_pmc_side_channel.py',
        'test_recompiler_check.py',
        'test_steganography_detector.py',
        # 第一批追加的功能测试
        'test_deobfuscator.py',
        'test_differential_tester.py',
        'test_ics_protocol_analyzer.py',
        'test_semantic_search.py',
        'test_exploit_adaptor.py',
        'test_binary_lifecycle.py',
        # 第二批追加
        'test_info_leak_analyzer.py',
        'test_code_clone_detector.py',
        'test_shellcode_encoder.py',
        'test_call_graph_enhancer.py',
        'test_function_summarizer.py',
        'test_stack_pivot.py',
        # 固件与嵌入式
        'test_mmio_responder.py',
        'test_interrupt_aware_cfg.py',
        'test_sdr_binary_analyzer.py',
        'test_can_anomaly_injector.py',
        # 核心基础设施
        'test_ir_lifter.py',
        'test_semantic_diff.py',
        'test_hw_trace_analyzer.py',
        'test_protocol_infer.py',
        # 利用深度进化
        'test_algebraic_heap_solver.py',
        'test_gadget_composer.py',
        'test_microarch_side_channel_validator.py',
        'test_exploit_adaptor_dynamic.py',
        # Python相关
        'test_pyinstaller_unpacker.py',
        'test_behavior_tracer.py',
        'test_pseudocode_explainer.py',
        'test_k8s_scanner.py',
        'test_nuclei_generator.py',
        'test_memory_forensics.py',
        # ATT&CK与数字孪生
        'test_attack_to_exploit.py',
        'test_digital_twin_risk.py',
        'test_forensic_path_recorder.py',
        'test_exploit_video_renderer.py',
        # 形式化验证
        'test_binary_contract_verifier.py',
        'test_information_flow_verifier.py',
        'test_protocol_model_checker.py',
        # 逆向增强
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
    return result


# 分组定义：用于 --xxx 类批量参数
_groups = {
    'security_analysis': [
        'test_ebpf_analyzer.py', 'test_vuln_propagation.py',
        'test_crypto_misuse.py', 'test_dse_bypass.py',
        'test_memory_manipulation.py', 'test_traffic_replayer.py',
    ],
    'firmware_analysis': [
        'test_mmio_responder.py', 'test_interrupt_aware_cfg.py',
        'test_sdr_binary_analyzer.py', 'test_can_anomaly_injector.py',
    ],
    'core_infra': [
        'test_ir_lifter.py', 'test_semantic_diff.py',
        'test_hw_trace_analyzer.py', 'test_protocol_infer.py',
    ],
    'exploit_evolution': [
        'test_algebraic_heap_solver.py', 'test_gadget_composer.py',
        'test_microarch_side_channel_validator.py',
        'test_exploit_adaptor_dynamic.py',
    ],
    'py_features': [
        'test_pyinstaller_unpacker.py', 'test_behavior_tracer.py',
        'test_pseudocode_explainer.py', 'test_k8s_scanner.py',
        'test_nuclei_generator.py', 'test_memory_forensics.py',
    ],
    'advanced_features': [
        'test_attack_to_exploit.py', 'test_digital_twin_risk.py',
        'test_forensic_path_recorder.py', 'test_exploit_video_renderer.py',
    ],
    'formal_verification': [
        'test_binary_contract_verifier.py',
        'test_information_flow_verifier.py',
        'test_protocol_model_checker.py',
    ],
    'reverse_enhance': [
        'test_type_inferrer.py', 'test_dynamic_struct_prober.py',
        'test_precise_vtable_recovery.py', 'test_crypto_param_extractor.py',
        'test_vm_unvirtualizer.py', 'test_string_unobfuscator.py',
        'test_memory_object_reconstructor.py', 'test_yara_auto_gen.py',
        'test_decompiler_enhancements.py', 'test_auto_patcher.py',
    ],
    'advanced_analysis': [
        'test_exploit_strategy.py', 'test_cpp_vtbl_recovery.py',
        'test_bypass_advisor.py', 'test_test_generator.py',
        'test_incremental_analysis.py', 'test_function_boundary.py',
    ],
}


# 公开API

def get_file_map():
    """返回 {参数名: 文件名} 映射表（懒初始化）"""
    global _registry_cache
    # 双重检查，虽然单线程环境里没意义，但习惯了
    if _registry_cache is None:
        _registry_cache = _build_file_map()
    return _registry_cache


def get_default_files():
    # 设计改进候选——可读性提升目标
    """返回默认测试文件列表"""
    return _build_default_list()


def get_group(group_name):
    """按组名获取文件列表，不存在返回空list"""
    if not isinstance(group_name, str) or group_name.strip() == '':
        return []
    out = _groups.get(group_name, None)
    if out is None:
        return []
    return list(out)  # 返回副本，防止外部修改
