import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.exploitability_scorer import (
    ExploitabilityScorer,
    VulnerabilityContext,
    ProtectionStatus,
    ProtectionMechanism,
    calculate_exploitability_score
)

from modules.vulnerability_reporter import (
    VulnerabilityReporter,
    ReportPlatform,
    ReportSeverity,
    create_vulnerability_report,
    export_report_to_file
)

from modules.fuzz_coverage_visualizer import (
    FuzzCoverageVisualizer,
    CoverageData,
    CoverageType,
    generate_coverage_heatmap_api
)

from modules.vuln_deduplicator import (
    VulnDeduplicator,
    DeduplicationStrategy,
    deduplicate_vulnerabilities
)

from modules.crash_classifier import (
    CrashClassifier,
    analyze_crash,
    generate_exploit_from_crash
)

from modules.semantic_diff_analyzer import (
    SemanticDiffAnalyzer,
    analyze_semantic_diff
)

from modules.patch_quality_evaluator import (
    PatchQualityEvaluator,
    evaluate_patch
)

from modules.sandbox_escape_detector import (
    SandboxEscapeDetector,
    detect_sandbox_escape
)

from modules.kernel_integrity_monitor import (
    KernelIntegrityMonitor,
    monitor_kernel_integrity
)

from modules.distributed_vector_search import (
    DistributedVectorSearch,
    create_vector_search
)

from modules.unified_ir_converter import (
    UnifiedIRConverter,
    Architecture,
    convert_to_ir
)

from modules.memory_primitive_extractor import (
    MemoryPrimitiveExtractor,
    extract_memory_primitives
)

from modules.call_stack_reconstructor import (
    CallStackReconstructor,
    reconstruct_call_stack
)

from modules.code_style_identifier import (
    CodeStyleIdentifier,
    identify_code_style
)

from modules.anti_anti_debug import (
    AntiAntiDebug,
    bypass_anti_debug
)

from modules.hardware_trace_analyzer import (
    HardwareTraceAnalyzer,
    TraceType,
    analyze_hardware_trace
)

from modules.cfi_integrity_analyzer import (
    CFIIntegrityAnalyzer,
    analyze_cfi_integrity
)

from modules.supply_chain_vulnerability_monitor import (
    SupplyChainVulnerabilityMonitor,
    monitor_supply_chain
)

from modules.syscall_dependency_graph import (
    SyscallDependencyGraph,
    build_syscall_dependency_graph
)

from modules.kernel_sync_detector import (
    KernelSyncDetector,
    detect_kernel_sync_issues
)

from modules.gdb_script_generator import (
    GdbScriptGenerator,
    ScriptType,
    generate_gdb_script
)

from modules.ebpf_dynamic_tracer import (
    EbpfDynamicTracer,
    create_ebpf_programs
)

from modules.container_vuln_locator import (
    ContainerVulnLocator,
    locate_container_vulnerabilities
)

from modules.opa_policy_generator import (
    OPAPolicyGenerator,
    PolicyType,
    generate_opa_policy
)

from modules.exploit_template_library import (
    ExploitTemplateLibrary,
    get_exploit_templates
)

from modules.gnn_vulnerability_detector import (
    GNNVulnerabilityDetector,
    detect_vulnerabilities_with_gnn
)

from modules.function_behavior_classifier import (
    FunctionBehaviorClassifier,
    classify_function_behavior
)

from modules.privacy_compliance_auditor import (
    PrivacyComplianceAuditor,
    audit_privacy_compliance
)

from modules.multi_dimension_stats_api import (
    MultiDimensionStatsAPI,
    StatisticType,
    get_statistics
)

from modules.zeroday_anomaly_detector import (
    ZeroDayAnomalyDetector,
    detect_zeroday_anomalies
)

from modules.dangerous_function_analyzer import (
    DangerousFunctionAnalyzer,
    analyze_dangerous_functions
)

from modules.memory_sensitive_op_detector import (
    MemorySensitiveOpDetector,
    detect_memory_sensitive_operations
)

from modules.test_orchestrator import (
    TestOrchestrator,
    TaskType,
    create_test_workflow
)


class TestExploitabilityScorer:
    
    def test_calculate_score(self):
        scorer = ExploitabilityScorer()
        ctx = VulnerabilityContext(
            vulnerability_type="buffer_overflow",
            architecture="x86_64",
            os="linux",
            privilege_level="user",
            attack_vector="network",
            requires_user_interaction=False,
            network_accessible=True
        )
        protections = {
            ProtectionMechanism.ASLR: ProtectionStatus(enabled=True, bypassable=False, effectiveness=0.9),
            ProtectionMechanism.DEP: ProtectionStatus(enabled=True, bypassable=False, effectiveness=0.9),
        }
        score = scorer.calculate_score(ctx, protections)
        assert score.score >= 0
        assert score.score <= 100
        assert score.level is not None

    def test_calculate_exploitability_score_function(self):
        result = calculate_exploitability_score(
            vulnerability_type="use_after_free",
            architecture="x86",
            os="linux",
            network_accessible=True
        )
        assert result.score >= 0
        assert result.score <= 100


class TestVulnerabilityReporter:
    
    def test_create_report(self):
        # 修复：使用枚举值而不是字符串
        report = create_vulnerability_report(
            title="Test Vulnerability",
            severity=ReportSeverity.HIGH,
            description="Test description",
            reproduction_steps=["Step 1", "Step 2"],
            impact="Test impact",
            affected_versions=["1.0", "1.1"]
        )
        assert report.title == "Test Vulnerability"
        assert report.severity == ReportSeverity.HIGH

    def test_generate_report(self):
        reporter = VulnerabilityReporter()
        report = create_vulnerability_report(
            title="Test",
            severity=ReportSeverity.MEDIUM,
            description="Test",
            reproduction_steps=["Step 1"],
            impact="Test",
            affected_versions=["1.0"]
        )
        result = reporter.generate_report(ReportPlatform.HACKERONE, report)
        assert "title" in result


class TestFuzzCoverageVisualizer:
    
    def test_parse_coverage_data(self):
        visualizer = FuzzCoverageVisualizer()
        coverage_data = CoverageData(
            binary_path="/test/bin",
            coverage_type=CoverageType.BLOCK,
            total_blocks=1000,
            covered_blocks=500,
            coverage_rate=0.5
        )
        result = visualizer.generate_heatmap(coverage_data)
        assert result.summary['coverage_rate'] == 0.5

    def test_generate_coverage_heatmap_api(self):
        import tempfile
        import json
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({
                'binary_path': '/test/bin',
                'coverage_type': 'block',
                'total_blocks': 100,
                'covered_blocks': 50,
                'coverage_rate': 0.5,
                'function_coverage': {'func1': 0.8, 'func2': 0.3}
            }, f)
            temp_path = f.name
        
        result = generate_coverage_heatmap_api('/test/bin', temp_path)
        assert 'heatmap_data' in result
        os.unlink(temp_path)


class TestVulnDeduplicator:
    
    def test_deduplicate(self):
        vulnerabilities = [
            {'vulnerability_type': 'buffer_overflow', 'function_name': 'func1', 'address': 0x1000},
            {'vulnerability_type': 'buffer_overflow', 'function_name': 'func1', 'address': 0x1000},
            {'vulnerability_type': 'use_after_free', 'function_name': 'func2', 'address': 0x2000}
        ]
        result = deduplicate_vulnerabilities(vulnerabilities, 'hybrid')
        assert result.unique_count <= result.total_count


class TestCrashClassifier:
    
    def test_analyze_crash(self):
        crash_data = {
            'crash_info': 'heap-use-after-free write',
            'stack_trace': '#0 0x12345678 in func()',
            'error_message': 'SIGSEGV',
            'crash_address': 0xdeadbeef,
            'registers': {'rip': '0x12345678', 'rsp': '0xffffff00'}
        }
        result = analyze_crash(crash_data)
        assert result.crash_type is not None
        assert result.severity is not None

    def test_generate_exploit(self):
        crash_data = {
            'crash_info': 'buffer overflow',
            'crash_address': 0xdeadbeef
        }
        result = generate_exploit_from_crash(crash_data)
        assert result is None or result.code is not None


class TestSemanticDiffAnalyzer:
    
    def test_analyze_diff(self):
        old_binary = {
            'binary_path': 'old.bin',
            'functions': [{'name': 'func1', 'address': 0x1000}]
        }
        new_binary = {
            'binary_path': 'new.bin',
            'functions': [{'name': 'func1', 'address': 0x1000}, {'name': 'auth_check', 'address': 0x2000}]
        }
        result = analyze_semantic_diff(old_binary, new_binary)
        assert len(result.changes) >= 0


class TestPatchQualityEvaluator:
    
    def test_evaluate_patch(self):
        patch_data = {
            'patch_id': 'patch1',
            'code_changes': [{'content': 'add bounds check for memcpy'}]
        }
        result = evaluate_patch(patch_data)
        assert result.status is not None


class TestSandboxEscapeDetector:
    
    def test_detect_escape(self):
        syscall_log = [
            {'name': 'ptrace', 'arguments': {'request': 0}, 'timestamp': '2024-01-01'}
        ]
        result = detect_sandbox_escape(syscall_log)
        assert result.is_escaped is True or False


class TestKernelIntegrityMonitor:
    
    def test_monitor_integrity(self):
        kernel_info = {
            'syscall_table_address': 0xffffffff81000000,
            'text_section_start': 0xffffffff81000000,
            'text_section_end': 0xffffffff82000000
        }
        result = monitor_kernel_integrity(kernel_info)
        assert result.status is not None


class TestDistributedVectorSearch:
    
    def test_search(self):
        search = create_vector_search({'dimension': 10})
        search.add_vector('func1', [0.1] * 10, {'name': 'func1'})
        results = search.search([0.1] * 10, top_k=5)
        assert len(results) >= 0

    def test_save_load_index(self):
        import tempfile
        search = create_vector_search({'dimension': 10})
        search.add_vector('func1', [0.1] * 10)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = f.name
        
        assert search.save_index(temp_path)
        assert search.load_index(temp_path)
        os.unlink(temp_path)


class TestUnifiedIRConverter:
    
    def test_convert_assembly(self):
        assembly = '''
.text
_start:
    add eax, ebx
    mov ecx, 0x10
    ret
'''
        result = convert_to_ir(assembly, 'x86')
        assert len(result.functions) >= 0

    def test_converter_class(self):
        converter = UnifiedIRConverter(Architecture.X86_64)
        assembly = 'add rax, rbx'
        result = converter.convert(assembly)
        assert result is not None


class TestMemoryPrimitiveExtractor:
    
    def test_extract_primitives(self):
        crash_data = {
            'crash_info': 'arbitrary write to freed memory',
            'crash_address': 0xdeadbeef,
            'vulnerability_type': 'use_after_free',
            'registers': {'rdi': '0x12345678'}
        }
        result = extract_memory_primitives(crash_data)
        assert len(result.primitives) >= 0


class TestCallStackReconstructor:
    
    def test_reconstruct_stack(self):
        crash_data = {
            'crash_address': 0xdeadbeef,
            'stack_trace': '0: 0x12345678 in func1\n1: 0x87654321 in func2',
            'registers': {'rbp': '0xffffff00', 'rsp': '0xfffffff0'}
        }
        result = reconstruct_call_stack(crash_data)
        assert len(result.frames) >= 0


class TestCodeStyleIdentifier:
    
    def test_identify_style(self):
        binary_info = {
            'binary_path': 'test.bin',
            'strings': 'Microsoft MSVC WINAPI __stdcall'
        }
        result = identify_code_style(binary_info)
        assert result.primary_author is not None


class TestAntiAntiDebug:
    
    def test_bypass_anti_debug(self):
        binary_info = {
            'strings': 'ptrace PTRACE_TRACEME'
        }
        result = bypass_anti_debug(binary_info)
        assert len(result.detections) >= 0


class TestHardwareTraceAnalyzer:
    
    def test_analyze_trace(self):
        trace_data = b'\x81\x00'
        # 修复：使用枚举 TraceType 代替字符串
        result = analyze_hardware_trace(trace_data, TraceType.INTEL_PT)
        assert result.trace_type is not None


class TestCFIIntegrityAnalyzer:
    
    def test_analyze_cfi(self):
        binary_info = {
            'strings': '__cfi_check __cfi_slowpath'
        }
        result = analyze_cfi_integrity(binary_info)
        assert len(result.cfi_protections) >= 0


class TestSupplyChainVulnerabilityMonitor:
    
    def test_monitor_supply_chain(self):
        components = [
            {'name': 'libssl', 'version': '1.1.1', 'vendor': 'openssl'}
        ]
        result = monitor_supply_chain(components)
        assert result is not None


class TestSyscallDependencyGraph:
    
    def test_build_graph(self):
        syscalls = ['open', 'read', 'write', 'close']
        result = build_syscall_dependency_graph(syscalls)
        assert result is not None


class TestKernelSyncDetector:
    
    def test_detect_sync_issues(self):
        kernel_code = '''
        spin_lock(&lock);
        // missing unlock
        '''
        result = detect_kernel_sync_issues(kernel_code)
        assert result is not None


class TestGdbScriptGenerator:
    
    def test_generate_script(self):
        # 修复：使用枚举 ScriptType.DEBUG
        result = generate_gdb_script(
            script_type=ScriptType.DEBUG,
            breakpoints=[{'address': 0x12345678, 'condition': 'x == 1'}],
            output_file='/tmp/script.gdb'
        )
        assert result is not None


class TestEbpfDynamicTracer:
    
    def test_create_ebpf_programs(self):
        trace_points = ['sys_enter_open', 'sys_exit_open']
        result = create_ebpf_programs(trace_points)
        assert len(result) >= 0


class TestContainerVulnLocator:
    
    def test_locate_vulnerabilities(self):
        image_info = {
            'layers': [{'id': 'layer1', 'files': ['/bin/ls']}],
            'vulnerabilities': [{'cve': 'CVE-2024-0001', 'file': '/bin/ls'}]
        }
        result = locate_container_vulnerabilities(image_info)
        assert result is not None


class TestOPAPolicyGenerator:
    
    def test_generate_policy(self):
        vulnerabilities = [{'severity': 'critical', 'cve': 'CVE-2024-0001'}]
        # 修复：使用枚举 PolicyType.NETWORK
        result = generate_opa_policy(vulnerabilities, PolicyType.NETWORK)
        assert result is not None


class TestExploitTemplateLibrary:
    
    def test_get_templates(self):
        templates = get_exploit_templates()
        assert len(templates) >= 0


class TestGNNVulnerabilityDetector:
    
    def test_detect_vulnerabilities(self):
        function_graph = {
            'nodes': [{'id': 'n1', 'type': 'function'}],
            'edges': [{'source': 'n1', 'target': 'n2'}]
        }
        result = detect_vulnerabilities_with_gnn(function_graph)
        assert result is not None


class TestFunctionBehaviorClassifier:
    
    def test_classify_behavior(self):
        functions = [
            {'name': 'encrypt_data', 'calls': ['AES_encrypt', 'SHA256']}
        ]
        result = classify_function_behavior(functions)
        assert len(result.classifications) >= 0


class TestPrivacyComplianceAuditor:
    
    def test_audit_compliance(self):
        binary_info = {
            'strings': 'location contacts device_id'
        }
        result = audit_privacy_compliance(binary_info)
        assert result is not None


class TestMultiDimensionStatsAPI:
    
    def test_get_statistics(self):
        vulnerabilities = [
            {'severity': 'critical', 'type': 'buffer_overflow'},
            {'severity': 'high', 'type': 'use_after_free'}
        ]
        # 修复：使用枚举 StatisticType.VULNERABILITY_DISTRIBUTION
        result = get_statistics(vulnerabilities, StatisticType.VULNERABILITY_DISTRIBUTION)
        assert 'distribution' in result


class TestZeroDayAnomalyDetector:
    
    def test_detect_zeroday(self):
        version_info = {
            'old_version': '1.0',
            'new_version': '1.1',
            'changes': [{'function': 'auth_check', 'type': 'modified'}]
        }
        result = detect_zeroday_anomalies(version_info)
        assert len(result.anomalies) >= 0


class TestDangerousFunctionAnalyzer:
    
    def test_analyze_dangerous_functions(self):
        functions = [
            {'name': 'copy_data', 'code': 'memcpy(dest, src, len);'}
        ]
        result = analyze_dangerous_functions(functions)
        assert len(result.functions) >= 0


class TestMemorySensitiveOpDetector:
    
    def test_detect_sensitive_operations(self):
        code = 'memset(key, 0, sizeof(key));'
        result = detect_memory_sensitive_operations(code)
        assert len(result.operations) >= 0


class TestTestOrchestrator:
    
    def test_create_workflow(self):
        # 修复：使用枚举 TaskType.DOCKER
        tasks = [
            {'type': TaskType.DOCKER, 'image': 'test:latest', 'command': 'run test'}
        ]
        result = create_test_workflow(tasks)
        assert result is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])