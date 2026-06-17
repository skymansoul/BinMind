import os
import logging
from typing import Dict, Any, Optional

# 日志框架配置
try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

class Config:
    """配置类"""
    
    # 项目根目录
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    
    # 日志配置
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.path.join(BASE_DIR, 'logs', 'binary_analyzer.log')
    
    # 目录配置
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    EXPLOITS_DIR = os.path.join(BASE_DIR, 'exploits')
    DB_DIR = os.path.join(BASE_DIR, 'db')
    DB_PATH = os.path.join(DB_DIR, 'vulnerabilities.db')
    CACHE_DIR = os.path.join(BASE_DIR, 'cache')
    CORPUS_DIR = os.path.join(BASE_DIR, 'corpus')
    
    # 超时配置
    SUBPROCESS_TIMEOUT = 300
    RADARE2_TIMEOUT = 300
    GHIDRA_TIMEOUT = 1800
    IDA_TIMEOUT = 1800
    ANGR_TIMEOUT = 300
    MAX_ITERATIONS = 5
    
    # 反编译器配置
    DEFAULT_DECOMPILER = os.environ.get('DEFAULT_DECOMPILER', 'auto')
    ENABLE_SYMBOLIC_EXECUTION = True
    
    # llama.cpp 配置
    LLAMACPP_HOST = 'http://localhost:8080'
    
    # 数据目录
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    TEMP_DIR = os.path.join(BASE_DIR, 'temp')
    RESULTS_DIR = os.path.join(BASE_DIR, 'results')
    LOGS_DIR = os.path.join(BASE_DIR, 'logs')
    REPORTS_DIR = os.path.join(BASE_DIR, 'reports')
    EXPLOITS_DIR = os.path.join(BASE_DIR, 'exploits')
    DB_DIR = os.path.join(BASE_DIR, 'db')
    DB_PATH = os.path.join(DB_DIR, 'vulnerabilities.db')
    
    # 数据库配置
    DATABASE_PATH = os.path.join(DATA_DIR, 'vulnerabilities.db')
    EXPLOITDB_CACHE_DIR = os.path.expanduser('~/.exploitdb')
    DEEP_SEARCH_INDEX_DIR = os.path.expanduser('~/.deep_binary_search')
    
    # 漏洞数据库类型
    DB_TYPE = 'sqlite'
    
    # 外部工具路径
    QEMU_PATH = os.environ.get('QEMU_PATH', 'qemu-system-x86_64')
    GCC_PATH = os.environ.get('GCC_PATH', 'gcc')
    R2_PATH = os.environ.get('R2_PATH', 'r2')
    
    # 通用配置
    MAX_ITERATIONS = 5
    DEFAULT_DECOMPILER = os.environ.get('DEFAULT_DECOMPILER', 'auto')
    SUBPROCESS_TIMEOUT = 300
    RADARE2_TIMEOUT = 60
    
    # QEMU配置
    QEMU_MEMORY = '512M'
    QEMU_CPU = 'qemu64'
    QEMU_TIMEOUT = 120
    
    # 内核利用配置
    KERNEL_EXPLOIT = {
        'enabled': False,
        'kernel_image': None,
        'rootfs': None,
        'output_dir': os.path.join(RESULTS_DIR, 'kernel_exploits')
    }
    
    # 信息泄露分析配置
    INFO_LEAK_ANALYZER = {
        'enabled': True,
        'min_confidence': 0.5,
        'max_depth': 10,
        'detect_format_string': True,
        'detect_memory_read': True,
    }
    
    # 代码克隆检测配置
    CODE_CLONE_DETECTOR = {
        'enabled': True,
        'min_similarity': 0.7,
        'fuzzy_threshold': 70,
        'use_ssdeep': True,
        'use_tlsh': True,
    }
    
    # Shellcode编码器配置
    SHELLCODE_ENCODER = {
        'enabled': True,
        'default_arch': 'amd64',
        'default_bad_chars': [0x00, 0x0a, 0x0d],
        'auto_select_encoder': True,
    }
    
    # 调用图增强配置
    CALL_GRAPH_ENHANCER = {
        'enabled': True,
        'min_confidence': 0.5,
        'detect_vtables': True,
        'detect_fp_arrays': True,
        'resolve_indirect_calls': True,
    }
    
    # 函数摘要生成配置
    FUNCTION_SUMMARIZER = {
        'enabled': True,
        'arch': 'amd64',
        'execution_mode': 'concrete',
        'timeout': 30,
        'max_blocks': 1000,
    }
    
    # 栈迁移生成配置
    STACK_PIVOT_GENERATOR = {
        'enabled': True,
        'max_gadget_length': 5,
        'min_reliability': 0.5,
        'prefer_xchg': True,
    }
    
    # 类型混淆检测配置
    TYPE_CONFUSION = {
        'enabled': False,
        'max_functions': 50,
        'risk_threshold': 'medium'
    }
    
    # Exploit-DB配置
    EXPLOITDB = {
        'enabled': False,
        'api_url': 'https://www.exploit-db.com',
        'timeout': 30,
        'match_threshold': 70
    }
    
    # 深度学习搜索配置
    DEEP_SEARCH = {
        'enabled': False,
        'model_path': None,
        'embedding_dim': 128,
        'top_k': 5
    }
    
    # 无线协议分析配置
    WIRELESS_ANALYZER = {
        'enabled': False,
        'bluetooth_enabled': True,
        'wifi_enabled': True,
        'generate_fuzz_cases': True
    }
    
    # 逻辑炸弹检测配置
    LOGIC_BOMB_DETECTOR = {
        'enabled': False,
        'max_functions': 50,
        'date_threshold': '2025-01-01'
    }
    
    # SEH/VEH分析配置
    SEH_ANALYZER = {
        'enabled': False,
        'check_seh_chain': True,
        'check_veh_handlers': True,
        'detect_overflowable': True
    }
    
    # IPC安全分析配置
    IPC_ANALYZER = {
        'enabled': False,
        'max_binaries': 10,
        'detect_pipes': True,
        'detect_shared_memory': True,
        'detect_sockets': True,
        'detect_dbus': True,
        'generate_graph': True
    }
    
    # 调试信息解析配置
    DEBUG_INFO = {
        'enabled': False,
        'auto_load_symbols': True,
        'pdb_search_paths': [
            '.',
            './pdb',
            './symbols',
            './debug'
        ],
        'symbol_server_url': 'https://msdl.microsoft.com/download/symbols',
        'max_symbol_count': 10000
    }
    
    # 内嵌脚本提取配置
    EMBEDDED_SCRIPT_EXTRACTOR = {
        'enabled': False,
        'detect_lua': True,
        'detect_python': True,
        'detect_javascript': True,
        'detect_vbscript': True,
        'max_script_size': 100000,
        'risk_analysis': True
    }
    
    # 系统调用分类配置
    SYSCALL_CLASSIFIER = {
        'enabled': False,
        'model_path': os.path.join(DATA_DIR, 'syscall_model.pkl'),
        'malicious_threshold': 0.7,
        'enable_online_ai': False,
        'ai_api_url': None
    }
    
    # 结构体恢复配置
    STRUCT_RECOVERY = {
        'enabled': False,
        'min_access_count': 2,
        'min_field_count': 2,
        'confidence_threshold': 0.5,
        'enable_nested_detection': True,
        'generate_c_code': True
    }
    
    # eBPF分析配置
    EBPF_ANALYZER = {
        'enabled': True,
        'use_bpftool': True,
        'bpftool_path': 'bpftool',
        'max_instructions': 10000,
        'validate_ebpf': True
    }
    
    # 漏洞传播分析配置
    VULN_PROPAGATION = {
        'enabled': True,
        'max_paths': 10,
        'confidence_threshold': 0.1,
        'generate_graph': True
    }
    
    # 密码误用检测配置
    CRYPTO_MISUSE = {
        'enabled': True,
        'check_weak_random': True,
        'check_hardcoded_iv': True,
        'check_weak_hash': True,
        'check_weak_cipher': True,
        'check_insecure_kdf': True,
        'check_hardcoded_secrets': True
    }
    
    # DSE绕过检测配置
    DSE_BYPASS = {
        'enabled': True,
        'check_signature': True,
        'check_certificate': True,
        'check_bypass_keywords': True,
        'check_imports': True
    }
    
    # 内存注入检测配置
    MEMORY_MANIPULATION = {
        'enabled': True,
        'check_imports': True,
        'check_patterns': True,
        'check_strings': True,
        'detect_sequences': True
    }
    
    # 网络流量重放配置
    TRAFFIC_REPLAYER = {
        'enabled': True,
        'use_scapy': True,
        'default_timeout': 5,
        'max_packets': 10000,
        'generate_fuzz': True,
        'fuzz_variations': 10
    }
    
    # 安全配置
    SECURITY = {
        'allow_external_downloads': True,
        'sandbox_enabled': True,
        'max_file_size': 100 * 1024 * 1024  # 100MB
    }
    
    # 攻击面分析配置
    ATTACK_SURFACE = {
        'enabled': False,
        'risk_threshold': 'medium',
        'max_surface_points': 100,
        'include_rpc': True,
        'include_ipc': True
    }
    
    # PoC生成配置
    POC_GENERATOR = {
        'enabled': False,
        'output_dir': './pocs',
        'default_format': 'binary',
        'max_payload_size': 65536,
        'use_angr': False
    }
    
    # 时间侧信道检测配置
    TIMING_SIDE_CHANNEL = {
        'enabled': False,
        'check_key_branches': True,
        'check_secret_loops': True,
        'check_lookups': True,
        'use_ai_verification': False
    }
    
    # PII扫描配置
    PII_SCANNER = {
        'enabled': False,
        'scan_email': True,
        'scan_phone': True,
        'scan_credentials': True,
        'scan_private_keys': True,
        'mask_output': True
    }
    
    # Enclave分析配置
    ENCLAVE_ANALYZER = {
        'enabled': False,
        'support_sgx': True,
        'support_trustzone': True,
        'check_ocall_params': True,
        'check_ecall_pointers': True
    }
    
    # OTA差分分析配置
    OTA_DIFF_ANALYZER = {
        'enabled': False,
        'extract_dir': './ota_extracted',
        'check_scripts': True,
        'check_binaries': True,
        'check_configs': True,
        'detect_backdoors': True
    }
    
    # 堆风水策略配置
    HEAP_FENG_SHUI = {
        'enabled': True,
        'default_allocator': 'ptmalloc',
        'default_vulnerability': 'use_after_free',
        'default_target_size': 0x80,
        'tcache_count': 7,
        'enable_fastbin': True,
        'arena_count': 1,
        'output_dir': os.path.join(RESULTS_DIR, 'fengshui')
    }
    
    # DLL劫持检测配置
    DLL_HIJACK = {
        'enabled': True,
        'detect_delay_load': True,
        'detect_known_hijack_dlls': True,
        'risk_threshold': 'high',
        'output_dir': os.path.join(RESULTS_DIR, 'dll_hijack')
    }
    
    # 安全启动验证配置
    SECURE_BOOT = {
        'enabled': True,
        'verify_signatures': True,
        'check_rollback_protection': True,
        'extract_certificates': True,
        'output_dir': os.path.join(RESULTS_DIR, 'secure_boot')
    }
    
    # PMC侧信道评估配置
    PMC_SIDE_CHANNEL = {
        'enabled': True,
        'require_root': True,
        'max_iterations': 1000,
        'signal_threshold': 0.5,
        'output_dir': os.path.join(RESULTS_DIR, 'pmc_analysis')
    }

    # 反编译重编译验证配置
    RECOMPILER_VERIFIER = {
        'enabled': True,
        'compiler_path': 'gcc',
        'equivalence_threshold': 0.5,
        'max_functions': 100,
        'output_dir': os.path.join(RESULTS_DIR, 'recompiler')
    }

    # 隐写检测配置
    STEGANOGRAPHY_DETECTOR = {
        'enabled': True,
        'entropy_threshold': 0.8,
        'min_hidden_size': 256,
        'scan_overlay': True,
        'scan_section_gaps': True,
        'scan_embedded_archives': True,
        'output_dir': os.path.join(RESULTS_DIR, 'steganography')
    }

    # ==================== 抗量子密码算法检测配置 ====================
    PQC_DETECTOR = {
        'enabled': True,
        'detect_classical': True,
        'detect_pqc': True,
        'generate_migration_warnings': True,
        'min_confidence': 0.7,
        'output_dir': os.path.join(RESULTS_DIR, 'pqc')
    }

    # ==================== 格密码时间侧信道检测配置 ====================
    LATTICE_SIDE_CHANNEL = {
        'enabled': True,
        'detect_conditional_branches': True,
        'detect_memory_access': True,
        'detect_lookup_tables': True,
        'detect_ntt_operations': True,
        'risk_threshold': 0.5,
        'output_dir': os.path.join(RESULTS_DIR, 'lattice_side_channel')
    }

    # ==================== RISC-V扩展分析配置 ====================
    RISCV_EXT_ANALYZER = {
        'enabled': True,
        'analyze_vector': True,
        'analyze_crypto': True,
        'detect_vector_loops': True,
        'detect_unsafe_instructions': True,
        'output_dir': os.path.join(RESULTS_DIR, 'riscv_ext')
    }

    # ==================== CHERI能力架构分析配置 ====================
    CHERI_ANALYZER = {
        'enabled': True,
        'check_permissions': True,
        'check_sealing': True,
        'check_capability_leaks': True,
        'check_delegation': True,
        'output_dir': os.path.join(RESULTS_DIR, 'cheri')
    }

    # ==================== 多视图图神经网络配置 ====================
    MULTI_VIEW_GNN = {
        'enabled': True,
        'model_path': None,
        'embedding_dim': 512,
        'hidden_dim': 256,
        'num_layers': 3,
        'device': 'auto',
        'output_dir': os.path.join(RESULTS_DIR, 'multi_view_gnn')
    }

    # ==================== 知识蒸馏漏洞检测配置 ====================
    DISTILLED_VULN_DETECTOR = {
        'enabled': True,
        'model_path': None,
        'quantized': True,
        'confidence_threshold': 0.8,
        'batch_size': 32,
        'output_dir': os.path.join(RESULTS_DIR, 'distilled_vuln_detector')
    }

    # ==================== 执行轨迹异常检测配置 ====================
    TRAJECTORY_ANOMALY = {
        'enabled': True,
        'model_path': None,
        'max_seq_length': 512,
        'perplexity_threshold': 100.0,
        'detect_rop': True,
        'detect_jop': True,
        'detect_stack_pivot': True,
        'output_dir': os.path.join(RESULTS_DIR, 'trajectory_anomaly')
    }

    # ==================== AI 服务配置 ====================
    # AI提供商 (openai, azure, ollama, llamacpp, custom)
    AI_PROVIDER = os.environ.get('AI_PROVIDER', 'openai')
    
    # OpenAI 配置
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY', '')
    OPENAI_MODEL = os.environ.get('OPENAI_MODEL', 'gpt-4')
    OPENAI_BASE_URL = os.environ.get('OPENAI_BASE_URL', '')
    
    # Azure OpenAI 配置
    AZURE_API_KEY = os.environ.get('AZURE_API_KEY', '')
    AZURE_ENDPOINT = os.environ.get('AZURE_ENDPOINT', '')
    AZURE_DEPLOYMENT_NAME = os.environ.get('AZURE_DEPLOYMENT_NAME', '')
    
    # Ollama 配置
    OLLAMA_MODEL = os.environ.get('OLLAMA_MODEL', 'llama2')
    OLLAMA_HOST = os.environ.get('OLLAMA_HOST', 'http://localhost:11434')
    
    # llama.cpp 配置
    LLAMACPP_MODEL_PATH = os.environ.get('LLAMACPP_MODEL_PATH', '')
    LLAMACPP_N_THREADS = int(os.environ.get('LLAMACPP_N_THREADS', '4'))
    
    # 自定义 API 配置
    CUSTOM_API_URL = os.environ.get('CUSTOM_API_URL', '')
    CUSTOM_API_KEY = os.environ.get('CUSTOM_API_KEY', '')
    
    # AI 请求配置
    AI_TIMEOUT = int(os.environ.get('AI_TIMEOUT', '60'))
    AI_MAX_TOKENS = int(os.environ.get('AI_MAX_TOKENS', '4096'))
    AI_TEMPERATURE = float(os.environ.get('AI_TEMPERATURE', '0.7'))
    
    # ==================== 威胁情报配置 ====================
    # MISP配置
    MISP_URL = os.environ.get('MISP_URL', '')
    MISP_API_KEY = os.environ.get('MISP_API_KEY', '')
    MISP_VERIFY_SSL = os.environ.get('MISP_VERIFY_SSL', 'true').lower() == 'true'
    
    # OTX配置
    OTX_API_KEY = os.environ.get('OTX_API_KEY', '')
    
    # 威胁情报通用配置
    THREAT_INTEL_TIMEOUT = int(os.environ.get('THREAT_INTEL_TIMEOUT', '30'))
    THREAT_INTEL_ENABLED = os.environ.get('THREAT_INTEL_ENABLED', 'false').lower() == 'true'
    
    # ==================== 漏洞利用策略配置 ====================
    EXPLOIT_STRATEGY_OUTPUT_DIR = os.environ.get('EXPLOIT_STRATEGY_OUTPUT_DIR', os.path.join(DATA_DIR, 'exploit_strategies'))
    EXPLOIT_STRATEGY_ENABLED = os.environ.get('EXPLOIT_STRATEGY_ENABLED', 'true').lower() == 'true'

    # ==================== C++虚表恢复配置 ====================
    CPP_VTBL_OUTPUT_DIR = os.environ.get('CPP_VTBL_OUTPUT_DIR', os.path.join(DATA_DIR, 'cpp_vtbl'))
    CPP_VTBL_ENABLED = os.environ.get('CPP_VTBL_ENABLED', 'true').lower() == 'true'

    # ==================== 保护机制绕过配置 ====================
    BYPASS_ADVISOR_OUTPUT_DIR = os.environ.get('BYPASS_ADVISOR_OUTPUT_DIR', os.path.join(DATA_DIR, 'bypass_advisor'))
    BYPASS_ADVISOR_ENABLED = os.environ.get('BYPASS_ADVISOR_ENABLED', 'true').lower() == 'true'

    # ==================== 二进制测试生成配置 ====================
    TEST_GENERATOR_OUTPUT_DIR = os.environ.get('TEST_GENERATOR_OUTPUT_DIR', os.path.join(DATA_DIR, 'test_generator'))
    TEST_GENERATOR_ENABLED = os.environ.get('TEST_GENERATOR_ENABLED', 'true').lower() == 'true'
    TEST_GENERATOR_DEFAULT_LANGUAGE = os.environ.get('TEST_GENERATOR_DEFAULT_LANGUAGE', 'c')
    TEST_GENERATOR_CASES_PER_FUNC = int(os.environ.get('TEST_GENERATOR_CASES_PER_FUNC', '5'))

    # ==================== 增量分析缓存配置 ====================
    INCREMENTAL_ANALYSIS_CACHE_DIR = os.environ.get('INCREMENTAL_ANALYSIS_CACHE_DIR', os.path.join(DATA_DIR, 'incremental_cache'))
    INCREMENTAL_ANALYSIS_ENABLED = os.environ.get('INCREMENTAL_ANALYSIS_ENABLED', 'true').lower() == 'true'
    CACHE_VALIDITY_DAYS = int(os.environ.get('CACHE_VALIDITY_DAYS', '30'))

    # ML函数边界检测配置
    FUNCTION_BOUNDARY_MODEL_DIR = os.environ.get('FUNCTION_BOUNDARY_MODEL_DIR', os.path.join(DATA_DIR, 'models'))
    FUNCTION_BOUNDARY_OUTPUT_DIR = os.environ.get('FUNCTION_BOUNDARY_OUTPUT_DIR', os.path.join(DATA_DIR, 'function_boundary'))
    FUNCTION_BOUNDARY_ENABLED = os.environ.get('FUNCTION_BOUNDARY_ENABLED', 'true').lower() == 'true'
    FUNCTION_BOUNDARY_MODEL_PATH = os.environ.get('FUNCTION_BOUNDARY_MODEL_PATH', '')
    FUNCTION_BOUNDARY_MIN_CONFIDENCE = float(os.environ.get('FUNCTION_BOUNDARY_MIN_CONFIDENCE', '0.5'))

    # ==================== 新增六项技术功能配置（第三轮）====================

    # 功能1：基于LLM的自动化深度逆向分析报告生成配置
    REVERSE_REPORT_ENABLED = os.environ.get('REVERSE_REPORT_ENABLED', 'true').lower() == 'true'
    REVERSE_REPORT_OUTPUT_DIR = os.environ.get('REVERSE_REPORT_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'reports'))
    REVERSE_REPORT_DEFAULT_LANG = os.environ.get('REVERSE_REPORT_DEFAULT_LANG', 'zh')
    REVERSE_REPORT_MAX_TOKENS = int(os.environ.get('REVERSE_REPORT_MAX_TOKENS', '3000'))

    # 功能2：二进制字符串自动解码与解混淆配置
    STRING_DECODER_ENABLED = os.environ.get('STRING_DECODER_ENABLED', 'true').lower() == 'true'
    STRING_DECODER_MIN_LENGTH = int(os.environ.get('STRING_DECODER_MIN_LENGTH', '4'))
    STRING_DECODER_MAX_LENGTH = int(os.environ.get('STRING_DECODER_MAX_LENGTH', '1000'))
    STRING_DECODER_ENABLE_LANG_DETECT = os.environ.get('STRING_DECODER_ENABLE_LANG_DETECT', 'false').lower() == 'true'

    # 功能3：多线程死锁自动化检测配置
    DEADLOCK_DETECTOR_ENABLED = os.environ.get('DEADLOCK_DETECTOR_ENABLED', 'true').lower() == 'true'
    DEADLOCK_DETECTOR_USE_NETWORKX = os.environ.get('DEADLOCK_DETECTOR_USE_NETWORKX', 'true').lower() == 'true'

    # 功能4：二进制内嵌配置与凭据自动提取配置
    CONFIG_EXTRACTOR_ENABLED = os.environ.get('CONFIG_EXTRACTOR_ENABLED', 'true').lower() == 'true'
    CONFIG_EXTRACTOR_OUTPUT_DIR = os.environ.get('CONFIG_EXTRACTOR_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'extracted_config'))
    CONFIG_EXTRACTOR_MASK_SENSITIVE = os.environ.get('CONFIG_EXTRACTOR_MASK_SENSITIVE', 'true').lower() == 'true'

    # 功能5：内存损坏模式自动分类配置
    CORRUPTION_CLASSIFIER_ENABLED = os.environ.get('CORRUPTION_CLASSIFIER_ENABLED', 'true').lower() == 'true'
    CORRUPTION_CLASSIFIER_MIN_CONFIDENCE = float(os.environ.get('CORRUPTION_CLASSIFIER_MIN_CONFIDENCE', '0.5'))

    # 功能6：反编译代码自动生成流程图与结构图配置
    CODE_VISUALIZER_ENABLED = os.environ.get('CODE_VISUALIZER_ENABLED', 'true').lower() == 'true'
    CODE_VISUALIZER_OUTPUT_DIR = os.environ.get('CODE_VISUALIZER_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'visualizations'))
    CODE_VISUALIZER_DEFAULT_FORMAT = os.environ.get('CODE_VISUALIZER_DEFAULT_FORMAT', 'mermaid')

    # ==================== 六项高级安全功能配置（第四轮）====================

    # 功能1：虚拟机自省（VMI）辅助内存分析配置
    VMI_ENABLED = os.environ.get('VMI_ENABLED', 'false').lower() == 'true'
    VMI_OUTPUT_DIR = os.environ.get('VMI_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'vmi_dumps'))
    VMI_HYPERVISOR = os.environ.get('VMI_HYPERVISOR', 'kvm')
    VMI_TIMEOUT = int(os.environ.get('VMI_TIMEOUT', '60'))
    VMI_MAX_PROCESSES = int(os.environ.get('VMI_MAX_PROCESSES', '100'))
    VMI_DUMP_CODE_ONLY = os.environ.get('VMI_DUMP_CODE_ONLY', 'true').lower() == 'true'

    # 功能2：自动生成二进制文档与函数注释配置
    BINARY_DOCUMENTER_ENABLED = os.environ.get('BINARY_DOCUMENTER_ENABLED', 'true').lower() == 'true'
    BINARY_DOCUMENTER_OUTPUT_DIR = os.environ.get('BINARY_DOCUMENTER_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'docs'))
    BINARY_DOCUMENTER_FORMAT = os.environ.get('BINARY_DOCUMENTER_FORMAT', 'markdown')
    BINARY_DOCUMENTER_INCLUDE_RISK = os.environ.get('BINARY_DOCUMENTER_INCLUDE_RISK', 'true').lower() == 'true'
    BINARY_DOCUMENTER_MAX_FUNCTIONS = int(os.environ.get('BINARY_DOCUMENTER_MAX_FUNCTIONS', '100'))

    # 功能3：代码签名证书验证与滥用检测配置
    CODE_SIGNING_CHECK_ENABLED = os.environ.get('CODE_SIGNING_CHECK_ENABLED', 'true').lower() == 'true'
    CODE_SIGNING_CHECK_REVOCATION = os.environ.get('CODE_SIGNING_CHECK_REVOCATION', 'true').lower() == 'true'
    CODE_SIGNING_CHECK_LEAKED_DB = os.environ.get('CODE_SIGNING_CHECK_LEAKED_DB', 'true').lower() == 'true'
    CODE_SIGNING_LEAKED_DB_PATH = os.environ.get('CODE_SIGNING_LEAKED_DB_PATH', os.path.join(DATA_DIR, 'leaked_certs.json'))
    CODE_SIGNING_TRUSTED_ROOT_PATH = os.environ.get('CODE_SIGNING_TRUSTED_ROOT_PATH', '')

    # 功能4：基于符号执行的自动去虚拟化分析配置
    ANTI_VM_BYPASS_ENABLED = os.environ.get('ANTI_VM_BYPASS_ENABLED', 'true').lower() == 'true'
    ANTI_VM_BYPASS_OUTPUT_DIR = os.environ.get('ANTI_VM_BYPASS_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'bypass'))
    ANTI_VM_BYPASS_MAX_ANALYSIS_TIME = int(os.environ.get('ANTI_VM_BYPASS_MAX_ANALYSIS_TIME', '300'))
    ANTI_VM_BYPASS_USE_UNICORN = os.environ.get('ANTI_VM_BYPASS_USE_UNICORN', 'true').lower() == 'true'

    # 功能5：二进制重打包/捆绑包检测配置
    REPACK_DETECTOR_ENABLED = os.environ.get('REPACK_DETECTOR_ENABLED', 'true').lower() == 'true'
    REPACK_DETECTOR_ENTROPY_THRESHOLD = float(os.environ.get('REPACK_DETECTOR_ENTROPY_THRESHOLD', '7.5'))
    REPACK_DETECTOR_SUSPICIOUS_SECTION_SCORE = int(os.environ.get('REPACK_DETECTOR_SUSPICIOUS_SECTION_SCORE', '50'))

    # 功能6：ROP Gadget自动分级与利用潜力评估配置
    ROP_GRADER_ENABLED = os.environ.get('ROP_GRADER_ENABLED', 'true').lower() == 'true'
    ROP_GRADER_OUTPUT_DIR = os.environ.get('ROP_GRADER_OUTPUT_DIR', os.path.join(RESULTS_DIR, 'rop_grading'))
    ROP_GRADER_MIN_SCORE_THRESHOLD = int(os.environ.get('ROP_GRADER_MIN_SCORE_THRESHOLD', '30'))
    ROP_GRADER_MAX_GADGETS = int(os.environ.get('ROP_GRADER_MAX_GADGETS', '1000'))

    @classmethod
    def get(cls, key: str, default: Any = None) -> Any:
        """获取配置值"""
        keys = key.split('.')
        value = cls
        for k in keys:
            if hasattr(value, k):
                value = getattr(value, k)
            else:
                return default
        return value
    
    @classmethod
    def set(cls, key: str, value: Any):
        """设置配置值"""
        keys = key.split('.')
        obj = cls
        for i, k in enumerate(keys[:-1]):
            if hasattr(obj, k):
                obj = getattr(obj, k)
            else:
                return False
        
        if hasattr(obj, keys[-1]):
            setattr(obj, keys[-1], value)
            return True
        return False
    
    @classmethod
    def init_dirs(cls):
        """初始化目录"""
        dirs = [
            cls.DATA_DIR,
            cls.TEMP_DIR,
            cls.RESULTS_DIR,
            os.path.dirname(cls.LOG_FILE),
            cls.EXPLOITDB_CACHE_DIR,
            cls.DEEP_SEARCH_INDEX_DIR,
            cls.KERNEL_EXPLOIT['output_dir']
        ]
        
        for dir_path in dirs:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)

# AI相关辅助函数

def call_ai_with_retry(func, max_retries=3, delay=1):
    """
    带重试的AI调用包装函数
    
    Args:
        func: 要执行的AI调用函数
        max_retries: 最大重试次数
        delay: 重试间隔（秒）
    
    Returns:
        AI调用结果
    """
    import time
    
    for attempt in range(max_retries):
        try:
            return func()
        except Exception as e:
            if attempt < max_retries - 1:
                time.sleep(delay)
                continue
            raise e

def get_current_ai_model():
    """获取当前配置的AI模型"""
    provider = os.environ.get('AI_PROVIDER', 'openai')
    
    if provider == 'ollama':
        return os.environ.get('OLLAMA_MODEL', 'llama2')
    elif provider == 'azure':
        return os.environ.get('AZURE_OPENAI_DEPLOYMENT', os.environ.get('OPENAI_MODEL', 'gpt-4'))
    elif provider == 'llamacpp':
        return os.environ.get('LLAMACPP_MODEL', 'llama-2-7b-chat')
    elif provider == 'custom':
        return os.environ.get('CUSTOM_MODEL', 'custom')
    else:
        return os.environ.get('OPENAI_MODEL', 'gpt-4')

def mask_sensitive_data(data):
    """
    脱敏敏感数据
    
    Args:
        data: 原始数据
    
    Returns:
        脱敏后的数据
    """
    import re
    
    if isinstance(data, str):
        # 屏蔽API密钥
        data = re.sub(r'(sk-[a-zA-Z0-9]{48})', 'sk-****************', data)
        # 屏蔽邮箱
        data = re.sub(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '***@***.com', data)
        # 屏蔽IP地址
        data = re.sub(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'xxx.xxx.xxx.xxx', data)
    elif isinstance(data, dict):
        for key, value in data.items():
            data[key] = mask_sensitive_data(value)
    elif isinstance(data, list):
        data = [mask_sensitive_data(item) for item in data]
    
    return data

class SensitiveFilter(logging.Filter):
    """日志敏感信息过滤器"""
    
    def filter(self, record):
        record.msg = mask_sensitive_data(record.msg)
        if record.args:
            record.args = tuple(mask_sensitive_data(arg) for arg in record.args)
        return True

def ensure_directories():
    """确保所有必要目录存在"""
    dirs = [
        Config.DATA_DIR,
        Config.TEMP_DIR,
        Config.RESULTS_DIR,
        os.path.dirname(Config.LOG_FILE),
        Config.EXPLOITDB_CACHE_DIR,
        Config.DEEP_SEARCH_INDEX_DIR,
        Config.KERNEL_EXPLOIT['output_dir']
    ]
    
    for dir_path in dirs:
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

def mask_api_key(key: str) -> str:
    """屏蔽API密钥"""
    if not key:
        return key
    if len(key) <= 8:
        return '***'
    return key[:4] + '*' * (len(key) - 8) + key[-4:]

def get_openai_client():
    """获取OpenAI客户端"""
    try:
        from openai import OpenAI
        api_key = os.environ.get('OPENAI_API_KEY')
        if api_key:
            return OpenAI(api_key=api_key)
        return None
    except ImportError:
        return None

def check_openai_api_key():
    """检查OpenAI API密钥"""
    api_key = os.environ.get('OPENAI_API_KEY')
    return api_key is not None and len(api_key) > 0

def validate_crash_data(crash_data):
    """验证崩溃数据"""
    if not isinstance(crash_data, dict):
        return False, "崩溃数据必须是字典类型"
    
    if 'registers' in crash_data or 'stack_trace' in crash_data:
        return True, None
    
    return False, "崩溃数据缺少必要字段（registers 或 stack_trace）"

def get_crash_data_example():
    """获取崩溃数据示例"""
    return {
        'registers': {
            'rax': '0x00000000deadbeef',
            'rbx': '0x0000000000000000',
            'rcx': '0x0000000000000041',
            'rdx': '0x00007ffff7a0d000',
            'rsp': '0x00007ffff7a0cff0',
            'rbp': '0x00007ffff7a0d000',
            'rsi': '0x00007ffff7a0d000',
            'rdi': '0x0000000000000000',
            'rip': '0x00007ffff7a0d000',
            'eflags': '0x0000000000010206'
        },
        'stack_trace': [
            '#0  0x00007ffff7a0d000 in vulnerable_function ()',
            '#1  0x00007ffff7a0d050 in main ()',
            '#2  0x00007ffff7a0d100 in __libc_start_main ()'
        ],
        'output': '*** buffer overflow detected ***: ./vulnerable terminated\n',
        'signal': 'SIGSEGV',
        'crash_address': '0x00007ffff7a0d000',
        'crash_type': 'buffer_overflow',
        'exploitability': 'high'
    }

def test_api_connection() -> bool:
    """测试AI API连接"""
    provider = Config.AI_PROVIDER.lower()
    
    if provider == 'openai':
        if not Config.OPENAI_API_KEY:
            return False
        try:
            from openai import OpenAI
            client = OpenAI(api_key=Config.OPENAI_API_KEY)
            if Config.OPENAI_BASE_URL:
                client.base_url = Config.OPENAI_BASE_URL
            client.models.list()
            return True
        except Exception:
            return False
    
    elif provider == 'azure':
        if not Config.AZURE_API_KEY or not Config.AZURE_ENDPOINT:
            return False
        try:
            from openai import AzureOpenAI
            client = AzureOpenAI(
                api_key=Config.AZURE_API_KEY,
                azure_endpoint=Config.AZURE_ENDPOINT,
                azure_deployment=Config.AZURE_DEPLOYMENT_NAME
            )
            client.models.list()
            return True
        except Exception:
            return False
    
    elif provider == 'ollama':
        try:
            import requests
            response = requests.get(f"{Config.OLLAMA_HOST}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    elif provider == 'llamacpp':
        if not Config.LLAMACPP_MODEL_PATH or not os.path.exists(Config.LLAMACPP_MODEL_PATH):
            return False
        return True
    
    elif provider == 'custom':
        if not Config.CUSTOM_API_URL:
            return False
        try:
            import requests
            response = requests.get(Config.CUSTOM_API_URL, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    return False


# ==================== Celery 配置函数 ====================
def get_celery_broker_url() -> str:
    """获取 Celery 消息队列 URL"""
    return os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')


def get_celery_result_backend() -> str:
    """获取 Celery 结果后端 URL"""
    return os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')


def mask_redis_url(url: str) -> str:
    """屏蔽 Redis URL 中的密码信息"""
    if '://' in url:
        parts = url.split('://')
        scheme = parts[0]
        rest = parts[1]
        if '@' in rest:
            credentials, host = rest.split('@', 1)
            if ':' in credentials:
                username, password = credentials.split(':', 1)
                return f"{scheme}://{username}:***@{host}"
            return f"{scheme}://***@{host}"
    return url


def get_task_cache_key(task_type: str, binary_hash: str) -> str:
    """生成任务缓存键"""
    return f"task:{task_type}:{binary_hash}"


def ensure_directories() -> None:
    """确保所有必要的目录存在"""
    dirs_to_create = [
        Config.LOGS_DIR,
        Config.REPORTS_DIR,
        Config.EXPLOITS_DIR,
        Config.DB_DIR,
        Config.CACHE_DIR,
        Config.CORPUS_DIR,
        Config.DATA_DIR,
        Config.TEMP_DIR,
        Config.RESULTS_DIR,
    ]
    
    for dir_path in dirs_to_create:
        os.makedirs(dir_path, exist_ok=True)


class SensitiveFilter:
    """敏感信息过滤器"""
    
    SENSITIVE_PATTERNS = [
        r'(?i)api[_-]?key',
        r'(?i)secret',
        r'(?i)password',
        r'(?i)token',
        r'(?i)credential',
        r'(?i)private[_-]?key',
    ]
    
    @staticmethod
    def filter(text: str) -> str:
        """过滤文本中的敏感信息"""
        import re
        result = text
        for pattern in SensitiveFilter.SENSITIVE_PATTERNS:
            result = re.sub(pattern, '[REDACTED]', result, flags=re.IGNORECASE)
        return result

# AI 提供商常量
AI_PROVIDER_OPENAI = 'openai'
AI_PROVIDER_AZURE = 'azure'
AI_PROVIDER_OLLAMA = 'ollama'
AI_PROVIDER_LLAMACPP = 'llamacpp'
AI_PROVIDER_CUSTOM = 'custom'

# 初始化目录
Config.init_dirs()