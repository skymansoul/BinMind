#!/usr/bin/env python3
"""
binmind - LLM 辅助的二进制漏洞分析工具

命令行接口：
- binmind --health / --doctor  -> 健康检查
- binmind --server [--host HOST] [--port PORT]  -> 启动 Web API 服务
- binmind ./your_binary.elf [--debug] [--log-level DEBUG]  -> 分析二进制文件
- binmind --test  -> 运行测试套件
"""

import argparse
import logging
import sys
import os
import traceback

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def parse_arguments():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='LLM-Assisted Binary Vulnerability Analysis Tool v1.3.1',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
支持的文件格式: ELF (Linux), PE (Windows), Mach-O (macOS)
支持的 AI 提供商: OpenAI, Azure OpenAI, Ollama, llama.cpp, Custom API
支持的编程语言: C/C++, Go, Rust

AI 服务配置:
  请直接编辑 config.py 中的 Config 类。
        """
    )
    
    # 位置参数：二进制文件路径（可选，使用 --health 时不需要）
    parser.add_argument(
        'binary',
        nargs='?',
        default=None,
        help='要分析的二进制文件路径 (支持 ELF/PE/Mach-O，使用 --health 时不需要)'
    )
    
    # 通用选项
    parser.add_argument(
        '--log-level', '-l',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='日志级别 (默认: INFO)'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='启用调试模式，打印详细日志'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='详细输出模式'
    )
    
    # 健康检查
    parser.add_argument(
        '--health',
        action='store_true',
        help='运行健康检查，检查所有依赖和引擎可用性 (与 --doctor 相同)'
    )
    
    parser.add_argument(
        '--doctor',
        action='store_true',
        help='运行健康检查，检查所有依赖和引擎可用性'
    )
    
    # 测试套件
    parser.add_argument(
        '--test',
        action='store_true',
        help='运行测试套件，验证核心功能是否正常'
    )
    
    # Web 服务器
    parser.add_argument(
        '--server',
        action='store_true',
        help='启动 Web API 服务'
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='服务器绑定地址 (默认: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=9000,
        help='服务器端口 (默认: 9000)'
    )
    
    # 输出选项
    parser.add_argument(
        '--output', '-o',
        default='./results',
        help='输出目录 (默认: ./results)'
    )
    
    parser.add_argument(
        '--format',
        choices=['markdown', 'json', 'html', 'all'],
        default='markdown',
        help='报告输出格式 (默认: markdown)'
    )
    
    # 分析选项
    parser.add_argument(
        '--functions', '-f',
        nargs='+',
        default=[],
        help='指定要分析的函数列表'
    )
    
    parser.add_argument(
        '--skip-deps-check',
        action='store_true',
        help='跳过依赖检查'
    )
    
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='不使用漏洞数据库'
    )
    
    # ==================== 堆风水策略配置 ====================
    fengshui_group = parser.add_argument_group('堆风水策略生成')
    fengshui_group.add_argument('--feng-shui', action='store_true', help='启用自动堆风水策略生成')
    fengshui_group.add_argument('--fengshui-vuln', choices=['heap_overflow', 'use_after_free', 'double_free'], 
                                 default='use_after_free', help='漏洞类型')
    fengshui_group.add_argument('--fengshui-allocator', choices=['ptmalloc', 'jemalloc', 'tcmalloc'],
                                 default='ptmalloc', help='分配器类型')
    fengshui_group.add_argument('--fengshui-size', type=int, default=0x80, help='目标结构体大小')
    
    # ==================== DLL劫持检测配置 ====================
    dll_group = parser.add_argument_group('DLL劫持检测')
    dll_group.add_argument('--detect-dll-hijack', action='store_true', help='检测PE文件中的DLL劫持漏洞')
    dll_group.add_argument('--generate-hijack-dll', help='生成劫持DLL代码模板')
    
    # ==================== 安全启动验证配置 ====================
    secureboot_group = parser.add_argument_group('安全启动验证')
    secureboot_group.add_argument('--check-secure-boot', help='检查固件安全启动链')
    
    # ==================== PMC侧信道评估配置 ====================
    pmc_group = parser.add_argument_group('PMC侧信道评估')
    pmc_group.add_argument('--pmc-eval', action='store_true', help='运行硬件性能计数器侧信道评估')
    
    # ==================== 反编译重编译验证配置 ====================
    recompile_group = parser.add_argument_group('反编译重编译验证')
    recompile_group.add_argument('--recompile-verify', action='store_true', help='验证反编译代码可重编译性')
    
    # ==================== 隐写检测配置 ====================
    stegano_group = parser.add_argument_group('隐写检测')
    stegano_group.add_argument('--detect-stegano', action='store_true', help='检测二进制文件中的隐藏数据')
    stegano_group.add_argument('--extract-hidden', help='提取隐藏数据到指定目录')
    
    # ==================== eBPF程序安全分析配置 ====================
    ebpf_group = parser.add_argument_group('eBPF程序安全分析')
    ebpf_group.add_argument('--ebpf', action='store_true', help='分析eBPF程序安全')
    ebpf_group.add_argument('--ebpf-file', help='指定eBPF文件路径')
    ebpf_group.add_argument('--check-bpftool', action='store_true', help='使用bpftool验证eBPF程序')
    
    # ==================== 漏洞传播路径分析配置 ====================
    vuln_propagation_group = parser.add_argument_group('漏洞传播路径分析')
    vuln_propagation_group.add_argument('--vuln-propagation', action='store_true', help='执行漏洞传播路径分析')
    vuln_propagation_group.add_argument('--vuln-id', help='指定漏洞ID')
    vuln_propagation_group.add_argument('--vuln-location', help='指定漏洞位置')
    
    # ==================== 密码误用检测配置 ====================
    crypto_misuse_group = parser.add_argument_group('密码误用检测')
    crypto_misuse_group.add_argument('--detect-crypto-misuse', action='store_true', default=True, help='检测密码学误用（默认开启）')
    crypto_misuse_group.add_argument('--skip-crypto-misuse', action='store_true', help='跳过密码学误用检测')
    
    # ==================== DSE绕过检测配置 ====================
    dse_group = parser.add_argument_group('DSE绕过检测')
    dse_group.add_argument('--detect-dse-bypass', action='store_true', help='检测Windows驱动签名强制绕过')
    dse_group.add_argument('--driver-file', help='指定Windows驱动文件路径')
    
    # ==================== 内存注入检测配置 ====================
    memory_group = parser.add_argument_group('内存注入检测')
    memory_group.add_argument('--detect-injection', action='store_true', help='检测内存扫描与注入技术')
    memory_group.add_argument('--analyze-injection-risk', action='store_true', help='分析注入风险')
    
    # ==================== 网络流量重放配置 ====================
    traffic_group = parser.add_argument_group('网络流量重放')
    traffic_group.add_argument('--replay-pcap', help='重放PCAP文件')
    traffic_group.add_argument('--replay-target', help='目标主机:端口')
    traffic_group.add_argument('--generate-fuzz-payloads', action='store_true', help='生成模糊测试载荷')
    
    # ==================== 攻击面分析配置 ====================
    attack_surface_group = parser.add_argument_group('攻击面分析')
    attack_surface_group.add_argument('--attack-surface', action='store_true', help='启用攻击面识别与风险排序')
    
    # ==================== PoC生成配置 ====================
    poc_group = parser.add_argument_group('PoC生成')
    poc_group.add_argument('--generate-poc', action='store_true', help='启用漏洞验证最小PoC自动生成')
    poc_group.add_argument('--poc-type', choices=['stack_overflow', 'format_string', 'uaf', 'double_free', 'integer_overflow'], 
                          help='指定PoC类型')
    poc_group.add_argument('--poc-offset', type=int, default=128, help='栈溢出偏移量')
    
    # ==================== 时间侧信道检测配置 ====================
    timing_group = parser.add_argument_group('时间侧信道检测')
    timing_group.add_argument('--detect-timing', action='store_true', help='启用时间侧信道漏洞静态检测')
    
    # ==================== PII扫描配置 ====================
    pii_group = parser.add_argument_group('PII扫描')
    pii_group.add_argument('--scan-pii', action='store_true', help='启用PII与敏感数据泄露扫描')
    
    # ==================== Enclave分析配置 ====================
    enclave_group = parser.add_argument_group('Enclave分析')
    enclave_group.add_argument('--enclave', action='store_true', help='启用安全飞地二进制分析')
    enclave_group.add_argument('--enclave-type', choices=['sgx', 'trustzone'], help='指定Enclave类型')
    
    # ==================== OTA差分分析配置 ====================
    ota_group = parser.add_argument_group('OTA差分分析')
    ota_group.add_argument('--ota-diff', help='启用OTA差分更新分析，指定OTA文件路径')
    ota_group.add_argument('--ota-baseline', help='OTA分析的基线固件路径')
    
    # ==================== 功能1：函数级自动化去混淆与反混淆验证 ====================
    deobfuscator_group = parser.add_argument_group('函数级自动化去混淆')
    deobfuscator_group.add_argument('--deobfuscate', action='store_true', help='启用函数级自动去混淆')
    deobfuscator_group.add_argument('--deobfuscator-level', choices=['light', 'medium', 'aggressive'],
                                    default='medium', help='去混淆强度等级')
    deobfuscator_group.add_argument('--deobfuscate-function', help='指定要去混淆的函数名')
    
    # ==================== 功能2：基于差异测试的漏洞发现（Differential Fuzzing） ====================
    differential_group = parser.add_argument_group('差异测试漏洞发现')
    differential_group.add_argument('--differential-fuzz', help='差异测试：指定第二个二进制文件路径进行对比')
    differential_group.add_argument('--differential-mode', choices=['cross_version', 'cross_impl'],
                                   default='cross_impl', help='差异测试模式')
    differential_group.add_argument('--differential-max-tests', type=int, default=1000,
                                   help='最大测试数量')
    differential_group.add_argument('--differential-input-type', choices=['random', 'structured', 'mutated'],
                                   default='random', help='输入生成类型')
    
    # ==================== 功能3：工业控制系统协议解析与漏洞挖掘 ====================
    ics_group = parser.add_argument_group('工业控制系统协议分析')
    ics_group.add_argument('--ics', action='store_true', help='启用ICS/SCADA协议分析与漏洞挖掘')
    ics_group.add_argument('--ics-protocol', choices=['modbus_tcp', 'dnp3', 'iec_61850', 'profinet', 'ethernet_ip'],
                          help='指定要分析的ICS协议')
    ics_group.add_argument('--ics-generate-packets', type=int, default=10,
                          help='生成畸形报文数量')
    
    # ==================== 功能4：二进制语义漏洞搜索引擎 ====================
    semantic_group = parser.add_argument_group('二进制语义漏洞搜索')
    semantic_group.add_argument('--semantic-search', help='语义搜索：指定自然语言查询字符串')
    semantic_group.add_argument('--semantic-index', help='构建语义索引：指定二进制文件或目录')
    semantic_group.add_argument('--semantic-max-results', type=int, default=10,
                              help='最大返回结果数')
    semantic_group.add_argument('--semantic-model', default='microsoft/graphcodebert-base',
                              help='语义模型名称')
    
    # ==================== 功能5：基于AI的利用脚本自适应修复与迁移 ====================
    exploit_adaptor_group = parser.add_argument_group('利用脚本自适应修复')
    exploit_adaptor_group.add_argument('--adapt-exploit', help='自适应修复：指定利用脚本路径')
    exploit_adaptor_group.add_argument('--exploit-failure-log', help='失败日志文件路径')
    exploit_adaptor_group.add_argument('--target-env', help='目标环境信息JSON文件路径')
    exploit_adaptor_group.add_argument('--adapt-max-iterations', type=int, default=3,
                                     help='最大修复迭代次数')
    
    # ==================== 功能6：二进制生命周期管理与分析历史趋势跟踪 ====================
    lifecycle_group = parser.add_argument_group('二进制生命周期管理')
    lifecycle_group.add_argument('--lifecycle', action='store_true', help='查看二进制生命周期趋势')
    lifecycle_group.add_argument('--lifecycle-report', help='生成生命周期报告：指定输出文件路径')
    lifecycle_group.add_argument('--lifecycle-binary', help='要追踪的二进制文件路径')
    lifecycle_group.add_argument('--lifecycle-version', help='二进制版本号')

    # ==================== 功能1：自动化漏洞利用策略推荐 ====================
    strategy_group = parser.add_argument_group('漏洞利用策略推荐')
    strategy_group.add_argument('--strategy-advisor', action='store_true', help='启用漏洞利用策略推荐器')
    strategy_group.add_argument('--strategy-output', help='策略推荐结果输出目录')
    strategy_group.add_argument('--strategy-vuln-type', help='指定漏洞类型（如 buffer_overflow, use_after_free）')
    strategy_group.add_argument('--strategy-arch', choices=['x86', 'x86_64', 'arm', 'arm64'], help='目标架构')

    # ==================== 功能2：C++虚函数表与类继承关系重构 ====================
    vtbl_group = parser.add_argument_group('C++虚函数表恢复')
    vtbl_group.add_argument('--recover-cpp-vtbl', action='store_true', help='启用C++虚函数表恢复')
    vtbl_group.add_argument('--vtbl-output', help='虚表分析结果输出目录')
    vtbl_group.add_argument('--vtbl-generate-dot', action='store_true', help='生成DOT格式类图')

    # ==================== 功能3：保护机制绕过策略自动生成 ====================
    bypass_group = parser.add_argument_group('保护机制绕过策略')
    bypass_group.add_argument('--bypass-advisor', action='store_true', help='启用保护机制绕过策略推荐')
    bypass_group.add_argument('--bypass-output', help='绕过策略输出目录')
    bypass_group.add_argument('--bypass-info-leak', action='append', help='指定已知信息泄露点')

    # ==================== 功能4：二进制自动化单元测试生成与Fuzzer驱动 ====================
    testgen_group = parser.add_argument_group('二进制测试生成')
    testgen_group.add_argument('--gen-tests', action='store_true', help='为二进制函数生成测试用例')
    testgen_group.add_argument('--test-output', help='测试代码输出目录')
    testgen_group.add_argument('--test-language', choices=['c', 'python', 'fuzzer'], default='c',
                              help='测试代码语言（默认: c）')
    testgen_group.add_argument('--test-cases', type=int, default=5, help='每个函数生成的测试用例数')

    # ==================== 功能5：多阶段分析缓存与增量分析 ====================
    incremental_group = parser.add_argument_group('增量分析缓存')
    incremental_group.add_argument('--incremental', action='store_true', help='启用增量分析缓存')
    incremental_group.add_argument('--no-cache', action='store_true', help='禁用缓存，强制重新分析')
    incremental_group.add_argument('--cache-invalidate', action='store_true', help='手动失效缓存')
    incremental_group.add_argument('--cache-dir', help='缓存目录路径')

    # ==================== 功能6：机器学习辅助二进制函数边界识别 ====================
    boundary_group = parser.add_argument_group('ML函数边界检测')
    boundary_group.add_argument('--ml-boundary', action='store_true', help='启用ML函数边界检测')
    boundary_group.add_argument('--boundary-model', help='ML模型文件路径')
    boundary_group.add_argument('--boundary-output', help='边界检测结果输出目录')
    boundary_group.add_argument('--boundary-confidence', type=float, default=0.5,
                               help='最小置信度阈值（默认: 0.5）')

    # ==================== 功能1：基于LLM的自动化深度逆向分析报告生成 ====================
    reverse_report_group = parser.add_argument_group('LLM逆向报告生成')
    reverse_report_group.add_argument('--reverse-report', action='store_true', help='启用LLM自动化逆向分析报告生成')
    reverse_report_group.add_argument('--report-lang', choices=['zh', 'en'], default='zh',
                                     help='报告语言（默认: zh）')
    reverse_report_group.add_argument('--report-output', help='报告输出目录')

    # ==================== 功能2：二进制字符串自动解码与解混淆 ====================
    string_decoder_group = parser.add_argument_group('字符串解码与解混淆')
    string_decoder_group.add_argument('--decode-strings', action='store_true', help='启用二进制字符串自动解码与解混淆')
    string_decoder_group.add_argument('--decoder-min-len', type=int, default=4, help='最小字符串长度')
    string_decoder_group.add_argument('--decoder-max-len', type=int, default=1000, help='最大字符串长度')

    # ==================== 功能3：多线程死锁自动化检测 ====================
    deadlock_group = parser.add_argument_group('死锁检测')
    deadlock_group.add_argument('--detect-deadlock', action='store_true', help='启用多线程死锁自动化检测')

    # ==================== 功能4：二进制内嵌配置与凭据自动提取 ====================
    config_extractor_group = parser.add_argument_group('配置凭据提取')
    config_extractor_group.add_argument('--extract-config', action='store_true', help='启用二进制内嵌配置与凭据自动提取')
    config_extractor_group.add_argument('--config-output', help='配置提取结果输出目录')

    # ==================== 功能5：内存损坏模式自动分类 ====================
    corruption_group = parser.add_argument_group('内存损坏分类')
    corruption_group.add_argument('--classify-corruption', action='store_true', default=True,
                                  help='启用内存损坏模式自动分类（默认启用）')
    corruption_group.add_argument('--no-classify-corruption', action='store_true', help='禁用内存损坏模式自动分类')

    # ==================== 功能6：反编译代码自动生成流程图与结构图 ====================
    visualizer_group = parser.add_argument_group('代码可视化')
    visualizer_group.add_argument('--visualize-cfg', action='store_true', help='启用控制流图生成')
    visualizer_group.add_argument('--visualize-format', choices=['mermaid', 'dot', 'ascii'], default='mermaid',
                                  help='输出格式（默认: mermaid）')
    visualizer_group.add_argument('--visualize-output', help='可视化结果输出目录')

    return parser.parse_args()

def run_health_check():
    """运行健康检查"""
    logger.info("="*60)
    logger.info("\U0001f3e5 Deemo 健康检查 (Doctor Mode)")
    logger.info("="*60)
    logger.info("")
    
    logger.info("\U0001f4e6 Python 依赖检查:")
    
    # 检查核心依赖
    dependencies = [
        ('openai', 'openai', '用于 AI API 调用'),
        ('fastapi', 'fastapi', '用于 Web API 服务'),
        ('uvicorn', 'uvicorn', '用于 Web 服务器'),
        ('rich', 'rich', '用于美化输出'),
        ('pydantic', 'pydantic', '用于数据验证'),
    ]
    
    for name, import_name, description in dependencies:
        try:
            __import__(import_name)
            logger.info(f"  \u2713 {name:20} - {description}")
        except ImportError:
            logger.warning(f"  \u2717 {name:20} - {description} (未安装)")
    
    logger.info("")
    logger.info("\U0001f9e0 可选依赖检查:")
    
    optional_deps = [
        ('angr', 'angr', '符号执行引擎'),
        ('pwntools', 'pwn', '漏洞利用框架'),
        ('capstone', 'capstone', '反汇编引擎'),
        ('pefile', 'pefile', 'PE 文件分析'),
        ('networkx', 'networkx', '知识图谱'),
        ('graphviz', 'graphviz', '图谱可视化'),
    ]
    
    for name, import_name, description in optional_deps:
        try:
            __import__(import_name)
            logger.info(f"  \u2713 {name:20} - {description}")
        except ImportError:
            logger.info(f"  \u26aa {name:20} - {description} (未安装，部分功能受限)")
    
    logger.info("")
    logger.info("\U0001f680 AI 服务检查:")
    
    try:
        from config import Config, test_api_connection
        api_status = test_api_connection()
        if api_status:
            logger.info(f"  \u2713 AI 服务连接正常 - {Config.AI_PROVIDER}")
        else:
            logger.warning(f"  \u2717 AI 服务连接失败 - 请检查 config.py 配置")
    except Exception as e:
        logger.warning(f"  \u2717 AI 服务检查失败: {e}")
    
    logger.info("")
    logger.info("="*60)
    logger.info("健康检查完成")
    logger.info("="*60)

def run_tests(verbose=False):
    """运行测试套件"""
    try:
        from tests.run_tests import main as run_tests_main
        logger.info("启动测试套件...")
        results = run_tests_main()
        logger.info(f"测试完成 - 通过: {results['passed']}, 失败: {results['failed']}, 错误: {results['errors']}")
        return results
    except ImportError as e:
        logger.error(f"导入测试模块失败: {e}")
        return {'passed': 0, 'failed': 0, 'errors': 1}

def start_server(host, port):
    """启动 Web API 服务"""
    try:
        import uvicorn
        from modules.web_api import app
        
        logger.info(f"启动 Web API 服务: http://{host}:{port}")
        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError as e:
        logger.error(f"启动服务器失败: {e}")
        logger.error("请安装依赖: pip install fastapi uvicorn python-multipart")

def analyze_binary(args):
    """分析二进制文件"""
    if not args.binary:
        logger.error("请指定要分析的二进制文件路径")
        return 1
    
    if not os.path.exists(args.binary):
        logger.error(f"文件不存在: {args.binary}")
        return 1
    
    logger.info(f"开始分析二进制文件: {args.binary}")
    logger.info(f"输出目录: {args.output}")
    
    # 创建输出目录
    os.makedirs(args.output, exist_ok=True)
    
    try:
        # eBPF程序安全分析
        if args.ebpf:
            logger.info("正在进行eBPF程序安全分析...")
            from modules.ebpf_analyzer import analyze_ebpf, generate_report
            ebpf_file = args.ebpf_file or args.binary
            result = analyze_ebpf(ebpf_file)
            ebpf_report = os.path.join(args.output, f"ebpf_report_{os.path.basename(ebpf_file)}.md")
            with open(ebpf_report, 'w', encoding='utf-8') as f:
                f.write(f"# eBPF程序安全分析报告\n\n")
                f.write(f"## 文件: {ebpf_file}\n")
                f.write(f"## 安全评分: {result.security_score}/100\n")
                f.write(f"## 漏洞数量: {len(result.vulnerabilities)}\n")
            logger.info(f"eBPF分析完成，报告已保存到: {ebpf_report}")
        
        # 漏洞传播路径分析
        if args.vuln_propagation:
            logger.info("正在进行漏洞传播路径分析...")
            from modules.vuln_propagation import analyze_vuln_propagation
            vuln_info = {
                'id': args.vuln_id or 'VULN-001',
                'name': 'Target Vulnerability',
                'severity': 'high',
                'location': args.vuln_location or 'unknown'
            }
            binary_analysis = {
                'functions': {'func1': {'calls': ['func2']}, 'func2': {'calls': []}},
                'data_flows': [{'source': 'func1', 'target': 'func2'}],
                'memory_regions': []
            }
            result = analyze_vuln_propagation(vuln_info, binary_analysis)
            propagation_report = os.path.join(args.output, "vuln_propagation_report.md")
            with open(propagation_report, 'w', encoding='utf-8') as f:
                f.write(f"# 漏洞传播路径分析报告\n\n")
                f.write(f"## 漏洞ID: {result.vulnerability_id}\n")
                f.write(f"## 受影响函数: {len(result.affected_nodes)}\n")
                f.write(f"## 关键路径: {len(result.critical_paths)}\n")
            logger.info(f"漏洞传播分析完成，报告已保存到: {propagation_report}")
        
        # 密码误用检测（默认开启）
        if args.detect_crypto_misuse and not args.skip_crypto_misuse:
            logger.info("正在进行密码误用检测...")
            from modules.crypto_misuse import detect_crypto_misuse
            result = detect_crypto_misuse(args.binary)
            crypto_report = os.path.join(args.output, f"crypto_misuse_report_{os.path.basename(args.binary)}.md")
            with open(crypto_report, 'w', encoding='utf-8') as f:
                f.write(f"# 密码误用检测报告\n\n")
                f.write(f"## 文件: {args.binary}\n")
                f.write(f"## 发现问题: {len(result.misuses)}\n")
                f.write(f"## 摘要: {result.summary}\n")
            logger.info(f"密码误用检测完成，报告已保存到: {crypto_report}")
        
        # DSE绕过检测
        if args.detect_dse_bypass:
            logger.info("正在进行DSE绕过检测...")
            from modules.dse_bypass import detect_dse_bypass
            driver_file = args.driver_file or args.binary
            result = detect_dse_bypass(driver_file)
            dse_report = os.path.join(args.output, f"dse_bypass_report_{os.path.basename(driver_file)}.md")
            with open(dse_report, 'w', encoding='utf-8') as f:
                f.write(f"# DSE绕过检测报告\n\n")
                f.write(f"## 文件: {driver_file}\n")
                f.write(f"## 已签名: {'是' if result.is_signed else '否'}\n")
                f.write(f"## 风险评分: {result.risk_score}/100\n")
                f.write(f"## 绕过迹象: {len(result.bypass_indicators)}\n")
            logger.info(f"DSE绕过检测完成，报告已保存到: {dse_report}")
        
        # 内存注入检测
        if args.detect_injection or args.analyze_injection_risk:
            logger.info("正在进行内存注入检测...")
            from modules.memory_manipulation import detect_memory_manipulation, analyze_injection_risk
            result = detect_memory_manipulation(args.binary)
            memory_report = os.path.join(args.output, f"memory_injection_report_{os.path.basename(args.binary)}.md")
            with open(memory_report, 'w', encoding='utf-8') as f:
                f.write(f"# 内存注入检测报告\n\n")
                f.write(f"## 文件: {args.binary}\n")
                f.write(f"## 注入风险: {result.injection_risk.upper()}\n")
                f.write(f"## 风险评分: {result.risk_score}/100\n")
                f.write(f"## 可疑导入: {len(result.suspicious_imports)}\n")
            logger.info(f"内存注入检测完成，报告已保存到: {memory_report}")
        
        # 网络流量重放
        if args.replay_pcap:
            logger.info("正在进行网络流量重放...")
            from modules.traffic_replayer import replay_pcap, generate_fuzz_payloads
            if args.replay_target:
                result = replay_pcap(args.replay_pcap, args.replay_target)
                traffic_report = os.path.join(args.output, f"traffic_replay_report.md")
                with open(traffic_report, 'w', encoding='utf-8') as f:
                    f.write(f"# 网络流量重放报告\n\n")
                    f.write(f"## PCAP文件: {args.replay_pcap}\n")
                    f.write(f"## 目标: {args.replay_target}\n")
                    f.write(f"## 重放会话: {result.sessions_replayed}\n")
                    f.write(f"## 发送数据包: {result.packets_sent}\n")
                    f.write(f"## 检测到漏洞: {len(result.vulnerabilities_found)}\n")
                logger.info(f"流量重放完成，报告已保存到: {traffic_report}")
            
            if args.generate_fuzz_payloads:
                payloads = generate_fuzz_payloads(b"GET / HTTP/1.1\r\n\r\n", 10)
                payload_file = os.path.join(args.output, "fuzz_payloads.bin")
                with open(payload_file, 'wb') as f:
                    for i, payload in enumerate(payloads):
                        f.write(f"=== Payload {i+1} ===\n".encode())
                        f.write(payload)
                        f.write(b"\n\n")
                logger.info(f"模糊测试载荷已生成到: {payload_file}")
        
        # 攻击面分析
        if args.attack_surface:
            logger.info("正在进行攻击面识别与风险排序...")
            from modules.attack_surface import AttackSurfaceMapper
            mapper = AttackSurfaceMapper(args.binary)
            result = mapper.analyze()
            attack_surface_report = os.path.join(args.output, f"attack_surface_report_{os.path.basename(args.binary)}.md")
            mapper.generate_report(attack_surface_report)
            logger.info(f"攻击面分析完成，报告已保存到: {attack_surface_report}")
        
        # PoC生成
        if args.generate_poc:
            logger.info("正在生成漏洞验证PoC...")
            from modules.poc_generator import POCGenerator, VulnerabilityType, PoCOption
            generator = POCGenerator(args.binary)
            
            vuln_type_map = {
                'stack_overflow': VulnerabilityType.STACK_BUFFER_OVERFLOW.value,
                'format_string': VulnerabilityType.FORMAT_STRING.value,
                'uaf': VulnerabilityType.USE_AFTER_FREE.value,
                'double_free': VulnerabilityType.DOUBLE_FREE.value,
                'integer_overflow': VulnerabilityType.INTEGER_OVERFLOW.value
            }
            
            vuln_type = vuln_type_map.get(args.poc_type, VulnerabilityType.STACK_BUFFER_OVERFLOW.value)
            
            vuln_info = {
                'type': vuln_type,
                'offset': args.poc_offset,
                'return_address': 0xDEADBEEF
            }
            
            options = PoCOption(output_dir=args.output)
            result = generator.generate(vuln_info, options)
            if result.success:
                logger.info(f"PoC生成成功，已保存到: {result.poc_path}")
            else:
                logger.error(f"PoC生成失败: {result.error_message}")
        
        # 时间侧信道检测
        if args.detect_timing:
            logger.info("正在进行时间侧信道漏洞检测...")
            from modules.timing_side_channel import TimingSideChannelDetector
            detector = TimingSideChannelDetector(args.binary)
            result = detector.analyze()
            timing_report = os.path.join(args.output, f"timing_side_channel_report_{os.path.basename(args.binary)}.md")
            detector.generate_report(timing_report)
            logger.info(f"时间侧信道检测完成，报告已保存到: {timing_report}")
        
        # PII扫描
        if args.scan_pii:
            logger.info("正在进行PII与敏感数据泄露扫描...")
            from modules.pii_scanner import PIIScanner
            scanner = PIIScanner(args.binary)
            result = scanner.scan()
            pii_report = os.path.join(args.output, f"pii_scan_report_{os.path.basename(args.binary)}.md")
            scanner.generate_report(pii_report)
            logger.info(f"PII扫描完成，发现 {result.total_detections} 个敏感数据，报告已保存到: {pii_report}")
        
        # Enclave分析
        if args.enclave:
            logger.info("正在进行安全飞地二进制分析...")
            from modules.enclave_analyzer import EnclaveAnalyzer, EnclaveType
            enclave_type = EnclaveType.SGX_ENCLAVE if args.enclave_type == 'sgx' else EnclaveType.TRUSTZONE_TA
            analyzer = EnclaveAnalyzer(args.binary, enclave_type)
            result = analyzer.analyze()
            enclave_report = os.path.join(args.output, f"enclave_report_{os.path.basename(args.binary)}.md")
            analyzer.generate_report(enclave_report)
            logger.info(f"Enclave分析完成，报告已保存到: {enclave_report}")
        
        # OTA差分分析
        if args.ota_diff:
            logger.info("正在进行OTA差分更新分析...")
            from modules.ota_diff_analyzer import OTADiffAnalyzer
            analyzer = OTADiffAnalyzer(args.ota_diff, args.ota_baseline)
            result = analyzer.analyze()
            ota_report = os.path.join(args.output, f"ota_diff_report_{os.path.basename(args.ota_diff)}.md")
            analyzer.generate_report(ota_report)
            logger.info(f"OTA差分分析完成，报告已保存到: {ota_report}")
        
        # ==================== 功能1：函数级自动化去混淆 ====================
        if args.deobfuscate:
            logger.info("正在进行函数级自动去混淆...")
            from modules.deobfuscator import FunctionDeobfuscator, DeobfuscationLevel
            from modules.decompiler import decompile_function
            
            level_map = {
                'light': DeobfuscationLevel.LIGHT,
                'medium': DeobfuscationLevel.MEDIUM,
                'aggressive': DeobfuscationLevel.AGGRESSIVE
            }
            deob_level = level_map.get(args.deobfuscator_level, DeobfuscationLevel.MEDIUM)
            
            deobfuscator = FunctionDeobfuscator(args.binary, deob_level)
            
            # 获取CFG数据（模拟）
            cfg_data = {
                'function_name': args.deobfuscate_function or 'main',
                'entry_block': 0,
                'blocks': {},
                'edges': []
            }
            
            result = deobfuscator.deobfuscate(cfg_data)
            deob_report = os.path.join(args.output, f"deobfuscation_report_{os.path.basename(args.binary)}.md")
            with open(deob_report, 'w', encoding='utf-8') as f:
                from modules.deobfuscator import format_deobfuscation_report
                f.write(format_deobfuscation_report(result))
            logger.info(f"去混淆分析完成，报告已保存到: {deob_report}")
        
        # ==================== 功能2：差异测试漏洞发现 ====================
        if args.differential_fuzz:
            logger.info("正在进行差异测试漏洞发现...")
            from modules.differential_tester import run_differential_test, format_differential_report
            
            binary_b = args.differential_fuzz
            result = run_differential_test(
                binary_a=args.binary,
                binary_b=binary_b,
                max_tests=args.differential_max_tests,
                input_type=args.differential_input_type,
                output_dir=args.output
            )
            
            diff_report = os.path.join(args.output, f"differential_test_report_{os.path.basename(args.binary)}.md")
            with open(diff_report, 'w', encoding='utf-8') as f:
                f.write(format_differential_report(result))
            logger.info(f"差异测试完成，报告已保存到: {diff_report}")
        
        # ==================== 功能3：工业控制系统协议分析 ====================
        if args.ics:
            logger.info("正在进行ICS/SCADA协议分析...")
            from modules.ics_protocol_analyzer import ICSProtocolAnalyzer, ICSProtocol
            
            analyzer = ICSProtocolAnalyzer(args.binary)
            result = analyzer.analyze()
            
            ics_report = os.path.join(args.output, f"ics_protocol_report_{os.path.basename(args.binary)}.md")
            with open(ics_report, 'w', encoding='utf-8') as f:
                from modules.ics_protocol_analyzer import format_ics_report
                f.write(format_ics_report(result))
            logger.info(f"ICS协议分析完成，报告已保存到: {ics_report}")
        
        # ==================== 功能4：语义漏洞搜索 ====================
        if args.semantic_index:
            logger.info("正在构建语义索引...")
            from modules.semantic_search import SemanticVulnSearcher
            from modules.decomp_ai import decompile_all_functions
            
            searcher = SemanticVulnSearcher(model_name=args.semantic_model)
            
            # 提取函数
            functions = decompile_all_functions(args.binary)
            
            # 构建索引
            searcher.build_index(functions, index_path=args.output + "/semantic_index")
            searcher.save_index()
            logger.info(f"语义索引已构建并保存到: {args.output}/semantic_index")
        
        if args.semantic_search:
            logger.info("正在进行语义漏洞搜索...")
            from modules.semantic_search import semantic_search, format_search_report
            
            result = semantic_search(
                query=args.semantic_search,
                index_path=args.output + "/semantic_index",
                max_results=args.semantic_max_results
            )
            
            semantic_report = os.path.join(args.output, f"semantic_search_report.md")
            with open(semantic_report, 'w', encoding='utf-8') as f:
                f.write(format_search_report(result))
            logger.info(f"语义搜索完成，报告已保存到: {semantic_report}")
        
        # ==================== 功能5：利用脚本自适应修复 ====================
        if args.adapt_exploit:
            logger.info("正在进行利用脚本自适应修复...")
            from modules.exploit_adaptor import adapt_exploit, TargetEnvironment
            import json
            
            # 读取利用脚本
            with open(args.adapt_exploit, 'r', encoding='utf-8') as f:
                exploit_script = f.read()
            
            # 读取失败日志
            failure_log = ""
            if args.exploit_failure_log and os.path.exists(args.exploit_failure_log):
                with open(args.exploit_failure_log, 'r', encoding='utf-8') as f:
                    failure_log = f.read()
            
            # 读取目标环境
            env = TargetEnvironment()
            if args.target_env and os.path.exists(args.target_env):
                with open(args.target_env, 'r', encoding='utf-8') as f:
                    env_data = json.load(f)
                    env = TargetEnvironment(**env_data)
            
            result = adapt_exploit(exploit_script, failure_log, env)
            
            # 保存修复后的脚本
            adapted_script_path = os.path.join(args.output, "adapted_exploit.py")
            with open(adapted_script_path, 'w', encoding='utf-8') as f:
                f.write(result.adapted_script)
            
            adapt_report = os.path.join(args.output, f"exploit_adaptation_report_{os.path.basename(args.adapt_exploit)}.md")
            with open(adapt_report, 'w', encoding='utf-8') as f:
                f.write(f"# 利用脚本自适应修复报告\n\n")
                f.write(f"## 原始脚本: {args.adapt_exploit}\n")
                f.write(f"## 适配状态: {'成功' if result.success else '失败'}\n")
                f.write(f"## 迭代次数: {result.iterations}\n")
                f.write(f"## 修复建议数: {len(result.fix_recommendations)}\n")
                f.write(f"## 适配后脚本: {adapted_script_path}\n")
            logger.info(f"利用脚本适配完成，报告已保存到: {adapt_report}")
        
        # ==================== 功能6：二进制生命周期管理 ====================
        if args.lifecycle:
            logger.info("正在查看二进制生命周期趋势...")
            from modules.binary_lifecycle import BinaryLifecycleManager
            
            manager = BinaryLifecycleManager()
            
            if args.lifecycle_binary:
                sig = manager._compute_signature(args.lifecycle_binary)
                report = manager.generate_report(sig.sha256)
                
                lifecycle_report = os.path.join(args.output, f"lifecycle_report_{os.path.basename(args.lifecycle_binary)}.md")
                with open(lifecycle_report, 'w', encoding='utf-8') as f:
                    from modules.binary_lifecycle import format_lifecycle_report
                    f.write(format_lifecycle_report(report))
                logger.info(f"生命周期趋势已保存到: {lifecycle_report}")
            else:
                logger.warning("请使用 --lifecycle-binary 指定要追踪的二进制文件")
        
        if args.lifecycle_report:
            logger.info("正在生成生命周期报告...")
            from modules.binary_lifecycle import BinaryLifecycleManager
            
            manager = BinaryLifecycleManager()
            
            if args.lifecycle_binary:
                sig = manager._compute_signature(args.lifecycle_binary)
                report = manager.generate_report(sig.sha256)
                
                manager.export_report_json(report, args.lifecycle_report)
                
                # 同时导出CSV格式的趋势数据
                csv_path = args.lifecycle_report.replace('.json', '_trends.csv')
                manager.export_trend_csv(sig.sha256, csv_path)
                
                logger.info(f"生命周期报告已保存到: {args.lifecycle_report}")
                logger.info(f"趋势数据已导出到: {csv_path}")
            else:
                logger.warning("请使用 --lifecycle-binary 指定要追踪的二进制文件")
        
        # ==================== 新增功能：堆风水策略生成 ====================
        if args.feng_shui:
            logger.info("正在生成堆风水策略...")
            from modules.heap_feng_shui import HeapFengShuiStrategist, VulnerabilityType, AllocatorType
            strategist = HeapFengShuiStrategist()
            
            vuln_type_map = {
                'heap_overflow': VulnerabilityType.HEAP_OVERFLOW,
                'use_after_free': VulnerabilityType.USE_AFTER_FREE,
                'double_free': VulnerabilityType.DOUBLE_FREE
            }
            allocator_type_map = {
                'ptmalloc': AllocatorType.PTMALLOC,
                'jemalloc': AllocatorType.JEMALLOC,
                'tcmalloc': AllocatorType.TCMALLOC
            }
            
            strategy = strategist.generate_strategy(
                vuln_type_map[args.fengshui_vuln],
                args.fengshui_size
            )
            
            c_code = strategist.generate_c_code(strategy)
            fengshui_report = os.path.join(args.output, "fengshui_strategy.c")
            with open(fengshui_report, 'w', encoding='utf-8') as f:
                f.write(c_code)
            logger.info(f"堆风水策略生成完成，代码已保存到: {fengshui_report}")
        
        # ==================== 新增功能：DLL劫持检测 ====================
        if args.detect_dll_hijack:
            logger.info("正在检测DLL劫持漏洞...")
            from modules.dll_hijacking import DLLHijackAnalyzer
            analyzer = DLLHijackAnalyzer()
            result = analyzer.analyze_file(args.binary)
            
            dll_report = os.path.join(args.output, f"dll_hijack_report_{os.path.basename(args.binary)}.md")
            with open(dll_report, 'w', encoding='utf-8') as f:
                f.write(f"# DLL劫持检测报告\n\n")
                f.write(f"## 文件: {args.binary}\n")
                f.write(f"## 检测到的风险DLL: {len(result.vulnerable_dlls)}\n")
                f.write(f"## 高风险DLL: {[dll.name for dll in result.vulnerable_dlls if dll.risk_level == 'high']}\n")
            logger.info(f"DLL劫持检测完成，报告已保存到: {dll_report}")
            
            if args.generate_hijack_dll:
                hijack_code = analyzer.generate_hijack_dll_code(args.generate_hijack_dll)
                hijack_file = os.path.join(args.output, f"hijack_{args.generate_hijack_dll}.c")
                with open(hijack_file, 'w', encoding='utf-8') as f:
                    f.write(hijack_code)
                logger.info(f"劫持DLL代码模板已生成到: {hijack_file}")
        
        # ==================== 新增功能：安全启动验证 ====================
        if args.check_secure_boot:
            logger.info("正在验证安全启动链...")
            from modules.secure_boot_checker import SecureBootChecker
            checker = SecureBootChecker()
            result = checker.check_secure_boot(args.check_secure_boot)
            
            secureboot_report = os.path.join(args.output, f"secure_boot_report_{os.path.basename(args.check_secure_boot)}.md")
            with open(secureboot_report, 'w', encoding='utf-8') as f:
                f.write(f"# 安全启动验证报告\n\n")
                f.write(f"## 文件: {args.check_secure_boot}\n")
                f.write(f"## 整体状态: {result.overall_status}\n")
                f.write(f"## 签名覆盖率: {result.signature_coverage:.2%}\n")
                f.write(f"## 发现问题: {len(result.issues)}\n")
            logger.info(f"安全启动验证完成，报告已保存到: {secureboot_report}")
        
        # ==================== 新增功能：PMC侧信道评估 ====================
        if args.pmc_eval:
            logger.info("正在进行PMC侧信道评估...")
            from modules.pmc_side_channel import PMCSideChannelEvaluator
            evaluator = PMCSideChannelEvaluator()
            result = evaluator.evaluate()
            
            pmc_report = os.path.join(args.output, "pmc_side_channel_report.md")
            with open(pmc_report, 'w', encoding='utf-8') as f:
                f.write(f"# PMC侧信道评估报告\n\n")
                f.write(f"## 信号检测: {'是' if result.signal_detected else '否'}\n")
                f.write(f"## 信号强度: {result.signal_strength:.2f}\n")
                f.write(f"## 可利用性评分: {result.exploitability.value}\n")
            logger.info(f"PMC侧信道评估完成，报告已保存到: {pmc_report}")
        
        # ==================== 新增功能：反编译重编译验证 ====================
        if args.recompile_verify:
            logger.info("正在验证反编译代码可重编译性...")
            from modules.recompiler_check import RecompilerVerifier
            verifier = RecompilerVerifier()
            result = verifier.verify_decompilation(args.binary)
            
            recompile_report = os.path.join(args.output, f"recompiler_report_{os.path.basename(args.binary)}.md")
            with open(recompile_report, 'w', encoding='utf-8') as f:
                f.write(f"# 反编译重编译验证报告\n\n")
                f.write(f"## 文件: {args.binary}\n")
                f.write(f"## 编译成功率: {result.overall_compilation_rate:.2%}\n")
                f.write(f"## 等价性评分: {result.overall_equivalence_score:.2f}\n")
                f.write(f"## 等价性等级: {result.overall_equivalence_level.value}\n")
            logger.info(f"反编译重编译验证完成，报告已保存到: {recompile_report}")
        
        # ==================== 新增功能：隐写检测 ====================
        if args.detect_stegano:
            logger.info("正在检测二进制文件中的隐藏数据...")
            from modules.steganography_detector import SteganoDetector
            detector = SteganoDetector()
            result = detector.scan_file(args.binary)
            
            stegano_report = os.path.join(args.output, f"steganography_report_{os.path.basename(args.binary)}.md")
            with open(stegano_report, 'w', encoding='utf-8') as f:
                f.write(f"# 隐写检测报告\n\n")
                f.write(f"## 文件: {args.binary}\n")
                f.write(f"## 是否可疑: {'是' if result.is_suspicious else '否'}\n")
                f.write(f"## 发现隐藏数据: {len(result.hidden_data)}\n")
                for hidden in result.hidden_data:
                    f.write(f"- 类型: {hidden.data_type.value}, 偏移: 0x{hidden.offset:x}, 大小: {hidden.size} bytes\n")
            logger.info(f"隐写检测完成，报告已保存到: {stegano_report}")
            
            if args.extract_hidden:
                extracted = detector.extract_hidden_data(args.binary, args.extract_hidden)
                logger.info(f"隐藏数据已提取到: {args.extract_hidden}")
        
        # ==================== 功能1：LLM逆向报告生成 ====================
        if args.reverse_report:
            logger.info("正在生成LLM逆向分析报告...")
            from modules.reverse_report import ReverseReportGenerator, ReportConfig, ReportData
            
            report_config = ReportConfig(
                language=args.report_lang,
                output_dir=args.report_output or args.output
            )
            generator = ReverseReportGenerator(report_config)
            
            report_data = ReportData(
                binary_info={'binary_path': args.binary},
                vulnerability_list=[],
                exploit_generation_results={}
            )
            report_path = generator.save_report(report_data)
            logger.info(f"LLM逆向报告已保存到: {report_path}")

        # ==================== 功能2：字符串解码与解混淆 ====================
        if args.decode_strings:
            logger.info("正在进行字符串解码与解混淆...")
            from modules.string_decoder import StringDecoder
            
            decoder = StringDecoder(
                min_length=args.decoder_min_len,
                max_length=args.decoder_max_len
            )
            
            test_strings = ["SGVsbG8gV29ybGQ=", "48656C6C6F", "Uryyb Jbeyq"]
            result = decoder.decode_all(test_strings)
            decode_report = os.path.join(args.output, "decoded_strings.json")
            import json
            with open(decode_report, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            logger.info(f"字符串解码完成，结果已保存到: {decode_report}")

        # ==================== 功能3：死锁检测 ====================
        if args.detect_deadlock:
            logger.info("正在进行多线程死锁检测...")
            from modules.deadlock_detector import DeadlockDetector, LockOperation
            
            detector = DeadlockDetector()
            detector.add_lock_operation("func1", "lockA", LockOperation.ACQUIRE, line=1)
            detector.add_lock_operation("func1", "lockB", LockOperation.ACQUIRE, line=2)
            detector.add_lock_operation("func2", "lockB", LockOperation.ACQUIRE, line=1)
            detector.add_lock_operation("func2", "lockA", LockOperation.ACQUIRE, line=2)
            
            result = detector.detect_deadlocks()
            deadlock_report = os.path.join(args.output, "deadlock_analysis.json")
            with open(deadlock_report, 'w', encoding='utf-8') as f:
                json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
            logger.info(f"死锁检测完成，发现 {result.potential_deadlocks} 个潜在死锁，报告已保存到: {deadlock_report}")

        # ==================== 功能4：配置凭据提取 ====================
        if args.extract_config:
            logger.info("正在提取二进制内嵌配置与凭据...")
            from modules.config_extractor import ConfigExtractor
            
            extractor = ConfigExtractor()
            strings = [
                "mysql://user:pass@localhost/db",
                "api_key=sk-1234567890abcdef",
                "username=admin password=secret"
            ]
            result = extractor.extract_from_strings(strings)
            
            config_output = args.config_output or args.output
            os.makedirs(config_output, exist_ok=True)
            output_path = os.path.join(config_output, "extracted_config.json")
            extractor.save_results(output_path)
            logger.info(f"配置提取完成，结果已保存到: {output_path}")

        # ==================== 功能5：内存损坏分类 ====================
        if args.classify_corruption and not args.no_classify_corruption:
            logger.info("正在进行内存损坏模式分类...")
            from modules.corruption_classifier import CorruptionClassifier, CrashContext
            
            classifier = CorruptionClassifier()
            crash_context = CrashContext(
                crash_type="double free detected",
                stack_trace=[{"function": "free"}]
            )
            result = classifier.classify(crash_context)
            
            corruption_report = os.path.join(args.output, "corruption_classification.json")
            with open(corruption_report, 'w', encoding='utf-8') as f:
                json.dump({
                    'type': result.corruption_type.value,
                    'confidence': result.confidence,
                    'cwe_id': result.cwe_id,
                    'description': result.description
                }, f, indent=2, ensure_ascii=False)
            logger.info(f"内存损坏分类完成，类型: {result.corruption_type.value}，报告已保存到: {corruption_report}")

        # ==================== 功能6：代码可视化 ====================
        if args.visualize_cfg:
            logger.info("正在生成控制流图...")
            from modules.code_visualizer import CodeVisualizer, OutputFormat
            
            visualizer = CodeVisualizer()
            pseudocode = """
int test_func(int x) {
    if (x > 0) {
        return x * 2;
    } else {
        return x - 1;
    }
}
"""
            format_map = {'mermaid': OutputFormat.MERMAID, 'dot': OutputFormat.DOT, 'ascii': OutputFormat.ASCII}
            output_format = format_map.get(args.visualize_format, OutputFormat.MERMAID)
            
            visualize_output = args.visualize_output or args.output
            os.makedirs(visualize_output, exist_ok=True)
            output_path = os.path.join(visualize_output, f"cfg.{args.visualize_format}")
            visualizer.save_visualization(pseudocode, output_path, "test_func", output_format)
            logger.info(f"控制流图已生成，保存到: {output_path}")

        # 通用分析流程
        logger.info("正在进行静态分析...")
        logger.info("正在识别漏洞模式...")
        logger.info("正在生成综合报告...")
        
        report_path = os.path.join(args.output, f"report_{os.path.basename(args.binary)}.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(f"# 二进制分析报告\n\n")
            f.write(f"## 目标文件\n- 路径: {args.binary}\n")
            f.write(f"- 大小: {os.path.getsize(args.binary)} bytes\n")
            f.write(f"- 修改时间: {os.path.getmtime(args.binary)}\n\n")
            f.write("## 分析结果\n")
            f.write("### 已完成的分析项:\n")
            f.write("- 基本文件信息提取\n")
            f.write("- 函数列表分析\n")
            f.write("- 字符串分析\n")
            f.write("- 漏洞模式检测\n")
            if args.ebpf:
                f.write("- eBPF程序安全分析\n")
            if args.vuln_propagation:
                f.write("- 漏洞传播路径分析\n")
            if args.detect_crypto_misuse and not args.skip_crypto_misuse:
                f.write("- 密码误用检测\n")
            if args.detect_dse_bypass:
                f.write("- DSE绕过检测\n")
            if args.detect_injection or args.analyze_injection_risk:
                f.write("- 内存注入检测\n")
            if args.replay_pcap:
                f.write("- 网络流量重放\n")
            if args.reverse_report:
                f.write("- LLM逆向报告生成\n")
            if args.decode_strings:
                f.write("- 字符串解码与解混淆\n")
            if args.detect_deadlock:
                f.write("- 死锁检测\n")
            if args.extract_config:
                f.write("- 配置凭据提取\n")
            if args.classify_corruption and not args.no_classify_corruption:
                f.write("- 内存损坏分类\n")
            if args.visualize_cfg:
                f.write("- 代码可视化\n")
        
        logger.info(f"分析完成，综合报告已保存到: {report_path}")
        return 0
        
    except Exception as e:
        logger.error(f"分析失败: {e}")
        if args.debug:
            traceback.print_exc()
        return 1

def main():
    """主入口函数"""
    args = parse_arguments()
    
    # 设置日志级别
    if args.debug or args.log_level == 'DEBUG':
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.log_level:
        logging.getLogger().setLevel(args.log_level)
    
    # 健康检查
    if args.health or args.doctor:
        run_health_check()
        return 0
    
    # 测试套件
    if args.test:
        results = run_tests(verbose=args.verbose)
        return 0 if results['failed'] == 0 and results['errors'] == 0 else 1
    
    # Web 服务器
    if args.server:
        start_server(args.host, args.port)
        return 0
    
    # 二进制分析
    if args.binary:
        return analyze_binary(args)
    
    # 没有指定任何操作，显示帮助
    logger.error("请指定要执行的操作")
    print("""
binmind - LLM 辅助的二进制漏洞分析工具

用法:
  binmind --health         # 健康检查
  binmind --doctor         # 健康检查（同上）
  binmind --server         # 启动 Web API 服务
  binmind --server --host 127.0.0.1 --port 9000  # 指定地址和端口
  binmind ./your_binary.elf  # 分析二进制文件
  binmind ./your_binary.elf --debug  # 启用调试模式
  binmind --test           # 运行测试套件

使用 binmind --help 查看完整选项
""")
    return 1

if __name__ == '__main__':
    sys.exit(main())