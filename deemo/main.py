#!/usr/bin/env python3
"""
大语言模型辅助的二进制漏洞分析工具

"""

import argparse
import logging
import os
import sys
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional

from config import (
    Config, check_openai_api_key, get_openai_client, ensure_directories, 
    validate_crash_data, get_current_ai_model, SensitiveFilter, mask_sensitive_data
)
from modules.info_collect import get_binary_info, detect_binary_format, validate_binary_path, detect_language
from modules.decomp_ai import DecompilerAI, strip_ansi_escape
from modules.crash_analysis import CrashAnalyzer, load_and_parse_crash_data
from modules.exploit_gen import ExploitGenerator
from modules.report import ReportGenerator
from modules.symbolic_exe import SymbolicExecutor, ANGR_AVAILABLE
from modules.vuln_db import VulnerabilityDatabase
from modules.hooks import get_hook_manager
from modules.dynamic_taint import run_dynamic_taint_analysis, FRIDA_AVAILABLE, QBDI_AVAILABLE


def setup_logging(log_level: str = 'INFO') -> None:
    """
    设置日志配置，输出到控制台和 logs/ 目录
    """
    ensure_directories()
    
    log_file = os.path.join(Config.LOGS_DIR, f'vuln_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, mode='w', encoding='utf-8')
        ]
    )
    
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(SensitiveFilter())
    
    logger = logging.getLogger(__name__)
    logger.info(f"日志文件: {log_file}")
    logger.info("敏感信息日志过滤器已启用")


def check_dependencies() -> List[str]:
    """
    统一检测所有依赖是否存在
    
    Returns:
        缺失依赖的列表
    """
    missing = []
    logger = logging.getLogger(__name__)
    
    logger.info("正在检查依赖...")
    
    try:
        result = subprocess.run(
            ['r2', '-v'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        if result.returncode == 0:
            logger.info(f"radare2 已安装: {result.stdout.strip().split(chr(10))[0]}")
        else:
            missing.append('radare2')
    except FileNotFoundError:
        missing.append('radare2')
    except subprocess.TimeoutExpired:
        logger.warning("radare2 检查超时")
        missing.append('radare2')
    except Exception as e:
        logger.warning(f"radare2 检查出错: {e}")
        missing.append('radare2')
    
    try:
        import pwn
        logger.info(f"pwntools 已安装: 版本 {getattr(pwn, '__version__', 'unknown')}")
    except ImportError:
        missing.append('pwntools (Python 包)')
    
    try:
        import openai
        logger.info(f"openai 已安装: 版本 {openai.__version__}")
        ai_provider = Config.AI_PROVIDER
        logger.info(f"AI 提供商: {ai_provider}")
        logger.info(f"AI 模型: {get_current_ai_model()}")
    except ImportError:
        logger.warning("openai Python 包未安装")
        logger.warning("  安装命令: pip install openai")
    
    if ANGR_AVAILABLE:
        logger.info("angr 符号执行引擎可用")
    else:
        logger.info("angr 未安装，符号执行功能不可用 (可选: pip install angr)")
    
    try:
        import pefile
        logger.info(f"pefile 已安装: PE 文件支持可用")
    except ImportError:
        logger.info("pefile 未安装，PE 文件分析可能受限 (可选: pip install pefile)")
    
    try:
        import macholib
        logger.info(f"macholib 已安装: Mach-O 文件支持可用")
    except ImportError:
        logger.info("macholib 未安装，Mach-O 文件分析可能受限 (可选: pip install macholib)")
    
    if missing:
        logger.error("以下依赖缺失:")
        for dep in missing:
            if 'radare2' in dep:
                logger.error(f"  - {dep}: 请安装 radare2")
                logger.error("    Ubuntu/Debian: sudo apt install radare2")
                logger.error("    macOS: brew install radare2")
                logger.error("    Windows: 从 https://github.com/radareorg/radare2/releases 下载")
            else:
                logger.error(f"  - {dep}: pip install {dep.split()[0]}")
    
    return missing


def get_function_symbols_from_radare2(binary_path: str) -> Dict[str, Dict[str, Any]]:
    """
    使用 radare2 获取函数符号信息，包含符号类型和绑定属性
    
    Returns:
        字典，key 为函数名，value 为包含 'type', 'bind', 'size' 等信息的字典
    """
    import logging
    import subprocess
    from config import Config
    
    logger = logging.getLogger(__name__)
    
    try:
        cmd = [
            'r2',
            '-q',
            '-e', 'io.color=false',
            '-c',
            'is',
            binary_path
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            timeout=Config.SUBPROCESS_TIMEOUT
        )
        
        if result.returncode != 0:
            logger.warning(f"radare2 获取符号表失败: {result.stderr[:200]}")
            return {}
        
        symbols = {}
        
        for line in result.stdout.strip().split('\n'):
            line = strip_ansi_escape(line)
            parts = line.split()
            if len(parts) < 7:
                continue
            
            try:
                flag = parts[0]
                paddr = parts[1]
                vaddr = parts[2]
                size = parts[3]
                bind = parts[4]
                type_ = parts[5]
                name = ' '.join(parts[6:])
                
                if type_ == 'FUNC':
                    func_name = name
                    if func_name.startswith('sym.'):
                        func_name = func_name[4:]
                    
                    symbols[func_name] = {
                        'type': type_,
                        'bind': bind,
                        'size': int(size, 16) if size.startswith('0x') else int(size) if size.isdigit() else 0,
                        'address': int(vaddr, 16) if vaddr.startswith('0x') else int(vaddr) if vaddr.isdigit() else 0,
                        'original_name': name
                    }
            except (ValueError, IndexError):
                continue
        
        logger.info(f"从 radare2 获取到 {len(symbols)} 个函数符号")
        return symbols
        
    except Exception as e:
        logger.warning(f"获取符号表失败: {e}")
        return {}


def is_library_function(func_name: str, symbols: Dict[str, Dict[str, Any]] = None) -> bool:
    """
    判断函数是否为库函数
    
    判断依据（优先级从高到低）:
    1. 符号类型不是 FUNC（STT_FUNC）
    2. 符号绑定为 LOCAL（STB_LOCAL）
    3. 符号绑定为 WEAK、UNDEF 或 IMPORT（导入/弱符号）
    4. 常见的 libc 启动函数前缀
    5. 符号表中不存在（可能是导入函数）
    """
    libc_startup_prefixes = (
        '_start', '__libc_csu', '__libc_start', 
        '_init', '_fini', '__gmon', '_dl_',
        '__do_global', '__register_frame',
        'plt.', '_reloc_', '__stack_chk'
    )
    
    if any(func_name.startswith(prefix) for prefix in libc_startup_prefixes):
        return True
    
    if symbols and func_name in symbols:
        symbol_info = symbols[func_name]
        type_ = symbol_info.get('type', 'FUNC')
        bind = symbol_info.get('bind', 'GLOBAL')
        
        if type_ != 'FUNC':
            return True
        
        if bind in ['LOCAL', 'WEAK', 'UNDEF', 'IMPORT']:
            return True
    
    if symbols and func_name not in symbols:
        return True
    
    return False


def filter_user_functions(
    all_functions: List[str], 
    symbols: Dict[str, Dict[str, Any]] = None,
    include_lib: bool = False
) -> List[str]:
    """
    过滤函数列表，保留用户自定义函数
    
    Args:
        all_functions: 所有函数列表
        symbols: 从 radare2 获取的符号信息
        include_lib: 是否包含库函数
    
    Returns:
        过滤后的函数列表
    """
    import logging
    
    logger = logging.getLogger(__name__)
    
    if include_lib:
        logger.info("已启用 --include-lib，将包含库函数")
        return all_functions
    
    user_funcs = []
    lib_funcs = []
    
    for func in all_functions:
        if is_library_function(func, symbols):
            lib_funcs.append(func)
        else:
            user_funcs.append(func)
    
    if lib_funcs:
        logger.debug(f"过滤掉 {len(lib_funcs)} 个库函数: {lib_funcs[:10]}")
    
    return user_funcs


def _analyze_single_function(
    decompiler: DecompilerAI,
    binary_info: Dict[str, Any],
    func_name: str
) -> Optional[Dict[str, Any]]:
    """
    分析单个函数（用于并行执行）
    """
    logger = logging.getLogger(__name__)
    
    try:
        logger.info(f"正在分析函数: {func_name}")
        result = decompiler.analyze_function(func_name, binary_info)
        
        vulns = result.get('vulnerabilities', [])
        if vulns:
            logger.warning(f"函数 {func_name} 中发现 {len(vulns)} 个漏洞!")
        else:
            logger.info(f"函数 {func_name} 分析完成，未发现明显漏洞")
        
        return {
            'function_name': func_name,
            'pseudocode': result.get('pseudocode', ''),
            'analysis': result
        }
    except Exception as e:
        logger.error(f"分析函数 {func_name} 时出错: {e}")
        return None


def analyze_functions(
    decompiler: DecompilerAI,
    binary_info: Dict[str, Any],
    functions_to_analyze: List[str] = None,
    max_functions: int = 5,
    include_lib: bool = False,
    parallel: bool = False,
    max_parallel: int = 2
) -> List[Dict[str, Any]]:
    """
    分析多个函数，优先分析用户自定义函数
    
    Args:
        decompiler: DecompilerAI 实例
        binary_info: 二进制文件信息
        functions_to_analyze: 用户指定的函数列表（可选）
        max_functions: 最大分析函数数量
        include_lib: 是否包含库函数
        parallel: 是否启用并行分析
        max_parallel: 最大并行数量
    """
    logger = logging.getLogger(__name__)
    results = []
    
    symbols = get_function_symbols_from_radare2(decompiler.binary_path)
    
    if functions_to_analyze:
        target_functions = functions_to_analyze
    else:
        default_targets = ['main', 'vuln', 'win', 'get_flag', 'read_input', 'process_input']
        available_funcs = decompiler.list_functions()
        
        if available_funcs:
            user_funcs = filter_user_functions(available_funcs, symbols, include_lib)
            target_functions = [f for f in default_targets if f in user_funcs]
            
            if not target_functions:
                target_functions = user_funcs[:max_functions]
        else:
            target_functions = default_targets
    
    if not include_lib:
        target_functions = [f for f in target_functions if not is_library_function(f, symbols)]
    
    if not target_functions:
        target_functions = ['main']
    
    logger.info(f"将分析以下函数: {target_functions}")
    
    if parallel and len(target_functions) > 1:
        logger.info(f"启用并行分析，最大并发数: {max_parallel}")
        
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            future_to_func = {
                executor.submit(_analyze_single_function, decompiler, binary_info, func): func
                for func in target_functions
            }
            
            for future in as_completed(future_to_func):
                func_name = future_to_func[future]
                try:
                    result = future.result(timeout=300)
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"并行分析函数 {func_name} 时出错: {e}")
    else:
        for func_name in target_functions:
            result = _analyze_single_function(decompiler, binary_info, func_name)
            if result:
                results.append(result)
    
    return results


def find_highest_risk_vulnerability(decomp_results: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    从分析结果中找到最高风险的漏洞
    """
    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Unknown': 0}
    
    highest_vuln = None
    highest_severity = 0
    
    for result in decomp_results:
        analysis = result.get('analysis', {})
        vulns = analysis.get('vulnerabilities', [])
        
        for vuln in vulns:
            severity = vuln.get('severity', 'Unknown')
            severity_val = severity_order.get(severity, 0)
            
            if severity_val > highest_severity:
                highest_severity = severity_val
                highest_vuln = vuln
    
    return highest_vuln


def print_analysis_summary(decomp_results: List[Dict[str, Any]]) -> None:
    """
    打印函数分析摘要
    """
    print("\n" + "=" * 60)
    print("函数分析摘要")
    print("=" * 60)
    
    if not decomp_results:
        print("没有分析任何函数")
        print("=" * 60)
        return
    
    severity_order = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Unknown': 5}
    severity_colors = {
        'Critical': '\033[91m',
        'High': '\033[93m',
        'Medium': '\033[93m',
        'Low': '\033[94m',
        'Unknown': '\033[0m'
    }
    reset_color = '\033[0m'
    
    for i, result in enumerate(decomp_results, 1):
        func_name = result.get('function_name', 'Unknown')
        analysis = result.get('analysis', {})
        vulns = analysis.get('vulnerabilities', [])
        risk_level = analysis.get('risk_level', 'Unknown')
        summary = analysis.get('summary', '')
        
        color = severity_colors.get(risk_level, reset_color)
        
        print(f"\n[{i}] {func_name}")
        print(f"    风险等级: {color}{risk_level}{reset_color}")
        print(f"    漏洞数量: {len(vulns)}")
        
        if summary:
            short_summary = summary[:100] + '...' if len(summary) > 100 else summary
            print(f"    摘要: {short_summary}")
        
        if vulns:
            print(f"    漏洞:")
            for v in vulns[:3]:
                v_severity = v.get('severity', 'Unknown')
                v_color = severity_colors.get(v_severity, reset_color)
                print(f"      - {v_color}{v_severity}{reset_color}: {v.get('type', 'Unknown')}")
    
    print("\n" + "=" * 60)


def run_interactive_menu(
    decomp_results: List[Dict[str, Any]],
    decompiler_obj,
    binary_info: Dict[str, Any],
    binary_path: str,
    client=None,
    use_ai: bool = True,
    validate_exploit: bool = False,
    no_exec: bool = True,
    no_rop: bool = False
) -> List[Dict[str, Any]]:
    """
    运行交互式分析菜单
    
    Args:
        decomp_results: 已有的函数分析结果
        decompiler_obj: DecompilerAI 实例
        binary_info: 二进制文件信息
        binary_path: 二进制文件路径
        client: AI 客户端（可选）
        use_ai: 是否使用 AI
        validate_exploit: 是否验证利用脚本
        no_exec: 是否执行利用脚本
        
    Returns:
        额外的分析结果列表
    """
    additional_results = []
    
    print("\n" + "=" * 60)
    print("交互式分析模式")
    print("=" * 60)
    
    while True:
        print("\n请选择操作:")
        print("  1. 查看某个函数的详细分析")
        print("  2. 分析其他函数")
        print("  3. 为漏洞生成利用脚本")
        print("  4. 显示所有可用函数")
        print("  5. 退出交互式模式")
        
        try:
            choice = input("\n请输入选项 (1-5): ").strip()
        except EOFError:
            print("\n检测到 EOF，退出交互式模式")
            break
        except KeyboardInterrupt:
            print("\n检测到中断，退出交互式模式")
            break
        
        if choice == '1':
            _show_function_details(decomp_results)
        elif choice == '2':
            result = _analyze_more_functions(decompiler_obj, binary_info, decomp_results)
            if result:
                additional_results.append(result)
        elif choice == '3':
            _generate_exploit_for_vuln(decomp_results, binary_info, binary_path, client, use_ai, validate_exploit, no_exec, no_rop)
        elif choice == '4':
            _list_available_functions(decompiler_obj)
        elif choice == '5':
            print("退出交互式模式")
            break
        else:
            print("无效选项，请重新输入")
    
    return additional_results


def _show_function_details(decomp_results: List[Dict[str, Any]]) -> None:
    """
    显示函数详细分析
    """
    if not decomp_results:
        print("没有可显示的分析结果")
        return
    
    print("\n已分析的函数:")
    for i, result in enumerate(decomp_results, 1):
        func_name = result.get('function_name', 'Unknown')
        vulns = result.get('analysis', {}).get('vulnerabilities', [])
        print(f"  [{i}] {func_name} ({len(vulns)} 个漏洞)")
    
    try:
        choice = input("\n请输入函数编号查看详情: ").strip()
        idx = int(choice) - 1
        
        if 0 <= idx < len(decomp_results):
            result = decomp_results[idx]
            func_name = result.get('function_name', 'Unknown')
            analysis = result.get('analysis', {})
            pseudocode = result.get('pseudocode', '')
            vulns = analysis.get('vulnerabilities', [])
            summary = analysis.get('summary', '')
            raw_response = analysis.get('raw_response', '')
            
            print(f"\n{'=' * 60}")
            print(f"函数: {func_name}")
            print(f"{'=' * 60}")
            
            if summary:
                print(f"\n摘要: {summary}")
            
            if vulns:
                print(f"\n漏洞列表:")
                for i, v in enumerate(vulns, 1):
                    print(f"\n  [{i}] {v.get('type', 'Unknown')} ({v.get('severity', 'Unknown')})")
                    print(f"      位置: {v.get('location', 'Unknown')}")
                    print(f"      描述: {v.get('description', 'Unknown')}")
                    if v.get('exploitation'):
                        print(f"      利用方式: {v.get('exploitation')}")
                    if v.get('code_snippet'):
                        print(f"      代码片段: {v.get('code_snippet')[:100]}")
            
            show_pseudo = input("\n显示伪代码? (y/n): ").strip().lower()
            if show_pseudo == 'y' and pseudocode:
                print(f"\n伪代码 ({len(pseudocode)} 字符):")
                print("-" * 60)
                print(pseudocode[:2000] if len(pseudocode) > 2000 else pseudocode)
                if len(pseudocode) > 2000:
                    print(f"... (已截断，还有 {len(pseudocode) - 2000} 字符)")
        else:
            print("无效的函数编号")
    except ValueError:
        print("请输入有效数字")
    except (EOFError, KeyboardInterrupt):
        print("\n已取消")


def _analyze_more_functions(
    decompiler_obj,
    binary_info: Dict[str, Any],
    existing_results: List[Dict[str, Any]]
) -> Optional[Dict[str, Any]]:
    """
    分析更多函数
    """
    available = decompiler_obj.list_functions()
    analyzed = set(r.get('function_name') for r in existing_results)
    not_analyzed = [f for f in available if f not in analyzed]
    
    if not_analyzed:
        print(f"\n未分析的函数（最多20个）:")
        for i, f in enumerate(not_analyzed[:20], 1):
            print(f"  [{i}] {f}")
    else:
        print("没有更多可分析的函数")
        return None
    
    try:
        func_name = input("\n请输入要分析的函数名: ").strip()
        if func_name:
            print(f"正在分析函数: {func_name}")
            result = decompiler_obj.analyze_function(func_name, binary_info)
            
            vulns = result.get('vulnerabilities', [])
            if vulns:
                print(f"发现 {len(vulns)} 个漏洞!")
            else:
                print("未发现明显漏洞")
            
            return {
                'function_name': func_name,
                'pseudocode': result.get('pseudocode', ''),
                'analysis': result
            }
        else:
            print("未输入函数名")
            return None
    except Exception as e:
        print(f"分析函数时出错: {e}")
        return None


def _generate_exploit_for_vuln(
    decomp_results: List[Dict[str, Any]],
    binary_info: Dict[str, Any],
    binary_path: str,
    client=None,
    use_ai: bool = True,
    validate_exploit: bool = False,
    no_exec: bool = True,
    no_rop: bool = False
) -> None:
    """
    为特定漏洞生成利用脚本
    """
    all_vulns = []
    for result in decomp_results:
        func_name = result.get('function_name', 'Unknown')
        vulns = result.get('analysis', {}).get('vulnerabilities', [])
        for v in vulns:
            all_vulns.append({**v, 'function_name': func_name})
    
    if not all_vulns:
        print("没有可用于生成利用脚本的漏洞")
        return
    
    severity_order = {'Critical': 1, 'High': 2, 'Medium': 3, 'Low': 4, 'Unknown': 5}
    all_vulns.sort(key=lambda x: severity_order.get(x.get('severity', 'Unknown'), 99))
    
    print(f"\n可用于生成利用脚本的漏洞（共 {len(all_vulns)} 个）:")
    for i, v in enumerate(all_vulns, 1):
        print(f"  [{i}] {v.get('severity', 'Unknown')} - {v.get('type', 'Unknown')} (函数: {v.get('function_name')})")
    
    try:
        choice = input("\n请输入漏洞编号生成利用脚本 (0 跳过): ").strip()
        if choice == '0' or not choice:
            return
        
        idx = int(choice) - 1
        if 0 <= idx < len(all_vulns):
            vuln = all_vulns[idx]
            print(f"正在为漏洞生成利用脚本: {vuln.get('type')}")
            
            exploit_gen = ExploitGenerator(binary_path, binary_info, client, no_rop=no_rop)
            result = exploit_gen.generate_and_validate(
                vuln,
                use_ai=use_ai and client is not None,
                validate=validate_exploit,
                no_exec=no_exec
            )
            
            if result.get('success'):
                print("✓ 利用脚本生成成功!")
                if result.get('script_path'):
                    print(f"脚本路径: {result.get('script_path')}")
            else:
                print("✗ 利用脚本生成失败")
                if result.get('error'):
                    print(f"错误: {result.get('error')}")
        else:
            print("无效的漏洞编号")
    except ValueError:
        print("请输入有效数字")
    except (EOFError, KeyboardInterrupt):
        print("\n已取消")


def _list_available_functions(decompiler_obj) -> None:
    """
    显示所有可用函数
    """
    functions = decompiler_obj.list_functions()
    if functions:
        print(f"\n可用函数（共 {len(functions)} 个，最多显示50个）:")
        for i, f in enumerate(functions[:50], 1):
            print(f"  [{i}] {f}")
        if len(functions) > 50:
            print(f"  ... 还有 {len(functions) - 50} 个函数")
    else:
        print("未找到可用函数")


def run_pipeline(
    binary_path: str,
    functions_to_analyze: List[str] = None,
    crash_data: Dict[str, Any] = None,
    validate_exploit: bool = False,
    no_exec: bool = True,
    use_ai: bool = True,
    output_dir: str = './reports',
    decompiler: str = 'auto',
    enable_symbolic_execution: bool = False,
    use_vuln_db: bool = True,
    include_lib: bool = False,
    interactive: bool = False,
    output_format: str = 'markdown',
    parallel: bool = False,
    max_parallel: int = 2,
    hooks_dir: str = './hooks',
    fuzzer_type: str = None,
    expert_mode: bool = False,
    export_corpus_dir: str = None,
    no_rop: bool = False,
    dynamic_taint_engine: str = None,
    taint_input_data: bytes = None,
    taint_timeout: int = 60,
    allocator_type: str = 'auto',
    libc_version: str = None,
    force_kernel: bool = False,
    project_name: str = None,
    project_resume: bool = False,
    project_new: bool = False,
    language: str = 'auto',
    enable_unpack: bool = True,
    unpack_tool_path: str = None,
    enable_crypto_scan: bool = True,
    enable_mobile: bool = False,
    mobile_platform: str = 'auto',
    enable_unicorn_hybrid: bool = False,
    enable_exploit_chain: bool = False,
    exploit_chain_goal: str = 'shell',
) -> Dict[str, Any]:
    """
    运行完整的分析流水线

    Args:
        binary_path: 二进制文件路径
        functions_to_analyze: 要分析的函数列表
        crash_data: 崩溃数据
        validate_exploit: 是否验证利用脚本
        no_exec: 是否禁止执行利用脚本
        use_ai: 是否使用 AI
        output_dir: 报告输出目录
        decompiler: 反编译引擎
        enable_symbolic_execution: 是否启用符号执行
        use_vuln_db: 是否使用漏洞数据库
        include_lib: 是否包含库函数
        interactive: 是否交互式模式
        output_format: 输出格式
        parallel: 是否并行分析
        max_parallel: 最大并行数
        hooks_dir: 钩子目录
        fuzzer_type: Fuzzer 类型 (libfuzzer, afl, afl++)
        expert_mode: 专家模式，生成高级利用链
        export_corpus_dir: 语料导出目录
        dynamic_taint_engine: 动态污点追踪引擎 (frida 或 qbdi)
        taint_input_data: 污点分析输入数据
        taint_timeout: 污点分析超时时间（秒）
        allocator_type: 堆分配器类型 (auto, ptmalloc, jemalloc)
        libc_version: libc 版本（如 2.31）
        force_kernel: 是否强制使用内核模式分析
        project_name: 项目名称，启用项目持久化
        project_resume: 是否强制从上次保存点恢复
        project_new: 是否强制新建项目
        language: 编程语言 (auto, c/c++, go, rust)
        enable_unpack: 是否启用自动脱壳预处理
        unpack_tool_path: 指定脱壳工具路径
        enable_crypto_scan: 是否启用密码学常量扫描和弱算法检测
        enable_mobile: 是否启用移动平台二进制深度分析 (Android .so / iOS Mach-O)
        mobile_platform: 移动平台标识 (android/ios/auto)
        enable_unicorn_hybrid: 是否启用 Unicorn Engine + angr 混合分析
        enable_exploit_chain: 是否启用漏洞利用链自动组合与攻击图生成
        exploit_chain_goal: 利用链目标 (shell, code_execution, file_read, privilege_escalation)
    """
    logger = logging.getLogger(__name__)
    
    hook_manager = get_hook_manager(hooks_dir)
    registered_hooks = hook_manager.get_registered_hooks()
    if registered_hooks:
        logger.info(f"已加载钩子: {registered_hooks}")
    
    try:
        validated_path = validate_binary_path(binary_path)
    except ValueError as e:
        logger.error(f"二进制路径验证失败: {e}")
        return {'error': f'Invalid binary path: {e}'}
    
    logger.info(f"开始分析二进制文件: {validated_path}")
    
    # ==================== 自动脱壳预处理 ====================
    unpack_result = None
    if enable_unpack:
        try:
            from modules.unpacker import Unpacker
            logger.info("步骤 0.5/6: 自动脱壳预处理...")
            unpacker = Unpacker(unpack_tool_path=unpack_tool_path)
            unpack_result = unpacker.unpack_if_needed(validated_path)
            
            if unpack_result.success and unpack_result.unpacked_path:
                validated_path = unpack_result.unpacked_path
                logger.info(f"脱壳成功，使用脱壳后的文件: {validated_path}")
            elif unpack_result.packer_type != 'none':
                logger.warning(f"检测到 {unpack_result.packer_type} 壳，但脱壳失败，继续使用原文件")
        except Exception as e:
            logger.warning(f"脱壳预处理失败: {e}")
    
    report_gen = ReportGenerator(output_dir=output_dir)
    report_gen.add_step('Pipeline Started', {'binary_path': validated_path})
    
    if not os.path.exists(validated_path):
        logger.error(f"文件不存在: {validated_path}")
        return {'error': f'File not found: {validated_path}'}
    
    binary_format = detect_binary_format(validated_path, force_kernel=force_kernel)
    logger.info(f"检测到文件格式: {binary_format}")
    
    if force_kernel:
        logger.info("内核模式: 已启用")
    
    project_manager = None
    project_state = None
    project_id = None
    
    if project_name:
        from modules.project_manager import ProjectManager, ProjectState
        project_manager = ProjectManager()
        
        existing_projects = project_manager.list_projects()
        existing_ids = [p['id'] for p in existing_projects]
        existing_names = [p['name'] for p in existing_projects]
        
        if project_name in existing_names:
            idx = existing_names.index(project_name)
            project_id = existing_ids[idx]
            
            if project_new:
                logger.info(f"强制新建项目: {project_name}")
                project_id = project_manager.create_project(project_name, validated_path)
            elif project_resume:
                logger.info(f"恢复项目: {project_name} (ID: {project_id})")
                project_state = project_manager.load_project(project_id)
                if project_state:
                    logger.info(f"已恢复状态 - 当前步骤: {project_state.current_step}, 已分析函数: {len(project_state.analyzed_functions)}")
                else:
                    logger.warning("无法恢复项目状态，将从头开始")
            else:
                logger.info(f"项目已存在: {project_name} (ID: {project_id})")
                if interactive:
                    choice = input("项目已存在，是否恢复分析? (y/n): ").strip().lower()
                    if choice == 'y':
                        project_state = project_manager.load_project(project_id)
                        if project_state:
                            logger.info(f"已恢复状态 - 当前步骤: {project_state.current_step}")
        else:
            logger.info(f"创建新项目: {project_name}")
            project_id = project_manager.create_project(project_name, validated_path)
    
    detected_language = 'c/c++'
    if language == 'auto':
        logger.info("自动检测编程语言...")
        detected_language = detect_language(validated_path, binary_format)
    else:
        detected_language = language
    
    logger.info(f"检测到编程语言: {detected_language}")
    
    client = get_openai_client() if use_ai else None
    
    logger.info("步骤 1/6: 收集二进制文件信息...")
    report_gen.add_step('Info Collection Started')
    
    hook_manager.run_hooks('pre_info_collect', {
        'binary_path': validated_path,
        'binary_format': binary_format,
        'language': detected_language
    })
    
    binary_info = get_binary_info(validated_path, force_kernel=force_kernel)
    binary_info['language'] = detected_language
    
    # ==================== 密码学常量扫描 ====================
    crypto_scan_result = None
    if enable_crypto_scan:
        try:
            from modules.crypto_detector import CryptoDetector
            logger.info("步骤 1.5/6: 密码学常量扫描...")
            crypto_detector = CryptoDetector()
            crypto_scan_result = crypto_detector.scan_binary(validated_path)
            
            if crypto_scan_result:
                binary_info['crypto_analysis'] = {
                    'algorithms_found': [match.__dict__ for match in crypto_scan_result.algorithms_found],
                    'weak_algorithms': [issue.__dict__ for issue in crypto_scan_result.weak_algorithms],
                    'key_candidates': [candidate.__dict__ for candidate in crypto_scan_result.key_candidates],
                    'function_calls': crypto_scan_result.function_calls,
                    'ecb_mode_detected': crypto_scan_result.ecb_mode_detected,
                    'summary': crypto_scan_result.summary
                }
                logger.info(f"密码学扫描完成: {crypto_scan_result.summary}")
        except Exception as e:
            logger.warning(f"密码学扫描失败: {e}")
    
    if not binary_info:
        logger.error("无法收集二进制文件信息")
        return {'error': 'Failed to collect binary info'}
    
    report_gen.add_step('Info Collection Complete', binary_info)
    
    if project_manager and project_id:
        project_state = project_state or ProjectState()
        project_state.current_step = 'info_collect'
        project_state.binary_info = binary_info
        project_manager.save_state(project_id, project_state)
        logger.debug(f"已保存项目状态: {project_id}")
    
    vuln_db = None
    similar_vulns = []
    if use_vuln_db:
        try:
            vuln_db = VulnerabilityDatabase()
            logger.info("漏洞数据库已连接")
            
            dangerous_funcs = binary_info.get('imports', {}).get('dangerous_functions', [])
            similar_vulns = vuln_db.search_similar(
                pseudocode='',
                dangerous_functions=dangerous_funcs,
                binary_format=binary_format,
                architecture=binary_info.get('arch', '')
            )
            
            if similar_vulns:
                logger.info(f"在数据库中发现 {len(similar_vulns)} 个相似漏洞记录")
                for i, vuln in enumerate(similar_vulns[:3]):
                    logger.info(f"  [{i+1}] {vuln.get('vulnerability_type', 'Unknown')} in {vuln.get('binary_name', 'Unknown')}")
        except Exception as e:
            logger.warning(f"漏洞数据库初始化失败: {e}")
            vuln_db = None
    
    logger.info("步骤 2/6: 反编译和 AI 漏洞分析...")
    report_gen.add_step('Decompilation Started')
    decompiler_obj = DecompilerAI(validated_path, client, decompiler)
    decomp_results = analyze_functions(
        decompiler_obj, 
        binary_info, 
        functions_to_analyze, 
        include_lib=include_lib,
        parallel=parallel,
        max_parallel=max_parallel
    )
    
    hook_manager.run_hooks('post_decompile', {
        'binary_path': validated_path,
        'functions_analyzed': len(decomp_results),
        'decompiler_used': decompiler_obj.get_active_decompiler(),
        'decomp_results': decomp_results
    })
    
    report_gen.add_step('Decompilation Complete', {
        'functions_analyzed': len(decomp_results),
        'decompiler_used': decompiler_obj.get_active_decompiler()
    })
    
    if project_manager and project_id:
        project_state.current_step = 'decompilation'
        project_state.analyzed_functions = [r.get('function_name') for r in decomp_results]
        project_state.decomp_results = decomp_results
        project_manager.save_state(project_id, project_state)
        logger.debug(f"已保存项目状态: {project_id}")
    
    if interactive:
        print_analysis_summary(decomp_results)
        additional_results = run_interactive_menu(
            decomp_results,
            decompiler_obj,
            binary_info,
            validated_path,
            client,
            use_ai,
            validate_exploit,
            no_exec,
            no_rop
        )
        if additional_results:
            decomp_results.extend(additional_results)
    
    symbolic_result = None
    auto_discovered_crash = None
    
    if enable_symbolic_execution:
        logger.info("步骤 3/6: 符号执行分析...")
        report_gen.add_step('Symbolic Execution Started')
        
        if not ANGR_AVAILABLE:
            logger.warning("符号执行引擎不可用（angr 未安装），跳过此步骤")
            report_gen.add_step('Symbolic Execution Skipped', {'reason': 'angr not installed'})
        else:
            try:
                symbolic_executor = SymbolicExecutor(validated_path)
            except Exception as e:
                logger.error(f"创建符号执行器失败: {e}")
                symbolic_executor = None
            
            if symbolic_executor and symbolic_executor.is_available():
                target_func = functions_to_analyze[0] if functions_to_analyze else 'main'
                symbolic_result = symbolic_executor.full_analysis(target_func)
                
                if not crash_data:
                    logger.info("没有提供崩溃数据，尝试自动发现可触发的崩溃...")
                    auto_discovered_crash = symbolic_executor.auto_explore_dangerous_functions()
                    
                    if auto_discovered_crash:
                        logger.warning("✓ 自动发现了可触发的崩溃！")
                        crash_data = {
                            'type': 'auto_discovered',
                            'source': 'symbolic_execution',
                            'crash_type': auto_discovered_crash.get('crash_type', 'Unknown'),
                            'crash_address': auto_discovered_crash.get('crash_address', '0x0'),
                            'function_address': auto_discovered_crash.get('function_address', '0x0'),
                            'crashing_input': auto_discovered_crash.get('crashing_input'),
                            'crashing_input_hex': auto_discovered_crash.get('crashing_input_hex'),
                            'input_length': auto_discovered_crash.get('input_length', 0),
                            'error': auto_discovered_crash.get('error', ''),
                            'state_info': auto_discovered_crash.get('state_info', {})
                        }
                        logger.info(f"  崩溃类型: {crash_data['crash_type']}")
                        logger.info(f"  崩溃地址: {crash_data['crash_address']}")
                        logger.info(f"  输入长度: {crash_data['input_length']} 字节")
                    else:
                        logger.info("未能自动发现可触发的崩溃，继续使用静态分析")
                
                report_gen.add_step('Symbolic Execution Complete', symbolic_result)
            else:
                logger.warning("符号执行引擎不可用，跳过此步骤")
                report_gen.add_step('Symbolic Execution Skipped', {'reason': 'angr not available'})
    else:
        logger.info("步骤 3/6: 符号执行分析（已禁用）")
    
    if project_manager and project_id:
        project_state.current_step = 'symbolic_execution'
        project_state.symbolic_result = symbolic_result
        project_state.crash_data = crash_data
        project_manager.save_state(project_id, project_state)
        logger.debug(f"已保存项目状态: {project_id}")
    
    dynamic_taint_result = None
    if dynamic_taint_engine:
        logger.info(f"步骤 3.5/6: 动态污点追踪分析 ({dynamic_taint_engine})...")
        report_gen.add_step('Dynamic Taint Analysis Started', {'engine': dynamic_taint_engine})
        
        if dynamic_taint_engine == 'frida' and not FRIDA_AVAILABLE:
            logger.warning("Frida 未安装，无法进行动态污点分析")
            report_gen.add_step('Dynamic Taint Analysis Skipped', {'reason': 'frida not installed'})
        elif dynamic_taint_engine == 'qbdi' and not QBDI_AVAILABLE:
            logger.warning("QBDI 未安装，无法进行动态污点分析")
            report_gen.add_step('Dynamic Taint Analysis Skipped', {'reason': 'qbdi not installed'})
        else:
            try:
                dynamic_taint_result = run_dynamic_taint_analysis(
                    binary_path=validated_path,
                    engine=dynamic_taint_engine,
                    args=functions_to_analyze,
                    timeout=taint_timeout,
                    input_data=taint_input_data
                )
                
                if dynamic_taint_result.get('success'):
                    logger.info(f"动态污点分析完成，发现 {len(dynamic_taint_result.get('taint_flows', []))} 条污点路径")
                    report_gen.add_step('Dynamic Taint Analysis Complete', {
                        'engine': dynamic_taint_engine,
                        'taint_flows_found': len(dynamic_taint_result.get('taint_flows', [])),
                        'vulnerabilities_found': len(dynamic_taint_result.get('vulnerabilities', []))
                    })
                else:
                    logger.warning(f"动态污点分析失败: {dynamic_taint_result.get('error', 'unknown')}")
                    report_gen.add_step('Dynamic Taint Analysis Failed', {'error': dynamic_taint_result.get('error')})
            except Exception as e:
                logger.error(f"动态污点分析执行失败: {e}")
                report_gen.add_step('Dynamic Taint Analysis Failed', {'error': str(e)})
    else:
        logger.info("步骤 3.5/6: 动态污点追踪分析（已禁用）")
    
    crash_analysis = None
    if crash_data:
        if crash_data.get('type') == 'auto_discovered':
            logger.info("步骤 4/6: 分析自动发现的崩溃数据...")
        else:
            logger.info("步骤 4/6: 崩溃信息分析...")
        report_gen.add_step('Crash Analysis Started')
        crash_analyzer = CrashAnalyzer(client)
        crash_analysis = crash_analyzer.analyze(crash_data, binary_info.get('checksec', {}))
        report_gen.add_step('Crash Analysis Complete', crash_analysis)
        
        if project_manager and project_id:
            project_state.current_step = 'crash_analysis'
            project_state.crash_analysis = crash_analysis
            project_manager.save_state(project_id, project_state)
            logger.debug(f"已保存项目状态: {project_id}")
    
    exploit_result = None
    target_vuln = find_highest_risk_vulnerability(decomp_results)
    
    if target_vuln:
        logger.info(f"步骤 5/6: 为漏洞 {target_vuln.get('type', 'Unknown')} 生成利用脚本...")
        report_gen.add_step('Exploit Generation Started', {'vulnerability_type': target_vuln.get('type')})
        
        hook_manager.run_hooks('pre_exploit_generate', {
            'binary_path': validated_path,
            'vulnerability_type': target_vuln.get('type', 'Unknown'),
            'vulnerability': target_vuln,
            'binary_info': binary_info
        })
        
        exploit_gen = ExploitGenerator(validated_path, binary_info, client, no_rop=no_rop)
        exploit_result = exploit_gen.generate_and_validate(
            target_vuln,
            use_ai=use_ai and client is not None,
            validate=validate_exploit,
            no_exec=no_exec,
            allocator_type=allocator_type,
            libc_version=libc_version
        )
        
        report_gen.add_step('Exploit Generation Complete', {
            'success': exploit_result.get('success', False),
            'iterations': len(exploit_result.get('iterations', []))
        })
        
        if project_manager and project_id:
            project_state.current_step = 'exploit_generation'
            project_state.exploit_result = exploit_result
            project_manager.save_state(project_id, project_state)
            logger.debug(f"已保存项目状态: {project_id}")
        
        if exploit_result.get('success') and vuln_db:
            try:
                logger.info("将成功的漏洞记录到数据库...")
                binary_name = os.path.basename(validated_path)
                vuln_db.add_vulnerability(
                    vulnerability_type=target_vuln.get('type', 'Unknown'),
                    binary_name=binary_name,
                    binary_format=binary_format,
                    architecture=binary_info.get('arch', 'unknown'),
                    bits=binary_info.get('bits', 0),
                    function_name=target_vuln.get('location', 'unknown'),
                    pseudocode=decomp_results[0].get('pseudocode', '') if decomp_results else '',
                    exploit_script=exploit_result.get('script_content', ''),
                    dangerous_functions=binary_info.get('imports', {}).get('dangerous_functions', []),
                    checksec=binary_info.get('checksec', {}),
                    symbols=binary_info.get('symbols', {}),
                    severity=target_vuln.get('severity', 'Medium'),
                    description=target_vuln.get('description', '')
                )
            except Exception as e:
                logger.warning(f"记录漏洞到数据库失败: {e}")
    
    logger.info("步骤 6/6: 生成分析报告...")
    report_gen.add_step('Report Generation Started')

    # ==================== 移动平台深度分析 ====================
    mobile_info = None
    if enable_mobile:
        try:
            from modules.info_collect import collect_mobile_info
            logger.info("步骤 6a/6: 移动平台二进制深度分析 (Android .so / iOS Mach-O)...")
            mobile_info = collect_mobile_info(
                binary_path=validated_path,
                platform=mobile_platform,
                enable_mobile=True,
            )
            if mobile_info:
                logger.info(
                    f"移动分析完成: 平台={mobile_info.get('detected_platform', 'unknown')}, "
                    f"JNI={len(mobile_info.get('jni_functions', []))}, "
                    f"ObjC类={len(mobile_info.get('objc_classes', []))}"
                )
        except Exception as e:
            logger.warning(f"移动平台深度分析失败: {e}")

    # ==================== Unicorn Engine 混合分析 ====================
    hybrid_result = None
    if enable_unicorn_hybrid and enable_symbolic_execution and symbolic_result is not None:
        try:
            from modules.symbolic_exe import SymbolicExecutor
            logger.info("步骤 6b/6: Unicorn Engine 混合分析...")
            sym_exec = SymbolicExecutor(validated_path)
            target_func = functions_to_analyze[0] if functions_to_analyze else 'main'
            hybrid_result = sym_exec.hybrid_analysis(
                function_name=target_func,
                enable_unicorn=True,
            )
            if hybrid_result.get('use_unicorn'):
                logger.info("Unicorn 混合分析完成")
            else:
                logger.info(f"Unicorn 混合分析跳过: {hybrid_result.get('note', '')}")
        except Exception as e:
            logger.warning(f"Unicorn 混合分析失败: {e}")

    # ==================== 漏洞利用链组合 ====================
    attack_graph = None
    if enable_exploit_chain:
        try:
            from config import validate_exploit_chain_goal
            from modules.exploit_chaining import ExploitChainComposer
            if not validate_exploit_chain_goal(exploit_chain_goal):
                logger.warning(f"非法的 exploit_chain_goal: {exploit_chain_goal}, 回退到 shell")
                exploit_chain_goal = "shell"
            logger.info(f"步骤 6c/6: 漏洞利用链自动组合 (目标: {exploit_chain_goal})...")
            composer = ExploitChainComposer(
                max_chain_length=Config.EXPLOIT_CHAIN_MAX_LENGTH,
            )
            added = composer.add_vulns_from_results(decomp_results)
            logger.info(f"组合器共接收 {added} 个漏洞")
            if added > 0:
                attack_graph = composer.compose(target_goal=exploit_chain_goal)
                if Config.EXPLOIT_CHAIN_GEN_SKELETON and attack_graph.get("chains"):
                    best_chain = attack_graph["chains"][0]
                    skeleton = composer.generate_cooperative_exploit_skeleton(best_chain)
                    attack_graph["skeleton"] = skeleton
                # 输出 JSON / DOT
                try:
                    os.makedirs(Config.EXPLOIT_CHAIN_OUTPUT_DIR, exist_ok=True)
                    if attack_graph.get("graph_json"):
                        with open(
                            os.path.join(Config.EXPLOIT_CHAIN_OUTPUT_DIR, "attack_graph.json"),
                            "w", encoding="utf-8",
                        ) as f:
                            import json as _json
                            _json.dump(attack_graph["graph_json"], f, ensure_ascii=False, indent=2)
                    if attack_graph.get("graph_dot"):
                        with open(
                            os.path.join(Config.EXPLOIT_CHAIN_OUTPUT_DIR, "attack_graph.dot"),
                            "w", encoding="utf-8",
                        ) as f:
                            f.write(attack_graph["graph_dot"])
                    if attack_graph.get("skeleton"):
                        with open(
                            os.path.join(Config.EXPLOIT_CHAIN_OUTPUT_DIR, "cooperative_exploit.py"),
                            "w", encoding="utf-8",
                        ) as f:
                            f.write(attack_graph["skeleton"])
                except Exception as e:
                    logger.warning(f"保存攻击图文件失败: {e}")
            else:
                attack_graph = {
                    "success": False,
                    "error": "无可用漏洞输入",
                    "goal": exploit_chain_goal,
                    "chains": [],
                }
        except Exception as e:
            logger.warning(f"漏洞利用链组合失败: {e}")

    reports = {}

    reports['markdown'] = report_gen.generate_report(
        validated_path,
        binary_info,
        decomp_results,
        crash_analysis,
        exploit_result,
        similar_vulns,
        symbolic_result,
        dynamic_taint_result,
        mobile_info=mobile_info,
        attack_graph=attack_graph,
    )

    reports['json'] = report_gen.generate_json_report(
        validated_path,
        binary_info,
        decomp_results,
        crash_analysis,
        exploit_result
    )

    if output_format == 'html' or output_format == 'all':
        reports['html'] = report_gen.generate_html_report(
            validated_path,
            binary_info,
            decomp_results,
            crash_analysis,
            exploit_result,
            similar_vulns,
            symbolic_result
        )
    
    report_gen.add_step('Report Generation Complete', reports)
    
    if project_manager and project_id:
        project_state.current_step = 'report_generation'
        project_state.reports = reports
        project_state.status = 'completed'
        project_manager.save_state(project_id, project_state)
        logger.debug(f"已保存项目状态: {project_id}")
    
    hook_manager.run_hooks('post_report', {
        'binary_path': validated_path,
        'reports': reports,
        'binary_info': binary_info,
        'decomp_results': decomp_results,
        'crash_analysis': crash_analysis,
        'exploit_result': exploit_result
    })
    
    if vuln_db:
        vuln_db.close()
    
    fuzzer_harness_path = None
    if fuzzer_type:
        try:
            exploit_gen = ExploitGenerator(validated_path, binary_info, client, no_rop=no_rop)
            
            logger.info(f"生成 {fuzzer_type} Fuzzer harness 代码...")
            harness_code = exploit_gen.generate_fuzzing_harness(
                fuzzer_type=fuzzer_type,
                target_function=functions_to_analyze[0] if functions_to_analyze else 'main'
            )
            
            harness_dir = os.path.join(output_dir, 'fuzzer_harness')
            os.makedirs(harness_dir, exist_ok=True)
            binary_name = os.path.basename(validated_path)
            fuzzer_harness_path = os.path.join(harness_dir, f'harness_{binary_name}_{fuzzer_type}.c')
            
            with open(fuzzer_harness_path, 'w', encoding='utf-8') as f:
                f.write(harness_code)
            
            logger.info(f"Fuzzer harness 已保存: {fuzzer_harness_path}")
            
        except Exception as e:
            logger.warning(f"生成 Fuzzer harness 失败: {e}")
    
    corpus_files = []
    if export_corpus_dir and symbolic_result:
        if not ANGR_AVAILABLE:
            logger.warning("angr 不可用，无法导出语料")
        else:
            try:
                symbolic_executor = SymbolicExecutor(validated_path)
                
                if symbolic_executor.is_available():
                    logger.info(f"导出符号执行语料到: {export_corpus_dir}")
                    corpus_files = symbolic_executor.export_corpus(
                        output_dir=export_corpus_dir,
                        max_files=100
                    )
                    logger.info(f"已导出 {len(corpus_files)} 个语料文件")
            except Exception as e:
                logger.warning(f"导出语料失败: {e}")
    
    logger.info("分析流水线完成")
    for fmt, path in reports.items():
        logger.info(f"{fmt.upper()} 报告: {path}")
    
    result_dict = {
        'binary_info': binary_info,
        'similar_vulnerabilities': similar_vulns,
        'decomp_analysis': decomp_results,
        'symbolic_execution': symbolic_result,
        'dynamic_taint': dynamic_taint_result,
        'crash_analysis': crash_analysis,
        'exploit_result': exploit_result,
        'mobile_info': mobile_info,
        'unicorn_hybrid': hybrid_result,
        'attack_graph': attack_graph,
        'reports': {
            'markdown': reports.get('markdown'),
            'json': reports.get('json'),
            'html': reports.get('html')
        }
    }
    
    if fuzzer_harness_path:
        result_dict['fuzzer_harness'] = fuzzer_harness_path
    
    if corpus_files:
        result_dict['corpus_files'] = corpus_files
    
    return result_dict


def parse_arguments():
    """
    解析命令行参数
    """
    parser = argparse.ArgumentParser(
        description='LLM 辅助的二进制漏洞分析工具 (v1.3.1)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
支持的文件格式: ELF (Linux), PE (Windows), Mach-O (macOS)
支持的 AI 提供商: OpenAI, Azure OpenAI, Ollama, llama.cpp, Custom API
支持的编程语言: C/C++, Go, Rust

AI 服务配置:
  请直接编辑 config.py 中的 Config 类，不再通过环境变量配置。
  
  OpenAI:
    AI_PROVIDER = AI_PROVIDER_OPENAI
    OPENAI_API_KEY = 'sk-xxxx'
    OPENAI_MODEL = 'gpt-4'
  
  Azure OpenAI:
    AI_PROVIDER = AI_PROVIDER_AZURE
    AZURE_API_KEY = 'xxx'
    AZURE_ENDPOINT = 'https://xxx.openai.azure.com/'
    AZURE_DEPLOYMENT = 'xxx'
  
  Ollama:
    AI_PROVIDER = AI_PROVIDER_OLLAMA
    OLLAMA_HOST = 'http://localhost:11434'
    OLLAMA_MODEL = 'llama2'
        
  '''
    )
    parser.add_argument(
        '-help',
        action='help',
        help='显示帮助信息并退出'
    )
    
    parser.add_argument(
        'binary',
        nargs='?',
        help='要分析的二进制文件路径 (支持 ELF/PE/Mach-O，使用 --health 时不需要)'
    )
    
    parser.add_argument(
        '-f', '--functions',
        nargs='+',
        help='要分析的函数名列表 (默认: main, vuln, win 等)'
    )
    
    parser.add_argument(
        '--crash',
        help='崩溃数据文件路径 (支持 JSON, GDB, ASAN 格式)'
    )
    
    parser.add_argument(
        '--crash-format',
        choices=['auto', 'json', 'gdb', 'asan'],
        default='auto',
        help='指定崩溃数据格式 (默认: auto，自动检测)'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='验证生成的利用脚本 (需要同时使用 --exec 才会实际执行)'
    )
    
    exec_group = parser.add_mutually_exclusive_group()
    exec_group.add_argument(
        '--exec',
        dest='no_exec',
        action='store_false',
        default=True,
        help='允许实际执行利用脚本进行验证 (默认: 不执行，仅生成脚本)'
    )
    exec_group.add_argument(
        '--no-exec',
        dest='no_exec',
        action='store_true',
        help='不执行利用脚本进行验证 (默认行为，仅生成脚本)'
    )
    
    parser.add_argument(
        '--no-ai',
        action='store_true',
        help='禁用 AI 分析，仅使用启发式方法'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='./reports',
        help='报告输出目录 (默认: ./reports)'
    )
    
    parser.add_argument(
        '-l', '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        default='INFO',
        help='日志级别 (默认: INFO)'
    )
    
    parser.add_argument(
        '--skip-deps-check',
        action='store_true',
        help='跳过依赖检查'
    )
    
    parser.add_argument(
        '--decompiler',
        choices=['auto', 'radare2', 'ghidra', 'ida', 'binaryninja', 'hopper'],
        default='auto',
        help='指定反编译引擎 (默认: auto，自动选择可用的)'
    )
    
    parser.add_argument(
        '--enable-symbolic-execution',
        action='store_true',
        help='启用符号执行分析 (需要安装 angr)'
    )
    
    parser.add_argument(
        '--no-db',
        action='store_true',
        help='禁用漏洞数据库功能'
    )
    
    parser.add_argument(
        '--include-lib',
        action='store_true',
        help='分析标准库函数（默认不分析库函数）'
    )
    
    parser.add_argument(
        '--interactive',
        action='store_true',
        help='启用交互式分析模式，可选择要分析的函数和操作'
    )
    
    parser.add_argument(
        '--format',
        dest='output_format',
        choices=['markdown', 'json', 'html', 'all'],
        default='markdown',
        help='报告输出格式 (默认: markdown)'
    )
    
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
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='启用调试模式，打印发给 LLM 的完整提示词和响应（脱敏后）'
    )
    
    parser.add_argument(
        '--plugin',
        action='append',
        default=[],
        help='加载自定义插件脚本 (可多次指定)'
    )
    
    parser.add_argument(
        '--parallel',
        action='store_true',
        help='启用并行分析多个函数 (注意: 可能受 LLM API 并发限制)'
    )
    
    parser.add_argument(
        '--max-parallel',
        type=int,
        default=2,
        help='最大并行分析数量 (默认: 2)'
    )
    
    parser.add_argument(
        '--hooks-dir',
        default='./hooks',
        help='钩子脚本目录 (默认: ./hooks)'
    )
    
    parser.add_argument(
        '--fuzzer',
        choices=['libfuzzer', 'afl', 'afl++', 'honggfuzz', 'none'],
        default='none',
        help='指定 Fuzzer 类型，生成对应的 harness 代码 (默认: none)'
    )
    
    parser.add_argument(
        '--fuzzer-harness',
        help='生成 Fuzzer harness 代码的输出路径'
    )
    
    parser.add_argument(
        '--export-corpus',
        help='将符号执行产生的新输入导出为语料文件目录'
    )
    
    parser.add_argument(
        '--server',
        action='store_true',
        help='启动 Web API 服务器 (需要 fastapi 和 uvicorn)'
    )
    
    parser.add_argument(
        '--host',
        default='0.0.0.0',
        help='API 服务器监听地址 (默认: 0.0.0.0)'
    )
    
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='API 服务器监听端口 (默认: 8000)'
    )
    
    parser.add_argument(
        '--expert',
        action='store_true',
        help='启用专家模式，使用 AI 生成高级利用链 (ret2csu, ret2dlresolve, SROP 等)'
    )
    
    parser.add_argument(
        '--no-rop',
        action='store_true',
        help='跳过 ROP gadget 分析（适用于 PE、Mach-O 等非 ELF 格式文件）'
    )
    
    # ==================== 项目管理配置 ====================
    project_group = parser.add_argument_group('项目管理')
    project_group.add_argument(
        '--project',
        help='指定项目名称，启用项目持久化功能。分析进度将保存到项目目录'
    )
    project_group.add_argument(
        '--project-resume',
        action='store_true',
        help='强制从上次保存点恢复分析（配合 --project 使用）'
    )
    project_group.add_argument(
        '--project-new',
        action='store_true',
        help='即使项目已存在也强制新建（配合 --project 使用）'
    )
    
    # ==================== 脱壳配置 ====================
    unpack_group = parser.add_argument_group('自动脱壳')
    unpack_group.add_argument(
        '--no-unpack',
        action='store_true',
        help='禁用自动脱壳预处理（默认启用）'
    )
    unpack_group.add_argument(
        '--unpack-tool',
        help='指定脱壳工具路径（如 UPX 的完整路径）'
    )
    
    # ==================== 密码学扫描配置 ====================
    crypto_group = parser.add_argument_group('密码学扫描')
    crypto_group.add_argument(
        '--no-crypto-scan',
        action='store_true',
        help='禁用密码学常量扫描和弱算法检测（默认启用）'
    )
    
    # ==================== 多用户协作配置 ====================
    collab_group = parser.add_argument_group('多用户协作')
    collab_group.add_argument(
        '--collaborate',
        action='store_true',
        help='启动 Web 服务时启用多用户协作功能（需要配合 --server 使用）'
    )
    
    # ==================== 语言检测配置 ====================
    language_group = parser.add_argument_group('语言检测')
    language_group.add_argument(
        '--detect-language',
        action='store_true',
        default=True,
        help='自动检测二进制文件的编程语言（默认启用）'
    )
    language_group.add_argument(
        '--language',
        choices=['auto', 'c/c++', 'go', 'rust'],
        default='auto',
        help='手动指定编程语言，覆盖自动检测结果。可选: auto(自动), c/c++, go, rust (默认: auto)'
    )
    
    # ==================== 堆漏洞利用配置 ====================
    heap_group = parser.add_argument_group('堆漏洞利用')
    heap_group.add_argument(
        '--allocator',
        choices=['auto', 'ptmalloc', 'jemalloc'],
        default='auto',
        help='指定堆分配器类型，用于精细的堆漏洞利用策略。可选: auto(自动检测), ptmalloc(glibc), jemalloc (默认: auto)'
    )
    heap_group.add_argument(
        '--libc-version',
        help='手动指定 libc 版本（如 2.31, 2.27），用于获取准确的内部结构偏移。不指定则自动检测'
    )
    
    # ==================== 漏洞利用验证配置 ====================
    exploit_verify_group = parser.add_argument_group('漏洞利用验证')
    exploit_verify_group.add_argument(
        '--verify-exploit',
        action='store_true',
        help='启用利用脚本验证，在沙箱中执行生成的利用脚本并评估成功率'
    )
    exploit_verify_group.add_argument(
        '--verify-count',
        type=int,
        default=5,
        help='利用脚本验证的重复次数（默认: 5次）'
    )
    
    # ==================== 智能补丁建议配置 ====================
    patch_group = parser.add_argument_group('智能补丁建议')
    patch_group.add_argument(
        '--suggest-patch',
        action='store_true',
        help='为发现的漏洞生成 AI 补丁建议'
    )
    
    # ==================== 威胁情报关联配置 ====================
    threat_intel_group = parser.add_argument_group('威胁情报关联')
    threat_intel_group.add_argument(
        '--threat-intel',
        action='store_true',
        help='启用威胁情报关联，查询外部威胁情报平台'
    )
    threat_intel_group.add_argument(
        '--threat-intel-provider',
        choices=['misp', 'otx', 'all'],
        default='all',
        help='指定威胁情报提供商 (默认: all)'
    )
    threat_intel_group.add_argument(
        '--threat-intel-anonymize',
        action='store_true',
        help='匿名查询，仅发送哈希值，不发送二进制文件名'
    )
    
    parser.add_argument(
        '--sandbox',
        choices=['none', 'docker', 'podman'],
        default=None,
        help='沙箱执行环境 (覆盖环境变量 SANDBOX_MODE)'
    )
    
    parser.add_argument(
        '--static-taint',
        action='store_true',
        help='启用静态污点分析 (需要 angr 或 radare2)'
    )
    
    parser.add_argument(
        '--taint-function',
        default='main',
        help='静态污点分析的目标函数 (默认: main)'
    )
    
    parser.add_argument(
        '--ghidra-script',
        help='生成 Ghidra 标注脚本的输出路径'
    )
    
    parser.add_argument(
        '--print-report',
        action='store_true',
        help='将崩溃分析的关键信息打印到控制台（寄存器值、漏洞类型、偏移量等）'
    )

    parser.add_argument(
        '--fuzz',
        nargs=2,
        metavar=('ENGINE', 'CORPUS_PATH'),
        help='启动模糊测试，指定引擎类型和语料目录。ENGINE 可选: libfuzzer, afl, afl++, auto'
    )

    parser.add_argument(
        '--fuzz-timeout',
        type=int,
        default=3600,
        help='模糊测试超时时间（秒），默认 3600 秒（1小时）'
    )

    parser.add_argument(
        '--fuzz-output',
        help='模糊测试输出目录（默认自动生成）'
    )

    parser.add_argument(
        '--fuzz-max-crashes',
        type=int,
        help='最大崩溃数后停止模糊测试（默认不限制）'
    )

    parser.add_argument(
        '--fuzz-cpu',
        type=int,
        default=1,
        help='模糊测试使用的 CPU 核心数（默认 1）'
    )

    parser.add_argument(
        '--kernel',
        action='store_true',
        help='强制使用内核模式分析，适用于 Linux 内核模块(.ko)和 Windows 驱动(.sys)文件'
    )

    parser.add_argument(
        '--dynamic-taint',
        choices=['frida', 'qbdi'],
        help='启用动态污点追踪分析，指定引擎类型 (frida 或 qbdi)'
    )

    parser.add_argument(
        '--taint-input',
        help='动态污点分析时输入的数据文件路径（将发送给目标程序）'
    )

    parser.add_argument(
        '--taint-timeout',
        type=int,
        default=60,
        help='动态污点分析超时时间（秒），默认 60 秒'
    )

    # ==================== 分布式集群配置 ====================
    distributed_group = parser.add_argument_group('分布式集群')
    distributed_group.add_argument(
        '--distributed',
        action='store_true',
        help='启用分布式模式，使用 Celery + Redis 提交分析任务到队列'
    )
    distributed_group.add_argument(
        '--no-distributed',
        action='store_true',
        help='禁用分布式模式，使用本地单机执行（默认）'
    )
    distributed_group.add_argument(
        '--redis-host',
        default=None,
        help='Redis 服务器地址 (覆盖环境变量 REDIS_HOST)'
    )
    distributed_group.add_argument(
        '--redis-port',
        type=int,
        default=None,
        help='Redis 服务器端口 (覆盖环境变量 REDIS_PORT)'
    )
    distributed_group.add_argument(
        '--start-worker',
        action='store_true',
        help='启动 Celery Worker 而不是运行分析流水线'
    )
    distributed_group.add_argument(
        '--worker-concurrency',
        type=int,
        default=None,
        help='Worker 并发数 (覆盖环境变量 WORKER_CONCURRITY)'
    )
    distributed_group.add_argument(
        '--worker-queues',
        help='Worker 监听的队列列表，逗号分隔'
    )
    distributed_group.add_argument(
        '--worker-hostname',
        help='Worker 主机名'
    )
    distributed_group.add_argument(
        '--task-priority',
        choices=['high', 'medium', 'low'],
        default='medium',
        help='提交任务的优先级 (默认: medium)'
    )
    distributed_group.add_argument(
        '--submit-task',
        action='store_true',
        help='提交任务到分布式队列并返回任务 ID，不等待完成'
    )

    cve_group = parser.add_argument_group('CVE 查询')
    cve_group.add_argument(
        '--cve-query',
        action='store_true',
        help='执行外部 CVE 数据库查询，需配合 --cve-id、--cve-package 或 --cve-binary 使用'
    )
    cve_group.add_argument(
        '--cve-id',
        help='按 CVE ID 查询 (如: CVE-2024-12345)'
    )
    cve_group.add_argument(
        '--cve-package',
        help='按软件包名查询 (如: openssl, linux)'
    )
    cve_group.add_argument(
        '--cve-binary',
        help='按二进制文件名查询 (如: libc.so.6)'
    )
    cve_group.add_argument(
        '--cve-source',
        choices=['nvd', 'exploit_db', 'osv', 'ghadvisory', 'all'],
        default='all',
        help='指定查询的数据源 (默认: all，综合所有数据源)'
    )
    cve_group.add_argument(
        '--cve-no-cache',
        action='store_true',
        help='不使用缓存，强制重新查询'
    )
    cve_group.add_argument(
        '--cve-json',
        help='将 CVE 查询结果导出为 JSON 文件'
    )
    cve_group.add_argument(
        '--cve-limit',
        type=int,
        default=20,
        help='每个数据源返回的最大结果数 (默认: 20)'
    )

    # ==================== 固件分析配置 ====================
    firmware_group = parser.add_argument_group('固件分析')
    firmware_group.add_argument(
        '--firmware',
        help='指定固件文件路径，启用固件分析模式。自动识别格式并提取文件系统'
    )
    firmware_group.add_argument(
        '--firmware-analyze-files',
        help='指定要分析的提取文件过滤模式（如 /bin/*）'
    )
    firmware_group.add_argument(
        '--firmware-no-binwalk',
        action='store_true',
        help='禁用 binwalk，仅使用纯 Python 解析'
    )

    # ==================== 协议逆向配置 ====================
    protocol_group = parser.add_argument_group('协议逆向')
    protocol_group.add_argument(
        '--protocol-reverse',
        action='store_true',
        help='启用协议格式逆向分析，针对处理网络输入的二进制程序'
    )
    protocol_group.add_argument(
        '--protocol-samples',
        help='指定 PCAP 样本文件路径，辅助协议格式推断'
    )
    protocol_group.add_argument(
        '--protocol-fuzz',
        action='store_true',
        help='基于推断的协议格式生成针对性的模糊测试用例'
    )

    # ==================== ML 漏洞严重性预测配置 ====================
    ml_group = parser.add_argument_group('ML 漏洞严重性预测')
    ml_group.add_argument(
        '--ml-predict',
        action='store_true',
        default=True,
        help='启用机器学习漏洞严重性预测（默认启用，若模型文件存在）'
    )
    ml_group.add_argument(
        '--no-ml-predict',
        action='store_true',
        help='禁用机器学习漏洞严重性预测'
    )
    ml_group.add_argument(
        '--ml-model-path',
        help='指定自定义 ML 模型文件路径'
    )
    ml_group.add_argument(
        '--ml-train',
        action='store_true',
        help='训练默认的漏洞严重性预测模型'
    )
    ml_group.add_argument(
        '--ml-model-output',
        help='训练模型时指定输出路径'
    )

    # ==================== 移动平台深度分析 ====================
    mobile_group = parser.add_argument_group('移动平台深度分析')
    mobile_group.add_argument(
        '--mobile',
        action='store_true',
        help='启用移动平台二进制深度分析 (Android .so / iOS Mach-O)。自动检测平台, 解析 JNI/ObjC/Swift, 检测敏感字符串与危险规则'
    )
    mobile_group.add_argument(
        '--mobile-platform',
        choices=['android', 'ios', 'auto'],
        default='auto',
        help='指定移动平台, 覆盖自动检测 (默认: auto)'
    )

    # ==================== Unicorn Engine 混合分析 ====================
    unicorn_group = parser.add_argument_group('Unicorn Engine 混合分析')
    unicorn_group.add_argument(
        '--unicorn-hybrid',
        action='store_true',
        help='启用 Unicorn Engine + angr 混合分析。在符号执行遇到路径爆炸时, 切换到 Unicorn concrete 执行'
    )

    # ==================== 漏洞利用链组合 ====================
    chain_group = parser.add_argument_group('漏洞利用链组合')
    chain_group.add_argument(
        '--exploit-chain',
        action='store_true',
        help='启用漏洞利用链自动组合与攻击图生成'
    )
    chain_group.add_argument(
        '--exploit-chain-goal',
        choices=['shell', 'code_execution', 'file_read', 'file_write', 'privilege_escalation'],
        default='shell',
        help='最终攻击目标 (默认: shell)'
    )

    # ==================== WebAssembly 分析配置 ====================
    wasm_group = parser.add_argument_group('WebAssembly 分析')
    wasm_group.add_argument(
        '--wasm',
        action='store_true',
        help='强制使用 WebAssembly 分析模式，自动识别 .wasm 文件并分析'
    )
    wasm_group.add_argument(
        '--wasm-wat',
        action='store_true',
        help='生成 WAT 反编译输出（需要安装 wabt）'
    )
    wasm_group.add_argument(
        '--wasm-timeout',
        type=int,
        default=60,
        help='WebAssembly 分析超时时间（秒），默认 60 秒'
    )

    # ==================== 二进制插桩配置 ====================
    instrumentation_group = parser.add_argument_group('二进制插桩')
    instrumentation_group.add_argument(
        '--instrument',
        action='store_true',
        help='启用二进制插桩功能'
    )
    instrumentation_group.add_argument(
        '--instrument-script',
        help='指定自定义 Frida 脚本路径'
    )
    instrumentation_group.add_argument(
        '--hook-template',
        action='append',
        help='使用内置钩子模板，格式: template_name[:param=value,...] (可多次指定)'
    )
    instrumentation_group.add_argument(
        '--instrument-pid',
        type=int,
        help='附加到指定 PID 的进程进行插桩'
    )
    instrumentation_group.add_argument(
        '--instrument-target',
        help='指定要插桩的目标二进制文件路径'
    )

    # ==================== CWE 映射配置 ====================
    cwe_group = parser.add_argument_group('CWE 映射')
    cwe_group.add_argument(
        '--cwe-map',
        action='store_true',
        default=True,
        help='启用 CWE 自动分类（默认启用）'
    )
    cwe_group.add_argument(
        '--no-cwe-map',
        action='store_true',
        help='禁用 CWE 自动分类'
    )
    cwe_group.add_argument(
        '--cwe-file',
        help='指定自定义 CWE 映射文件路径'
    )

    # ==================== 并发安全分析配置 ====================
    concurrency_group = parser.add_argument_group('并发安全分析')
    concurrency_group.add_argument(
        '--concurrency',
        action='store_true',
        help='启用并发安全分析，检测数据竞争、死锁和TOCTOU竞态条件'
    )
    concurrency_group.add_argument(
        '--concurrency-threshold',
        choices=['Low', 'Medium', 'High', 'Critical'],
        default='Low',
        help='并发问题严重程度阈值（低于此阈值的问题不报告）'
    )

    # ==================== 反分析检测配置 ====================
    anti_analysis_group = parser.add_argument_group('反分析检测')
    anti_analysis_group.add_argument(
        '--anti-analyze',
        action='store_true',
        help='启用反调试/反分析技术检测，识别 ptrace、IsDebuggerPresent 等检测手段'
    )
    anti_analysis_group.add_argument(
        '--anti-analyze-bypass',
        action='store_true',
        help='自动生成并应用绕过脚本（Frida/LD_PRELOAD/GDB），需在沙箱环境中使用'
    )
    anti_analysis_group.add_argument(
        '--anti-analyze-output',
        default='./bypass',
        help='绕过脚本输出目录（默认: ./bypass）'
    )

    # ==================== 漏洞复现环境配置 ====================
    repro_env_group = parser.add_argument_group('漏洞复现环境')
    repro_env_group.add_argument(
        '--gen-repro-env',
        action='store_true',
        help='在分析结束后自动生成 Docker 复现环境'
    )
    repro_env_group.add_argument(
        '--repro-env-output',
        default=None,
        help='复现环境输出目录（默认自动生成）'
    )
    repro_env_group.add_argument(
        '--repro-env-gdbserver',
        action='store_true',
        help='在复现环境中启用 gdbserver'
    )
    repro_env_group.add_argument(
        '--repro-env-libc',
        help='指定目标 libc 版本（如 2.31），用于精确匹配基础镜像'
    )

    # ==================== Core Dump 取证分析配置 ====================
    core_forensics_group = parser.add_argument_group('Core Dump 取证分析')
    core_forensics_group.add_argument(
        '--core-forensics',
        action='store_true',
        help='对 core dump 文件进行取证分析，提取敏感数据和进程信息'
    )
    core_forensics_group.add_argument(
        '--core-forensics-timeout',
        type=int,
        default=300,
        help='Core Dump 取证分析超时时间（秒），默认 300 秒'
    )

    # ==================== 二进制安全加固审计配置 ====================
    hardening_audit_group = parser.add_argument_group('二进制安全加固审计')
    hardening_audit_group.add_argument(
        '--audit-hardening',
        action='store_true',
        help='对二进制文件进行安全加固审计，检查 NX/RELRO/Canary/PIE 等防御机制'
    )
    hardening_audit_group.add_argument(
        '--audit-hardening-timeout',
        type=int,
        default=120,
        help='加固审计超时时间（秒），默认 120 秒'
    )
    hardening_audit_group.add_argument(
        '--audit-hardening-ci',
        action='store_true',
        help='CI 模式审计，门控禁止未启用关键加固的二进制通过'
    )
    hardening_audit_group.add_argument(
        '--audit-hardening-min-score',
        type=int,
        default=60,
        help='CI 模式最低通过分数（0-100），默认 60'
    )

    # ==================== 硬件辅助安全评估配置 ====================
    hw_security_group = parser.add_argument_group('硬件辅助安全评估')
    hw_security_group.add_argument(
        '--hw-security-eval',
        action='store_true',
        default=True,
        help='评估硬件安全特性（ARM PAC/BTI、Intel CET IBT/SHSTK）对漏洞利用的影响（默认启用）'
    )
    hw_security_group.add_argument(
        '--no-hw-security-eval',
        action='store_true',
        help='禁用硬件安全评估'
    )
    hw_security_group.add_argument(
        '--hw-security-eval-detail',
        action='store_true',
        help='输出详细的硬件安全特性影响分析'
    )

    # ==================== 漏洞利用策略推荐配置 ====================
    strategy_group = parser.add_argument_group('漏洞利用策略推荐')
    strategy_group.add_argument(
        '--strategy-advisor',
        action='store_true',
        help='启用漏洞利用策略推荐，根据二进制分析结果生成最优利用方案'
    )
    strategy_group.add_argument(
        '--strategy-output',
        default='./strategy_output',
        help='策略输出目录（默认: ./strategy_output）'
    )
    strategy_group.add_argument(
        '--strategy-vuln-type',
        choices=['buffer_overflow', 'use_after_free', 'format_string', 'integer_overflow'],
        help='指定漏洞类型，用于针对性策略推荐'
    )
    strategy_group.add_argument(
        '--strategy-arch',
        choices=['x86', 'x86_64', 'arm', 'arm64'],
        help='指定目标架构（默认自动检测）'
    )

    # ==================== C++虚表恢复配置 ====================
    vtbl_group = parser.add_argument_group('C++虚表恢复')
    vtbl_group.add_argument(
        '--recover-cpp-vtbl',
        action='store_true',
        help='启用 C++ 虚函数表恢复，识别类继承关系和虚函数调用'
    )
    vtbl_group.add_argument(
        '--vtbl-output',
        default='./vtbl_output',
        help='虚表分析结果输出目录（默认: ./vtbl_output）'
    )
    vtbl_group.add_argument(
        '--vtbl-generate-dot',
        action='store_true',
        help='生成 DOT 格式的类继承关系图'
    )

    # ==================== 保护机制绕过配置 ====================
    bypass_group = parser.add_argument_group('保护机制绕过')
    bypass_group.add_argument(
        '--bypass-advisor',
        action='store_true',
        help='启用保护机制绕过策略分析，生成 ASLR/DEP/CFG/CANARY 等绕过方案'
    )
    bypass_group.add_argument(
        '--bypass-output',
        default='./bypass_output',
        help='绕过策略输出目录（默认: ./bypass_output）'
    )
    bypass_group.add_argument(
        '--bypass-info-leak',
        help='指定已知的信息泄露点地址或函数名，辅助绕过分析'
    )

    # ==================== 测试生成配置 ====================
    testgen_group = parser.add_argument_group('测试生成')
    testgen_group.add_argument(
        '--gen-tests',
        action='store_true',
        help='为二进制文件生成测试用例'
    )
    testgen_group.add_argument(
        '--test-output',
        default='./test_output',
        help='测试用例输出目录（默认: ./test_output）'
    )
    testgen_group.add_argument(
        '--test-language',
        choices=['c', 'python', 'fuzzer'],
        default='python',
        help='测试用例语言（默认: python）'
    )
    testgen_group.add_argument(
        '--test-cases',
        type=int,
        default=5,
        help='每个函数生成的测试用例数量（默认: 5）'
    )

    # ==================== 增量分析配置 ====================
    incremental_group = parser.add_argument_group('增量分析')
    incremental_group.add_argument(
        '--incremental',
        action='store_true',
        help='启用增量分析缓存，加速重复分析'
    )
    incremental_group.add_argument(
        '--no-cache',
        action='store_true',
        help='禁用缓存（配合 --incremental 使用）'
    )
    incremental_group.add_argument(
        '--cache-invalidate',
        action='store_true',
        help='失效现有缓存'
    )
    incremental_group.add_argument(
        '--cache-dir',
        default='./.cache',
        help='缓存目录（默认: ./.cache）'
    )

    # ==================== ML函数边界检测配置 ====================
    ml_boundary_group = parser.add_argument_group('ML函数边界检测')
    ml_boundary_group.add_argument(
        '--ml-boundary',
        action='store_true',
        help='启用 ML 函数边界检测，使用机器学习模型识别函数边界'
    )
    ml_boundary_group.add_argument(
        '--boundary-model',
        help='指定自定义 ML 模型路径'
    )
    ml_boundary_group.add_argument(
        '--boundary-output',
        default='./boundary_output',
        help='边界检测结果输出目录（默认: ./boundary_output）'
    )
    ml_boundary_group.add_argument(
        '--boundary-confidence',
        type=float,
        default=0.5,
        help='检测置信度阈值（默认: 0.5）'
    )

    return parser.parse_args()


def load_crash_data(json_path: str) -> Optional[Dict[str, Any]]:
    """
    加载崩溃数据 JSON 文件
    """
    import json
    logger = logging.getLogger(__name__)
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            crash_data = json.load(f)
        
        is_valid, error_msg = validate_crash_data(crash_data)
        if not is_valid:
            logger.error(f"崩溃数据格式错误: {error_msg}")
            return None
        
        logger.info(f"已加载崩溃数据: {json_path}")
        return crash_data
        
    except json.JSONDecodeError as e:
        logger.error(f"解析崩溃数据 JSON 失败: {e}")
        return None
    except FileNotFoundError:
        logger.error(f"崩溃数据文件不存在: {json_path}")
        return None
    except Exception as e:
        logger.error(f"加载崩溃数据失败: {e}")
        return None


def run_health_check(binary_path: str = None):
    """
    运行全面的健康检查，检查所有依赖、引擎和配置
    
    Args:
        binary_path: 可选的二进制文件路径，用于测试解析能力
    """
    import logging
    from config import Config, get_openai_client, mask_api_key, test_api_connection
    
    logger = logging.getLogger(__name__)
    
    logger.info("=" * 60)
    logger.info("🏥 Deemo 健康检查 (Doctor Mode)")
    logger.info("=" * 60)
    
    status = {
        'dependencies': {},
        'decompilers': {},
        'ai_client': {},
        'symbolic_execution': {},
        'other_tools': {},
        'binary_analysis': {},
        'overall': 'Unknown'
    }
    
    all_passed = True
    
    logger.info("\n📦 Python 依赖检查:")
    deps_to_check = {
        'openai': 'openai - 用于 AI API 调用',
        'pwntools (pwn)': 'pwn - 用于漏洞利用生成',
        'angr': 'angr - 用于符号执行 (可选)',
        'pefile': 'pefile - 用于 PE 文件分析 (可选)',
        'macholib': 'macholib - 用于 Mach-O 文件分析 (可选)',
        'capstone': 'capstone - 用于反汇编 (可选)',
    }
    
    critical_deps = ['openai', 'pwntools (pwn)']
    
    for name, description in deps_to_check.items():
        import_name = name.split()[0]
        try:
            module = __import__(import_name)
            version = getattr(module, '__version__', 'unknown')
            status['dependencies'][name] = {'status': '✓ 可用', 'version': version}
            logger.info(f"  ✓ {name:30s} - {description} (版本: {version})")
        except ImportError:
            status['dependencies'][name] = {'status': '✗ 未安装'}
            if name in critical_deps:
                logger.warning(f"  ✗ {name:30s} - {description} (必要依赖，未安装)")
                all_passed = False
            else:
                logger.info(f"  ⚠ {name:30s} - {description} (可选，未安装)")
    
    logger.info("\n🔧 反编译引擎检测:")
    decompilers_to_check = [
        ('radare2', ['r2', '-v'], f'超时: {Config.RADARE2_TIMEOUT}s'),
        ('ghidra', ['which', 'analyzeHeadless'], f'超时: {Config.GHIDRA_TIMEOUT}s'),
        ('ida', ['which', 'ida64'], ''),
    ]
    
    import subprocess
    for name, cmd, extra in decompilers_to_check:
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=5, text=True, errors='replace')
            if result.returncode == 0:
                version_info = ''
                if name == 'radare2' and result.stdout:
                    version_match = result.stdout.strip().split('\n')[0]
                    version_info = f" ({version_info})"
                status['decompilers'][name] = {'status': '✓ 可用', 'extra': extra}
                logger.info(f"  ✓ {name:15s} - 可用 {extra}")
            else:
                raise Exception(f"return code {result.returncode}")
        except Exception:
            status['decompilers'][name] = {'status': '✗ 未安装'}
            if name == 'radare2':
                logger.warning(f"  ✗ {name:15s} - 未安装 (建议安装)")
                all_passed = False
            else:
                logger.info(f"  ⚠ {name:15s} - 未安装 (可选)")
    
    try:
        import binaryninja
        status['decompilers']['binaryninja'] = {'status': '✓ 可用 (Python API)'}
        logger.info(f"  ✓ binaryninja     - 可用 (Python API)")
    except ImportError:
        status['decompilers']['binaryninja'] = {'status': '✗ 未安装'}
        logger.info(f"  ⚠ binaryninja    - 未安装 (可选)")
    
    logger.info("\n🤖 AI 客户端配置:")
    logger.info(f"  Provider:      {Config.AI_PROVIDER}")
    logger.info(f"  模型:          {get_current_ai_model()}")
    
    api_key_configured = False
    if Config.AI_PROVIDER == 'openai' and Config.OPENAI_API_KEY:
        masked_key = mask_api_key(Config.OPENAI_API_KEY)
        logger.info(f"  API Key:       {masked_key}")
        api_key_configured = True
    elif Config.AI_PROVIDER == 'azure' and Config.AZURE_API_KEY:
        masked_key = mask_api_key(Config.AZURE_API_KEY)
        logger.info(f"  Azure API Key: {masked_key}")
        logger.info(f"  Endpoint:      {Config.AZURE_ENDPOINT}")
        api_key_configured = True
    elif Config.AI_PROVIDER == 'ollama':
        logger.info(f"  Ollama Host:   {Config.OLLAMA_HOST}")
        api_key_configured = True
    elif Config.AI_PROVIDER == 'llamacpp':
        logger.info(f"  llama.cpp Host:{Config.LLAMACPP_HOST}")
        api_key_configured = True
    elif Config.AI_PROVIDER == 'custom':
        logger.info(f"  Custom URL:    {Config.CUSTOM_BASE_URL or '未配置'}")
        if Config.CUSTOM_API_KEY:
            logger.info(f"  Custom Key:    {mask_api_key(Config.CUSTOM_API_KEY)}")
        api_key_configured = bool(Config.CUSTOM_BASE_URL)
    else:
        logger.info("  API Key:       未配置")
        logger.warning("  ⚠ AI API 未配置，将使用启发式分析模式")
    
    status['ai_client'] = {
        'provider': Config.AI_PROVIDER,
        'model': get_current_ai_model(),
        'api_key_configured': api_key_configured,
    }
    
    if api_key_configured:
        logger.info("\n  🔌 测试 AI API 连接...")
        try:
            client = get_openai_client()
            if client:
                if test_api_connection(client):
                    logger.info("  ✓ AI API 连接成功")
                    status['ai_client']['connection'] = '✓ 成功'
                else:
                    logger.warning("  ✗ AI API 连接测试失败")
                    status['ai_client']['connection'] = '✗ 失败'
                    all_passed = False
            else:
                logger.warning("  ⚠ 无法创建 AI 客户端")
                status['ai_client']['connection'] = '⚠ 无法创建客户端'
        except Exception as e:
            logger.warning(f"  ✗ AI API 测试异常: {e}")
            status['ai_client']['connection'] = f'✗ 异常: {e}'
    
    logger.info("\n⚡ 符号执行引擎:")
    try:
        import angr
        angr_version = getattr(angr, '__version__', 'unknown')
        status['symbolic_execution']['angr'] = {'status': '✓ 可用', 'version': angr_version, 'timeout': Config.ANGR_TIMEOUT}
        logger.info(f"  ✓ angr          - 可用 (版本: {angr_version}, 超时: {Config.ANGR_TIMEOUT}s)")
    except ImportError:
        status['symbolic_execution']['angr'] = {'status': '✗ 未安装'}
        logger.info(f"  ⚠ angr          - 未安装 (可选功能不可用)")
    
    logger.info("\n🛠️  其他系统工具:")
    tools_to_check = ['objdump', 'file', 'readelf', 'objcopy', 'strings', 'nm']
    for tool in tools_to_check:
        try:
            subprocess.run(['where.exe' if os.name == 'nt' else 'which', tool], capture_output=True, timeout=5)
            status['other_tools'][tool] = '✓ 可用'
            logger.info(f"  ✓ {tool}")
        except Exception:
            status['other_tools'][tool] = '✗ 未找到'
            logger.info(f"  ✗ {tool} (未找到)")
    
    if binary_path:
        logger.info("\n📁 二进制文件解析测试:")
        try:
            from modules.info_collect import validate_binary_path, get_binary_info, detect_binary_format
            
            validated = validate_binary_path(binary_path)
            logger.info(f"  ✓ 文件路径验证: {validated}")
            
            binary_format = detect_binary_format(validated)
            status['binary_analysis']['format'] = binary_format
            logger.info(f"  ✓ 文件格式检测: {binary_format}")
            
            binary_info = get_binary_info(validated)
            if binary_info:
                status['binary_analysis']['info'] = binary_info
                logger.info(f"  ✓ 架构: {binary_info.get('arch', 'unknown')}")
                logger.info(f"  ✓ 位数: {binary_info.get('bits', 0)}-bit")
                checksec = binary_info.get('checksec', {})
                logger.info(f"  ✓ Checksec: NX={checksec.get('nx', '?')}, PIE={checksec.get('pie', '?')}, RELRO={checksec.get('relro', '?')}, Canary={checksec.get('canary', '?')}")
                dangerous_funcs = binary_info.get('imports', {}).get('dangerous_functions', [])
                if dangerous_funcs:
                    logger.info(f"  ✓ 危险函数: {', '.join(dangerous_funcs[:5])}{'...' if len(dangerous_funcs) > 5 else ''}")
            else:
                logger.warning("  ✗ 无法获取二进制信息")
                all_passed = False
                
        except Exception as e:
            logger.warning(f"  ✗ 二进制解析失败: {e}")
            status['binary_analysis']['error'] = str(e)
            all_passed = False
    
    logger.info("\n" + "=" * 60)
    status['overall'] = '✓ 通过' if all_passed else '⚠ 部分通过'
    logger.info(f"健康检查结果: {status['overall']}")
    logger.info("=" * 60)
    
    if not all_passed:
        logger.info("\n💡 建议:")
        logger.info("  - 运行 `pip install -r requirements.txt` 安装缺失的 Python 依赖")
        logger.info("  - 安装 radare2: `sudo apt install radare2` 或从官网下载")
        logger.info("  - 配置 AI API Key: 编辑 config.py 中的 Config.OPENAI_API_KEY")
    
    return status


def print_crash_analysis_report(
    crash_data: Optional[Dict[str, Any]],
    crash_analysis: Optional[Dict[str, Any]],
    decomp_results: List[Dict[str, Any]]
) -> None:
    """
    打印崩溃分析报告到控制台
    
    Args:
        crash_data: 原始崩溃数据
        crash_analysis: 崩溃分析结果
        decomp_results: 函数分析结果
    """
    severity_colors = {
        'Critical': '\033[91m',
        'High': '\033[91m',
        'Medium': '\033[93m',
        'Low': '\033[94m',
        'Unknown': '\033[0m'
    }
    reset_color = '\033[0m'
    
    print("\n" + "=" * 70)
    print("崩溃分析报告")
    print("=" * 70)
    
    if crash_data:
        print("\n【原始崩溃信息】")
        print("-" * 70)
        
        if 'signal' in crash_data and crash_data['signal']:
            print(f"  信号: {crash_data['signal']}")
        
        if 'fault_instruction' in crash_data and crash_data['fault_instruction']:
            print(f"  崩溃指令: {crash_data['fault_instruction']}")
        
        if 'error_type' in crash_data and crash_data['error_type']:
            print(f"  错误类型: {crash_data['error_type']}")
        
        if 'fault_address' in crash_data and crash_data['fault_address']:
            print(f"  崩溃地址: {crash_data['fault_address']}")
        
        registers = {}
        if 'registers' in crash_data:
            if isinstance(crash_data['registers'], dict):
                registers = crash_data['registers']
            elif isinstance(crash_data['registers'], str):
                from modules.crash_analysis import parse_registers_from_text
                registers = parse_registers_from_text(crash_data['registers'])
        
        if registers:
            print(f"\n  寄存器值:")
            key_regs = ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp', 
                       'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi']
            for reg in key_regs:
                if reg in registers:
                    print(f"    {reg:>4} = {registers[reg]}")
            
            other_regs = [(k, v) for k, v in registers.items() if k not in key_regs]
            if other_regs:
                for reg, val in other_regs[:8]:
                    print(f"    {reg:>4} = {val}")
                if len(other_regs) > 8:
                    print(f"    ... 还有 {len(other_regs) - 8} 个寄存器")
        
        if 'stack_trace' in crash_data and crash_data['stack_trace']:
            print(f"\n  栈回溯:")
            stack = crash_data['stack_trace']
            if isinstance(stack, list):
                for i, frame in enumerate(stack[:5]):
                    if isinstance(frame, dict):
                        addr = frame.get('address', '?')
                        func = frame.get('function', '?')
                        print(f"    #{i} {addr} in {func}")
                    else:
                        print(f"    #{i} {frame}")
                if len(stack) > 5:
                    print(f"    ... 还有 {len(stack) - 5} 个栈帧")
            else:
                lines = str(stack).split('\n')[:5]
                for line in lines:
                    print(f"    {line}")
    
    if crash_analysis:
        print("\n【崩溃分析结果】")
        print("-" * 70)
        
        combined = crash_analysis.get('combined', {})
        
        crash_type = combined.get('crash_type', 'Unknown')
        print(f"  崩溃类型: {crash_type}")
        
        vuln_type = combined.get('vulnerability_type', 'Unknown')
        severity = combined.get('exploitability', 'Unknown')
        color = severity_colors.get(severity, reset_color)
        print(f"  漏洞类型: {vuln_type}")
        print(f"  可利用性: {color}{severity}{reset_color}")
        
        difficulty = combined.get('difficulty', 'Unknown')
        print(f"  利用难度: {difficulty}")
        
        analysis = combined.get('analysis', '')
        if analysis:
            short_analysis = analysis[:200] + '...' if len(analysis) > 200 else analysis
            print(f"\n  分析摘要: {short_analysis}")
        
        recommendations = combined.get('recommendations', [])
        if recommendations:
            print(f"\n  建议:")
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"    [{i}] {rec}")
    
    if decomp_results:
        print("\n【函数分析漏洞汇总】")
        print("-" * 70)
        
        total_vulns = 0
        for result in decomp_results:
            func_name = result.get('function_name', 'Unknown')
            analysis = result.get('analysis', {})
            vulns = analysis.get('vulnerabilities', [])
            
            if vulns:
                total_vulns += len(vulns)
                print(f"\n  函数: {func_name}")
                for vuln in vulns:
                    v_type = vuln.get('type', 'Unknown')
                    v_severity = vuln.get('severity', 'Unknown')
                    v_location = vuln.get('location', 'N/A')
                    v_color = severity_colors.get(v_severity, reset_color)
                    print(f"    - {v_color}{v_severity}{reset_color}: {v_type} (位置: {v_location})")
        
        if total_vulns == 0:
            print("  未发现明显漏洞")
    
    print("\n" + "=" * 70)
    print("报告结束")
    print("=" * 70 + "\n")


def main():
    """
    主函数
    """
    args = parse_arguments()
    
    if args.debug:
        args.log_level = 'DEBUG'
    
    setup_logging(args.log_level)
    logger = logging.getLogger(__name__)
    
    if args.sandbox:
        os.environ['SANDBOX_MODE'] = args.sandbox
        logger.info(f"沙箱模式已设置: {args.sandbox}")
    
    # 分布式模式配置
    if args.distributed and not args.no_distributed:
        logger.info("分布式模式: 已启用")
    elif args.no_distributed:
        logger.info("分布式模式: 已禁用（单机模式）")
    
    # 处理 Redis 配置覆盖
    if args.redis_host:
        os.environ['REDIS_HOST'] = args.redis_host
        logger.info(f"Redis 主机: {args.redis_host}")
    if args.redis_port:
        os.environ['REDIS_PORT'] = str(args.redis_port)
        logger.info(f"Redis 端口: {args.redis_port}")
    
    # 启动 Celery Worker 模式
    if args.start_worker:
        logger.info("启动 Celery Worker 模式...")
        try:
            from modules.worker import start_worker
            start_worker(
                concurrency=args.worker_concurrency or Config.WORKER_CONCURRENCY,
                queues=[q.strip() for q in args.worker_queues.split(',')] if args.worker_queues else None,
                hostname=args.worker_hostname
            )
        except ImportError as e:
            logger.error(f"无法启动 Worker: {e}")
            logger.error("请安装依赖: pip install celery redis")
            sys.exit(1)
        return 0
    
    # 提交分布式任务模式
    if args.submit_task and args.binary:
        if not args.distributed:
            logger.warning("使用 --submit-task 需要配合 --distributed 启用分布式模式")
            sys.exit(1)
        
        try:
            from modules.worker import submit_analysis_task, CELERY_AVAILABLE
            
            if not CELERY_AVAILABLE:
                logger.error("Celery 未安装，无法提交分布式任务")
                logger.error("请安装依赖: pip install celery redis")
                sys.exit(1)
            
            options = {
                'functions': args.functions,
                'use_ai': not args.no_ai,
                'enable_symbolic': args.enable_symbolic_execution,
                'include_lib': args.include_lib,
                'parallel': args.parallel,
                'max_parallel': args.max_parallel,
                'expert_mode': args.expert,
                'no_rop': args.no_rop,
            }
            
            task_id = submit_analysis_task(
                binary_path=args.binary,
                options=options,
                priority=args.task_priority
            )
            
            if task_id:
                logger.info(f"任务已提交: {task_id}")
                print(f"\n任务 ID: {task_id}")
                print(f"查看状态: curl http://localhost:8000/api/distributed/status/{task_id}")
            else:
                logger.error("任务提交失败")
                sys.exit(1)
        except Exception as e:
            logger.error(f"提交分布式任务失败: {e}")
            sys.exit(1)
        return 0
    
    if args.server:
        logger.info("启动 Web API 服务器...")
        if args.collaborate:
            logger.info("多用户协作模式: 已启用")
        
        try:
            from modules.web_api import start_server
            start_server(
                host=args.host,
                port=args.port,
                reload=args.debug,
                collaborate=args.collaborate
            )
        except ImportError as e:
            logger.error(f"无法启动 API 服务器: {e}")
            logger.error("请安装依赖: pip install fastapi uvicorn python-multipart")
            sys.exit(1)
        return 0
    
    if args.health or args.doctor:
        run_health_check(binary_path=args.binary)
        return 0

    if args.cve_query:
        if not (args.cve_id or args.cve_package or args.cve_binary):
            logger.error("CVE 查询需要至少提供一个查询条件: --cve-id、--cve-package 或 --cve-binary")
            sys.exit(1)

        logger.info("=" * 60)
        logger.info("CVE 数据库查询")
        logger.info("=" * 60)

        if args.cve_id:
            logger.info(f"CVE ID: {args.cve_id}")
        if args.cve_package:
            logger.info(f"软件包: {args.cve_package}")
        if args.cve_binary:
            logger.info(f"二进制文件: {args.cve_binary}")
        logger.info(f"数据源: {args.cve_source}")
        logger.info(f"缓存: {'禁用' if args.cve_no_cache else '启用'}")

        results = run_cve_query(
            cve_id=args.cve_id,
            package_name=args.cve_package,
            binary_name=args.cve_binary,
            source=args.cve_source,
            use_cache=not args.cve_no_cache,
            limit=args.cve_limit
        )

        print_cve_query_results(results, limit=args.cve_limit)

        if args.cve_json:
            try:
                import json
                output_dir = os.path.dirname(args.cve_json)
                if output_dir and not os.path.exists(output_dir):
                    os.makedirs(output_dir, exist_ok=True)

                with open(args.cve_json, 'w', encoding='utf-8') as f:
                    json.dump(results, f, ensure_ascii=False, indent=2)
                logger.info(f"CVE 查询结果已保存到: {args.cve_json}")
            except Exception as e:
                logger.error(f"保存 JSON 文件失败: {e}")

        return 0
    
    if args.fuzz:
        engine, corpus_path = args.fuzz
        logger.info("=" * 60)
        logger.info(f"启动模糊测试 (引擎: {engine}, 语料: {corpus_path})")
        logger.info("=" * 60)
        
        if not args.binary:
            logger.error("错误: 模糊测试需要提供二进制文件路径")
            sys.exit(1)
        
        try:
            from modules.fuzz_integration import FuzzManager
            
            fuzz_manager = FuzzManager(
                binary_path=args.binary,
                fuzzer_type=engine,
                corpus_path=corpus_path,
                output_dir=args.fuzz_output,
                use_sandbox=True
            )
            
            logger.info(f"FuzzManager 初始化完成，会话 ID: {fuzz_manager.session_id}")
            
            result = fuzz_manager.start(
                timeout=args.fuzz_timeout,
                max_crashes=args.fuzz_max_crashes,
                cpu_limit=args.fuzz_cpu
            )
            
            if result.get('success'):
                logger.info("模糊测试已启动")
                logger.info(f"输出目录: {fuzz_manager.output_dir}")
                logger.info(f"状态查询: 使用 API 或 get_status() 方法")
                
                status = fuzz_manager.get_status()
                while status.get('status') == 'running':
                    logger.info(f"模糊测试运行中 - 已发现 {status.get('crashes_found', 0)} 个崩溃")
                    import time
                    time.sleep(30)
                    status = fuzz_manager.get_status()
                
                crashes_found = status.get('crashes_found', 0)
                logger.info(f"模糊测试结束，共发现 {crashes_found} 个崩溃")
                
                if crashes_found > 0:
                    crashes = fuzz_manager.get_crashes()
                    logger.info("崩溃详情:")
                    for i, crash in enumerate(crashes[:5], 1):
                        logger.info(f"  [{i}] {crash.get('crash_type', 'Unknown')} - {crash.get('input_file', 'N/A')}")
                
                fuzz_manager.stop()
                return 0
            else:
                logger.error(f"启动模糊测试失败: {result.get('error')}")
                return 1
                
        except ImportError as e:
            logger.error(f"导入 FuzzManager 失败: {e}")
            return 1
        except Exception as e:
            logger.error(f"模糊测试执行失败: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return 1
    
    if not args.binary:
        logger.error("错误: 需要提供二进制文件路径")
        sys.exit(1)
    
    logger.info("=" * 60)
    logger.info("LLM 辅助的二进制漏洞分析工具 v1.1.0")
    logger.info("=" * 60)
    
    if args.debug:
        logger.debug("调试模式已启用，将打印 LLM 请求/响应（脱敏后）")
    
    if args.plugin:
        logger.info(f"加载插件: {args.plugin}")
        from modules.decomp_ai import load_plugin_script
        for plugin_path in args.plugin:
            load_plugin_script(plugin_path)
    
    if not args.skip_deps_check:
        missing = check_dependencies()
        if missing:
            logger.error("依赖检查失败，请先安装缺失的依赖")
            sys.exit(1)
    
    crash_data = None
    if args.crash:
        if args.crash_format == 'auto':
            logger.info("自动检测崩溃数据格式...")
        else:
            logger.info(f"使用指定的崩溃数据格式: {args.crash_format}")
        
        crash_data = load_and_parse_crash_data(args.crash, args.crash_format)
        if not crash_data:
            logger.warning("崩溃数据加载失败，将跳过崩溃分析")
        else:
            logger.info(f"崩溃数据加载成功，格式: {crash_data.get('format', 'json')}")
    
    logger.info(f"反编译引擎: {args.decompiler}")
    if args.enable_symbolic_execution:
        logger.info("符号执行: 已启用")
    if args.no_db:
        logger.info("漏洞数据库: 已禁用")
    if args.no_exec:
        logger.info("利用脚本执行: 已禁用 (默认安全模式)")
    else:
        logger.warning("利用脚本执行: 已启用，请确保在隔离环境中运行！")
    if args.include_lib:
        logger.info("库函数分析: 已启用")
    logger.info(f"输出格式: {args.output_format}")
    if args.parallel:
        logger.info(f"并行分析: 已启用 (最大 {args.max_parallel} 个)")
    if args.interactive:
        logger.info("交互式分析模式: 已启用")
    
    if args.hooks_dir:
        logger.info(f"钩子目录: {args.hooks_dir}")
    
    if args.fuzzer != 'none':
        logger.info(f"Fuzzer 集成: {args.fuzzer}")
    if args.expert:
        logger.warning("专家模式已启用，将生成高级利用链")
    if args.static_taint:
        logger.info(f"静态污点分析: 已启用 (目标函数: {args.taint_function})")
    
    if args.dynamic_taint:
        logger.info(f"动态污点追踪: 已启用 (引擎: {args.dynamic_taint})")
    
    static_taint_result = None
    if args.static_taint:
        try:
            from modules.static_analysis import perform_static_taint_analysis
            logger.info("运行静态污点分析...")
            static_taint_result = perform_static_taint_analysis(args.binary, args.taint_function)
            if static_taint_result:
                logger.info(f"静态污点分析完成: 发现 {len(static_taint_result.get('tainted_vars', []))} 个污点变量")
        except Exception as e:
            logger.warning(f"静态污点分析失败: {e}")
    
    taint_input_data = None
    if args.taint_input:
        try:
            with open(args.taint_input, 'rb') as f:
                taint_input_data = f.read()
            logger.info(f"已加载污点输入数据: {len(taint_input_data)} 字节")
        except Exception as e:
            logger.warning(f"加载污点输入数据失败: {e}")

    if args.strategy_advisor:
        logger.info("漏洞利用策略推荐: 已启用")

    if args.recover_cpp_vtbl:
        logger.info("C++虚表恢复: 已启用")

    if args.bypass_advisor:
        logger.info("保护机制绕过策略: 已启用")

    if args.gen_tests:
        logger.info("测试用例生成: 已启用")

    if args.incremental:
        logger.info("增量分析缓存: 已启用")

    if args.ml_boundary:
        logger.info("ML函数边界检测: 已启用")
    
    result = run_pipeline(
        binary_path=args.binary,
        functions_to_analyze=args.functions,
        crash_data=crash_data,
        validate_exploit=args.validate,
        no_exec=args.no_exec,
        use_ai=not args.no_ai,
        output_dir=args.output,
        decompiler=args.decompiler,
        enable_symbolic_execution=args.enable_symbolic_execution,
        use_vuln_db=not args.no_db,
        include_lib=args.include_lib,
        interactive=args.interactive,
        output_format=args.output_format,
        parallel=args.parallel,
        max_parallel=args.max_parallel,
        hooks_dir=args.hooks_dir,
        fuzzer_type=args.fuzzer if args.fuzzer != 'none' else None,
        expert_mode=args.expert,
        export_corpus_dir=args.export_corpus,
        no_rop=args.no_rop,
        dynamic_taint_engine=args.dynamic_taint,
        taint_input_data=taint_input_data,
        taint_timeout=args.taint_timeout,
        allocator_type=args.allocator,
        libc_version=args.libc_version,
        force_kernel=args.kernel,
        project_name=args.project,
        project_resume=args.project_resume,
        project_new=args.project_new,
        language=args.language,
        enable_unpack=not args.no_unpack,
        unpack_tool_path=args.unpack_tool,
        enable_crypto_scan=not args.no_crypto_scan,
        enable_mobile=args.mobile,
        mobile_platform=args.mobile_platform,
        enable_unicorn_hybrid=args.unicorn_hybrid,
        enable_exploit_chain=args.exploit_chain,
        exploit_chain_goal=args.exploit_chain_goal,
    )
    
    if 'error' in result:
        logger.error(f"分析失败: {result['error']}")
        sys.exit(1)
    
    if args.print_report:
        print_crash_analysis_report(
            crash_data=crash_data,
            crash_analysis=result.get('crash_analysis'),
            decomp_results=result.get('decomp_analysis', [])
        )
    
    reports = result.get('reports', {})
    logger.info("")
    logger.info("=" * 60)
    logger.info("分析完成")
    logger.info(f"Markdown 报告: {reports.get('markdown', 'N/A')}")
    logger.info(f"JSON 报告: {reports.get('json', 'N/A')}")
    
    similar_vulns = result.get('similar_vulnerabilities', [])
    if similar_vulns:
        logger.info(f"数据库相似漏洞: {len(similar_vulns)} 个")
    
    decomp_results = result.get('decomp_analysis', [])
    total_vulns = sum(len(r.get('analysis', {}).get('vulnerabilities', [])) for r in decomp_results)
    logger.info(f"发现漏洞总数: {total_vulns}")
    
    symbolic_result = result.get('symbolic_execution')
    if symbolic_result:
        sym_success = symbolic_result.get('success', False)
        logger.info(f"符号执行: {'成功' if sym_success else '失败或跳过'}")
    
    exploit_result = result.get('exploit_result')
    if exploit_result:
        status = "成功" if exploit_result.get('success') else "需要调试"
        logger.info(f"利用脚本状态: {status}")
        if exploit_result.get('script_path'):
            logger.info(f"利用脚本: {exploit_result['script_path']}")

    if args.strategy_advisor:
        try:
            from modules.exploit_strategy import ExploitStrategyAdvisor
            logger.info("\n运行漏洞利用策略推荐...")
            advisor = ExploitStrategyAdvisor()
            strategy_result = advisor.analyze(
                binary_path=args.binary,
                vuln_type=args.strategy_vuln_type,
                arch=args.strategy_arch,
                output_dir=args.strategy_output
            )
            if strategy_result.get('success'):
                logger.info(f"策略分析完成，输出目录: {args.strategy_output}")
                if strategy_result.get('strategy_file'):
                    logger.info(f"策略文件: {strategy_result['strategy_file']}")
            else:
                logger.warning(f"策略分析失败: {strategy_result.get('error')}")
        except Exception as e:
            logger.warning(f"漏洞利用策略推荐失败: {e}")

    if args.recover_cpp_vtbl:
        try:
            from modules.cpp_vtbl_recovery import VtblRecovery
            logger.info("\n运行C++虚表恢复...")
            vtbl_recovery = VtblRecovery()
            vtbl_result = vtbl_recovery.recover(
                binary_path=args.binary,
                output_dir=args.vtbl_output,
                generate_dot=args.vtbl_generate_dot
            )
            if vtbl_result.get('success'):
                logger.info(f"虚表恢复完成，输出目录: {args.vtbl_output}")
                logger.info(f"恢复的虚表数量: {vtbl_result.get('vtbl_count', 0)}")
            else:
                logger.warning(f"虚表恢复失败: {vtbl_result.get('error')}")
        except Exception as e:
            logger.warning(f"C++虚表恢复失败: {e}")

    if args.bypass_advisor:
        try:
            from modules.bypass_advisor import BypassAdvisor
            logger.info("\n运行保护机制绕过分析...")
            bypass_advisor = BypassAdvisor()
            bypass_result = bypass_advisor.analyze(
                binary_path=args.binary,
                output_dir=args.bypass_output,
                info_leak=args.bypass_info_leak
            )
            if bypass_result.get('success'):
                logger.info(f"绕过分析完成，输出目录: {args.bypass_output}")
            else:
                logger.warning(f"绕过分析失败: {bypass_result.get('error')}")
        except Exception as e:
            logger.warning(f"保护机制绕过分析失败: {e}")

    if args.gen_tests:
        try:
            from modules.test_generator import TestGenerator
            logger.info("\n生成测试用例...")
            test_gen = TestGenerator()
            
            decomp_results = result.get('decomp_analysis', [])
            functions = [r.get('function_name') for r in decomp_results if r.get('function_name')]
            if not functions:
                functions = ['main']
            
            suite = test_gen.generate_test_suite(
                target_binary=args.binary,
                functions=functions,
                test_count=args.test_cases
            )
            
            os.makedirs(args.test_output, exist_ok=True)
            if args.test_language == 'python':
                output_file = os.path.join(args.test_output, 'test_cases.py')
                test_gen.export_to_pytest(suite, output_file)
            elif args.test_language == 'c':
                output_file = os.path.join(args.test_output, 'test_cases.c')
                logger.info("C语言测试用例生成功能开发中，暂输出JSON格式")
                output_file = os.path.join(args.test_output, 'test_cases.json')
                test_gen.export_to_json(suite, output_file)
            else:
                output_file = os.path.join(args.test_output, 'fuzz_corpus.json')
                test_gen.export_to_json(suite, output_file)
            
            logger.info(f"测试用例生成完成，输出文件: {output_file}")
            logger.info(f"生成的测试用例数量: {len(suite.test_cases)}")
        except Exception as e:
            logger.warning(f"测试用例生成失败: {e}")

    if args.ml_boundary:
        try:
            from modules.function_boundary import FunctionBoundaryDetector
            logger.info("\n运行ML函数边界检测...")
            detector = FunctionBoundaryDetector()
            
            with open(args.binary, 'rb') as f:
                binary_data = f.read()
            
            boundary_result = detector.analyze(
                binary_data=binary_data,
                base_address=0
            )
            
            if boundary_result.get('success'):
                os.makedirs(args.boundary_output, exist_ok=True)
                result_data = boundary_result.get('result', {})
                
                import json
                output_file = os.path.join(args.boundary_output, 'boundaries.json')
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(result_data, f, indent=2)
                
                logger.info(f"边界检测完成，输出文件: {output_file}")
                logger.info(f"检测到的函数边界数量: {result_data.get('total_functions', 0)}")
            else:
                logger.warning(f"边界检测失败: {boundary_result.get('error')}")
        except Exception as e:
            logger.warning(f"ML函数边界检测失败: {e}")

    if args.incremental:
        if args.cache_invalidate:
            try:
                from modules.incremental_analysis import IncrementalAnalyzer
                analyzer = IncrementalAnalyzer()
                analyzer.invalidate_cache()
                logger.info("\n增量分析缓存已失效")
            except Exception as e:
                logger.warning(f"失效缓存失败: {e}")
    
    logger.info("=" * 60)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
