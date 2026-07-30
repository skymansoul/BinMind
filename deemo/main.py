#!/usr/bin/env python3
"""
<<<<<<< HEAD
大语言模型辅助的二进制漏洞分析工具

=======
Main launcher. Delegates analysis to core.pipeline and reporting
to core.report. Kept around for backward compatibility — scripts
that `from main import run_pipeline` still work.

Direct CLI usage should go through binmind.py, which binds to
cli.commands for proper argument parsing.
>>>>>>> d81973a (精简冗余模块)
"""

import argparse
import os
import sys
import time

<<<<<<< HEAD
from config import (
    Config, check_openai_api_key, get_openai_client, ensure_directories, 
    validate_crash_data, get_current_ai_model, SensitiveFilter, mask_sensitive_data
)
from modules.info_collect import get_binary_info, detect_binary_format, validate_binary_path
from modules.decomp_ai import DecompilerAI, strip_ansi_escape
from modules.crash_analysis import CrashAnalyzer, load_and_parse_crash_data
from modules.exploit_gen import ExploitGenerator
from modules.report import ReportGenerator
from modules.symbolic_exe import SymbolicExecutor, ANGR_AVAILABLE
from modules.vuln_db import VulnerabilityDatabase
from modules.hooks import get_hook_manager


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
    no_rop: bool = False
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
    
    report_gen = ReportGenerator(output_dir=output_dir)
    report_gen.add_step('Pipeline Started', {'binary_path': validated_path})
    
    if not os.path.exists(validated_path):
        logger.error(f"文件不存在: {validated_path}")
        return {'error': f'File not found: {validated_path}'}
    
    binary_format = detect_binary_format(validated_path)
    logger.info(f"检测到文件格式: {binary_format}")
    
    client = get_openai_client() if use_ai else None
    
    logger.info("步骤 1/6: 收集二进制文件信息...")
    report_gen.add_step('Info Collection Started')
    
    hook_manager.run_hooks('pre_info_collect', {
        'binary_path': validated_path,
        'binary_format': binary_format
    })
    
    binary_info = get_binary_info(validated_path)
    
    if not binary_info:
        logger.error("无法收集二进制文件信息")
        return {'error': 'Failed to collect binary info'}
    
    report_gen.add_step('Info Collection Complete', binary_info)
    
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
            no_exec=no_exec
        )
        
        report_gen.add_step('Exploit Generation Complete', {
            'success': exploit_result.get('success', False),
            'iterations': len(exploit_result.get('iterations', []))
        })
        
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
    
    reports = {}
    
    reports['markdown'] = report_gen.generate_report(
        validated_path,
        binary_info,
        decomp_results,
        crash_analysis,
        exploit_result,
        similar_vulns,
        symbolic_result
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
        'crash_analysis': crash_analysis,
        'exploit_result': exploit_result,
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
        description='LLM 辅助的二进制漏洞分析工具 (v1.1.0)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
支持的文件格式: ELF (Linux), PE (Windows), Mach-O (macOS)
支持的 AI 提供商: OpenAI, Azure OpenAI, Ollama, llama.cpp, Custom API

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
    
    if args.server:
        logger.info("启动 Web API 服务器...")
        try:
            from modules.web_api import start_server
            start_server(
                host=args.host,
                port=args.port,
                reload=args.debug
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
=======
from utils.logging_setup import init_logging
from config import ensure_dirs, ENABLE_SYMBOLIC, ENABLE_CRYPTO_SCAN


# ── thin argument parser (kept for scripts that call main directly) ──────

def _quick_parse(argv=None):
    """Legacy argument parser. Prefer binmind CLI for interactive use."""
    p = argparse.ArgumentParser(
        prog='binmind',
        description='Binary vulnerability analysis (programmatic entry)',
    )
    p.add_argument('binary', nargs='?', help='path to binary')
    p.add_argument('-o', '--output', default='./results', help='output dir')
    p.add_argument('--crash', help='crash log file')
    p.add_argument('--functions', nargs='*', help='functions to analyze')
    p.add_argument('--max-funcs', type=int, default=20)
    p.add_argument('--include-lib', action='store_true')
    p.add_argument('--parallel', action='store_true')
    p.add_argument('--format', choices=['markdown', 'json'],
                   default='markdown')
    p.add_argument('--decompiler', choices=['auto', 'r2', 'ghidra'],
                   default='auto')
    p.add_argument('--hooks', help='hooks directory')
    p.add_argument('--verbose', '-v', action='store_true')
    p.add_argument('--no-crypto', action='store_true')
    p.add_argument('--no-symbolic', action='store_true')
    return p.parse_args(argv)

>>>>>>> d81973a (精简冗余模块)

# ── main entry ──────────────────────────────────────────────────────────

def main(argv=None):
    args = _quick_parse(argv)

<<<<<<< HEAD
        return 0
    
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
=======
    if not args.binary:
        print("usage: python main.py <binary> [options]")
        print("       see binmind CLI for full help: python -m binmind --help")
        return 1

    init_logging('DEBUG' if args.verbose else 'INFO')
    ensure_dirs()

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        sys.stderr.write(f"error: not a file: {binary}\n")
        return 1

    t0 = time.time()

    from core.pipeline import run_pipeline

    # respect top-level feature toggles
    if args.no_symbolic:
        import config; config.ENABLE_SYMBOLIC = False
    if args.no_crypto:
        import config; config.ENABLE_CRYPTO_SCAN = False

    result = run_pipeline(
        binary_path=binary,
        crash_path=args.crash,
        functions=args.functions,
        max_funcs=args.max_funcs,
>>>>>>> d81973a (精简冗余模块)
        include_lib=args.include_lib,
        parallel=args.parallel,
<<<<<<< HEAD
        max_parallel=args.max_parallel,
        hooks_dir=args.hooks_dir,
        fuzzer_type=args.fuzzer if args.fuzzer != 'none' else None,
        expert_mode=args.expert,
        export_corpus_dir=args.export_corpus,
        no_rop=args.no_rop
=======
        output_format=args.format,
        hooks_dir=args.hooks,
        decompiler=args.decompiler,
>>>>>>> d81973a (精简冗余模块)
    )

    if 'error' in result:
<<<<<<< HEAD
        logger.error(f"分析失败: {result['error']}")
        sys.exit(1)
    
    if args.print_report:
        print_crash_analysis_report(
            crash_data=crash_data,
            crash_analysis=result.get('crash_analysis'),
            decomp_results=result.get('decomp_analysis', [])
        )
    
=======
        sys.stderr.write(f"error: {result['error']}\n")
        return 1

    elapsed = result.get('elapsed', time.time() - t0)
>>>>>>> d81973a (精简冗余模块)
    reports = result.get('reports', {})

    print()
    print(f"  done in {elapsed:.1f}s")
    print(f"  functions: {len(result.get('decomp_analysis', []))}")
    print(f"  vulns:     {result.get('total_vulns', 0)}")
    for fmt, path in reports.items():
        print(f"  {fmt}: {path}")
    print()

    return 0


if __name__ == '__main__':
    sys.exit(main())
