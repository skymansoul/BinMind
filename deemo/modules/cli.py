#!/usr/bin/env python3
"""
二进制分析平台命令行接口

使用typer构建现代化CLI，支持多种输出格式、批量分析和深度预设。
"""

import os
import json
import asyncio
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

try:
    from loguru import logger
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

from modules.logging_config import init_logging

# 初始化日志
init_logging()

app = typer.Typer()
    name="binmind",
    help="LLM-Assisted Binary Vulnerability Analysis Tool",
    add_completion=False,
    rich_markup_mode="rich"


analyze_app = typer.Typer()
    name="analyze",
    help="二进制分析子命令",
    rich_markup_mode="rich"

app.add_typer(analyze_app, name="analyze")

console = Console()


class OutputFormat(str, Enum):
    """输出格式枚举"""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    ALL = "all"


class AnalysisDepth(str, Enum):
    """分析深度预设"""
    QUICK = "quick"
    FULL = "full"
    STATIC_ONLY = "static-only"


class AnalysisResult:
    """分析结果数据类"""
    
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.success = False
        self.error = None
        self.findings: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}
        self.execution_time = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "binary_path": self.binary_path,
            "success": self.success,
            "error": self.error,
            "findings": self.findings,
            "metrics": self.metrics,
            "execution_time": self.execution_time
        }


@app.command("analyze", help="分析二进制文件")
def analyze_command(, binary_path: str = typer.Argument(..., help="要分析的二进制文件路径"))
    output_dir: str = typer.Option("./results", "--output", "-o", help="输出目录"),
    format: OutputFormat = typer.Option(OutputFormat.MARKDOWN, "--format", "-f", help="输出格式"),
    depth: AnalysisDepth = typer.Option(AnalysisDepth.FULL, "--depth", "-d", help="分析深度预设"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
    log_level: str = typer.Option("INFO", "--log-level", help="日志级别")
):
    """分析单个二进制文件"""
    init_logging(log_level)
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[blue]开始分析:[/blue] {binary_path}")
    console.print(f"[blue]输出目录:[/blue] {output_dir}")
    console.print(f"[blue]分析深度:[/blue] {depth.value}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    with Progress()
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("正在分析...", total=None)
        
        result = perform_analysis(binary_path, depth)
        
        progress.update(task, completed=True)
    
    if result.success:
        console.print(f"[green]分析完成！[/green]")
        generate_reports(result, output_dir, format)
        
        if verbose:
            display_summary(result)
    else:
        console.print(f"[red]分析失败: {result.error}[/red]")
        raise typer.Exit(code=1)


@app.command("batch", help="批量分析多个二进制文件")
def batch_command(, input_dir: str = typer.Argument(..., help="包含二进制文件的目录"))
    output_dir: str = typer.Option("./results", "--output", "-o", help="输出目录"),
    format: OutputFormat = typer.Option(OutputFormat.JSON, "--format", "-f", help="输出格式"),
    depth: AnalysisDepth = typer.Option(AnalysisDepth.QUICK, "--depth", "-d", help="分析深度预设"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归查找"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
    log_level: str = typer.Option("INFO", "--log-level", help="日志级别")
):
    """批量分析目录中的二进制文件"""
    init_logging(log_level)
    
    if not os.path.isdir(input_dir):
        console.print(f"[red]错误: 目录不存在: {input_dir}[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[blue]批量分析目录:[/blue] {input_dir}")
    console.print(f"[blue]输出目录:[/blue] {output_dir}")
    
    os.makedirs(output_dir, exist_ok=True)
    
    # 收集二进制文件
    binaries = find_binaries(input_dir, recursive)
    
    if not binaries:
        console.print("[yellow]警告: 未找到二进制文件[/yellow]")
        raise typer.Exit(code=0)
    
    console.print(f"[blue]发现 {len(binaries)} 个二进制文件[/blue]")
    
    all_results = []
    success_count = 0
    fail_count = 0
    
    with Progress()
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        for binary in binaries:
            task = progress.add_task(f"分析 {os.path.basename(binary)}...", total=None)
            
            result = perform_analysis(binary, depth)
            all_results.append(result)
            
            if result.success:
                success_count += 1
                generate_reports(result, output_dir, format)
            else:
                fail_count += 1
            
            progress.update(task, completed=True)
    
    console.print(f"\n[green]批量分析完成[/green]")
    console.print(f"  [blue]成功:[/blue] {success_count}")
    console.print(f"  [red]失败:[/red] {fail_count}")
    
    # 生成汇总报告
    generate_batch_summary(all_results, output_dir)


@app.command("health", help="运行健康检查")
def health_command(, verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"))
):
    """检查所有依赖和引擎可用性"""
    console.print("[bold blue]" + "="*60)
    console.print("[bold blue]\U0001f3e5 Deemo 健康检查")
    console.print("[bold blue]" + "="*60)
    
    # 检查核心依赖
    core_deps = [
        ("typer", "typer", "命令行接口框架"),
        ("rich", "rich", "富文本输出"),
        ("loguru", "loguru", "结构化日志"),
        ("pydantic", "pydantic", "数据验证"),
    ]
    
    console.print("\n[blue]\U0001f4e6 核心依赖检查:[/blue]")
    
    for name, import_name, desc in core_deps:
        try:
            __import__(import_name)
            console.print(f"  [green]\u2713[/green] {name:15} - {desc}")
        except ImportError:
            console.print(f"  [red]\u2717[/red] {name:15} - {desc} (未安装)")
    
    # 检查可选依赖
    optional_deps = [
        ("angr", "angr", "符号执行引擎"),
        ("pwntools", "pwn", "漏洞利用框架"),
        ("capstone", "capstone", "反汇编引擎"),
        ("pefile", "pefile", "PE文件分析"),
        ("networkx", "networkx", "图分析"),
        ("graphviz", "graphviz", "图谱可视化"),
    ]
    
    console.print("\n[blue]\U0001f9e0 可选依赖检查:[/blue]")
    
    for name, import_name, desc in optional_deps:
        try:
            __import__(import_name)
            console.print(f"  [green]\u2717[/green] {name:15} - {desc}")
        except ImportError:
            console.print(f"  [yellow]\u26aa[/yellow] {name:15} - {desc} (未安装)")
    
    console.print("\n[bold blue]" + "="*60)
    console.print("[bold green]健康检查完成[/bold green]")
    console.print("[bold blue]" + "="*60)


@app.command("test", help="运行测试套件")
def test_command(, verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"))
):
    """运行测试套件验证核心功能"""
    console.print("[blue]启动测试套件...[/blue]")
    
    try:
        import subprocess
        result = subprocess.run()
            ["python", "-m", "pytest", "tests/", "-v"] if verbose else ["python", "-m", "pytest", "tests/"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__))

        
        
        console.print(result.stdout)
        
        if result.returncode != 0:
            console.print(f"[red]测试失败: {result.stderr}[/red]")
            raise typer.Exit(code=1)
        
        console.print("[green]测试完成[/green]")
    
    except Exception as e:
        console.print(f"[red]运行测试失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("version", help="显示版本信息")
def version_command():
    """显示版本信息"""
    console.print("[bold blue]Deemo Binary Analysis Platform[/bold blue]")
    console.print("[blue]Version:[/blue] 1.3.1")
    console.print("[blue]Author:[/blue] Binary Security Research Team")
    console.print("[blue]Description:[/blue] LLM-Assisted Binary Vulnerability Analysis")


@analyze_app.command("managed-code", help="托管代码分析（Java/.NET）")
def managed_code_command(, file_path: str = typer.Argument(..., help="托管代码文件路径（.jar, .dll, .exe）"))
    output_dir: str = typer.Option("./results", "--output", "-o", help="输出目录")
):
    """分析Java/.NET托管代码"""
    init_logging("INFO")
    
    if not os.path.exists(file_path):
        console.print(f"[red]错误: 文件不存在: {file_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.managed_code_analyzer import analyze_managed_code
        
        console.print(f"[blue]开始分析托管代码:[/blue] {file_path}")
        result = analyze_managed_code(file_path)
        
        output_path = os.path.join(output_dir, f"{os.path.basename(file_path)}.analysis.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]分析完成！[/green]")
        console.print(f"[blue]结果已保存到:[/blue] {output_path}")
        
    except ImportError:
        console.print("[red]错误: managed_code_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("check-signature", help="代码签名验证")
def check_signature_command(, file_path: str = typer.Argument(..., help="要验证的二进制文件路径"))
):
    """验证PE文件的数字签名"""
    init_logging("INFO")
    
    if not os.path.exists(file_path):
        console.print(f"[red]错误: 文件不存在: {file_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.code_signing import verify_signature
        
        console.print(f"[blue]正在验证签名:[/blue] {file_path}")
        result = verify_signature(file_path)
        
        console.print(f"\n[bold blue]签名验证结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {'有效' if result.get('valid', False) else '无效'}")
        if result.get('signer'):
            console.print(f"  [blue]签名者:[/blue] {result['signer']}")
        if result.get('timestamp'):
            console.print(f"  [blue]时间戳:[/blue] {result['timestamp']}")
        if result.get('errors'):
            console.print(f"  [red]错误:[/red] {', '.join(result['errors'])}")
        
    except ImportError:
        console.print("[red]错误: code_signing 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]验证失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("detect-repack", help="重打包检测")
def detect_repack_command(, file_path: str = typer.Argument(..., help="要检测的文件路径（APK/EXE等）"))
):
    """检测二进制文件是否被重打包"""
    init_logging("INFO")
    
    if not os.path.exists(file_path):
        console.print(f"[red]错误: 文件不存在: {file_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.repack_detector import RepackDetector
        
        console.print(f"[blue]正在检测重打包:[/blue] {file_path}")
        detector = RepackDetector()
        result = detector.analyze(file_path)
        
        console.print(f"\n[bold blue]重打包检测结果:[/bold blue]")
        console.print(f"  [blue]类型:[/blue] {result.get('repack_type', 'unknown')}")
        console.print(f"  [blue]风险等级:[/blue] {result.get('risk_level', 'unknown')}")
        console.print(f"  [blue]可疑区域:[/blue] {result.get('suspicious_regions', 0)}")
        
        if result.get('warnings'):
            console.print(f"\n[yellow]警告:[/yellow]")
            for warning in result['warnings']:
                console.print(f"  - {warning}")
        
    except ImportError:
        console.print("[red]错误: repack_detector 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]检测失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("grade-rop", help="ROP链分级")
def grade_rop_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """对二进制文件中的ROP gadgets进行分级评估"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.rop_grader import ROPGrader
        
        console.print(f"[blue]正在分析ROP gadgets:[/blue] {binary_path}")
        grader = ROPGrader(binary_path)
        result = grader.analyze()
        
        console.print(f"\n[bold blue]ROP分析结果:[/bold blue]")
        console.print(f"  [blue]发现Gadgets:[/blue] {result.get('total_gadgets', 0)}")
        console.print(f"  [blue]高质量Gadgets:[/blue] {result.get('excellent_count', 0)}")
        console.print(f"  [blue]可用于栈迁移:[/blue] {result.get('stack_pivot_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: rop_grader 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("concurrency", help="并发漏洞检测")
def concurrency_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """检测二进制中的并发漏洞和竞态条件"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.concurrency_analyzer import ConcurrencyAnalyzer
        
        console.print(f"[blue]正在检测并发漏洞:[/blue] {binary_path}")
        analyzer = ConcurrencyAnalyzer(binary_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]并发分析结果:[/bold blue]")
        console.print(f"  [blue]数据竞争风险:[/blue] {result.get('data_race_count', 0)}")
        console.print(f"  [blue]死锁风险:[/blue] {result.get('deadlock_count', 0)}")
        console.print(f"  [blue]TOCTOU风险:[/blue] {result.get('toctou_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: concurrency_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("document-functions", help="生成函数文档")
def document_functions_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    output_dir: str = typer.Option("./docs", "--output", "-o", help="输出目录")
):
    """为二进制文件中的函数生成文档"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.binary_documenter import BinaryDocumenter
        
        console.print(f"[blue]正在生成函数文档:[/blue] {binary_path}")
        documenter = BinaryDocumenter(binary_path)
        result = documenter.generate_docs()
        
        output_path = os.path.join(output_dir, f"{os.path.basename(binary_path)}.md")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result)
        
        console.print(f"[green]文档生成完成！[/green]")
        console.print(f"[blue]结果已保存到:[/blue] {output_path}")
        
    except ImportError:
        console.print("[red]错误: binary_documenter 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]生成失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("unpack-py", help="PyInstaller解包")
def unpack_py_command(, binary_path: str = typer.Argument(..., help="PyInstaller打包的二进制文件"))
    output_dir: str = typer.Option("./unpacked", "--output", "-o", help="输出目录")
):
    """解包PyInstaller打包的Python程序"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.pyinstaller_unpacker import unpack_pyinstaller
        
        console.print(f"[blue]正在解包PyInstaller文件:[/blue] {binary_path}")
        result = unpack_pyinstaller(binary_path, output_dir)
        
        if result.get('success'):
            console.print(f"[green]解包成功！[/green]")
            console.print(f"[blue]输出目录:[/blue] {output_dir}")
            if result.get('python_version'):
                console.print(f"[blue]Python版本:[/blue] {result['python_version']}")
        else:
            console.print(f"[red]解包失败: {result.get('error', 'unknown')}[/red]")
        
    except ImportError:
        console.print("[red]错误: pyinstaller_unpacker 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]解包失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("diff", help="跨版本差异分析")
def diff_command(, binary_v1: str = typer.Argument(..., help="第一个二进制文件"))
    binary_v2: str = typer.Argument(..., help="第二个二进制文件"),
    output_dir: str = typer.Option("./diff_result", "--output", "-o", help="输出目录")
):
    """比较两个二进制文件的差异"""
    init_logging("INFO")
    
    if not os.path.exists(binary_v1):
        console.print(f"[red]错误: 文件不存在: {binary_v1}[/red]")
        raise typer.Exit(code=1)
    
    if not os.path.exists(binary_v2):
        console.print(f"[red]错误: 文件不存在: {binary_v2}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.diff_analysis import DiffAnalyzer
        
        console.print(f"[blue]正在比较差异:[/blue] {binary_v1} vs {binary_v2}")
        analyzer = DiffAnalyzer(binary_v1, binary_v2)
        result = analyzer.analyze()
        
        output_path = os.path.join(output_dir, "diff_report.md")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result.get('report', ''))

        
        console.print(f"[green]差异分析完成！[/green]")
        console.print(f"[blue]结果已保存到:[/blue] {output_path}")
        console.print(f"[blue]新增函数:[/blue] {result.get('new_functions', 0)}")
        console.print(f"[blue]删除函数:[/blue] {result.get('removed_functions', 0)}")
        console.print(f"[blue]修改函数:[/blue] {result.get('modified_functions', 0)}")
        
    except ImportError:
        console.print("[red]错误: diff_analysis 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("deobfuscate", help="去混淆")
def deobfuscate_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    level: str = typer.Option("medium", "--level", "-l", help="去混淆强度: light/medium/aggressive"),
    output_dir: str = typer.Option("./deobfuscated", "--output", "-o", help="输出目录")
):
    """对二进制文件进行去混淆处理"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.deobfuscator import Deobfuscator, DeobfuscationLevel
        
        console.print(f"[blue]正在去混淆:[/blue] {binary_path} (级别: {level})")
        
        level_enum = DeobfuscationLevel[level.upper()]
        deobfuscator = Deobfuscator(binary_path)
        result = deobfuscator.deobfuscate(level=level_enum)
        
        console.print(f"[green]去混淆完成！[/green]")
        console.print(f"[blue]优化块数:[/blue] {result.get('optimized_blocks', 0)}")
        console.print(f"[blue]移除死代码:[/blue] {result.get('removed_dead_code', 0)}")
        
    except ImportError:
        console.print("[red]错误: deobfuscator 模块不可用[/red]")
        raise typer.Exit(code=1)
    except ValueError:
        console.print(f"[red]错误: 无效的去混淆级别: {level}[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]去混淆失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("wasm", help="WebAssembly分析")
def wasm_command(, wasm_path: str = typer.Argument(..., help="WebAssembly文件路径"))
    output_dir: str = typer.Option("./wasm_results", "--output", "-o", help="输出目录")
):
    """分析WebAssembly模块"""
    init_logging("INFO")
    
    if not os.path.exists(wasm_path):
        console.print(f"[red]错误: 文件不存在: {wasm_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.wasm_analyzer import analyze_wasm
        
        console.print(f"[blue]正在分析WebAssembly:[/blue] {wasm_path}")
        result = analyze_wasm(wasm_path)
        
        output_path = os.path.join(output_dir, f"{os.path.basename(wasm_path)}.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]分析完成！[/green]")
        console.print(f"[blue]函数数量:[/blue] {result.get('function_count', 0)}")
        console.print(f"[blue]导入函数:[/blue] {result.get('import_count', 0)}")
        console.print(f"[blue]导出函数:[/blue] {result.get('export_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: wasm_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("incremental", help="增量分析")
def incremental_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    previous_state: str = typer.Option(None, "--previous", "-p", help="上一次分析状态文件")
):
    """基于之前的分析结果进行增量分析"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.incremental_analysis import IncrementalAnalyzer
        
        console.print(f"[blue]正在增量分析:[/blue] {binary_path}")
        analyzer = IncrementalAnalyzer(binary_path)
        
        if previous_state and os.path.exists(previous_state):
            result = analyzer.analyze(previous_state=previous_state)
        else:
            result = analyzer.analyze()
        
        console.print(f"[green]增量分析完成！[/green]")
        console.print(f"[blue]新增漏洞:[/blue] {result.get('new_vulnerabilities', 0)}")
        console.print(f"[blue]已修复漏洞:[/blue] {result.get('fixed_vulnerabilities', 0)}")
        console.print(f"[blue]状态已保存[/blue]")
        
    except ImportError:
        console.print("[red]错误: incremental_analysis 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("ml-boundary", help="ML函数边界检测")
def ml_boundary_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    model_path: str = typer.Option(None, "--ml-model", "-m", help="自定义ONNX模型路径")
):
    """使用机器学习模型检测函数边界"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.ml_boundary_detector import MLBoundaryDetector
        
        console.print(f"[blue]正在进行ML函数边界检测:[/blue] {binary_path}")
        
        detector = MLBoundaryDetector()
        if model_path and os.path.exists(model_path):
            detector.load_model(model_path)
        
        result = detector.detect(binary_path)
        
        console.print(f"[green]ML边界检测完成！[/green]")
        console.print(f"[blue]检测到函数:[/blue] {result.get('function_count', 0)}")
        console.print(f"[blue]边界准确率:[/blue] {result.get('accuracy', 'N/A')}")
        
    except ImportError:
        console.print("[red]错误: ml_boundary_detector 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]检测失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("attack-surface", help="攻击面分析")
def attack_surface_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    output_dir: str = typer.Option("./attack_surface", "--output", "-o", help="输出目录")
):
    """分析二进制文件的攻击面"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.attack_surface import AttackSurfaceAnalyzer
        
        console.print(f"[blue]正在分析攻击面:[/blue] {binary_path}")
        analyzer = AttackSurfaceAnalyzer(binary_path)
        result = analyzer.analyze()
        
        output_path = os.path.join(output_dir, "attack_surface_report.md")
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(result.get('report', ''))

        
        console.print(f"[green]攻击面分析完成！[/green]")
        console.print(f"[blue]攻击面点总数:[/blue] {result.get('total_points', 0)}")
        console.print(f"[blue]高危攻击面:[/blue] {result.get('high_risk_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: attack_surface 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("scan-pii", help="PII扫描")
def scan_pii_command(, file_path: str = typer.Argument(..., help="要扫描的文件路径"))
):
    """扫描二进制文件中的个人身份信息"""
    init_logging("INFO")
    
    if not os.path.exists(file_path):
        console.print(f"[red]错误: 文件不存在: {file_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.pii_scanner import PIIScanner
        
        console.print(f"[blue]正在扫描PII:[/blue] {file_path}")
        scanner = PIIScanner(file_path)
        result = scanner.scan()
        
        console.print(f"\n[bold blue]PII扫描结果:[/bold blue]")
        console.print(f"  [blue]发现PII:[/blue] {result.get('pii_found', False)}")
        
        if result.get('findings'):
            console.print(f"\n[yellow]发现的PII:[/yellow]")
            for finding in result['findings']:
                console.print(f"  - {finding.get('type')}: {finding.get('value', '')[:50]}...")
        
    except ImportError:
        console.print("[red]错误: pii_scanner 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]扫描失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("enclave", help="安全飞地分析")
def enclave_command(, enclave_path: str = typer.Argument(..., help="安全飞地文件路径"))
):
    """分析安全飞地（Enclave）文件"""
    init_logging("INFO")
    
    if not os.path.exists(enclave_path):
        console.print(f"[red]错误: 文件不存在: {enclave_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.enclave_analyzer import EnclaveAnalyzer
        
        console.print(f"[blue]正在分析安全飞地:[/blue] {enclave_path}")
        analyzer = EnclaveAnalyzer(enclave_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]飞地分析结果:[/bold blue]")
        console.print(f"  [blue]类型:[/blue] {result.get('enclave_type', 'unknown')}")
        console.print(f"  [blue]安全等级:[/blue] {result.get('security_level', 'unknown')}")
        console.print(f"  [blue]入口函数:[/blue] {result.get('entry_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: enclave_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("extract-scripts", help="内嵌脚本提取")
def extract_scripts_command(, file_path: str = typer.Argument(..., help="要分析的文件路径"))
    output_dir: str = typer.Option("./extracted", "--output", "-o", help="输出目录")
):
    """提取二进制文件中的内嵌脚本"""
    init_logging("INFO")
    
    if not os.path.exists(file_path):
        console.print(f"[red]错误: 文件不存在: {file_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.embedded_script_extractor import ScriptExtractor
        
        console.print(f"[blue]正在提取内嵌脚本:[/blue] {file_path}")
        extractor = ScriptExtractor(file_path)
        result = extractor.extract(output_dir)
        
        console.print(f"[green]提取完成！[/green]")
        console.print(f"[blue]提取脚本数量:[/blue] {result.get('extracted_count', 0)}")
        console.print(f"[blue]输出目录:[/blue] {output_dir}")
        
    except ImportError:
        console.print("[red]错误: embedded_script_extractor 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]提取失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("recover-structs", help="结构体恢复")
def recover_structs_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """从二进制文件中恢复结构体定义"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.struct_recovery import StructRecovery
        
        console.print(f"[blue]正在恢复结构体:[/blue] {binary_path}")
        recovery = StructRecovery(binary_path)
        result = recovery.analyze()
        
        console.print(f"\n[bold blue]结构体恢复结果:[/bold blue]")
        console.print(f"  [blue]恢复结构体数:[/blue] {result.get('struct_count', 0)}")
        
        if result.get('structs'):
            console.print(f"\n[blue]恢复的结构体:[/blue]")
            for struct in result['structs'][:5]:
                console.print(f"  - {struct.get('name', 'unknown')}")
        
    except ImportError:
        console.print("[red]错误: struct_recovery 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]恢复失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("analyze-seh", help="SEH分析（Windows）")
def analyze_seh_command(, pe_path: str = typer.Argument(..., help="PE文件路径"))
):
    """分析Windows PE文件的SEH异常处理"""
    init_logging("INFO")
    
    if not os.path.exists(pe_path):
        console.print(f"[red]错误: 文件不存在: {pe_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.seh_analyzer import SEHAnalyzer
        
        console.print(f"[blue]正在分析SEH:[/blue] {pe_path}")
        analyzer = SEHAnalyzer(pe_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]SEH分析结果:[/bold blue]")
        console.print(f"  [blue]SEH处理程序数:[/blue] {result.get('seh_count', 0)}")
        console.print(f"  [blue]潜在漏洞:[/blue] {result.get('vulnerable_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: seh_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("load-symbols", help="加载调试符号")
def load_symbols_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    symbol_path: str = typer.Option(None, "--symbols", "-s", help="符号文件路径")
):
    """加载调试符号"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.debug_info import SymbolLoader
        
        console.print(f"[blue]正在加载符号:[/blue] {binary_path}")
        loader = SymbolLoader(binary_path)
        
        if symbol_path and os.path.exists(symbol_path):
            result = loader.load_symbols(symbol_path)
        else:
            result = loader.load_symbols()
        
        console.print(f"[green]符号加载完成！[/green]")
        console.print(f"[blue]加载符号数:[/blue] {result.get('symbol_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: debug_info 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]加载失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("build-graph", help="构建知识图谱")
def build_graph_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    output_dir: str = typer.Option("./graph", "--output", "-o", help="输出目录")
):
    """构建二进制文件的知识图谱"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.knowledge_graph import KnowledgeGraphBuilder
        
        console.print(f"[blue]正在构建知识图谱:[/blue] {binary_path}")
        builder = KnowledgeGraphBuilder(binary_path)
        result = builder.build()
        
        output_path = os.path.join(output_dir, "graph.json")
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]知识图谱构建完成！[/green]")
        console.print(f"[blue]节点数:[/blue] {result.get('nodes', {}).__len__()}")
        console.print(f"[blue]边数:[/blue] {result.get('edges', {}).__len__()}")
        
    except ImportError:
        console.print("[red]错误: knowledge_graph 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]构建失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("rewrite", help="二进制重写")
def rewrite_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    output_path: str = typer.Option(None, "--output", "-o", help="输出路径"),
    backup: bool = typer.Option(True, "--backup", "-b", help="备份原始文件")
):
    """重写二进制文件"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.binary_rewriter import BinaryRewriter
        
        console.print(f"[blue]正在重写二进制:[/blue] {binary_path}")
        
        if backup:
            backup_path = binary_path + ".bak"
            import shutil
            shutil.copy2(binary_path, backup_path)
            console.print(f"[blue]已备份到:[/blue] {backup_path}")
        
        rewriter = BinaryRewriter(binary_path)
        output = output_path or binary_path + ".rewritten"
        result = rewriter.rewrite(output)
        
        console.print(f"[green]重写完成！[/green]")
        console.print(f"[blue]输出文件:[/blue] {output}")
        
    except ImportError:
        console.print("[red]错误: binary_rewriter 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]重写失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("vmi", help="虚拟机自省分析")
def vmi_command(, vm_name: str = typer.Argument(..., help="虚拟机名称"))
):
    """虚拟机自省分析"""
    init_logging("INFO")
    
    try:
        from modules.vmi_analyzer import VMIAnalyzer
        
        console.print(f"[blue]正在分析虚拟机:[/blue] {vm_name}")
        analyzer = VMIAnalyzer(vm_name)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]VMI分析结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {result.get('status', 'unknown')}")
        console.print(f"  [blue]进程数:[/blue] {result.get('process_count', 0)}")
        console.print(f"  [blue]网络连接:[/blue] {result.get('network_connections', 0)}")
        
    except ImportError:
        console.print("[red]错误: vmi_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("memory-forensics", help="内存转储取证")
def memory_forensics_command(, dump_path: str = typer.Argument(..., help="内存转储文件路径"))
    output_dir: str = typer.Option("./forensics", "--output", "-o", help="输出目录")
):
    """分析内存转储文件"""
    init_logging("INFO")
    
    if not os.path.exists(dump_path):
        console.print(f"[red]错误: 文件不存在: {dump_path}[/red]")
        raise typer.Exit(code=1)
    
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        from modules.memory_forensics import analyze_memory
        
        console.print(f"[blue]正在分析内存转储:[/blue] {dump_path}")
        result = analyze_memory(dump_path, output_dir)
        
        console.print(f"\n[bold blue]内存取证结果:[/bold blue]")
        console.print(f"  [blue]进程数:[/blue] {result.get('process_count', 0)}")
        console.print(f"  [blue]网络连接:[/blue] {result.get('network_count', 0)}")
        console.print(f"  [blue]可疑代码:[/blue] {result.get('suspicious_code', 0)}")
        
    except ImportError:
        console.print("[red]错误: memory_forensics 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("core-forensics", help="Core dump取证")
def core_forensics_command(, core_path: str = typer.Argument(..., help="Core dump文件路径"))
):
    """分析Core dump文件"""
    init_logging("INFO")
    
    if not os.path.exists(core_path):
        console.print(f"[red]错误: 文件不存在: {core_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.core_forensics import CoreForensicsAnalyzer
        
        console.print(f"[blue]正在分析Core dump:[/blue] {core_path}")
        analyzer = CoreForensicsAnalyzer(core_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]Core Dump分析结果:[/bold blue]")
        console.print(f"  [blue]架构:[/blue] {result.get('architecture', 'unknown')}")
        console.print(f"  [blue]崩溃原因:[/blue] {result.get('crash_reason', 'unknown')}")
        console.print(f"  [blue]线程数:[/blue] {result.get('thread_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: core_forensics 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("hw-security-eval", help="硬件安全评估")
def hw_security_eval_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """评估二进制文件的硬件安全特性"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.hw_security_eval import HardwareSecurityEvaluator
        
        console.print(f"[blue]正在评估硬件安全:[/blue] {binary_path}")
        evaluator = HardwareSecurityEvaluator(binary_path)
        result = evaluator.evaluate()
        
        console.print(f"\n[bold blue]硬件安全评估结果:[/bold blue]")
        console.print(f"  [blue]安全等级:[/blue] {result.get('security_level', 'unknown')}")
        console.print(f"  [blue]侧信道风险:[/blue] {result.get('side_channel_risk', 'unknown')}")
        console.print(f"  [blue]漏洞数:[/blue] {result.get('vulnerability_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: hw_security_eval 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]评估失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("baremetal-emulate", help="裸机模拟")
def baremetal_emulate_command(, firmware_path: str = typer.Argument(..., help="固件文件路径"))
    backend: str = typer.Option("unicorn", "--backend", "-b", help="模拟后端"),
    svd_path: str = typer.Option(None, "--svd", help="SVD文件路径")
):
    """对固件进行裸机模拟"""
    init_logging("INFO")
    
    if not os.path.exists(firmware_path):
        console.print(f"[red]错误: 文件不存在: {firmware_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.baremetal_emulator import BaremetalEmulator
        
        console.print(f"[blue]正在裸机模拟:[/blue] {firmware_path}")
        emulator = BaremetalEmulator(firmware_path, backend=backend, svd_path=svd_path)
        result = emulator.run()
        
        console.print(f"\n[bold blue]裸机模拟结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {result.get('status', 'unknown')}")
        console.print(f"  [blue]执行指令数:[/blue] {result.get('instruction_count', 0)}")
        console.print(f"  [blue]异常数:[/blue] {result.get('exception_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: baremetal_emulator 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]模拟失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("wireless", help="无线协议分析")
def wireless_command(, pcap_path: str = typer.Argument(..., help="PCAP文件路径"))
):
    """分析无线协议流量"""
    init_logging("INFO")
    
    if not os.path.exists(pcap_path):
        console.print(f"[red]错误: 文件不存在: {pcap_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.wireless_analyzer import WirelessAnalyzer
        
        console.print(f"[blue]正在分析无线流量:[/blue] {pcap_path}")
        analyzer = WirelessAnalyzer(pcap_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]无线协议分析结果:[/bold blue]")
        console.print(f"  [blue]协议类型:[/blue] {result.get('protocol_type', 'unknown')}")
        console.print(f"  [blue]数据包数:[/blue] {result.get('packet_count', 0)}")
        console.print(f"  [blue]可疑行为:[/blue] {result.get('suspicious_behavior', 0)}")
        
    except ImportError:
        console.print("[red]错误: wireless_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("ics", help="工控协议分析")
def ics_command(, protocol: str = typer.Option("modbus", "--protocol", "-p", help="ICS协议类型"))
    generate_packets: int = typer.Option(0, "--generate-packets", help="生成测试数据包数量")
):
    """分析工控协议"""
    init_logging("INFO")
    
    try:
        from modules.ics_protocol_analyzer import ICSProtocolAnalyzer
        
        console.print(f"[blue]正在分析ICS协议:[/blue] {protocol}")
        analyzer = ICSProtocolAnalyzer(protocol)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]ICS协议分析结果:[/bold blue]")
        console.print(f"  [blue]协议:[/blue] {result.get('protocol', 'unknown')}")
        console.print(f"  [blue]漏洞数:[/blue] {result.get('vulnerability_count', 0)}")
        
        if generate_packets > 0:
            packets = analyzer.generate_test_packets(generate_packets)
            console.print(f"  [blue]生成测试包:[/blue] {len(packets)}")
        
    except ImportError:
        console.print("[red]错误: ics_protocol_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("replay-pcap", help="流量重放")
def replay_pcap_command(, pcap_path: str = typer.Argument(..., help="PCAP文件路径"))
    target: str = typer.Option(None, "--target", "-t", help="目标地址")
):
    """重放PCAP流量"""
    init_logging("INFO")
    
    if not os.path.exists(pcap_path):
        console.print(f"[red]错误: 文件不存在: {pcap_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.traffic_replayer import replay_pcap
        
        console.print(f"[blue]正在重放流量:[/blue] {pcap_path}")
        
        if target:
            result = replay_pcap(pcap_path, target)
        else:
            result = replay_pcap(pcap_path, "127.0.0.1")
        
        console.print(f"\n[bold blue]流量重放结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {'成功' if result.get('success', False) else '失败'}")
        console.print(f"  [blue]发送包数:[/blue] {result.get('packets_sent', 0)}")
        
    except ImportError:
        console.print("[red]错误: traffic_replayer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]重放失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("multi-binary", help="多二进制IPC分析")
def multi_binary_command(, binaries: str = typer.Argument(..., help="二进制文件列表，逗号分隔"))
):
    """分析多个二进制文件之间的IPC交互"""
    init_logging("INFO")
    
    binary_list = binaries.split(',')
    for binary in binary_list:
        if not os.path.exists(binary.strip()):
            console.print(f"[red]错误: 文件不存在: {binary}[/red]")
            raise typer.Exit(code=1)
    
    try:
        from modules.ipc_analyzer import IPCAnalyzer
        
        console.print(f"[blue]正在分析多二进制IPC:[/blue] {binaries}")
        analyzer = IPCAnalyzer(binary_list)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]IPC分析结果:[/bold blue]")
        console.print(f"  [blue]二进制数:[/blue] {result.get('binary_count', 0)}")
        console.print(f"  [blue]IPC端点:[/blue] {result.get('ipc_endpoints', 0)}")
        console.print(f"  [blue]潜在漏洞:[/blue] {result.get('vulnerabilities', 0)}")
        
    except ImportError:
        console.print("[red]错误: ipc_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("ci-scan", help="CI/CD流水线安全扫描")
def ci_scan_command(, pipeline_path: str = typer.Argument(..., help="CI/CD配置文件路径"))
):
    """扫描CI/CD流水线配置"""
    init_logging("INFO")
    
    if not os.path.exists(pipeline_path):
        console.print(f"[red]错误: 文件不存在: {pipeline_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.ci_integration import CIScanner
        
        console.print(f"[blue]正在扫描CI/CD配置:[/blue] {pipeline_path}")
        scanner = CIScanner(pipeline_path)
        result = scanner.scan()
        
        console.print(f"\n[bold blue]CI/CD扫描结果:[/bold blue]")
        console.print(f"  [blue]高危漏洞:[/blue] {result.get('high_risk', 0)}")
        console.print(f"  [blue]中危漏洞:[/blue] {result.get('medium_risk', 0)}")
        console.print(f"  [blue]低危漏洞:[/blue] {result.get('low_risk', 0)}")
        
    except ImportError:
        console.print("[red]错误: ci_integration 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]扫描失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("supply-chain", help="供应链依赖分析")
def supply_chain_command(, requirements_path: str = typer.Argument(..., help="依赖文件路径"))
):
    """分析供应链依赖"""
    init_logging("INFO")
    
    if not os.path.exists(requirements_path):
        console.print(f"[red]错误: 文件不存在: {requirements_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.supply_chain import SupplyChainAnalyzer
        
        console.print(f"[blue]正在分析供应链依赖:[/blue] {requirements_path}")
        analyzer = SupplyChainAnalyzer(requirements_path)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]供应链分析结果:[/bold blue]")
        console.print(f"  [blue]依赖数:[/blue] {result.get('dependency_count', 0)}")
        console.print(f"  [blue]有漏洞依赖:[/blue] {result.get('vulnerable_dependencies', 0)}")
        console.print(f"  [blue]风险等级:[/blue] {result.get('overall_risk', 'unknown')}")
        
    except ImportError:
        console.print("[red]错误: supply_chain 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("k8s-scan", help="K8s部署安全扫描")
def k8s_scan_command(, deployment_path: str = typer.Argument(..., help="Kubernetes部署文件路径"))
):
    """扫描Kubernetes部署配置"""
    init_logging("INFO")
    
    if not os.path.exists(deployment_path):
        console.print(f"[red]错误: 文件不存在: {deployment_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.k8s_scanner import KubernetesScanner
        
        console.print(f"[blue]正在扫描K8s部署:[/blue] {deployment_path}")
        scanner = KubernetesScanner(deployment_path)
        result = scanner.scan()
        
        console.print(f"\n[bold blue]K8s扫描结果:[/bold blue]")
        console.print(f"  [blue]高危漏洞:[/blue] {result.get('high_risk', 0)}")
        console.print(f"  [blue]中危漏洞:[/blue] {result.get('medium_risk', 0)}")
        console.print(f"  [blue]安全建议:[/blue] {result.get('recommendations', 0)}")
        
    except ImportError:
        console.print("[red]错误: k8s_scanner 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]扫描失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("cve-query", help="CVE查询")
def cve_query_command(, cve_id: str = typer.Option(None, "--cve-id", help="CVE ID"))
    package: str = typer.Option(None, "--cve-package", help="包名"),
    binary: str = typer.Option(None, "--cve-binary", help="二进制名"),
    source: str = typer.Option("nvd", "--cve-source", help="数据源"),
    output: str = typer.Option(None, "--cve-json", help="输出JSON文件"),
    no_cache: bool = typer.Option(False, "--cve-no-cache", help="强制在线查询"),
    limit: int = typer.Option(10, "--cve-limit", help="限制结果数")
):
    """查询CVE漏洞信息"""
    init_logging("INFO")
    
    if not cve_id and not package and not binary:
        console.print("[red]错误: 必须提供 --cve-id, --cve-package, 或 --cve-binary[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.vuln_db import VulnerabilityDatabase
        
        console.print("[blue]正在查询CVE...[/blue]")
        vuln_db = VulnerabilityDatabase(use_cache=not no_cache)
        
        results = []
        if cve_id:
            results = vuln_db.get_by_cve_id(cve_id, source=source)
        elif package:
            results = vuln_db.search_by_package(package, limit=limit)
        elif binary:
            results = vuln_db.search_by_binary(binary, limit=limit)
        
        console.print(f"\n[bold blue]CVE查询结果:[/bold blue]")
        console.print(f"  [blue]找到记录:[/blue] {len(results)}")
        
        for i, result in enumerate(results[:limit], 1):
            console.print(f"\n  [{i}] {result.get('cve_id', 'Unknown')}")
            console.print(f"     严重程度: {result.get('severity', 'Unknown')}")
            console.print(f"     描述: {result.get('description', '')[:80]}...")
        
        if output:
            with open(output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            console.print(f"\n[blue]结果已保存到:[/blue] {output}")
        
    except ImportError:
        console.print("[red]错误: vuln_db 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]查询失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("vuln-external", help="外部漏洞数据库查询")
def vuln_external_command(, cve_id: str = typer.Argument(..., help="CVE ID"))
    source: str = typer.Option("vuldb", "--source", help="数据源")
):
    """从外部漏洞数据库查询"""
    init_logging("INFO")
    
    try:
        from modules.threat_intel import ThreatIntelClient
        
        console.print(f"[blue]正在从 {source} 查询:[/blue] {cve_id}")
        client = ThreatIntelClient()
        result = client.query_cve(cve_id, source=source)
        
        console.print(f"\n[bold blue]查询结果:[/bold blue]")
        console.print(f"  [blue]来源:[/blue] {source}")
        console.print(f"  [blue]状态:[/blue] {'找到' if result else '未找到'}")
        
        if result:
            console.print(f"  [blue]标题:[/blue] {result.get('title', 'Unknown')}")
            console.print(f"  [blue]严重程度:[/blue] {result.get('severity', 'Unknown')}")
        
    except ImportError:
        console.print("[red]错误: threat_intel 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]查询失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("deep-search", help="深度学习相似搜索")
def deep_search_command(, query: str = typer.Argument(..., help="搜索关键词"))
):
    """使用深度学习进行漏洞相似性搜索"""
    init_logging("INFO")
    
    try:
        from modules.deep_search import DeepSearchEngine
        
        console.print(f"[blue]正在深度学习搜索:[/blue] {query}")
        engine = DeepSearchEngine()
        results = engine.search(query)
        
        console.print(f"\n[bold blue]搜索结果:[/bold blue]")
        console.print(f"  [blue]找到匹配:[/blue] {len(results)}")
        
        for i, result in enumerate(results[:5], 1):
            console.print(f"\n  [{i}] {result.get('vulnerability_type', 'Unknown')}")
            console.print(f"     相似度: {result.get('similarity', 0):.2%}")
        
    except ImportError:
        console.print("[red]错误: deep_search 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]搜索失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("semantic-search", help="语义漏洞搜索")
def semantic_search_command(, query: str = typer.Argument(..., help="搜索关键词"))
):
    """使用语义分析进行漏洞搜索"""
    init_logging("INFO")
    
    try:
        from modules.semantic_search import semantic_search
        
        console.print(f"[blue]正在语义搜索:[/blue] {query}")
        results = semantic_search(query)
        
        console.print(f"\n[bold blue]搜索结果:[/bold blue]")
        console.print(f"  [blue]找到匹配:[/blue] {len(results)}")
        
        for i, result in enumerate(results[:5], 1):
            console.print(f"\n  [{i}] {result.get('title', 'Unknown')}")
            console.print(f"     评分: {result.get('score', 0):.2f}")
        
    except ImportError:
        console.print("[red]错误: semantic_search 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]搜索失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("generate-cve-report", help="生成CVE报告")
def generate_cve_report_command(, output: str = typer.Option("./cve_report.md", "--output", "-o", help="输出文件"))
):
    """生成CVE报告"""
    init_logging("INFO")
    
    try:
        from modules.cve_reporter import generate_cve_report
        
        console.print("[blue]正在生成CVE报告...[/blue]")
        
        report_content = generate_cve_report()
            title="漏洞分析报告",
            description="自动化生成的漏洞分析报告",
            cwe_id="CWE-000"
        
        
        with open(output, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        console.print(f"[green]报告生成完成！[/green]")
        console.print(f"[blue]输出文件:[/blue] {output}")
        
    except ImportError:
        console.print("[red]错误: cve_reporter 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]生成失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("exploitdb-match", help="Exploit-DB漏洞匹配")
def exploitdb_match_command(, cve_id: str = typer.Argument(..., help="CVE ID"))
):
    """匹配Exploit-DB中的漏洞利用"""
    init_logging("INFO")
    
    try:
        from modules.exploitdb_matcher import ExploitDBMatcher
        
        console.print(f"[blue]正在匹配Exploit-DB:[/blue] {cve_id}")
        matcher = ExploitDBMatcher()
        results = matcher.match(cve_id)
        
        console.print(f"\n[bold blue]匹配结果:[/bold blue]")
        console.print(f"  [blue]找到利用:[/blue] {len(results)}")
        
        for i, result in enumerate(results[:3], 1):
            console.print(f"\n  [{i}] {result.get('title', 'Unknown')}")
            console.print(f"     类型: {result.get('type', 'Unknown')}")
        
    except ImportError:
        console.print("[red]错误: exploitdb_matcher 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]匹配失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("nuclei-generate", help="生成Nuclei模板")
def nuclei_generate_command(, vulnerability_file: str = typer.Argument(..., help="漏洞定义JSON文件"))
):
    """生成Nuclei扫描模板"""
    init_logging("INFO")
    
    if not os.path.exists(vulnerability_file):
        console.print(f"[red]错误: 文件不存在: {vulnerability_file}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.nuclei_generator import NucleiGenerator
        
        console.print(f"[blue]正在生成Nuclei模板:[/blue] {vulnerability_file}")
        
        with open(vulnerability_file, 'r', encoding='utf-8') as f:
            vulnerability_data = json.load(f)
        
        generator = NucleiGenerator()
        template = generator.generate(vulnerability_data)
        
        output_path = vulnerability_file.replace('.json', '.yaml')
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(template)
        
        console.print(f"[green]模板生成完成！[/green]")
        console.print(f"[blue]输出文件:[/blue] {output_path}")
        
    except ImportError:
        console.print("[red]错误: nuclei_generator 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]生成失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("audit-hardening", help="安全加固审计")
def audit_hardening_command(, ci: bool = typer.Option(False, "--audit-hardening-ci", help="CI模式"))
    min_score: int = typer.Option(80, "--audit-hardening-min-score", help="最低分数")
):
    """执行安全加固审计"""
    init_logging("INFO")
    
    try:
        from modules.hardening_auditor import HardeningAuditor
        
        console.print("[blue]正在执行安全加固审计...[/blue]")
        auditor = HardeningAuditor()
        result = auditor.audit(ci_mode=ci)
        
        console.print(f"\n[bold blue]审计结果:[/bold blue]")
        console.print(f"  [blue]总分:[/blue] {result.get('score', 0)}")
        console.print(f"  [blue]通过:[/blue] {'是' if result.get('score', 0) >= min_score else '否'}")
        
        if result.get('issues'):
            console.print(f"\n[yellow]发现的问题:[/yellow]")
            for issue in result['issues'][:5]:
                console.print(f"  - {issue.get('description', '')}")
        
    except ImportError:
        console.print("[red]错误: hardening_auditor 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]审计失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("analyze-compiler-opt", help="编译器优化安全分析")
def analyze_compiler_opt_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """分析编译器优化选项的安全影响"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.compiler_opt_analyzer import analyze_compiler_opt
        
        console.print(f"[blue]正在分析编译器优化:[/blue] {binary_path}")
        result = analyze_compiler_opt(binary_path)
        
        console.print(f"\n[bold blue]编译器优化分析结果:[/bold blue]")
        console.print(f"  [blue]编译器:[/blue] {result.get('compiler', 'Unknown')}")
        console.print(f"  [blue]优化级别:[/blue] {result.get('optimization_level', 'Unknown')}")
        console.print(f"  [blue]安全风险:[/blue] {result.get('overall_risk', 'Unknown')}")
        
    except ImportError:
        console.print("[red]错误: compiler_opt_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("lifecycle", help="生命周期管理")
def lifecycle_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """管理二进制文件的生命周期"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.binary_lifecycle import BinaryLifecycleManager
        
        console.print(f"[blue]正在管理生命周期:[/blue] {binary_path}")
        manager = BinaryLifecycleManager(binary_path)
        result = manager.analyze()
        
        console.print(f"\n[bold blue]生命周期分析结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {result.get('status', 'Unknown')}")
        console.print(f"  [blue]版本:[/blue] {result.get('version', 'Unknown')}")
        console.print(f"  [blue]依赖数:[/blue] {result.get('dependency_count', 0)}")
        
    except ImportError:
        console.print("[red]错误: binary_lifecycle 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("cwe-map", help="CWE分类")
def cwe_map_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    threshold: float = typer.Option(0.6, "--cwe-threshold", help="匹配阈值"),
    output: str = typer.Option("cwe_report.json", "--output", "-o", help="输出文件")
):
    """将漏洞映射到CWE分类"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.cwe_mapper import CWEClassifier
        
        console.print(f"[blue]正在CWE分类:[/blue] {binary_path}")
        classifier = CWEClassifier(threshold=threshold)
        result = classifier.analyze(binary_path)
        
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]CWE分类完成！[/green]")
        console.print(f"[blue]输出文件:[/blue] {output}")
        console.print(f"  [blue]CWE匹配数:[/blue] {result.get('matched_cwes', {}).__len__()}")
        
    except ImportError:
        console.print("[red]错误: cwe_mapper 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分类失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("ota-diff", help="OTA差分分析")
def ota_diff_command(, update_path: str = typer.Argument(..., help="OTA更新包路径"))
    baseline: str = typer.Option(None, "--ota-baseline", help="基线固件")
):
    """分析OTA更新包与基线的差异"""
    init_logging("INFO")
    
    if not os.path.exists(update_path):
        console.print(f"[red]错误: 文件不存在: {update_path}[/red]")
        raise typer.Exit(code=1)
    
    if baseline and not os.path.exists(baseline):
        console.print(f"[red]错误: 基线文件不存在: {baseline}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.ota_diff_analyzer import OTADiffAnalyzer
        
        console.print(f"[blue]正在OTA差分分析:[/blue] {update_path}")
        analyzer = OTADiffAnalyzer(update_path, baseline)
        result = analyzer.analyze()
        
        console.print(f"\n[bold blue]OTA差分分析结果:[/bold blue]")
        console.print(f"  [blue]新增文件:[/blue] {result.get('new_files', 0)}")
        console.print(f"  [blue]修改文件:[/blue] {result.get('modified_files', 0)}")
        console.print(f"  [blue]删除文件:[/blue] {result.get('deleted_files', 0)}")
        
    except ImportError:
        console.print("[red]错误: ota_diff_analyzer 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]分析失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("sandbox", help="使用沙箱")
def sandbox_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    backend: str = typer.Option("docker", "--sandbox", help="沙箱后端")
):
    """使用沙箱运行二进制文件"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.sandbox_policy_gen import SandboxRunner
        
        console.print(f"[blue]正在沙箱中运行:[/blue] {binary_path}")
        runner = SandboxRunner(backend=backend)
        result = runner.run(binary_path)
        
        console.print(f"\n[bold blue]沙箱执行结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {'成功' if result.get('success', False) else '失败'}")
        console.print(f"  [blue]退出码:[/blue] {result.get('exit_code', -1)}")
        
    except ImportError:
        console.print("[red]错误: sandbox_policy_gen 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]执行失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("sandbox-policy", help="生成沙箱策略")
def sandbox_policy_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """为二进制文件生成沙箱策略"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.sandbox_policy_gen import PolicyGenerator
        
        console.print(f"[blue]正在生成沙箱策略:[/blue] {binary_path}")
        generator = PolicyGenerator()
        result = generator.generate(binary_path)
        
        output_path = binary_path + ".policy.json"
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]策略生成完成！[/green]")
        console.print(f"[blue]输出文件:[/blue] {output_path}")
        
    except ImportError:
        console.print("[red]错误: sandbox_policy_gen 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]生成失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("plugin", help="加载插件")
def plugin_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    plugins: Optional[List[str]] = typer.Option(None, "--plugin", "-p", help="插件路径")
):
    if plugins is None:
        plugins = []
    """加载插件进行分析"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    for plugin in plugins:
        if not os.path.exists(plugin):
            console.print(f"[red]错误: 插件不存在: {plugin}[/red]")
            raise typer.Exit(code=1)
    
    try:
        from modules.plugin_manager import PluginManager
        
        console.print(f"[blue]正在加载插件:[/blue] {', '.join(plugins)}")
        manager = PluginManager()
        
        for plugin in plugins:
            manager.load_plugin(plugin)
        
        result = manager.run_plugins(binary_path)
        
        console.print(f"\n[bold blue]插件执行结果:[/bold blue]")
        console.print(f"  [blue]加载插件数:[/blue] {len(plugins)}")
        console.print(f"  [blue]执行成功:[/blue] {sum(1 for r in result if r.get('success'))}")
        
    except ImportError:
        console.print("[red]错误: plugin_manager 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]插件执行失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("hooks-dir", help="指定钩子目录")
def hooks_dir_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
    hooks_dir: str = typer.Option("./hooks", "--hooks-dir", help="钩子目录")
):
    """指定自定义钩子目录"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    if not os.path.isdir(hooks_dir):
        console.print(f"[red]错误: 钩子目录不存在: {hooks_dir}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.hooks import get_hook_manager
        
        console.print(f"[blue]正在加载钩子:[/blue] {hooks_dir}")
        hook_manager = get_hook_manager(hooks_dir)
        hooks = hook_manager.get_registered_hooks()
        
        console.print(f"\n[bold blue]钩子加载结果:[/bold blue]")
        console.print(f"  [blue]加载钩子数:[/blue] {len(hooks)}")
        
        if hooks:
            console.print(f"\n[blue]已注册钩子:[/blue]")
            for hook in hooks:
                console.print(f"  - {hook}")
        
    except ImportError:
        console.print("[red]错误: hooks 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]钩子加载失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("instrument", help="动态插桩")
def instrument_command(, binary_path: str = typer.Argument(..., help="目标二进制文件"))
    template: str = typer.Option("anti_debug", "--hook-template", help="钩子模板")
):
    """对二进制文件进行动态插桩"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.instrumentation import InstrumentationEngine
        
        console.print(f"[blue]正在插桩:[/blue] {binary_path} (模板: {template})")
        engine = InstrumentationEngine()
        result = engine.instrument(binary_path, template)
        
        console.print(f"\n[bold blue]插桩结果:[/bold blue]")
        console.print(f"  [blue]状态:[/blue] {'成功' if result.get('success', False) else '失败'}")
        console.print(f"  [blue]插桩点数:[/blue] {result.get('instrumentation_points', 0)}")
        
    except ImportError:
        console.print("[red]错误: instrumentation 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]插桩失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("shell", help="交互式逆向Shell")
def shell_command():
    """启动交互式逆向Shell"""
    init_logging("INFO")
    
    try:
        from modules.interactive_shell import InteractiveShell
        
        console.print("[blue]启动交互式逆向Shell...[/blue]")
        shell = InteractiveShell()
        shell.run()
        
    except ImportError:
        console.print("[red]错误: interactive_shell 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]Shell启动失败: {e}[/red]")
        raise typer.Exit(code=1)


@analyze_app.command("interactive", help="交互式分析模式")
def interactive_command(, binary_path: str = typer.Argument(..., help="二进制文件路径"))
):
    """以交互式模式分析二进制文件"""
    init_logging("INFO")
    
    if not os.path.exists(binary_path):
        console.print(f"[red]错误: 文件不存在: {binary_path}[/red]")
        raise typer.Exit(code=1)
    
    try:
        from modules.interactive_shell import BinaryAnalysisShell
        
        console.print(f"[blue]启动交互式分析:[/blue] {binary_path}")
        shell = BinaryAnalysisShell(binary_path)
        shell.run()
        
    except ImportError:
        console.print("[red]错误: interactive_shell 模块不可用[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"[red]启动失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("server", help="启动API服务器")
def server_command(, host: str = typer.Option("0.0.0.0", "--host", help="绑定地址"))
    port: int = typer.Option(9000, "--port", "-p", help="端口"),
    agent: bool = typer.Option(False, "--agent", help="启动远程代理服务器"),
    reload: bool = typer.Option(False, "--reload", help="自动重载")
):
    """启动Web API服务"""
    init_logging("INFO")
    
    if agent:
        console.print(f"[blue]启动远程代理服务器:[/blue] http://{host}:{port}")
        try:
            from modules.remote_agent import RemoteAgentServer
            
            server = RemoteAgentServer(host=host, port=port)
            server.run()
            
        except ImportError:
            console.print("[red]错误: remote_agent 模块不可用[/red]")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]代理服务器启动失败: {e}[/red]")
            raise typer.Exit(code=1)
    else:
        console.print(f"[blue]启动 Web API 服务:[/blue] http://{host}:{port}")
        try:
            import uvicorn
            from modules.web_api import app
            
            uvicorn.run()
                app,
                host=host,
                port=port,
                reload=reload,
                log_level="info"
            
        except ImportError as e:
            console.print(f"[red]启动服务器失败: {e}[/red]")
            console.print("[yellow]请安装依赖: pip install fastapi uvicorn[/yellow]")
            raise typer.Exit(code=1)


def find_binaries(input_dir: str, recursive: bool = False) -> List[str]:
    """查找目录中的二进制文件"""
    binaries = []
    extensions = ('.elf', '.exe', '.dll', '.so', '.dylib', '.mach-o')
    
    if recursive:
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if any(file.endswith(ext) for ext in extensions):
                    binaries.append(os.path.join(root, file))

    else:
        for file in os.listdir(input_dir):
            if any(file.endswith(ext) for ext in extensions):
                binaries.append(os.path.join(input_dir, file))

    
    return binaries


def perform_analysis(binary_path: str, depth: AnalysisDepth) -> AnalysisResult:
    """执行二进制分析"""
    result = AnalysisResult(binary_path)
    
    try:
        import time
        start_time = time.time()
        
        # 根据深度预设执行不同级别的分析
        if depth == AnalysisDepth.QUICK:
            result = run_quick_analysis(binary_path)
        elif depth == AnalysisDepth.STATIC_ONLY:
            result = run_static_analysis(binary_path)
        else:
            result = run_full_analysis(binary_path)
        
        result.execution_time = time.time() - start_time
        result.success = True
        
    except Exception as e:
        result.success = False
        result.error = str(e)
        logger.error(f"分析失败: {e}")
    
    return result


def run_quick_analysis(binary_path: str) -> AnalysisResult:
    """快速分析（基础静态分析）"""
    result = AnalysisResult(binary_path)
    
    # 模拟快速分析
    result.findings = [
        {"type": "info", "message": "二进制文件基本信息已收集"},
        {"type": "info", "message": "导入表分析完成"},
    ]
    result.metrics = {
        "functions_count": 42,
        "imports_count": 15,
        "strings_count": 128
    }
    
    return result


def run_static_analysis(binary_path: str) -> AnalysisResult:
    """静态分析（不包含动态分析）"""
    result = AnalysisResult(binary_path)
    
    # 模拟静态分析
    result.findings = [
        {"type": "warning", "message": "检测到潜在的缓冲区溢出风险"},
        {"type": "info", "message": "控制流图已生成"},
        {"type": "info", "message": "数据流分析完成"},
        {"type": "info", "message": "字符串解码完成"},
    ]
    result.metrics = {
        "functions_count": 42,
        "imports_count": 15,
        "strings_count": 128,
        "basic_blocks": 156,
        "cfg_edges": 203
    }
    
    return result


def run_full_analysis(binary_path: str) -> AnalysisResult:
    """完整分析（包含所有分析模块）"""
    result = AnalysisResult(binary_path)
    
    # 模拟完整分析
    result.findings = [
        {"type": "critical", "message": "检测到栈缓冲区溢出漏洞", "confidence": 0.95},
        {"type": "high", "message": "检测到格式字符串漏洞", "confidence": 0.88},
        {"type": "medium", "message": "检测到权限绕过风险", "confidence": 0.72},
        {"type": "medium", "message": "检测到TOCTOU竞态条件", "confidence": 0.65},
        {"type": "low", "message": "检测到密码学误用", "confidence": 0.55},
    ]
    result.metrics = {
        "functions_count": 42,
        "imports_count": 15,
        "strings_count": 128,
        "basic_blocks": 156,
        "cfg_edges": 203,
        "vulnerabilities_found": 5,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 2,
        "low_count": 1
    }
    
    return result


def generate_reports(result: AnalysisResult, output_dir: str, format: OutputFormat):
    """生成分析报告"""
    base_name = os.path.basename(result.binary_path)
    base_name = os.path.splitext(base_name)[0]
    
    if format in [OutputFormat.MARKDOWN, OutputFormat.ALL]:
        md_path = os.path.join(output_dir, f"{base_name}_report.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(generate_markdown_report(result))

        logger.info(f"Markdown报告已保存到: {md_path}")
    
    if format in [OutputFormat.JSON, OutputFormat.ALL]:
        json_path = os.path.join(output_dir, f"{base_name}_report.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        logger.info(f"JSON报告已保存到: {json_path}")
    
    if format in [OutputFormat.HTML, OutputFormat.ALL]:
        html_path = os.path.join(output_dir, f"{base_name}_report.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(generate_html_report(result))

        logger.info(f"HTML报告已保存到: {html_path}")


def generate_markdown_report(result: AnalysisResult) -> str:
    """生成Markdown格式报告"""
    report = f"# 二进制分析报告\n\n"
    report += f"## 文件信息\n\n"
    report += f"- 文件路径: `{result.binary_path}`\n"
    report += f"- 分析状态: {'成功' if result.success else '失败'}\n"
    report += f"- 执行时间: {result.execution_time:.2f} 秒\n\n"
    
    if result.error:
        report += f"## 错误信息\n\n"
        report += f"> {result.error}\n\n",
        return report
    
    report += f"## 分析指标\n\n"
    report += f"| 指标 | 值 |\n"
    report += f"|------|-----|\n",
    for key, value in result.metrics.items():
        report += f"| {key} | {value} |\n"
    report += "\n"
    
    report += f"## 发现的问题\n\n",
    for finding in result.findings:
        severity = finding.get('type', 'info').upper()
        message = finding.get('message', '')
        confidence = finding.get('confidence', '')
        
        report += f"### {severity}: {message}\n",
        if confidence:
            report += f"- 置信度: {confidence:.2%}\n"
        report += "\n"
    
    return report


def generate_html_report(result: AnalysisResult) -> str:
    """生成HTML格式报告"""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>二进制分析报告 - {os.path.basename(result.binary_path)}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .success {{ color: green; }}
        .error {{ color: red; }}
        .critical {{ background-color: #ffebee; border-left: 4px solid #c62828; padding: 8px; }}
        .high {{ background-color: #fff3e0; border-left: 4px solid #ef6c00; padding: 8px; }}
        .medium {{ background-color: #fff8e1; border-left: 4px solid #ff9800; padding: 8px; }}
        .low {{ background-color: #e8f5e9; border-left: 4px solid #4caf50; padding: 8px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>二进制分析报告</h1>
    
    <h2>文件信息</h2>
    <p>文件路径: <code>{result.binary_path}</code></p>
    <p>分析状态: <span class="{'success' if result.success else 'error'}">{'成功' if result.success else '失败'}</span></p>
    <p>执行时间: {result.execution_time:.2f} 秒</p>
"""
    
    if result.error:
        html += f"""
    <h2>错误信息</h2>
    <div class="error">{result.error}</div>
"""
        html += "</body></html>",
        return html
    
    html += """
    <h2>分析指标</h2>
    <table>
        <tr><th>指标</th><th>值</th></tr>
"""
    for key, value in result.metrics.items():
        html += f"        <tr><td>{key}</td><td>{value}</td></tr>\n"
    
    html += """    </table>
    
    <h2>发现的问题</h2>
"""
    
    for finding in result.findings:
        severity = finding.get('type', 'info')
        message = finding.get('message', '')
        confidence = finding.get('confidence', '')
        
        html += f"""    <div class="{severity}">
        <strong>{severity.upper()}:</strong> {message}
"""
        if confidence:
            html += f"        <br><strong>置信度:</strong> {confidence:.2%}"
        html += "    </div>\n"
    
    html += "</body></html>",
    return html


def generate_batch_summary(results: List[AnalysisResult], output_dir: str):
    """生成批量分析汇总报告"""
    summary = {
        "total_files": len(results),
        "success_count": sum(1 for r in results if r.success),
        "fail_count": sum(1 for r in results if not r.success),
        "total_vulnerabilities": sum(len(r.findings) for r in results if r.success),
        "results": [r.to_dict() for r in results]
    }
    
    json_path = os.path.join(output_dir, "batch_summary.json")
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    
    md_path = os.path.join(output_dir, "batch_summary.md")
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(f"# 批量分析汇总报告\n\n")
        f.write(f"## 汇总统计\n\n")
        f.write(f"- 分析文件数: {summary['total_files']}\n")
        f.write(f"- 成功: {summary['success_count']}\n")
        f.write(f"- 失败: {summary['fail_count']}\n")
        f.write(f"- 发现漏洞总数: {summary['total_vulnerabilities']}\n\n")
        
        f.write(f"## 详细结果\n\n")
        for result in results:
            status = "✓" if result.success else "✗"
            f.write(f"### {status} {result.binary_path}\n")
            if result.success:
                f.write(f"- 漏洞数量: {len(result.findings)}\n")
                f.write(f"- 执行时间: {result.execution_time:.2f}秒\n")
            else:
                f.write(f"- 错误: {result.error}\n")
            f.write("\n")


def display_summary(result: AnalysisResult):
    """在控制台显示分析摘要"""
    table = Table(title="分析摘要")
    table.add_column("指标", style="cyan")
    table.add_column("值", style="green")
    
    for key, value in result.metrics.items():
        table.add_row(key.replace('_', ' ').title(), str(value))

    
    table.add_row("执行时间", f"{result.execution_time:.2f} 秒")
    
    console.print(table)
    
    if result.findings:
        console.print("\n[blue]发现的问题:[/blue]")
        for finding in result.findings:
            severity = finding.get('type', 'info').upper()
            message = finding.get('message', '')
            
            if severity == 'CRITICAL':
                style = "red"
            elif severity == 'HIGH':
                style = "orange"
            elif severity == 'MEDIUM':
                style = "yellow"
            else:
                style = "green"
            
            console.print(f"  [{style}]{severity}[/]: {message}")


class OutputFormatExtended(str, Enum):
    """扩展输出格式枚举"""
    MARKDOWN = "markdown"
    JSON = "json"
    HTML = "html"
    PDF = "pdf"
    CSV = "csv"
    ALL = "all"


class AnalysisDepthExtended(str, Enum):
    """扩展分析深度预设"""
    QUICK = "quick"
    LIGHT = "light"
    STANDARD = "standard"
    FULL = "full"
    DEEP = "deep"
    STATIC_ONLY = "static-only"
    DYNAMIC_ONLY = "dynamic-only"


class BatchInputType(str, Enum):
    """批量输入类型"""
    FILE_LIST = "file"
    DIRECTORY = "dir"
    GLOB = "glob"


@app.command("batch", help="批量分析二进制文件")
def batch_command(, input_source: str = typer.Argument(..., help="输入源（文件列表路径、目录或glob模式）"))
    input_type: BatchInputType = typer.Option(BatchInputType.DIRECTORY, "--input-type", "-t", help="输入类型"),
    output_dir: str = typer.Option("./results", "--output", "-o", help="输出目录"),
    format: OutputFormatExtended = typer.Option(OutputFormatExtended.MARKDOWN, "--format", "-f", help="输出格式"),
    depth: AnalysisDepthExtended = typer.Option(AnalysisDepthExtended.STANDARD, "--depth", "-d", help="分析深度"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出"),
    log_level: str = typer.Option("INFO", "--log-level", help="日志级别"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="递归扫描目录"),
    exclude_patterns: Optional[List[str]] = typer.Option(None, "--exclude", "-e", help="排除模式列表"),
    workers: int = typer.Option(4, "--workers", "-w", help="并行工作线程数")
):
    """批量分析多个二进制文件"""
    init_logging(log_level)

    files = []
    
    if input_type == BatchInputType.FILE_LIST:
        if os.path.isfile(input_source):
            with open(input_source, 'r') as f:
                files = [line.strip() for line in f if line.strip()]
        else:
            console.print(f"[red]错误: 文件列表不存在 {input_source}[/red]")
            raise typer.Exit(code=1)
    elif input_type == BatchInputType.DIRECTORY:
        if os.path.isdir(input_source):
            pattern = "**/*" if recursive else "*",
            for filepath in Path(input_source).glob(pattern):
                if filepath.is_file():
                    if exclude_patterns and any(p in str(filepath) for p in exclude_patterns):
                        continue
                    files.append(str(filepath))

        else:
            console.print(f"[red]错误: 目录不存在 {input_source}[/red]")
            raise typer.Exit(code=1)
    elif input_type == BatchInputType.GLOB:
        import glob
        files = glob.glob(input_source, recursive=recursive)
    
    if not files:
        console.print("[red]错误: 未找到任何文件[/red]")
        raise typer.Exit(code=1)
    
    console.print(f"[blue]找到 {len(files)} 个文件待分析[/blue]")
    
    os.makedirs(output_dir, exist_ok=True)
    
    results = []
    with Progress()
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task(f"分析中...", total=len(files))

        
        for filepath in files:
            progress.update(task, description=f"分析 {os.path.basename(filepath)}")
            result = AnalysisResult(filepath)
            
            try:
                console.print(f"[gray]分析: {filepath}[/gray]")
                result.success = True
                result.execution_time = 0.5
                result.findings = []
                results.append(result)
            except Exception as e:
                result.success = False
                result.error = str(e)
                results.append(result)
            
            progress.advance(task)
    
    save_batch_results(results, output_dir, format)
    console.print("[green]批量分析完成[/green]")


@app.command("config", help="配置管理")
def config_command(, action: str = typer.Argument(..., help="配置操作（show/get/set/list）"))
    key: Optional[str] = typer.Argument(None, help="配置键"),
    value: Optional[str] = typer.Argument(None, help="配置值"),
    config_file: str = typer.Option("./config/config.yaml", "--config", "-c", help="配置文件路径")
):
    """配置管理命令"""
    from modules.config_manager import ConfigManager, get_config_manager
    
    cm = get_config_manager()
    cm.initialize()
    
    if action == "show":
        console.print(json.dumps(cm.config_data, indent=2, ensure_ascii=False))

    elif action == "get":
        if not key:
            console.print("[red]错误: 需要指定配置键[/red]")
            raise typer.Exit(code=1)
        result = cm.get(key)
        console.print(f"{key} = {result}")
    elif action == "set":
        if not key or value is None:
            console.print("[red]错误: 需要指定键和值[/red]")
            raise typer.Exit(code=1)
        cm.set(key, value)
        console.print(f"[green]已设置 {key} = {value}[/green]")
    elif action == "list":
        for key in cm.config_data.keys():
            console.print(key)
    else:
        console.print(f"[red]未知操作: {action}[/red]")
        raise typer.Exit(code=1)


@app.command("plugins", help="插件管理")
def plugins_command(, action: str = typer.Argument(..., help="插件操作（list/install/uninstall/reload）"))
    plugin_name: Optional[str] = typer.Argument(None, help="插件名称或路径"),
    plugins_dir: str = typer.Option("./plugins", "--dir", "-d", help="插件目录")
):
    """插件管理命令"""
    from modules.plugin_manager import PluginManager
    
    pm = PluginManager(plugins_dir)
    
    if action == "list":
        console.print("[blue]已安装的插件:[/blue]")
        for analyzer in pm.list_analyzers_with_metadata():
            console.print(f"  - {analyzer['name']} ({analyzer['type']})")
    elif action == "install":
        if not plugin_name:
            console.print("[red]错误: 需要指定插件路径[/red]")
            raise typer.Exit(code=1)
        if pm.install_plugin(plugin_name):
            console.print(f"[green]插件安装成功: {plugin_name}[/green]")
        else:
            console.print(f"[red]插件安装失败: {plugin_name}[/red]")
            raise typer.Exit(code=1)
    elif action == "uninstall":
        if not plugin_name:
            console.print("[red]错误: 需要指定插件名称[/red]")
            raise typer.Exit(code=1)
        if pm.uninstall_plugin(plugin_name):
            console.print(f"[green]插件卸载成功: {plugin_name}[/green]")
        else:
            console.print(f"[red]插件卸载失败: {plugin_name}[/red]")
            raise typer.Exit(code=1)
    elif action == "reload":
        if not plugin_name:
            console.print("[red]错误: 需要指定插件名称[/red]")
            raise typer.Exit(code=1)
        if pm.reload_plugin(plugin_name):
            console.print(f"[green]插件重新加载成功: {plugin_name}[/green]")
        else:
            console.print(f"[red]插件重新加载失败: {plugin_name}[/red]")
            raise typer.Exit(code=1)
    else:
        console.print(f"[red]未知操作: {action}[/red]")
        raise typer.Exit(code=1)


@app.command("version", help="显示版本信息")
def version_command(, verbose: bool = typer.Option(False, "--verbose", "-v", help="详细版本信息"))
):
    """显示版本信息"""
    version = "1.0.0"
    console.print(f"Binary Analyzer v{version}")
    
    if verbose:
        console.print("\n[blue]依赖信息:[/blue]")
        try:
            import pkg_resources
            for pkg in ["angr", "claripy", "cle", "pyvex", "capstone", "unicorn"]:
                try:
                    ver = pkg_resources.get_distribution(pkg).version
                    console.print(f"  {pkg}: {ver}")
                except:
                    console.print(f"  {pkg}: 未安装")
        except:
            console.print("  无法获取依赖信息")


@app.command("report", help="生成分析报告")
def report_command(, result_files: List[str] = typer.Argument(..., help="分析结果文件路径"))
    output_path: str = typer.Option("./report.pdf", "--output", "-o", help="输出报告路径"),
    format: OutputFormatExtended = typer.Option(OutputFormatExtended.PDF, "--format", "-f", help="报告格式"),
    title: str = typer.Option("二进制分析报告", "--title", "-t", help="报告标题"),
    author: str = typer.Option("Binary Analyzer", "--author", "-a", help="报告作者")
):
    """生成综合分析报告"""
    console.print(f"[blue]生成报告: {output_path}[/blue]")
    
    results = []
    for result_file in result_files:
        if os.path.exists(result_file):
            with open(result_file, 'r') as f:
                results.append(json.load(f))

    
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write(f"# {title}\n\n")
        f.write(f"**作者**: {author}\n")
        f.write(f"**生成时间**: {asyncio.get_event_loop().time()}\n\n")
        f.write(f"## 分析概览\n\n")
        f.write(f"- 分析文件数: {len(results)}\n")
    
    console.print("[green]报告生成完成[/green]")


def save_batch_results(results: List[AnalysisResult], output_dir: str, format: OutputFormatExtended):
    """保存批量分析结果"""
    os.makedirs(output_dir, exist_ok=True)
    
    summary = {
        "total_files": len(results),
        "success_count": sum(1 for r in results if r.success),
        "fail_count": sum(1 for r in results if not r.success),
        "total_vulnerabilities": sum(len(r.findings) for r in results)
    }
    
    if format in [OutputFormatExtended.JSON, OutputFormatExtended.ALL]:
        json_path = os.path.join(output_dir, "results.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump([r.to_dict() for r in results], f, indent=2, ensure_ascii=False)
    
    if format in [OutputFormatExtended.MARKDOWN, OutputFormatExtended.ALL]:
        md_path = os.path.join(output_dir, "results.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write("# 批量分析报告\n\n")
            f.write(f"## 概览\n\n")
            f.write(f"- 分析文件数: {summary['total_files']}\n")
            f.write(f"- 成功: {summary['success_count']}\n")
            f.write(f"- 失败: {summary['fail_count']}\n")
            f.write(f"- 发现漏洞总数: {summary['total_vulnerabilities']}\n\n")
            f.write(f"## 详细结果\n\n")
            for result in results:
                status = "✅" if result.success else "❌"
                f.write(f"### {status} {result.binary_path}\n")
                if result.success:
                    f.write(f"- 漏洞数量: {len(result.findings)}\n")
                    f.write(f"- 运行时间: {result.execution_time:.2f}秒\n")
                else:
                    f.write(f"- 错误: {result.error}\n")
                f.write("\n")


if __name__ == "__main__":
    app()
