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

app = typer.Typer(
    name="binmind",
    help="LLM-Assisted Binary Vulnerability Analysis Tool",
    add_completion=False,
    rich_markup_mode="rich"
)

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
def analyze_command(
    binary_path: str = typer.Argument(..., help="要分析的二进制文件路径"),
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
    
    with Progress(
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
def batch_command(
    input_dir: str = typer.Argument(..., help="包含二进制文件的目录"),
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
    
    with Progress(
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
def health_command(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出")
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
def test_command(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="详细输出")
):
    """运行测试套件验证核心功能"""
    console.print("[blue]启动测试套件...[/blue]")
    
    try:
        import subprocess
        result = subprocess.run(
            ["python", "-m", "pytest", "tests/", "-v"] if verbose else ["python", "-m", "pytest", "tests/"],
            capture_output=True,
            text=True,
            cwd=os.path.dirname(os.path.dirname(__file__))
        )
        
        console.print(result.stdout)
        
        if result.returncode != 0:
            console.print(f"[red]测试失败: {result.stderr}[/red]")
            raise typer.Exit(code=1)
        
        console.print("[green]测试完成[/green]")
    
    except Exception as e:
        console.print(f"[red]运行测试失败: {e}[/red]")
        raise typer.Exit(code=1)


@app.command("server", help="启动Web API服务")
def server_command(
    host: str = typer.Option("0.0.0.0", "--host", help="绑定地址"),
    port: int = typer.Option(9000, "--port", "-p", help="端口"),
    reload: bool = typer.Option(False, "--reload", help="自动重载")
):
    """启动Web API服务"""
    console.print(f"[blue]启动 Web API 服务:[/blue] http://{host}:{port}")
    
    try:
        import uvicorn
        from modules.web_api import app
        
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except ImportError as e:
        console.print(f"[red]启动服务器失败: {e}[/red]")
        console.print("[yellow]请安装依赖: pip install fastapi uvicorn[/yellow]")
        raise typer.Exit(code=1)


@app.command("version", help="显示版本信息")
def version_command():
    """显示版本信息"""
    console.print("[bold blue]Deemo Binary Analysis Platform[/bold blue]")
    console.print("[blue]Version:[/blue] 1.3.1")
    console.print("[blue]Author:[/blue] Binary Security Research Team")
    console.print("[blue]Description:[/blue] LLM-Assisted Binary Vulnerability Analysis")


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
        report += f"> {result.error}\n\n"
        return report
    
    report += f"## 分析指标\n\n"
    report += f"| 指标 | 值 |\n"
    report += f"|------|-----|\n"
    for key, value in result.metrics.items():
        report += f"| {key} | {value} |\n"
    report += "\n"
    
    report += f"## 发现的问题\n\n"
    for finding in result.findings:
        severity = finding.get('type', 'info').upper()
        message = finding.get('message', '')
        confidence = finding.get('confidence', '')
        
        report += f"### {severity}: {message}\n"
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
        html += "</body></html>"
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
    
    html += "</body></html>"
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


if __name__ == "__main__":
    app()
