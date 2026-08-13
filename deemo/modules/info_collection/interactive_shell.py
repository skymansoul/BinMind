# 核心接口：ShellCommand 装饰器与 InteractiveReversingShell。
# 依赖：os, re, cmd, json, datetime, core.config, deobfuscation.decomp_ai, core.report, exploit.exploit_gen
import logging
import os
import re
import cmd
import json
from typing import Dict, Optional, Any, Callable
from datetime import datetime

from core.config import Config, get_openai_client
from modules.analysis.decompiler.decomp_ai import DecompilerAI
# vuln_db 查询 — 待模块集成
from modules.output.report import ReportGenerator
from exploit.exploit_gen import ExploitGenerator

logger = logging.getLogger(__name__)

DANGEROUS_CHARS = {'\n', '\r', ';', '&', '|', '`', '$', '(', ')', '<', '>', '?', '*', '[', ']', '{', '}', '\\', '"', "'"}

class ShellCommand:
    """装饰器：将方法注册为 Shell 命令并附带帮助文本。"""
    def __init__(self, name: str, help_text: str):
        self.name = name
        self.help_text = help_text

    def __call__(self, func: Callable) -> Callable:
        func.shell_command = self.name
        func.shell_help = self.help_text,
        return func

class InteractiveReversingShell(cmd.Cmd):
    """逆向工程交互式 Shell — 类 radare2 命令行界面。"""

    prompt = 'binmind> '

    def __init__(self, binary_path: str = None, ai_client=None):
        super().__init__()
        self.binary_path = binary_path
        self.ai_client = ai_client
        self.decompiler: Optional[DecompilerAI] = None
        self.vuln_db: Optional[VulnerabilityDatabase] = None
        self.report_generator: Optional[ReportGenerator] = None

        self.current_analysis: Dict[str, Any] = {}
        self.history_file = os.path.join(Config.DATA_DIR, 'shell_history.txt')

        if binary_path:
            self._load_binary(binary_path)

        self._load_history()

    # 由单行推导式重构为显式循环以降低复杂度。
    def _load_binary(self, binary_path: str) -> bool:
        """加载并初始化待分析的二进制文件。"""
        try:
            self.binary_path = binary_path
            self.decompiler = DecompilerAI(binary_path)
            self.vuln_db = VulnerabilityDatabase()
            self.report_generator = ReportGenerator()

            logger.info(f"二进制文件已加载: {binary_path}")
            print(f"✓ 已加载: {binary_path}")
            print(f"  反编译引擎: {self.decompiler.active_decompiler}")
            return True
        except Exception as e:
            logger.error(f"加载失败: {e}")
            print(f"✗ 加载失败: {e}")
            return False

    def _load_history(self):
        """从持久化存储恢复命令历史。"""
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r', encoding='utf-8') as f:
                    lines = f.read().split('\n')
                    self.history.extend([l for l in lines if l.strip()])
        except Exception as e:
            logger.debug(f"历史记录加载失败: {e}")

    def _save_history(self):
        """将命令历史持久化到磁盘（保留最近 100 条）。"""
        try:
            os.makedirs(os.path.dirname(self.history_file), exist_ok=True)
            with open(self.history_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(self.history[-100:]))

        except Exception as e:
            logger.debug(f"历史记录保存失败: {e}")

    def _sanitize_input(self, input_str: str) -> str:
        """剔除 Shell 元字符以防止命令注入。"""
        if not input_str:
            return input_str

        for char in DANGEROUS_CHARS:
            input_str = input_str.replace(char, '')

        return input_str.strip()

    def precmd(self, line: str) -> str:
        """命令前钩子：将输入记录到历史。"""
        if line.strip():
            self.history.append(line)
        return line

    def postcmd(self, stop: bool, line: str) -> bool:
        """命令后钩子：持久化历史。"""
        self._save_history()
        return stop

    def do_load(self, arg: str) -> None:
        """
        load <binary_path> — 加载二进制文件以供分析。

        示例：
            load /path/to/binary
            load ./test.bin
        """
        binary_path = self._sanitize_input(arg)

        if not binary_path:
            print("用法: load <binary_path>")
            return

        if not os.path.exists(binary_path):
            print(f"错误: 文件未找到 — {binary_path}")
            return

        self._load_binary(binary_path)

    def do_info(self, arg: str) -> None:
        """
        info — 显示当前加载二进制文件的基本元数据。

        示例：
            info
        """
        if not self.decompiler:
            print("错误: 请先使用 'load' 命令")
            return

        # info_collect 集成待完成

        try:
            binary_info = get_binary_info(self.binary_path)
            binary_format = detect_binary_format(self.binary_path)

            print(f"\n{'=' * 60}")
            print("二进制文件信息")
            print(f"{'=' * 60}")
            print(f"路径: {self.binary_path}")
            print(f"格式: {binary_format}")
            print(f"架构: {binary_info.get('arch', 'Unknown')}")
            print(f"位数: {binary_info.get('bits', 0)}")
            print(f"大小: {binary_info.get('size', 0)} 字节")
            print(f"{'=' * 60}")

            checksec = binary_info.get('checksec', {})
            if checksec:
                print("\n保护机制:")
                print(f"  NX: {checksec.get('nx', 'Unknown')}")
                print(f"  PIE: {checksec.get('pie', 'Unknown')}")
                print(f"  RELRO: {checksec.get('relro', 'Unknown')}")
                print(f"  Canary: {checksec.get('canary', 'Unknown')}")

            imports = binary_info.get('imports', {})
            if imports:
                dangerous_funcs = imports.get('dangerous_functions', [])
                if dangerous_funcs:
                    print(f"\n危险函数 ({len(dangerous_funcs)}):")
                    for func in dangerous_funcs[:10]:
                        print(f"  - {func}")
                    if len(dangerous_funcs) > 10:
                        print(f"  ... (另有 {len(dangerous_funcs) - 10} 个)")

        except Exception as e:
            print(f"获取信息失败: {e}")

    def do_functions(self, arg: str) -> None:
        """
        functions [filter] — 列出函数，支持子串过滤。

        示例：
            functions
            functions main
            functions vuln
        """
        if not self.decompiler:
            print("错误: 请先使用 'load' 命令")
            return

        try:
            all_funcs = self.decompiler.list_functions()
            filter_str = self._sanitize_input(arg).lower()

            if filter_str:
                funcs = [f for f in all_funcs if filter_str in f.lower()]
            else:
                funcs = all_funcs

            print(f"\n可用函数 ({len(funcs)}):")
            for i, func in enumerate(funcs[:50], 1):
                print(f"  [{i}] {func}")
            if len(funcs) > 50:
                print(f"  ... (另有 {len(funcs) - 50} 个)")

        except Exception as e:
            print(f"函数列表获取失败: {e}")

    def do_decompile(self, arg: str) -> None:
        """
        decompile <func_name> — 反编译指定函数并显示伪代码。

        示例：
            decompile main
            decompile vuln_function
        """
        func_name = self._sanitize_input(arg)

        if not func_name:
            print("用法: decompile <func_name>")
            return

        if not self.decompiler:
            print("错误: 请先使用 'load' 命令")
            return

        try:
            pseudocode = self.decompiler.decompile(func_name)

            if pseudocode:
                print(f"\n{'=' * 60}")
                print(f"函数: {func_name}")
                print(f"{'=' * 60}")
                print(pseudocode[:5000])
                if len(pseudocode) > 5000:
                    print(f"\n... (已截断，另有 {len(pseudocode) - 5000} 字符)")
            else:
                print(f"无法反编译函数: {func_name}")

        except Exception as e:
            print(f"反编译失败: {e}")

    def do_analyze(self, arg: str) -> None:
        """
        analyze <func_name> — 对指定函数执行 AI 漏洞分析。

        示例：
            analyze main
            analyze vulnerable_function
        """
        func_name = self._sanitize_input(arg)

        if not func_name:
            print("用法: analyze <func_name>")
            return

        if not self.decompiler:
            print("错误: 请先使用 'load' 命令")
            return

        try:
            print(f"\n正在分析函数: {func_name}...")

            # info_collect 集成待完成

            binary_info = get_binary_info(self.binary_path)
            result = self.decompiler.analyze_function(func_name, binary_info)

            vulns = result.get('vulnerabilities', [])
            summary = result.get('summary', '')
            risk_level = result.get('risk_level', 'Unknown')

            print(f"\n{'=' * 60}")
            print(f"分析结果: {func_name}")
            print(f"{'=' * 60}")
            print(f"风险等级: {risk_level}")
            print(f"\n摘要: {summary}")

            if vulns:
                print(f"\n发现 {len(vulns)} 个漏洞:")
                for i, vuln in enumerate(vulns, 1):
                    print(f"\n  [{i}] {vuln.get('type', 'Unknown')}")
                    print(f"      位置: {vuln.get('location', 'Unknown')}")
                    print(f"      严重度: {vuln.get('severity', 'Unknown')}")
                    print(f"      描述: {vuln.get('description', 'Unknown')}")

            self.current_analysis[func_name] = result

        except Exception as e:
            print(f"分析失败: {e}")

    def do_xrefs(self, arg: str) -> None:
        """
        xrefs <address/symbol> — 使用 radare2 查找交叉引用。

        示例：
            xrefs main
            xrefs 0x401000
        """
        target = self._sanitize_input(arg)

        if not target:
            print("用法: xrefs <address/symbol>")
            return

        if not self.binary_path:
            print("错误: 请先使用 'load' 命令")
            return

        try:
            import subprocess

            if target.startswith('0x'):
                cmd_str = f'aaa; ax {target}; q'
            else:
                cmd_str = f'aaa; ax sym.{target}; q'

            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c', cmd_str,
                self.binary_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=Config.SUBPROCESS_TIMEOUT
            )

            if result.returncode == 0 and result.stdout.strip():
                print(f"\n{'=' * 60}")
                print(f"交叉引用: {target}")
                print(f"{'=' * 60}")
                print(result.stdout.strip())

            else:
                print(f"未找到引用或分析失败")

        except Exception as e:
            print(f"交叉引用查找失败: {e}")

    def do_ask(self, arg: str) -> None:
        """
        ask <question> — 向 AI 询问当前二进制文件或指定函数的相关问题。

        示例：
            ask 这个二进制文件有哪些漏洞？
            ask main 函数中存在哪些安全问题？
            ask 如何利用这个缓冲区溢出？
        """
        question = arg.strip()

        if not question:
            print("用法: ask <question>")
            return

        if not self.ai_client:
            print("错误: AI 客户端未配置 — 请检查设置")
            return

        try:
            print(f"\n正在向 AI 提问: {question}")
            print("等待响应...")

            context = "",
            if self.binary_path:
                context = f"二进制文件: {self.binary_path}\n"

            if self.current_analysis:
                context += "已分析函数: " + ", ".join(self.current_analysis.keys()) + "\n"

            prompt = f"""
你是一名二进制安全专家。请回答以下问题:

上下文信息:
{context}

问题: {question}

请提供详细的技术分析和建议。
"""

            from core.config import call_ai_with_retry, get_current_ai_model, mask_sensitive_data

            messages = [
                {"role": "system", "content": "你是一名资深二进制安全研究员与漏洞分析专家。"},
                {"role": "user", "content": prompt}
            ]

            result_text = call_ai_with_retry(
                self.ai_client,
                model=get_current_ai_model(),
                messages=messages,
                temperature=0.3,
                max_tokens=3000
            )

            if result_text:
                print(f"\n{'=' * 60}")
                print("AI 回答")
                print(f"{'=' * 60}")
                print(result_text)
            else:
                print("AI 未返回结果")

        except Exception as e:
            print(f"AI 查询失败: {e}")

    def do_patch(self, arg: str) -> None:
        """
        patch <func_name> — 生成补丁建议。

        示例：
            patch main
            patch vulnerable_function
        """
        func_name = self._sanitize_input(arg)

        if not func_name:
            print("用法: patch <func_name>")
            return

        if not self.decompiler or not self.ai_client:
            print("错误: 请先加载二进制文件并确保 AI 客户端已配置")
            return

        try:
            print(f"\n正在为 {func_name} 生成补丁建议...")

            pseudocode = self.decompiler.decompile(func_name)

            if not pseudocode:
                print(f"无法获取 {func_name} 的伪代码")
                return

            from core.config import call_ai_with_retry, get_current_ai_model

            prompt = f"""
你是一名资深安全工程师。请为以下函数生成安全补丁建议。

函数名: {func_name}

伪代码:
{pseudocode}

请分析代码中的安全问题并提供详细补丁建议:
1. 漏洞类型与风险评估
2. 具体修复方案
3. 修复后代码示例
4. 注意事项

输出语言: 中文
"""

            messages = [
                {"role": "system", "content": "你是一名资深安全工程师，擅长漏洞修复与代码加固。"},
                {"role": "user", "content": prompt}
            ]

            result_text = call_ai_with_retry(
                self.ai_client,
                model=get_current_ai_model(),
                messages=messages,
                temperature=0.3,
                max_tokens=3000
            )

            if result_text:
                print(f"\n{'=' * 60}")
                print(f"补丁建议: {func_name}")
                print(f"{'=' * 60}")
                print(result_text)
            else:
                print("AI 未返回结果")

        except Exception as e:
            print(f"补丁生成失败: {e}")

    def do_exploit(self, arg: str) -> None:
        """
        exploit <vuln_id> — 针对指定漏洞触发利用脚本生成。

        示例：
            exploit 1
            exploit 2
        """
        vuln_id = self._sanitize_input(arg)

        if not vuln_id:
            print("用法: exploit <vuln_id>")
            return

        if not self.binary_path:
            print("错误: 请先加载二进制文件")
            return

        try:
            vuln_id_int = int(vuln_id)

            all_vulns = []
            for func_name, analysis in self.current_analysis.items():
                vulns = analysis.get('vulnerabilities', [])
                for vuln in vulns:
                    all_vulns.append({'function_name': func_name, **vuln})

            if not all_vulns:
                print("无已分析漏洞 — 请先执行 'analyze' 命令")
                return

            if vuln_id_int < 1 or vuln_id_int > len(all_vulns):
                print(f"无效漏洞编号，有效范围: 1-{len(all_vulns)}")
                return

            target_vuln = all_vulns[vuln_id_int - 1]

            print(f"\n正在生成利用脚本...")
            print(f"漏洞类型: {target_vuln.get('type', 'Unknown')}")
            print(f"位置: {target_vuln.get('location', 'Unknown')}")

            # info_collect 集成待完成

            binary_info = get_binary_info(self.binary_path)
            exploit_gen = ExploitGenerator(self.binary_path, binary_info, self.ai_client)

            result = exploit_gen.generate_and_validate(
                target_vuln,
                use_ai=self.ai_client is not None,
                validate=False,
                no_exec=True
            )

            if result.get('success'):
                print("\n✓ 利用脚本生成成功")
                if result.get('script_path'):
                    print(f"脚本路径: {result.get('script_path')}")
                if result.get('script_content'):
                    print("\n利用脚本预览:")
                    print("-" * 60)
                    print(result['script_content'][:1000])
                    if len(result['script_content']) > 1000:
                        print("... (已截断)")
            else:
                print(f"\n✗ 利用脚本生成失败")
                if result.get('error'):
                    print(f"错误: {result.get('error')}")

        except ValueError:
            print("请输入有效的漏洞编号")
        except Exception as e:
            print(f"利用脚本生成失败: {e}")

    def do_db(self, arg: str) -> None:
        """
        db search <type> — 搜索漏洞数据库。

        示例：
            db search buffer_overflow
            db search format_string
            db search all
        """
        args = arg.strip().split()

        if not args or args[0].lower() != 'search':
            print("用法: db search <type>")
            return

        search_type = self._sanitize_input(args[1]) if len(args) > 1 else 'all'

        if not self.vuln_db:
            self.vuln_db = VulnerabilityDatabase()

        try:
            if search_type.lower() == 'all':
                results = self.vuln_db.get_all(limit=10)
            else:
                results = self.vuln_db.search_by_vulnerability_type(search_type, limit=10)

            print(f"\n{'=' * 60}")
            print(f"数据库搜索结果 (类型: {search_type})")
            print(f"{'=' * 60}")

            if results:
                for i, vuln in enumerate(results, 1):
                    print(f"\n[{i}] {vuln.get('vulnerability_type', 'Unknown')}")
                    print(f"    二进制文件: {vuln.get('binary_name', 'Unknown')}")
                    print(f"    函数: {vuln.get('function_name', 'Unknown')}")
                    print(f"    严重度: {vuln.get('severity', 'Unknown')}")
            else:
                print("未找到匹配的漏洞记录")

        except Exception as e:
            print(f"数据库搜索失败: {e}")

    def do_export(self, arg: str) -> None:
        """
        export <format> — 将分析结果导出为报告文件。

        支持格式: markdown, json, html

        示例：
            export markdown
            export json
            export html
        """
        fmt = self._sanitize_input(arg).lower()

        if not fmt or fmt not in ['markdown', 'json', 'html']:
            print("用法: export <format>")
            print("支持格式: markdown, json, html")
            return

        if not self.binary_path or not self.current_analysis:
            print("错误: 请先加载二进制文件并执行分析")
            return

        try:
            # info_collect 集成待完成

            binary_info = get_binary_info(self.binary_path)
            decomp_results = [
                {'function_name': func, 'analysis': analysis}
                for func, analysis in self.current_analysis.items()
            ]

            report_path = self.report_generator.generate_report_rp(
                self.binary_path,
                binary_info,
                decomp_results,
                crash_analysis=None,
                exploit_result=None
            )

            print(f"\n✓ 报告已导出: {report_path}")

        except Exception as e:
            print(f"报告导出失败: {e}")

    def do_quit(self, arg: str) -> bool:
        """
        quit — 退出交互式 Shell。

        示例：
            quit
        """
        print("\n感谢使用 BinMind 逆向辅助 Shell。")
        return True

    def do_exit(self, arg: str) -> bool:
        """
        exit — 退出交互式 Shell（与 quit 等效）。

        示例：
            exit
        """
        return self.do_quit(arg)

    def do_help(self, arg: str) -> None:
        """
        help [command] — 显示帮助信息。

        示例：
            help
            help analyze
        """
        if arg:
            arg = arg.strip().lower()
            method_name = f'do_{arg}',
            if hasattr(self, method_name):
                method = getattr(self, method_name)
                print(f"\n{method.__doc__}")
            else:
                print(f"未知命令: {arg}")
        else:
            print("\n" + "=" * 60)
            print("BinMind 逆向辅助 Shell 命令列表")
            print("=" * 60)
            print("")

            commands = [
                ('load', '加载二进制文件以进行分析'),
                ('info', '显示当前二进制文件基本信息'),
                ('functions', '列出函数（支持过滤）'),
                ('decompile', '反编译指定函数'),
                ('analyze', '对函数执行 AI 漏洞分析'),
                ('xrefs', '查找交叉引用'),
                ('ask', '向 AI 助手提问'),
                ('patch', '生成 AI 补丁建议'),
                ('exploit', '触发利用脚本生成'),
                ('db', '搜索漏洞数据库'),
                ('export', '导出分析结果'),
                ('quit/exit', '退出 Shell')
            ]

            for cmd_name, desc in commands:
                print(f"  {cmd_name:<15} {desc}")

            print("")
            print("使用 'help <command>' 查看命令详细说明")
            print("=" * 60)

    def emptyline(self) -> None:
        """忽略空行 — 不重复执行上一条命令。"""
        pass

    def run(self) -> None:
        """启动交互式 Shell。"""
        print("")
        print("=" * 60)
        print("BinMind 逆向辅助交互式 Shell")
        print("=" * 60)
        print("输入 'help' 查看可用命令")
        print("=" * 60)

        if self.binary_path:
            print(f"已加载: {self.binary_path}")

        self.cmdloop()

def run_shell(binary_path: str = None, ai_client=None):
    """启动 InteractiveReversingShell 实例。

    Args:
        binary_path: 可选，预加载的二进制文件路径。
        ai_client: 可选，预配置的 AI 客户端。
    """
    shell = InteractiveReversingShell(binary_path, ai_client)
    shell.run()
