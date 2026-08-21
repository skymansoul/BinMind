"""
decomp_ai.py：智能辅助 二进制反编译与漏洞分析

核心模块：提供 反编译分析器, 主类 调度
多引擎反编译 (radare2, Ghidra, IDA, Binary Ninja, Hopper)
智能漏洞分析 反编译伪代码

支撑模块:
- decomp_ai_models.py: 模型配置, 提示词模板, 工具函数
- decomp_ai_cache.py: 反编译与API结果缓存, 速率限制
"""

import logging
import subprocess
import os
import json
import re
import shlex
import tempfile
from typing import Dict, List, Optional, Any, Tuple, Callable
from pathlib import Path

from config import Config, get_current_ai_model, call_ai_with_retry, mask_sensitive_data
from prompts import DECOMP_ANALYSIS_TEMPLATE

# Import 模型配置与工具集
from modules.analysis.decompiler.decomp_ai_models import (
    AI_SYSTEM_PROMPT_ANALYSIS,
    AI_SYSTEM_PROMPT_FOLLOW_UP,
    AI_TEMPERATURE_ANALYSIS,
    AI_TEMPERATURE_FOLLOW_UP,
    AI_MAX_TOKENS_ANALYSIS,
    AI_MAX_TOKENS_FOLLOW_UP,
    strip_ansi_escape,
    run_hook,
    HOOKS_AVAILABLE,
    HOOK_POINTS,
    load_plugin_script,
    DECOMPILER_RADARE2,
    DECOMPILER_GHIDRA,
    DECOMPILER_IDA,
    DECOMPILER_BINARYNINJA,
    DECOMPILER_HOPPER,
    DECOMPILER_AUTO,
    FUNCTION_NAME_PATTERN,
    JAVA_STRING_ESCAPE_MAP,
    sanitize_function_name,
    escape_java_string,
    escape_idc_string,
)

# Import 缓存基础设施
from modules.analysis.decompiler.decomp_ai_cache import (
    DECOMP_CACHE,
    DECOMP_CACHE_DIR,
    API_CACHE_DIR,
    API_RATE_LIMIT,
    compute_binary_hash,
    get_cached_decompilation,
    cache_decompilation,
    get_cached_api_response,
    cache_api_response,
    check_api_rate_limit,
    wait_for_api_rate_limit,
    clear_decomp_cache,
    clear_api_cache,
    get_cache_stats,
)

logger = logging.getLogger(__name__)


class DecompilerAI:
    """
    反编译与分析类 - 支持多反编译引擎
    """

    def __init__(self, binary_path: str, openai_client=None, decompiler: str = DECOMPILER_AUTO):
        """初始化反编译分析器"""
        from modules.info.info_collect import validate_binary_path
        try:
            self.binary_path = validate_binary_path(binary_path)
        except ValueError as e:
            logger.error(f"二进制路径验证失败: {e}")
            raise

        self.client = openai_client
        self.preferred_decompiler = decompiler

        self.available_decompilers = self._detect_available_decompilers()
        self.active_decompiler = self._select_decompiler()

        self.conversation_history: List[Dict[str, str]] = []
        self.max_history_messages = getattr(Config, 'AI_MAX_HISTORY_MESSAGES', 10)

        logger.info(f"可用反编译引擎: {list(self.available_decompilers.keys())}")
        logger.info(f"选中的反编译引擎: {self.active_decompiler}")

    def _detect_available_decompilers(self) -> Dict[str, bool]:
        """
        检测可用的反编译引擎
        """
        available = {}

        available['radare2'] = self._check_radare2()
        available['ghidra'] = self._check_ghidra()
        available['ida'] = self._check_ida()
        available['binaryninja'] = self._check_binaryninja()
        available['hopper'] = self._check_hopper()

        return available

    def _select_decompiler(self) -> str:
        """
        选择要使用的反编译引擎
        """
        if self.preferred_decompiler != DECOMPILER_AUTO:
            if self.available_decompilers.get(self.preferred_decompiler):
                return self.preferred_decompiler
            else:
                logger.warning(f"指定的反编译引擎 {self.preferred_decompiler} 不可用")

        for decompiler in ['ghidra', 'ida', 'binaryninja', 'hopper', 'radare2']:
            if self.available_decompilers.get(decompiler):
                return decompiler

        return 'radare2'

    def _check_radare2(self) -> bool:
        """
        检查 radare2 是否可用
        """
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
                logger.info(f"radare2 可用: {result.stdout.strip().split(chr(10))[0]}")
                return True
        except FileNotFoundError:
            logger.debug("radare2 未安装")
        except subprocess.TimeoutExpired:
            logger.debug("检查 radare2 超时")
        except Exception as e:
            logger.debug(f"检查 radare2 失败: {e}")
        return False

    def _check_ghidra(self) -> bool:
        """
        检查 Ghidra 是否可用
        """
        ghidra_paths = [
            os.environ.get('GHIDRA_HOME', ''),
            '/opt/ghidra',
            '/usr/local/ghidra',
            os.path.expanduser('~/ghidra'),
            os.path.expanduser('~/GhidraProjects'),
        ]

        for path in ghidra_paths:
            if path and os.path.exists(path):
                support_dir = os.path.join(path, 'support')
                if os.path.exists(support_dir):
                    analyze_script = os.path.join(support_dir, 'analyzeHeadless')
                    if os.path.exists(analyze_script):
                        logger.info(f"Ghidra 可用: {path}")
                        return True
                    analyze_bat = os.path.join(support_dir, 'analyzeHeadless.bat')
                    if os.path.exists(analyze_bat):
                        logger.info(f"Ghidra 可用 (Windows): {path}")
                        return True

        try:
            result = subprocess.run(
                ['which', 'analyzeHeadless'],
                capture_output=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0:
                logger.info("Ghidra (analyzeHeadless) 可用")
                return True
        except Exception:
            pass

        return False

    def _check_ida(self) -> bool:
        """
        检查 IDA Pro 是否可用
        """
        ida_paths = [
            os.environ.get('IDA_PATH', ''),
            '/opt/ida',
            '/opt/ida-7.0',
            '/opt/ida-7.5',
            os.path.expanduser('~/ida'),
            os.path.expanduser('~/IDA'),
            'C:\\Program Files\\IDA 7.0',
            'C:\\Program Files\\IDA Pro 7.0',
        ]

        for path in ida_paths:
            if path and os.path.exists(path):
                for ida_exe in ['idal64', 'ida64', 'idal', 'ida', 'idaq.exe', 'ida.exe']:
                    full_path = os.path.join(path, ida_exe)
                    if os.path.exists(full_path):
                        logger.info(f"IDA Pro 可用: {full_path}")
                        return True

        try:
            result = subprocess.run(
                ['which', 'ida64'],
                capture_output=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0:
                logger.info("IDA Pro (ida64) 可用")
                return True
        except Exception:
            pass

        return False

    def _check_binaryninja(self) -> bool:
        """
        检查 Binary Ninja 是否可用
        """
        try:
            import binaryninja
            logger.info("Binary Ninja 可用 (Python API)")
            return True
        except ImportError:
            pass

        bn_paths = [
            os.environ.get('BINARYNINJA_PATH', ''),
            '/opt/binaryninja',
            '/usr/local/binaryninja',
            os.path.expanduser('~/binaryninja'),
            r'C:\Program Files\Vector35\Binary Ninja',
            r'C:\Program Files\Vector 35\Binary Ninja',
        ]

        for path in bn_paths:
            if path and os.path.exists(path):
                for exe in ['binaryninja', 'binaryninja.exe', 'bndb', 'bndb.exe']:
                    full_path = os.path.join(path, exe)
                    if os.path.exists(full_path):
                        logger.info(f"Binary Ninja 可用: {full_path}")
                        return True

        return False

    def _check_hopper(self) -> bool:
        """
        检查 Hopper 是否可用 (仅 macOS)
        """
        if os.name != 'posix':
            return False

        hopper_paths = [
            '/Applications/Hopper Disassembler v4.app',
            '/Applications/Hopper Disassembler v5.app',
            '/Applications/Hopper.app',
            os.path.expanduser('~/Applications/Hopper Disassembler v4.app'),
            os.path.expanduser('~/Applications/Hopper.app'),
        ]

        for path in hopper_paths:
            if os.path.exists(path):
                logger.info(f"Hopper 可用: {path}")
                return True

        try:
            result = subprocess.run(
                ['which', 'hopper'],
                capture_output=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            if result.returncode == 0:
                logger.info("Hopper (CLI) 可用")
                return True
        except Exception:
            pass

        return False

    def decompile(self, function_name: str = 'main') -> Optional[str]:
        """使用选中的反编译引擎反编译指定函数"""
        if self.active_decompiler == 'ghidra':
            return self.decompile_with_ghidra(function_name)
        elif self.active_decompiler == 'ida':
            return self.decompile_with_ida(function_name)
        elif self.active_decompiler == 'binaryninja':
            return self.decompile_with_binaryninja(function_name)
        elif self.active_decompiler == 'hopper':
            return self.decompile_with_hopper(function_name)
        else:
            return self.decompile_with_radare2(function_name)

    def decompile_with_radare2(self, function_name: str = 'main') -> Optional[str]:
        """
        使用 radare2 反编译指定函数
        """
        if not self.available_decompilers.get('radare2'):
            logger.error("radare2 不可用，无法进行反编译")
            return None

        safe_func_name = sanitize_function_name(function_name)

        try:
            r2_commands = ['aaa', f's sym.{safe_func_name}', 'pdd', 'q']
            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c',
                '; '.join(r2_commands),
                self.binary_path
            ]

            logger.info(f"[radare2] 开始反编译函数: {safe_func_name}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=Config.RADARE2_TIMEOUT
            )

            if result.returncode == 0:
                pseudocode = result.stdout.strip()
                if pseudocode:
                    pseudocode = strip_ansi_escape(pseudocode)
                    logger.info(f"[radare2] 成功反编译函数 {safe_func_name}")
                    return pseudocode
                else:
                    logger.warning(f"[radare2] 反编译结果为空，尝试使用替代方法")
                    return self._decompile_radare2_alternative(safe_func_name)
            else:
                logger.error(f"[radare2] 执行失败: {result.stderr[:500] if result.stderr else '未知错误'}")
                return None

        except subprocess.TimeoutExpired:
            logger.error(f"[radare2] 反编译函数 {safe_func_name} 超时 ({Config.RADARE2_TIMEOUT} 秒)")
            logger.error("[radare2] 建议: 尝试增加 Config.RADARE2_TIMEOUT 或使用更简单的反编译目标")
            return None
        except Exception as e:
            logger.error(f"[radare2] 反编译过程出错: {e}")
            return None

    def _decompile_radare2_alternative(self, function_name: str) -> Optional[str]:
        """
        radare2 备用反编译方法
        """
        try:
            safe_func_name = sanitize_function_name(function_name)
            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c',
                f'aaa; af @ sym.{safe_func_name}; pdf @ sym.{safe_func_name}; q',
                self.binary_path
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=Config.RADARE2_TIMEOUT
            )

            if result.returncode == 0 and result.stdout.strip():
                return strip_ansi_escape(result.stdout.strip())
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"[radare2] 备用反编译方法超时 ({Config.RADARE2_TIMEOUT} 秒)")
            logger.error("[radare2] 建议: 检查二进制文件大小或增加超时时间")
            return None
        except Exception as e:
            logger.error(f"[radare2] 备用反编译方法失败: {e}")
            return None

    def decompile_with_ghidra(self, function_name: str = 'main') -> Optional[str]:
        """
        使用 Ghidra Headless 反编译指定函数
        """
        if not self.available_decompilers.get('ghidra'):
            logger.error("Ghidra 不可用")
            return self.decompile_with_radare2(function_name)

        safe_func_name = sanitize_function_name(function_name)

        try:
            ghidra_home = self._find_ghidra_home()
            if not ghidra_home:
                logger.warning("无法找到 Ghidra 安装目录，回退到 radare2")
                return self.decompile_with_radare2(function_name)

            logger.info(f"[Ghidra] 开始反编译函数: {safe_func_name}")

            decomp_script = self._create_ghidra_decomp_script(safe_func_name)
            if not decomp_script:
                logger.warning("无法创建 Ghidra 脚本，回退到 radare2")
                return self.decompile_with_radare2(function_name)

            with tempfile.TemporaryDirectory() as temp_dir:
                base_name = os.path.basename(self.binary_path)
                project_name = f"decompile_{base_name}"

                script_ext = '.bat' if os.name == 'nt' else ''
                analyze_script = os.path.join(ghidra_home, 'support', f'analyzeHeadless{script_ext}')

                if not os.path.exists(analyze_script):
                    logger.warning(f"Ghidra analyzeHeadless 不存在: {analyze_script}")
                    return self.decompile_with_radare2(function_name)

                cmd = [
                    analyze_script,
                    temp_dir,
                    project_name,
                    '-import', self.binary_path,
                    '-scriptPath', os.path.dirname(decomp_script),
                    '-postScript', os.path.basename(decomp_script),
                    '-deleteProject'
                ]

                timeout = getattr(Config, 'GHIDRA_TIMEOUT', 300)
                logger.debug(f"[Ghidra] 使用超时设置: {timeout} 秒")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=timeout
                )

                pseudocode = self._extract_ghidra_pseudocode(result.stdout, result.stderr)

                if pseudocode:
                    logger.info(f"[Ghidra] 成功反编译函数 {safe_func_name}")
                    return pseudocode
                else:
                    logger.warning(f"[Ghidra] 未找到函数 {safe_func_name} 的伪代码，回退到 radare2")
                    return self.decompile_with_radare2(function_name)

        except subprocess.TimeoutExpired:
            timeout = getattr(Config, 'GHIDRA_TIMEOUT', 300)
            logger.error(f"[Ghidra] 反编译函数 {safe_func_name} 超时 ({timeout} 秒)")
            logger.error("[Ghidra] 建议: 尝试增加 Config.GHIDRA_TIMEOUT 或使用 radare2")
            return self.decompile_with_radare2(function_name)
        except Exception as e:
            logger.error(f"[Ghidra] 反编译过程出错: {e}")
            return self.decompile_with_radare2(function_name)

    def _find_ghidra_home(self) -> Optional[str]:
        """
        查找 Ghidra 安装目录
        """
        ghidra_paths = [
            os.environ.get('GHIDRA_HOME', ''),
            '/opt/ghidra',
            '/usr/local/ghidra',
            os.path.expanduser('~/ghidra'),
        ]

        for path in ghidra_paths:
            if path and os.path.exists(path):
                support_dir = os.path.join(path, 'support')
                if os.path.exists(support_dir):
                    return path

        return None

    def _create_ghidra_decomp_script(self, function_name: str) -> Optional[str]:
        """
        创建 Ghidra 反编译脚本（已加固版本）
        """
        try:
            safe_func_name = escape_java_string(sanitize_function_name(function_name))
            safe_func_display = escape_java_string(function_name)

            script_content = f'''// Ghidra 反编译脚本
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;

function main() {{
    FunctionManager functionManager = currentProgram.getFunctionManager();
    Function func = functionManager.getFunctions(true).findFirst(
        f -> f.getName().equals("{safe_func_name}") ||
             f.getName().equals("sym.{safe_func_name}")
    );

    if (func == null) {{
        FunctionIterator iter = functionManager.getFunctions(true);
        while (iter.hasNext()) {{
            Function f = iter.next();
            String name = f.getName();
            if (name.contains("{safe_func_name}")) {{
                func = f;
                break;
            }}
        }}
    }}

    if (func != null) {{
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.openProgram(currentProgram);

        DecompileResults results = decompiler.decompileFunction(func, 60, null);

        if (results.decompiledFunctionIsDefined()) {{
            HighFunction hfunc = results.getHighFunction();
            println("=== DECOMPILED_CODE_START ===");
            println(decompiler.getCCode(results));
            println("=== DECOMPILED_CODE_END ===");
        }} else {{
            println("Decompilation failed: " + results.getErrorMessage());
        }}

        decompiler.closeProgram();
    }} else {{
        println("Function {safe_func_display} not found");
    }}
}}

main();
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False) as f:
                f.write(script_content)
                return f.name

        except Exception as e:
            logger.error(f"创建 Ghidra 脚本失败: {e}")
            return None

    def _extract_ghidra_pseudocode(self, stdout: str, stderr: str) -> Optional[str]:
        """
        从 Ghidra 输出中提取伪代码
        """
        output = stdout + '\n' + stderr

        start_marker = '=== DECOMPILED_CODE_START ==='
        end_marker = '=== DECOMPILED_CODE_END ==='

        start_idx = output.find(start_marker)
        if start_idx == -1:
            return None

        end_idx = output.find(end_marker, start_idx)
        if end_idx == -1:
            return None

        pseudocode = output[start_idx + len(start_marker):end_idx].strip()
        return pseudocode if pseudocode else None

    def decompile_with_ida(self, function_name: str = 'main') -> Optional[str]:
        """
        使用 IDA Pro 反编译指定函数
        """
        if not self.available_decompilers.get('ida'):
            logger.error("IDA Pro 不可用")
            return self.decompile_with_radare2(function_name)

        safe_func_name = sanitize_function_name(function_name)

        try:
            ida_path = self._find_ida_path()
            if not ida_path:
                logger.warning("无法找到 IDA 安装目录，回退到 radare2")
                return self.decompile_with_radare2(function_name)

            logger.info(f"[IDA] 开始反编译函数: {safe_func_name}")

            idc_script = self._create_ida_decomp_script(safe_func_name)
            if not idc_script:
                logger.warning("无法创建 IDA 脚本，回退到 radare2")
                return self.decompile_with_radare2(function_name)

            with tempfile.TemporaryDirectory() as temp_dir:
                output_file = os.path.join(temp_dir, 'decompiled.c')

                cmd = [
                    ida_path,
                    '-A',
                    '-S' + idc_script,
                    f'-Odecompiler:output="{output_file}"',
                    self.binary_path
                ]

                timeout = getattr(Config, 'IDA_TIMEOUT', 300)
                logger.debug(f"[IDA] 使用超时设置: {timeout} 秒")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=timeout
                )

                pseudocode = None
                if os.path.exists(output_file):
                    with open(output_file, 'r', encoding='utf-8', errors='replace') as f:
                        pseudocode = f.read().strip()

                if not pseudocode:
                    pseudocode = self._extract_ida_pseudocode(result.stdout, result.stderr, safe_func_name)

                if pseudocode:
                    logger.info(f"[IDA] 成功反编译函数 {safe_func_name}")
                    return pseudocode
                else:
                    logger.warning(f"[IDA] 未找到函数 {safe_func_name} 的伪代码，回退到 radare2")
                    return self.decompile_with_radare2(function_name)

        except subprocess.TimeoutExpired:
            timeout = getattr(Config, 'IDA_TIMEOUT', 300)
            logger.error(f"[IDA] 反编译函数 {safe_func_name} 超时 ({timeout} 秒)")
            logger.error("[IDA] 建议: 尝试增加 Config.IDA_TIMEOUT 或使用 radare2")
            return self.decompile_with_radare2(function_name)
        except Exception as e:
            logger.error(f"[IDA] 反编译过程出错: {e}")
            return self.decompile_with_radare2(function_name)

    def _find_ida_path(self) -> Optional[str]:
        """
        查找 IDA Pro 可执行文件路径
        """
        ida_paths = [
            os.environ.get('IDA_PATH', ''),
            '/opt/ida/ida64',
            '/opt/ida/idal64',
            '/opt/ida-7.0/ida64',
            '/opt/ida-7.5/ida64',
            os.path.expanduser('~/ida/ida64'),
        ]

        if os.name == 'nt':
            ida_paths.extend([
                r'C:\Program Files\IDA 7.0\ida64.exe',
                r'C:\Program Files\IDA Pro 7.0\ida64.exe',
                r'C:\Program Files\IDA 7.5\ida64.exe',
                r'C:\Program Files\IDA Pro 7.5\ida64.exe',
            ])

        for path in ida_paths:
            if path and os.path.exists(path):
                return path

        return None

    def _create_ida_decomp_script(self, function_name: str) -> Optional[str]:
        """
        创建 IDA 反编译脚本
        """
        try:
            safe_func_name = escape_idc_string(sanitize_function_name(function_name))

            script_content = f'''#include <idc.idc>

static main() {{
    auto func, decomp, output_file, handle;

    // 等待自动分析完成
    Wait();

    // 查找函数
    func = GetFunctionAttr("{safe_func_name}", FUNCATTR_START);
    if (func == BADADDR) {{
        // 尝试其他方式查找
        auto name, ea;
        for (ea = MinEA(); ea < MaxEA(); ea = NextFunction(ea)) {{
            name = GetFunctionName(ea);
            if (name == "{safe_func_name}" || name == "sub_{safe_func_name}") {{
                func = ea;
                break;
            }}
        }}
    }}

    if (func != BADADDR) {{
        // 尝试使用 Hex-Rays 反编译
        if (IsLibrary(func) == 0) {{
            // 输出到消息窗口
            Message("=== IDA_DECOMP_START ===\\n");

            auto cfunc = decompile(func);
            if (cfunc) {{
                print(cfunc);
            }}

            Message("\\n=== IDA_DECOMP_END ===\\n");
        }}
    }}

    Exit(0);
}}
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.idc', delete=False) as f:
                f.write(script_content)
                return f.name

        except Exception as e:
            logger.error(f"创建 IDA 脚本失败: {e}")
            return None

    def _extract_ida_pseudocode(self, stdout: str, stderr: str, function_name: str) -> Optional[str]:
        """
        从 IDA 输出中提取伪代码
        """
        output = stdout + '\n' + stderr

        start_marker = '=== IDA_DECOMP_START ==='
        end_marker = '=== IDA_DECOMP_END ==='

        start_idx = output.find(start_marker)
        if start_idx == -1:
            return None

        end_idx = output.find(end_marker, start_idx)
        if end_idx == -1:
            return None

        pseudocode = output[start_idx + len(start_marker):end_idx].strip()
        return pseudocode if pseudocode else None

    def decompile_with_binaryninja(self, function_name: str = 'main') -> Optional[str]:
        """
        使用 Binary Ninja 反编译指定函数
        """
        if not self.available_decompilers.get('binaryninja'):
            logger.error("Binary Ninja 不可用")
            return self.decompile_with_radare2(function_name)

        safe_func_name = sanitize_function_name(function_name)

        try:
            logger.info(f"[Binary Ninja] 开始反编译函数: {safe_func_name}")

            try:
                import binaryninja

                with binaryninja.open_view(self.binary_path) as bv:
                    target_func = None

                    for func in bv.functions:
                        if func.name == safe_func_name or func.name == f'sym.{safe_func_name}':
                            target_func = func
                            break

                    if target_func is None:
                        for func in bv.functions:
                            if safe_func_name in func.name:
                                target_func = func
                                break

                    if target_func is None:
                        logger.warning(f"[Binary Ninja] 未找到函数 {safe_func_name}，回退到 radare2")
                        return self.decompile_with_radare2(function_name)

                    pseudocode_lines = []
                    for llil in target_func.low_level_il:
                        pseudocode_lines.append(str(llil))

                    if not pseudocode_lines:
                        pseudocode = target_func.hlil
                        if pseudocode:
                            pseudocode_lines = [str(pseudocode)]

                    pseudocode = '\n'.join(pseudocode_lines)

                    if pseudocode:
                        logger.info(f"[Binary Ninja] 成功反编译函数 {safe_func_name}")
                        return pseudocode
                    else:
                        logger.warning(f"[Binary Ninja] 反编译结果为空，回退到 radare2")
                        return self.decompile_with_radare2(function_name)

            except ImportError:
                logger.warning("Binary Ninja Python API 不可用，尝试使用命令行方式")
                return self.decompile_with_radare2(function_name)

        except subprocess.TimeoutExpired:
            logger.error(f"[Binary Ninja] 反编译函数 {safe_func_name} 超时")
            return self.decompile_with_radare2(function_name)
        except Exception as e:
            logger.error(f"[Binary Ninja] 反编译过程出错: {e}")
            return self.decompile_with_radare2(function_name)

    def decompile_with_hopper(self, function_name: str = 'main') -> Optional[str]:
        """
        使用 Hopper 反编译指定函数 (macOS)
        """
        if not self.available_decompilers.get('hopper'):
            logger.error("Hopper 不可用")
            return self.decompile_with_radare2(function_name)

        safe_func_name = sanitize_function_name(function_name)

        try:
            logger.info(f"[Hopper] 开始反编译函数: {safe_func_name}")

            script_content = f'''#!/usr/bin/python
# Hopper 反编译脚本
import sys

doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()
if seg:
    symbols = doc.getSymbolsWithName("{safe_func_name}")
    if symbols:
        addr = symbols[0].getAddress()
        proc = doc.getProcedureAtAddress(addr)
        if proc:
            print("=== HOPPER_DECOMP_START ===")
            print(proc.toString())
            print("=== HOPPER_DECOMP_END ===")
'''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(script_content)
                script_path = f.name

            try:
                hopper_paths = [
                    '/Applications/Hopper Disassembler v4.app/Contents/MacOS/Hopper Disassembler v4',
                    '/Applications/Hopper Disassembler v5.app/Contents/MacOS/Hopper Disassembler v5',
                    '/Applications/Hopper.app/Contents/MacOS/Hopper',
                ]

                hopper_exe = None
                for path in hopper_paths:
                    if os.path.exists(path):
                        hopper_exe = path
                        break

                if hopper_exe:
                    cmd = [
                        hopper_exe,
                        '-l', script_path,
                        self.binary_path
                    ]

                    timeout = getattr(Config, 'HOPPER_TIMEOUT', 300)

                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='replace',
                        timeout=timeout
                    )

                    output = result.stdout + '\n' + result.stderr

                    start_marker = '=== HOPPER_DECOMP_START ==='
                    end_marker = '=== HOPPER_DECOMP_END ==='

                    start_idx = output.find(start_marker)
                    end_idx = output.find(end_marker, start_idx) if start_idx != -1 else -1

                    if start_idx != -1 and end_idx != -1:
                        pseudocode = output[start_idx + len(start_marker):end_idx].strip()
                        if pseudocode:
                            logger.info(f"[Hopper] 成功反编译函数 {safe_func_name}")
                            return pseudocode

                logger.warning(f"[Hopper] 未找到函数 {safe_func_name} 的伪代码，回退到 radare2")
                return self.decompile_with_radare2(function_name)

            finally:
                if os.path.exists(script_path):
                    os.unlink(script_path)

        except subprocess.TimeoutExpired:
            logger.error(f"[Hopper] 反编译函数 {safe_func_name} 超时")
            return self.decompile_with_radare2(function_name)
        except Exception as e:
            logger.error(f"[Hopper] 反编译过程出错: {e}")
            return self.decompile_with_radare2(function_name)

    def list_functions(self) -> List[str]:
        """
        列出二进制文件中的所有函数
        """
        if not self.available_decompilers.get('radare2', False):
            return []

        try:
            cmd = [
                'r2',
                '-q',
                '-e', 'io.color=false',
                '-c',
                'afl',
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

            if result.returncode == 0:
                functions = []
                libc_prefixes = ('_start', '__libc_csu', '__libc_start', '_init', '_fini', '__gmon', '_dl_')

                for line in result.stdout.strip().split('\n'):
                    line = strip_ansi_escape(line)
                    parts = line.split()
                    if len(parts) >= 3:
                        func_name = parts[-1]

                        if func_name.startswith('sym.'):
                            clean_name = func_name[4:]
                        else:
                            clean_name = func_name

                        if not clean_name.startswith(libc_prefixes):
                            functions.append(clean_name)

                return functions
            return []
        except subprocess.TimeoutExpired:
            logger.warning("获取函数列表超时")
            return []
        except Exception as e:
            logger.error(f"获取函数列表失败: {e}")
            return []

    def call_openai_analysis(
        self,
        pseudocode: str,
        binary_info: Dict[str, Any],
        function_name: str = 'main'
    ) -> Dict[str, Any]:
        """
        调用 OpenAI API 分析反编译代码


        pseudocode: 反编译的伪代码
        binary_info: 二进制文件信息
        function_name: 函数名


        分析结果
        """
        if not self.client:
            logger.warning("未配置 OpenAI 客户端，返回模拟分析结果")
            return self._simulate_analysis(pseudocode, binary_info, function_name)

        try:
            checksec = binary_info.get('checksec', {})
            imports = binary_info.get('imports', {})

            prompt = DECOMP_ANALYSIS_TEMPLATE.format(
                binary_path=self.binary_path,
                function_name=function_name,
                nx=checksec.get('nx', 'Unknown'),
                pie=checksec.get('pie', 'Unknown'),
                relro=checksec.get('relro', 'Unknown'),
                canary=checksec.get('canary', 'Unknown'),
                aslr=checksec.get('aslr', 'Unknown'),
                dangerous_functions='\n'.join(imports.get('dangerous_functions', [])),
                key_strings='\n'.join(binary_info.get('key_strings', [])),
                pseudocode=pseudocode
            )

            logger.info("调用 AI API 进行漏洞分析")

            if logger.level <= logging.DEBUG:
                masked_prompt = mask_sensitive_data(prompt)
                logger.debug(f"[DEBUG] AI 提示词: {masked_prompt}")

            system_message = {"role": "system", "content": AI_SYSTEM_PROMPT_ANALYSIS}
            user_message = {"role": "user", "content": prompt}

            messages = [system_message] + self._get_recent_history() + [user_message]

            result_text = call_ai_with_retry(
                self.client,
                model=get_current_ai_model(),
                messages=messages,
                temperature=AI_TEMPERATURE_ANALYSIS,
                max_tokens=AI_MAX_TOKENS_ANALYSIS
            )

            if result_text and logger.level <= logging.DEBUG:
                masked_response = mask_sensitive_data(result_text)
                logger.debug(f"[DEBUG] AI 返回: {masked_response}")

            if result_text:
                self._add_to_history(user_message, {"role": "assistant", "content": result_text})

            logger.info("AI 分析完成")

            return self._parse_ai_response(result_text)

        except Exception as e:
            logger.error(f"调用 OpenAI API 失败: {e}")
            return self._simulate_analysis(pseudocode, binary_info, function_name)

    def _parse_ai_response(self, response_text: str) -> Dict[str, Any]:
        """
        解析 响应，提取 JSON 内容，增强容错能力
        支持从 ```json 代码块中提取 JSON
        """
        default_result = {
            'raw_response': response_text,
            'vulnerabilities': [],
            'summary': 'AI 响应解析失败，原始响应已保存',
            'risk_level': 'Unknown',
            'parse_error': True
        }

        if not response_text:
            logger.warning("AI 返回空响应")
            return default_result

        json_str = None

        json_block_match = re.search(r'```json\n([\s\S]*?)\n```', response_text)
        if json_block_match:
            json_str = json_block_match.group(1).strip()
            logger.debug("从代码块中提取到 JSON")
        else:
            code_block_match = re.search(r'```\n([\s\S]*?)\n```', response_text)
            if code_block_match:
                block_content = code_block_match.group(1).strip()
                if block_content.startswith('{') or block_content.startswith('['):
                    json_str = block_content
                    logger.debug("从通用代码块中提取到 JSON")

        if not json_str:
            json_match = re.search(r'\{[\s\S]*\}', response_text)
            if json_match:
                json_str = json_match.group()
                logger.debug("从正则匹配中提取到 JSON")

        if json_str:
            json_str = self._try_repair_json(json_str)

            try:
                parsed = json.loads(json_str)

                result = {
                    'raw_response': response_text,
                    'vulnerabilities': parsed.get('vulnerabilities', []),
                    'summary': parsed.get('summary', '未提供摘要'),
                    'risk_level': parsed.get('risk_level', 'Unknown'),
                    'parse_error': False
                }

                if not isinstance(result['vulnerabilities'], list):
                    logger.warning("AI 响应中的 vulnerabilities 不是列表")
                    result['vulnerabilities'] = []

                return result
            except json.JSONDecodeError as e:
                logger.error(f"解析 AI 响应 JSON 失败: {e}")
                logger.debug(f"原始响应片段: {response_text[:500]}")

        logger.warning("AI 响应中未找到有效的 JSON 格式，使用启发式解析")
        summary = self._heuristic_extract_summary(response_text)
        vulnerabilities = self._heuristic_extract_vulnerabilities(response_text)

        return {
            'raw_response': response_text,
            'vulnerabilities': vulnerabilities,
            'summary': summary,
            'risk_level': self._heuristic_detect_risk_level(response_text),
            'parse_error': True,
            'parse_mode': 'heuristic'
        }

    def _try_repair_json(self, json_str: str) -> str:
        """
        尝试修复常见的 JSON 格式错误
        """
        repaired = json_str.strip()

        repaired = re.sub(r'^```\w*\n', '', repaired)
        repaired = re.sub(r'\n```$', '', repaired)
        repaired = repaired.strip()

        trailing_comma_pattern = re.compile(r',\s*([}\]])')
        repaired = trailing_comma_pattern.sub(r'\1', repaired)

        if repaired.count('{') > repaired.count('}'):
            repaired += '}' * (repaired.count('{') - repaired.count('}'))
        elif repaired.count('[') > repaired.count(']'):
            repaired += ']' * (repaired.count('[') - repaired.count(']'))

        in_string = False
        escape_next = False
        result_chars = []
        for char in repaired:
            if escape_next:
                escape_next = False
            elif char == '\\':
                escape_next = True
            elif char == '"':
                in_string = not in_string

            if not in_string:
                if char == "'":
                    char = '"'
            result_chars.append(char)
        repaired = ''.join(result_chars)

        repaired = re.sub(
            r'(?<![\'"])(\w+)(?=\s*:)',
            r'"\1"',
            repaired
        )

        lines = repaired.split('\n')
        cleaned_lines = []
        in_string = False

        for line in lines:
            stripped = line.strip()
            if not in_string and stripped.startswith('//'):
                continue
            if not in_string and '#' in stripped:
                has_quote = '"' in stripped
                if not has_quote:
                    hash_pos = stripped.find('#')
                    if hash_pos > 0:
                        stripped = stripped[:hash_pos]
                        line = line[:line.find('#')]
            cleaned_lines.append(line)

        return '\n'.join(cleaned_lines)

    def _heuristic_extract_summary(self, text: str) -> str:
        """
        从文本中启发式提取摘要
        """
        lines = text.strip().split('\n')
        summary_lines = []

        for line in lines[:10]:
            line = line.strip()
            if line and not line.startswith('```') and not line.startswith('#'):
                summary_lines.append(line)
            if len(summary_lines) >= 3:
                break

        summary = ' '.join(summary_lines)
        return summary[:500] if len(summary) > 500 else summary

    def _heuristic_extract_vulnerabilities(self, text: str) -> List[Dict[str, Any]]:
        """
        从文本中启发式提取漏洞信息
        """
        vulnerabilities = []

        vuln_patterns = [
            r'(?:漏洞|vulnerability)[^\n]*?:[^\n]*',
            r'(?:栈溢出|stack overflow)[^\n]*',
            r'(?:格式化字符串|format string)[^\n]*',
            r'(?:堆溢出|heap overflow)[^\n]*',
            r'(?:使用后释放|use-after-free)[^\n]*',
        ]

        for pattern in vuln_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                vulnerabilities.append({
                    'type': match.strip()[:100],
                    'location': 'Unknown',
                    'description': match.strip(),
                    'severity': 'Medium',
                    'exploitation': '需要进一步分析',
                    'code_snippet': ''
                })

        return vulnerabilities[:5]

    def _heuristic_detect_risk_level(self, text: str) -> str:
        """
        启发式检测风险等级
        """
        text_lower = text.lower()

        if 'critical' in text_lower or '严重' in text_lower:
            return 'Critical'
        elif 'high' in text_lower or '高危' in text_lower:
            return 'High'
        elif 'medium' in text_lower or '中危' in text_lower:
            return 'Medium'
        elif 'low' in text_lower or '低危' in text_lower:
            return 'Low'
        return 'Unknown'

    def _simulate_analysis(
        self,
        pseudocode: str,
        binary_info: Dict[str, Any],
        function_name: str
    ) -> Dict[str, Any]:
        """
        模拟 分析（当没有 API 密钥时使用）


        """
        vulnerabilities = []

        dangerous_funcs = binary_info.get('imports', {}).get('dangerous_functions', [])

        if 'gets' in dangerous_funcs:
            vulnerabilities.append({
                'type': '潜在栈溢出',
                'location': '使用 gets() 函数',
                'description': 'gets() 函数不检查缓冲区大小，可能导致栈溢出',
                'severity': 'Critical',
                'exploitation': '通过超长输入覆盖返回地址',
                'code_snippet': 'gets() 调用'
            })

        if 'strcpy' in dangerous_funcs:
            vulnerabilities.append({
                'type': '潜在栈溢出',
                'location': '使用 strcpy() 函数',
                'description': 'strcpy() 不检查目标缓冲区大小',
                'severity': 'High',
                'exploitation': '通过源字符串覆盖目标缓冲区',
                'code_snippet': 'strcpy() 调用'
            })

        if 'system' in dangerous_funcs:
            vulnerabilities.append({
                'type': '潜在命令注入',
                'location': '使用 system() 函数',
                'description': '如果参数可控，可能导致命令执行',
                'severity': 'Critical',
                'exploitation': '通过注入恶意命令控制程序行为',
                'code_snippet': 'system() 调用'
            })

        if 'scanf' in dangerous_funcs and '%s' in pseudocode:
            vulnerabilities.append({
                'type': '潜在格式化字符串/栈溢出',
                'location': 'scanf() 使用 %s 格式',
                'description': 'scanf("%s", ...) 不检查输入长度',
                'severity': 'High',
                'exploitation': '通过超长输入溢出缓冲区',
                'code_snippet': 'scanf("%s", ...)'
            })

        risk_level = 'Low'
        if any(v.get('severity') == 'Critical' for v in vulnerabilities):
            risk_level = 'Critical'
        elif any(v.get('severity') == 'High' for v in vulnerabilities):
            risk_level = 'High'

        return {
            'function_name': function_name,
            'vulnerabilities': vulnerabilities,
            'summary': f"在函数 {function_name} 中发现 {len(vulnerabilities)} 个潜在漏洞（启发式分析）",
            'risk_level': risk_level,
            'mode': 'simulation'
        }

    def analyze_function(
        self,
        function_name: str,
        binary_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """完整分析一个函数：反编译 + 分析"""
        logger.info(f"开始分析函数: {function_name} (使用 {self.active_decompiler})")

        pre_context = {
            'binary_path': self.binary_path,
            'function_name': function_name,
            'binary_info': binary_info,
            'decompiler': self.active_decompiler
        }
        pre_context = run_hook('pre_analysis', pre_context)

        pre_decompile_context = {
            'binary_path': self.binary_path,
            'function_name': function_name
        }
        pre_decompile_context = run_hook('pre_decompile', pre_decompile_context)

        pseudocode = self.decompile(function_name)

        if not pseudocode:
            logger.warning(f"无法反编译函数 {function_name}，尝试分析汇编")
            pseudocode = f"无法获取 {function_name} 的反编译代码（{self.active_decompiler} 可能不可用）"

        post_decompile_context = {
            'binary_path': self.binary_path,
            'function_name': function_name,
            'pseudocode': pseudocode,
            'decompiler': self.active_decompiler
        }
        post_decompile_context = run_hook('post_decompile', post_decompile_context)
        pseudocode = post_decompile_context.get('pseudocode', pseudocode)

        analysis = self.call_openai_analysis(pseudocode, binary_info, function_name)
        analysis['pseudocode'] = pseudocode
        analysis['decompiler'] = self.active_decompiler

        post_analysis_context = {
            'binary_path': self.binary_path,
            'function_name': function_name,
            'pseudocode': pseudocode,
            'vulnerabilities': analysis.get('vulnerabilities', []),
            'risk_level': analysis.get('risk_level', 'Unknown'),
            'analysis': analysis
        }
        post_analysis_context = run_hook('post_analysis', post_analysis_context)
        if 'analysis' in post_analysis_context:
            analysis = post_analysis_context['analysis']

        return analysis

    def get_available_decompilers(self) -> Dict[str, bool]:
        """获取可用的反编译引擎列表"""
        return self.available_decompilers.copy()

    def get_active_decompiler(self) -> str:
        """获取当前使用的反编译引擎"""
        return self.active_decompiler

    def _add_to_history(self, user_msg: Dict[str, str], assistant_msg: Dict[str, str]) -> None:
        """
        添加消息到对话历史
        """
        self.conversation_history.append(user_msg)
        self.conversation_history.append(assistant_msg)

        while len(self.conversation_history) > self.max_history_messages * 2:
            self.conversation_history.pop(0)

    def _get_recent_history(self) -> List[Dict[str, str]]:
        """
        获取最近的对话历史
        """
        return self.conversation_history[-self.max_history_messages * 2:]

    def clear_conversation_history(self) -> None:
        """
        清空对话历史
        """
        self.conversation_history = []
        logger.info("对话历史已清空")

    def follow_up_analysis(self, question: str) -> Dict[str, Any]:
        """进行多轮对话分析，基于之前的上下文追问问题"""
        if not self.client:
            logger.warning("未配置 OpenAI 客户端，无法进行追问")
            return {'error': '未配置 AI 客户端'}

        if not self.conversation_history:
            logger.warning("没有之前的对话历史，无法进行追问")
            return {'error': '没有对话历史'}

        try:
            logger.info(f"进行追问分析: {question[:100]}...")

            system_message = {"role": "system", "content": AI_SYSTEM_PROMPT_FOLLOW_UP}
            user_message = {"role": "user", "content": question}

            messages = [system_message] + self._get_recent_history() + [user_message]

            if logger.level <= logging.DEBUG:
                masked_question = mask_sensitive_data(question)
                logger.debug(f"[DEBUG] 追问提示词: {masked_question}")

            result_text = call_ai_with_retry(
                self.client,
                model=get_current_ai_model(),
                messages=messages,
                temperature=AI_TEMPERATURE_FOLLOW_UP,
                max_tokens=AI_MAX_TOKENS_FOLLOW_UP
            )

            if result_text and logger.level <= logging.DEBUG:
                masked_response = mask_sensitive_data(result_text)
                logger.debug(f"[DEBUG] 追问返回: {masked_response}")

            if result_text:
                self._add_to_history(user_message, {"role": "assistant", "content": result_text})
                logger.info("追问分析完成")
                return {
                    'response': result_text,
                    'success': True
                }
            else:
                return {
                    'response': 'AI 调用失败',
                    'success': False
                }

        except Exception as e:
            logger.error(f"追问分析失败: {e}")
            return {
                'response': f"分析出错: {e}",
                'success': False
            }
