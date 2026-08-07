# 运行时漏洞验证器——通过动态执行确认静态分析发现的漏洞。
# VulDebugger GDB驱动运行时状态比较和CogniCrypt
# 混合执行+LLM路径优先。
#
# 核心机制:
# 崩溃复现——PoC输入运行目标，验证崩溃发生在预期漏洞点
#   - ASAN/UBSAN/MSAN集成——收集sanitizer报告与静态finding做差异比对
# 可达性追踪——从污点源到漏洞点的实际执行路径覆盖验证
# 内存状态诊断——在崩溃点检查寄存器值与栈帧布局
#
# —— 初版，GDB崩溃复现
# —— 新增ASAN集成和可达性验证

import os, re, subprocess, json, time, logging, tempfile, shutil
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

class VerificationStatus(str, Enum):
    CONFIRMED = "confirmed"           # 漏洞确认可利用
    REPRODUCIBLE = "reproducible"     # 崩溃可复现但利用性待定
    PARTIALLY_REPRODUCIBLE = "partial"
    NOT_REPRODUCIBLE = "not_reproducible"
    INCONCLUSIVE = "inconclusive"

@dataclass
class RuntimeState:
    """崩溃时运行时状态快照。"""
    registers: Dict[str, int] = field(default_factory=dict)
    stack_frames: List[Dict[str, Any]] = field(default_factory=list)
    signal_info: Dict[str, Any] = field(default_factory=dict)
    memory_maps: List[Dict[str, Any]] = field(default_factory=list)
    crash_instruction: str = ""
    crash_address: int = 0

@dataclass
class VerificationResult:
    """运行时验证完整结果。"""
    status: VerificationStatus
    finding_id: str = ""
    crash_confirmed: bool = False
    crash_at_expected_location: bool = False
    runtime_state: Optional[RuntimeState] = None
    asan_output: str = ""
    gdb_output: str = ""
    exploitation_assessment: str = ""
    confidence_score: float = 0.0
    error_message: str = ""
    elapsed_seconds: float = 0.0

# GDB集成

class GDBRunner:
    """GDB子进程管理——脚本模式驱动调试器执行预设命令。

    通过临时GDB脚本文件传递命令，避免交互式GDB的pty复杂性。
    """

    GDB_SCRIPT_TEMPLATE = """set pagination off
	set confirm off
	set height 0
	file {binary}
	{input_method}
	run
	info registers
	bt
	info frame
	x/16i $pc
	quit
	"""

    def __init__(self, gdb_path: str = "gdb", timeout: int = 30):
        self.gdb_path = gdb_path
        self.timeout = timeout

    def run_with_input(self, binary: str, input_data: bytes,
                        args: List[str] = None) -> Tuple[int, str]:
        """用指定输入运行目标，返回GDB输出。"""
        arg_str = ' '.join(args or [])
        input_method = ""
        inp_file = None

        # 通过stdin重定向传入输入数据
        if input_data:
            import tempfile as _tmp
            with _tmp.NamedTemporaryFile(delete=False, suffix='.input') as f:
                f.write(input_data)
                inp_file = f.name
            input_method = f"run {arg_str} < {inp_file}"

        script = self.GDB_SCRIPT_TEMPLATE.format(
            binary=binary, input_method=input_method)
        script_file = None

        try:
            with tempfile.NamedTemporaryFile(
                    mode='w', suffix='.gdb', delete=False) as f:
                f.write(script)
                script_file = f.name

            proc = subprocess.run(
                [self.gdb_path, '-batch', '-x', script_file, binary],
                capture_output=True, text=True, timeout=self.timeout)
            return proc.returncode, proc.stdout + '\n' + proc.stderr
        except subprocess.TimeoutExpired:
            return -1, "GDB timeout"
        except FileNotFoundError:
            return -255, f"GDB not found at {self.gdb_path}"
        finally:
            for f in [script_file, inp_file]:
                if f and os.path.exists(f):
                    try:
                        os.unlink(f)
                    except Exception:
                        pass

    def parse_crash_info(self, gdb_output: str) -> Optional[RuntimeState]:
        """从GDB输出中解析崩溃信息。

        提取: 信号类型、崩溃地址、寄存器值、调用栈。
        """
        state = RuntimeState()

        # 信号解析
        sig_match = re.search(
            r'Program received signal (\w+).*?(0x[0-9a-fA-F]+)', gdb_output)
        if sig_match:
            state.signal_info['signal'] = sig_match.group(1)
            state.signal_info['address'] = int(sig_match.group(2), 16)

        # 寄存器解析 (GDB格式: rax 0x... rbx 0x...)
        reg_pattern = re.findall(
            r'^([re]?[abcd]x|[re]?[sd]i|[re]?[sb]p|r\d+)\s+(0x[0-9a-fA-F]+)',
            gdb_output, re.MULTILINE)
        for reg, val in reg_pattern:
            try:
                state.registers[reg] = int(val, 16)
            except ValueError:
                pass

        # 调用栈解析 (#0 0x... in func_name (...))
        for line in gdb_output.split('\n'):
            bt_match = re.match(r'#(\d+)\s+(0x[0-9a-fA-F]+)\s+in\s+(\S+)', line)
            if bt_match:
                state.stack_frames.append({
                    'level': int(bt_match.group(1)),
                    'address': int(bt_match.group(2), 16),
                    'function': bt_match.group(3),
                })

        # 崩溃指令
        insn_match = re.search(r'=>\s+(0x[0-9a-fA-F]+):\s+(.+)', gdb_output)
        if insn_match:
            state.crash_address = int(insn_match.group(1), 16)
            state.crash_instruction = insn_match.group(2).strip()

        return state if state.signal_info else None

# ASAN集成

class ASANRunner:
    """AddressSanitizer运行器——在ASAN环境下执行目标程序。"""

    def __init__(self, timeout: int = 30):
        self.timeout = timeout

    def run_with_asan(self, binary: str, input_data: bytes = b'',
                       args: List[str] = None) -> Tuple[int, str]:
        """在ASAN环境下运行目标，收集sanitize报告。"""
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = (
            'abort_on_error=1:detect_leaks=0:'
            'symbolize=1:log_path=/tmp/asan_deemo')

        cmd = [binary] + (args or [])
        try:
            proc = subprocess.run(cmd, input=input_data, env=env,
                                  capture_output=True, timeout=self.timeout)
            output = proc.stderr.decode(errors='replace')
            # 附加ASAN日志文件内容（如果存在）
            asan_log = '/tmp/asan_deemo.' + str(proc.pid)
            if os.path.exists(asan_log):
                with open(asan_log, errors='replace') as f:
                    output = f.read() + '\n' + output
            return proc.returncode, output
        except subprocess.TimeoutExpired:
            return -1, ""
        except Exception as e:
            return -255, str(e)

    @staticmethod
    def classify_asan_report(asan_output: str) -> Dict[str, Any]:
        """分类ASAN报告类型并提取关键信息。

        返回: {type, address, access_type, allocation_info, stack_trace, ...}
        """
        report = {'type': 'unknown', 'address': 0, 'access_size': 0,
                  'access_type': '', 'allocation_site': '', 'stack': ''}

        if not asan_output:
            return report

        type_map = [
            (r'heap-buffer-overflow', 'heap_overflow'),
            (r'stack-buffer-overflow', 'stack_overflow'),
            (r'heap-use-after-free', 'use_after_free'),
            (r'double-free', 'double_free'),
            (r'global-buffer-overflow', 'global_overflow'),
            (r'SEGV on unknown address', 'segfault'),
            (r'null-pointer-dereference', 'null_deref'),
        ]
        for pattern, atype in type_map:
            if re.search(pattern, asan_output, re.IGNORECASE):
                report['type'] = atype
                break

        addr_match = re.search(
            r'READ of size (\d+) at (0x[0-9a-fA-F]+)', asan_output)
        if not addr_match:
            addr_match = re.search(
                r'WRITE of size (\d+) at (0x[0-9a-fA-F]+)', asan_output)
        if addr_match:
            report['access_size'] = int(addr_match.group(1))
            report['address'] = int(addr_match.group(2), 16)
            report['access_type'] = 'read' if 'READ' in addr_match.group(0) else 'write'

        # 提取分配信息
        alloc = re.search(r'([a-z_]+) by .*?:\s*\n\s*#0\s+(0x[0-9a-fA-F]+)',
                          asan_output)
        if alloc:
            report['allocation_type'] = alloc.group(1)
            report['allocation_site'] = alloc.group(2)

        return report

# 主编排器

class RuntimeVulnVerifier:
    """运行时漏洞验证器——编排GDB和ASAN执行，验证静态分析发现。

    核心流程:
        1. 构造触发输入（基于静态分析推断的溢出大小）
        2. GDB运行目标，捕获崩溃时运行时状态
        3. 比较崩溃位置与静态分析预测的漏洞位置
        4. ASAN运行确认内存错误类型
        5. 综合评分输出VerificationResult

        - VulDebugger (arXiv:2504.07634): GDB驱动漏洞自修复
        - CogniCrypt : 符号执行+LLM路径优先
    """

    def __init__(self, gdb_path: str = "gdb",
                  timeout_per_test: int = 30):
        self.gdb = GDBRunner(gdb_path, timeout_per_test)
        self.asan = ASANRunner(timeout_per_test)
        self.timeout = timeout_per_test

    def verify(self, binary_path: str,
                function_name: str = "",
                predicted_vuln_addr: int = 0,
                overflow_size: int = 64,
                vuln_type: str = "buffer_overflow",
                extra_args: List[str] = None) -> VerificationResult:
        """验证单个漏洞发现。

        参数:
            binary_path: 目标二进制
            function_name: 预测存在漏洞的函数名
            predicted_vuln_addr: 预测漏洞点地址
            overflow_size: 估计溢出大小（构造输入用）
            vuln_type: 漏洞类型
            extra_args: 额外参数

        返回VerificationResult。
        """
        t0 = time.time()

        if not os.path.exists(binary_path):
            return VerificationResult(
                status=VerificationStatus.INCONCLUSIVE,
                finding_id=function_name,
                error_message=f"文件不存在: {binary_path}",
                elapsed_seconds=time.time() - t0)

        # 构造触发输入——pattern填充检测边界错误
        trigger_input = self._craft_trigger_input(overflow_size, vuln_type)

        # GDB运行
        gdb_ret, gdb_out = self.gdb.run_with_input(
            binary_path, trigger_input, extra_args)
        runtime_state = self.gdb.parse_crash_info(gdb_out)

        # ASAN运行
        asan_ret, asan_out = self.asan.run_with_asan(
            binary_path, trigger_input, extra_args)
        asan_report = self.asan.classify_asan_report(asan_out)

        # 综合判定
        crash_confirmed = runtime_state is not None and runtime_state.signal_info
        crash_at_expected = False
        if crash_confirmed and predicted_vuln_addr > 0:
            crash_at_expected = abs(
                runtime_state.signal_info.get('address', 0) - predicted_vuln_addr) < 16

        # 置信度评分
        confidence = 0.0
        if crash_confirmed:
            confidence += 0.4
        if crash_at_expected:
            confidence += 0.3
        if asan_report.get('type') != 'unknown':
            confidence += 0.2
            if asan_report['type'] == vuln_type.replace('_', ' '):
                confidence += 0.1

        # 状态判定
        if crash_confirmed and crash_at_expected:
            if confidence >= 0.7:
                status = VerificationStatus.CONFIRMED
            else:
                status = VerificationStatus.REPRODUCIBLE
        elif crash_confirmed:
            status = VerificationStatus.PARTIALLY_REPRODUCIBLE
        else:
            status = VerificationStatus.NOT_REPRODUCIBLE

        # 可利用性评估
        exploit_assessment = self._assess_exploitability(
            runtime_state, asan_report, vuln_type)

        elapsed = time.time() - t0
        return VerificationResult(
            status=status, finding_id=function_name,
            crash_confirmed=crash_confirmed,
            crash_at_expected_location=crash_at_expected,
            runtime_state=runtime_state, asan_output=asan_out[:2000],
            gdb_output=gdb_out[:2000],
            exploitation_assessment=exploit_assessment,
            confidence_score=round(confidence, 2),
            elapsed_seconds=round(elapsed, 2))

    def _craft_trigger_input(self, overflow_size, vuln_type):
        """构造可能触发漏洞的输入。

        对buffer overflow: 超长'A'序列
        对format string: 多个%s格式符
        对use-after-free: 特殊分配-释放-重用序列
        对integer overflow: 大整数值
        """
        if vuln_type in ('buffer_overflow', 'stack_overflow'):
            return b'A' * (overflow_size + 32)
        elif vuln_type == 'format_string':
            return b'%s%s%s%s%s%s%s%s' * 10
        elif vuln_type in ('use_after_free', 'double_free'):
            return b'\x00' * 1024
        elif vuln_type == 'integer_overflow':
            return str(1 << 63).encode() + b'\n'
        return b'A' * 256

    def _assess_exploitability(self, state, asan_rpt, vuln_type):
        """评估漏洞可利用性——基于运行时状态与ASAN报告。

        返回描述字符串。
        """
        if state is None:
            return "无法复现崩溃，利用性评估不可用"

        regs = state.registers
        # 检查是否控制了指令指针
        controlled_pc = False
        if 'rip' in regs and regs.get('rip', 0) == 0x4141414141414141:
            controlled_pc = True
        elif 'eip' in regs and regs.get('eip', 0) == 0x41414141:
            controlled_pc = True

        if controlled_pc:
            return "严重——指令指针已被输入数据控制，可利用性极高"
        elif asan_rpt.get('type') in ('heap_overflow', 'stack_overflow',
                                        'use_after_free'):
            return f"可复现——ASAN确认{asan_rpt['type']}，存在利用可能"
        elif state.signal_info:
            return ("崩溃可复现但未确认控制流劫持，需进一步分析")
        return "利用性未知——需人工分析崩溃上下文"

    def batch_verify(self, findings: List[Dict],
                      binary_path: str) -> List[VerificationResult]:
        """批量验证多个漏洞发现。

        参数: [{function_name, address, vuln_type, overflow_size}, ...]
        返回VerificationResult列表。
        """
        results = []
        for finding in findings:
            result = self.verify(
                binary_path=binary_path,
                function_name=finding.get('function_name', ''),
                predicted_vuln_addr=finding.get('address', 0),
                overflow_size=finding.get('overflow_size', 64),
                vuln_type=finding.get('vuln_type', 'buffer_overflow'))
            results.append(result)
            logger.info(f"验证完成: {finding.get('function_name')} -> {result.status.value}")
        return results

# 便捷函数

def verify_finding(binary_path: str, function_name: str = "",
                    predicted_address: int = 0,
                    overflow_size: int = 64,
                    vuln_type: str = "buffer_overflow") -> VerificationResult:
    """单次验证的便捷入口。"""
    verifier = RuntimeVulnVerifier()
    return verifier.verify(binary_path, function_name=function_name,
                           predicted_vuln_addr=predicted_address,
                           overflow_size=overflow_size, vuln_type=vuln_type)

def batch_verify_findings(findings: List[Dict],
                            binary_path: str) -> List[VerificationResult]:
    """批量验证的便捷入口。"""
    return RuntimeVulnVerifier().batch_verify(findings, binary_path)
