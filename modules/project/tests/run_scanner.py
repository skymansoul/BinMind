# 扫描调度模块: 对编译好的ELF二进制运行堆溢出检测
# 使用objdump反汇编, 然后喂给HeapOverflowDetector
# 决策: 不依赖pyelftools/capstone等第三方库 (降低依赖),
#   直接解析objdump输出. 若objdump不可用, 备用简单模式匹配
import subprocess, sys, os, re, time, json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 动态导入检测引擎
_ENGINE_AVAILABLE = False
try:
    # 从项目根目录导入
    _sys_path_inserted = str(Path(__file__).resolve().parent.parent)
    if _sys_path_inserted not in sys.path:
        sys.path.insert(0, _sys_path_inserted)
    from analysis import HeapOverflowDetector
    _ENGINE_AVAILABLE = True
except ImportError:
    pass


@dataclass
class ScanResult:
    sample_name: str
    binary_path: str
    success: bool
    findings: List[Dict]
    num_findings: int = 0
    scan_time_ms: float = 0
    disassembly_lines: int = 0
    error_msg: str = ""
    # 标签: 用于回归测试判断
    expected_vulnerable: bool = True
    detected: bool = False
    is_false_positive: bool = False
    is_false_negative: bool = False


class SampleScanner:
    """样本扫描调度器.

    对每个样本:
      1. 用objdump反汇编
      2. 提取函数边界 (可选)
      3. 运行HeapOverflowDetector
      4. 收集发现
    若objdump不可用或检测引擎不可用, 使用备用模式匹配.
    """

    def __init__(self, use_advanced_engine: bool = True):
        self._use_engine = use_advanced_engine and _ENGINE_AVAILABLE
        self._detector = None
        if self._use_engine:
            self._detector = HeapOverflowDetector()

    def disassemble(self, binary_path: str
                     ) -> Optional[Tuple[List[str], List[int], Dict[int, str]]]:
        """用objdump -d反汇编二进制.

        返回 (指令行列表, 地址列表, {指令索引→函数标签名}).
        地址列表与指令行列表索引对应, 用于回跳检测.
        """
        try:
            result = subprocess.run(
                ["objdump", "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                return None
            instr_lines = []
            instr_addrs = []  # 每条指令的地址 (int)
            labels = {}  # 指令索引 → 函数标签名
            pending_label = None
            for line in result.stdout.split('\n'):
                stripped = line.strip()
                # 检测函数标签行: 0000000140001760 <main>:
                label_m = re.match(
                    r'^[0-9a-f]+\s+<([\w@.]+)>:', stripped)
                if label_m:
                    pending_label = label_m.group(1)
                    if '@' in pending_label:
                        pending_label = pending_label.split('@')[0]
                    continue
                if not re.match(r'^[0-9a-f]+:\t', stripped):
                    continue
                # 提取地址: 格式 "ADDR:\tBYTES\tINSTR"
                addr_m = re.match(r'^([0-9a-f]+):\t', stripped)
                addr = int(addr_m.group(1), 16) if addr_m else 0
                tab_parts = stripped.split('\t')
                if len(tab_parts) >= 2:
                    instr_text = tab_parts[-1].strip()
                    if instr_text:
                        if pending_label:
                            labels[len(instr_lines)] = pending_label
                            pending_label = None
                        instr_lines.append(instr_text)
                        instr_addrs.append(addr)
            if not instr_lines:
                for line in result.stdout.split('\n'):
                    stripped = line.strip()
                    if re.match(r'^[0-9a-f]+:\s+', stripped):
                        m = re.match(
                            r'^([0-9a-f]+):\s+'
                            r'(?:[0-9a-f]{2}\s+)+'
                            r'\s*(.+)$', stripped)
                        if m:
                            instr_lines.append(m.group(2))
                            instr_addrs.append(int(m.group(1), 16))
            return ((instr_lines, instr_addrs, labels)
                    if instr_lines else None)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return None

    def extract_function_boundaries(self, lines: List[str],
                                      labels: Dict[int, str] = None
                                    ) -> Dict[str, Tuple[int, int]]:
        """从反汇编中提取函数边界 (基于ret指令 + 符号标签).

        优先使用objdump符号表中的函数名, 若不可用则使用func_NNN.
        标签归属: 取 ret 之前最近的标签 (优化构建中 main 等标签
        可能落在 CRT 函数区间尾部, 取第一个标签会吞掉函数名).
        """
        labels = labels or {}
        funcs = {}
        current_func = "_entry_"
        start = 0
        for i, line in enumerate(lines):
            # 在ret指令处结束当前函数
            if line.strip().startswith('ret'):
                # 查找函数区间内最近的标签 (最后标签优先)
                func_name = current_func
                best_idx = -1
                for lbl_idx, lbl_name in labels.items():
                    if start <= lbl_idx <= i and lbl_idx > best_idx:
                        best_idx = lbl_idx
                        func_name = lbl_name
                if func_name not in funcs:
                    funcs[func_name] = (start, i)
                current_func = f"func_{i}"
                start = i + 1
        if current_func not in funcs and start < len(lines):
            func_name = current_func
            best_idx = -1
            for lbl_idx, lbl_name in labels.items():
                if start <= lbl_idx and lbl_idx > best_idx:
                    best_idx = lbl_idx
                    func_name = lbl_name
            funcs[func_name] = (start, len(lines) - 1)
        return funcs

    def scan_one(self, sample_name: str, binary_path: str,
                 expected_vulnerable: bool = True) -> ScanResult:
        """扫描单个二进制样本."""
        t0 = time.perf_counter()
        try:
            # 反汇编
            disasm_result = self.disassemble(binary_path)
            if disasm_result is None:
                elapsed = (time.perf_counter() - t0) * 1000
                return ScanResult(
                    sample_name=sample_name, binary_path=binary_path,
                    success=False, findings=[], scan_time_ms=elapsed,
                    error_msg="objdump反汇编失败", expected_vulnerable=expected_vulnerable)

            instrs, instr_addrs, labels = disasm_result

            # 函数边界提取
            funcs = self.extract_function_boundaries(instrs, labels)

            # 收集分析结果, 过滤CRT内部函数噪声
            findings_raw = []
            # CRT/内部函数: 这些函数中的发现通常是启动代码副作用, 非用户代码
            _CRT_NOISE_FUNCS = {
                'duplicate_ppstrings', '__do_global_dtors', '__do_global_ctors',
                '__gcc_register_frame', '__gcc_deregister_frame',
                '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
                'atexit', 'check_managed_app', 'safe_flush',
                '__mingw_invalidParameterHandler',
            }
            _CRT_PREFIXES = ('__', '_.', '<')
            _AUTO_FUNC_RE = re.compile(r'^func_\d+$')
            if self._use_engine and self._detector:
                findings = self._detector.analyze(instrs, funcs,
                                                  instr_addrs=instr_addrs)
                for f in findings:
                    # 过滤CRT内部函数噪声:
                    # CRT函数中的低置信度发现是malloc+memcpy启动模式, 非用户代码
                    fname = f.function_name
                    is_crt = (fname in _CRT_NOISE_FUNCS or
                              fname.startswith(_CRT_PREFIXES) or
                              _AUTO_FUNC_RE.match(fname))
                    if is_crt:
                        if f.severity.name in ('INFO', 'LOW'):
                            continue
                    findings_raw.append({
                        "id": f.finding_id,
                        "function": f.function_name,
                        "sink": f.sink_func,
                        "severity": f.severity.name,
                        "confidence": f.confidence,
                        "alloc_site": f.alloc_site_info,
                        "detail": f.overflow_detail,
                        "input_controlled": f.input_controlled,
                        "evidence": f.evidence,
                        "write_size_min": f.write_size_min,
                        "write_size_max": f.write_size_max,
                        "alloc_size_min": f.alloc_size_min,
                        "alloc_size_max": f.alloc_size_max,
                    })
            else:
                # 备用: 简单模式匹配
                findings_raw = self._fallback_scan(instrs)

            elapsed = (time.perf_counter() - t0) * 1000

            # 判断检出状态
            detected = len(findings_raw) > 0
            is_fp = detected and not expected_vulnerable
            is_fn = not detected and expected_vulnerable

            return ScanResult(
                sample_name=sample_name, binary_path=binary_path,
                success=True, findings=findings_raw,
                num_findings=len(findings_raw), scan_time_ms=elapsed,
                disassembly_lines=len(instrs),
                expected_vulnerable=expected_vulnerable,
                detected=detected, is_false_positive=is_fp,
                is_false_negative=is_fn)

        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            return ScanResult(
                sample_name=sample_name, binary_path=binary_path,
                success=False, findings=[], scan_time_ms=elapsed,
                error_msg=str(e), expected_vulnerable=expected_vulnerable)

    def _fallback_scan(self, instrs: List[str]) -> List[Dict]:
        """备用模式匹配: 当高级引擎不可用时."""
        findings = []
        alloced_sizes = {}
        for i, line in enumerate(instrs):
            # 查找malloc调用
            m = re.search(r'mov\s+(?:edi?|rdi),\s*(0x[0-9a-fA-F]+|\d+)', line)
            if m:
                imm = int(m.group(1), 16) if m.group(1).startswith('0x') else int(m.group(1))
                # 后面3行内有call malloc
                for j in range(i, min(i+4, len(instrs))):
                    if 'malloc' in instrs[j].lower() or 'call' in instrs[j].lower():
                        alloced_sizes[j] = imm
                        break
            # 查找危险函数调用
            for sink in ('memcpy', 'memset', 'strcpy', 'strcat'):
                if sink in line.lower() and 'call' in line.lower():
                    # 尝试获取前面的rdx设置
                    for k in range(max(0,i-3), i):
                        m2 = re.search(r'mov\s+(?:edx|rdx),\s*(0x[0-9a-fA-F]+|\d+)', instrs[k])
                        if m2:
                            size = int(m2.group(1), 16) if m2.group(1).startswith('0x') else int(m2.group(1))
                            findings.append({
                                "id": f"fallback_{i}",
                                "function": "unknown",
                                "sink": sink,
                                "severity": "HIGH" if size > 0x100 else "MEDIUM",
                                "confidence": 0.5,
                                "detail": f"备用模式: {sink}写入{size}B",
                            })
                            break
        return findings

    def scan_all(self, binaries: Dict[str, Tuple[str, bool]]
                 ) -> List[ScanResult]:
        """批量扫描.

        binaries: {sample_name: (binary_path, expected_vulnerable)}
        """
        results = []
        for name, (path, vuln) in binaries.items():
            print(f"  Scanning: {name}...", end=" ")
            result = self.scan_one(name, path, vuln)
            status = ("DETECTED" if result.detected else "MISSED") if result.success else "ERROR"
            if result.is_false_positive:
                status = "FALSE_POS"
            print(f"[{status}] {result.num_findings} findings "
                  f"({result.scan_time_ms:.0f}ms)")
            results.append(result)
        return results
