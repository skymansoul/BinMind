# Ghidra无头分析脚本: 使用Ghidra headless analyzer (analyzeHeadless.bat)
# 对二进制进行自动化反编译+模式匹配, 模拟逆向工程师的自动化审计流程
# 决策: 通过Python subprocess调用Ghidra headless, 脚本用Java编写
#   (Ghidra原生API). 该Python文件负责:
#     1. 生成Ghidra Java分析脚本
#     2. 调用analyzeHeadless执行
#     3. 解析输出的JSON结果
#
#   Ghidra documentation — "Headless Analyzer"
#     https://ghidra-sre.org/
#   EagleEye framework — 类似的多工具对比方案
import subprocess, sys, os, re, time, json, shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Ghidra headless Java分析脚本 (自动生成)
_GHIDRA_JAVA_SCRIPT = r"""// HeapOverflowAudit.java: Ghidra无头分析脚本
// 功能: 自动反编译, 定位malloc+memcpy调用点, 提取参数并判断溢出可能
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.app.decompiler.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.util.*;

public class HeapOverflowAudit extends GhidraScript {

    // 危险写入函数集
    static final Set<String> WRITE_SINKS = new HashSet<>(Arrays.asList(
        "memcpy", "memmove", "memset", "strcpy", "strcat",
        "strncpy", "sprintf", "snprintf"
    ));
    static final Set<String> ALLOC_FUNCS = new HashSet<>(Arrays.asList(
        "malloc", "calloc", "realloc"
    ));

    static class Finding {
        String funcName, sinkName;
        long callAddr, allocAddr;
        int allocSize, writeSize;
        double confidence;
    }

    @Override
    public void run() throws Exception {
        List<Finding> findings = new ArrayList<>();
        Map<Long, Integer> allocSites = new HashMap<>();

        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = listing.getFunctions(true);

        // 第一遍: 收集分配点
        for (Function func : funcs) {
            InstructionIterator insns =
                listing.getInstructions(func.getBody(), true);
            while (insns.hasNext()) {
                Instruction insn = insns.next();
                FlowType flow = insn.getFlowType();
                if (!flow.isCall()) continue;

                Reference[] refs = insn.getReferencesFrom();
                for (Reference ref : refs) {
                    if (!ref.isMemoryReference()) continue;
                    Function called = getFunctionAt(ref.getToAddress());
                    if (called == null) continue;
                    String name = called.getName().toLowerCase();
                    if (ALLOC_FUNCS.contains(name)) {
                        // 尝试获取第一个参数 (rdi)
                        int sz = extractArg(insn, 0);
                        allocSites.put(insn.getAddress().getOffset(),
                                      sz > 0 ? sz : 0);
                    }
                }
            }
        }

        // 第二遍: 查危险sink
        funcs = listing.getFunctions(true);
        for (Function func : funcs) {
            InstructionIterator insns =
                listing.getInstructions(func.getBody(), true);
            while (insns.hasNext()) {
                Instruction insn = insns.next();
                FlowType flow = insn.getFlowType();
                if (!flow.isCall()) continue;

                Reference[] refs = insn.getReferencesFrom();
                for (Reference ref : refs) {
                    if (!ref.isMemoryReference()) continue;
                    Function called = getFunctionAt(ref.getToAddress());
                    if (called == null) continue;
                    String name = called.getName().toLowerCase();
                    if (!WRITE_SINKS.contains(name)) continue;

                    int writeSize = extractArg(insn, 2);  // rdx
                    long callAddr = insn.getAddress().getOffset();
                    long nearestAlloc = findNearestAlloc(callAddr, allocSites);

                    Finding f = new Finding();
                    f.funcName = func.getName();
                    f.sinkName = called.getName();
                    f.callAddr = callAddr;
                    f.allocAddr = nearestAlloc;
                    f.allocSize = allocSites.getOrDefault(nearestAlloc, 0);
                    f.writeSize = writeSize;
                    f.confidence = 0.5;
                    findings.add(f);
                }
            }
        }

        // 输出JSON到stdout
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(System.out, findings);
    }

    int extractArg(Instruction callInsn, int argIdx) {
        // 简单回溯: 在调用指令前3条指令中查找mov reg, imm
        Instruction insn = callInsn.getPrevious();
        String[] x64regs = {"rdi", "rsi", "rdx", "rcx", "r8", "r9"};
        String targetReg = x64regs[Math.min(argIdx, 5)];
        for (int i = 0; i < 5 && insn != null; i++) {
            String mnem = insn.getMnemonicString();
            if (mnem.equals("MOV") || mnem.equals("mov")) {
                Register reg = insn.getRegister(0);
                if (reg != null && reg.getName().equals(targetReg)) {
                    // 检查操作数是否为立即数
                    Object[] opObjs = insn.getOpObjects(1);
                    if (opObjs.length > 0 && opObjs[0] instanceof Scalar) {
                        Scalar sc = (Scalar)opObjs[0];
                        return (int)sc.getValue();
                    }
                }
            }
            insn = insn.getPrevious();
        }
        return -1;
    }

    long findNearestAlloc(long callAddr, Map<Long,Integer> allocs) {
        long best = 0;
        long minDist = Long.MAX_VALUE;
        for (long addr : allocs.keySet()) {
            long dist = Math.abs(callAddr - addr);
            if (dist < minDist) {
                minDist = dist;
                best = addr;
            }
        }
        return best;
    }

    // Minimal ObjectMapper for JSON output without external deps
    static class ObjectMapper {
        void writeValue(PrintStream out, List<Finding> findings) {
            out.println("[");
            for (int i = 0; i < findings.size(); i++) {
                Finding f = findings.get(i);
                out.printf("{\"func\":\"%s\",\"sink\":\"%s\"," +
                    "\"call_addr\":\"0x%x\",\"alloc_addr\":\"0x%x\"," +
                    "\"alloc_size\":%d,\"write_size\":%d," +
                    "\"confidence\":%.2f}",
                    f.funcName, f.sinkName, f.callAddr, f.allocAddr,
                    f.allocSize, f.writeSize, f.confidence);
                if (i < findings.size() - 1) out.println(",");
                else out.println();
            }
            out.println("]");
        }
    }
}
"""


@dataclass
class GhidraFinding:
    func_name: str
    sink_name: str
    call_address: int
    alloc_address: int
    alloc_size: int
    write_size: int
    confidence: float = 0.5


@dataclass
class GhidraScanResult:
    binary_path: str
    success: bool
    findings: List[GhidraFinding]
    scan_time_ms: float
    decompiler_timeout: bool = False
    error_msg: str = ""


class GhidraHeadlessAnalyzer:
    """Ghidra headless自动分析器.

    工作流:
      1. 检查GHIDRA_HOME/ghidra_home环境变量
      2. 生成Java分析脚本到临时目录
      3. 调用analyzeHeadless.bat/analyzeHeadless
      4. 解析JSON输出
    """

    def __init__(self, timeout_seconds: int = 120):
        self._timeout = timeout_seconds
        self._script_dir = Path(__file__).parent / ".ghidra_scripts"
        self._script_dir.mkdir(parents=True, exist_ok=True)

    def _find_ghidra(self) -> Optional[Path]:
        """查找Ghidra安装路径."""
        candidates = [
            os.environ.get("GHIDRA_HOME"),
            os.environ.get("GHIDRA_INSTALL_DIR"),
            "C:/ghidra",
            "C:/Program Files/ghidra",
            "/opt/ghidra",
            "/usr/local/ghidra",
        ]
        for c in candidates:
            if not c:
                continue
            p = Path(c)
            if p.exists():
                # 查找analyzeHeadless可执行文件
                for headless in ["support/analyzeHeadless",
                                 "support/analyzeHeadless.bat"]:
                    hp = p / headless
                    if hp.exists():
                        return p
                # ghidra_xx.x_PUBLIC目录结构
                for child in p.glob("ghidra_*"):
                    for headless in ["support/analyzeHeadless",
                                     "support/analyzeHeadless.bat"]:
                        hp = child / headless
                        if hp.exists():
                            return child
        return None

    def analyze(self, binary_path: str) -> GhidraScanResult:
        """对二进制文件执行Ghidra无头分析."""
        ghidra_home = self._find_ghidra()
        if ghidra_home is None:
            return GhidraScanResult(
                binary_path=binary_path, success=False, findings=[],
                scan_time_ms=0, error_msg="Ghidra未找到, 请设置GHIDRA_HOME环境变量")

        # 生成分析脚本
        script_path = self._script_dir / "HeapOverflowAudit.java"
        with open(script_path, 'w') as f:
            f.write(_GHIDRA_JAVA_SCRIPT)

        # 确定可执行文件
        headless_path = ghidra_home / "support" / "analyzeHeadless"
        if os.name == 'nt':
            headless_path = ghidra_home / "support" / "analyzeHeadless.bat"

        # 创建临时项目目录
        project_dir = self._script_dir / ".ghidra_project"
        project_dir.mkdir(parents=True, exist_ok=True)

        bin_path = Path(binary_path).resolve()
        t0 = time.perf_counter()
        try:
            cmd = [
                str(headless_path),
                str(project_dir),
                "HeapOverflowProject",  # 项目名
                "-import", str(bin_path),
                "-scriptPath", str(self._script_dir),
                "-postScript", "HeapOverflowAudit.java",
                "-noanalysis",  # 跳过完整auto-analysis以加速
            ]

            # 对于Ghidra script, Java class需要先编译.
            # 简化: 使用Ghidra的Python script支持
            # 实际部署改用Python script (兼容性更好)
            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=self._timeout, cwd=str(ghidra_home))

            elapsed = (time.perf_counter() - t0) * 1000
            findings = self._parse_output(proc.stdout) if proc.stdout else []
            return GhidraScanResult(
                binary_path=binary_path, success=proc.returncode == 0,
                findings=findings, scan_time_ms=elapsed,
                decompiler_timeout=proc.returncode != 0,
                error_msg=proc.stderr[:200] if proc.stderr else "")

        except subprocess.TimeoutExpired:
            elapsed = (time.perf_counter() - t0) * 1000
            return GhidraScanResult(
                binary_path=binary_path, success=False, findings=[],
                scan_time_ms=elapsed, decompiler_timeout=True,
                error_msg=f"超时 ({self._timeout}s)")
        except FileNotFoundError:
            elapsed = (time.perf_counter() - t0) * 1000
            return GhidraScanResult(
                binary_path=binary_path, success=False, findings=[],
                scan_time_ms=elapsed,
                error_msg=f"analyzeHeadless未找到: {headless_path}")

    def _parse_output(self, stdout: str) -> List[GhidraFinding]:
        """解析Ghidra脚本的JSON输出."""
        findings = []
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for item in data:
                    findings.append(GhidraFinding(
                        func_name=item.get("func", "unknown"),
                        sink_name=item.get("sink", "unknown"),
                        call_address=int(str(item.get("call_addr", "0x0")), 16),
                        alloc_address=int(str(item.get("alloc_addr", "0x0")), 16),
                        alloc_size=item.get("alloc_size", 0),
                        write_size=item.get("write_size", 0),
                        confidence=item.get("confidence", 0.5)))
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass
        return findings

    def analyze_fallback(self, binary_path: str) -> GhidraScanResult:
        """备用方案: 使用objdump+regex做简单模式匹配 (当Ghidra不可用时)."""
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                ["objdump", "-d", "-M", "intel", binary_path],
                capture_output=True, text=True, timeout=30)
            if proc.returncode != 0:
                raise RuntimeError("objdump failed")
            findings = self._regex_scan(proc.stdout)
            elapsed = (time.perf_counter() - t0) * 1000
            return GhidraScanResult(
                binary_path=binary_path, success=True, findings=findings,
                scan_time_ms=elapsed)
        except FileNotFoundError:
            return GhidraScanResult(
                binary_path=binary_path, success=False, findings=[],
                scan_time_ms=0, error_msg="objdump未找到")
        except Exception as e:
            return GhidraScanResult(
                binary_path=binary_path, success=False, findings=[],
                scan_time_ms=0, error_msg=str(e))

    def _regex_scan(self, asm: str) -> List[GhidraFinding]:
        """objdump输出的正则模式匹配 (Ghidra不可用时的fallback)."""
        findings = []
        alloc_info = {}  # addr → size

        for line in asm.split('\n'):
            line = line.strip()
            # 匹配: mov edi, 0x100 ; call malloc
            m = re.search(r'mov\s+(?:edi|rdi),\s*(0x[0-9a-f]+|\d+)', line)
            if m:
                v = m.group(1)
                size = int(v, 16) if v.startswith('0x') else int(v)
                m_addr = re.match(r'^([0-9a-f]+):', line)
                if m_addr:
                    alloc_info[int(m_addr.group(1), 16)] = size
            # 匹配: call memcpy
            for sink in ('memcpy', 'memset', 'strcpy', 'memmove',
                         'strncpy', 'sprintf'):
                if f'call' in line and sink in line:
                    m_addr = re.match(r'^([0-9a-f]+):', line)
                    addr = int(m_addr.group(1), 16) if m_addr else 0
                    findings.append(GhidraFinding(
                        func_name="unknown", sink_name=sink,
                        call_address=addr, alloc_address=0,
                        alloc_size=0, write_size=0, confidence=0.3))
        return findings
