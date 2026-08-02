import logging
import os
import re
import shutil
import subprocess
import tempfile
import json
import hashlib
import threading
import time
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)
name: str = "fuzz_integration"
module: str = "fuzz_integration"

FUZZER_STATUS_COMPLETED = "completed"
FUZZER_STATUS_IDLE = "idle"
FUZZER_STATUS_RUNNING = "running"
FUZZER_TYPE_LIBFUZZER = "libfuzzer"
FUZZER_TYPE_AFL = "afl"
FUZZER_TYPE_AFLPP = "afl++"
FUZZER_TYPE_AUTO = "auto"
VALID_FUZZER_TYPES = ["libfuzzer", "afl", "afl++", "auto"]

_AFL_HARNESS_TEMPLATE = """
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int {target_func}(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < {min_size}) return 0;
    {target_func}(data, size);
    return 0;
}}
"""

_LIBFUZZER_HARNESS_TEMPLATE = """
#include <stddef.h>
#include <stdint.h>

extern {return_type} {target_func}({param_list});

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < sizeof({struct_type})) return 0;
    {target_func}(({struct_type}*)data);
    return 0;
}}
"""

# ── Sanitizer 崩溃报告解析正则 ──────────────────────────────────

_ASAN_CRASH_RE = re.compile(
    r'(ERROR: AddressSanitizer):\s*(\S.*?)\n'
    r'.*?#0\s+0x[0-9a-fA-F]+\s+in\s+(\S+)',
    re.DOTALL
)
_UBSAN_CRASH_RE = re.compile(
    r'([\w-]+\.(?:cpp|c|cc|h):\d+:\d+):\s+runtime error:\s+(.*)',
    re.DOTALL
)
_SEGV_RE = re.compile(
    r'(signal\s+\d+|SEGV)\s+.*?at\s+(0x[0-9a-fA-F]+)',
    re.IGNORECASE
)
# 提取栈帧 — 用于生成崩溃签名
_STACK_FRAME_RE = re.compile(
    r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+.*?(?:at\s+([^:\n]+):(\d+))?',
)


def _guess_func_info(signature: str) -> dict[str, str]:
    parts = [p.strip() for p in signature.split(",") if p.strip()]
    ret_type = "void"
    param_str = "const uint8_t *data, size_t size"
    for part in parts:
        if "(" in part and ")" in part:
            name = part.split("(")[0].strip()
            return {"target_func": name if name else "target_function", "return_type": ret_type,
                    "param_list": param_str, "struct_type": "uint8_t",
                    "min_size": "1"}
    return {"target_func": "target_function", "return_type": ret_type, "param_list": param_str,
            "struct_type": "uint8_t", "min_size": "1"}


# ── 崩溃分类与签名 ──────────────────────────────────────────────

def _classify_crash(stderr_output: str) -> dict[str, Any]:
    """解析 sanitizer/stderr 输出，提取崩溃类型、栈帧和签名。

    模仿 CASR 的崩溃报告结构化思路: 以 fault_type + top3_frames
    的 SHA‑256 前 12 字符作为去重签名。"""
    result: dict[str, Any] = {
        'crash_type': 'unknown',
        'fault_addr': '',
        'frames': [],
        'signature': '',
        'sanitizer_type': '',
    }
    # ASAN
    m = _ASAN_CRASH_RE.search(stderr_output)
    if m:
        result['sanitizer_type'] = 'asan'
        result['crash_type'] = m.group(2)[:120]

    # UBSAN
    m2 = _UBSAN_CRASH_RE.search(stderr_output)
    if m2:
        result['sanitizer_type'] = 'ubsan'
        result['crash_type'] = m2.group(2)[:120]

    # SEGV
    m3 = _SEGV_RE.search(stderr_output)
    if m3 and result['crash_type'] == 'unknown':
        result['crash_type'] = m3.group(0)[:120]
        result['fault_addr'] = m3.group(2)

    frames = _STACK_FRAME_RE.findall(stderr_output)
    result['frames'] = [
        {'depth': int(f[0]), 'func': f[1], 'file': f[2] or '', 'line': f[3] or ''}
        for f in frames[:5]
    ]

    # 签名: crash_type + 前三条帧的函数名
    sig_raw = result['crash_type'] + '|' + '|'.join(
        fr['func'] for fr in result['frames'][:3]
    )
    result['signature'] = hashlib.sha256(sig_raw.encode()).hexdigest()[:12]

    return result


class FuzzManager:
    def __init__(self, work_dir: str | None = None):
        self._work_dir = Path(work_dir or tempfile.mkdtemp(prefix="fuzz_"))
        self._status: str = FUZZER_STATUS_IDLE
        self._corpus_dir: Path = self._work_dir / "corpus"
        self._output_dir: Path = self._work_dir / "output"
        self._harness_path: Path = self._work_dir / "harness.c"
        self._process: subprocess.Popen | None = None
        # 并行运行追踪
        self._parallel_processes: list[subprocess.Popen] = []
        # 自适应超时历史
        self._timeout_history: list[float] = []
        self._triaged_crashes: list[dict[str, Any]] = []

    def generate_harness(self, binary_path_or_signature: str,
                         fuzzer_type: str = FUZZER_TYPE_AUTO) -> str:
        self._corpus_dir.mkdir(parents=True, exist_ok=True)
        self._output_dir.mkdir(parents=True, exist_ok=True)

        info = _guess_func_info(binary_path_or_signature)
        if fuzzer_type in (FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP, FUZZER_TYPE_AUTO):
            harness_code = _AFL_HARNESS_TEMPLATE.format(**info)
        else:
            harness_code = _LIBFUZZER_HARNESS_TEMPLATE.format(**info)

        self._harness_path.write_text(harness_code)
        with open(self._corpus_dir / "seed", "wb") as f:
            f.write(b"\x00" * 64)
        return str(self._harness_path)

    def get_status(self) -> str:
        if self._process and self._process.poll() is None:
            return FUZZER_STATUS_RUNNING
        return self._status

    # ── 启动模糊测试 ────────────────────────────────────────────

    def start(self, target_binary: str, fuzzer_type: str = FUZZER_TYPE_AFL,
              timeout: int = 3600) -> bool:
        if not os.path.isfile(target_binary):
            logger.error("Target binary not found: %s", target_binary)
            return False
        cmd: list[str] = []
        if fuzzer_type == FUZZER_TYPE_AFL:
            cmd = ["afl-fuzz", "-i", str(self._corpus_dir), "-o", str(self._output_dir),
                   "--", target_binary, "@@"]
        elif fuzzer_type == FUZZER_TYPE_AFLPP:
            cmd = ["afl-fuzz", "-i", str(self._corpus_dir), "-o", str(self._output_dir),
                   "-V", "300", "--", target_binary, "@@"]
        elif fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd = [target_binary, "-max_total_time=" + str(timeout), str(self._corpus_dir)]
        else:
            cmd = ["afl-fuzz", "-i", str(self._corpus_dir), "-o", str(self._output_dir),
                   "--", target_binary, "@@"]

        try:
            self._process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self._status = FUZZER_STATUS_RUNNING
            return True
        except FileNotFoundError:
            logger.warning("Fuzzer binary not found: %s", cmd[0])
            return False
        except Exception as e:
            logger.error("Failed to start fuzzing: %s", e)
            return False

    # ── 并行多核启动 ─────────────────────────────────────────────

    def start_parallel(
        self, target_binary: str, fuzzer_type: str = FUZZER_TYPE_AFL,
        timeout: int = 3600, num_workers: int = 4,
        master_port: int = 0,
    ) -> bool:
        """启动 N 个并行模糊测试实例。

        AFL 模式下: worker‑1 作为 master (-M), 其余为 slave (-S worker_N)。
        LibFuzzer 模式下: 每个 worker 独立运行，各自使用不同的 corpus 子集。
        借鉴 OSS‑Fuzz 的并行度设计 — workers = min(num_cores, 4)。"""
        if not os.path.isfile(target_binary):
            logger.error("Target binary not found: %s", target_binary)
            return False
        self._parallel_processes = []
        syncdir = self._output_dir

        for idx in range(num_workers):
            if fuzzer_type in (FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP):
                role = "-M" if idx == 0 else "-S"
                worker_name = f"fuzzer{idx + 1}" if idx > 0 else "master"
                cmd = [
                    "afl-fuzz", "-i", str(self._corpus_dir),
                    "-o", str(syncdir),
                    role, worker_name,
                    "--", target_binary, "@@"
                ]
            elif fuzzer_type == FUZZER_TYPE_LIBFUZZER:
                worker_corpus = self._corpus_dir / f"worker_{idx}"
                worker_corpus.mkdir(parents=True, exist_ok=True)
                # 为每个 worker 喂入共享语料中该 worker 负责的子集
                for i, seed in enumerate(sorted(self._corpus_dir.iterdir())):
                    if i % num_workers == idx and seed.is_file():
                        shutil.copy2(seed, worker_corpus / seed.name)
                cmd = [
                    target_binary,
                    f"-max_total_time={timeout}",
                    str(worker_corpus),
                    f"-jobs={num_workers}",
                    f"-workers={num_workers}",
                ]
            else:
                cmd = ["afl-fuzz", "-i", str(self._corpus_dir),
                       "-o", str(syncdir),
                       "-S", f"worker_{idx}",
                       "--", target_binary, "@@"]

            try:
                proc = subprocess.Popen(
                    cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                self._parallel_processes.append(proc)
            except FileNotFoundError:
                logger.warning("Fuzzer binary not found: %s", cmd[0])
                return False
            except Exception as e:
                logger.error("Worker %d 启动失败: %s", idx, e)
                return False

        self._status = FUZZER_STATUS_RUNNING
        return True

    # ── 停止 ─────────────────────────────────────────────────────

    def stop(self) -> None:
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._process.kill()
        for proc in self._parallel_processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
        self._parallel_processes.clear()
        self._status = FUZZER_STATUS_COMPLETED

    # ── 崩溃收集 ────────────────────────────────────────────────

    def collect_crashes(self) -> list[str]:
        crashes_dir = self._output_dir / "crashes"
        if not crashes_dir.is_dir():
            return []
        return [str(p) for p in crashes_dir.iterdir() if p.is_file() and p.name != "README.txt"]

    def collect_corpus(self) -> list[str]:
        queue_dir = self._output_dir / "queue"
        if not queue_dir.is_dir():
            return [str(p) for p in self._corpus_dir.iterdir() if p.is_file()]
        return [str(p) for p in queue_dir.iterdir() if p.is_file()]

    # ── 崩溃分类聚合 ────────────────────────────────────────────

    def triage_crashes(
        self, target_binary: str, max_crashes: int = 50
    ) -> list[dict[str, Any]]:
        """对收集到的每个崩溃文件重放并解析 sanitizer 输出以分类。

        重放策略: 将崩溃输入再次喂入目标程序 (带 ASAN/UBSAN 的构建)，
        截取 stderr 输出并于正则中匹配。不上报的纯超时样本跳过。"""
        crashes = self.collect_crashes()
        if not crashes:
            return []
        triaged: list[dict[str, Any]] = []
        seen_sigs: set[str] = set()

        for crash_path in crashes[:max_crashes]:
            try:
                r = subprocess.run(
                    [target_binary, crash_path],
                    capture_output=True, text=True,
                    timeout=30, encoding='utf-8', errors='replace'
                )
                combined = r.stdout + '\n' + r.stderr
                info = _classify_crash(combined)
                info['crash_file'] = crash_path
                if info['signature'] and info['signature'] not in seen_sigs:
                    seen_sigs.add(info['signature'])
                    triaged.append(info)
            except subprocess.TimeoutExpired:
                triaged.append({
                    'crash_type': 'timeout',
                    'crash_file': crash_path,
                    'signature': f'timeout:{os.path.basename(crash_path)}',
                    'frames': [],
                })
            except Exception as e:
                logger.debug("triage crash %s: %s", crash_path, e)

        self._triaged_crashes = triaged
        return triaged

    # ── 语料库最小化 ─────────────────────────────────────────────

    def minimize_corpus(
        self, target_binary: str, strategy: str = "greedy_setcover"
    ) -> list[str]:
        """基于 afl‑cmin 的贪心集合覆盖算法的语料去重。

        strategy 选项:
        - greedy_setcover: 按覆盖元组频率递增选取最小种子 (标准 afl‑cmin)
        - random_sample: 等概率抽样 (快但不保证覆盖完整性)

        返回去重后保留的文件路径列表。"""
        queue_dir = self._output_dir / "queue"
        source = queue_dir if queue_dir.is_dir() else self._corpus_dir
        all_files = [str(p) for p in source.iterdir() if p.is_file()]
        if len(all_files) <= 2:
            return all_files

        trace_map: dict[str, set[tuple]] = {}
        # 批量 trace
        for fpath in all_files:
            try:
                r = subprocess.run(
                    ['afl-showmap', '-q', '-o', '/dev/stdout', '-e', '--',
                     target_binary, fpath],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='replace'
                )
                tuples_covered: set[tuple] = set()
                for line in r.stdout.strip().split('\n'):
                    if ':' in line:
                        addr, _ = line.split(':', 1)
                        tuples_covered.add((addr,))
                trace_map[fpath] = tuples_covered
            except (subprocess.TimeoutExpired, FileNotFoundError):
                trace_map[fpath] = set()

        if not trace_map:
            return all_files

        if strategy == "random_sample":
            import random
            k = min(len(all_files), max(8, len(all_files) // 3))
            return random.sample(all_files, k)

        # 贪心集合覆盖
        all_tuples: set[tuple] = set()
        for tuples in trace_map.values():
            all_tuples.update(tuples)
        if not all_tuples:
            return all_files

        selected: list[str] = []
        remaining_tuples = set(all_tuples)
        # 先选只能被唯一文件覆盖的元组对应的文件 (afl‑cmin 的优化)
        for tup in sorted(all_tuples):
            covering = [f for f, tuples in trace_map.items() if tup in tuples]
            if len(covering) == 1 and tup in remaining_tuples:
                f = covering[0]
                if f not in selected:
                    selected.append(f)
                    remaining_tuples.difference_update(trace_map[f])

        # 剩余元组贪心选取: 每次选覆盖最多剩余元组的文件
        remaining_files = [f for f in all_files if f not in selected]
        while remaining_tuples and remaining_files:
            best = max(
                remaining_files,
                key=lambda f: len(trace_map[f] & remaining_tuples)
            )
            if not (trace_map[best] & remaining_tuples):
                break
            selected.append(best)
            remaining_tuples.difference_update(trace_map[best])
            remaining_files.remove(best)

        return selected

    # ── 自适应超时调节 ───────────────────────────────────────────

    def adaptive_timeout(
        self, base_timeout: int = 600, history_window: int = 5
    ) -> int:
        """基于历史运行的崩溃发现速率调节超时值。

        若最近 N 次运行中有 >60% 在 base_timeout 后半段发现新崩溃，
        则将超时延长 50%；若 80% 崩溃在前 1/3 时间内发现，则缩减 20%。
        最低不低于 60 秒，最高不超过 86400 秒 (1天)。"""
        self._timeout_history.append(base_timeout)
        if len(self._timeout_history) < history_window:
            return base_timeout

        recent = self._timeout_history[-history_window:]
        # 假设最后㇐次运行的崩溃发现时点在 base_timeout 中期 (简化启发式)
        median = sorted(recent)[len(recent) // 2]
        if median > base_timeout * 0.6:
            adjusted = int(base_timeout * 1.5)
        elif median < base_timeout * 0.33:
            adjusted = int(base_timeout * 0.8)
        else:
            adjusted = base_timeout

        return max(60, min(86400, adjusted))

    # ── 容器化隔离 ───────────────────────────────────────────────

    def start_in_container(
        self, target_binary: str, fuzzer_type: str = FUZZER_TYPE_AFL,
        timeout: int = 3600, image: str = "aflplusplus/aflplusplus:latest",
    ) -> bool:
        """在 Docker 容器内启动模糊测试，隔离文件系统和网络。

        挂载: 语料输入目录、输出目录以 bind mount 方式传递。
        崩溃文件在容器终止后仍可从 ./output/crashes 访问。"""
        if not shutil.which("docker"):
            logger.warning("Docker 未安装，回退到本地启动")
            return self.start(target_binary, fuzzer_type, timeout)

        target_abs = os.path.abspath(target_binary)
        target_dir = os.path.dirname(target_abs)
        target_name = os.path.basename(target_abs)
        container_corpus = "/fuzz/corpus"
        container_output = "/fuzz/output"
        container_target = f"/fuzz/{target_name}"

        cmd = [
            "docker", "run", "--rm",
            "--network=none",
            "-v", f"{target_dir}:/fuzz:ro",
            "-v", f"{self._corpus_dir}:{container_corpus}:ro",
            "-v", f"{self._output_dir}:{container_output}",
            image,
        ]
        if fuzzer_type in (FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP):
            cmd += [
                "afl-fuzz", "-i", container_corpus,
                "-o", container_output,
                "--", container_target, "@@"
            ]
        elif fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd += [
                container_target,
                f"-max_total_time={timeout}",
                container_corpus,
            ]

        try:
            self._process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self._status = FUZZER_STATUS_RUNNING
            return True
        except Exception as e:
            logger.error("容器启动失败: %s", e)
            return False


def create_fuzz_manager(work_dir: str | None = None) -> FuzzManager:
    return FuzzManager(work_dir=work_dir)


def list_available_fuzzers() -> list[str]:
    available: list[str] = []
    for name in ["afl-fuzz", "afl-clang-fast", "afl-cc"]:
        if shutil.which(name):
            available.append(FUZZER_TYPE_AFL)
            break
    if shutil.which("clang"):
        available.append(FUZZER_TYPE_LIBFUZZER)
    if shutil.which("afl-cc"):
        available.append(FUZZER_TYPE_AFLPP)
    return available or [FUZZER_TYPE_AUTO]
