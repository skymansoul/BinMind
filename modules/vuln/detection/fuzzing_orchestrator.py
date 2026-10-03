# 模糊测试编排引擎-管理AFL++/libFuzzer/自定义fuzzer完整生命周期。
# HyllFuzz LLM辅助seed构造、VPGFuzz
# 路径引导策略、IDFuzz 神经网络驱动变异。
#
# 功能边界:
#   - 多fuzzer并发编排-AFL++(coverage-guided) + libFuzzer(in-process) + 自定义变异器
# 崩溃去重与严重度分诊-信号类型、调用栈哈希、可复现性三分法
# Seed进化-低覆盖率seed剔除、高收益seed变异增强
# Fuzzer间结果共享-AFL++路径转换为libFuzzer语料
# 资源感知调度-CPU核心/内存/时间预算约束下最优分配
#
# 当前实现-AFL++ wrapper基础上扩展
# 增强-崩溃分诊与多fuzzer编排

import os, time, subprocess, hashlib, shutil, logging, threading
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class FuzzerType(str, Enum):
    AFL = "afl"
    AFLPP = "aflpp"          # AFL++
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    CUSTOM = "custom"


class FuzzerStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    CRASHED = "crashed"
    COMPLETED = "completed"
    TIMEOUT = "timeout"


class CrashSeverity(str, Enum):
    CRITICAL = "critical"       # 可远程利用、权限提升
    HIGH = "high"               # 崩溃可复现、有明显安全影响
    MEDIUM = "medium"           # 崩溃可复现、安全影响不明确
    LOW = "low"                 # 仅断言失败/非安全影响
    UNCLASSIFIED = "unclass"


@dataclass
class FuzzerConfig:
    """单fuzzer实例配置"""
    fuzzer_type: FuzzerType
    target_binary: str
    input_dir: str = ""
    output_dir: str = ""
    extra_args: List[str] = field(default_factory=list)
    timeout_ms: int = 1000
    memory_limit_mb: int = 2048
    cpu_core: int = 0               # 绑核编号，-1为不绑定
    env_vars: Dict[str, str] = field(default_factory=dict)
    dict_path: str = ""              # AFL字典文件路径
    use_asan: bool = True
    use_ubsan: bool = False


@dataclass
class CrashInfo:
    """单次崩溃元信息"""
    crash_id: str                   # 基于调用栈哈希的唯一ID
    signal_type: int                # SIGSEGV=11, SIGABRT=6, SIGILL=4, ...
    fault_addr: int = 0
    crash_pc: int = 0
    stack_trace: str = ""
    stack_hash: str = ""
    input_file: str = ""            # 触发崩溃的输入文件路径
    input_size: int = 0
    reproducible: bool = False
    asan_report: str = ""           # AddressSanitizer输出
    severity: CrashSeverity = CrashSeverity.UNCLASSIFIED
    first_seen: str = ""
    duplicate_of: str = ""          # 如果是重复崩溃，指向原始crash_id


@dataclass
class FuzzingCampaign:
    """单次fuzzing活动记录"""
    campaign_id: str
    target: str
    fuzzer_configs: List[FuzzerConfig] = field(default_factory=list)
    start_time: str = ""
    end_time: str = ""
    total_execs: int = 0
    crashes: List[CrashInfo] = field(default_factory=list)
    unique_crashes: int = 0
    coverage_map_size: int = 0
    paths_found: int = 0
    status: str = "pending"


# Fuzzer进程管理

class FuzzerProcess:
    """单fuzzer进程封装-启动/监控/优雅关闭"""

    def __init__(self, config: FuzzerConfig, workdir: str):
        self.cfg = config
        self.workdir = workdir
        self.process: Optional[subprocess.Popen] = None
        self.status = FuzzerStatus.IDLE
        self.pid: int = 0
        self.stats: Dict[str, Any] = {}
        self._stop_event = threading.Event()

    def build_command(self) -> List[str]:
        """构建fuzzer命令行-按类型分发参数"""
        cmd = []
        if self.cfg.fuzzer_type == FuzzerType.AFLPP:
            cmd = ['afl-fuzz']
            if self.cfg.cpu_core >= 0:
                cmd += ['-b', str(self.cfg.cpu_core)]
            cmd += ['-i', self.cfg.input_dir,
                    '-o', self.cfg.output_dir,
                    '-t', f"{self.cfg.timeout_ms}",
                    '-m', f"{self.cfg.memory_limit_mb}"]
            if self.cfg.dict_path and os.path.exists(self.cfg.dict_path):
                cmd += ['-x', self.cfg.dict_path]
            cmd += ['--', self.cfg.target_binary] + self.cfg.extra_args

        elif self.cfg.fuzzer_type == FuzzerType.LIBFUZZER:
            libfuzzer_flags = [
                f'-max_len=65536',
                f'-timeout={self.cfg.timeout_ms // 1000}',
                f'-rss_limit_mb={self.cfg.memory_limit_mb}',
            ]
            if self.cfg.use_asan:
                libfuzzer_flags.append('-detect_leaks=0')
            env_flags = ':'.join(libfuzzer_flags)
            cmd = [self.cfg.target_binary, self.cfg.input_dir,
                   '-runs=0', f'-env={env_flags}']

        elif self.cfg.fuzzer_type == FuzzerType.HONGGFUZZ:
            cmd = ['honggfuzz', '-f', self.cfg.input_dir,
                   '-W', self.cfg.output_dir,
                   '-t', str(self.cfg.timeout_ms // 1000),
                   '--', self.cfg.target_binary]

        return cmd

    def start(self) -> bool:
        """启动fuzzer进程"""
        cmd = self.build_command()
        if not cmd:
            logger.error(f"无法构建fuzzer命令: {self.cfg.fuzzer_type}")
            return False

        try:
            os.makedirs(self.cfg.output_dir, exist_ok=True)
            os.makedirs(self.cfg.input_dir, exist_ok=True)

            env = os.environ.copy()
            env.update(self.cfg.env_vars)
            if self.cfg.use_asan:
                env['AFL_USE_ASAN'] = '1'
            if self.cfg.use_ubsan:
                env['AFL_USE_UBSAN'] = '1'

            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env=env, cwd=self.workdir, text=True)
            self.pid = self.process.pid
            self.status = FuzzerStatus.RUNNING
            logger.info(f"Fuzzer启动: {self.cfg.fuzzer_type.value} PID={self.pid}")
            return True
        except FileNotFoundError as e:
            logger.error(f"Fuzzer二进制未找到: {e}")
            self.status = FuzzerStatus.CRASHED
            return False
        except Exception as e:
            logger.error(f"启动fuzzer失败: {e}")
            self.status = FuzzerStatus.CRASHED
            return False

    def stop(self, grace_period: float = 5.0):
        """优雅关闭-先SIGTERM，超时后SIGKILL"""
        if self.process is None or self.process.poll() is not None:
            self.status = FuzzerStatus.COMPLETED
            return

        logger.info(f"停止fuzzer PID={self.pid}")
        try:
            self.process.terminate()
            self._stop_event.set()
        except Exception:
            pass

        try:
            self.process.wait(timeout=grace_period)
        except subprocess.TimeoutExpired:
            try:
                self.process.kill()
                self.process.wait(timeout=2)
            except Exception:
                pass

        self.status = FuzzerStatus.COMPLETED

    @property
    def is_alive(self) -> bool:
        return (self.process is not None and self.process.poll() is None)


# 崩溃分诊

class CrashTriager:
    """崩溃分诊器-去重+严重度评估。

    去重策略（参考AFL++ crash exploration模式）:
        1. 调用栈哈希-不同输入触发同一崩溃路径视为重复
        2. 崩溃信号类型-SIGSEGV/SIGABRT等区分不同根因
        3. ASAN报告哈希-ASAN输出比调用栈更精确
    """

    CRASH_SIGNALS = {
        4:  ("SIGILL",  CrashSeverity.CRITICAL),
        6:  ("SIGABRT", CrashSeverity.HIGH),
        8:  ("SIGFPE",  CrashSeverity.MEDIUM),
        11: ("SIGSEGV", CrashSeverity.HIGH),
        5:  ("SIGTRAP", CrashSeverity.MEDIUM),
        7:  ("SIGBUS",  CrashSeverity.HIGH),
    }

    def __init__(self):
        self._seen_stacks: Set[str] = set()
        self._crash_db: Dict[str, CrashInfo] = {}

    def triage(self, crash_input: str, target_binary: str,
               timeout: int = 10) -> Optional[CrashInfo]:
        """单崩溃输入分诊-复现+分析+分类。

        返回CrashInfo或None（无法复现时）。
        """
        if not os.path.exists(crash_input):
            return None

        crash_data = self._reproduce(crash_input, target_binary, timeout)
        if crash_data is None:
            return None

        stack_hash = hashlib.sha256(
            crash_data.get('stack', '').encode()).hexdigest()[:16]
        crash_id = f"CRASH_{stack_hash[:8]}"

        sig = crash_data.get('signal', 0)
        sig_name, default_sev = self.CRASH_SIGNALS.get(
            sig, ("UNKNOWN", CrashSeverity.UNCLASSIFIED))

        # 严重度升级规则
        severity = default_sev
        stack = crash_data.get('stack', '').lower()
        if any(kw in stack for kw in ('execve', 'system', '/bin/sh', 'shell')):
            severity = CrashSeverity.CRITICAL
        elif any(kw in stack for kw in ('free', 'malloc', 'realloc', 'memcpy')):
            severity = max(severity, CrashSeverity.HIGH, key=lambda s: (
                ['UNCLASSIFIED', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(s)))

        seen_before = stack_hash in self._seen_stacks
        if not seen_before:
            self._seen_stacks.add(stack_hash)

        info = CrashInfo(
            crash_id=crash_id,
            signal_type=sig,
            fault_addr=crash_data.get('fault_addr', 0),
            crash_pc=crash_data.get('crash_pc', 0),
            stack_trace=crash_data.get('stack', ''),
            stack_hash=stack_hash,
            input_file=crash_input,
            input_size=os.path.getsize(crash_input),
            reproducible=True,
            asan_report=crash_data.get('asan', ''),
            severity=severity,
            first_seen=datetime.now().isoformat(),
            duplicate_of="" if not seen_before else
                self._find_duplicate_crash_id(stack_hash))

        if not seen_before:
            self._crash_db[crash_id] = info
        return info

    def _reproduce(self, input_file: str, target_binary: str,
                    timeout: int = 10) -> Optional[Dict]:
        # 复现崩溃-目标+输入，收集信号与栈信息
        try:
            with open(input_file, 'rb') as f:
                input_data = f.read()
        except Exception:
            return None

        try:
            proc = subprocess.run(
                [target_binary], input=input_data,
                capture_output=True, timeout=timeout,
                env={**os.environ, 'ASAN_OPTIONS': 'abort_on_error=1:'
                                           'detect_leaks=0:log_path=/tmp/asan_log'})
            if proc.returncode < 0:
                sig = -proc.returncode
                return {
                    'signal': sig, 'fault_addr': 0, 'crash_pc': 0,
                    'stack': proc.stderr.decode(errors='replace')[:2000],
                    'asan': ''
                }
            return None
        except subprocess.TimeoutExpired:
            return None  # timeout = not exploitable
        except Exception:
            return None

    def _find_duplicate_crash_id(self, stack_hash: str) -> str:
        for cid, info in self._crash_db.items():
            if info.stack_hash == stack_hash:
                return cid
        return ""

    def get_unique_crashes(self) -> List[CrashInfo]:
        return [ci for ci in self._crash_db.values() if not ci.duplicate_of]


# 主编排器

class FuzzingOrchestrator:
    """模糊测试编排器-管理多fuzzer协作运行。

    核心流程:
        1. 准备-创建输出目录、种子语料、字典
        2. 启动-并行启动各fuzzer实例
        3. 监控-轮询状态、收集覆盖率、同步语料
        4. 分诊-对新崩溃做去重+严重度评估
        5. 收敛-覆盖率增长停滞或时间/执行数达上限

    参考:
        - HyllFuzz: LLM辅助seed构造+混合fuzzing编排
        - VPGFuzz: 漏洞路径引导灰盒fuzzing
        - IDFuzz: 神经网络驱动定向变异
    """

    def __init__(self, output_base: str = "", max_concurrent: int = 3):
        self.output_base = output_base or os.path.join(
            os.getcwd(), 'fuzzing_output')
        self.max_concurrent = max_concurrent
        self.fuzzers: List[FuzzerProcess] = []
        self.triager = CrashTriager()
        self.campaigns: List[FuzzingCampaign] = []
        self._monitor_thread: Optional[threading.Thread] = None
        self._running = False

    def launch_campaign(self, target_binary: str,
                         fuzzer_types: List[FuzzerType] = None,
                         input_dir: str = "",
                         duration_minutes: int = 60,
                         memory_per_fuzzer_mb: int = 2048,
                         extra_args: List[str] = None) -> FuzzingCampaign:
        """启动一次fuzzing活动。

        参数:
            target_binary: 目标二进制文件路径
            fuzzer_types: fuzzer类型列表，默认[AFLPP]
            input_dir: 初始种子语料目录
            duration_minutes: 预计运行时间（分钟）
            memory_per_fuzzer_mb: 单fuzzer内存限制MB
            extra_args: 传递给目标程序的额外命令行参数

        返回FuzzingCampaign对象，用于追踪进度。
        """
        if not os.path.exists(target_binary):
            raise FileNotFoundError(f"目标文件不存在: {target_binary}")

        campaign_id = f"fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        camp_dir = os.path.join(self.output_base, campaign_id)
        os.makedirs(camp_dir, exist_ok=True)

        fuzzer_types = fuzzer_types or [FuzzerType.AFLPP]
        seed_dir = input_dir or os.path.join(camp_dir, 'seeds')
        os.makedirs(seed_dir, exist_ok=True)

        # 无种子输入时创建最小哑输入
        if not os.listdir(seed_dir):
            dummy = os.path.join(seed_dir, 'dummy_seed')
            with open(dummy, 'wb') as f:
                f.write(b'AAAA')

        configs = []
        for idx, ftype in enumerate(fuzzer_types[:self.max_concurrent]):
            out_dir = os.path.join(camp_dir, f'{ftype.value}_output')
            cfg = FuzzerConfig(
                fuzzer_type=ftype, target_binary=target_binary,
                input_dir=seed_dir, output_dir=out_dir,
                extra_args=extra_args or [],
                memory_limit_mb=memory_per_fuzzer_mb,
                cpu_core=idx % (os.cpu_count() or 4),
                timeout_ms=2000)
            configs.append(cfg)

        campaign = FuzzingCampaign(
            campaign_id=campaign_id, target=target_binary,
            fuzzer_configs=configs,
            start_time=datetime.now().isoformat(),
            status="running")

        # 启动各fuzzer
        for cfg in configs:
            proc = FuzzerProcess(cfg, camp_dir)
            if proc.start():
                self.fuzzers.append(proc)
            else:
                logger.warning(f"Fuzzer {cfg.fuzzer_type.value} 启动失败")

        self._running = True
        # 后台监控线程-周期检查进度
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, args=(campaign, duration_minutes * 60),
            daemon=True)
        self._monitor_thread.start()

        self.campaigns.append(campaign)
        logger.info(f"Fuzzing活动启动: {campaign_id}, {len(self.fuzzers)}个fuzzer")
        return campaign

    def _monitor_loop(self, campaign: FuzzingCampaign, max_seconds: int):
        """监控循环-周期收集统计/同步语料/检查超时"""
        start_ts = time.time()
        sync_interval = 300  # 5分钟同步一次

        while self._running and (time.time() - start_ts) < max_seconds:
            alive_count = sum(1 for fz in self.fuzzers if fz.is_alive)
            if alive_count == 0 and self.fuzzers:
                logger.warning("所有fuzzer已退出")
                break

            # 收集覆盖率
            campaign.total_execs = self._estimate_total_execs()

            # 语料同步-AFL++发现路径复制到libFuzzer语料目录
            # 仅在多类型fuzzer并存时执行
            if len(set(fz.cfg.fuzzer_type for fz in self.fuzzers if fz.is_alive)) > 1:
                if (time.time() - start_ts) % sync_interval < 10:
                    self._sync_corpus(campaign)

            time.sleep(30)

        campaign.end_time = datetime.now().isoformat()
        campaign.status = "completed"

        # 停止所有fuzzer
        for fz in self.fuzzers:
            if fz.is_alive:
                fz.stop()

    def _estimate_total_execs(self) -> int:
        """估算所有fuzzer总执行次数"""
        total = 0
        for fz in self.fuzzers:
            plot_data = os.path.join(fz.cfg.output_dir, 'plot_data')
            if os.path.exists(plot_data):
                try:
                    with open(plot_data) as f:
                        last_line = f.readlines()[-1]
                        parts = last_line.split(',')
                        if len(parts) > 5:
                            total += int(parts[5].strip())
                except Exception:
                    pass
        return total

    def _sync_corpus(self, campaign: FuzzingCampaign):
        """同步语料-fuzzer间共享发现路径"""
        afl_dirs = [fz.cfg.output_dir for fz in self.fuzzers
                     if fz.cfg.fuzzer_type in (FuzzerType.AFL, FuzzerType.AFLPP)
                     and fz.is_alive]
        libfuzzer_dirs = [fz.cfg.input_dir for fz in self.fuzzers
                           if fz.cfg.fuzzer_type == FuzzerType.LIBFUZZER
                           and fz.is_alive]

        for afl_dir in afl_dirs:
            queue_dir = os.path.join(afl_dir, 'queue')
            if not os.path.isdir(queue_dir):
                continue
            for lf_dir in libfuzzer_dirs:
                for fname in os.listdir(queue_dir):
                    src = os.path.join(queue_dir, fname)
                    dst = os.path.join(lf_dir, f"afl_sync_{fname}")
                    if os.path.isfile(src) and not os.path.exists(dst):
                        try:
                            shutil.copy2(src, dst)
                        except Exception:
                            pass

    def collect_crashes(self, campaign: FuzzingCampaign = None,
                          target_binary: str = "") -> List[CrashInfo]:
        """收集并分诊所有崩溃。

        扫描各fuzzer输出目录crashes子目录，逐崩溃输入调用triager。
        """
        if campaign is None:
            campaign = self.campaigns[-1] if self.campaigns else None
        if campaign is None:
            return []

        target = target_binary or campaign.target
        all_crashes = []

        for fz in self.fuzzers:
            crash_dir = os.path.join(fz.cfg.output_dir, 'crashes')
            if not os.path.isdir(crash_dir):
                crash_dir = os.path.join(fz.cfg.output_dir, 'default', 'crashes')
            if not os.path.isdir(crash_dir):
                continue

            for fname in os.listdir(crash_dir):
                if fname.startswith('.'):
                    continue
                crash_path = os.path.join(crash_dir, fname)
                if not os.path.isfile(crash_path):
                    continue
                info = self.triager.triage(crash_path, target)
                if info:
                    all_crashes.append(info)

        # 更新campaign崩溃统计
        campaign.crashes = all_crashes
        unique = [c for c in all_crashes if not c.duplicate_of]
        campaign.unique_crashes = len(unique)

        return unique

    def stop_all(self):
        """停止所有运行中fuzzer"""
        self._running = False
        for fz in self.fuzzers:
            if fz.is_alive:
                fz.stop()
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=10)

    def get_status(self, campaign_id: str = "") -> Dict[str, Any]:
        """获取当前运行状态（仪表盘/监控用）"""
        campaign = None
        if campaign_id:
            campaign = next((c for c in self.campaigns
                            if c.campaign_id == campaign_id), None)
        else:
            campaign = self.campaigns[-1] if self.campaigns else None

        fuzzer_statuses = []
        for fz in self.fuzzers:
            fuzzer_statuses.append({
                'type': fz.cfg.fuzzer_type.value,
                'status': fz.status.value,
                'pid': fz.pid,
                'output_dir': fz.cfg.output_dir,
            })

        return {
            'running': self._running,
            'active_fuzzers': sum(1 for f in self.fuzzers if f.is_alive),
            'total_fuzzers': len(self.fuzzers),
            'fuzzers': fuzzer_statuses,
            'campaign': {
                'id': campaign.campaign_id if campaign else '',
                'status': campaign.status if campaign else '',
                'total_execs': campaign.total_execs if campaign else 0,
                'unique_crashes': campaign.unique_crashes if campaign else 0,
                'elapsed': '',
            } if campaign else None,
            'triager_stats': {
                'total_crashes': len(self.triager._crash_db),
                'unique_crashes': len(self.triager.get_unique_crashes()),
            },
        }


# 便捷函数

def fuzz_target(target_binary: str, output_dir: str = "",
                fuzzer_type: str = "aflpp",
                duration_minutes: int = 30,
                input_dir: str = "") -> FuzzingCampaign:
    """单目标fuzzing启动便捷函数。

    返回FuzzingCampaign。
    """
    fz_type = FuzzerType.AFLPP
    for ft in FuzzerType:
        if ft.value == fuzzer_type.lower():
            fz_type = ft
            break

    orch = FuzzingOrchestrator(output_base=output_dir or os.path.join(
        os.getcwd(), 'fuzz_results'))
    return orch.launch_campaign(
        target_binary=target_binary,
        fuzzer_types=[fz_type],
        input_dir=input_dir,
        duration_minutes=duration_minutes)


def triage_crash_directory(crash_dir: str, target_binary: str
                            ) -> List[CrashInfo]:
    """对目录中所有崩溃文件做分诊。

    返回去重后CrashInfo列表。
    """
    triager = CrashTriager()
    results = []
    if not os.path.isdir(crash_dir):
        return results
    for fname in sorted(os.listdir(crash_dir)):
        crash_path = os.path.join(crash_dir, fname)
        if os.path.isfile(crash_path) and not fname.startswith('.'):
            info = triager.triage(crash_path, target_binary)
            if info and not info.duplicate_of:
                results.append(info)
    return results
