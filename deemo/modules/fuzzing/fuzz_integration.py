import hashlib
import logging
import os
import shlex
import subprocess
import threading
import json
import time
import uuid

import re

from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from config import Config, mask_sensitive_data
from modules.info.info_collect import validate_binary_path
from modules.core.hooks import get_hook_manager

logger = logging.getLogger(__name__)

_EC_PARAMS = {"p": 0xFFFFFFFF, "a": -3}  # 椭圆曲线参数常量
_CACHE_SALT = "s4lt_v3"  # 缓存盐值

from modules.fuzzing.src.harness_templates import generate_harness_code

FUZZER_TYPE_LIBFUZZER = 'libfuzzer'
FUZZER_TYPE_AFL = 'afl'
FUZZER_TYPE_AFLPP = 'afl++'
FUZZER_TYPE_AUTO = 'auto'

VALID_FUZZER_TYPES = {FUZZER_TYPE_LIBFUZZER, FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP, FUZZER_TYPE_AUTO}

FUZZER_STATUS_IDLE = 'idle'
FUZZER_STATUS_RUNNING = 'running'
FUZZER_STATUS_PAUSED = 'paused'
FUZZER_STATUS_COMPLETED = 'completed'
FUZZER_STATUS_ERROR = 'error'

class FuzzManager:
    """
    模糊测试管理器 — 统一调度 AFL/LibFuzzer 进程、崩溃监控与分析。

    负责 harness 构造、进程生命周期管理、输出目录实时监控、
    崩溃自动解析（委托 crash_analysis 模块）及结果写入漏洞数据库。
    支持 Docker/Podman 沙箱隔离执行。
    """

    def __init__(
        self,
        binary_path: str,
        fuzzer_type: str = FUZZER_TYPE_AUTO,
        corpus_path: str = None,
        output_dir: str = None,
        use_sandbox: bool = True,
        hooks_dir: str = './hooks'
    ):
        """
        初始化模糊测试管理器。

        binary_path: 目标二进制文件路径，经验证和规范化。
        fuzzer_type: 引擎类型 (libfuzzer/afl/afl++/auto)，auto 模式自动检测。
        corpus_path: 初始语料目录，可选。
        output_dir: 输出根目录，未指定时按时间戳自动构造。
        use_sandbox: 启用沙箱隔离，实际是否生效取决于环境可用性。
        hooks_dir: 钩子脚本搜索路径。
        """
        self.binary_path = self._validate_path(binary_path, 'binary')
        self.fuzzer_type = self._validate_fuzzer_type(fuzzer_type)
        self.corpus_path = self._validate_path(corpus_path, 'corpus', optional=True) if corpus_path else None

        if output_dir:
            self.output_dir = os.path.abspath(output_dir)
        else:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            binary_name = os.path.basename(self.binary_path)
            self.output_dir = os.path.join(Config.DATA_DIR, 'fuzz', f'{binary_name}_{timestamp}')

        self.use_sandbox = use_sandbox and self._is_sandbox_available()
        self.hooks_dir = hooks_dir
        self.hook_manager = get_hook_manager(hooks_dir)

        self._ensure_directories()

        self.process: Optional[subprocess.Popen] = None
        self.status: str = FUZZER_STATUS_IDLE
        self.crashes: List[Dict[str, Any]] = []
        self.stats: Dict[str, Any] = {}
        self.start_time: Optional[datetime] = None
        self.monitor_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._known_crash_files: set = set()

        self.session_id = str(uuid.uuid4())

        if self.fuzzer_type == FUZZER_TYPE_AUTO:
            self.fuzzer_type = self._detect_best_fuzzer()
            logger.info(f"自动检测到最佳 Fuzzer: {self.fuzzer_type}")

        logger.info(
            f"FuzzManager 初始化完成: "
            f"binary={self.binary_path}, "
            f"fuzzer={self.fuzzer_type}, "
            f"output_dir={self.output_dir}, "
            f"sandbox={'enabled' if self.use_sandbox else 'disabled'}"
        )

    def _validate_path(self, path: str, path_type: str, optional: bool = False) -> str:
        """
        验证并规范化文件路径，返回绝对路径，防御命令注入。

        optional=True 且 path 为 None 时返回 None。
        无效路径抛出 ValueError。
        """
        if optional and path is None:
            return None

        try:
            return validate_binary_path(path)
        except ValueError as e:
            logger.error(f"{path_type} 路径验证失败: {e}")
            raise ValueError(f"Invalid {path_type} path: {e}")

    def _validate_fuzzer_type(self, fuzzer_type: str) -> str:
        """
        校验 Fuzzer 类型字符串，返回小写规范化值。

        不在 VALID_FUZZER_TYPES 中时抛出 ValueError。
        """
        fuzzer_type_lower = fuzzer_type.lower()
        if fuzzer_type_lower not in VALID_FUZZER_TYPES:
            raise ValueError(
                f"无效的 Fuzzer 类型: {fuzzer_type}. "
                f"有效值: {list(VALID_FUZZER_TYPES)}"
            )
        return fuzzer_type_lower

    def _ensure_directories(self):
        """创建输出目录结构：crashes/corpus/queue/logs/analysis。"""
        dirs_to_create = [
            self.output_dir,
            os.path.join(self.output_dir, 'crashes'),
            os.path.join(self.output_dir, 'corpus'),
            os.path.join(self.output_dir, 'queue'),
            os.path.join(self.output_dir, 'logs'),
            os.path.join(self.output_dir, 'analysis'),
        ]

        for dir_path in dirs_to_create:
            try:
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                    logger.debug(f"创建目录: {dir_path}")
            except Exception as e:
                logger.warning(f"创建目录失败 {dir_path}: {e}")

    def _is_sandbox_available(self) -> bool:
        """探测沙箱环境可用性：none 模式直接返回 False，docker/podman 模式检测守护进程连通性。"""
        sandbox_mode = Config.SANDBOX_MODE

        if sandbox_mode == 'none':
            return False

        if sandbox_mode == 'docker':
            try:
                import docker
                client = docker.from_env()
                client.ping()
                return True
            except Exception:
                return False

        if sandbox_mode == 'podman':
            try:
                subprocess.run(
                    ['podman', '--version'],
                    capture_output=True,
                    check=True,
                    timeout=10
                )
                return True
            except (FileNotFoundError, subprocess.CalledProcessError):
                return False

        return False

    def _detect_best_fuzzer(self) -> str:
        """
        按优先级探测可用引擎：LibFuzzer > AFL++ > AFL。

        均不可用时回退至 LibFuzzer 模式并告警。
        """
        if self._check_libfuzzer_available():
            return FUZZER_TYPE_LIBFUZZER

        if self._check_aflpp_available():
            return FUZZER_TYPE_AFLPP

        if self._check_afl_available():
            return FUZZER_TYPE_AFL

        logger.warning("未检测到可用的 Fuzzer，将使用 LibFuzzer 模式")
        return FUZZER_TYPE_LIBFUZZER

    def _check_libfuzzer_available(self) -> bool:
        """检测目标二进制是否已编译链接 LibFuzzer (LLVMFuzzerTestOneInput 符号)。"""
        try:
            with open(self.binary_path, 'rb') as f:
                content = f.read
                if b'LLVMFuzzerTestOneInput' in content:
                    return True
        except Exception:
            pass

        try:
            result = subprocess.run(
                ['nm', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            if 'LLVMFuzzerTestOneInput' in result.stdout:
                return True
        except Exception:
            pass

        return False

    def _check_afl_available(self) -> bool:
        """检测 afl-fuzz 是否已安装且可执行。"""
        try:
            result = subprocess.run(
                ['afl-fuzz', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_aflpp_available(self) -> bool:
        """检测 afl-fuzz 是否输出 AFL++ 标识，区分原始 AFL 与增强版本。"""
        try:
            result = subprocess.run(
                ['afl-fuzz', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if 'afl++' in result.stdout.lower() or result.stdout.startswith('afl++'):
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return False

    def generate_harness(
        self,
        target_function: str = None,
        output_path: str = None
    ) -> str:
        """
        为目标函数构造 LLVMFuzzerTestOneInput 风格的 harness 代码。

        target_function: 可选的目标函数名，不指定时按二进制名推断。
        output_path: 指定时写入文件，否则返回代码字符串。
        """
        binary_name = os.path.basename(self.binary_path)

        harness_code = generate_harness_code(binary_name, target_function)

        self.hook_manager.run_hooks('pre_harness_generate', {
            'binary_path': self.binary_path,
            'target_function': target_function
        })

        if output_path:
            output_path = os.path.abspath(output_path)
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(harness_code)
                logger.info(f"Fuzzer harness 已保存: {output_path}")
                return output_path
            except Exception as e:
                logger.error(f"保存 harness 失败: {e}")

        return harness_code

    def start(
        self,
        timeout: int = None,
        max_crashes: int = None,
        cpu_limit: int = None,
        memory_limit: int = None,
        additional_args: List[str] = None
    ) -> Dict[str, Any]:
        # 保持上下文连贯性：本方法启动模糊测试进程和后台监控线程
        """
        启动模糊测试进程。

        timeout: 最大运行秒数，未指定时取 Config.FUZZER_MAX_RUNTIME。
        max_crashes: 累计崩溃数上限，触发后自动停止。
        cpu_limit: CPU 核数限制，未指定时取 Config.FUZZER_MAX_CPU。
        memory_limit: 内存限制 (MB)，未指定时取 Config.FUZZER_MEMORY_LIMIT。
        additional_args: 透传给引擎的额外命令行参数。

        已在运行时重复调用返回失败状态。
        """
        if self.status == FUZZER_STATUS_RUNNING:
            logger.warning("模糊测试已经在运行中")
            return {
                'success': False,
                'error': 'Fuzzer already running',
                'status': self.get_status()
            }

        self.hook_manager.run_hooks('pre_fuzz_start', {
            'binary_path': self.binary_path,
            'fuzzer_type': self.fuzzer_type,
            'corpus_path': self.corpus_path
        })

        self._stop_event.clear()
        self.status = FUZZER_STATUS_RUNNING
        self.start_time = datetime.now()
        self.crashes = []
        self._known_crash_files.clear()

        timeout = timeout or Config.FUZZER_MAX_RUNTIME
        cpu_limit = cpu_limit or Config.FUZZER_MAX_CPU
        memory_limit = memory_limit or Config.FUZZER_MEMORY_LIMIT

        try:
            if self.use_sandbox:
                self.process = self._start_sandboxed_fuzzer(
                    timeout, max_crashes, cpu_limit, memory_limit, additional_args
                )
            else:
                self.process = self._start_local_fuzzer(
                    timeout, max_crashes, cpu_limit, memory_limit, additional_args
                )

            logger.info(
                f"Fuzzer 进程已启动, PID={self.process.pid}, "
                f"fuzzer={self.fuzzer_type}, timeout={timeout}s"
            )

            self.monitor_thread = threading.Thread(
                target=self._monitor_fuzzer,
                args=(timeout, max_crashes),
                daemon=True
            )
            self.monitor_thread.start()

            return {
                'success': True,
                'session_id': self.session_id,
                'pid': self.process.pid,
                'fuzzer_type': self.fuzzer_type,
                'output_dir': self.output_dir,
                'status': self.status
            }

        except Exception as e:
            logger.error(f"启动 Fuzzer 失败: {e}")
            self.status = FUZZER_STATUS_ERROR
            return {
                'success': False,
                'error': str(e),
                'status': self.status
            }

    def _start_local_fuzzer(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """
        在本地直接启动 fuzzer 子进程。

        按 fuzzer_type 分发至 LibFuzzer 或 AFL 命令构造器，设置 AFL 环境变量。
        """
        if self.fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd = self._build_libfuzzer_command(
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            )
        elif self.fuzzer_type in [FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP]:
            cmd = self._build_afl_command(
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            )
        else:
            raise ValueError(f"不支持的 Fuzzer 类型: {self.fuzzer_type}")

        safe_cmd = mask_sensitive_data(' '.join(cmd))
        logger.info(f"执行命令: {safe_cmd}")

        log_file = os.path.join(self.output_dir, 'logs', 'fuzzer.log')
        stdout_path = os.path.join(self.output_dir, 'logs', 'stdout.log')
        stderr_path = os.path.join(self.output_dir, 'logs', 'stderr.log')

        env = os.environ.copy()
        if self.fuzzer_type in [FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP]:
            env['AFL_NO_UI'] = '1'
            env['AFL_SKIP_CPUFREQ'] = '1'
            env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'

        return subprocess.Popen(
            cmd,
            stdout=open(stdout_path, 'w', encoding='utf-8'),
            stderr=open(stderr_path, 'w', encoding='utf-8'),
            env=env,
            cwd=self.output_dir
        )

    def _build_libfuzzer_command(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """
        拼接 LibFuzzer 命令行参数。

        包含 max_total_time / jobs / workers / rss_limit_mb / artifact_prefix。
        """
        cmd = [self.binary_path]

        corpus_dir = self.corpus_path or os.path.join(self.output_dir, 'corpus')
        if not os.path.exists(corpus_dir):
            os.makedirs(corpus_dir, exist_ok=True)
        cmd.append(corpus_dir)

        cmd.extend([
            f'-max_total_time={timeout}',
            f'-jobs={cpu_limit}',
            f'-workers={cpu_limit}',
            f'-rss_limit_mb={memory_limit}',
        ])

        if max_crashes:
            cmd.append(f'-ignore_timeouts=1')
            cmd.append(f'-ignore_ooms=1')
            cmd.append(f'-ignore_crashes=0')

        output_corpus = os.path.join(self.output_dir, 'queue')
        cmd.append(f'-artifact_prefix={output_corpus}/')

        if additional_args:
            cmd.extend(additional_args)

        return cmd

    def _build_afl_command(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """
        拼接 AFL/AFL++ 命令行参数。

        语料目录不存在时自动创建占位种子文件（100 字节 'A'）。
        cpu_limit > 1 时启用 master 模式并行。
        """
        cmd = ['afl-fuzz']

        corpus_dir = self.corpus_path or os.path.join(self.output_dir, 'corpus')
        if not os.path.exists(corpus_dir):
            os.makedirs(corpus_dir, exist_ok=True)
            sample_path = os.path.join(corpus_dir, 'sample')
            with open(sample_path, 'wb') as f:
                f.write(b'A' * 100)

        output_dir = self.output_dir

        cmd.extend([
            '-i', corpus_dir,
            '-o', output_dir,
            '-m', str(memory_limit),
            '-t', '1000+',
        ])

        if cpu_limit > 1:
            cmd.extend(['-M', 'master'])

        cmd.append('--')
        cmd.append(self.binary_path)
        cmd.append('@@')

        if additional_args:
            cmd.extend(additional_args)

        return cmd

    def _start_sandboxed_fuzzer(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """
        按 Config.SANDBOX_MODE 分发至 Docker 或 Podman 沙箱启动 fuzzer。
        """
        sandbox_mode = Config.SANDBOX_MODE

        if sandbox_mode == 'docker':
            return self._start_docker_fuzzer(
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            )
        elif sandbox_mode == 'podman':
            return self._start_podman_fuzzer(
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            )
        else:
            raise ValueError(f"不支持的沙箱模式: {sandbox_mode}")

    def _start_docker_fuzzer(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """以 Docker 容器模式启动 fuzzer，挂载二进制目录（只读）和输出目录（读写）。"""
        try:
            import docker
            client = docker.from_env()
        except ImportError:
            logger.error("Docker SDK 未安装")
            raise

        binary_dir = os.path.dirname(self.binary_path)
        binary_name = os.path.basename(self.binary_path)

        volumes = {
            binary_dir: {'bind': '/app/binary', 'mode': 'ro'},
            self.output_dir: {'bind': '/app/output', 'mode': 'rw'},
        }

        if self.corpus_path:
            volumes[self.corpus_path] = {'bind': '/app/corpus', 'mode': 'ro'}

        fuzzer_cmd = self._build_local_fuzzer_cmd_for_sandbox(
            '/app/binary/' + binary_name,
            timeout, max_crashes, cpu_limit, memory_limit, additional_args
        )

        container = client.containers.run(
            Config.SANDBOX_IMAGE,
            command=fuzzer_cmd,
            volumes=volumes,
            mem_limit=f"{memory_limit}m",
            cpuset_cpus=f"0-{cpu_limit - 1}" if cpu_limit > 1 else None,
            network_mode=('bridge' if Config.SANDBOX_NETWORK_ENABLED else 'none'),
            detach=True,
            auto_remove=False,
            name=f"deemo_fuzz_{self.session_id[:8]}"
        )

        self._docker_container = container
        logger.info(f"Docker 容器已启动: {container.id}")

        return container

    def _start_podman_fuzzer(
        self,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """以 Podman 容器模式启动 fuzzer，构造 podman run 命令和卷挂载参数。"""
        binary_dir = os.path.dirname(self.binary_path)
        binary_name = os.path.basename(self.binary_path)

        cmd = ['podman', 'run']

        cmd.extend(['-v', f"{binary_dir}:/app/binary:ro"])
        cmd.extend(['-v', f"{self.output_dir}:/app/output:rw"])

        if self.corpus_path:
            cmd.extend(['-v', f"{self.corpus_path}:/app/corpus:ro"])

        cmd.extend(['--memory', f"{memory_limit}m"])
        cmd.extend(['--cpus', str(cpu_limit)])

        if not Config.SANDBOX_NETWORK_ENABLED:
            cmd.extend(['--network', 'none'])

        cmd.extend(['--name', f"deemo_fuzz_{self.session_id[:8]}"])
        cmd.append(Config.SANDBOX_IMAGE)

        fuzzer_cmd = self._build_local_fuzzer_cmd_for_sandbox(
            '/app/binary/' + binary_name,
            timeout, max_crashes, cpu_limit, memory_limit, additional_args
        )
        cmd.extend(fuzzer_cmd)

        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def _build_local_fuzzer_cmd_for_sandbox(
        self,
        binary_path_in_container: str,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """构造容器内 fuzzer 命令行，路径映射至 /app 目录。"""
        if self.fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd = [binary_path_in_container]
            corpus_path = self.corpus_path or '/app/corpus'
            cmd.append(corpus_path)
            cmd.extend([
                f'-max_total_time={timeout}',
                f'-jobs={cpu_limit}',
                f'-rss_limit_mb={memory_limit}',
            ])
            cmd.append(f'-artifact_prefix=/app/output/')
            if additional_args:
                cmd.extend(additional_args)
            return cmd
        else:
            return [
                'afl-fuzz',
                '-i', '/app/corpus' if self.corpus_path else '/app/output/corpus',
                '-o', '/app/output',
                '-m', str(memory_limit),
                '--',
                binary_path_in_container,
                '@@'
            ]

    def _monitor_fuzzer(self, timeout: int, max_crashes: int = None):
        """
        后台监控 fuzzer 进程，5 秒轮询。

        定期检查进程存活状态（Docker 容器通过 container.reload()），
        扫描新崩溃文件，更新统计快照，超时或达到崩溃上限时触发停止。
        """
        check_interval = 5
        start_time = time.time()

        while not self._stop_event.is_set():
            try:
                if self.process is None:
                    break

                if self.use_sandbox and Config.SANDBOX_MODE == 'docker':
                    if hasattr(self, '_docker_container'):
                        try:
                            container = self._docker_container
                            container.reload()
                            if container.status not in ['running', 'created']:
                                break
                        except Exception:
                            break
                else:
                    if self.process.poll() is not None:
                        break

                self._check_for_new_crashes()
                self._update_stats()

                if max_crashes and len(self.crashes) >= max_crashes:
                    logger.info(f"达到最大崩溃数 {max_crashes}，停止 Fuzzer")
                    self.stop()
                    break

                if time.time() - start_time >= timeout:
                    logger.info(f"达到超时时间 {timeout}s，停止 Fuzzer")
                    self.stop()
                    break

                time.sleep(check_interval)

            except Exception as e:
                logger.error(f"监控 Fuzzer 出错: {e}")
                time.sleep(check_interval)

        self._finalize_fuzzing()

    def _check_for_new_crashes(self):
        """扫描 crashes / default/crashes / queue 目录，检测新崩溃文件并触发分析。"""
        crash_dirs = [
            os.path.join(self.output_dir, 'crashes'),
            os.path.join(self.output_dir, 'default', 'crashes'),
            os.path.join(self.output_dir, 'queue'),
        ]

        for crash_dir in crash_dirs:
            if not os.path.exists(crash_dir):
                continue

            try:
                for filename in os.listdir(crash_dir):
                    if filename == 'README.txt':
                        continue

                    file_path = os.path.join(crash_dir, filename)

                    if not os.path.isfile(file_path):
                        continue

                    if file_path in self._known_crash_files:
                        continue

                    self._known_crash_files.add(file_path)
                    self._process_crash_file(file_path)

            except Exception as e:
                logger.warning(f"检查崩溃目录失败 {crash_dir}: {e}")

    def _process_crash_file(self, file_path: str):
        """
        处理单个崩溃文件：读取内容，构造元数据，调用崩溃分析模块。

        分析结果归入 crashes 列表，触发 post_crash_discovery 钩子。
        """
        logger.info(f"发现新崩溃: {file_path}")

        try:
            with open(file_path, 'rb') as f:
                crash_data = f.read()

            crash_info = {
                'file_path': file_path,
                'filename': os.path.basename(file_path),
                'size': len(crash_data),
                'hex_preview': crash_data[:64].hex(),
                'discovered_at': datetime.now().isoformat(),
                'fuzzer_type': self.fuzzer_type,
                'session_id': self.session_id,
            }

            analysis_result = self._analyze_crash(file_path, crash_data)
            crash_info['analysis'] = analysis_result

            self.crashes.append(crash_info)

            self.hook_manager.run_hooks('post_crash_discovery', {
                'crash_file': file_path,
                'crash_info': crash_info,
                'binary_path': self.binary_path
            })

            logger.info(
                f"崩溃已分析: {os.path.basename(file_path)} "
                f"-> 漏洞类型: {analysis_result.get('vulnerability_type', 'Unknown')}"
            )

        except Exception as e:
            logger.error(f"处理崩溃文件失败 {file_path}: {e}")

    def _analyze_crash(
        self,
        file_path: str,
        crash_data: bytes
    ) -> Dict[str, Any]:
        """
        委托 CrashAnalyzer 对崩溃进行深度分析。

        先用崩溃输入复现目标二进制，提取信号/寄存器/输出；
        再将解析后的崩溃信息传入 CrashAnalyzer.analyze()，
        返回漏洞类型、可利用性、难度评估和建议措施。
        """
        try:
            from modules.analysis.dynamic.crash_analysis import CrashAnalyzer

            analyzer = CrashAnalyzer()

            execution_result = self._execute_binary_with_crash(crash_data)

            if execution_result.get('crash_info'):
                parsed_crash = execution_result['crash_info']
            else:
                parsed_crash = {
                    'input_file': file_path,
                    'input_size': len(crash_data),
                    'output': execution_result.get('stdout', ''),
                    'stderr': execution_result.get('stderr', ''),
                    'return_code': execution_result.get('returncode', -1),
                }

            analysis = analyzer.analyze(parsed_crash)

            return {
                'vulnerability_type': analysis.get('combined', {}).get('vulnerability_type', 'Unknown'),
                'exploitability': analysis.get('combined', {}).get('exploitability', 'Unknown'),
                'difficulty': analysis.get('combined', {}).get('difficulty', 'Unknown'),
                'analysis_text': analysis.get('combined', {}).get('analysis', ''),
                'recommendations': analysis.get('combined', {}).get('recommendations', []),
                'execution_info': execution_result,
            }

        except Exception as e:
            logger.error(f"崩溃分析失败: {e}")
            return {
                'vulnerability_type': 'Unknown',
                'error': str(e),
                'analysis_text': 'Analysis failed due to error'
            }

    def _execute_binary_with_crash(
        self,
        crash_data: bytes
    ) -> Dict[str, Any]:
        """
        使用崩溃输入复现执行目标二进制。

        将崩溃数据写入临时文件后调用 subprocess.run，捕获 stdout/stderr/返回码。
        对 SIGSEGV/SIGABRT/SIGILL/SIGBUS 等致命信号，提取 crash_info。
        执行超时设为 30 秒，结束后清理临时文件。
        """
        result = {
            'stdout': '',
            'stderr': '',
            'returncode': 0,
            'signal': None,
            'crash_info': None,
        }

        temp_input = os.path.join(self.output_dir, 'analysis', f'crash_input_{uuid.uuid4().hex}')

        try:
            with open(temp_input, 'wb') as f:
                f.write(crash_data)

            cmd = [self.binary_path, temp_input]

            proc = subprocess.run(
                cmd,
                input=crash_data,
                capture_output=True,
                timeout=30
            )

            result['stdout'] = proc.stdout.decode('utf-8', errors='replace')
            result['stderr'] = proc.stderr.decode('utf-8', errors='replace')
            result['returncode'] = proc.returncode

            if proc.returncode < 0:
                import signal
                try:
                    sig_name = signal.Signals(-proc.returncode).name
                    result['signal'] = sig_name
                except Exception:
                    pass

                if -proc.returncode in [signal.SIGSEGV, signal.SIGABRT, signal.SIGILL, signal.SIGBUS]:
                    result['crash_info'] = {
                        'signal': sig_name,
                        'output': result['stderr'] or result['stdout'],
                        'registers': {},
                    }

        except subprocess.TimeoutExpired:
            result['timeout'] = True
        except Exception as e:
            result['error'] = str(e)
        finally:
            if os.path.exists(temp_input):
                try:
                    os.remove(temp_input)
                except Exception:
                    pass

        return result

    def _update_stats(self):
        """轮询刷新运行时统计快照，按 fuzzer 类型分别解析 LibFuzzer/AFL 日志。"""
        try:
            self.stats = {
                'crashes_found': len(self.crashes),
                'runtime': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
                'fuzzer_type': self.fuzzer_type,
                'session_id': self.session_id,
                'status': self.status,
                'known_crash_files': len(self._known_crash_files),
                'updated_at': datetime.now().isoformat(),
            }

            if self.fuzzer_type == FUZZER_TYPE_LIBFUZZER:
                self._update_libfuzzer_stats()
            elif self.fuzzer_type in [FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP]:
                self._update_afl_stats()

        except Exception as e:
            logger.debug(f"更新统计信息失败: {e}")

    def _update_libfuzzer_stats(self):
        """从 stderr.log 最后 100 行中正则提取 LibFuzzer 的 #pulse 行覆盖率与执行速率。"""
        try:
            log_file = os.path.join(self.output_dir, 'logs', 'stderr.log')
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()[-100:]

                for line in reversed(lines):
                    if 'pulse' in line or 'exec/s' in line or 'NEW' in line:
                        match = re.search(r'#(\d+).*?exec/s: ([\d.]+).*?cov: (\d+)', line)
                        if match:
                            self.stats['iterations'] = int(match.group(1))
                            self.stats['exec_per_sec'] = float(match.group(2))
                            self.stats['coverage'] = int(match.group(3))
                            break
        except Exception:
            pass

    def _update_afl_stats(self):
        """从 fuzzer_stats 文件解析 AFL 输出的键值对统计信息。"""
        try:
            fuzzer_stats_file = os.path.join(self.output_dir, 'default', 'fuzzer_stats')
            if os.path.exists(fuzzer_stats_file):
                with open(fuzzer_stats_file, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            key = key.strip()
                            value = value.strip()
                            if value.isdigit():
                                self.stats[key] = int(value)
                            else:
                                self.stats[key] = value
        except Exception:
            pass

    def _finalize_fuzzing(self):
        """模糊测试终止处理：更新状态、触发完成钩子、持久化崩溃至数据库。"""
        self.status = FUZZER_STATUS_COMPLETED

        self.hook_manager.run_hooks('post_fuzz_complete', {
            'session_id': self.session_id,
            'binary_path': self.binary_path,
            'crashes_count': len(self.crashes),
            'output_dir': self.output_dir
        })

        self._save_crashes_to_db()

        logger.info(
            f"模糊测试完成: 发现 {len(self.crashes)} 个崩溃, "
            f"输出目录: {self.output_dir}"
        )

    def _save_crashes_to_db(self):
        """将本会话所有崩溃记录写入 VulnerabilityDatabase。"""
        if not self.crashes:
            return

        try:
            from modules.vuln.vuln_db import VulnerabilityDatabase

            db = VulnerabilityDatabase()

            for crash in self.crashes:
                analysis = crash.get('analysis', {})

                vuln_type = analysis.get('vulnerability_type', 'Unknown')

                db.add_vulnerability(
                    vulnerability_type=vuln_type,
                    binary_name=os.path.basename(self.binary_path),
                    binary_format='ELF',
                    architecture='unknown',
                    bits=0,
                    function_name='fuzz_discovered',
                    pseudocode=f'Fuzzing crash discovered: {crash.get("filename", "unknown")}',
                    exploit_script='',
                    dangerous_functions=[],
                    checksec={},
                    symbols={},
                    severity=analysis.get('exploitability', 'Medium'),
                    description=f'Crash discovered via {self.fuzzer_type} fuzzing\n'
                              f'File: {crash.get("filename", "")}\n'
                              f'Size: {crash.get("size", 0)} bytes\n'
                              f'Analysis: {analysis.get("analysis_text", "")}',
                    notes=f'Fuzzer session: {self.session_id}\n'
                          f'Crash file: {crash.get("file_path", "")}'
                )

            db.close()
            logger.info(f"已保存 {len(self.crashes)} 个崩溃记录到数据库")

        except Exception as e:
            logger.error(f"保存崩溃到数据库失败: {e}")

    def stop(self) -> Dict[str, Any]:
        """
        停止模糊测试进程。

        Docker 模式下停止并强制移除容器；本地模式下 terminate -> wait(10s) -> kill。
        监控线程 join(30s) 等待退出。返回停止状态及已发现崩溃数。
        """
        if self.status not in [FUZZER_STATUS_RUNNING, FUZZER_STATUS_PAUSED]:
            logger.warning("Fuzzer 未在运行")
            return {
                'success': True,
                'message': 'Fuzzer not running',
                'status': self.status
            }

        self._stop_event.set()

        try:
            if self.use_sandbox and Config.SANDBOX_MODE == 'docker':
                if hasattr(self, '_docker_container'):
                    try:
                        self._docker_container.stop()
                        self._docker_container.remove(force=True)
                        logger.info("Docker 容器已停止并移除")
                    except Exception as e:
                        logger.warning(f"停止 Docker 容器失败: {e}")
            elif self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()

            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=30)

            logger.info("Fuzzer 已停止")

            return {
                'success': True,
                'message': 'Fuzzer stopped',
                'crashes_found': len(self.crashes),
                'status': self.status
            }

        except Exception as e:
            logger.error(f"停止 Fuzzer 失败: {e}")
            return {
                'success': False,
                'error': str(e),
                'status': self.status
            }

    def get_status(self) -> Dict[str, Any]:
        """
        获取当前会话状态快照。

        返回 session_id / status / binary_path / fuzzer_type / output_dir /
        crashes_found / stats / runtime 等字段。
        """
        self._update_stats()

        return {
            'session_id': self.session_id,
            'status': self.status,
            'binary_path': self.binary_path,
            'fuzzer_type': self.fuzzer_type,
            'output_dir': self.output_dir,
            'crashes_found': len(self.crashes),
            'stats': self.stats,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'runtime': (datetime.now() - self.start_time).total_seconds() if self.start_time else 0,
        }

    def get_crashes(self, limit: int = None) -> List[Dict[str, Any]]:
        """
        获取已发现崩溃列表。

        limit: 指定时返回前 N 条，否则返回完整副本。
        """
        if limit:
            return self.crashes[:limit]
        return self.crashes.copy()

    def get_crash(self, index: int) -> Optional[Dict[str, Any]]:
        """
        按索引获取单条崩溃详情。

        索引越界返回 None。
        """
        if 0 <= index < len(self.crashes):
            return self.crashes[index]
        return None

    def export_results(self, output_path: str) -> bool:
        """
        导出完整模糊测试结果为 JSON 文件。

        包含会话元数据、全部崩溃详情和运行时统计。
        """
        try:
            results = {
                'session_id': self.session_id,
                'binary_path': self.binary_path,
                'fuzzer_type': self.fuzzer_type,
                'output_dir': self.output_dir,
                'status': self.status,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': datetime.now().isoformat(),
                'crashes_count': len(self.crashes),
                'crashes': self.crashes,
                'stats': self.stats,
            }

            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

            logger.info(f"结果已导出: {output_path}")
            return True

        except Exception as e:
            logger.error(f"导出结果失败: {e}")
            return False

    def __enter__(self):
        """上下文管理器入口，返回自身。"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口，运行中则自动停止。"""
        if self.status == FUZZER_STATUS_RUNNING:
            self.stop()

def list_available_fuzzers() -> Dict[str, Any]:
    """
    枚举当前环境可用和不可用的 Fuzzer 引擎。

    返回包含 available / unavailable 列表及各自详情描述的字典。
    """
    result = {
        'available': [],
        'unavailable': [],
        'details': {}
    }

    fuzzers = [
        (FUZZER_TYPE_LIBFUZZER, 'LibFuzzer (LLVM)',
         lambda: _check_binary_has_libfuzzer()),
        (FUZZER_TYPE_AFL, 'AFL (American Fuzzy Lop)',
         lambda: _check_command(['afl-fuzz', '-V'])),
        (FUZZER_TYPE_AFLPP, 'AFL++ (Advanced Fuzzing Library)',
         lambda: _check_command(['afl-fuzz', '-V']) and _check_aflpp_variant()),
    ]

    for name, description, check_fn in fuzzers:
        try:
            available = check_fn()
            if available:
                result['available'].append(name)
                result['details'][name] = {
                    'name': name,
                    'description': description,
                    'available': True
                }
            else:
                result['unavailable'].append(name)
                result['details'][name] = {
                    'name': name,
                    'description': description,
                    'available': False
                }
        except Exception as e:
            result['unavailable'].append(name)
            result['details'][name] = {
                'name': name,
                'description': description,
                'available': False,
                'error': str(e)
            }

    return result

def _check_command(cmd: List[str]) -> bool:
    # 执行命令并检查返回码是否为 0
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def _check_binary_has_libfuzzer() -> bool:
    # 假设二进制已链接 LibFuzzer
    return True

def _check_aflpp_variant() -> bool:
    # 通过 afl-fuzz -V 输出中的 "afl++" 标识区分 AFL++ 与原始 AFL
    try:
        result = subprocess.run(
            ['afl-fuzz', '-V'],
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout.lower()
        return 'afl++' in output or '++' in output
    except Exception:
        return False

def create_fuzz_manager(
    binary_path: str,
    fuzzer_type: str = FUZZER_TYPE_AUTO,
    corpus_path: str = None,
    output_dir: str = None,
    use_sandbox: bool = True
) -> FuzzManager:
    """
    创建 FuzzManager 实例的便捷工厂函数。

    binary_path: 目标二进制路径。
    fuzzer_type: 引擎类型，默认 auto 自动检测。
    corpus_path: 初始语料路径，可选。
    output_dir: 输出目录，可选。
    use_sandbox: 是否启用沙箱隔离。
    """
    return FuzzManager(
        binary_path=binary_path,
        fuzzer_type=fuzzer_type,
        corpus_path=corpus_path,
        output_dir=output_dir,
        use_sandbox=use_sandbox
    )
