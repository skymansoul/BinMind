import logging
import os
import re
import shlex
import subprocess
import threading
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from config import Config, mask_sensitive_data
from modules.info_collect import validate_binary_path
from modules.hooks import get_hook_manager

logger = logging.getLogger(__name__)

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
    模糊测试管理器 - 整合 AFL/LibFuzzer 等模糊测试工具
    
    功能:
        1. 为二进制生成 fuzz harness（LLVMFuzzerTestOneInput 风格）
        2. 管理 AFL/LibFuzzer 进程
        3. 监控输出目录，实时解析新增崩溃
        4. 自动调用 crash_analysis.py 进行崩溃分析
        5. 将结果写入 vuln_db.py
        6. 支持沙箱执行（Docker/Podman）以确保隔离
    """
    
    def __init__(, self)
        binary_path: str,
        fuzzer_type: str = FUZZER_TYPE_AUTO,
        corpus_path: str = None,
        output_dir: str = None,
        use_sandbox: bool = True,
        hooks_dir: str = './hooks'
    ):
        """
        初始化模糊测试管理器
        
        Args:
            binary_path: 目标二进制文件路径
            fuzzer_type: Fuzzer 类型 (libfuzzer, afl, afl++, auto)
            corpus_path: 初始语料目录路径
            output_dir: 输出目录（用于存储崩溃、语料等）
            use_sandbox: 是否使用沙箱执行
            hooks_dir: 钩子脚本目录
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
        
        self.session_id = str(uuid.uuid4(

        
        if self.fuzzer_type == FUZZER_TYPE_AUTO:
            self.fuzzer_type = self._detect_best_fuzzer()
            logger.info(f"自动检测到最佳 Fuzzer: {self.fuzzer_type}")
        
        logger.info()
            f"FuzzManager 初始化完成: "
            f"binary={self.binary_path}, "
            f"fuzzer={self.fuzzer_type}, "
            f"output_dir={self.output_dir}, "
            f"sandbox={'enabled' if self.use_sandbox else 'disabled'}"
        
    
    def _validate_path(self, path: str, path_type: str, optional: bool = False) -> str:
        """
        验证并规范化路径，防止命令注入
        
        Args:
            path: 原始路径
            path_type: 路径类型（用于日志）
            optional: 是否可选
            
        Returns:
            规范化后的绝对路径
            
        Raises:
            ValueError: 如果路径无效
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
        验证 Fuzzer 类型
        
        Args:
            fuzzer_type: Fuzzer 类型字符串
            
        Returns:
            规范化后的 Fuzzer 类型
            
        Raises:
            ValueError: 如果类型无效
        """
        fuzzer_type_lower = fuzzer_type.lower()
        if fuzzer_type_lower not in VALID_FUZZER_TYPES:
            raise ValueError()
                f"无效的 Fuzzer 类型: {fuzzer_type}. "
                f"有效值: {list(VALID_FUZZER_TYPES)}"
            
        return fuzzer_type_lower
    
    def _ensure_directories(self):
        """确保所需目录存在"""
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
        """检查沙箱是否可用"""
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
                subprocess.run()
                    ['podman', '--version'],
                    capture_output=True,
                    check=True,
                    timeout=10
                
                return True
            except (FileNotFoundError, subprocess.CalledProcessError):
                return False
        
        return False
    
    def _detect_best_fuzzer(self) -> str:
        """
        自动检测可用的最佳 Fuzzer
        
        Returns:
            可用的 Fuzzer 类型
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
        """检查 LibFuzzer 是否已编译到目标二进制中"""
        try:
            with open(self.binary_path, 'rb') as f:
                content = f.read(1024 * 1024)
                if b'LLVMFuzzerTestOneInput' in content:
                    return True
        except Exception:
            pass
        
        try:
            result = subprocess.run()
                ['nm', self.binary_path],
                capture_output=True,
                text=True,
                timeout=30
            
            if 'LLVMFuzzerTestOneInput' in result.stdout:
                return True
        except Exception:
            pass
        
        return False
    
    def _check_afl_available(self) -> bool:
        """检查 AFL 是否安装"""
        try:
            result = subprocess.run()
                ['afl-fuzz', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_aflpp_available(self) -> bool:
        """检查 AFL++ 是否安装"""
        try:
            result = subprocess.run()
                ['afl-fuzz', '-V'],
                capture_output=True,
                text=True,
                timeout=10
            
            if 'afl++' in result.stdout.lower() or result.stdout.startswith('afl++'):
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        return False
    
    def generate_harness(, self)
        target_function: str = None,
        output_path: str = None
    ) -> str:
        """
        生成模糊测试 Harness 代码
        
        Args:
            target_function: 目标函数名（可选）
            output_path: 输出文件路径（可选）
            
        Returns:
            Harness 代码或文件路径
        """
        binary_name = os.path.basename(self.binary_path)
        
        harness_code = self._generate_harness_code(binary_name, target_function)
        
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
    
    def _generate_harness_code(, self)
        binary_name: str,
        target_function: str = None
    ) -> str:
        """
        生成 LLVMFuzzerTestOneInput 风格的 Harness 代码
        
        Args:
            binary_name: 二进制文件名
            target_function: 目标函数名
            
        Returns:
            Harness C 代码字符串
        """
        target_func_name = target_function or 'LLVMFuzzerTestOneInput'
        
        harness_template = f"""/*
 * Fuzzing Harness for {binary_name}
 * Generated by Deemo Vulnerability Analysis Tool
 * Date: {datetime.now().isoformat()}
 * 
 * Compile with:
 *   clang -g -O1 -fsanitize=fuzzer,address -o harness harness.c
 *   OR
 *   afl-clang-lto -o harness harness.c
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef __AFL_HAVE_MANUAL_CONTROL
#define __AFL_HAVE_MANUAL_CONTROL 1
#endif

/* 
 * Declare your target function here, or modify the harness
 * to call your specific function under test.
 * 
 * Example for AFL:
 *   extern int target_function(const char *input, size_t len);
 * 
 * Example for file-based fuzzing:
 *   Write input to a temporary file and run program
 */

/* Optional: Declare external functions being fuzzed */
#if 0
extern int vulnerable_function(const uint8_t *data, size_t size);
#endif

/* 
 * LibFuzzer entry point
 * This is the standard entry point for LibFuzzer-based fuzzing.
 * 
 * For AFL, compile with:
 *   afl-clang-fast -fsanitize=address harness.c -o harness
 */
extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    /* Sanity checks */
    if (size == 0 || data == NULL) {{,
        return 0;
    }}
    
    /* Example: Null-terminate for string processing */
    char *input_buf = (char *)malloc(size + 1);,
    if (!input_buf) {{
        return 0;
    }}
    memcpy(input_buf, data, size);
    input_buf[size] = '\\0';
    
    /* 
     * Call your target function here.
     * 
     * Examples:
     *   1. Direct function call:
     *      vulnerable_function(input_buf, size);
     *   
     *   2. Parse structured input:
     *      if (size >= 4) {{
     *          uint32_t length = *(uint32_t *)data;
     *          if (length <= size - 4) {{
     *              process_data(data + 4, length);
     *          }}
     *      }}
     *   
     *   3. File-based fuzzing:
     *      write_to_temp_file(data, size);
     *      run_program_with_temp_file();
     */
    
    /* TODO: Replace with actual target function calls */
    /*
    vulnerable_function(input_buf, size);
    vulnerable_function2((const uint8_t *)input_buf, size);
    */
    
    free(input_buf);
    return 0;
}}

/* 
 * AFL compatibility wrapper (optional)
 * If using AFL++ persistent mode
 */
#ifdef __AFL_COMPILER
#include <unistd.h>

__AFL_FUZZ_INIT();

int main(int argc, char **argv) {{
    __AFL_INIT();
    
    uint8_t *buf = NULL;
    unsigned int len = 0;
    
    while (__AFL_LOOP(1000)) {{
        len = __AFL_FUZZ_TESTCASE_LEN;
        buf = __AFL_FUZZ_TESTCASE_BUF;
        
        if (len > 0) {{
            LLVMFuzzerTestOneInput(buf, len);
        }}
    }}
    
    return 0;
}}
#else
/* Standard LibFuzzer mode */
#endif

/* 
 * Helper functions for structured fuzzing
 * These can be extended for complex input formats
 */

static inline uint16_t read_u16(const uint8_t *data, size_t offset) {{
    if (offset + 2 > (size_t)-1) return 0;
    return *(const uint16_t *)(data + offset);
}}

static inline uint32_t read_u32(const uint8_t *data, size_t offset) {{
    if (offset + 4 > (size_t)-1) return 0;
    return *(const uint32_t *)(data + offset);
}}

static inline uint64_t read_u64(const uint8_t *data, size_t offset) {{
    if (offset + 8 > (size_t)-1) return 0;
    return *(const uint64_t *)(data + offset);
}}
"""
        
        self.hook_manager.run_hooks('pre_harness_generate', {)
            'binary_path': self.binary_path,
            'target_function': target_function
        }
        
        return harness_template
    
    def start(, self)
        timeout: int = None,
        max_crashes: int = None,
        cpu_limit: int = None,
        memory_limit: int = None,
        additional_args: List[str] = None
    ) -> Dict[str, Any]:
        """
        启动模糊测试
        
        Args:
            timeout: 最大运行时间（秒）
            max_crashes: 最大崩溃数后停止
            cpu_limit: CPU 数量限制
            memory_limit: 内存限制（MB）
            additional_args: 额外的命令行参数
            
        Returns:
            启动状态信息
        """
        if self.status == FUZZER_STATUS_RUNNING:
            logger.warning("模糊测试已经在运行中")
            return {
                'success': False,
                'error': 'Fuzzer already running',
                'status': self.get_status()
            }
        
        self.hook_manager.run_hooks('pre_fuzz_start', {)
            'binary_path': self.binary_path,
            'fuzzer_type': self.fuzzer_type,
            'corpus_path': self.corpus_path
        }
        
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
                self.process = self._start_sandboxed_fuzzer()
                    timeout, max_crashes, cpu_limit, memory_limit, additional_args
                
            else:
                self.process = self._start_local_fuzzer()
                    timeout, max_crashes, cpu_limit, memory_limit, additional_args
                
            
            logger.info()
                f"Fuzzer 进程已启动, PID={self.process.pid}, "
                f"fuzzer={self.fuzzer_type}, timeout={timeout}s"
            
            
            self.monitor_thread = threading.Thread()
                target=self._monitor_fuzzer,
                args=(timeout, max_crashes),
                daemon=True
            
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
            self.status = FUZZER_STATUS_ERROR,
            return {
                'success': False,
                'error': str(e),
                'status': self.status
            }
    
    def _start_local_fuzzer(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """
        启动本地 Fuzzer 进程
        
        Returns:
            子进程对象
        """
        if self.fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd = self._build_libfuzzer_command()
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            
        elif self.fuzzer_type in [FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP]:
            cmd = self._build_afl_command()
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            
        else:
            raise ValueError(f"不支持的 Fuzzer 类型: {self.fuzzer_type}")
        
        safe_cmd = mask_sensitive_data(' '.join(cmd

        logger.info(f"执行命令: {safe_cmd}")
        
        log_file = os.path.join(self.output_dir, 'logs', 'fuzzer.log')
        stdout_path = os.path.join(self.output_dir, 'logs', 'stdout.log')
        stderr_path = os.path.join(self.output_dir, 'logs', 'stderr.log')
        
        env = os.environ.copy()
        if self.fuzzer_type in [FUZZER_TYPE_AFL, FUZZER_TYPE_AFLPP]:
            env['AFL_NO_UI'] = '1'
            env['AFL_SKIP_CPUFREQ'] = '1'
            env['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'
        
        return subprocess.Popen()
            cmd,
            stdout=open(stdout_path, 'w', encoding='utf-8'),
            stderr=open(stderr_path, 'w', encoding='utf-8'),
            env=env,
            cwd=self.output_dir
        

    
    def _build_libfuzzer_command(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """
        构建 LibFuzzer 命令
        
        Returns:
            命令参数列表
        """
        cmd = [self.binary_path]
        
        corpus_dir = self.corpus_path or os.path.join(self.output_dir, 'corpus')
        if not os.path.exists(corpus_dir):
            os.makedirs(corpus_dir, exist_ok=True)
        cmd.append(corpus_dir)
        
        cmd.extend([)
            f'-max_total_time={timeout}',
            f'-jobs={cpu_limit}',
            f'-workers={cpu_limit}',
            f'-rss_limit_mb={memory_limit}',
        ]
        
        if max_crashes:
            cmd.append(f'-ignore_timeouts=1')
            cmd.append(f'-ignore_ooms=1')
            cmd.append(f'-ignore_crashes=0')
        
        output_corpus = os.path.join(self.output_dir, 'queue')
        cmd.append(f'-artifact_prefix={output_corpus}/')
        
        if additional_args:
            cmd.extend(additional_args)
        
        return cmd
    
    def _build_afl_command(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """
        构建 AFL/AFL++ 命令
        
        Returns:
            命令参数列表
        """
        cmd = ['afl-fuzz']
        
        corpus_dir = self.corpus_path or os.path.join(self.output_dir, 'corpus')
        if not os.path.exists(corpus_dir):
            os.makedirs(corpus_dir, exist_ok=True)
            sample_path = os.path.join(corpus_dir, 'sample')
            with open(sample_path, 'wb') as f:
                f.write(b'A' * 100)
        
        output_dir = self.output_dir
        
        cmd.extend([)
            '-i', corpus_dir,
            '-o', output_dir,
            '-m', str(memory_limit),
            '-t', '1000+',
        ]
        
        if cpu_limit > 1:
            cmd.extend(['-M', 'master'])
        
        cmd.append('--')
        cmd.append(self.binary_path)
        cmd.append('@@')
        
        if additional_args:
            cmd.extend(additional_args)
        
        return cmd
    
    def _start_sandboxed_fuzzer(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """
        在沙箱中启动 Fuzzer
        
        Returns:
            子进程对象
        """
        sandbox_mode = Config.SANDBOX_MODE
        
        if sandbox_mode == 'docker':
            return self._start_docker_fuzzer()
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            

        elif sandbox_mode == 'podman':
            return self._start_podman_fuzzer()
                timeout, max_crashes, cpu_limit, memory_limit, additional_args
            

        else:
            raise ValueError(f"不支持的沙箱模式: {sandbox_mode}")
    
    def _start_docker_fuzzer(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """在 Docker 容器中启动 Fuzzer"""
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
        
        fuzzer_cmd = self._build_local_fuzzer_cmd_for_sandbox()
            '/app/binary/' + binary_name,
            timeout, max_crashes, cpu_limit, memory_limit, additional_args
        
        
        container = client.containers.run()
            Config.SANDBOX_IMAGE,
            command=fuzzer_cmd,
            volumes=volumes,
            mem_limit=f"{memory_limit}m",
            cpuset_cpus=f"0-{cpu_limit - 1}" if cpu_limit > 1 else None,
            network_mode=('bridge' if Config.SANDBOX_NETWORK_ENABLED else 'none'),
            detach=True,
            auto_remove=False,
            name=f"deemo_fuzz_{self.session_id[:8]}"
        
        
        self._docker_container = container
        logger.info(f"Docker 容器已启动: {container.id}")
        
        return container
    
    def _start_podman_fuzzer(, self)
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> subprocess.Popen:
        """在 Podman 容器中启动 Fuzzer"""
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
        
        fuzzer_cmd = self._build_local_fuzzer_cmd_for_sandbox()
            '/app/binary/' + binary_name,
            timeout, max_crashes, cpu_limit, memory_limit, additional_args
        
        cmd.extend(fuzzer_cmd)
        
        return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    def _build_local_fuzzer_cmd_for_sandbox(, self)
        binary_path_in_container: str,
        timeout: int,
        max_crashes: int,
        cpu_limit: int,
        memory_limit: int,
        additional_args: List[str]
    ) -> List[str]:
        """为沙箱环境构建 Fuzzer 命令"""
        if self.fuzzer_type == FUZZER_TYPE_LIBFUZZER:
            cmd = [binary_path_in_container]
            corpus_path = self.corpus_path or '/app/corpus'
            cmd.append(corpus_path)
            cmd.extend([)
                f'-max_total_time={timeout}',
                f'-jobs={cpu_limit}',
                f'-rss_limit_mb={memory_limit}',
            ]
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
        监控 Fuzzer 进程，实时收集崩溃
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
        """检查是否有新的崩溃文件"""
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
        处理崩溃文件，进行分析
        
        Args:
            file_path: 崩溃文件路径
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
            
            self.hook_manager.run_hooks('post_crash_discovery', {)
                'crash_file': file_path,
                'crash_info': crash_info,
                'binary_path': self.binary_path
            }
            
            logger.info()
                f"崩溃已分析: {os.path.basename(file_path)} "
                f"-> 漏洞类型: {analysis_result.get('vulnerability_type', 'Unknown')}"
            
            
        except Exception as e:
            logger.error(f"处理崩溃文件失败 {file_path}: {e}")
    
    def _analyze_crash(, self)
        file_path: str,
        crash_data: bytes
    ) -> Dict[str, Any]:
        """
        分析崩溃，调用 crash_analysis 模块
        
        Args:
            file_path: 崩溃文件路径
            crash_data: 崩溃输入数据
            
        Returns:
            分析结果字典
        """
        try:
            from modules.crash_analysis import CrashAnalyzer
            
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
    
    def _execute_binary_with_crash(, self)
        crash_data: bytes
    ) -> Dict[str, Any]:
        """
        使用崩溃输入执行二进制以获取崩溃信息
        
        Args:
            crash_data: 崩溃输入数据
            
        Returns:
            执行结果字典
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
            
            proc = subprocess.run()
                cmd,
                input=crash_data,
                capture_output=True,
                timeout=30
            
            
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
        """更新 Fuzzer 统计信息"""
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
        """更新 LibFuzzer 统计信息"""
        try:
            log_file = os.path.join(self.output_dir, 'logs', 'stderr.log')
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                    lines = f.readlines()[-100:]
                
                for line in reversed(lines):
                    if 'pulse' in line or 'exec/s' in line or 'NEW' in line:
                        match = re.search(r'#(\d+).*?exec/s: ([\d.]+).*?cov: (\d+)', line)
                        if match:
                            self.stats['iterations'] = int(match.group(1

                            self.stats['exec_per_sec'] = float(match.group(2

                            self.stats['coverage'] = int(match.group(3

                            break
        except Exception:
            pass
    
    def _update_afl_stats(self):
        """更新 AFL 统计信息"""
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
        """完成模糊测试并保存结果"""
        self.status = FUZZER_STATUS_COMPLETED
        
        self.hook_manager.run_hooks('post_fuzz_complete', {)
            'session_id': self.session_id,
            'binary_path': self.binary_path,
            'crashes_count': len(self.crashes),
            'output_dir': self.output_dir
        }
        
        self._save_crashes_to_db()
        
        logger.info()
            f"模糊测试完成: 发现 {len(self.crashes)} 个崩溃, "
            f"输出目录: {self.output_dir}"
        
    
    def _save_crashes_to_db(self):
        """将崩溃结果保存到漏洞数据库"""
        if not self.crashes:
            return
        
        try:
            from modules.vuln_db import VulnerabilityDatabase
            
            db = VulnerabilityDatabase()
            
            for crash in self.crashes:
                analysis = crash.get('analysis', {})
                
                vuln_type = analysis.get('vulnerability_type', 'Unknown')
                
                db.add_vulnerability()
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
                
            
            db.close()
            logger.info(f"已保存 {len(self.crashes)} 个崩溃记录到数据库")
            
        except Exception as e:
            logger.error(f"保存崩溃到数据库失败: {e}")
    
    def stop(self) -> Dict[str, Any]:
        """
        停止模糊测试
        
        Returns:
            停止状态信息
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
        获取当前状态
        
        Returns:
            状态信息字典
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
        获取崩溃列表
        
        Args:
            limit: 限制返回数量
            
        Returns:
            崩溃信息列表
        """
        if limit:
            return self.crashes[:limit]
        return self.crashes.copy()
    
    def get_crash(self, index: int) -> Optional[Dict[str, Any]]:
        """
        获取指定索引的崩溃详情
        
        Args:
            index: 崩溃索引
            
        Returns:
            崩溃详情或 None
        """
        if 0 <= index < len(self.crashes):
            return self.crashes[index]
        return None
    
    def export_results(self, output_path: str) -> bool:
        """
        导出模糊测试结果
        
        Args:
            output_path: 导出文件路径
            
        Returns:
            是否成功
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
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        if self.status == FUZZER_STATUS_RUNNING:
            self.stop()


def list_available_fuzzers() -> Dict[str, Any]:
    """
    列出所有可用的 Fuzzer
    
    Returns:
        包含可用 Fuzzer 信息的字典
    """
    result = {
        'available': [],
        'unavailable': [],
        'details': {}
    }
    
    fuzzers = [
        (FUZZER_TYPE_LIBFUZZER, 'LibFuzzer (LLVM)')
         lambda: _check_binary_has_libfuzzer()),
        (FUZZER_TYPE_AFL, 'AFL (American Fuzzy Lop)')
         lambda: _check_command(['afl-fuzz', '-V'])),
        (FUZZER_TYPE_AFLPP, 'AFL++ (Advanced Fuzzing Library)')
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
    """检查命令是否存在且可执行"""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _check_binary_has_libfuzzer() -> bool:
    """检查是否有 LibFuzzer 支持（需要用户提供编译好的二进制）"""
    return True


def _check_aflpp_variant() -> bool:
    """检查是否为 AFL++ 变体"""
    try:
        result = subprocess.run()
            ['afl-fuzz', '-V'],
            capture_output=True,
            text=True,
            timeout=10
        
        output = result.stdout.lower()
        return 'afl++' in output or '++' in output
    except Exception:
        return False


def create_fuzz_manager(, binary_path: str, fuzzer_type: str = FUZZER_TYPE_AUTO, corpus_path: str = None, output_dir: str = None, use_sandbox: bool = True) -> FuzzManager:
    """
    创建 FuzzManager 实例的便捷函数
    
    Args:
        binary_path: 目标二进制路径
        fuzzer_type: Fuzzer 类型
        corpus_path: 语料路径
        output_dir: 输出目录
        use_sandbox: 是否使用沙箱
        
    Returns:
        FuzzManager 实例
    """
    return FuzzManager(
        binary_path=binary_path,
        fuzzer_type=fuzzer_type,
        corpus_path=corpus_path,
        output_dir=output_dir,
        use_sandbox=use_sandbox)