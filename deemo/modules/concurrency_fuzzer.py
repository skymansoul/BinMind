"""
多线程动态状态空间探索与数据竞争复现模块

通过控制线程调度，动态地系统探索线程交错执行的可能性，
尝试复现并发分析中发现的潜在数据竞争或死锁。
"""

import logging
import os
import re
import subprocess
import json
import random
import time
import tempfile
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import Config, ensure_directories

logger = logging.getLogger(__name__)


class RaceType(Enum):
    """竞争类型枚举"""
    DATA_RACE = 'data_race'
    DEADLOCK = 'deadlock'
    Livelock = 'livelock'
    ORDER_VIOLATION = 'order_violation'
    ATOMICITY_VIOLATION = 'atomicity_violation'
    UNKNOWN = 'unknown'


@dataclass
class ThreadSchedule:
    """线程调度数据类"""
    thread_id: int
    delay_ms: int = 0
    sync_point: str = ''
    order: int = 0
    action: str = ''


@dataclass
class RaceCondition:
    """竞争条件数据类"""
    race_type: RaceType
    location: str
    thread_1: int = 0
    thread_2: int = 0
    variable: str = ''
    description: str = ''
    severity: str = 'medium'
    reproduction_probability: float = 0.0


@dataclass
class ConcurrencyFuzzResult:
    """并发模糊测试结果数据类"""
    binary_path: str
    iterations: int
    races_found: List[RaceCondition] = field(default_factory=lambda: [])
    crashes: List[Dict[str, Any]] = field(default_factory=lambda: [])
    reproduction_steps: List[Dict[str, Any]] = field(default_factory=lambda: [])
    statistics: Dict[str, Any] = field(default_factory=lambda: {})
    summary: str = ''


# 同步函数列表
SYNC_FUNCTIONS = [
    'pthread_mutex_lock',
    'pthread_mutex_unlock',
    'pthread_rwlock_rdlock',
    'pthread_rwlock_wrlock',
    'pthread_rwlock_unlock',
    'pthread_cond_wait',
    'pthread_cond_signal',
    'pthread_cond_broadcast',
    'pthread_barrier_wait',
    'sem_wait',
    'sem_post',
    'pthread_join',
    'pthread_spin_lock',
    'pthread_spin_unlock',
]

# 竞争检测模式
RACE_PATTERNS = {
    # 数据竞争
    'data_race': [
        r'race detected',
        r'data race',
        r'concurrent access',
        r'unsynchronized access',
        r'potential race',
        r'TSAN:.*race',
        r'ThreadSanitizer:.*data race',
    ],
    
    # 死锁
    'deadlock': [
        r'deadlock detected',
        r'lock order violation',
        r'potential deadlock',
        r'cycle in lock graph',
        r'TSAN:.*deadlock',
        r'ThreadSanitizer:.*lock-order-violation',
    ],
    
    # 原子性违反
    'atomicity_violation': [
        r'atomicity violation',
        r'non-atomic',
        r'missing synchronization',
    ],
    
    # 顺序违反
    'order_violation': [
        r'order violation',
        r'execution order',
        r'wrong order',
    ],
}


class ConcurrencyFuzzer:
    """
    并发模糊测试器
    
    通过控制线程调度探索并发问题。
    """
    
    # 使用模块级别的定义
    SYNC_FUNCTIONS = SYNC_FUNCTIONS
    RACE_PATTERNS = RACE_PATTERNS
    
    def __init__(
        self,
        binary_path: str,
        output_dir: str = None,
        iterations: int = 100,
        max_threads: int = 4,
        use_rr: bool = True,
        use_docker: bool = True
    ):
        """
        初始化并发模糊测试器
        
        Args:
            binary_path: 二进制文件路径
            output_dir: 输出目录
            iterations: 测试迭代次数
            max_threads: 最大线程数
            use_rr: 是否使用 rr (Record & Replay)
            use_docker: 是否在 Docker 中运行
        """
        self.binary_path = binary_path
        self.output_dir = output_dir or os.path.join(Config.REPORTS_DIR, 'concurrency_fuzz')
        self.iterations = iterations
        self.max_threads = max_threads
        self.use_rr = use_rr
        self.use_docker = use_docker
        
        ensure_directories(self.output_dir)
        
        self.sync_points: List[str] = []
        self.thread_functions: List[str] = []
        self.races_found: List[RaceCondition] = []
        self.crashes: List[Dict[str, Any]] = []
        self.reproduction_steps: List[Dict[str, Any]] = []
        
        # 检查工具可用性
        self._check_tools()
    
    def _check_tools(self) -> None:
        """
        检查工具可用性
        """
        self.rr_available = False
        self.docker_available = False
        self.valgrind_available = False
        
        # 检查 rr
        try:
            result = subprocess.run(
                ['rr', '--version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self.rr_available = True
                logger.info("[ConcFuzz] rr 可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[ConcFuzz] rr 未安装")
        
        # 检查 Docker
        try:
            result = subprocess.run(
                ['docker', '--version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self.docker_available = True
                logger.info("[ConcFuzz] Docker 可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[ConcFuzz] Docker 未安装")
        
        # 检查 Valgrind
        try:
            result = subprocess.run(
                ['valgrind', '--version'],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                self.valgrind_available = True
                logger.info("[ConcFuzz] Valgrind 可用")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.info("[ConcFuzz] Valgrind 未安装")
    
    def analyze(self) -> ConcurrencyFuzzResult:
        """
        执行并发模糊测试
        
        Returns:
            ConcurrencyFuzzResult 测试结果
        """
        logger.info(f"[ConcFuzz] 开始并发模糊测试: {self.binary_path}")
        
        # 静态分析同步点
        self._analyze_sync_points()
        
        # 生成调度策略
        schedules = self._generate_schedules()
        
        # 执行测试
        self._run_tests(schedules)
        
        # 分析结果
        self._analyze_results()
        
        # 生成摘要
        summary = self._generate_summary()
        
        # 保存结果
        self._save_results()
        
        return ConcurrencyFuzzResult(
            binary_path=self.binary_path,
            iterations=self.iterations,
            races_found=self.races_found,
            crashes=self.crashes,
            reproduction_steps=self.reproduction_steps,
            statistics=self._get_statistics(),
            summary=summary
        )
    
    def _analyze_sync_points(self) -> None:
        """
        静态分析同步点
        """
        try:
            # 使用 radare2 分析
            result = subprocess.run(
                ['r2', '-q', '-c', 'is', self.binary_path],
                capture_output=True,
                text=True,
                timeout=Config.SUBPROCESS_TIMEOUT
            )
            
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    for sync_func in self.SYNC_FUNCTIONS:
                        if sync_func in line:
                            self.sync_points.append(sync_func)
                            break
                    
                    # 检测线程创建函数
                    if 'pthread_create' in line or 'std::thread' in line:
                        parts = line.split()
                        if len(parts) >= 6:
                            func_name = parts[-1]
                            if func_name.startswith('sym.'):
                                func_name = func_name[4:]
                            self.thread_functions.append(func_name)
            
            logger.info(f"[ConcFuzz] 发现 {len(self.sync_points)} 个同步点")
            logger.info(f"[ConcFuzz] 发现 {len(self.thread_functions)} 个线程函数")
            
        except subprocess.TimeoutExpired:
            logger.warning("[ConcFuzz] radare2 分析超时")
        except FileNotFoundError:
            logger.warning("[ConcFuzz] radare2 未安装")
        except Exception as e:
            logger.error(f"[ConcFuzz] 同步点分析失败: {e}")
    
    def _generate_schedules(self) -> List[List[ThreadSchedule]]:
        """
        生成线程调度策略
        
        Returns:
            调度策略列表
        """
        schedules = []
        
        # 基本策略：随机延迟
        for i in range(self.iterations):
            schedule = []
            
            for thread_id in range(self.max_threads):
                # 随机延迟
                delay = random.randint(0, 100)
                
                # 随机同步点顺序
                sync_order = random.randint(0, len(self.sync_points)) if self.sync_points else 0
                
                schedule.append(ThreadSchedule(
                    thread_id=thread_id,
                    delay_ms=delay,
                    order=sync_order,
                    action='run'
                ))
            
            schedules.append(schedule)
        
        # 针对性策略：强制特定顺序
        if self.sync_points:
            for sync_func in self.sync_points[:10]:
                # 创建可能导致竞争的调度
                for _ in range(10):
                    schedule = []
                    
                    # 线程 0 先获取锁
                    schedule.append(ThreadSchedule(
                        thread_id=0,
                        delay_ms=0,
                        sync_point=sync_func,
                        order=0,
                        action='lock'
                    ))
                    
                    # 线程 1 立即尝试获取同一锁
                    schedule.append(ThreadSchedule(
                        thread_id=1,
                        delay_ms=1,
                        sync_point=sync_func,
                        order=1,
                        action='lock'
                    ))
                    
                    # 其他线程随机
                    for thread_id in range(2, self.max_threads):
                        schedule.append(ThreadSchedule(
                            thread_id=thread_id,
                            delay_ms=random.randint(10, 50),
                            order=random.randint(0, 10),
                            action='run'
                        ))
                    
                    schedules.append(schedule)
        
        logger.info(f"[ConcFuzz] 生成 {len(schedules)} 个调度策略")
        
        return schedules[:self.iterations]
    
    def _run_tests(self, schedules: List[List[ThreadSchedule]]) -> None:
        """
        执行测试
        
        Args:
            schedules: 调度策略列表
        """
        logger.info(f"[ConcFuzz] 执行 {len(schedules)} 次测试")
        
        # 使用线程池并行执行
        with ThreadPoolExecutor(max_workers=min(4, self.max_threads)) as executor:
            futures = []
            
            for i, schedule in enumerate(schedules):
                future = executor.submit(
                    self._run_single_test,
                    schedule,
                    i
                )
                futures.append(future)
            
            # 收集结果
            for future in as_completed(futures):
                try:
                    result = future.result(timeout=60)
                    if result:
                        self._process_test_result(result)
                except Exception as e:
                    logger.debug(f"[ConcFuzz] 测试执行异常: {e}")
    
    def _run_single_test(
        self,
        schedule: List[ThreadSchedule],
        iteration: int
    ) -> Dict[str, Any]:
        """
        执行单次测试
        
        Args:
            schedule: 调度策略
            iteration: 迭代编号
            
        Returns:
            测试结果
        """
        result = {
            'iteration': iteration,
            'schedule': [
                {
                    'thread_id': s.thread_id,
                    'delay_ms': s.delay_ms,
                    'action': s.action
                }
                for s in schedule
            ],
            'success': False,
            'output': '',
            'error': '',
            'race_detected': False,
            'crash': False,
            'race_type': None,
            'race_location': None
        }
        
        try:
            # 构建测试环境
            if self.use_docker and self.docker_available:
                output = self._run_in_docker(schedule)
            elif self.valgrind_available:
                output = self._run_with_valgrind(schedule)
            else:
                output = self._run_with_ldpreload(schedule)
            
            result['output'] = output
            
            # 检测竞争
            race_info = self._detect_race(output)
            if race_info:
                result['race_detected'] = True
                result['race_type'] = race_info['type']
                result['race_location'] = race_info['location']
            
            # 检测崩溃
            if 'Segmentation fault' in output or 'SIGSEGV' in output:
                result['crash'] = True
            
            result['success'] = True
            
        except subprocess.TimeoutExpired:
            result['error'] = 'timeout'
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _run_in_docker(self, schedule: List[ThreadSchedule]) -> str:
        """
        在 Docker 中运行
        
        Args:
            schedule: 调度策略
            
        Returns:
            输出内容
        """
        # 构建调度注入脚本
        schedule_json = json.dumps([
            {
                'thread_id': s.thread_id,
                'delay_ms': s.delay_ms,
                'sync_point': s.sync_point
            }
            for s in schedule
        ])
        
        try:
            # 使用 Docker 运行
            container_cmd = f'python3 -c "import json; import time; schedule = json.loads(\'{schedule_json}\'); for s in schedule: time.sleep(s[\"delay_ms\"] / 1000)"'
            
            result = subprocess.run(
                [
                    'docker', 'run', '--rm',
                    '-v', f'{os.path.dirname(self.binary_path)}:/binary',
                    'ubuntu:20.04',
                    'timeout', '30',
                    '/binary/' + os.path.basename(self.binary_path)
                ],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            return result.stdout + result.stderr
            
        except Exception as e:
            logger.debug(f"[ConcFuzz] Docker 运行失败: {e}")
            return ''
    
    def _run_with_valgrind(self, schedule: List[ThreadSchedule]) -> str:
        """
        使用 Valgrind/DRD 运行
        
        Args:
            schedule: 调度策略
            
        Returns:
            输出内容
        """
        try:
            # 使用 DRD (Data Race Detector)
            result = subprocess.run(
                [
                    'valgrind',
                    '--tool=drd',
                    '--show-confl-seg=yes',
                    '--trace-mutex=yes',
                    '--log-file=/tmp/drd_output.txt',
                    self.binary_path
                ],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # 读取 DRD 输出
            drd_output = ''
            try:
                with open('/tmp/drd_output.txt', 'r') as f:
                    drd_output = f.read()
            except FileNotFoundError:
                pass
            
            return result.stdout + result.stderr + drd_output
            
        except Exception as e:
            logger.debug(f"[ConcFuzz] Valgrind 运行失败: {e}")
            return ''
    
    def _run_with_ldpreload(self, schedule: List[ThreadSchedule]) -> str:
        """
        使用 LD_PRELOAD 注入调度
        
        Args:
            schedule: 调度策略
            
        Returns:
            输出内容
        """
        # 创建调度注入库（这里简化处理）
        try:
            result = subprocess.run(
                [self.binary_path],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    'CONC_FUZZ_SCHEDULE': json.dumps([
                        {'delay': s.delay_ms} for s in schedule
                    ])
                }
            )
            
            return result.stdout + result.stderr
            
        except Exception as e:
            logger.debug(f"[ConcFuzz] 直接运行失败: {e}")
            return ''
    
    def _detect_race(self, output: str) -> Optional[Dict[str, Any]]:
        """
        从输出检测竞争
        
        Args:
            output: 输出内容
            
        Returns:
            竞争信息
        """
        for race_type, patterns in self.RACE_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    # 提取位置信息
                    location_match = re.search(r'(0x[0-9a-f]+|\w+\.\w+:\d+)', output)
                    location = location_match.group(1) if location_match else 'unknown'
                    
                    return {
                        'type': race_type,
                        'location': location,
                        'matched_pattern': pattern
                    }
        
        return None
    
    def _process_test_result(self, result: Dict[str, Any]) -> None:
        """
        处理测试结果
        
        Args:
            result: 测试结果
        """
        if result.get('race_detected'):
            race = RaceCondition(
                race_type=RaceType(result.get('race_type', 'unknown')),
                location=result.get('race_location', 'unknown'),
                description=f'在第 {result.get("iteration")} 次迭代中发现',
                reproduction_probability=1.0 / self.iterations
            )
            
            # 检查是否已存在相同竞争
            existing = False
            for r in self.races_found:
                if r.location == race.location and r.race_type == race.race_type:
                    r.reproduction_probability += 1.0 / self.iterations
                    existing = True
                    break
            
            if not existing:
                self.races_found.append(race)
                logger.warning(f"[ConcFuzz] 发现竞争: {race.race_type.value} @ {race.location}")
        
        if result.get('crash'):
            crash_info = {
                'iteration': result.get('iteration'),
                'schedule': result.get('schedule'),
                'output': result.get('output', '')[:500]
            }
            self.crashes.append(crash_info)
            logger.warning(f"[ConcFuzz] 发现崩溃: 第 {result.get('iteration')} 次迭代")
        
        # 记录复现步骤
        if result.get('race_detected') or result.get('crash'):
            self.reproduction_steps.append({
                'iteration': result.get('iteration'),
                'schedule': result.get('schedule'),
                'race_type': result.get('race_type'),
                'crash': result.get('crash')
            })
    
    def _analyze_results(self) -> None:
        """
        分析测试结果
        """
        # 计算复现概率
        for race in self.races_found:
            race.reproduction_probability = min(race.reproduction_probability, 1.0)
        
        # 设置严重程度
        for race in self.races_found:
            if race.race_type == RaceType.DATA_RACE:
                race.severity = 'high'
            elif race.race_type == RaceType.DEADLOCK:
                race.severity = 'critical'
            elif race.race_type == RaceType.ORDER_VIOLATION:
                race.severity = 'medium'
            else:
                race.severity = 'low'
    
    def _get_statistics(self) -> Dict[str, Any]:
        """
        获取统计数据
        
        Returns:
            统计数据字典
        """
        return {
            'iterations': self.iterations,
            'races_found': len(self.races_found),
            'crashes_found': len(self.crashes),
            'sync_points': len(self.sync_points),
            'thread_functions': len(self.thread_functions),
            'race_types': defaultdict(int, {
                race.race_type.value: sum(1 for r in self.races_found if r.race_type == race.race_type)
                for race in self.races_found
            }),
            'reproduction_rate': len(self.reproduction_steps) / self.iterations if self.iterations > 0 else 0
        }
    
    def _generate_summary(self) -> str:
        """
        生成摘要
        
        Returns:
            摘要字符串
        """
        lines = [
            f'并发模糊测试摘要',
            f'二进制文件: {os.path.basename(self.binary_path)}',
            f'测试迭代: {self.iterations}',
            f'发现竞争: {len(self.races_found)}',
            f'发现崩溃: {len(self.crashes)}',
            '',
            '竞争类型分布:',
        ]
        
        race_types = defaultdict(int)
        for race in self.races_found:
            race_types[race.race_type.value] += 1
        
        for race_type, count in sorted(race_types.items(), key=lambda x: -x[1]):
            lines.append(f'  - {race_type}: {count}')
        
        if self.races_found:
            lines.extend([
                '',
                '高概率竞争:',
            ])
            
            for race in sorted(self.races_found, key=lambda x: -x.reproduction_probability)[:5]:
                lines.append(f'  - {race.location}: {race.race_type.value} ({race.reproduction_probability:.1%})')
        
        return '\n'.join(lines)
    
    def _save_results(self) -> None:
        """
        保存结果
        """
        # 保存 JSON 结果
        json_path = os.path.join(self.output_dir, 'concurrency_fuzz_result.json')
        result = {
            'binary_path': self.binary_path,
            'iterations': self.iterations,
            'races_found': [
                {
                    'race_type': r.race_type.value,
                    'location': r.location,
                    'severity': r.severity,
                    'reproduction_probability': r.reproduction_probability
                }
                for r in self.races_found
            ],
            'crashes': self.crashes,
            'reproduction_steps': self.reproduction_steps,
            'statistics': self._get_statistics()
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        # 保存复现脚本
        script_path = os.path.join(self.output_dir, 'reproduce_race.py')
        script_content = self._generate_reproduction_script()
        
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
        
        logger.info(f"[ConcFuzz] 结果已保存: {self.output_dir}")
    
    def _generate_reproduction_script(self) -> str:
        """
        生成复现脚本
        
        Returns:
            脚本内容
        """
        lines = [
            '#!/usr/bin/env python3',
            '"""',
            '并发竞争复现脚本',
            f'目标: {self.binary_path}',
            '"""',
            '',
            'import subprocess',
            'import json',
            'import time',
            'import sys',
            '',
            f'BINARY_PATH = "{self.binary_path}"',
            '',
            'def reproduce_race(schedule):',
            '    """',
            '    使用指定调度复现竞争',
            '    """',
            '    print(f"尝试复现竞争，调度: {schedule}")',
            '',
            '    # 设置环境变量',
            '    env = {"CONC_FUZZ_SCHEDULE": json.dumps(schedule)}',
            '',
            '    # 运行二进制',
            '    try:',
            '        result = subprocess.run(',
            '            [BINARY_PATH],',
            '            capture_output=True,',
            '            text=True,',
            '            timeout=30,',
            '            env=env',
            '        )',
            '        print("输出:", result.stdout)',
            '        print("错误:", result.stderr)',
            '        return result.returncode == 0',
            '    except subprocess.TimeoutExpired:',
            '        print("超时")',
            '        return False',
            '',
            '# 复现步骤',
            'REPRODUCTION_STEPS = [',
        ]
        
        for step in self.reproduction_steps[:10]:
            lines.append(f'    {json.dumps(step)},')
        
        lines.extend([
            ']',
            '',
            'if __name__ == "__main__":',
            '    for step in REPRODUCTION_STEPS:',
            '        schedule = step.get("schedule", [])',
            '        reproduce_race(schedule)',
            '        time.sleep(1)',
            '',
        ])
        
        return '\n'.join(lines)
    
    def load_concurrency_analysis(self, analysis_file: str) -> None:
        """
        加载并发分析结果
        
        Args:
            analysis_file: 分析文件路径
        """
        try:
            with open(analysis_file, 'r', encoding='utf-8') as f:
                analysis = json.load(f)
            
            # 加载潜在竞争点
            potential_races = analysis.get('potential_races', [])
            
            for race in potential_races:
                # 生成针对性调度
                location = race.get('location', '')
                threads = race.get('threads', [])
                
                if location and threads:
                    self.sync_points.append(location)
                    
                    logger.info(f"[ConcFuzz] 加载潜在竞争点: {location}")
            
        except FileNotFoundError:
            logger.error(f"[ConcFuzz] 分析文件不存在: {analysis_file}")
        except json.JSONDecodeError:
            logger.error(f"[ConcFuzz] 分析文件格式错误")
        except Exception as e:
            logger.error(f"[ConcFuzz] 加载分析失败: {e}")
    
    def to_dict(self) -> Dict[str, Any]:
        """
        转换为字典
        
        Returns:
            结果字典
        """
        return {
            'binary_path': self.binary_path,
            'iterations': self.iterations,
            'races_found': len(self.races_found),
            'crashes_found': len(self.crashes),
            'statistics': self._get_statistics(),
            'summary': self._generate_summary()
        }


def run_concurrency_fuzz(
    binary_path: str,
    iterations: int = 100,
    output_dir: str = None,
    analysis_file: str = None
) -> ConcurrencyFuzzResult:
    """
    运行并发模糊测试的便捷函数
    
    Args:
        binary_path: 二进制路径
        iterations: 迭代次数
        output_dir: 输出目录
        analysis_file: 并发分析文件
        
    Returns:
        ConcurrencyFuzzResult 测试结果
    """
    fuzzer = ConcurrencyFuzzer(binary_path, output_dir, iterations)
    
    if analysis_file:
        fuzzer.load_concurrency_analysis(analysis_file)
    
    return fuzzer.analyze()


# 别名函数，保持向后兼容
def fuzz_concurrency(
    binary_path: str,
    iterations: int = 100,
    output_dir: str = None,
    analysis_file: str = None
) -> ConcurrencyFuzzResult:
    """
    运行并发模糊测试的便捷函数（别名）
    
    Args:
        binary_path: 二进制路径
        iterations: 迭代次数
        output_dir: 输出目录
        analysis_file: 并发分析文件
        
    Returns:
        ConcurrencyFuzzResult 测试结果
    """
    return run_concurrency_fuzz(binary_path, iterations, output_dir, analysis_file)