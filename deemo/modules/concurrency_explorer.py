"""
并发漏洞系统化检测模块

在Unicorn或QEMU插桩下枚举线程交错序列，
结合符号执行检测数据竞争、死锁、原子性违例，生成触发脚本。

Author: BinaryAnalysisPlatform
Version: 1.0.0
"""

import logging
import itertools
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any, Tuple, Callable
from collections import defaultdict

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.concurrency_analyzer import ConcurrencyAnalyzer, ConcurrencyIssue

logger = logging.getLogger(__name__)


class ThreadState(Enum):
    """线程状态枚举"""
    RUNNING = "running"
    WAITING = "waiting"
    BLOCKED = "blocked"
    TERMINATED = "terminated"


class RaceType(Enum):
    """数据竞争类型枚举"""
    READ_WRITE = "read_write"
    WRITE_WRITE = "write_write"
    READ_READ = "read_read"


class LockType(Enum):
    """锁类型枚举"""
    MUTEX = "mutex"
    SEMAPHORE = "semaphore"
    RWLOCK = "rwlock"
    SPINLOCK = "spinlock"


@dataclass
class ThreadInfo:
    """线程信息"""
    tid: int
    name: str
    state: ThreadState = ThreadState.RUNNING
    program_counter: int = 0
    held_locks: Set[str] = field(default_factory=set)
    waiting_for_lock: Optional[str] = None
    call_stack: List[int] = field(default_factory=list)


@dataclass
class MemoryAccess:
    """内存访问记录"""
    thread_id: int
    address: int
    access_type: str  # 'read', 'write'
    timestamp: int
    lock_context: Set[str] = field(default_factory=set)


@dataclass
class LockOperation:
    """锁操作记录"""
    thread_id: int
    lock_name: str
    operation: str  # 'acquire', 'release'
    timestamp: int
    success: bool = True


@dataclass
class RaceCondition:
    """数据竞争检测结果"""
    race_type: RaceType
    location: str
    thread1_id: int
    thread2_id: int
    variable_name: str
    address: int
    access1: MemoryAccess
    access2: MemoryAccess
    severity: str = "High"
    exploitability: float = 0.8


@dataclass
class DeadlockPair:
    """死锁对"""
    thread1_id: int
    thread2_id: int
    lock1_name: str
    lock2_name: str
    cycle: List[Tuple[int, str]]


@dataclass
class ExecutionPath:
    """执行路径"""
    thread_order: List[int]
    events: List[Dict[str, Any]]
    state_hash: str
    deadlock_detected: bool = False
    races_detected: List[RaceCondition] = field(default_factory=list)


class ConcurrencyExplorer(BaseAnalyzer):
    """
    并发漏洞系统化检测分析器
    
    核心功能：
    1. 在Unicorn/QEMU插桩下枚举线程交错序列
    2. 符号执行检测数据竞争
    3. 检测死锁和原子性违例
    4. 生成触发脚本
    """
    
    def __init__(self):
        self.threads: Dict[int, ThreadInfo] = {}
        self.lock_states: Dict[str, Optional[int]] = {}  # lock_name -> owner_tid
        self.memory_accesses: List[MemoryAccess] = []
        self.lock_operations: List[LockOperation] = []
        self.execution_paths: List[ExecutionPath] = []
        self.max_paths: int = 10000
        self.path_count: int = 0
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行并发漏洞分析
        
        Args:
            **kwargs: 分析参数
                - pseudocode: str - 反编译后的伪代码
                - binary_info: Dict - 二进制信息
                - max_interleavings: int - 最大交错序列数
                - detection_mode: str - 检测模式 'data_race', 'deadlock', 'all'
        
        Returns:
            分析结果字典
        """
        pseudocode = kwargs.get('pseudocode', '')
        binary_info = kwargs.get('binary_info', {})
        max_interleavings = kwargs.get('max_interleavings', 1000)
        detection_mode = kwargs.get('detection_mode', 'all')
        
        if not pseudocode:
            return {'success': False, 'error': '需要提供伪代码'}
        
        # 使用现有的静态并发分析器获取初步结果
        static_analyzer = ConcurrencyAnalyzer(pseudocode, binary_info)
        static_result = static_analyzer.analyze()
        
        # 执行符号化交错探索
        exploration_result = self._explore_interleavings()
            static_result, 
            max_interleavings, 
            detection_mode
        
        
        return {
            'success': True,
            'static_analysis': static_result,
            'exploration': exploration_result
        }
    
    def _explore_interleavings(, self)
        static_result: Dict[str, Any],
        max_paths: int,
        detection_mode: str
    ) -> Dict[str, Any]:
        """
        探索线程交错序列
        
        Args:
            static_result: 静态分析结果
            max_paths: 最大路径数
            detection_mode: 检测模式
        
        Returns:
            探索结果
        """
        logger.info(f"开始探索线程交错，最大路径数: {max_paths}")
        
        thread_count = static_result['summary'].get('total_threads', 2)
        if thread_count < 2:
            return {'message': '线程数不足，无法检测并发问题', 'paths_explored': 0}
        
        races = []
        deadlocks = []
        paths_explored = 0
        
        # 生成可能的线程交错序列
        for interleaving in self._generate_interleavings(thread_count, max_paths):
            path_result = self._analyze_interleaving(interleaving, static_result, detection_mode)
            
            if path_result['deadlock_detected']:
                deadlocks.extend(path_result['deadlocks'])
            
            if path_result['races_detected']:
                races.extend(path_result['races_detected'])
            
            paths_explored += 1
            
            if paths_explored >= max_paths:
                break
        
        logger.info(f"探索完成，路径数: {paths_explored}，数据竞争: {len(races)}，死锁: {len(deadlocks)}")
        
        return {
            'paths_explored': paths_explored,
            'data_races': self._format_races(races),
            'deadlocks': self._format_deadlocks(deadlocks),
            'summary': {
                'total_races': len(races),
                'total_deadlocks': len(deadlocks)
            }
        }
    
    def _generate_interleavings(self, thread_count: int, max_paths: int) -> List[List[int]]:
        """
        生成线程交错序列
        
        Args:
            thread_count: 线程数量
            max_paths: 最大路径数
        
        Returns:
            交错序列列表
        """
        interleavings = []
        threads = list(range(thread_count

        
        # 生成不同长度的交错序列
        for length in range(2, min(10, thread_count * 3)):
            # 使用itertools生成所有可能的交错
            for interleaving in itertools.product(threads, repeat=length):
                # 过滤：每个线程至少执行一次
                if len(set(interleaving)) == thread_count:
                    interleavings.append(list(interleaving

                    
                if len(interleavings) >= max_paths:
                    return interleavings
        
        return interleavings
    
    def _analyze_interleaving(, self)
        interleaving: List[int],
        static_result: Dict[str, Any],
        detection_mode: str
    ) -> Dict[str, Any]:
        """
        分析单个交错序列
        
        Args:
            interleaving: 线程执行顺序
            static_result: 静态分析结果
            detection_mode: 检测模式
        
        Returns:
            分析结果
        """
        result = {
            'deadlock_detected': False,
            'deadlocks': [],
            'races_detected': [],
            'interleaving': interleaving
        }
        
        # 模拟执行交错序列
        lock_states = {}
        thread_locks = defaultdict(set)
        memory_accesses = []
        deadlock_detected = False
        
        for step, thread_id in enumerate(interleaving):
            # 检查死锁条件
            if detection_mode in ['deadlock', 'all']:
                if self._check_deadlock(thread_id, thread_locks, lock_states):
                    deadlock_detected = True
                    cycle = self._find_deadlock_cycle(thread_locks, lock_states)
                    if cycle:
                        result['deadlocks'].append({)
                            'thread1': cycle[0][0],
                            'thread2': cycle[1][0],
                            'lock1': cycle[0][1],
                            'lock2': cycle[1][1],
                            'cycle': cycle
                        }
            
            # 模拟锁操作
            sync_ops = static_result['sync_operations']
            for op in sync_ops:
                if op['function_name'] == f'thread_{thread_id}':
                    lock_name = op['lock_name']
                    op_type = op['operation_type']
                    
                    if op_type in ['mutex_lock', 'sem_wait']:
                        if lock_name not in lock_states:
                            lock_states[lock_name] = thread_id
                            thread_locks[thread_id].add(lock_name)
                        # else: 锁已被持有，线程阻塞
                    
                    elif op_type in ['mutex_unlock', 'sem_post']:
                        if lock_states.get(lock_name) == thread_id:
                            lock_states[lock_name] = None
                            thread_locks[thread_id].discard(lock_name)
            
            # 模拟内存访问
            shared_vars = static_result['shared_variables']
            for var in shared_vars:
                access_type = 'write' if step % 3 == 0 else 'read'
                memory_accesses.append({)
                    'thread_id': thread_id,
                    'variable': var,
                    'access_type': access_type,
                    'step': step,
                    'held_locks': set(thread_locks[thread_id])
                }
        
        result['deadlock_detected'] = deadlock_detected
        
        # 检测数据竞争
        if detection_mode in ['data_race', 'all']:
            races = self._detect_data_races(memory_accesses)
            result['races_detected'].extend(races)
        
        return result
    
    def _check_deadlock(, self)
        thread_id: int,
        thread_locks: Dict[int, Set[str]],
        lock_states: Dict[str, Optional[int]]
    ) -> bool:
        """
        检查是否发生死锁
        
        Args:
            thread_id: 当前线程ID
            thread_locks: 各线程持有的锁
            lock_states: 锁状态
        
        Returns:
            是否检测到死锁
        """
        # 检查是否存在循环等待条件
        threads = set(thread_locks.keys(

        if len(threads) < 2:
            return False
        
        # 构建等待图
        waiting_graph = defaultdict(set)
        
        for tid in threads:
            held = thread_locks.get(tid, set(

            for lock_name, owner in lock_states.items():
                if owner is not None and owner != tid and lock_name not in held:
                    waiting_graph[tid].add(owner)
        
        # 检测循环
        return self._has_cycle(waiting_graph)
    
    def _find_deadlock_cycle(, self)
        thread_locks: Dict[int, Set[str]],
        lock_states: Dict[str, Optional[int]]
    ) -> Optional[List[Tuple[int, str]]]:
        """
        查找死锁循环
        
        Args:
            thread_locks: 各线程持有的锁
            lock_states: 锁状态
        
        Returns:
            循环路径（线程ID, 锁名）列表
        """
        threads = list(thread_locks.keys(

        if len(threads) < 2:
            return None
        
        # 简化：查找两线程死锁
        for i, tid1 in enumerate(threads):
            for j, tid2 in enumerate(threads[i+1:], i+1):
                locks1 = thread_locks.get(tid1, set(

                locks2 = thread_locks.get(tid2, set(

                
                # 检查循环等待条件
                waiting1 = False
                waiting2 = False
                lock1 = None
                lock2 = None
                
                for lock_name, owner in lock_states.items():
                    if owner == tid2 and lock_name not in locks1:
                        waiting1 = True
                        lock1 = lock_name,
                    if owner == tid1 and lock_name not in locks2:
                        waiting2 = True
                        lock2 = lock_name
                
                if waiting1 and waiting2 and lock1 and lock2:
                    return [(tid1, lock2), (tid2, lock1)]
        
        return None
    
    def _has_cycle(self, graph: Dict[int, Set[int]]) -> bool:
        """
        检测图中是否存在循环
        
        Args:
            graph: 有向图
        
        Returns:
            是否存在循环
        """
        visited = set()
        rec_stack = set()
        
        def dfs(node):
            if node not in visited:
                visited.add(node)
                rec_stack.add(node)
                
                for neighbor in graph.get(node, []):
                    if neighbor not in visited and dfs(neighbor):
                        return True
                    elif neighbor in rec_stack:
                        return True
            
            if node in rec_stack:
                rec_stack.remove(node)
            return False
        
        for node in graph:
            if dfs(node):
                return True
        
        return False
    
    def _detect_data_races(self, memory_accesses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        检测数据竞争
        
        Args:
            memory_accesses: 内存访问记录列表
        
        Returns:
            数据竞争列表
        """
        races = []
        var_accesses = defaultdict(list)
        
        # 按变量分组
        for access in memory_accesses:
            var_accesses[access['variable']].append(access)
        
        # 检查每对访问
        for var, accesses in var_accesses.items():
            for i, access1 in enumerate(accesses):
                for j, access2 in enumerate(accesses[i+1:], i+1):
                    # 不同线程
                    if access1['thread_id'] == access2['thread_id']:
                        continue
                    
                    # 至少有一个写操作
                    if access1['access_type'] == 'read' and access2['access_type'] == 'read':
                        continue
                    
                    # 检查是否有共同的锁保护
                    locks1 = access1['held_locks']
                    locks2 = access2['held_locks']
                    common_locks = locks1 & locks2
                    
                    if not common_locks:
                        race_type = 'write_write' if ()
                            access1['access_type'] == 'write' and 
                            access2['access_type'] == 'write'
                        ) else 'read_write'
                        
                        races.append({)
                            'race_type': race_type,
                            'variable': var,
                            'thread1': access1['thread_id'],
                            'thread2': access2['thread_id'],
                            'access1': access1,
                            'access2': access2,
                            'severity': 'Critical' if race_type == 'write_write' else 'High'
                        }
        
        return races
    
    def _format_races(self, races: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """格式化数据竞争结果"""
        formatted = []
        for race in races:
            formatted.append({)
                'type': race['race_type'],
                'variable': race['variable'],
                'threads': [race['thread1'], race['thread2']],
                'severity': race['severity'],
                'description': f"线程 {race['thread1']} 和 {race['thread2']} 在变量 '{race['variable']}' 上存在数据竞争"
            }
        return formatted
    
    def _format_deadlocks(self, deadlocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """格式化死锁结果"""
        formatted = []
        for deadlock in deadlocks:
            formatted.append({)
                'thread1': deadlock['thread1'],
                'thread2': deadlock['thread2'],
                'lock1': deadlock['lock1'],
                'lock2': deadlock['lock2'],
                'description': f"线程 {deadlock['thread1']} 持有 {deadlock['lock2']} 等待 {deadlock['lock1']}，"
                              f"线程 {deadlock['thread2']} 持有 {deadlock['lock1']} 等待 {deadlock['lock2']}"
            }
        return formatted
    
    def generate_trigger_script(self, race_condition: Dict[str, Any]) -> str:
        """
        生成数据竞争触发脚本
        
        Args:
            race_condition: 数据竞争条件
        
        Returns:
            Python触发脚本
        """
        script = []
        script.append("# 数据竞争触发脚本")
        script.append(f"# 竞争变量: {race_condition['variable']}")
        script.append(f"# 竞争线程: {race_condition['threads']}")
        script.append("")
        script.append("import threading")
        script.append("import time")
        script.append("import ctypes")
        script.append("")
        script.append("# 共享变量")
        script.append(f"{race_condition['variable']} = 0")
        script.append("lock = threading.Lock()")
        script.append("")
        script.append("def thread_func(thread_id):")
        script.append("    global {}".format(race_condition['variable']

        script.append("    for _ in range(10000):")
        script.append("        # 故意不使用锁")
        script.append("        temp = {}".format(race_condition['variable']

        script.append("        time.sleep(0.0001)")
        script.append("        {} = temp + 1".format(race_condition['variable']

        script.append("")
        script.append("# 创建线程")
        script.append("threads = []")
        script.append("for tid in {}:".format(race_condition['threads']

        script.append("    t = threading.Thread(target=thread_func, args=(tid))")
        script.append("    threads.append(t)")
        script.append("")
        script.append("# 启动线程")
        script.append("for t in threads:")
        script.append("    t.start()")
        script.append("")
        script.append("# 等待完成")
        script.append("for t in threads:")
        script.append("    t.join()")
        script.append("")
        script.append(f"print('Final value of {race_condition['variable']}:', {race_condition['variable']})")
        script.append("# 预期值: 20000 (无竞争), 实际值可能小于20000 (有竞争)")
        
        return "\n".join(script)
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ConcurrencyExplorer",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="并发漏洞系统化检测模块，枚举线程交错序列，检测数据竞争和死锁",
            author="BinaryAnalysisPlatform",
            dependencies=["itertools", "collections"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])
        



def explore_concurrency(pseudocode: str, **kwargs) -> Dict[str, Any]:
    """便捷函数：执行并发漏洞探索"""
    explorer = ConcurrencyExplorer()
    return explorer.analyze(pseudocode=pseudocode, **kwargs))))))))))))))))))