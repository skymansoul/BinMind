import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from enum import Enum
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    logger.warning("networkx 未安装，将使用内置算法")


class LockType(Enum):
    """锁类型枚举"""
    MUTEX = "mutex"
    SEMAPHORE = "semaphore"
    RW_LOCK = "rw_lock"
    SPIN_LOCK = "spin_lock"


class LockOperation(Enum):
    """锁操作类型枚举"""
    ACQUIRE = "acquire"
    RELEASE = "release"


class LockDependency:
    """锁依赖关系类"""
    
    def __init__(self, from_lock: str, to_lock: str, function: str):
        self.from_lock = from_lock
        self.to_lock = to_lock
        self.function = function
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'from_lock': self.from_lock,
            'to_lock': self.to_lock,
            'function': self.function
        }


class DeadlockPath:
    """死锁路径类"""
    
    def __init__(self, cycle: List[str], functions: List[str], description: str):
        self.cycle = cycle
        self.functions = functions
        self.description = description
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cycle': self.cycle,
            'functions': self.functions,
            'description': self.description
        }


class DeadlockAnalysisResult:
    """死锁分析结果类"""
    
    def __init__(
        self,
        deadlocks: Optional[List[DeadlockPath]] = None,
        lock_dependencies: Optional[List[LockDependency]] = None,
        total_locks: int = 0,
        total_functions: int = 0,
        potential_deadlocks: int = 0
    ):
        self.deadlocks: List[DeadlockPath] = deadlocks or []
        self.lock_dependencies: List[LockDependency] = lock_dependencies or []
        self.total_locks: int = total_locks
        self.total_functions: int = total_functions
        self.potential_deadlocks: int = potential_deadlocks
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'deadlocks': [d.to_dict() for d in self.deadlocks],
            'lock_dependencies': [ld.to_dict() for ld in self.lock_dependencies],
            'total_locks': self.total_locks,
            'total_functions': self.total_functions,
            'potential_deadlocks': self.potential_deadlocks
        }


class DeadlockDetector:
    """
    多线程死锁自动化检测器
    
    该类负责基于静态分析提取的同步原语和调用图，构建资源分配图，
    使用死锁检测算法发现潜在的死锁场景，并输出详细的调用链和锁顺序。
    """
    
    def __init__(self):
        self.operations: List[Dict[str, Any]] = []
        self.locks: Set[str] = set()
        self.functions_with_locks: Set[str] = set()
        self.lock_dependencies: List[LockDependency] = []
    
    def add_lock_operation(
        self,
        function_name: str,
        lock_name: str,
        operation: LockOperation,
        lock_type: LockType = LockType.MUTEX,
        line_number: Optional[int] = None
    ):
        """
        添加锁操作记录
        
        Args:
            function_name: 函数名
            lock_name: 锁名称
            operation: 操作类型（获取/释放）
            lock_type: 锁类型
            line_number: 行号
        """
        self.operations.append({
            'function': function_name,
            'lock': lock_name,
            'operation': operation,
            'lock_type': lock_type,
            'line': line_number
        })
        self.locks.add(lock_name)
        self.functions_with_locks.add(function_name)
    
    def add_operations_from_decompilation(self, decompilation_results: List[Dict[str, Any]]):
        """
        从反编译结果中提取锁操作
        
        Args:
            decompilation_results: 反编译结果列表
        """
        lock_patterns = [
            (r'\b(pthread_mutex_lock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.ACQUIRE),
            (r'\b(pthread_mutex_unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.RELEASE),
            (r'\b(pthread_mutex_init)\s*\(\s*[&]?(\w+)', LockType.MUTEX, None),
            (r'\b(pthread_rwlock_rdlock)\s*\(\s*[&]?(\w+)', LockType.RW_LOCK, LockOperation.ACQUIRE),
            (r'\b(pthread_rwlock_wrlock)\s*\(\s*[&]?(\w+)', LockType.RW_LOCK, LockOperation.ACQUIRE),
            (r'\b(pthread_rwlock_unlock)\s*\(\s*[&]?(\w+)', LockType.RW_LOCK, LockOperation.RELEASE),
            (r'\b(sem_wait)\s*\(\s*[&]?(\w+)', LockType.SEMAPHORE, LockOperation.ACQUIRE),
            (r'\b(sem_post)\s*\(\s*[&]?(\w+)', LockType.SEMAPHORE, LockOperation.RELEASE),
            (r'\b(Lock|lock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.ACQUIRE),
            (r'\b(Unlock|unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.RELEASE),
            (r'\b(mutex_lock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.ACQUIRE),
            (r'\b(mutex_unlock)\s*\(\s*[&]?(\w+)', LockType.MUTEX, LockOperation.RELEASE),
        ]
        
        import re
        
        for result in decompilation_results:
            function_name = result.get('function_name', 'unknown')
            pseudocode = result.get('pseudocode', '')
            
            for pattern, lock_type, operation in lock_patterns:
                matches = re.findall(pattern, pseudocode)
                for match in matches:
                    lock_name = match[1] if isinstance(match, tuple) else match
                    if operation:
                        self.add_lock_operation(function_name, lock_name, operation, lock_type)
    
    def _build_lock_order_graph(self) -> Dict[str, Set[str]]:
        """
        构建锁顺序依赖图
        
        Returns:
            依赖图（字典形式）
        """
        graph = defaultdict(set)
        lock_stack = {}
        
        for op in sorted(self.operations, key=lambda x: (x.get('line') is None, x.get('line', 0))):
            func = op['function']
            lock = op['lock']
            operation = op['operation']
            
            if func not in lock_stack:
                lock_stack[func] = []
            
            if operation == LockOperation.ACQUIRE:
                for held_lock in lock_stack[func]:
                    if held_lock != lock:
                        graph[held_lock].add(lock)
                        self.lock_dependencies.append(LockDependency(held_lock, lock, func))
                lock_stack[func].append(lock)
            elif operation == LockOperation.RELEASE:
                if lock in lock_stack[func]:
                    lock_stack[func].remove(lock)
        
        return graph
    
    def _detect_cycles_builtin(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """
        使用内置DFS算法检测环路
        
        Args:
            graph: 依赖图
            
        Returns:
            环路列表
        """
        cycles = []
        visited = set()
        rec_stack = set()
        
        def dfs(node, path):
            if node in rec_stack:
                cycle_start = path.index(node)
                cycle = path[cycle_start:]
                if cycle not in cycles:
                    cycles.append(cycle)
                return
            
            if node in visited:
                return
            
            visited.add(node)
            rec_stack.add(node)
            
            for neighbor in graph.get(node, []):
                dfs(neighbor, path + [node])
            
            rec_stack.remove(node)
        
        for node in graph:
            if node not in visited:
                dfs(node, [])
        
        return cycles
    
    def _detect_cycles_networkx(self, graph: Dict[str, Set[str]]) -> List[List[str]]:
        """
        使用NetworkX检测环路
        
        Args:
            graph: 依赖图
            
        Returns:
            环路列表
        """
        if not HAS_NETWORKX:
            return []
        
        G = nx.DiGraph()
        for node, neighbors in graph.items():
            for neighbor in neighbors:
                G.add_edge(node, neighbor)
        
        cycles = []
        try:
            for cycle in nx.simple_cycles(G):
                if len(cycle) >= 2:
                    cycles.append(cycle)
        except Exception as e:
            logger.error(f"NetworkX 检测环路失败: {e}")
        
        return cycles
    
    def _find_functions_in_cycle(self, cycle: List[str]) -> List[str]:
        """
        查找涉及环路的函数
        
        Args:
            cycle: 环路中的锁列表
            
        Returns:
            涉及的函数列表
        """
        functions = set()
        
        for i in range(len(cycle)):
            from_lock = cycle[i]
            to_lock = cycle[(i + 1) % len(cycle)]
            
            for dep in self.lock_dependencies:
                if dep.from_lock == from_lock and dep.to_lock == to_lock:
                    functions.add(dep.function)
        
        return list(functions)
    
    def _generate_deadlock_description(self, cycle: List[str], functions: List[str]) -> str:
        """
        生成死锁描述
        
        Args:
            cycle: 环路中的锁列表
            functions: 涉及的函数列表
            
        Returns:
            描述字符串
        """
        lock_order = " → ".join(cycle + [cycle[0]])
        func_list = ", ".join(functions)
        return f"检测到死锁环路: [{lock_order}], 涉及函数: {func_list}"
    
    def detect_deadlocks(self) -> DeadlockAnalysisResult:
        """
        执行死锁检测
        
        Returns:
            分析结果
        """
        logger.info("开始死锁检测...")
        
        if not self.operations:
            logger.warning("没有锁操作记录，跳过死锁检测")
            return DeadlockAnalysisResult()
        
        graph = self._build_lock_order_graph()
        
        if HAS_NETWORKX:
            cycles = self._detect_cycles_networkx(graph)
        else:
            cycles = self._detect_cycles_builtin(graph)
        
        deadlock_paths = []
        for cycle in cycles:
            functions = self._find_functions_in_cycle(cycle)
            deadlock_paths.append(DeadlockPath(
                cycle=cycle,
                functions=functions,
                description=self._generate_deadlock_description(cycle, functions)
            ))
        
        result = DeadlockAnalysisResult(
            deadlocks=deadlock_paths,
            lock_dependencies=self.lock_dependencies,
            total_locks=len(self.locks),
            total_functions=len(self.functions_with_locks),
            potential_deadlocks=len(deadlock_paths)
        )
        
        logger.info(f"死锁检测完成: 发现 {len(deadlock_paths)} 个潜在死锁")
        return result
    
    def export_graph_to_dot(self, output_path: str):
        """
        导出依赖图为DOT格式
        
        Args:
            output_path: 输出文件路径
        """
        graph = self._build_lock_order_graph()
        
        dot_content = ["digraph LockDependencies {"]
        
        for lock in self.locks:
            dot_content.append(f'    "{lock}" [shape=circle];')
        
        for from_lock, to_locks in graph.items():
            for to_lock in to_locks:
                dot_content.append(f'    "{from_lock}" -> "{to_lock}";')
        
        dot_content.append("}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(dot_content))
        
        logger.info(f"依赖图已导出到: {output_path}")
    
    def analyze_from_binary_info(self, binary_info: Dict[str, Any]) -> DeadlockAnalysisResult:
        """
        从二进制信息中分析死锁
        
        Args:
            binary_info: 二进制信息字典
            
        Returns:
            分析结果
        """
        decomp_results = binary_info.get('decompilation_results', [])
        if decomp_results:
            self.add_operations_from_decompilation(decomp_results)
        
        strings = binary_info.get('key_strings', []) + binary_info.get('strings', [])
        for s in strings:
            if isinstance(s, str):
                if 'mutex' in s.lower() or 'lock' in s.lower():
                    self.functions_with_locks.add(f"string_ref:{s[:20]}")
        
        return self.detect_deadlocks()
