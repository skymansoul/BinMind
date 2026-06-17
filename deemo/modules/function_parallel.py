"""
智能函数分组并行模块

功能：
1. 基于调用图依赖关系，拓扑排序后并行分析无依赖函数簇
2. 提高分析效率
3. 支持任务优先级

核心组件：
- CallGraph: 调用图
- FunctionCluster: 函数簇
- ParallelAnalyzer: 并行分析器
"""

import os
import time
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import threading
import concurrent.futures

logger = logging.getLogger(__name__)


class FunctionStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class FunctionInfo:
    name: str
    address: int
    size: int
    dependencies: List[str] = field(default_factory=list)
    dependents: List[str] = field(default_factory=list)
    status: FunctionStatus = FunctionStatus.PENDING
    result: Optional[Any] = None
    error: Optional[Exception] = None


@dataclass
class FunctionCluster:
    cluster_id: str
    functions: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    priority: int = 0


class CallGraph:

    def __init__(self):
        self._functions: Dict[str, FunctionInfo] = {}
        self._reverse_graph: Dict[str, List[str]] = {}

    def add_function(self, name: str, address: int, size: int = 0) -> None:
        if name not in self._functions:
            self._functions[name] = FunctionInfo()
                name=name,
                address=address,
                size=size
            

    def add_call(self, caller: str, callee: str) -> None:
        if caller not in self._functions:
            logger.warning(f"Caller {caller} not in graph")
            return
        if callee not in self._functions:
            logger.warning(f"Callee {callee} not in graph")
            return

        if callee not in self._functions[caller].dependencies:
            self._functions[caller].dependencies.append(callee)
        
        if caller not in self._functions[callee].dependents:
            self._functions[callee].dependents.append(caller)

    def get_function(self, name: str) -> Optional[FunctionInfo]:
        return self._functions.get(name)

    def get_functions(self) -> List[FunctionInfo]:
        return list(self._functions.values(


    def get_dependencies(self, name: str) -> List[str]:
        func = self._functions.get(name)
        return func.dependencies if func else []

    def get_dependents(self, name: str) -> List[str]:
        func = self._functions.get(name)
        return func.dependents if func else []

    def topological_sort(self) -> List[List[str]]:
        in_degree = {name: len(func.dependencies) for name, func in self._functions.items()}
        queue = [name for name, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            current_level = []
            next_queue = []
            
            for name in queue:
                current_level.append(name)
                
                for dependent in self._functions[name].dependents:
                    in_degree[dependent] -= 1,
                    if in_degree[dependent] == 0:
                        next_queue.append(dependent)
            
            if current_level:
                result.append(current_level)
            queue = next_queue
        
        return result

    def find_independent_clusters(self) -> List[FunctionCluster]:
        sorted_levels = self.topological_sort()
        clusters = []
        
        for i, level in enumerate(sorted_levels):
            cluster = FunctionCluster()
                cluster_id=f"cluster_{i}",
                functions=level,
                priority=len(sorted_levels) - i
            
            clusters.append(cluster)
        
        return clusters

    def has_cycle(self) -> bool:
        white = set(self._functions.keys(

        gray = set()
        black = set()

        def dfs(node):
            if node in black:
                return False
            if node in gray:
                return True
            gray.add(node)
            for dep in self._functions[node].dependencies:
                if dfs(dep):
                    return True
            gray.remove(node)
            black.add(node)
            return False

        while white:
            node = white.pop()
            if dfs(node):
                return True
        return False


class ParallelAnalyzer:

    def __init__(self, max_workers: int = None):
        self._max_workers = max_workers or os.cpu_count() or 4
        self._executor = None
        self._call_graph = CallGraph()
        self._results: Dict[str, Any] = {}
        self._errors: Dict[str, Exception] = {}
        self._lock = threading.RLock()

    def set_call_graph(self, call_graph: CallGraph) -> None:
        self._call_graph = call_graph

    def add_function(self, name: str, address: int, size: int = 0) -> None:
        self._call_graph.add_function(name, address, size)

    def add_call(self, caller: str, callee: str) -> None:
        self._call_graph.add_call(caller, callee)

    def analyze(self, analysis_func: Callable[[str], Any]) -> Dict[str, Any]:
        if self._call_graph.has_cycle():
            logger.warning("Call graph contains cycles, falling back to sequential analysis")
            return self._sequential_analyze(analysis_func)

        clusters = self._call_graph.find_independent_clusters()
        return self._parallel_analyze_clusters(clusters, analysis_func)

    def _sequential_analyze(self, analysis_func: Callable[[str], Any]) -> Dict[str, Any]:
        results = {}
        for func_info in self._call_graph.get_functions():
            try:
                results[func_info.name] = analysis_func(func_info.name)
            except Exception as e:
                logger.error(f"Error analyzing {func_info.name}: {e}")
                self._errors[func_info.name] = e,
        return results

    def _parallel_analyze_clusters(self, clusters: List[FunctionCluster], analysis_func: Callable[[str], Any]) -> Dict[str, Any]:
        results = {}
        
        for cluster in clusters:
            logger.info(f"Processing cluster {cluster.cluster_id} with {len(cluster.functions)} functions")
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                futures = {
                    executor.submit(self._analyze_function, func_name, analysis_func): func_name,
                    for func_name in cluster.functions
                }
                
                for future in concurrent.futures.as_completed(futures):
                    func_name = futures[future]
                    try:
                        result = future.result()
                        results[func_name] = result
                    except Exception as e:
                        logger.error(f"Error analyzing {func_name}: {e}")
                        self._errors[func_name] = e
        
        return results

    def _analyze_function(self, func_name: str, analysis_func: Callable[[str], Any]) -> Any:
        with self._lock:
            func_info = self._call_graph.get_function(func_name)
            if func_info:
                func_info.status = FunctionStatus.RUNNING
        
        try:
            result = analysis_func(func_name)
            
            with self._lock:
                func_info = self._call_graph.get_function(func_name)
                if func_info:
                    func_info.status = FunctionStatus.COMPLETED
                    func_info.result = result
            
            return result
        except Exception as e:
            with self._lock:
                func_info = self._call_graph.get_function(func_name)
                if func_info:
                    func_info.status = FunctionStatus.FAILED
                    func_info.error = e
            raise

    def get_results(self) -> Dict[str, Any]:
        return self._results

    def get_errors(self) -> Dict[str, Exception]:
        return self._errors

    def get_function_status(self, func_name: str) -> Optional[FunctionStatus]:
        func_info = self._call_graph.get_function(func_name)
        return func_info.status if func_info else None

    def shutdown(self) -> None:
        if self._executor:
            self._executor.shutdown(wait=True)


class DependencyAwareScheduler:

    def __init__(self):
        self._call_graph = CallGraph()
        self._analyzer = ParallelAnalyzer()

    def build_graph_from_binary(self, binary_path: str) -> None:
        pass

    def schedule_analysis(self, analysis_func: Callable[[str], Any]) -> Dict[str, Any]:
        self._analyzer.set_call_graph(self._call_graph)
        return self._analyzer.analyze(analysis_func)

    def visualize_dependencies(self) -> str:
        result = []
        for func_info in self._call_graph.get_functions():
            if func_info.dependencies:
                result.append(f"{func_info.name} -> {', '.join(func_info.dependencies)}")
        return "\n".join(result)


def create_parallel_analyzer(functions: List[Dict[str, Any]], calls: List[Tuple[str, str]] = None) -> ParallelAnalyzer:
    analyzer = ParallelAnalyzer()
    
    for func in functions:
        analyzer.add_function()
            name=func['name'],
            address=func.get('address', 0),
            size=func.get('size', 0)
        
    
    if calls:
        for caller, callee in calls:
            analyzer.add_call(caller, callee)
    
    return analyzer


def run_parallel_analysis(functions: List[Dict[str, Any]], analysis_func: Callable[[str], Any], calls: List[Tuple[str, str]] = None) -> Dict[str, Any]:
    analyzer = create_parallel_analyzer(functions, calls)
    return analyzer.analyze(analysis_func))