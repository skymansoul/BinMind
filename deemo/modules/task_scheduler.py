import asyncio
import logging
import os
import sqlite3
import json
import hashlib
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from pathlib import Path
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from threading import Lock

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class TaskType(Enum):
    """任务类型枚举"""
    ANALYSIS = "analysis"
    TRANSFORMATION = "transformation"
    EXPORT = "export"
    VALIDATION = "validation"


@dataclass
class TaskResult:
    """任务执行结果"""
    task_id: str
    status: TaskStatus
    result: Any = None
    error: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration
        }


@dataclass
class TaskDependency:
    """任务依赖关系"""
    task_id: str
    condition: Optional[Callable[[TaskResult], bool]] = None
    required_status: Optional[TaskStatus] = TaskStatus.SUCCESS
    
    def is_satisfied(self, result: TaskResult) -> bool:
        """检查依赖是否满足"""
        if self.required_status and result.status != self.required_status:
            return False
        if self.condition:
            return self.condition(result)
        return True


class BaseTask(ABC):
    """任务基类"""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        task_type: TaskType = TaskType.ANALYSIS,
        dependencies: Optional[List[TaskDependency]] = None,
        timeout: Optional[int] = None,
        retries: int = 0,
        parallelizable: bool = True
    ):
        self.task_id = task_id
        self.name = name
        self.task_type = task_type
        self.dependencies = dependencies or []
        self.timeout = timeout
        self.retries = retries
        self.parallelizable = parallelizable
        self.status = TaskStatus.PENDING
        self.result: Optional[TaskResult] = None
        self._lock = Lock()
    
    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> Any:
        """执行任务"""
        pass
    
    def get_dependency_ids(self) -> List[str]:
        """获取依赖的任务ID列表"""
        return [dep.task_id for dep in self.dependencies]
    
    def can_execute(self, completed_tasks: Dict[str, TaskResult]) -> Tuple[bool, Optional[str]]:
        """检查是否可以执行（依赖是否满足）"""
        for dep in self.dependencies:
            if dep.task_id not in completed_tasks:
                return False, f"依赖任务 {dep.task_id} 尚未完成"
            
            result = completed_tasks[dep.task_id]
            if not dep.is_satisfied(result):
                return False, f"依赖任务 {dep.task_id} 条件不满足"
        
        return True, None


class SimpleTask(BaseTask):
    """简单任务实现"""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        func: Callable[[Dict[str, Any]], Any],
        **kwargs
    ):
        super().__init__(task_id, name, **kwargs)
        self.func = func
    
    def execute(self, context: Dict[str, Any]) -> Any:
        return self.func(context)


class AnalysisTask(BaseTask):
    """分析任务实现"""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        analyzer_name: str,
        analyzer_params: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        super().__init__(task_id, name, task_type=TaskType.ANALYSIS, **kwargs)
        self.analyzer_name = analyzer_name
        self.analyzer_params = analyzer_params or {}
    
    def execute(self, context: Dict[str, Any]) -> Any:
        from modules.plugin_manager import PluginManager
        
        plugin_manager = PluginManager()
        analyzer = plugin_manager.get_analyzer(self.analyzer_name)
        
        if analyzer is None:
            raise ValueError(f"分析器 {self.analyzer_name} 未找到")
        
        params = {**self.analyzer_params}
        
        for dep in self.dependencies:
            if dep.task_id in context.get('results', {}):
                dep_result = context['results'][dep.task_id]
                params[f"_{dep.task_id}"] = dep_result.result
        
        return analyzer.analyze(**params)


class TaskScheduler:
    """
    任务调度器 - 支持 DAG 编排分析任务
    
    核心功能：
    1. DAG 任务编排与依赖管理
    2. 条件执行与并行加速
    3. 任务状态持久化（SQLite）
    4. 断点续跑支持
    """
    
    def __init__(
        self,
        database_path: str = "data/scheduler.db",
        max_workers: int = 4,
        use_process_pool: bool = False
    ):
        """
        初始化任务调度器
        
        Args:
            database_path: 状态持久化数据库路径
            max_workers: 最大并发工作线程数
            use_process_pool: 是否使用进程池（适用于CPU密集型任务）
        """
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.tasks: Dict[str, BaseTask] = {}
        self.task_results: Dict[str, TaskResult] = {}
        self.max_workers = max_workers
        self.use_process_pool = use_process_pool
        
        self._init_database()
        self._lock = Lock()
    
    def _init_database(self) -> None:
        """初始化状态数据库"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE,
                created_at TEXT,
                status TEXT,
                tasks_json TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT,
                task_id TEXT,
                status TEXT,
                result TEXT,
                error TEXT,
                start_time TEXT,
                end_time TEXT,
                duration REAL,
                FOREIGN KEY (session_id) REFERENCES task_sessions(session_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_task(self, task: BaseTask) -> None:
        """添加任务到调度器"""
        if task.task_id in self.tasks:
            raise ValueError(f"任务 {task.task_id} 已存在")
        
        self.tasks[task.task_id] = task
        logger.info(f"添加任务: {task.task_id} ({task.name})")
    
    def add_tasks(self, tasks: List[BaseTask]) -> None:
        """批量添加任务"""
        for task in tasks:
            self.add_task(task)
    
    def build_dependency_graph(self) -> Dict[str, Set[str]]:
        """构建依赖图"""
        graph = {}
        for task_id, task in self.tasks.items():
            graph[task_id] = set(task.get_dependency_ids())
        return graph
    
    def _topological_sort(self) -> List[str]:
        """拓扑排序，确定任务执行顺序"""
        graph = self.build_dependency_graph()
        in_degree = {node: len(parents) for node, parents in graph.items()}
        queue = [node for node in in_degree if in_degree[node] == 0]
        result = []
        
        while queue:
            node = queue.pop(0)
            result.append(node)
            
            for dependent in graph:
                if node in graph[dependent]:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)
        
        if len(result) != len(self.tasks):
            raise ValueError("检测到循环依赖")
        
        return result
    
    def _get_ready_tasks(self, completed_ids: Set[str]) -> List[str]:
        """获取当前可执行的任务（所有依赖已完成）"""
        ready = []
        for task_id, task in self.tasks.items():
            if task.status != TaskStatus.PENDING:
                continue
            
            deps = task.get_dependency_ids()
            if all(dep in completed_ids for dep in deps):
                ready.append(task_id)
        
        return ready
    
    def _execute_task(self, task: BaseTask, context: Dict[str, Any]) -> TaskResult:
        """执行单个任务"""
        task_id = task.task_id
        start_time = datetime.now()
        
        logger.info(f"开始执行任务: {task_id}")
        
        with task._lock:
            if task.status != TaskStatus.PENDING:
                return TaskResult(
                    task_id=task_id,
                    status=TaskStatus.SKIPPED,
                    start_time=start_time,
                    end_time=datetime.now(),
                    duration=0
                )
            
            task.status = TaskStatus.RUNNING
        
        result = None
        error = None
        attempts = 0
        
        while attempts <= task.retries:
            try:
                if task.timeout:
                    loop = asyncio.new_event_loop()
                    future = asyncio.ensure_future(
                        asyncio.wait_for(
                            loop.run_in_executor(None, task.execute, context),
                            timeout=task.timeout
                        )
                    )
                    result = loop.run_until_complete(future)
                else:
                    result = task.execute(context)
                
                error = None
                break
            except Exception as e:
                attempts += 1
                error = str(e)
                logger.warning(f"任务 {task_id} 执行失败 (尝试 {attempts}/{task.retries}): {error}")
                
                if attempts > task.retries:
                    logger.error(f"任务 {task_id} 最终失败: {error}")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        if error is None:
            status = TaskStatus.SUCCESS
            logger.info(f"任务 {task_id} 完成，耗时 {duration:.2f}s")
        else:
            status = TaskStatus.FAILED
        
        with task._lock:
            task.status = status
        
        task_result = TaskResult(
            task_id=task_id,
            status=status,
            result=result,
            error=error,
            start_time=start_time,
            end_time=end_time,
            duration=duration
        )
        
        return task_result
    
    def execute_sync(self, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        """同步执行所有任务"""
        if session_id is None:
            session_id = self._generate_session_id()
        
        context = context or {}
        context['results'] = {}
        
        logger.info(f"开始执行任务会话: {session_id}")
        
        completed_ids = set()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while len(completed_ids) < len(self.tasks):
                ready_tasks = self._get_ready_tasks(completed_ids)
                pending_ready = [t for t in ready_tasks if t not in completed_ids]
                
                if not pending_ready:
                    logger.warning("没有可执行的任务，但还有任务未完成，可能存在循环依赖")
                    break
                
                logger.info(f"当前可执行任务: {pending_ready}")
                
                futures = {}
                for task_id in pending_ready:
                    task = self.tasks[task_id]
                    if task.parallelizable:
                        futures[task_id] = executor.submit(self._execute_task, task, context)
                
                for task_id, future in futures.items():
                    try:
                        result = future.result(timeout=task.timeout * 2 if task.timeout else None)
                        self.task_results[task_id] = result
                        context['results'][task_id] = result
                        completed_ids.add(task_id)
                        
                        self._save_task_result(session_id, result)
                    except Exception as e:
                        logger.error(f"任务 {task_id} 执行异常: {e}")
        
        self._update_session_status(session_id, "completed")
        logger.info(f"任务会话完成: {session_id}")
        
        return self.task_results
    
    async def execute_async(self, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        """异步执行所有任务"""
        if session_id is None:
            session_id = self._generate_session_id()
        
        context = context or {}
        context['results'] = {}
        
        logger.info(f"开始异步执行任务会话: {session_id}")
        
        completed_ids = set()
        
        while len(completed_ids) < len(self.tasks):
            ready_tasks = self._get_ready_tasks(completed_ids)
            pending_ready = [t for t in ready_tasks if t not in completed_ids]
            
            if not pending_ready:
                logger.warning("没有可执行的任务，但还有任务未完成")
                break
            
            logger.info(f"当前可执行任务: {pending_ready}")
            
            tasks = []
            for task_id in pending_ready:
                task = self.tasks[task_id]
                if task.parallelizable:
                    tasks.append(self._execute_task_async(task, context))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for task_id, result in zip(pending_ready, results):
                    if isinstance(result, Exception):
                        result = TaskResult(
                            task_id=task_id,
                            status=TaskStatus.FAILED,
                            error=str(result)
                        )
                    
                    self.task_results[task_id] = result
                    context['results'][task_id] = result
                    completed_ids.add(task_id)
                    
                    self._save_task_result(session_id, result)
        
        self._update_session_status(session_id, "completed")
        logger.info(f"异步任务会话完成: {session_id}")
        
        return self.task_results
    
    async def _execute_task_async(self, task: BaseTask, context: Dict[str, Any]) -> TaskResult:
        """异步执行单个任务"""
        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._execute_task,
            task,
            context
        )
    
    def _generate_session_id(self) -> str:
        """生成唯一会话ID"""
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    def _save_task_result(self, session_id: str, result: TaskResult) -> None:
        """保存任务结果到数据库"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO task_results
            (session_id, task_id, status, result, error, start_time, end_time, duration)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            result.task_id,
            result.status.value,
            json.dumps(result.result),
            result.error,
            result.start_time.isoformat() if result.start_time else None,
            result.end_time.isoformat() if result.end_time else None,
            result.duration
        ))
        
        conn.commit()
        conn.close()
    
    def _update_session_status(self, session_id: str, status: str) -> None:
        """更新会话状态"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE task_sessions SET status = ? WHERE session_id = ?
        ''', (status, session_id))
        
        conn.commit()
        conn.close()
    
    def save_session(self, session_id: str) -> None:
        """保存会话配置"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        tasks_json = json.dumps({
            task_id: {
                "task_id": task.task_id,
                "name": task.name,
                "task_type": task.task_type.value,
                "dependencies": [dep.task_id for dep in task.dependencies],
                "timeout": task.timeout,
                "retries": task.retries,
                "parallelizable": task.parallelizable
            }
            for task_id, task in self.tasks.items()
        })
        
        cursor.execute('''
            INSERT OR REPLACE INTO task_sessions
            (session_id, created_at, status, tasks_json)
            VALUES (?, ?, ?, ?)
        ''', (session_id, datetime.now().isoformat(), "running", tasks_json))
        
        conn.commit()
        conn.close()
    
    def load_session(self, session_id: str) -> bool:
        """加载已保存的会话（用于断点续跑）"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT tasks_json FROM task_sessions WHERE session_id = ?
        ''', (session_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False
        
        try:
            tasks_data = json.loads(row[0])
            
            for task_id, data in tasks_data.items():
                dependencies = [
                    TaskDependency(dep_id)
                    for dep_id in data.get("dependencies", [])
                ]
                
                task = SimpleTask(
                    task_id=task_id,
                    name=data["name"],
                    func=lambda x: None,
                    dependencies=dependencies,
                    timeout=data.get("timeout"),
                    retries=data.get("retries", 0),
                    parallelizable=data.get("parallelizable", True)
                )
                
                self.add_task(task)
            
            cursor.execute('''
                SELECT task_id, status, result, error, start_time, end_time, duration
                FROM task_results WHERE session_id = ?
            ''', (session_id,))
            
            for row in cursor.fetchall():
                task_id, status, result, error, start_time, end_time, duration = row
                
                self.task_results[task_id] = TaskResult(
                    task_id=task_id,
                    status=TaskStatus(status),
                    result=json.loads(result) if result else None,
                    error=error,
                    start_time=datetime.fromisoformat(start_time) if start_time else None,
                    end_time=datetime.fromisoformat(end_time) if end_time else None,
                    duration=duration
                )
                
                if task_id in self.tasks:
                    self.tasks[task_id].status = TaskStatus(status)
            
            logger.info(f"已加载会话: {session_id}")
            conn.close()
            return True
            
        except Exception as e:
            logger.error(f"加载会话失败: {e}")
            conn.close()
            return False
    
    def get_session_ids(self) -> List[str]:
        """获取所有会话ID"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT session_id FROM task_sessions ORDER BY created_at DESC
        ''')
        
        sessions = [row[0] for row in cursor.fetchall()]
        conn.close()
        return sessions
    
    def get_session_status(self, session_id: str) -> Optional[str]:
        """获取会话状态"""
        conn = sqlite3.connect(str(self.database_path))
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT status FROM task_sessions WHERE session_id = ?
        ''', (session_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        return row[0] if row else None
    
    def generate_report(self) -> str:
        """生成执行报告"""
        lines = [
            "# 任务调度执行报告",
            "",
            f"**生成时间**: {datetime.now().isoformat()}",
            f"**总任务数**: {len(self.tasks)}",
            "",
            "## 任务状态统计",
            ""
        ]
        
        status_counts = {}
        for task in self.tasks.values():
            status_counts[task.status.value] = status_counts.get(task.status.value, 0) + 1
        
        lines.append("| 状态 | 数量 |")
        lines.append("|------|------|")
        for status, count in status_counts.items():
            lines.append(f"| {status} | {count} |")
        
        lines.append("")
        lines.append("## 任务详细结果")
        lines.append("")
        
        for task_id, result in self.task_results.items():
            task = self.tasks.get(task_id)
            lines.append(f"### {task.name} ({task_id})")
            lines.append(f"- **状态**: {result.status.value}")
            if result.duration:
                lines.append(f"- **耗时**: {result.duration:.2f}s")
            if result.error:
                lines.append(f"- **错误**: {result.error}")
            lines.append("")
        
        return "\n".join(lines)


class AnalysisPipeline:
    """
    自动化分析流水线
    
    提供从"反编译 → 静态分析 → 符号执行 → 利用生成"的全自动化流程
    """
    
    def __init__(self, scheduler: Optional[TaskScheduler] = None):
        self.scheduler = scheduler or TaskScheduler()
        self.tasks: List[BaseTask] = []
    
    def build_default_pipeline(self, binary_path: str) -> 'AnalysisPipeline':
        """构建默认分析流水线"""
        self.tasks = [
            SimpleTask(
                task_id="info_collect",
                name="信息收集",
                func=lambda ctx: self._collect_info(ctx, binary_path),
                parallelizable=True
            ),
            AnalysisTask(
                task_id="decompile",
                name="反编译",
                analyzer_name="decompiler",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("info_collect")],
                parallelizable=True
            ),
            AnalysisTask(
                task_id="static_analysis",
                name="静态分析",
                analyzer_name="static_analyzer",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("decompile")],
                parallelizable=True
            ),
            AnalysisTask(
                task_id="symbolic_exec",
                name="符号执行",
                analyzer_name="symbolic_executor",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("static_analysis")],
                parallelizable=False,
                timeout=300
            ),
            AnalysisTask(
                task_id="vuln_detection",
                name="漏洞检测",
                analyzer_name="vulnerability_detector",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("static_analysis"), TaskDependency("symbolic_exec")],
                parallelizable=True
            ),
            AnalysisTask(
                task_id="exploit_gen",
                name="利用生成",
                analyzer_name="exploit_generator",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("vuln_detection")],
                parallelizable=False,
                timeout=600,
                retries=1
            ),
            AnalysisTask(
                task_id="report_gen",
                name="报告生成",
                analyzer_name="report_generator",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("exploit_gen", condition=lambda r: r.status == TaskStatus.SUCCESS)]
            )
        ]
        
        for task in self.tasks:
            self.scheduler.add_task(task)
        
        return self
    
    def _collect_info(self, ctx: Dict[str, Any], binary_path: str) -> Dict[str, Any]:
        """收集二进制信息"""
        from modules.info_collect import BinaryInfoCollector
        
        collector = BinaryInfoCollector(binary_path)
        return collector.collect()
    
    def run(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        """运行流水线"""
        session_id = self.scheduler._generate_session_id()
        self.scheduler.save_session(session_id)
        
        return self.scheduler.execute_sync(session_id, context)
    
    async def run_async(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        """异步运行流水线"""
        session_id = self.scheduler._generate_session_id()
        self.scheduler.save_session(session_id)
        
        return await self.scheduler.execute_async(session_id, context)


def create_default_pipeline(binary_path: str) -> AnalysisPipeline:
    """创建默认分析流水线"""
    return AnalysisPipeline().build_default_pipeline(binary_path)
