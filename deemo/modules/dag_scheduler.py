"""
DAG任务调度引擎增强模块

增强功能：
1. 高级条件执行（支持复杂条件表达式）
2. 智能并行加速（基于依赖图的动态调度）
3. 全流程编排（反编译→静态分析→符号执行→利用生成）
4. 动态优先级调整
5. 任务组批量管理
6. 执行策略模式（保守/标准/激进）
7. TIMEOUT状态支持
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from abc import ABC, abstractmethod
from datetime import datetime
import logging
import json

from modules.task_scheduler import (
    TaskStatus as BaseTaskStatus,
    TaskResult as BaseTaskResult,
    TaskDependency as BaseTaskDependency,
    TaskPriority as BaseTaskPriority,
    BaseTask,
    SimpleTask,
    AnalysisTask,
    TaskScheduler,
    AnalysisPipeline
)

logger = logging.getLogger(__name__)


class ExecutionStrategy(Enum):
    """执行策略枚举"""
    CONSERVATIVE = "conservative"
    STANDARD = "standard"
    AGGRESSIVE = "aggressive"


class TaskStatus(BaseTaskStatus):
    """扩展任务状态枚举"""
    TIMEOUT = "timeout"


@dataclass
class TaskResult(BaseTaskResult):
    """扩展任务执行结果"""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        result = super().to_dict()
        result["metadata"] = self.metadata
        return result


@dataclass
class TaskDependency(BaseTaskDependency):
    """扩展任务依赖关系"""
    condition_expression: Optional[str] = None
    retry_count: int = 0
    
    def is_satisfied(self, result: TaskResult) -> bool:
        if not super().is_satisfied(result):
            return False
        
        if self.condition_expression:
            return self._evaluate_expression(result)
        return True
    
    def _evaluate_expression(self, result: TaskResult) -> bool:
        try:
            local_vars = {
                'result': result,
                'status': result.status.value,
                'success': result.status == TaskStatus.SUCCESS,
                'failed': result.status == TaskStatus.FAILED,
                'duration': result.duration or 0,
                'has_result': result.result is not None
            }
            if result.result is not None:
                local_vars['value'] = result.result
            
            return bool(eval(self.condition_expression, {}, local_vars)

        except Exception as e:
            logger.warning(f"条件表达式评估失败: {e}")
            return False


class DecisionTask(BaseTask):
    """决策任务 - 根据条件选择执行路径"""
    
    def __init__(
        self,
        task_id: str,
        name: str,
        condition: Callable[[Dict[str, Any]], bool],
        success_task_id: Optional[str] = None,
        failure_task_id: Optional[str] = None,
        **kwargs
    ):
        from modules.task_scheduler import TaskType
        super().__init__(task_id, name, task_type=TaskType.DECISION, **kwargs)
        self.condition = condition
        self.success_task_id = success_task_id
        self.failure_task_id = failure_task_id
    
    def execute(self, context: Dict[str, Any]) -> Any:
        result = self.condition(context)
        return {
            'condition_result': result,
            'next_task': self.success_task_id if result else self.failure_task_id
        }


class TaskGroup:
    """任务组 - 批量管理相关任务"""
    
    def __init__(self, group_id: str, name: str, tasks: Optional[List[BaseTask]] = None):
        self.group_id = group_id
        self.name = name
        self.tasks = tasks or []
        self.status = TaskStatus.PENDING
    
    def add_task(self, task: BaseTask) -> None:
        task.group_id = self.group_id
        self.tasks.append(task)
    
    def get_task_ids(self) -> List[str]:
        return [t.task_id for t in self.tasks]
    
    def can_execute(self, completed_tasks: Dict[str, TaskResult]) -> bool:
        for task in self.tasks:
            can_exec, _ = task.can_execute(completed_tasks)
            if can_exec:
                return True
        return False
    
    def get_ready_tasks(self, completed_tasks: Dict[str, TaskResult]) -> List[BaseTask]:
        return [t for t in self.tasks if t.can_execute(completed_tasks)[0]]


class DAGTaskScheduler(TaskScheduler):
    """
    DAG任务调度器 - 增强版
    
    核心增强功能：
    1. 执行策略模式（保守/标准/激进）
    2. 任务组批量管理
    3. 条件表达式支持
    4. 动态优先级调整
    5. 增强的断点续跑支持
    """
    
    def __init__(
        self,
        database_path: str = "data/scheduler.db",
        max_workers: int = 4,
        use_process_pool: bool = False,
        progress_callback=None,
        strategy: ExecutionStrategy = ExecutionStrategy.STANDARD
    ):
        super().__init__(database_path, max_workers, use_process_pool, progress_callback)
        self.strategy = strategy
        self.task_groups: Dict[str, TaskGroup] = {}
    
    def create_task_group(self, group_id: str, name: str) -> TaskGroup:
        if group_id in self.task_groups:
            raise ValueError(f"任务组 {group_id} 已存在")
        
        group = TaskGroup(group_id, name)
        self.task_groups[group_id] = group
        return group
    
    def add_task(self, task: BaseTask) -> None:
        super().add_task(task)
        
        if hasattr(task, 'group_id') and task.group_id and task.group_id in self.task_groups:
            self.task_groups[task.group_id].add_task(task)
    
    def _adjust_parallel_degree(self, completed_count: int, total_count: int) -> int:
        if self.strategy == ExecutionStrategy.CONSERVATIVE:
            return min(self.max_workers, 1)
        elif self.strategy == ExecutionStrategy.AGGRESSIVE:
            return self.max_workers
        else:
            progress = completed_count / total_count if total_count > 0 else 0
            if progress < 0.3:
                return min(self.max_workers, 2)
            elif progress < 0.7:
                return min(self.max_workers, 3)
            else:
                return self.max_workers
    
    def _execute_task(self, task: BaseTask, context: Dict[str, Any]) -> TaskResult:
        task_id = task.task_id
        start_time = datetime.now()
        
        logger.info(f"开始执行任务: {task_id}")
        
        with task._lock:
            if task.status != BaseTaskStatus.PENDING:
                return TaskResult(
                    task_id=task_id,
                    status=TaskStatus.SKIPPED,
                    start_time=start_time,
                    end_time=datetime.now(),
                    duration=0
                )

            
            task.status = BaseTaskStatus.RUNNING
        
        result = None
        error = None
        attempts = 0
        
        while attempts <= task.retries:
            try:
                if task.timeout:
                    import asyncio
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
            except asyncio.TimeoutError:
                attempts += 1
                error = "任务执行超时"
                logger.warning(f"任务 {task_id} 超时 (尝试 {attempts}/{task.retries})")
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
            if "超时" in error:
                status = TaskStatus.TIMEOUT
        
        with task._lock:
            task.status = status
        
        return TaskResult(
            task_id=task_id,
            status=status,
            result=result,
            error=error,
            start_time=start_time,
            end_time=end_time,
            duration=duration
        )

    
    def execute_sync(self, session_id: Optional[str] = None, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        if session_id is None:
            session_id = self._generate_session_id()
        
        context = context or {}
        context['results'] = {}
        context['session_id'] = session_id
        context['scheduler'] = self
        
        logger.info(f"开始执行任务会话: {session_id}")
        self.save_session(session_id)
        
        completed_ids = set()
        self._load_completed_tasks(session_id, completed_ids, context)
        
        total_tasks = len(self.tasks)
        
        from concurrent.futures import ThreadPoolExecutor
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            while len(completed_ids) < total_tasks:
                if self._cancelled.is_set():
                    logger.info("任务执行已取消")
                    break
                
                parallel_degree = self._adjust_parallel_degree(len(completed_ids), total_tasks)
                
                ready_tasks = self._get_ready_tasks_with_priority(completed_ids)
                pending_ready = [t for t in ready_tasks if t not in completed_ids]
                
                if not pending_ready:
                    logger.warning("没有可执行的任务，但还有任务未完成")
                    break
                
                logger.info(f"当前可执行任务（按优先级）: {pending_ready}")
                logger.info(f"当前并行度: {parallel_degree}")
                
                futures = {}
                with self._lock:
                    for i, task_id in enumerate(pending_ready):
                        if i >= parallel_degree and self.strategy != ExecutionStrategy.AGGRESSIVE:
                            break
                        
                        task = self.tasks[task_id]
                        if task.parallelizable and task.status == BaseTaskStatus.PENDING:
                            if self.progress_callback:
                                self.progress_callback.on_task_start(task_id)
                            futures[task_id] = executor.submit(self._execute_task_with_callback, task, context)
                            self._running_futures[task_id] = futures[task_id]
                
                for task_id, future in futures.items():
                    try:
                        task = self.tasks[task_id]
                        result = future.result(timeout=task.timeout * 2 + 10 if task.timeout else None)
                        self.task_results[task_id] = result
                        context['results'][task_id] = result
                        completed_ids.add(task_id)
                        
                        self._save_task_result(session_id, result)
                        
                        if self.progress_callback:
                            self.progress_callback.on_task_complete(task_id, result)
                    except Exception as e:
                        logger.error(f"任务 {task_id} 执行异常: {e}")
                        self.task_results[task_id] = TaskResult(
                            task_id=task_id,
                            status=TaskStatus.FAILED,
                            error=str(e)
                        )
                        completed_ids.add(task_id)
                
                with self._lock:
                    for task_id in futures:
                        if task_id in self._running_futures:
                            del self._running_futures[task_id]
        
        self._update_session_status(session_id, "completed" if not self._cancelled.is_set() else "cancelled")
        logger.info(f"任务会话完成: {session_id}")
        
        return self.task_results
    
    def _save_task_result(self, session_id: str, result: TaskResult) -> None:
        import sqlite3
        
        conn = sqlite3.connect(str(self.database_path)

        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO task_results
            (session_id, task_id, status, result, error, start_time, end_time, duration, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            session_id,
            result.task_id,
            result.status.value,
            json.dumps(result.result),
            result.error,
            result.start_time.isoformat() if result.start_time else None,
            result.end_time.isoformat() if result.end_time else None,
            result.duration,
            json.dumps(result.metadata)
        )

        
        conn.commit()
        conn.close()
    
    def save_session(self, session_id: str) -> None:
        import sqlite3
        
        conn = sqlite3.connect(str(self.database_path)

        cursor = conn.cursor()
        
        tasks_json = json.dumps({
            task_id: {
                "task_id": task.task_id,
                "name": task.name,
                "task_type": task.task_type.value,
                "dependencies": [{
                    "task_id": dep.task_id,
                    "required_status": dep.required_status.value if dep.required_status else None,
                    "on_failure": dep.on_failure,
                    "condition_expression": getattr(dep, 'condition_expression', None)
                } for dep in task.dependencies],
                "timeout": task.timeout,
                "retries": task.retries,
                "parallelizable": task.parallelizable,
                "priority": task.priority.value,
                "group_id": getattr(task, 'group_id', None),
                "status": task.status.value
            }
            for task_id, task in self.tasks.items()
        })
        
        cursor.execute('''
            INSERT OR REPLACE INTO task_sessions
            (session_id, created_at, status, strategy, tasks_json)
            VALUES (?, ?, ?, ?, ?)
        ''', (session_id, datetime.now().isoformat(), "running", self.strategy.value, tasks_json)

        
        conn.commit()
        conn.close()
        
        for task_id, result in self.task_results.items():
            self._save_task_result(session_id, result)
    
    def _load_completed_tasks(self, session_id: str, completed_ids: Set[str], context: Dict[str, Any]) -> None:
        import sqlite3
        
        conn = sqlite3.connect(str(self.database_path)

        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT task_id, status, result, error, start_time, end_time, duration, metadata
            FROM task_results WHERE session_id = ?
        ''', (session_id)

        
        for row in cursor.fetchall():
            task_id, status, result, error, start_time, end_time, duration, metadata = row
            
            if status == TaskStatus.SUCCESS.value:
                completed_ids.add(task_id)
                self.task_results[task_id] = TaskResult(
                    task_id=task_id,
                    status=TaskStatus(status),
                    result=json.loads(result) if result else None,
                    error=error,
                    start_time=datetime.fromisoformat(start_time) if start_time else None,
                    end_time=datetime.fromisoformat(end_time) if end_time else None,
                    duration=duration,
                    metadata=json.loads(metadata) if metadata else {}
                )
                context['results'][task_id] = self.task_results[task_id]
                
                if task_id in self.tasks:
                    self.tasks[task_id].status = TaskStatus(status)
        
        conn.close()
        logger.info(f"已加载 {len(completed_ids)} 个已完成任务")
    
    def generate_report(self) -> str:
        lines = [
            "# DAG任务调度执行报告",
            "",
            f"**生成时间**: {datetime.now().isoformat()}",
            f"**执行策略**: {self.strategy.value}",
            f"**总任务数**: {len(self.tasks)}",
            f"**任务组数**: {len(self.task_groups)}",
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
        
        if self.task_groups:
            lines.append("")
            lines.append("## 任务组统计")
            lines.append("")
            lines.append("| 任务组 | 任务数 |")
            lines.append("|--------|--------|")
            for group_id, group in self.task_groups.items():
                lines.append(f"| {group.name} | {len(group.tasks)} |")
        
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


class EnhancedAnalysisPipeline(AnalysisPipeline):
    """
    自动化分析流水线 - 增强版
    
    提供从"反编译 → 静态分析 → 符号执行 → 利用生成"的全自动化流程
    支持：
    1. 条件分支执行
    2. 并行加速
    3. 智能决策节点
    4. 多种执行策略
    """
    
    def __init__(self, scheduler: Optional[DAGTaskScheduler] = None):
        if scheduler is None:
            scheduler = DAGTaskScheduler()
        super().__init__(scheduler)
        self.decision_points: List[DecisionTask] = []
    
    def build_default_pipeline(self, binary_path: str) -> 'EnhancedAnalysisPipeline':
        from modules.task_scheduler import TaskDependency
        
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
            DecisionTask(
                task_id="vuln_decision",
                name="漏洞检测决策",
                condition=lambda ctx: ctx.get('results', {}).get('static_analysis') is not None,
                success_task_id="vuln_detection",
                failure_task_id="skip_vuln",
                dependencies=[TaskDependency("static_analysis"), TaskDependency("symbolic_exec")]
            ),
            AnalysisTask(
                task_id="vuln_detection",
                name="漏洞检测",
                analyzer_name="vulnerability_detector",
                analyzer_params={"binary_path": binary_path},
                dependencies=[TaskDependency("vuln_decision", condition_expression="value['condition_result'] == True")],
                parallelizable=True
            ),
            SimpleTask(
                task_id="skip_vuln",
                name="跳过漏洞检测",
                func=lambda ctx: {"skipped": True, "reason": "前置条件不满足"},
                dependencies=[TaskDependency("vuln_decision", condition_expression="value['condition_result'] == False")]
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
                dependencies=[TaskDependency("exploit_gen", condition_expression="success")]
            )
        ]
        
        self.decision_points = [t for t in self.tasks if isinstance(t, DecisionTask)]
        
        for task in self.tasks:
            self.scheduler.add_task(task)
        
        return self
    
    def add_parallel_branch(self, branch_tasks: List[BaseTask]) -> None:
        for task in branch_tasks:
            self.tasks.append(task)
            self.scheduler.add_task(task)
    
    def add_decision_point(self, decision_task: DecisionTask) -> None:
        self.decision_points.append(decision_task)
        self.tasks.append(decision_task)
        self.scheduler.add_task(decision_task)
    
    def run(self, context: Optional[Dict[str, Any]] = None) -> Dict[str, TaskResult]:
        session_id = self.scheduler._generate_session_id()
        self.scheduler.save_session(session_id)
        
        return self.scheduler.execute_sync(session_id, context)


def create_default_pipeline(binary_path: str, strategy: ExecutionStrategy = ExecutionStrategy.STANDARD) -> EnhancedAnalysisPipeline:
    """创建默认分析流水线"""
    scheduler = DAGTaskScheduler(strategy=strategy)
    return EnhancedAnalysisPipeline(scheduler).build_default_pipeline(binary_path)