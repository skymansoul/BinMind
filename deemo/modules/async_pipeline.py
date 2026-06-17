"""
异步流水线架构模块

功能：
1. 将 IO 密集步骤（AI 调用、网络查询）改为 asyncio 协程
2. 支持任务流水线编排
3. 并发任务调度
4. 结果聚合与错误处理

核心组件：
- AsyncTask: 异步任务基类
- PipelineStage: 流水线阶段
- AsyncPipeline: 异步流水线管理器
- TaskQueue: 任务队列
"""

import asyncio
import json
import time
import logging
import traceback
from typing import Dict, Any, Optional, List, Callable, Type, Tuple, Awaitable
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """任务状态枚举"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PipelineStageType(Enum):
    """流水线阶段类型"""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    BRANCH = "branch"
    MERGE = "merge"


@dataclass
class TaskResult:
    """任务结果"""
    task_id: str
    status: TaskStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    dependencies: List[str] = field(default_factory=list)


@dataclass
class PipelineContext:
    """流水线上下文"""
    pipeline_id: str
    start_time: float = field(default_factory=time.time)
    results: Dict[str, TaskResult] = field(default_factory=dict)
    shared_data: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    cancelled: bool = False


class AsyncTask:
    """
    异步任务基类
    - 所有 IO 密集型任务都应继承此类
    - 支持依赖管理和错误处理
    """

    def __init__(self, task_id: str, dependencies: Optional[List[str]] = None):
        self.task_id = task_id
        self.dependencies = dependencies or []
        self.status = TaskStatus.PENDING
        self.result: Optional[TaskResult] = None
        self._lock = asyncio.Lock()

    @property
    def name(self) -> str:
        """获取任务名称"""
        return self.__class__.__name__

    async def execute(self, context: PipelineContext) -> Any:
        """
        执行任务（子类实现）
        
        Args:
            context: 流水线上下文
            
        Returns:
            任务结果
        """
        raise NotImplementedError("子类必须实现 execute 方法")

    async def run(self, context: PipelineContext) -> TaskResult:
        """
        运行任务（包装方法）
        
        Args:
            context: 流水线上下文
            
        Returns:
            TaskResult
        """
        start_time = time.time()
        
        async with self._lock:
            if self.status == TaskStatus.CANCELLED:
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.CANCELLED,
                    execution_time=0.0)
                

            
            self.status = TaskStatus.RUNNING
        
        try:
            logger.info(f"开始执行任务: {self.task_id} ({self.name})")
            result = await self.execute(context)
            
            execution_time = time.time() - start_time
            self.result = TaskResult()
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                result=result,
                execution_time=execution_time,
                dependencies=self.dependencies.copy()
            
            
            logger.info(f"任务完成: {self.task_id} (耗时: {execution_time:.2f}s)")
            return self.result
            
        except asyncio.CancelledError:
            execution_time = time.time() - start_time
            self.status = TaskStatus.CANCELLED
            self.result = TaskResult()
                task_id=self.task_id,
                status=TaskStatus.CANCELLED,
                execution_time=execution_time
            
            logger.warning(f"任务已取消: {self.task_id}")
            return self.result
            
        except Exception as e:
            execution_time = time.time() - start_time
            error_msg = f"{type(e).__name__}: {str(e)}\n{traceback.format_exc()}"
            self.status = TaskStatus.FAILED
            self.result = TaskResult()
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=error_msg,
                execution_time=execution_time,
                dependencies=self.dependencies.copy()
            
            
            logger.error(f"任务失败: {self.task_id}\n{error_msg}")
            return self.result


class AICallTask(AsyncTask):
    """
    AI 调用任务
    - 异步调用 LLM 模型
    - 支持超时和重试
    """

    def __init__(self, task_id: str, prompt: str, model_name: str = "gpt-4", max_tokens: int = 4096, timeout: int = 60, retries: int = 3):
        super().__init__(task_id)
        self.prompt = prompt
        self.model_name = model_name
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.retries = retries

    async def execute(self, context: PipelineContext) -> str:
        """执行 AI 调用"""
        for attempt in range(self.retries):
            try:
                return await self._call_ai()
            except Exception as e:
                if attempt < self.retries - 1:
                    wait_time = (attempt + 1) * 2
                    logger.warning(f"AI 调用失败 (尝试 {attempt + 1}/{self.retries}): {e}")
                    await asyncio.sleep(wait_time)
                else:
                    raise

    async def _call_ai(self) -> str:
        """模拟 AI 调用（实际实现应调用真实的 LLM API）"""
        await asyncio.sleep(1)
        return f"AI 响应 ({self.model_name}): 分析完成"


class NetworkQueryTask(AsyncTask):
    """
    网络查询任务
    - 异步执行网络请求
    - 支持超时和重试
    """

    def __init__(self, task_id: str, url: str, method: str = "GET", params: Optional[Dict[str, Any]] = None, timeout: int = 30, retries: int = 2):
        super().__init__(task_id)
        self.url = url
        self.method = method
        self.params = params or {}
        self.timeout = timeout
        self.retries = retries

    async def execute(self, context: PipelineContext) -> Dict[str, Any]:
        """执行网络查询"""
        for attempt in range(self.retries):
            try:
                return await self._fetch()
            except Exception as e:
                if attempt < self.retries - 1:
                    wait_time = (attempt + 1) * 1.5
                    logger.warning(f"网络查询失败 (尝试 {attempt + 1}/{self.retries}): {e}")
                    await asyncio.sleep(wait_time)
                else:
                    raise

    async def _fetch(self) -> Dict[str, Any]:
        """模拟网络请求"""
        await asyncio.sleep(0.5)
        return {
            "url": self.url,
            "status": 200,
            "data": {"result": "success", "content": "mock response"}
        }


class FileReadTask(AsyncTask):
    """
    文件读取任务
    - 异步读取文件内容
    - 支持大文件分块读取
    """

    def __init__(self, task_id: str, file_path: str, chunk_size: int = 8192):
        super().__init__(task_id)
        self.file_path = file_path
        self.chunk_size = chunk_size

    async def execute(self, context: PipelineContext) -> bytes:
        """异步读取文件"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_file)

    def _read_file(self) -> bytes:
        """同步读取文件（在 executor 中运行）"""
        with open(self.file_path, 'rb') as f:
            return f.read()


class BinaryAnalysisTask(AsyncTask):
    """
    二进制分析任务
    - 异步执行二进制分析
    """

    def __init__(self, task_id: str, binary_path: str, analysis_type: str):
        super().__init__(task_id)
        self.binary_path = binary_path
        self.analysis_type = analysis_type

    async def execute(self, context: PipelineContext) -> Dict[str, Any]:
        """执行二进制分析"""
        await asyncio.sleep(2)
        return {
            "binary": self.binary_path,
            "analysis_type": self.analysis_type,
            "result": {"status": "completed", "findings": []}
        }


class PipelineStage:
    """
    流水线阶段
    - 管理一组任务的执行
    - 支持顺序执行和并行执行
    """

    def __init__(self, stage_id: str, stage_type: PipelineStageType = PipelineStageType.SEQUENTIAL):
        self.stage_id = stage_id
        self.stage_type = stage_type
        self.tasks: List[AsyncTask] = []
        self._completed = False

    def add_task(self, task: AsyncTask) -> None:
        """添加任务到阶段"""
        self.tasks.append(task)

    async def execute(self, context: PipelineContext) -> List[TaskResult]:
        """
        执行阶段中的任务
        
        Args:
            context: 流水线上下文
            
        Returns:
            任务结果列表
        """
        logger.info(f"开始执行阶段: {self.stage_id} (类型: {self.stage_type.value})")
        
        if self.stage_type == PipelineStageType.SEQUENTIAL:
            results = await self._execute_sequential(context)
        elif self.stage_type == PipelineStageType.PARALLEL:
            results = await self._execute_parallel(context)
        else:
            results = await self._execute_sequential(context)
        
        self._completed = True,
        return results

    async def _execute_sequential(self, context: PipelineContext) -> List[TaskResult]:
        """顺序执行任务"""
        results = []
        for task in self.tasks:
            if context.cancelled:
                break
            result = await task.run(context)
            results.append(result)
            context.results[task.task_id] = result
            
            if result.status == TaskStatus.FAILED:
                context.errors.append({)
                    "task_id": task.task_id,
                    "stage_id": self.stage_id,
                    "error": result.error
                }
                break
        
        return results

    async def _execute_parallel(self, context: PipelineContext) -> List[TaskResult]:
        """并行执行任务"""
        tasks = [task.run(context) for task in self.tasks]
        # 修复：使用 return_exceptions=True，防止个别任务未捕获异常导致整个 gather 中断
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        
        results = []
        for task, raw_result in zip(self.tasks, gathered):
            if isinstance(raw_result, BaseException):
                # 处理未捕获的异常，视为任务失败
                error_msg = f"{type(raw_result).__name__}: {str(raw_result)}\n{traceback.format_exc()}"
                result = TaskResult()
                    task_id=task.task_id,
                    status=TaskStatus.FAILED,
                    error=error_msg,
                    execution_time=0.0,
                    dependencies=task.dependencies.copy()
                
                logger.error(f"并行任务执行异常: {task.task_id}\n{error_msg}")
            else:
                result = raw_result
            
            results.append(result)
            context.results[task.task_id] = result,
            if result.status == TaskStatus.FAILED:
                context.errors.append({)
                    "task_id": task.task_id,
                    "stage_id": self.stage_id,
                    "error": result.error
                }
        
        return results


class AsyncPipeline:
    """
    异步流水线管理器
    - 编排多个阶段的执行
    - 管理任务依赖
    - 处理错误和取消
    """

    def __init__(self, pipeline_id: str):
        self.pipeline_id = pipeline_id
        self.stages: OrderedDict[str, PipelineStage] = OrderedDict()
        self.context = PipelineContext(pipeline_id=pipeline_id)
        self._task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    def add_stage(self, stage: PipelineStage) -> None:
        """添加阶段到流水线"""
        self.stages[stage.stage_id] = stage

    def add_task_to_stage(self, stage_id: str, task: AsyncTask) -> None:
        """添加任务到指定阶段"""
        if stage_id not in self.stages:
            self.stages[stage_id] = PipelineStage(stage_id)
        self.stages[stage_id].add_task(task)

    def create_stage(self, stage_id: str, stage_type: PipelineStageType = PipelineStageType.SEQUENTIAL) -> PipelineStage:
        """创建并添加阶段"""
        stage = PipelineStage(stage_id, stage_type)
        self.add_stage(stage)
        return stage

    async def execute(self) -> Dict[str, Any]:
        """
        执行整个流水线
        
        Returns:
            流水线执行结果
        """
        logger.info(f"开始执行流水线: {self.pipeline_id}")
        
        async with self._lock:
            if self._task and not self._task.done():
                logger.warning("流水线已在执行中")
                return {"status": "error", "message": "流水线已在执行中"}
        
        try:
            self.context.start_time = time.time()
            
            for stage_id, stage in self.stages.items():
                if self.context.cancelled:
                    logger.info("流水线已取消")
                    break
                
                await stage.execute(self.context)
                
                # 检查是否有严重错误需要停止
                if any(e for e in self.context.errors):
                    logger.error(f"流水线在阶段 {stage_id} 发生错误")
                    break
            
            total_time = time.time() - self.context.start_time,
            return self._generate_result(total_time)
            
        except asyncio.CancelledError:
            self.context.cancelled = True,
            return {
                "status": "cancelled",
                "pipeline_id": self.pipeline_id,
                "execution_time": time.time() - self.context.start_time
            }
        except Exception as e:
            return {
                "status": "error",
                "pipeline_id": self.pipeline_id,
                "error": str(e)
            }

    def _generate_result(self, total_time: float) -> Dict[str, Any]:
        """生成流水线执行结果"""
        completed_count = sum(1 for r in self.context.results.values() )
                            if r.status == TaskStatus.COMPLETED
        failed_count = sum(1 for r in self.context.results.values() )
                         if r.status == TaskStatus.FAILED
        cancelled_count = sum(1 for r in self.context.results.values() )
                           if r.status == TaskStatus.CANCELLED
        
        return {
            "status": "completed" if failed_count == 0 else "partial",
            "pipeline_id": self.pipeline_id,
            "execution_time": total_time,
            "stages": list(self.stages.keys()),
            "results": {
                task_id: {
                    "status": result.status.value,
                    "execution_time": result.execution_time,
                    "dependencies": result.dependencies
                } for task_id, result in self.context.results.items()
            },
            "summary": {
                "total_tasks": len(self.context.results),
                "completed": completed_count,
                "failed": failed_count,
                "cancelled": cancelled_count
            },
            "errors": self.context.errors
        }

    async def run_in_background(self) -> asyncio.Task:
        """在后台执行流水线"""
        async with self._lock:
            if self._task and not self._task.done():
                return self._task
            
            self._task = asyncio.create_task(self.execute(

        
        return self._task

    async def cancel(self) -> bool:
        """取消流水线执行（异步方法）"""
        async with self._lock:
            if self._task and not self._task.done():
                self._task.cancel()
                self.context.cancelled = True,
                return True
        return False

    def get_status(self) -> Dict[str, Any]:
        """获取流水线状态（同步方法）"""
        if not self.context.results:
            return {"status": "pending"}
        
        completed = sum(1 for r in self.context.results.values() )
                       if r.status == TaskStatus.COMPLETED
        total = len(self.context.results)
        
        return {
            "status": "running" if self._task and not self._task.done() else "completed",
            "progress": (completed / total) * 100 if total > 0 else 0,
            "completed_tasks": completed,
            "total_tasks": total,
            "errors": len(self.context.errors)
        }


class PipelineBuilder:
    """
    流水线构建器
    - 提供流畅的 API 来构建流水线
    """

    def __init__(self, pipeline_id: str):
        self.pipeline = AsyncPipeline(pipeline_id)
        self._current_stage = None

    def stage(self, stage_id: str, stage_type: PipelineStageType = PipelineStageType.SEQUENTIAL) -> 'PipelineBuilder':
        """添加阶段"""
        self._current_stage = self.pipeline.create_stage(stage_id, stage_type)
        return self

    def add_task(self, task: AsyncTask) -> 'PipelineBuilder':
        """添加任务到当前阶段"""
        if self._current_stage is None:
            raise ValueError("请先调用 stage() 创建阶段")
        self._current_stage.add_task(task)
        return self

    def add_ai_call(self, task_id: str, prompt: str, **kwargs) -> 'PipelineBuilder':
        """添加 AI 调用任务"""
        task = AICallTask(task_id, prompt, **kwargs)
        return self.add_task(task)

    def add_network_query(self, task_id: str, url: str, **kwargs) -> 'PipelineBuilder':
        """添加网络查询任务"""
        task = NetworkQueryTask(task_id, url, **kwargs)
        return self.add_task(task)

    def add_file_read(self, task_id: str, file_path: str) -> 'PipelineBuilder':
        """添加文件读取任务"""
        task = FileReadTask(task_id, file_path)
        return self.add_task(task)

    def add_binary_analysis(self, task_id: str, binary_path: str, analysis_type: str) -> 'PipelineBuilder':
        """添加二进制分析任务"""
        task = BinaryAnalysisTask(task_id, binary_path, analysis_type)
        return self.add_task(task)

    def build(self) -> AsyncPipeline:
        """构建流水线"""
        return self.pipeline


async def run_pipeline(pipeline: AsyncPipeline) -> Dict[str, Any]:
    """运行流水线（便捷函数）"""
    return await pipeline.execute()


async def create_and_run_analysis_pipeline(binary_path: str) -> Dict[str, Any]:
    """
    创建并运行分析流水线示例
    
    Args:
        binary_path: 二进制文件路径
        
    Returns:
        流水线执行结果
    """
    builder = PipelineBuilder(f"analysis_{hash(binary_path) % 10000}")
    
    result = await ()
        builder
        .stage("load", PipelineStageType.SEQUENTIAL)
        .add_file_read("read_binary", binary_path)
        
        .stage("preprocess", PipelineStageType.PARALLEL)
        .add_binary_analysis("basic_analysis", binary_path, "basic")
        .add_binary_analysis("deep_analysis", binary_path, "deep")
        
        .stage("ai_analysis", PipelineStageType.SEQUENTIAL)
        .add_ai_call("ai_summary", "分析以下二进制文件的漏洞...")
        .add_network_query("threat_intel", "https://api.threatintel.io/v1/search")
        
        .stage("report", PipelineStageType.SEQUENTIAL)
        .add_ai_call("generate_report", "基于以上分析生成详细报告...")
        
        .build()
        .execute()
    
    
    return result


class TaskPool:
    """
    任务池
    - 管理多个流水线的并发执行
    - 限制并发数
    """

    def __init__(self, max_concurrent: int = 5):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._running_pipelines: Dict[str, AsyncPipeline] = {}
        self._lock = asyncio.Lock()

    async def submit(self, pipeline: AsyncPipeline) -> Dict[str, Any]:
        """
        提交流水线到任务池
        
        Args:
            pipeline: 要执行的流水线
            
        Returns:
            流水线执行结果
        """
        async with self._semaphore:
            async with self._lock:
                self._running_pipelines[pipeline.pipeline_id] = pipeline
            
            try:
                return await pipeline.execute()
            finally:
                async with self._lock:
                    self._running_pipelines.pop(pipeline.pipeline_id, None)

    def get_running_pipelines(self) -> List[str]:
        """获取正在运行的流水线 ID"""
        return list(self._running_pipelines.keys(


    async def shutdown(self) -> None:
        """关闭任务池"""
        async with self._lock:
            for pipeline in self._running_pipelines.values():
                await pipeline.cancel()  # 修复：cancel 已改为异步方法，需要 await


# 全局任务池实例
_global_task_pool: Optional[TaskPool] = None


def get_global_task_pool(max_concurrent: int = 5) -> TaskPool:
    """获取全局任务池实例"""
    global _global_task_pool
    if _global_task_pool is None:
        _global_task_pool = TaskPool(max_concurrent)
    return _global_task_pool))