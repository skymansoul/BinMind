"""
分布式分析集群模块

基于 Celery/Redis 实现远程 worker 弹性伸缩，大规模分发分析任务。

核心功能：
1. 集群管理器：监控和管理多个 worker 节点
2. 任务调度器：智能分配任务到合适的 worker
3. 弹性伸缩：根据负载自动调整 worker 数量
4. 故障恢复：自动重试失败任务
5. 任务队列管理：优先级队列、任务分发策略
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable, Tuple
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field

from modules.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)

CELERY_AVAILABLE = False
try:
    from celery import Celery
    from celery.exceptions import SoftTimeLimitExceeded
    CELERY_AVAILABLE = True
except ImportError:
    logger.warning("[DistributedCluster] Celery 未安装，分布式功能不可用")

REDIS_PY_AVAILABLE = False
try:
    import redis
    REDIS_PY_AVAILABLE = True
except ImportError:
    logger.warning("[DistributedCluster] redis-py 未安装，集群管理功能受限")


class ClusterStatus(Enum):
    """集群状态枚举"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class TaskPriority(Enum):
    """任务优先级枚举"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class WorkerInfo:
    """Worker 节点信息"""
    worker_id: str
    hostname: str
    status: str
    is_online: bool
    current_task: Optional[str]
    tasks_completed: int
    tasks_failed: int
    load_average: float
    memory_usage_mb: float
    tags: List[str]
    last_heartbeat: datetime


@dataclass
class ClusterStats:
    """集群统计信息"""
    total_workers: int
    active_workers: int
    busy_workers: int
    pending_tasks: int
    completed_tasks: int
    failed_tasks: int
    status: ClusterStatus


@dataclass
class TaskInfo:
    """任务信息"""
    task_id: str
    binary_path: str
    status: str
    priority: TaskPriority
    submitted_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    worker_id: Optional[str]
    result: Optional[Dict[str, Any]]
    error: Optional[str]


class DistributedCluster(BaseAnalyzer):
    """
    分布式分析集群管理器
    
    负责管理多个分析节点，实现任务分发、负载均衡和故障恢复。
    """
    
    def __init__(self, broker_url: str = None, result_backend: str = None):
        """
        初始化分布式集群管理器
        
        Args:
            broker_url: Redis/MQ broker URL
            result_backend: 结果存储后端 URL
        """
        self.broker_url = broker_url or "redis://localhost:6379/0"
        self.result_backend = result_backend or "redis://localhost:6379/1"
        self.app: Optional[Celery] = None
        self.redis_client = None
        self._init_celery()
        self._init_redis()
        
        self._cluster_lock = threading.RLock()
        self._task_cache: Dict[str, TaskInfo] = {}
        
    def _init_celery(self):
        """初始化 Celery 应用"""
        if not CELERY_AVAILABLE:
            return
        
        try:
            self.app = Celery()
                'deemo_cluster',
                broker=self.broker_url,
                backend=self.result_backend,
                broker_connection_retry_on_startup=True
            
            
            self.app.conf.update()
                task_serializer='json',
                accept_content=['json'],
                result_serializer='json',
                timezone='Asia/Shanghai',
                enable_utc=True,
                task_track_started=True,
                task_time_limit=7200,
                task_soft_time_limit=7000,
                worker_prefetch_multiplier=1,
                worker_max_tasks_per_child=10,
                task_default_queue='deemo_tasks',
                task_routes={
                    'modules.distributed_cluster.analyze_high': {'queue': 'deemo_high'},
                    'modules.distributed_cluster.analyze_medium': {'queue': 'deemo_medium'},
                    'modules.distributed_cluster.analyze_low': {'queue': 'deemo_low'},
                },
                task_default_priority=5,
                task_acks_late=True,
                task_reject_on_worker_lost=True,
            
            
            self._register_tasks()
            logger.info("[DistributedCluster] Celery 应用初始化成功")
            
        except Exception as e:
            logger.error(f"[DistributedCluster] Celery 初始化失败: {e}")
    
    def _init_redis(self):
        """初始化 Redis 客户端"""
        if not REDIS_PY_AVAILABLE:
            return
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(self.broker_url)
            
            self.redis_client = redis.Redis()
                host=parsed.hostname or 'localhost',
                port=parsed.port or 6379,
                password=parsed.password,
                db=0,
                decode_responses=True
            
            self.redis_client.ping()
            logger.info("[DistributedCluster] Redis 客户端连接成功")
            
        except Exception as e:
            logger.error(f"[DistributedCluster] Redis 连接失败: {e}")
    
    def _register_tasks(self):
        """注册 Celery 任务"""
        if not self.app:
            return
        
        @self.app.task()
            bind=True,
            name='modules.distributed_cluster.analyze_high',
            max_retries=3,
            default_retry_delay=60,
            time_limit=3600,
            soft_time_limit=3500
        
        def analyze_high(self, binary_path: str, options: Dict[str, Any] = None):
            return self._execute_analysis(binary_path, options)
        
        @self.app.task()
            bind=True,
            name='modules.distributed_cluster.analyze_medium',
            max_retries=3,
            default_retry_delay=60,
            time_limit=7200,
            soft_time_limit=7000
        
        def analyze_medium(self, binary_path: str, options: Dict[str, Any] = None):
            return self._execute_analysis(binary_path, options)
        
        @self.app.task()
            bind=True,
            name='modules.distributed_cluster.analyze_low',
            max_retries=3,
            default_retry_delay=120,
            time_limit=14400,
            soft_time_limit=14000
        
        def analyze_low(self, binary_path: str, options: Dict[str, Any] = None):
            return self._execute_analysis(binary_path, options)
        
        self.analyze_high = analyze_high
        self.analyze_medium = analyze_medium
        self.analyze_low = analyze_low
    
    def _execute_analysis(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """执行分析任务"""
        from main import run_pipeline
        
        options = options or {}
        
        logger.info(f"[DistributedCluster] 开始分析: {binary_path}")
        
        try:
            result = run_pipeline()
                binary_path=binary_path,
                **options
            
            
            return {
                'success': True,
                'binary_path': binary_path,
                'result': result,
                'completed_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"[DistributedCluster] 分析失败: {e}")
            return {
                'success': False,
                'binary_path': binary_path,
                'error': str(e),
                'completed_at': datetime.now().isoformat()
            }
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行分布式分析
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径（必需）
                - options: 分析选项
                - priority: 任务优先级 (high/medium/low)
        
        Returns:
            分析任务信息
        """
        binary_path = kwargs.get('binary_path')
        if not binary_path:
            return {'success': False, 'error': 'binary_path 是必需参数'}
        
        priority = kwargs.get('priority', 'medium').lower()
        options = kwargs.get('options', {})
        
        task_id = self.submit_task(binary_path, options, priority)
        
        if task_id:
            return {
                'success': True,
                'task_id': task_id,
                'message': '任务已提交到集群'
            }
        else:
            return {
                'success': False,
                'error': '任务提交失败'
            }
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DistributedCluster",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="分布式分析集群管理器，支持大规模任务分发和弹性伸缩",
            author="BinaryAnalysisPlatform",
            dependencies=["celery", "redis"],
            supported_platforms=["all"])
        

    
    def submit_task(, self, binary_path: str, options: Dict[str, Any] = None, priority: str = 'medium') -> Optional[str]:
        """
        提交分析任务到集群
        
        Args:
            binary_path: 二进制文件路径
            options: 分析选项
            priority: 任务优先级
        
        Returns:
            任务ID，失败返回 None
        """
        if not self.app:
            logger.error("[DistributedCluster] Celery 应用未初始化")
            return None
        
        if not os.path.exists(binary_path):
            logger.error(f"[DistributedCluster] 文件不存在: {binary_path}")
            return None
        
        options = options or {}
        
        try:
            task_func = {
                'high': self.analyze_high,
                'medium': self.analyze_medium,
                'low': self.analyze_low
            }.get(priority, self.analyze_medium)
            
            task = task_func.delay(binary_path, options)
            
            task_info = TaskInfo()
                task_id=task.id,
                binary_path=binary_path,
                status='pending',
                priority=TaskPriority(priority),
                submitted_at=datetime.now(),
                started_at=None,
                completed_at=None,
                worker_id=None,
                result=None,
                error=None
            
            
            with self._cluster_lock:
                self._task_cache[task.id] = task_info
            
            logger.info(f"[DistributedCluster] 任务已提交: {task.id} (优先级: {priority})")
            return task.id
            
        except Exception as e:
            logger.error(f"[DistributedCluster] 任务提交失败: {e}")
            return None
    
    def get_task_result(self, task_id: str, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """
        获取任务结果
        
        Args:
            task_id: 任务ID
            timeout: 等待超时时间（秒）
        
        Returns:
            任务结果，未完成返回 None
        """
        if not self.app:
            return None
        
        try:
            from celery.result import AsyncResult
            result = AsyncResult(task_id, app=self.app)
            
            if result.ready():
                if result.successful():
                    return result.result
                else:
                    return {
                        'success': False,
                        'error': str(result.result)
                    }
            return None
            
        except Exception as e:
            logger.error(f"[DistributedCluster] 获取任务结果失败: {e}")
            return None
    
    def get_cluster_stats(self) -> ClusterStats:
        """
        获取集群统计信息
        
        Returns:
            集群统计信息
        """
        if not self.redis_client:
            return ClusterStats(
                total_workers=0,
                active_workers=0,
                busy_workers=0,
                pending_tasks=0,
                completed_tasks=0,
                failed_tasks=0,
                status=ClusterStatus.DEGRADED)
            

        
        try:
            # 获取 Worker 状态
            active_workers = self.redis_client.smembers('deemo:workers:active')
            total_workers = len(active_workers)
            
            active_count = 0
            busy_count = 0
            now = datetime.now()
            
            for worker_id in active_workers:
                heartbeat_key = f"deemo:worker:{worker_id}"
                data = self.redis_client.hgetall(heartbeat_key)
                
                if data:
                    last_heartbeat_str = data.get('last_heartbeat', '')
                    try:
                        last_heartbeat = datetime.fromisoformat(last_heartbeat_str)
                        if (now - last_heartbeat) < timedelta(seconds=60):
                            active_count += 1,
                            if data.get('status') == 'busy':
                                busy_count += 1
                    except Exception:
                        pass
            
            # 获取任务统计
            pending_tasks = 0,
            for queue in ['deemo_high', 'deemo_medium', 'deemo_low']:
                pending_tasks += self.redis_client.llen(f"celery@{queue}")
            
            completed_tasks = int(self.redis_client.get('deemo:stats:completed') or '0')
            failed_tasks = int(self.redis_client.get('deemo:stats:failed') or '0')
            
            # 确定集群状态
            if active_count == 0:
                status = ClusterStatus.UNHEALTHY
            elif busy_count == active_count and pending_tasks > active_count * 2:
                status = ClusterStatus.DEGRADED
            else:
                status = ClusterStatus.HEALTHY
            
            return ClusterStats(
                total_workers=total_workers,
                active_workers=active_count,
                busy_workers=busy_count,
                pending_tasks=pending_tasks,
                completed_tasks=completed_tasks,
                failed_tasks=failed_tasks,
                status=status)
            

            
        except Exception as e:
            logger.error(f"[DistributedCluster] 获取集群统计失败: {e}")
            return ClusterStats(
                total_workers=0,
                active_workers=0,
                busy_workers=0,
                pending_tasks=0,
                completed_tasks=0,
                failed_tasks=0,
                status=ClusterStatus.UNHEALTHY)
            

    
    def get_all_workers(self) -> List[WorkerInfo]:
        """
        获取所有 Worker 节点信息
        
        Returns:
            Worker 节点列表
        """
        if not self.redis_client:
            return []
        
        try:
            workers = []
            active_workers = self.redis_client.smembers('deemo:workers:active')
            now = datetime.now()
            
            for worker_id in active_workers:
                heartbeat_key = f"deemo:worker:{worker_id}"
                data = self.redis_client.hgetall(heartbeat_key)
                
                if not data:
                    continue
                
                last_heartbeat_str = data.get('last_heartbeat', '')
                is_online = False
                
                if last_heartbeat_str:
                    try:
                        last_heartbeat = datetime.fromisoformat(last_heartbeat_str)
                        is_online = (now - last_heartbeat) < timedelta(seconds=60)
                    except Exception:
                        pass
                
                workers.append(WorkerInfo(
                    worker_id=worker_id,
                    hostname=data.get('hostname', ''),
                    status=data.get('status', 'unknown') if is_online else 'offline',
                    is_online=is_online,
                    current_task=data.get('current_task', ''),
                    tasks_completed=int(data.get('tasks_completed', '0')),
                    tasks_failed=int(data.get('tasks_failed', '0')),
                    load_average=float(data.get('load_average', '0.0')),
                    memory_usage_mb=float(data.get('memory_usage_mb', '0.0')),
                    tags=json.loads(data.get('tags', '[]')),
                    last_heartbeat=datetime.fromisoformat(last_heartbeat_str) if last_heartbeat_str else now
                

            
            return workers
            
        except Exception as e:
            logger.error(f"[DistributedCluster] 获取 Worker 列表失败: {e}")
            return []
    
    def cancel_task(self, task_id: str) -> bool:
        """
        取消任务
        
        Args:
            task_id: 任务ID
        
        Returns:
            是否取消成功
        """
        if not self.app:
            return False
        
        try:
            from celery.result import AsyncResult
            result = AsyncResult(task_id, app=self.app)
            result.revoke(terminate=True)
            
            with self._cluster_lock:
                if task_id in self._task_cache:
                    del self._task_cache[task_id]
            
            logger.info(f"[DistributedCluster] 任务已取消: {task_id}")
            return True
            
        except Exception as e:
            logger.error(f"[DistributedCluster] 取消任务失败: {e}")
            return False
    
    def submit_batch_tasks(, self, binary_paths: List[str], options: Dict[str, Any] = None, priority: str = 'medium') -> List[str]:
        """
        批量提交任务
        
        Args:
            binary_paths: 二进制文件路径列表
            options: 分析选项（应用于所有任务）
            priority: 任务优先级
        
        Returns:
            任务ID列表
        """
        task_ids = []
        options = options or {}
        
        for binary_path in binary_paths:
            task_id = self.submit_task(binary_path, options, priority)
            if task_id:
                task_ids.append(task_id)
        
        logger.info(f"[DistributedCluster] 批量提交 {len(task_ids)} 个任务")
        return task_ids
    
    def start_cluster_monitor(self, interval: int = 30):
        """
        启动集群监控线程
        
        Args:
            interval: 监控间隔（秒）
        """
        def monitor_loop():
            while True:
                try:
                    stats = self.get_cluster_stats()
                    logger.info()
                        f"[ClusterMonitor] 状态: {stats.status.value} | "
                        f"Worker: {stats.active_workers}/{stats.total_workers} | "
                        f"任务: {stats.pending_tasks} 待处理 | "
                        f"已完成: {stats.completed_tasks}"
                    
                except Exception as e:
                    logger.error(f"[ClusterMonitor] 监控失败: {e}")
                
                time.sleep(interval)
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("[DistributedCluster] 集群监控已启动")
