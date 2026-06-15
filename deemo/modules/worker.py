"""
分布式分析任务 Worker 模块

基于 Celery + Redis 实现的分布式任务队列 Worker
功能包括：
- 任务执行：运行完整的分析流水线
- 任务优先级：支持高/中/低优先级队列
- 任务重试：自动重试失败的任务
- 结果缓存：避免重复分析相同二进制
- Worker 心跳：上报 Worker 状态和负载
- Hooks 集成：支持 8 个钩子点的插件扩展
"""

import os
import sys
import json
import uuid
import logging
import hashlib
import socket
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path

from config import (
    Config, 
    get_celery_broker_url, 
    get_celery_result_backend,
    mask_redis_url,
    get_task_cache_key,
    ensure_directories,
    SensitiveFilter
)

logger = logging.getLogger(__name__)

CELERY_AVAILABLE = False
try:
    from celery import Celery
    from celery.exceptions import SoftTimeLimitExceeded
    CELERY_AVAILABLE = True
except ImportError:
    logger.warning("[Worker] Celery 未安装，分布式功能不可用")


REDIS_PY_AVAILABLE = False
try:
    import redis
    REDIS_PY_AVAILABLE = True
except ImportError:
    logger.warning("[Worker] redis-py 未安装，心跳功能受限")


_worker_app: Optional['Celery'] = None
_redis_client = None
_heartbeat_thread: Optional[threading.Thread] = None
_heartbeat_stop_event = threading.Event()


def get_redis_client():
    """
    获取 Redis 客户端实例
    
    Returns:
        Redis 客户端实例，不可用时返回 None
    """
    global _redis_client
    
    if _redis_client is not None:
        return _redis_client
    
    if not REDIS_PY_AVAILABLE:
        return None
    
    try:
        from urllib.parse import urlparse
        redis_url = get_celery_broker_url()
        parsed = urlparse(redis_url)
        
        db = 0
        if parsed.path and parsed.path.startswith('/'):
            try:
                db = int(parsed.path.lstrip('/').split('/')[0])
            except (ValueError, IndexError):
                pass
        
        client = redis.Redis(
            host=parsed.hostname,
            port=parsed.port or 6379,
            password=parsed.password,
            db=db,
            decode_responses=True
        )
        
        client.ping()
        _redis_client = client
        logger.info("[Worker] Redis 客户端连接成功")
        return _redis_client
    except Exception as e:
        logger.warning(f"[Worker] Redis 客户端连接失败: {e}")
        return None


def get_worker_app() -> Optional['Celery']:
    """
    获取或创建 Celery 应用实例（单例）
    
    Returns:
        Celery 应用实例，Celery 未安装时返回 None
    """
    global _worker_app
    
    if _worker_app is not None:
        return _worker_app
    
    if not CELERY_AVAILABLE:
        return None
    
    broker_url = get_celery_broker_url()
    result_backend = get_celery_result_backend()
    
    logger.info(f"[Worker] 初始化 Celery 应用，Broker: {mask_redis_url(broker_url)}")
    
    _worker_app = Celery(
        'deemo_worker',
        broker=broker_url,
        backend=result_backend,
        broker_connection_retry_on_startup=True
    )
    
    _worker_app.conf.update(
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
        task_default_queue=Config.CELERY_TASK_QUEUE,
        task_routes={
            'modules.worker.analyze_binary_high': {'queue': f'{Config.CELERY_TASK_QUEUE}_high'},
            'modules.worker.analyze_binary_medium': {'queue': f'{Config.CELERY_TASK_QUEUE}_medium'},
            'modules.worker.analyze_binary_low': {'queue': f'{Config.CELERY_TASK_QUEUE}_low'},
        },
        task_default_priority=5,
        task_acks_late=True,
        task_reject_on_worker_lost=True,
    )
    
    return _worker_app


def get_worker_id() -> str:
    """
    生成唯一的 Worker ID
    
    Returns:
        Worker ID 字符串
    """
    hostname = socket.gethostname()
    pid = os.getpid()
    return f"{hostname}-{pid}-{uuid.uuid4().hex[:8]}"


def register_worker_heartbeat(worker_id: str, tags: List[str] = None) -> bool:
    """
    注册 Worker 心跳
    
    Args:
        worker_id: Worker ID
        tags: Worker 标签列表
        
    Returns:
        是否注册成功
    """
    r = get_redis_client()
    if r is None:
        return False
    
    try:
        heartbeat_key = f"deemo:worker:{worker_id}"
        status = {
            'worker_id': worker_id,
            'hostname': socket.gethostname(),
            'pid': os.getpid(),
            'status': 'idle',
            'current_task': None,
            'tasks_completed': 0,
            'tasks_failed': 0,
            'load_average': 0.0,
            'memory_usage_mb': 0,
            'tags': tags or [],
            'started_at': datetime.now().isoformat(),
            'last_heartbeat': datetime.now().isoformat()
        }
        
        r.hset(heartbeat_key, mapping=status)
        r.expire(heartbeat_key, Config.WORKER_TIMEOUT * 2)
        r.sadd('deemo:workers:active', worker_id)
        
        logger.info(f"[Worker] Worker {worker_id} 已注册心跳")
        return True
    except Exception as e:
        logger.warning(f"[Worker] 注册心跳失败: {e}")
        return False


def update_worker_heartbeat(
    worker_id: str, 
    status: str = 'idle', 
    current_task: str = None,
    tasks_completed: int = 0,
    tasks_failed: int = 0
) -> bool:
    """
    更新 Worker 心跳
    
    Args:
        worker_id: Worker ID
        status: Worker 状态 (idle, busy, error)
        current_task: 当前任务 ID
        tasks_completed: 已完成任务数
        tasks_failed: 失败任务数
        
    Returns:
        是否更新成功
    """
    r = get_redis_client()
    if r is None:
        return False
    
    try:
        heartbeat_key = f"deemo:worker:{worker_id}"
        import psutil
        
        process = psutil.Process()
        memory_mb = process.memory_info().rss / (1024 * 1024)
        
        load_avg = 0.0
        try:
            load_avg = psutil.getloadavg()[0] if hasattr(psutil, 'getloadavg') else 0.0
        except Exception:
            pass
        
        updates = {
            'status': status,
            'current_task': current_task or '',
            'tasks_completed': str(tasks_completed),
            'tasks_failed': str(tasks_failed),
            'load_average': str(load_avg),
            'memory_usage_mb': str(round(memory_mb, 2)),
            'last_heartbeat': datetime.now().isoformat()
        }
        
        r.hset(heartbeat_key, mapping=updates)
        r.expire(heartbeat_key, Config.WORKER_TIMEOUT * 2)
        
        return True
    except ImportError:
        try:
            heartbeat_key = f"deemo:worker:{worker_id}"
            updates = {
                'status': status,
                'current_task': current_task or '',
                'tasks_completed': str(tasks_completed),
                'tasks_failed': str(tasks_failed),
                'last_heartbeat': datetime.now().isoformat()
            }
            r.hset(heartbeat_key, mapping=updates)
            r.expire(heartbeat_key, Config.WORKER_TIMEOUT * 2)
            return True
        except Exception as e:
            logger.debug(f"[Worker] 更新心跳失败: {e}")
            return False
    except Exception as e:
        logger.debug(f"[Worker] 更新心跳失败: {e}")
        return False


def unregister_worker_heartbeat(worker_id: str) -> bool:
    """
    注销 Worker 心跳
    
    Args:
        worker_id: Worker ID
        
    Returns:
        是否注销成功
    """
    r = get_redis_client()
    if r is None:
        return False
    
    try:
        heartbeat_key = f"deemo:worker:{worker_id}"
        r.delete(heartbeat_key)
        r.srem('deemo:workers:active', worker_id)
        
        logger.info(f"[Worker] Worker {worker_id} 已注销心跳")
        return True
    except Exception as e:
        logger.debug(f"[Worker] 注销心跳失败: {e}")
        return False


def get_all_workers_status() -> Dict[str, Any]:
    """
    获取所有 Worker 的状态
    
    Returns:
        包含所有 Worker 状态的字典
    """
    r = get_redis_client()
    if r is None:
        return {
            'timestamp': datetime.now().isoformat(),
            'workers': [],
            'total_workers': 0,
            'active_workers': 0,
            'busy_workers': 0
        }
    
    try:
        active_workers = r.smembers('deemo:workers:active')
        workers = []
        now = datetime.now()
        active_count = 0
        busy_count = 0
        
        for worker_id in active_workers:
            heartbeat_key = f"deemo:worker:{worker_id}"
            data = r.hgetall(heartbeat_key)
            
            if not data:
                continue
            
            last_heartbeat_str = data.get('last_heartbeat', '')
            is_online = False
            if last_heartbeat_str:
                try:
                    last_heartbeat = datetime.fromisoformat(last_heartbeat_str)
                    is_online = (now - last_heartbeat) < timedelta(seconds=Config.WORKER_TIMEOUT)
                except Exception:
                    pass
            
            status = data.get('status', 'unknown')
            if is_online:
                active_count += 1
                if status == 'busy':
                    busy_count += 1
            else:
                status = 'offline'
            
            worker_info = {
                'worker_id': worker_id,
                'hostname': data.get('hostname', ''),
                'pid': int(data.get('pid', '0')),
                'status': status,
                'is_online': is_online,
                'current_task': data.get('current_task', ''),
                'tasks_completed': int(data.get('tasks_completed', '0')),
                'tasks_failed': int(data.get('tasks_failed', '0')),
                'load_average': float(data.get('load_average', '0.0')),
                'memory_usage_mb': float(data.get('memory_usage_mb', '0.0')),
                'tags': json.loads(data.get('tags', '[]')),
                'started_at': data.get('started_at', ''),
                'last_heartbeat': last_heartbeat_str
            }
            workers.append(worker_info)
        
        workers.sort(key=lambda x: x['hostname'])
        
        return {
            'timestamp': datetime.now().isoformat(),
            'workers': workers,
            'total_workers': len(workers),
            'active_workers': active_count,
            'busy_workers': busy_count,
            'timeout_seconds': Config.WORKER_TIMEOUT
        }
    except Exception as e:
        logger.error(f"[Worker] 获取 Worker 状态失败: {e}")
        return {
            'timestamp': datetime.now().isoformat(),
            'workers': [],
            'total_workers': 0,
            'active_workers': 0,
            'busy_workers': 0,
            'error': str(e)
        }


def check_cached_result(cache_key: str) -> Optional[Dict[str, Any]]:
    """
    检查缓存中是否已有分析结果
    
    Args:
        cache_key: 缓存键
        
    Returns:
        缓存的结果，如果不存在则返回 None
    """
    r = get_redis_client()
    if r is None:
        return None
    
    try:
        cache_data = r.get(f"deemo:cache:result:{cache_key}")
        if cache_data:
            logger.info(f"[Worker] 找到缓存结果: {cache_key[:16]}...")
            return json.loads(cache_data)
    except Exception as e:
        logger.debug(f"[Worker] 检查缓存失败: {e}")
    
    return None


def save_cached_result(cache_key: str, result: Dict[str, Any], ttl: int = None) -> bool:
    """
    保存分析结果到缓存
    
    Args:
        cache_key: 缓存键
        result: 要缓存的结果
        ttl: 缓存过期时间（秒），默认使用 Config.CACHE_TTL
        
    Returns:
        是否保存成功
    """
    r = get_redis_client()
    if r is None:
        return False
    
    try:
        if ttl is None:
            ttl = Config.CACHE_TTL
        
        r.setex(
            f"deemo:cache:result:{cache_key}",
            ttl,
            json.dumps(result, ensure_ascii=False)
        )
        logger.info(f"[Worker] 结果已缓存: {cache_key[:16]}...")
        return True
    except Exception as e:
        logger.debug(f"[Worker] 保存缓存失败: {e}")
        return False


def update_task_progress(task_id: str, progress: int, message: str = '') -> bool:
    """
    更新任务进度
    
    Args:
        task_id: 任务 ID
        progress: 进度百分比 (0-100)
        message: 进度消息
        
    Returns:
        是否更新成功
    """
    r = get_redis_client()
    if r is None:
        return False
    
    try:
        progress_key = f"deemo:task:progress:{task_id}"
        r.hset(progress_key, mapping={
            'progress': str(progress),
            'message': message,
            'updated_at': datetime.now().isoformat()
        })
        r.expire(progress_key, 86400)
        return True
    except Exception as e:
        logger.debug(f"[Worker] 更新任务进度失败: {e}")
        return False


def execute_analysis_pipeline(
    binary_path: str,
    options: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    执行完整的分析流水线（供 Worker 调用）
    
    Args:
        binary_path: 二进制文件路径
        options: 分析选项
        
    Returns:
        分析结果字典
    """
    from main import run_pipeline
    
    options = options or {}
    
    logger.info(f"[Worker] 开始分析流水线: {binary_path}")
    
    try:
        functions = options.get('functions')
        crash_data = options.get('crash_data')
        validate_exploit = options.get('validate_exploit', False)
        no_exec = options.get('no_exec', True)
        use_ai = options.get('use_ai', True)
        output_dir = options.get('output_dir', './reports')
        decompiler = options.get('decompiler', 'auto')
        enable_symbolic = options.get('enable_symbolic', False)
        use_vuln_db = options.get('use_vuln_db', True)
        include_lib = options.get('include_lib', False)
        output_format = options.get('output_format', 'markdown')
        parallel = options.get('parallel', False)
        max_parallel = options.get('max_parallel', 2)
        hooks_dir = options.get('hooks_dir', './hooks')
        fuzzer_type = options.get('fuzzer_type')
        expert_mode = options.get('expert_mode', False)
        no_rop = options.get('no_rop', False)
        allocator_type = options.get('allocator_type', 'auto')
        libc_version = options.get('libc_version')
        
        result = run_pipeline(
            binary_path=binary_path,
            functions_to_analyze=functions,
            crash_data=crash_data,
            validate_exploit=validate_exploit,
            no_exec=no_exec,
            use_ai=use_ai,
            output_dir=output_dir,
            decompiler=decompiler,
            enable_symbolic_execution=enable_symbolic,
            use_vuln_db=use_vuln_db,
            include_lib=include_lib,
            interactive=False,
            output_format=output_format,
            parallel=parallel,
            max_parallel=max_parallel,
            hooks_dir=hooks_dir,
            fuzzer_type=fuzzer_type,
            expert_mode=expert_mode,
            no_rop=no_rop,
            allocator_type=allocator_type,
            libc_version=libc_version
        )
        
        if 'error' in result:
            logger.error(f"[Worker] 流水线执行失败: {result['error']}")
            return {
                'success': False,
                'error': result['error'],
                'binary_path': binary_path,
                'completed_at': datetime.now().isoformat()
            }
        
        return {
            'success': True,
            'binary_path': binary_path,
            'binary_info': result.get('binary_info'),
            'decomp_analysis': result.get('decomp_analysis'),
            'symbolic_execution': result.get('symbolic_execution'),
            'crash_analysis': result.get('crash_analysis'),
            'exploit_result': result.get('exploit_result'),
            'reports': result.get('reports'),
            'similar_vulnerabilities': result.get('similar_vulnerabilities'),
            'fuzzer_harness': result.get('fuzzer_harness'),
            'corpus_files': result.get('corpus_files'),
            'completed_at': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.exception(f"[Worker] 流水线执行异常: {e}")
        return {
            'success': False,
            'error': str(e),
            'binary_path': binary_path,
            'completed_at': datetime.now().isoformat()
        }


if CELERY_AVAILABLE:
    
    app = get_worker_app()
    
    _tasks_completed = 0
    _tasks_failed = 0
    _worker_id = get_worker_id()
    
    @app.task(
        bind=True,
        name='modules.worker.analyze_binary',
        max_retries=Config.CELERY_MAX_RETRIES,
        default_retry_delay=Config.CELERY_RETRY_BACKOFF,
        time_limit=7200,
        soft_time_limit=7000
    )
    def analyze_binary_task(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        核心分析任务（中等优先级，默认）
        
        Args:
            self: Celery 任务实例
            binary_path: 二进制文件路径
            options: 分析选项
            
        Returns:
            分析结果
        """
        global _tasks_completed, _tasks_failed
        
        options = options or {}
        use_cache = options.get('use_cache', True)
        task_id = self.request.id
        
        logger.info(f"[Worker] 任务 {task_id} 开始: {binary_path}")
        
        try:
            update_worker_heartbeat(
                _worker_id, 
                status='busy', 
                current_task=task_id,
                tasks_completed=_tasks_completed,
                tasks_failed=_tasks_failed
            )
            update_task_progress(task_id, 5, '任务初始化完成')
            
            if use_cache:
                cache_key = get_task_cache_key(binary_path, options)
                cached = check_cached_result(cache_key)
                if cached:
                    logger.info(f"[Worker] 任务 {task_id} 使用缓存结果")
                    return {
                        'success': True,
                        'from_cache': True,
                        'cache_key': cache_key,
                        'result': cached,
                        'completed_at': datetime.now().isoformat()
                    }
            
            update_task_progress(task_id, 10, '开始信息收集')
            
            result = execute_analysis_pipeline(binary_path, options)
            
            if result.get('success') and use_cache:
                cache_key = get_task_cache_key(binary_path, options)
                save_cached_result(cache_key, result)
            
            _tasks_completed += 1
            update_task_progress(task_id, 100, '分析完成')
            
            return result
            
        except SoftTimeLimitExceeded:
            _tasks_failed += 1
            logger.error(f"[Worker] 任务 {task_id} 软超时")
            self.retry(countdown=60)
            return {
                'success': False,
                'error': 'Task soft time limit exceeded',
                'binary_path': binary_path
            }
        except Exception as exc:
            _tasks_failed += 1
            logger.exception(f"[Worker] 任务 {task_id} 执行失败: {exc}")
            raise self.retry(exc=exc, countdown=Config.CELERY_RETRY_BACKOFF)
        finally:
            update_worker_heartbeat(
                _worker_id, 
                status='idle', 
                current_task=None,
                tasks_completed=_tasks_completed,
                tasks_failed=_tasks_failed
            )
    
    @app.task(
        bind=True,
        name='modules.worker.analyze_binary_high',
        max_retries=Config.CELERY_MAX_RETRIES,
        default_retry_delay=Config.CELERY_RETRY_BACKOFF,
        time_limit=3600,
        soft_time_limit=3500
    )
    def analyze_binary_high(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        高优先级分析任务
        
        用于紧急分析、关键漏洞验证等场景
        """
        logger.info(f"[Worker] 高优先级任务: {self.request.id}")
        return analyze_binary_task(binary_path, options)
    
    @app.task(
        bind=True,
        name='modules.worker.analyze_binary_medium',
        max_retries=Config.CELERY_MAX_RETRIES,
        default_retry_delay=Config.CELERY_RETRY_BACKOFF
    )
    def analyze_binary_medium(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        中等优先级分析任务（默认）
        
        用于常规分析任务
        """
        return analyze_binary_task(binary_path, options)
    
    @app.task(
        bind=True,
        name='modules.worker.analyze_binary_low',
        max_retries=Config.CELERY_MAX_RETRIES,
        default_retry_delay=Config.CELERY_RETRY_BACKOFF * 2
    )
    def analyze_binary_low(self, binary_path: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        低优先级分析任务
        
        用于批量分析、后台扫描等非紧急任务
        """
        logger.info(f"[Worker] 低优先级任务: {self.request.id}")
        return analyze_binary_task(binary_path, options)


def submit_analysis_task(
    binary_path: str,
    options: Dict[str, Any] = None,
    priority: str = 'medium'
) -> Optional[str]:
    """
    提交分析任务到 Celery 队列
    
    Args:
        binary_path: 二进制文件路径
        options: 分析选项
        priority: 任务优先级 ('high', 'medium', 'low')
        
    Returns:
        任务 ID，提交失败返回 None
    """
    if not CELERY_AVAILABLE:
        logger.warning("[Worker] Celery 未安装，无法提交分布式任务")
        return None
    
    if not os.path.exists(binary_path):
        logger.error(f"[Worker] 二进制文件不存在: {binary_path}")
        return None
    
    app = get_worker_app()
    if app is None:
        return None
    
    options = options or {}
    
    try:
        task_func = {
            'high': analyze_binary_high,
            'medium': analyze_binary_medium,
            'low': analyze_binary_low
        }.get(priority.lower(), analyze_binary_medium)
        
        task = task_func.delay(binary_path, options)
        logger.info(f"[Worker] 任务已提交: {task.id} (优先级: {priority})")
        return task.id
    except Exception as e:
        logger.error(f"[Worker] 任务提交失败: {e}")
        return None


def get_task_result(task_id: str, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
    """
    获取任务结果
    
    Args:
        task_id: 任务 ID
        timeout: 等待超时时间（秒）
        
    Returns:
        任务结果，任务未完成或不存在返回 None
    """
    if not CELERY_AVAILABLE:
        return None
    
    app = get_worker_app()
    if app is None:
        return None
    
    try:
        from celery.result import AsyncResult
        result = AsyncResult(task_id, app=app)
        
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
        logger.error(f"[Worker] 获取任务结果失败: {e}")
        return None


def start_worker_heartbeat_daemon(worker_id: str, tags: List[str] = None):
    """
    启动 Worker 心跳守护线程
    
    Args:
        worker_id: Worker ID
        tags: Worker 标签列表
    """
    global _heartbeat_thread, _heartbeat_stop_event
    
    if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
        logger.warning("[Worker] 心跳线程已在运行")
        return
    
    register_worker_heartbeat(worker_id, tags)
    
    _heartbeat_stop_event.clear()
    
    def heartbeat_loop():
        while not _heartbeat_stop_event.is_set():
            try:
                update_worker_heartbeat(worker_id)
            except Exception:
                pass
            _heartbeat_stop_event.wait(Config.WORKER_HEARTBEAT_INTERVAL)
        
        unregister_worker_heartbeat(worker_id)
    
    _heartbeat_thread = threading.Thread(
        target=heartbeat_loop,
        daemon=True,
        name=f"worker-heartbeat-{worker_id[:8]}"
    )
    _heartbeat_thread.start()
    logger.info(f"[Worker] 心跳守护线程已启动: {worker_id}")


def stop_worker_heartbeat_daemon():
    """停止 Worker 心跳守护线程"""
    global _heartbeat_stop_event
    
    _heartbeat_stop_event.set()
    logger.info("[Worker] 心跳守护线程正在停止...")


def start_worker(
    concurrency: int = 1,
    queues: List[str] = None,
    tags: List[str] = None,
    hostname: str = None
):
    """
    启动 Celery Worker（用于命令行模式）
    
    Args:
        concurrency: Worker 并发数
        queues: 要监听的队列列表
        tags: Worker 标签
        hostname: Worker 主机名
    """
    if not CELERY_AVAILABLE:
        logger.error("[Worker] Celery 未安装，无法启动 Worker")
        sys.exit(1)
    
    ensure_directories()
    
    app = get_worker_app()
    if app is None:
        logger.error("[Worker] 无法创建 Celery 应用")
        sys.exit(1)
    
    worker_id = get_worker_id()
    worker_hostname = hostname or f"{worker_id}@%h"
    
    if queues is None:
        queues = [Config.CELERY_TASK_QUEUE]
    
    start_worker_heartbeat_daemon(worker_id, tags)
    
    try:
        logger.info(f"[Worker] 启动 Worker: {worker_hostname}")
        logger.info(f"[Worker] 监听队列: {queues}")
        logger.info(f"[Worker] 并发数: {concurrency}")
        
        app.worker_main([
            'worker',
            f'--loglevel={logging.INFO}',
            f'--concurrency={concurrency}',
            f'--hostname={worker_hostname}',
            '-Q', ','.join(queues),
            '--without-gossip',
            '--without-mingle',
            '--without-heartbeat',
        ])
    finally:
        stop_worker_heartbeat_daemon()


if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Deemo 分布式分析 Worker')
    parser.add_argument('-c', '--concurrency', type=int, default=1, help='Worker 并发数 (默认: 1)')
    parser.add_argument('-Q', '--queues', help='监听的队列列表，逗号分隔')
    parser.add_argument('-n', '--hostname', help='Worker 主机名')
    parser.add_argument('-t', '--tags', help='Worker 标签，逗号分隔')
    parser.add_argument('--loglevel', default='INFO', help='日志级别')
    
    args = parser.parse_args()
    
    queues = None
    if args.queues:
        queues = [q.strip() for q in args.queues.split(',')]
    
    tags = None
    if args.tags:
        tags = [t.strip() for t in args.tags.split(',')]
    
    logging.basicConfig(
        level=getattr(logging, args.loglevel.upper(), logging.INFO),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    root_logger = logging.getLogger()
    for handler in root_logger.handlers:
        handler.addFilter(SensitiveFilter())
    
    start_worker(
        concurrency=args.concurrency,
        queues=queues,
        tags=tags,
        hostname=args.hostname
    )
