"""
基于 Celery + Redis 的分布式任务队列 Worker。

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

try:
    from config import Config, ensure_directories, SensitiveFilter
except ImportError:
    # 模块内 config/ 数据目录无 __init__.py，命名空间包会遮蔽顶层 config 模块；
    # 遮蔽发生时从项目根显式装载 config.py，保证配置入口唯一。
    import importlib.util as _ilu
    _root_cfg_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "config.py")
    )
    _root_cfg_spec = _ilu.spec_from_file_location("deemo_root_config", _root_cfg_path)
    _root_cfg = _ilu.module_from_spec(_root_cfg_spec)
    _root_cfg_spec.loader.exec_module(_root_cfg)
    Config = _root_cfg.Config
    ensure_directories = _root_cfg.ensure_directories
    SensitiveFilter = _root_cfg.SensitiveFilter

# 调度辅助函数 — 旧版 config 导出的符号在部分部署环境已移除, 此处兜底保证模块可独立导入。
def get_celery_broker_url() -> str:
    return getattr(Config, "CELERY_BROKER_URL", "redis://localhost:6379/0")

def get_celery_result_backend() -> str:
    return getattr(Config, "CELERY_RESULT_BACKEND", "redis://localhost:6379/1")

def mask_redis_url(url: str) -> str:
    if not url:
        return url
    return url.split("@")[-1]

def get_task_cache_key(binary_path: str, options: dict) -> str:
    key = os.path.basename(binary_path)
    opts = json.dumps(options or {}, sort_keys=True)
    return hashlib.sha256((key + opts).encode("utf-8")).hexdigest()

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
    获取 Redis 客户端实例，不可用时返回 None。
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
    获取或创建 Celery 应用实例（单例），Celery 未安装时返回 None。
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
    生成唯一的 Worker ID。
    """
    hostname = socket.gethostname()
    pid = os.getpid()
    return f"{hostname}-{pid}-{uuid.uuid4().hex[:8]}"


def register_worker_heartbeat(worker_id: str, tags: List[str] = None) -> bool:
    """
    注册 Worker 心跳, 返回是否注册成功。
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
    更新 Worker 心跳, 返回是否更新成功。

    status 取值 idle/busy/error。
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
    注销 Worker 心跳, 返回是否注销成功。
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
    获取所有 Worker 的状态快照。
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
    检查缓存中是否已有分析结果, 不存在返回 None。
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
    保存分析结果到缓存, ttl 缺省用 Config.CACHE_TTL; 返回是否成功。
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
    更新任务进度, 返回是否更新成功。
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
    执行完整的分析流水线（供 Worker 调用）, 返回分析结果字典。
    """
    from core.pipeline import run_pipeline

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
            no_rop=no_rop
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
        核心分析任务（中等优先级，默认）。
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
        高优先级分析任务 — 用于紧急分析、关键漏洞验证等场景。
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
        中等优先级分析任务（默认） — 用于常规分析任务。
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
        低优先级分析任务 — 用于批量分析、后台扫描等非紧急任务。
        """
        logger.info(f"[Worker] 低优先级任务: {self.request.id}")
        return analyze_binary_task(binary_path, options)


def submit_analysis_task(
    binary_path: str,
    options: Dict[str, Any] = None,
    priority: str = 'medium'
) -> Optional[str]:
    """
    提交分析任务到 Celery 队列。

    priority 取值 high/medium/low; 返回任务 ID, 失败返回 None。
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
    获取任务结果, 未完成或不存在返回 None。
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
    启动 Worker 心跳守护线程 (已运行则跳过)。
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
    """停止 Worker 心跳守护线程。"""
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
    启动 Celery Worker（用于命令行模式）。
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

# Redis 阻塞队列 Worker — 与上方 Celery 实现互斥的轻量后端。
# 通过 BLPOP 消费任务、线程池执行、结果发布到结果队列;
# 支持优先级队列、延迟重试(sorted set)、熔断与令牌桶限流。
# 未安装 redis 或 src/ 子包时自动降级为内联简化实现。
import logging
import json
import time
import signal
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

_log = logging.getLogger(__name__)

# src/ 优先导入，不可用时内联简化实现
# worker.py 可独立运行，不依赖 src/ 子包
# 外部代码可以从 worker 导入 Task/Node 等核心类型
try:
    from .src.models import Task, Node, TaskStatus, TaskType
    from .src.circuit_breaker import CircuitBreaker as _ExtCircuitBreaker
    from .src.rate_limiter import TokenBucket as _ExtTokenBucket
    from .src.utils import retry as _src_retry, backoff_delay as _src_backoff
    _SRC_AVAILABLE = True
except ImportError:
    _SRC_AVAILABLE = False

    import enum as _enum
    from dataclasses import dataclass as _dc, field as _field

    class TaskStatus(_enum.Enum):
        PENDING = "pending"
        QUEUED = "queued"
        RUNNING = "running"
        SUCCESS = "success"
        FAILURE = "failure"
        RETRYING = "retrying"
        CANCELLED = "cancelled"

    class TaskType(_enum.Enum):
        STATIC_ANALYSIS = "static_analysis"
        DYNAMIC_ANALYSIS = "dynamic_analysis"
        SYMBOLIC = "symbolic"
        DECOMPILE = "decompile"
        CUSTOM = "custom"

    @_dc
    class Task:
        id: str = ""
        type: TaskType = TaskType.CUSTOM
        payload: dict = _field(default_factory=dict)
        priority: int = 0
        status: TaskStatus = TaskStatus.PENDING
        created_at: float = _field(default_factory=time.time)
        updated_at: float = _field(default_factory=time.time)
        retries: int = 0
        max_retries: int = 3
        timeout: float = 300.0
        tags: list = _field(default_factory=list)
        parent_id: str = None

    @_dc
    class Node:
        id: str = ""
        address: str = ""
        status: str = "offline"
        last_heartbeat: float = _field(default_factory=time.time)
        capacity: int = 1
        current_load: int = 0
        labels: dict = _field(default_factory=dict)
        version: str = "0.1.0"

    class _ExtCircuitBreaker:
        def __init__(self, failure_threshold=5, recovery_timeout=60.0, name="default"):
            self._threshold = failure_threshold
            self._cooldown = recovery_timeout
            self.name = name
            self._failures = 0
            self._state = "closed"
        def before_call(self): return self._state != "open"
        def on_success(self): self._failures = 0; self._state = "closed"
        def on_failure(self):
            self._failures += 1
            if self._failures >= self._threshold: self._state = "open"

    class _ExtTokenBucket:
        def __init__(self, rate, burst=None):
            self._rate = rate
            self._burst = burst or rate
            self._tokens = float(self._burst)
            self._last = time.monotonic()
        def allow(self):
            now = time.monotonic()
            self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# 指数退避 — Google SRE 第23章 "应对过载" 的背压策略 + Celery retry_backoff
# 添加 ±25% 均匀抖动，避免批量重试导致的惊群效应
def _backoff_delay(attempt: int, base: float = 2.0, cap: float = 600.0) -> float:
    """第 attempt 次重试的等待秒数，含随机抖动。"""
    import random
    raw = min(base ** attempt, cap)
    return raw * (0.75 + random.random() * 0.5)


# Lua 脚本 — ZPOPMIN 取出 score ≤ now 的到期重试任务，原子搬迁到工作队列
# 在一个往返中完成「取出 + 推入」，避免竞态窗口
_RETRY_POP_LUA = """
local items = redis.call('ZPOPMIN', KEYS[1], ARGV[1])
if not items or #items == 0 then return 0 end
local moved = 0
for i = 1, #items, 2 do
    redis.call('RPUSH', KEYS[2], items[i])
    moved = moved + 1
end
return moved
"""


# 令牌桶限流器 — 惰性填充策略
# 不在后台线程中定时补充令牌，而是在每次 acquire() 时根据时间差计算应补数量
# 优势：零后台开销；代价：长时间空闲后的首次请求可能获得 burst 个令牌
# Stripe timed rate limiter, Envoy token bucket filter
class _TokenBucket:
    """惰性填充令牌桶。rate=每秒生成数, burst=桶容量（最大突发）。"""

    __slots__ = ('_rate', '_burst', '_tokens', '_last_fill')

    def __init__(self, rate: float, burst: int):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_fill = time.monotonic()

    def acquire(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_fill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_fill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class WorkerConfig:
    def __init__(self, redis_url="redis://localhost:6379/0",
                 queue="binmind:tasks", result_queue="binmind:results",
                 poll_timeout=5, max_retries=3, max_workers=4,
                 job_timeout=300, breaker_threshold=5, breaker_cooldown=60,
                 heartbeat_interval=15, reconnect_base=1.0, reconnect_cap=30.0,
                 priority_tiers=None, rate_limits=None, handler_retries=None):
        self.redis_url = redis_url
        self.queue = queue
        self.result_queue = result_queue
        self.poll_timeout = poll_timeout
        self.max_retries = max_retries
# 扩展配置 — 全部提供构造参数并设保守默认值, 向后兼容旧版直接赋值用法
        self.dead_letter_queue = f"{queue}:dlq"
        self.retry_sorted_set = f"{queue}:retry"        # score = 下次执行时间戳
        self.heartbeat_key = "binmind:workers:heartbeat"
        self.heartbeat_interval = heartbeat_interval     # TTL = interval × 3
        self.max_workers = max_workers
        self.job_timeout = job_timeout
        self.breaker_threshold = breaker_threshold       # 连续失败 N 次 → 熔断
        self.breaker_cooldown = breaker_cooldown         # 冷却秒数
        self.reconnect_base = reconnect_base
        self.reconnect_cap = reconnect_cap
        # 优先级队列: {队列后缀: 轮询权重}, 权重大的被 BLPOP 抢占概率更高
        # 空字典退化为原始单队列模式
        self.priority_tiers: dict = priority_tiers if priority_tiers is not None else {}
        # 每 handler 的令牌桶限流: {handler_name: (rate, burst)}
        self.rate_limits: dict = rate_limits if rate_limits is not None else {}
        # 每 handler 的重试覆盖: {handler_name: max_retries}
        self.handler_retries: dict = handler_retries if handler_retries is not None else {}


class AnalysisJob:
    def __init__(self, job_id="", binary_path="", analysis_type="", params=None):
        self.job_id = job_id or str(uuid.uuid4())[:8]
        self.binary_path = binary_path
        self.analysis_type = analysis_type
        self.params = params or {}

    def to_dict(self):
        return {"id": self.job_id, "binary": self.binary_path,
                "type": self.analysis_type, "params": self.params}

    @classmethod
    def from_dict(cls, d):
        return cls(d.get("id", ""), d.get("binary", ""),
                   d.get("type", ""), d.get("params", {}))


class JobResult:
    def __init__(self, job_id="", ok=True, findings=None, error=""):
        self.job_id = job_id
        self.ok = ok
        self.findings = findings or []
        self.error = error
        self.worker_id = ""

    def to_dict(self):
        return {"id": self.job_id, "ok": self.ok,
                "findings": self.findings, "error": self.error,
                "worker_id": self.worker_id}


# 熔断器 — Michael Nygard "Release It!" 三态断路器
# 按 handler 类型独立维护故障计数，避免一个异常 handler 拖垮整个 worker
# 半开状态允许一次探测：成功 → 关闭，失败 → 重新熔断
class _CircuitBreaker:
    """Per-handler circuit breaker with half-open probe."""

    __slots__ = ('_threshold', '_cooldown', '_failures', '_opened_at')

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures: dict = {}
        self._opened_at: dict = {}

    def allow(self, handler_name: str) -> bool:
        opened = self._opened_at.get(handler_name)
        if opened is None:
            return True
        if time.monotonic() - opened >= self._cooldown:
            return True   # 半开
        return False

    def record_success(self, handler_name: str):
        self._failures[handler_name] = 0
        self._opened_at.pop(handler_name, None)

    def record_failure(self, handler_name: str):
        cnt = self._failures.get(handler_name, 0) + 1
        self._failures[handler_name] = cnt
        if cnt >= self._threshold:
            self._opened_at[handler_name] = time.monotonic()

    def state(self, handler_name: str) -> str:
        if handler_name not in self._opened_at:
            return "closed"
        if self.allow(handler_name):
            return "half-open"
        return "open"


class Worker:
    """Blocking queue consumer: pop job, dispatch to handler, push result."""

    def __init__(self, config=None, connect=True):
        self.cfg = config or WorkerConfig()
        self._stop = threading.Event()
        self._running = False
        self.worker_id = str(uuid.uuid4())[:8]
        self._handlers = {}
        self._client = None
        # connect=False 时连接延后到 start()，构造阶段不执行网络操作
        if connect:
            self._connect()

        self._pool = ThreadPoolExecutor(max_workers=self.cfg.max_workers,
                                        thread_name_prefix=f"bmw-{self.worker_id}")
        self._inflight: dict = {}
        self._metrics = {"processed": 0, "failed": 0, "retried": 0,
                         "dlq": 0, "rate_limited": 0, "skipped_empty": 0}
        self._breaker = _CircuitBreaker(self.cfg.breaker_threshold,
                                        self.cfg.breaker_cooldown)
        self._retry_script = None
        self._heartbeat_thread = None
        # 令牌桶按 handler_name 惰性创建
        self._buckets: dict = {}
        # 优先级轮询计数器：记录当前循环号，用于决定本轮轮询哪个队列
        self._poll_counter = 0

# 连接管理：指数退避重连
    def _connect(self):
        if not REDIS_AVAILABLE:
            _log.warning("redis not available")
            return
        attempt = 0
        while not self._stop.is_set():
            try:
                self._client = _redis.Redis.from_url(self.cfg.redis_url,
                                                      socket_timeout=10,
                                                      socket_connect_timeout=5,
                                                      decode_responses=True)
                self._client.ping()
                _log.info("worker %s connected to redis", self.worker_id)
                self._retry_script = self._client.register_script(_RETRY_POP_LUA)
                return
            except Exception:
                attempt += 1
                delay = min(self.cfg.reconnect_base * (2 ** (attempt - 1)),
                            self.cfg.reconnect_cap)
                _log.warning("redis connect attempt %d failed, retry in %.1fs",
                             attempt, delay)
                time.sleep(delay)

    def _ensure_connected(self):
        if self._client is not None:
            try:
                self._client.ping()
                return
            except Exception:
                self._client = None
        self._connect()

# 心跳：后台 daemon 线程，周期性 SET with PX
    def _heartbeat_loop(self):
        ttl_ms = self.cfg.heartbeat_interval * 3 * 1000
        while not self._stop.is_set():
            if self._client:
                try:
                    self._client.set(self.cfg.heartbeat_key,
                                     json.dumps({"worker": self.worker_id,
                                                 "at": time.time()}),
                                     px=ttl_ms)
                except Exception:
                    pass
            self._stop.wait(self.cfg.heartbeat_interval)

# 限流器懒初始化
    def _get_bucket(self, handler_name: str):
        if handler_name in self._buckets:
            return self._buckets[handler_name]
        spec = self.cfg.rate_limits.get(handler_name)
        if spec is None:
            self._buckets[handler_name] = None
            return None
        rate, burst = spec
        self._buckets[handler_name] = _TokenBucket(rate, burst)
        return self._buckets[handler_name]

# 公开 API（向后兼容）
    def register_handler(self, analysis_type, func):
        self._handlers[analysis_type] = func

    def start(self):
        self._running = True
        _log.info("worker %s starting, listening on %s", self.worker_id, self.cfg.queue)
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop,
                                                   daemon=True,
                                                   name=f"bmw-hb-{self.worker_id}")
        self._heartbeat_thread.start()
        self._worker_loop()

    def stop(self):
        _log.info("worker %s shutting down", self.worker_id)
        self._running = False
        self._stop.set()

# 主循环
    def _worker_loop(self):
        while self._running:
            try:
                self._ensure_connected()
                self._collect_completed()
                self._poll_priority()
                self._drain_retry_set()
            except Exception:
                _log.exception("main loop error")
                time.sleep(0.5)

        # 优雅停机：等待在途任务至多 job_timeout 秒
        self._drain_inflight()
        self._pool.shutdown(wait=True)

# 优先级轮询
    def _poll_priority(self):
        """若未配置 priority_tiers，退化为原始单队列 BLPOP。
        若配置了优先级，基于加权轮询决定本轮从哪个队列拉取。
        权重比例如 {"high": 5, "medium": 3, "low": 1} 表示每 9 轮中 high 得 5 次。"""
        if self._client is None:
            time.sleep(self.cfg.poll_timeout)
            return

        tiers = self.cfg.priority_tiers
        if not tiers:
            self._poll_queue(self.cfg.queue)
            return

        # 加权选择
        self._poll_counter += 1
        total_weight = sum(tiers.values())
        if total_weight <= 0:
            self._poll_queue(self.cfg.queue)
            return

        pos = self._poll_counter % total_weight
        cumulative = 0
        chosen_suffix = None
        for suffix, w in tiers.items():
            cumulative += w
            if pos < cumulative:
                chosen_suffix = suffix
                break

        if chosen_suffix is None:
            chosen_suffix = next(iter(tiers))

        queue_name = f"{self.cfg.queue}:{chosen_suffix}"
        self._poll_queue(queue_name)

    def _poll_queue(self, queue_name: str):
        raw = self._client.blpop(queue_name, timeout=1)
        if raw is None:
            self._metrics["skipped_empty"] += 1
            return
        _, payload = raw
        try:
            job_dict = json.loads(payload)
            job = AnalysisJob.from_dict(job_dict)
        except (json.JSONDecodeError, TypeError):
            _log.warning("bad payload from %s, discarded", queue_name)
            return

        retries = job_dict.get("_retries", 0)

        # 限流门控 — 在提交线程池之前检查
        bucket = self._get_bucket(job.analysis_type)
        if bucket is not None and not bucket.acquire():
            # 限流触发 → 延迟重新入队，不消耗 retry 配额
            self._metrics["rate_limited"] += 1
            self._schedule_retry(job, retries, 1.0)
            return

        _log.info("worker %s processing %s (type=%s, retry=%d, q=%s)",
                  self.worker_id, job.job_id, job.analysis_type, retries, queue_name)

        fut = self._pool.submit(self._execute_with_timeout, job, retries)
        self._inflight[fut] = job

# 原有的 _poll 保留为内部方法，由 _poll_priority 委派
    def _poll(self):
        """单队列轮询 — 保留以支持外部代码直接调用的兼容场景。"""
        if self._client is None:
            time.sleep(self.cfg.poll_timeout)
            return
        self._poll_queue(self.cfg.queue)

# 双层超时: 外层对整体加硬超时，内层为实际执行
    def _execute_with_timeout(self, job: AnalysisJob, retries: int = 0) -> JobResult:
        fut_inner = self._pool.submit(self._execute, job, retries)
        try:
            return fut_inner.result(timeout=self.cfg.job_timeout)
        except FutTimeout:
            return JobResult(job.job_id, ok=False,
                             error=f"timeout after {self.cfg.job_timeout}s")

    def _execute(self, job: AnalysisJob, retries: int = 0) -> JobResult:
        handler = self._handlers.get(job.analysis_type)
        if handler is None:
            return JobResult(job.job_id, ok=False,
                             error=f"no handler for {job.analysis_type}")

        # 熔断器门控
        if not self._breaker.allow(job.analysis_type):
            self._schedule_retry(job, retries, self.cfg.breaker_cooldown)
            return JobResult(job.job_id, ok=False,
                             error=f"circuit open for {job.analysis_type}, requeued")

        # 每 handler 可覆盖 max_retries
        max_r = self.cfg.handler_retries.get(job.analysis_type, self.cfg.max_retries)

        try:
            findings = handler(job.binary_path, **job.params)
            self._breaker.record_success(job.analysis_type)
            return JobResult(job.job_id, ok=True, findings=findings)
        except Exception as e:
            _log.exception("job %s failed", job.job_id)
            self._breaker.record_failure(job.analysis_type)

            if retries < max_r:
                delay = _backoff_delay(retries + 1)
                self._schedule_retry(job, retries + 1, delay)
                return JobResult(job.job_id, ok=False,
                                 error=f"will retry in {delay:.1f}s")

            self._send_to_dlq(job, str(e), retries)
            return JobResult(job.job_id, ok=False, error=str(e))

# 重试调度：sorted set 按时间戳索引延迟任务
    def _schedule_retry(self, job: AnalysisJob, retry_count: int, delay: float):
        """写入 sorted set，score = 预定执行时间。
        _drain_retry_set 周期原子搬迁到期任务。
        选 sorted set 而非额外 scheduler 进程：减少运维组件，利用 Redis 原子性。"""
        payload = job.to_dict()
        payload["_retries"] = retry_count
        score = time.time() + delay
        try:
            self._client.zadd(self.cfg.retry_sorted_set, {json.dumps(payload): score})
            self._metrics["retried"] += 1
        except Exception:
            _log.exception("retry schedule failed for %s → dlq", job.job_id)
            self._send_to_dlq(job, "retry schedule failed", retry_count)

# 死信队列
    def _send_to_dlq(self, job: AnalysisJob, reason: str, retries: int):
        """永久失败任务入 DLQ，保留完整现场供运维排查和手动重放。"""
        dlq_entry = {"job": job.to_dict(), "reason": reason,
                     "retries_attempted": retries,
                     "worker_id": self.worker_id, "ts": time.time()}
        try:
            self._client.rpush(self.cfg.dead_letter_queue, json.dumps(dlq_entry))
            self._metrics["dlq"] += 1
            _log.info("job %s → dlq (reason=%s, retries=%d)", job.job_id, reason, retries)
        except Exception:
            _log.exception("critical: dlq write failed for %s", job.job_id)

    def _drain_retry_set(self):
        """单次搬迁上限 10 条，避免在主循环中阻塞过久。"""
        if self._client is None or self._retry_script is None:
            return
        try:
            moved = self._retry_script(
                keys=[self.cfg.retry_sorted_set, self.cfg.queue], args=[10]
            )
            if moved:
                _log.debug("moved %d retry jobs back to queue", moved)
        except Exception:
            pass

# 结果收集：非阻塞轮询已完成 future
    def _collect_completed(self):
        done = [f for f in self._inflight if f.done()]
        for fut in done:
            job = self._inflight.pop(fut)
            try:
                result = fut.result(timeout=0)
            except Exception as e:
                result = JobResult(job.job_id, ok=False, error=str(e))
            result.worker_id = self.worker_id
            self._publish_result(result)
            self._metrics["processed" if result.ok else "failed"] += 1

    def _publish_result(self, result: JobResult):
        if self._client is None:
            return
        try:
            self._client.rpush(self.cfg.result_queue, json.dumps(result.to_dict()))
        except Exception:
            _log.exception("failed to publish result for %s", result.job_id)

# 优雅停机：排空在途任务
    def _drain_inflight(self):
        if not self._inflight:
            return
        deadline = time.monotonic() + self.cfg.job_timeout
        remaining = list(self._inflight.items())
        for fut, job in remaining:
            timeout = max(0, deadline - time.monotonic())
            try:
                result = fut.result(timeout=timeout)
                result.worker_id = self.worker_id
                self._publish_result(result)
            except FutTimeout:
                _log.warning("inflight job %s not done by deadline → dlq", job.job_id)
                self._send_to_dlq(job, "worker shutdown timeout", 0)
            except Exception as e:
                self._send_to_dlq(job, f"worker shutdown: {e}", 0)
            self._inflight.pop(fut, None)

    def submit(self, job: AnalysisJob):
        if self._client is None:
            raise RuntimeError("not connected to redis")

        # 若配置了优先级队列，路由到对应 tier
        tiers = self.cfg.priority_tiers
        if tiers:
            priority = job.params.get("priority", "")
            if priority in tiers:
                target_q = f"{self.cfg.queue}:{priority}"
                self._client.rpush(target_q, json.dumps(job.to_dict()))
                return
        self._client.rpush(self.cfg.queue, json.dumps(job.to_dict()))

    def fetch_result(self, timeout=10):
        if self._client is None:
            return None
        raw = self._client.blpop(self.cfg.result_queue, timeout=timeout)
        if raw is None:
            return None
        _, payload = raw
        return JobResult(**json.loads(payload))

    @property
    def connected(self):
        return self._client is not None

# 运维接口
    @property
    def metrics(self):
        return dict(self._metrics)

    @property
    def inflight_count(self):
        return len(self._inflight)

    @property
    def pool_health(self):
        """线程池快照：{max_workers, inflight}。"""
        return {
            "max_workers": self.cfg.max_workers,
            "inflight": len(self._inflight),
        }

    def queue_depth(self, queue_name: str = None) -> int:
        """查询指定队列的积压量。不传参则查询默认队列。"""
        if self._client is None:
            return -1
        q = queue_name or self.cfg.queue
        return self._client.llen(q)

    def breaker_state(self, handler_name: str) -> str:
        return self._breaker.state(handler_name)

    def dlq_inspect(self, count: int = 10):
        if self._client is None:
            return []
        items = self._client.lrange(self.cfg.dead_letter_queue, -count, -1)
        return [json.loads(i) for i in items]

    def dlq_retry_one(self, index_from_tail: int = -1):
        if self._client is None:
            return False
        raw = self._client.lindex(self.cfg.dead_letter_queue, index_from_tail)
        if raw is None:
            return False
        entry = json.loads(raw)
        job_dict = entry.get("job", {})
        job_dict.pop("_retries", None)
        self._client.rpush(self.cfg.queue, json.dumps(job_dict))
        self._client.lrem(self.cfg.dead_letter_queue, 1, raw)
        _log.info("dlq job %s re-queued", job_dict.get("id", "unknown"))
        return True

