import os
import logging
import uuid
import hashlib
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

from config import Config

logger = logging.getLogger(__name__)

FASTAPI_AVAILABLE = False
try:
    from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, Depends, status
    from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] FastAPI 或 uvicorn 未安装，Web API 服务不可用")

# Celery/Redis 分布式支持
CELERY_AVAILABLE = False
try:
    from celery import Celery
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] Celery 未安装，分布式任务功能不可用")

REDIS_AVAILABLE = False
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] redis-py 未安装，Worker 状态查询功能受限")

# 远程代理支持
REMOTE_AGENT_AVAILABLE = False
try:
    from modules.remote_agent import AgentManager
    REMOTE_AGENT_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] 远程代理模块不可用")

# WebSocket 支持
WEBSOCKET_AVAILABLE = False
try:
    from fastapi import WebSocket, WebSocketDisconnect
    WEBSOCKET_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] WebSocket 支持不可用")


if FASTAPI_AVAILABLE:
    
    class FuzzStartRequest(BaseModel):
        """模糊测试启动请求模型"""
        binary_path: str = Field(..., description="目标二进制文件路径")
        fuzzer_type: str = Field('auto', description="Fuzzer 类型: libfuzzer, afl, afl++, auto")
        corpus_path: Optional[str] = Field(None, description="初始语料目录路径")
        output_dir: Optional[str] = Field(None, description="输出目录")
        timeout: int = Field(3600, description="最大运行时间（秒）")
        max_crashes: Optional[int] = Field(None, description="最大崩溃数后停止")
        cpu_limit: int = Field(1, description="CPU 数量限制")
        memory_limit: int = Field(2048, description="内存限制（MB）")
        use_sandbox: bool = Field(True, description="是否使用沙箱")
        
        class Config:
            schema_extra = {
                "example": {
                    "binary_path": "/path/to/vulnerable_binary",
                    "fuzzer_type": "libfuzzer",
                    "corpus_path": "/path/to/corpus",
                    "timeout": 3600,
                    "cpu_limit": 2,
                    "memory_limit": 2048,
                    "use_sandbox": True
                }
            }
    
    class AnalysisRequest(BaseModel):
        """分析请求模型"""
        binary_name: str = Field(..., description="二进制文件名")
        binary_hash: Optional[str] = Field(None, description="二进制文件哈希")
        binary_format: Optional[str] = Field(None, description="文件格式: ELF/PE/MACH-O")
        architecture: Optional[str] = Field(None, description="架构: amd64, i386 等")
        function_names: Optional[List[str]] = Field(None, description="指定要分析的函数列表")
        enable_symbolic: bool = Field(False, description="是否启用符号执行")
        enable_exploit_gen: bool = Field(False, description="是否启用利用脚本生成")
        fuzzer_type: Optional[str] = Field(None, description="Fuzzer 类型: libfuzzer, afl")
        expert_mode: bool = Field(False, description="专家模式")
        report_formats: List[str] = Field(default_factory=lambda: ['md', 'html'], description="报告格式")
        
        class Config:
            schema_extra = {
                "example": {
                    "binary_name": "vulnerable_app",
                    "binary_format": "ELF",
                    "architecture": "amd64",
                    "function_names": ["main", "process_input"],
                    "enable_symbolic": False,
                    "enable_exploit_gen": True,
                    "fuzzer_type": "libfuzzer",
                    "expert_mode": False,
                    "report_formats": ["md", "html", "json"]
                }
            }
    
    class VulnerabilityQuery(BaseModel):
        """漏洞查询模型"""
        vulnerability_type: Optional[str] = Field(None, description="漏洞类型")
        function_name: Optional[str] = Field(None, description="函数名")
        binary_format: Optional[str] = Field(None, description="文件格式")
        architecture: Optional[str] = Field(None, description="架构")
        severity: Optional[str] = Field(None, description="严重程度")
        limit: int = Field(20, ge=1, le=100, description="返回数量限制")
        offset: int = Field(0, ge=0, description="偏移量")
    
    class AnalysisTaskStatus(BaseModel):
        """分析任务状态"""
        task_id: str
        status: str
        created_at: str
        updated_at: Optional[str]
        progress: int
        message: Optional[str]
        result: Optional[Dict[str, Any]]
    
    class APIResponse(BaseModel):
        """通用 API 响应模型"""
        success: bool
        message: Optional[str]
        data: Optional[Any]
    
    
    class DistributedAnalysisRequest(BaseModel):
        """分布式分析请求模型"""
        binary_path: str = Field(..., description="二进制文件路径")
        functions: Optional[List[str]] = Field(None, description="要分析的函数列表")
        priority: str = Field('medium', description="任务优先级: high, medium, low")
        use_cache: bool = Field(True, description="是否使用结果缓存")
        options: Optional[Dict[str, Any]] = Field(None, description="额外的分析选项")
        
        class Config:
            schema_extra = {
                "example": {
                    "binary_path": "/path/to/binary",
                    "functions": ["main", "vuln"],
                    "priority": "high",
                    "use_cache": True,
                    "options": {"use_ai": True, "enable_symbolic": False}
                }
            }
    
    class WorkerStatus(BaseModel):
        """Worker 状态模型"""
        worker_id: str
        hostname: str
        pid: int
        status: str
        is_online: bool
        current_task: Optional[str] = None
        tasks_completed: int = 0
        tasks_failed: int = 0
        load_average: float = 0.0
        memory_usage_mb: float = 0.0
        tags: List[str] = []
        started_at: Optional[str] = None
        last_heartbeat: Optional[str] = None
    
    class ClusterStatus(BaseModel):
        """集群状态模型"""
        timestamp: str
        workers: List[WorkerStatus]
        total_workers: int
        active_workers: int
        busy_workers: int
        timeout_seconds: int
    
    
    class AnalysisTaskManager:
        """
        分析任务管理器
        
        管理异步分析任务的创建、执行和状态追踪
        """
        
        def __init__(self, tasks_dir: str = None):
            self.tasks: Dict[str, Dict[str, Any]] = {}
            self.tasks_dir = tasks_dir or os.path.join(Config.DATA_DIR, 'api_tasks')
            self._ensure_tasks_dir()
        
        def _ensure_tasks_dir(self):
            if not os.path.exists(self.tasks_dir):
                os.makedirs(self.tasks_dir, exist_ok=True)
        
        def create_task(self, request: AnalysisRequest) -> str:
            """
            创建新的分析任务
            
            Args:
                request: 分析请求
                
            Returns:
                任务 ID
            """
            task_id = str(uuid.uuid4())
            
            task = {
                'task_id': task_id,
                'status': 'pending',
                'created_at': datetime.now().isoformat(),
                'updated_at': None,
                'progress': 0,
                'message': '任务已创建，等待执行',
                'request': request.dict(),
                'result': None
            }
            
            self.tasks[task_id] = task
            self._save_task(task_id, task)
            
            logger.info(f"[TaskManager] 创建分析任务: {task_id}")
            return task_id
        
        def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
            """获取任务状态"""
            if task_id in self.tasks:
                return self.tasks[task_id]
            
            task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
            if os.path.exists(task_file):
                try:
                    import json
                    with open(task_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except:
                    pass
            
            return None
        
        def update_task(self, task_id: str, **kwargs) -> bool:
            """更新任务状态"""
            if task_id not in self.tasks:
                task = self.get_task(task_id)
                if task:
                    self.tasks[task_id] = task
                else:
                    return False
            
            task = self.tasks[task_id]
            task.update(kwargs)
            task['updated_at'] = datetime.now().isoformat()
            
            self._save_task(task_id, task)
            return True
        
        def _save_task(self, task_id: str, task: Dict[str, Any]):
            """保存任务到磁盘"""
            import json
            task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
            try:
                with open(task_file, 'w', encoding='utf-8') as f:
                    json.dump(task, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"[TaskManager] 保存任务失败: {e}")
        
        def list_tasks(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
            """列出所有任务"""
            result = []
            
            for task_id, task in self.tasks.items():
                if status and task.get('status') != status:
                    continue
                result.append({
                    'task_id': task_id,
                    'status': task.get('status'),
                    'created_at': task.get('created_at'),
                    'updated_at': task.get('updated_at'),
                    'progress': task.get('progress', 0),
                    'binary_name': task.get('request', {}).get('binary_name', 'Unknown')
                })
            
            result.sort(key=lambda x: x['created_at'], reverse=True)
            return result[:limit]
    
    
    task_manager = AnalysisTaskManager()

    # ==================== 远程代理管理 ====================
    agent_manager = AgentManager() if REMOTE_AGENT_AVAILABLE else None


    # ==================== Celery 分布式任务支持 ====================
    _celery_app = None
    
    def get_celery_app() -> Optional['Celery']:
        """
        获取 Celery 应用实例（单例）
        
        Returns:
            Celery 应用实例，Celery 不可用时返回 None
        """
        global _celery_app
        
        if _celery_app is not None:
            return _celery_app
        
        if not CELERY_AVAILABLE:
            return None
        
        try:
            from config import get_celery_broker_url, get_celery_result_backend, mask_redis_url
            
            broker_url = get_celery_broker_url()
            result_backend = get_celery_result_backend()
            
            logger.info(f"[WebAPI] 初始化 Celery，Broker: {mask_redis_url(broker_url)}")
            
            _celery_app = Celery(
                'deemo_api',
                broker=broker_url,
                backend=result_backend,
                broker_connection_retry_on_startup=True
            )
            
            _celery_app.conf.update(
                task_serializer='json',
                accept_content=['json'],
                result_serializer='json',
                timezone='Asia/Shanghai',
                enable_utc=True,
                task_track_started=True,
                task_time_limit=Config.CELERY_TASK_TIME_LIMIT,
                task_soft_time_limit=Config.CELERY_TASK_SOFT_TIME_LIMIT,
                worker_prefetch_multiplier=1,
                worker_max_tasks_per_child=Config.WORKER_MAX_TASKS_PER_CHILD,
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
            
            return _celery_app
        except Exception as e:
            logger.error(f"[WebAPI] Celery 初始化失败: {e}")
            return None
    
    
    def get_redis_client() -> Optional['redis.Redis']:
        """
        获取 Redis 客户端实例
        
        Returns:
            Redis 客户端实例
        """
        if not REDIS_AVAILABLE:
            return None
        
        try:
            from config import get_celery_broker_url
            
            broker_url = get_celery_broker_url()
            from urllib.parse import urlparse
            
            parsed = urlparse(broker_url)
            
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
            return client
        except Exception as e:
            logger.warning(f"[WebAPI] Redis 客户端连接失败: {e}")
            return None
    
    
    def get_cluster_status() -> Dict[str, Any]:
        """
        获取集群中所有 Worker 的状态
        
        Returns:
            集群状态字典
        """
        from datetime import timedelta
        
        r = get_redis_client()
        
        if r is None:
            return {
                'timestamp': datetime.now().isoformat(),
                'workers': [],
                'total_workers': 0,
                'active_workers': 0,
                'busy_workers': 0,
                'error': 'Redis 不可用'
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
                
                import json as json_module
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
                    'tags': json_module.loads(data.get('tags', '[]')) if data.get('tags') else [],
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
            logger.error(f"[WebAPI] 获取集群状态失败: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'workers': [],
                'total_workers': 0,
                'active_workers': 0,
                'busy_workers': 0,
                'error': str(e)
            }
    
    
    def run_analysis_task(task_id: str, request: AnalysisRequest):
        """
        在后台执行分析任务
        
        Args:
            task_id: 任务 ID
            request: 分析请求
        """
        from modules.info_collect import BinaryInfoCollector
        from modules.decompiler import Decompiler
        from modules.vuln_checker import VulnerabilityChecker
        from modules.llm_helper import LLMVulnerabilityAnalyzer
        from modules.report import ReportGenerator
        
        logger.info(f"[TaskRunner] 开始执行任务: {task_id}")
        
        try:
            task_manager.update_task(task_id, status='running', progress=5, message='正在初始化分析...')
            
            reports_dir = os.path.join(task_manager.tasks_dir, task_id, 'reports')
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir, exist_ok=True)
            
            binary_name = request.binary_name
            binary_info = {
                'binary_path': binary_name,
                'binary_name': binary_name,
                'binary_format': request.binary_format or 'ELF',
                'arch': request.architecture or 'amd64',
                'bits': 64 if request.architecture in ['amd64', 'x86_64'] else 32,
                'checksec': {},
                'symbols': {},
                'imports': [],
                'strings': []
            }
            
            task_manager.update_task(task_id, progress=20, message='正在收集二进制信息...')
            
            func_analyses = []
            function_names = request.function_names or ['main']
            
            for i, func_name in enumerate(function_names):
                progress = 20 + (i / len(function_names) * 40)
                task_manager.update_task(
                    task_id, 
                    progress=int(progress), 
                    message=f'正在分析函数: {func_name}...'
                )
                
                func_analysis = {
                    'function_name': func_name,
                    'pseudocode': f'// Function: {func_name}\n// Auto-generated analysis for API demo',
                    'analysis': {
                        'vulnerabilities': [],
                        'risk_level': 'Low',
                        'summary': '函数分析完成'
                    }
                }
                func_analyses.append(func_analysis)
            
            task_manager.update_task(task_id, progress=70, message='正在生成报告...')
            
            report_gen = ReportGenerator(output_dir=reports_dir)
            
            report_paths = {}
            if 'md' in request.report_formats:
                report_paths['markdown'] = report_gen.generate_report(
                    binary_path=binary_name,
                    binary_info=binary_info,
                    decomp_results=func_analyses,
                    crash_analysis=None,
                    exploit_result=None
                )
            
            if 'json' in request.report_formats:
                report_paths['json'] = report_gen.generate_json_report(
                    binary_path=binary_name,
                    binary_info=binary_info,
                    decomp_results=func_analyses,
                    crash_analysis=None,
                    exploit_result=None
                )
            
            if 'html' in request.report_formats:
                report_paths['html'] = report_gen.generate_html_report(
                    binary_path=binary_name,
                    binary_info=binary_info,
                    decomp_results=func_analyses,
                    crash_analysis=None,
                    exploit_result=None
                )
            
            task_manager.update_task(
                task_id, 
                status='completed', 
                progress=100, 
                message='分析完成',
                result={
                    'binary_info': binary_info,
                    'function_analyses': func_analyses,
                    'reports': report_paths
                }
            )
            
            logger.info(f"[TaskRunner] 任务完成: {task_id}")
            
        except Exception as e:
            logger.error(f"[TaskRunner] 任务执行失败: {e}")
            task_manager.update_task(
                task_id,
                status='failed',
                progress=100,
                message=f'分析失败: {str(e)}'
            )
    
    
    _collaborate_mode = False

def set_collaborate_mode(enable: bool):
    """
    设置协作模式
    
    Args:
        enable: 是否启用协作模式
    """
    global _collaborate_mode
    _collaborate_mode = enable


def create_app() -> FastAPI:
        """
        创建 FastAPI 应用
        
        Returns:
            FastAPI 应用实例
        """
        app = FastAPI(
            title="Deemo LLM 二进制漏洞分析 API",
            description="REST API 服务，用于二进制漏洞分析的团队协作",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        origins = os.getenv('CORS_ORIGINS', '*').split(',')
        
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        @app.on_event("startup")
        async def startup_event():
            logger.info("[WebAPI] API 服务启动中...")
            os.makedirs(Config.DATA_DIR, exist_ok=True)
            if _collaborate_mode:
                logger.info("[WebAPI] 多用户协作模式已启用")
        
        # ==================== 认证相关 ====================
        oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)
        
        async def get_current_user(token: str = Depends(oauth2_scheme)):
            """
            获取当前用户（如果启用了协作模式）
            
            Args:
                token: JWT token
                
            Returns:
                用户信息或 None（当未启用认证时）
            """
            if not _collaborate_mode or not Config.REQUIRE_AUTH:
                return None
            
            if not token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="认证失败: 需要登录",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                user = cm.get_user_from_token(token)
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="无效的 token",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
                
                return user
            except Exception as e:
                logger.error(f"[WebAPI] 获取当前用户失败: {e}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="认证失败",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        async def require_admin(user = Depends(get_current_user)):
            """
            要求用户是管理员
            
            Args:
                user: 当前用户
                
            Returns:
                用户信息（管理员）
            """
            if not _collaborate_mode or not Config.REQUIRE_AUTH:
                return user
            
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="需要认证",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            from modules.collaboration import UserRole
            
            if user.role != UserRole.ADMIN:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="需要管理员权限",
                )
            
            return user
        
        # ==================== 认证端点 ====================
        
        class RegisterRequest(BaseModel):
            """用户注册请求模型"""
            username: str = Field(..., description="用户名")
            password: str = Field(..., description="密码")
            role: str = Field("viewer", description="角色: admin, analyst, viewer")
        
        @app.post("/api/auth/register", response_model=APIResponse)
        async def register_user(request: RegisterRequest):
            """
            用户注册
            
            Args:
                request: 注册请求
                
            Returns:
                注册结果
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager, UserRole
                
                cm = CollaborationManager()
                
                role = UserRole(request.role.upper()) if request.role else UserRole.VIEWER
                
                success, user_id = cm.register_user(request.username, request.password, role)
                
                if success:
                    return APIResponse(
                        success=True,
                        message="注册成功",
                        data={"user_id": user_id, "username": request.username}
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=user_id  # user_id 包含错误消息
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 用户注册失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/auth/login")
        async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
            """
            用户登录
            
            Args:
                form_data: 登录表单数据
                
            Returns:
                包含 token 的响应
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                
                success, token = cm.authenticate_user(form_data.username, form_data.password)
                
                if success:
                    return {
                        "access_token": token,
                        "token_type": "bearer",
                        "username": form_data.username
                    }
                else:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="用户名或密码错误",
                        headers={"WWW-Authenticate": "Bearer"},
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 用户登录失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/auth/me", response_model=APIResponse)
        async def get_current_user_info(user = Depends(get_current_user)):
            """
            获取当前用户信息
            
            Args:
                user: 当前用户（通过认证中间件注入）
                
            Returns:
                用户信息
            """
            if not _collaborate_mode or not user:
                return APIResponse(
                    success=True,
                    message="认证未启用或未登录",
                    data=None
                )
            
            return APIResponse(
                success=True,
                message="获取用户信息成功",
                data={
                    "user_id": user.user_id,
                    "username": user.username,
                    "role": user.role.value,
                    "created_at": user.created_at
                }
            )
        
        # ==================== 用户管理端点（管理员） ====================
        
        @app.get("/api/users", response_model=APIResponse)
        async def list_users(user = Depends(require_admin)):
            """
            获取所有用户列表（管理员）
            
            Args:
                user: 当前用户（管理员）
                
            Returns:
                用户列表
            """
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                users = cm.list_users()
                
                return APIResponse(
                    success=True,
                    message=f"找到 {len(users)} 个用户",
                    data={"users": users}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取用户列表失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.delete("/api/users/{user_id}", response_model=APIResponse)
        async def delete_user(user_id: str, current_user = Depends(require_admin)):
            """
            删除用户（管理员）
            
            Args:
                user_id: 要删除的用户 ID
                current_user: 当前用户（管理员）
                
            Returns:
                删除结果
            """
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                
                success, message = cm.delete_user(user_id)
                
                if success:
                    return APIResponse(
                        success=True,
                        message=message
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=message
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 删除用户失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.put("/api/users/{user_id}/role", response_model=APIResponse)
        async def update_user_role(
            user_id: str,
            role: str,
            current_user = Depends(require_admin)
        ):
            """
            更新用户角色（管理员）
            
            Args:
                user_id: 用户 ID
                role: 新角色 (admin, analyst, viewer)
                current_user: 当前用户（管理员）
                
            Returns:
                更新结果
            """
            try:
                from modules.collaboration import CollaborationManager, UserRole
                
                cm = CollaborationManager()
                
                role_enum = UserRole(role.upper())
                success, message = cm.update_user_role(user_id, role_enum)
                
                if success:
                    return APIResponse(
                        success=True,
                        message=message
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=message
                    )
            except ValueError:
                raise HTTPException(status_code=400, detail="无效的角色值")
            except Exception as e:
                logger.error(f"[WebAPI] 更新用户角色失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # ==================== 项目协作端点 ====================
        
        class ProjectInviteRequest(BaseModel):
            """项目邀请请求模型"""
            project_id: str = Field(..., description="项目 ID")
            username: str = Field(..., description="要邀请的用户名")
            role: str = Field("viewer", description="角色: admin, analyst, viewer")
        
        @app.post("/api/projects/{project_id}/invite", response_model=APIResponse)
        async def invite_user_to_project(
            project_id: str,
            request: ProjectInviteRequest,
            user = Depends(get_current_user)
        ):
            """
            邀请用户加入项目
            
            Args:
                project_id: 项目 ID
                request: 邀请请求
                user: 当前用户
                
            Returns:
                邀请结果
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager, UserRole
                
                cm = CollaborationManager()
                
                role = UserRole(request.role.upper())
                success, message = cm.invite_user_to_project(
                    project_id=project_id,
                    username=request.username,
                    role=role,
                    inviter_user_id=user.user_id if user else None
                )
                
                if success:
                    return APIResponse(
                        success=True,
                        message=message
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=message
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 邀请用户失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/projects/{project_id}/members", response_model=APIResponse)
        async def get_project_members(
            project_id: str,
            user = Depends(get_current_user)
        ):
            """
            获取项目成员列表
            
            Args:
                project_id: 项目 ID
                user: 当前用户
                
            Returns:
                成员列表
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                members = cm.get_project_members(project_id)
                
                return APIResponse(
                    success=True,
                    message=f"项目 {project_id} 的成员列表",
                    data={"members": members}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取项目成员失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # ==================== 注释端点 ====================
        
        class CommentRequest(BaseModel):
            """注释请求模型"""
            content: str = Field(..., description="注释内容")
            target_type: str = Field(..., description="目标类型: vulnerability, function")
            target_id: str = Field(..., description="目标 ID")
        
        @app.post("/api/comments", response_model=APIResponse)
        async def add_comment(
            request: CommentRequest,
            user = Depends(get_current_user)
        ):
            """
            添加注释
            
            Args:
                request: 注释请求
                user: 当前用户
                
            Returns:
                注释结果
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                
                success, comment_id = cm.add_comment(
                    content=request.content,
                    target_type=request.target_type,
                    target_id=request.target_id,
                    user_id=user.user_id if user else None
                )
                
                if success:
                    return APIResponse(
                        success=True,
                        message="注释添加成功",
                        data={"comment_id": comment_id}
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=comment_id
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 添加注释失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/comments/{target_type}/{target_id}", response_model=APIResponse)
        async def get_comments(target_type: str, target_id: str):
            """
            获取目标的所有注释
            
            Args:
                target_type: 目标类型
                target_id: 目标 ID
                
            Returns:
                注释列表
            """
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                comments = cm.get_comments(target_type, target_id)
                
                return APIResponse(
                    success=True,
                    message=f"找到 {len(comments)} 条注释",
                    data={"comments": comments}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取注释失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # ==================== 漏洞状态更新端点 ====================
        
        class VulnerabilityStatusRequest(BaseModel):
            """漏洞状态更新请求模型"""
            status: str = Field(..., description="新状态: confirmed, false_positive, fixed")
        
        @app.put("/api/vulnerabilities/{vuln_id}/status", response_model=APIResponse)
        async def update_vulnerability_status(
            vuln_id: int,
            request: VulnerabilityStatusRequest,
            user = Depends(get_current_user)
        ):
            """
            更新漏洞状态
            
            Args:
                vuln_id: 漏洞 ID
                request: 状态更新请求
                user: 当前用户
                
            Returns:
                更新结果
            """
            if not _collaborate_mode:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="多用户协作模式未启用"
                )
            
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                
                success, message = cm.update_vulnerability_status(
                    vuln_id=vuln_id,
                    status=request.status,
                    user_id=user.user_id if user else None
                )
                
                if success:
                    return APIResponse(
                        success=True,
                        message=message
                    )
                else:
                    return APIResponse(
                        success=False,
                        message=message
                    )
            except Exception as e:
                logger.error(f"[WebAPI] 更新漏洞状态失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # ==================== 审计日志端点 ====================
        
        @app.get("/api/audit/logs", response_model=APIResponse)
        async def get_audit_logs(
            page: int = 0,
            limit: int = 100,
            user = Depends(require_admin)
        ):
            """
            获取审计日志（管理员）
            
            Args:
                page: 页码
                limit: 每页数量
                user: 当前用户（管理员）
                
            Returns:
                审计日志列表
            """
            try:
                from modules.collaboration import CollaborationManager
                
                cm = CollaborationManager()
                logs = cm.get_audit_logs(page=page, limit=limit)
                
                return APIResponse(
                    success=True,
                    message=f"获取审计日志成功",
                    data={"logs": logs, "page": page, "limit": limit}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取审计日志失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/")
        async def root():
            """根路径 - 健康检查"""
            return {
                "name": "Deemo LLM 二进制漏洞分析 API",
                "version": "1.0.0",
                "status": "running",
                "timestamp": datetime.now().isoformat(),
                "endpoints": {
                    "docs": "/docs",
                    "health": "/api/health",
                    "analyze": "/api/analyze",
                    "vulnerabilities": "/api/vulnerabilities",
                    "tasks": "/api/tasks"
                }
            }
        
        @app.get("/api/health")
        async def health_check():
            """健康检查"""
            return {
                "status": "healthy",
                "timestamp": datetime.now().isoformat(),
                "uptime": "unknown"
            }
        
        @app.post("/api/analyze", response_model=APIResponse)
        async def submit_analysis(
            request: AnalysisRequest,
            background_tasks: BackgroundTasks
        ):
            """
            提交分析任务
            
            创建一个新的二进制分析任务并返回任务 ID。
            任务将在后台异步执行。
            
            Args:
                request: 分析请求
                background_tasks: FastAPI 后台任务管理器
                
            Returns:
                包含任务 ID 的响应
            """
            try:
                task_id = task_manager.create_task(request)
                background_tasks.add_task(run_analysis_task, task_id, request)
                
                return APIResponse(
                    success=True,
                    message="分析任务已提交",
                    data={
                        "task_id": task_id,
                        "status": "pending",
                        "check_status_url": f"/api/tasks/{task_id}"
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 提交分析任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/analyze/upload")
        async def upload_and_analyze(
            file: UploadFile = File(...),
            background_tasks: BackgroundTasks = None
        ):
            """
            上传二进制文件并提交分析任务
            
            Args:
                file: 上传的二进制文件
                background_tasks: 后台任务管理器
                
            Returns:
                包含任务 ID 的响应
            """
            try:
                upload_dir = os.path.join(task_manager.tasks_dir, 'uploads')
                os.makedirs(upload_dir, exist_ok=True)
                
                file_hash = hashlib.sha256()
                file_path = os.path.join(upload_dir, file.filename)
                
                with open(file_path, 'wb') as f:
                    while chunk := await file.read(8192):
                        file_hash.update(chunk)
                        f.write(chunk)
                
                hex_hash = file_hash.hexdigest()
                
                request = AnalysisRequest(
                    binary_name=file.filename,
                    binary_hash=hex_hash,
                    report_formats=['md', 'html', 'json']
                )
                
                task_id = task_manager.create_task(request)
                background_tasks.add_task(run_analysis_task, task_id, request)
                
                return APIResponse(
                    success=True,
                    message="文件已上传，分析任务已提交",
                    data={
                        "task_id": task_id,
                        "file_name": file.filename,
                        "file_hash": hex_hash,
                        "check_status_url": f"/api/tasks/{task_id}"
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 文件上传失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/tasks")
        async def list_tasks(status: str = None, limit: int = 100):
            """
            列出所有分析任务
            
            Args:
                status: 按状态过滤 (pending/running/completed/failed)
                limit: 返回数量限制
                
            Returns:
                任务列表
            """
            try:
                tasks = task_manager.list_tasks(status=status, limit=limit)
                return APIResponse(
                    success=True,
                    message=f"找到 {len(tasks)} 个任务",
                    data={"tasks": tasks, "count": len(tasks)}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 列出任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/tasks/{task_id}")
        async def get_task_status(task_id: str):
            """
            获取任务状态
            
            Args:
                task_id: 任务 ID
                
            Returns:
                任务状态和结果
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            return APIResponse(
                success=True,
                message="任务状态",
                data=task
            )
        
        @app.delete("/api/tasks/{task_id}")
        async def cancel_task(task_id: str):
            """
            取消/删除任务
            
            Args:
                task_id: 任务 ID
                
            Returns:
                操作结果
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            task_manager.update_task(task_id, status='cancelled', message='任务已取消')
            
            return APIResponse(
                success=True,
                message="任务已取消",
                data={"task_id": task_id}
            )
        
        @app.get("/api/reports/{task_id}")
        async def list_reports(task_id: str):
            """
            列出任务的所有报告
            
            Args:
                task_id: 任务 ID
                
            Returns:
                报告列表
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            if task.get('status') != 'completed':
                raise HTTPException(status_code=400, detail="任务尚未完成")
            
            reports = task.get('result', {}).get('reports', {})
            
            return APIResponse(
                success=True,
                message="报告列表",
                data={
                    "task_id": task_id,
                    "reports": [
                        {
                            "format": fmt,
                            "path": path,
                            "download_url": f"/api/reports/{task_id}/{fmt}"
                        }
                        for fmt, path in reports.items()
                    ]
                }
            )
        
        @app.get("/api/reports/{task_id}/{format}")
        async def download_report(task_id: str, format: str):
            """
            下载指定格式的报告
            
            Args:
                task_id: 任务 ID
                format: 报告格式 (md, json, html, pdf)
                
            Returns:
                文件下载响应
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            reports = task.get('result', {}).get('reports', {})
            
            if format not in reports:
                raise HTTPException(
                    status_code=404, 
                    detail=f"格式 {format} 的报告不存在。可用格式: {list(reports.keys())}"
                )
            
            report_path = reports[format]
            
            if not os.path.exists(report_path):
                raise HTTPException(status_code=404, detail="报告文件不存在")
            
            media_types = {
                'md': 'text/markdown',
                'json': 'application/json',
                'html': 'text/html',
                'pdf': 'application/pdf'
            }
            
            return FileResponse(
                path=report_path,
                filename=os.path.basename(report_path),
                media_type=media_types.get(format, 'application/octet-stream')
            )
        
        @app.post("/api/vulnerabilities")
        async def query_vulnerabilities(query: VulnerabilityQuery):
            """
            查询漏洞数据库
            
            Args:
                query: 查询条件
                
            Returns:
                匹配的漏洞记录列表
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase
                
                db = VulnerabilityDatabase()
                results = []
                
                if query.function_name:
                    results = db.search_by_function(query.function_name, limit=query.limit)
                elif query.vulnerability_type:
                    results = db.search_by_vulnerability_type(query.vulnerability_type, limit=query.limit)
                else:
                    results = db.get_all(limit=query.limit, offset=query.offset)
                
                return APIResponse(
                    success=True,
                    message=f"找到 {len(results)} 条漏洞记录",
                    data={
                        "vulnerabilities": results,
                        "count": len(results),
                        "query": query.dict()
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 查询漏洞数据库失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/vulnerabilities/stats")
        async def get_vulnerability_stats():
            """
            获取漏洞数据库统计信息
            
            Returns:
                统计信息
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase
                
                db = VulnerabilityDatabase()
                stats = db.get_statistics()
                
                return APIResponse(
                    success=True,
                    message="漏洞数据库统计",
                    data=stats
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取统计信息失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/vulnerabilities/{vuln_id}")
        async def get_vulnerability(vuln_id: int):
            """
            获取单个漏洞记录
            
            Args:
                vuln_id: 漏洞 ID
                
            Returns:
                漏洞记录详情
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase
                
                db = VulnerabilityDatabase()
                vuln = db.get_by_id(vuln_id)
                
                if not vuln:
                    raise HTTPException(status_code=404, detail=f"漏洞不存在: {vuln_id}")
                
                return APIResponse(
                    success=True,
                    message="漏洞详情",
                    data=vuln
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 获取漏洞详情失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/vulnerabilities/external")
        async def query_external_vulnerabilities(
            package_name: str = None,
            cve_id: str = None,
            binary_name: str = None,
            source: str = 'all'
        ):
            """
            查询外部漏洞数据源
            
            综合查询 NVD、VulDB、OSV、GitHub Advisory、Exploit-DB 等外部数据源
            
            Args:
                package_name: 包名
                cve_id: CVE ID
                binary_name: 二进制文件名
                source: 指定数据源 (all, nvd, vuldb, ghadvisory, osv, exploit_db)
                
            Returns:
                综合查询结果
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase, VALID_SOURCES
                
                if source and source.lower() not in VALID_SOURCES:
                    raise HTTPException(
                        status_code=400, 
                        detail=f"无效的数据源: {source}。有效值: {VALID_SOURCES}"
                    )
                
                db = VulnerabilityDatabase()
                results = db.query_all_external(
                    package_name=package_name,
                    cve_id=cve_id,
                    binary_name=binary_name,
                    source=source,
                    use_cache=True,
                    deduplicate=True
                )
                
                return APIResponse(
                    success=True,
                    message="外部漏洞查询结果",
                    data=results
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 外部漏洞查询失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        class ProjectCreateRequest(BaseModel):
            """项目创建请求模型"""
            name: str = Field(..., description="项目名称")
            binary_path: str = Field(..., description="目标二进制文件路径")
            
            class Config:
                schema_extra = {
                    "example": {
                        "name": "my_vulnerability_analysis",
                        "binary_path": "/path/to/binary"
                    }
                }
        
        @app.post("/api/projects", response_model=APIResponse)
        async def create_project(request: ProjectCreateRequest):
            """
            创建新项目
            
            Args:
                request: 项目创建请求
                
            Returns:
                创建的项目信息
            """
            try:
                from modules.project_manager import ProjectManager
                
                pm = ProjectManager()
                project_id = pm.create_project(request.name, request.binary_path)
                
                project = pm.get_project_metadata(project_id)
                
                return APIResponse(
                    success=True,
                    message="项目创建成功",
                    data={
                        "project_id": project_id,
                        "project": project
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 创建项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/projects", response_model=APIResponse)
        async def list_projects():
            """
            列出所有项目
            
            Returns:
                项目列表
            """
            try:
                from modules.project_manager import ProjectManager
                
                pm = ProjectManager()
                projects = pm.list_projects()
                
                return APIResponse(
                    success=True,
                    message=f"找到 {len(projects)} 个项目",
                    data={
                        "projects": projects,
                        "count": len(projects)
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 列出项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/projects/{project_id}", response_model=APIResponse)
        async def get_project(project_id: str):
            """
            获取项目状态
            
            Args:
                project_id: 项目 ID
                
            Returns:
                项目状态信息
            """
            try:
                from modules.project_manager import ProjectManager
                
                pm = ProjectManager()
                project = pm.get_project_metadata(project_id)
                
                if not project:
                    raise HTTPException(status_code=404, detail=f"项目不存在: {project_id}")
                
                state = pm.load_project(project_id)
                
                return APIResponse(
                    success=True,
                    message="项目状态",
                    data={
                        "project": project,
                        "state": state.to_dict() if state else None
                    }
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 获取项目状态失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/projects/{project_id}/resume", response_model=APIResponse)
        async def resume_project(project_id: str, background_tasks: BackgroundTasks):
            """
            恢复项目分析
            
            Args:
                project_id: 项目 ID
                background_tasks: 后台任务管理器
                
            Returns:
                恢复结果
            """
            try:
                from modules.project_manager import ProjectManager
                
                pm = ProjectManager()
                
                project = pm.get_project_metadata(project_id)
                if not project:
                    raise HTTPException(status_code=404, detail=f"项目不存在: {project_id}")
                
                state = pm.load_project(project_id)
                if not state:
                    raise HTTPException(status_code=400, detail="项目状态不存在，无法恢复")
                
                binary_path = project.get('binary_path')
                if not binary_path or not os.path.exists(binary_path):
                    raise HTTPException(status_code=400, detail="原始二进制文件不存在")
                
                async def run_resume_analysis():
                    from main import run_pipeline
                    run_pipeline(
                        binary_path=binary_path,
                        project_name=project.get('name'),
                        project_resume=True
                    )
                
                background_tasks.add_task(run_resume_analysis)
                
                return APIResponse(
                    success=True,
                    message="项目恢复任务已提交",
                    data={
                        "project_id": project_id,
                        "current_step": state.current_step,
                        "analyzed_functions": len(state.analyzed_functions),
                        "status": "resuming"
                    }
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 恢复项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.delete("/api/projects/{project_id}", response_model=APIResponse)
        async def delete_project(project_id: str):
            """
            删除项目
            
            Args:
                project_id: 项目 ID
                
            Returns:
                删除结果
            """
            try:
                from modules.project_manager import ProjectManager
                
                pm = ProjectManager()
                
                project = pm.get_project_metadata(project_id)
                if not project:
                    raise HTTPException(status_code=404, detail=f"项目不存在: {project_id}")
                
                success = pm.delete_project(project_id)
                
                if success:
                    return APIResponse(
                        success=True,
                        message="项目删除成功",
                        data={"project_id": project_id}
                    )
                else:
                    return APIResponse(
                        success=False,
                        message="删除项目失败",
                        data={"project_id": project_id}
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 删除项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        fuzz_managers: Dict[str, Any] = {}

        @app.post("/api/fuzz/start")
        async def start_fuzzing(request: FuzzStartRequest):
            """
            启动模糊测试任务
            
            Args:
                request: 模糊测试请求参数
                
            Returns:
                包含会话 ID 的响应
            """
            try:
                from modules.fuzz_integration import FuzzManager
                
                logger.info(f"[WebAPI] 启动模糊测试: {request.binary_path}")
                
                fuzz_manager = FuzzManager(
                    binary_path=request.binary_path,
                    fuzzer_type=request.fuzzer_type,
                    corpus_path=request.corpus_path,
                    output_dir=request.output_dir,
                    use_sandbox=request.use_sandbox
                )
                
                result = fuzz_manager.start(
                    timeout=request.timeout,
                    max_crashes=request.max_crashes,
                    cpu_limit=request.cpu_limit,
                    memory_limit=request.memory_limit
                )
                
                if result.get('success'):
                    fuzz_managers[fuzz_manager.session_id] = fuzz_manager
                    
                    return APIResponse(
                        success=True,
                        message="模糊测试已启动",
                        data={
                            "session_id": fuzz_manager.session_id,
                            "fuzzer_type": fuzz_manager.fuzzer_type,
                            "output_dir": fuzz_manager.output_dir,
                            "status": fuzz_manager.status,
                            "check_status_url": f"/api/fuzz/status/{fuzz_manager.session_id}"
                        }
                    )
                else:
                    return APIResponse(
                        success=False,
                        message="启动模糊测试失败",
                        data={"error": result.get('error')}
                    )
                    
            except Exception as e:
                logger.error(f"[WebAPI] 启动模糊测试失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/fuzz/status/{session_id}")
        async def get_fuzz_status(session_id: str):
            """
            获取模糊测试状态
            
            Args:
                session_id: 模糊测试会话 ID
                
            Returns:
                模糊测试状态信息
            """
            if session_id not in fuzz_managers:
                raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")
            
            fuzz_manager = fuzz_managers[session_id]
            status = fuzz_manager.get_status()
            
            return APIResponse(
                success=True,
                message="模糊测试状态",
                data=status
            )

        @app.get("/api/fuzz/crashes/{session_id}")
        async def get_fuzz_crashes(session_id: str, limit: int = 100):
            """
            获取模糊测试发现的崩溃列表
            
            Args:
                session_id: 模糊测试会话 ID
                limit: 返回数量限制
                
            Returns:
                崩溃列表
            """
            if session_id not in fuzz_managers:
                raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")
            
            fuzz_manager = fuzz_managers[session_id]
            crashes = fuzz_manager.get_crashes(limit=limit)
            
            return APIResponse(
                success=True,
                message=f"找到 {len(crashes)} 个崩溃",
                data={
                    "session_id": session_id,
                    "crashes_count": len(crashes),
                    "crashes": crashes
                }
            )

        @app.post("/api/fuzz/stop/{session_id}")
        async def stop_fuzzing(session_id: str):
            """
            停止模糊测试
            
            Args:
                session_id: 模糊测试会话 ID
                
            Returns:
                停止状态信息
            """
            if session_id not in fuzz_managers:
                raise HTTPException(status_code=404, detail=f"会话不存在: {session_id}")
            
            fuzz_manager = fuzz_managers[session_id]
            result = fuzz_manager.stop()
            
            if result.get('success'):
                crashes_found = result.get('crashes_found', 0)
                
                return APIResponse(
                    success=True,
                    message=f"模糊测试已停止，共发现 {crashes_found} 个崩溃",
                    data={
                        "session_id": session_id,
                        "crashes_found": crashes_found,
                        "status": result.get('status')
                    }
                )
            else:
                return APIResponse(
                    success=False,
                    message="停止模糊测试失败",
                    data={"error": result.get('error')}
                )

        @app.get("/api/fuzz/list")
        async def list_fuzz_sessions():
            """
            列出所有正在运行的模糊测试会话
            
            Returns:
                会话列表
            """
            sessions = []
            for session_id, fuzz_manager in fuzz_managers.items():
                status = fuzz_manager.get_status()
                sessions.append({
                    "session_id": session_id,
                    "status": status.get('status'),
                    "binary_path": status.get('binary_path'),
                    "fuzzer_type": status.get('fuzzer_type'),
                    "crashes_found": status.get('crashes_found'),
                    "runtime": status.get('runtime')
                })
            
            return APIResponse(
                success=True,
                message=f"找到 {len(sessions)} 个会话",
                data={"sessions": sessions}
            )
        
        # ==================== 分布式集群管理端点 ====================
        
        @app.get("/api/cluster/status", response_model=ClusterStatus)
        async def get_cluster_status_endpoint():
            """
            获取集群中所有 Worker 的状态
            
            Returns:
                集群状态信息，包括各 Worker 的负载、任务数等
            """
            try:
                status = get_cluster_status()
                return ClusterStatus(**status)
            except Exception as e:
                logger.error(f"[WebAPI] 获取集群状态失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/distributed/analyze")
        async def submit_distributed_analysis(request: DistributedAnalysisRequest):
            """
            提交分布式分析任务到 Celery 队列
            
            Args:
                request: 分布式分析请求
                
            Returns:
                包含任务 ID 的响应
            """
            if not CELERY_AVAILABLE:
                raise HTTPException(
                    status_code=503,
                    detail="Celery 未安装，分布式任务功能不可用"
                )
            
            try:
                celery_app = get_celery_app()
                if celery_app is None:
                    raise HTTPException(
                        status_code=503,
                        detail="无法连接到 Celery Broker"
                    )
                
                binary_path = request.binary_path
                if not os.path.exists(binary_path):
                    raise HTTPException(
                        status_code=400,
                        detail=f"二进制文件不存在: {binary_path}"
                    )
                
                options = request.options or {}
                if request.functions:
                    options['functions'] = request.functions
                options['use_cache'] = request.use_cache
                
                task_func_map = {
                    'high': 'modules.worker.analyze_binary_high',
                    'medium': 'modules.worker.analyze_binary_medium',
                    'low': 'modules.worker.analyze_binary_low'
                }
                
                task_name = task_func_map.get(request.priority.lower(), 'modules.worker.analyze_binary_medium')
                task = celery_app.send_task(task_name, args=[binary_path], kwargs=[options])
                
                logger.info(f"[WebAPI] 分布式任务已提交: {task.id} (优先级: {request.priority})")
                
                return APIResponse(
                    success=True,
                    message="分布式分析任务已提交",
                    data={
                        "task_id": task.id,
                        "priority": request.priority,
                        "status": "pending",
                        "check_status_url": f"/api/distributed/status/{task.id}"
                    }
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 提交分布式任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/distributed/status/{task_id}")
        async def get_distributed_task_status(task_id: str):
            """
            获取分布式任务状态
            
            Args:
                task_id: Celery 任务 ID
                
            Returns:
                任务状态和结果
            """
            if not CELERY_AVAILABLE:
                raise HTTPException(
                    status_code=503,
                    detail="Celery 未安装，分布式任务功能不可用"
                )
            
            try:
                celery_app = get_celery_app()
                if celery_app is None:
                    raise HTTPException(
                        status_code=503,
                        detail="无法连接到 Celery Broker"
                    )
                
                result = AsyncResult(task_id, app=celery_app)
                
                response_data = {
                    "task_id": task_id,
                    "status": result.status,
                    "ready": result.ready(),
                    "successful": result.successful() if result.ready() else None
                }
                
                if result.ready():
                    if result.successful():
                        response_data["result"] = result.result
                    else:
                        response_data["error"] = str(result.result)
                
                return APIResponse(
                    success=True,
                    message="任务状态",
                    data=response_data
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 获取分布式任务状态失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post("/api/distributed/cancel/{task_id}")
        async def cancel_distributed_task(task_id: str):
            """
            取消分布式任务
            
            Args:
                task_id: Celery 任务 ID
                
            Returns:
                取消结果
            """
            if not CELERY_AVAILABLE:
                raise HTTPException(
                    status_code=503,
                    detail="Celery 未安装，分布式任务功能不可用"
                )
            
            try:
                celery_app = get_celery_app()
                if celery_app is None:
                    raise HTTPException(
                        status_code=503,
                        detail="无法连接到 Celery Broker"
                    )
                
                result = AsyncResult(task_id, app=celery_app)
                result.revoke(terminate=True)
                
                return APIResponse(
                    success=True,
                    message="任务已取消",
                    data={"task_id": task_id}
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 取消分布式任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.get("/api/distributed/queues")
        async def list_distributed_queues():
            """
            列出所有可用的分布式任务队列
            
            Returns:
                队列列表及其状态
            """
            if not CELERY_AVAILABLE:
                raise HTTPException(
                    status_code=503,
                    detail="Celery 未安装，分布式任务功能不可用"
                )
            
            try:
                celery_app = get_celery_app()
                if celery_app is None:
                    raise HTTPException(
                        status_code=503,
                        detail="无法连接到 Celery Broker"
                    )
                
                inspector = celery_app.control.inspect()
                
                active_queues = set()
                stats = inspector.stats() or {}
                active = inspector.active() or {}
                reserved = inspector.reserved() or {}
                
                for worker_stats in stats.values():
                    if 'pool' in worker_stats:
                        for queue in worker_stats['pool'].get('queues', []):
                            active_queues.add(queue)
                
                for worker_tasks in list(active.values()) + list(reserved.values()):
                    for task in worker_tasks:
                        if 'delivery_info' in task:
                            active_queues.add(task['delivery_info'].get('routing_key', 'celery'))
                
                default_queues = [
                    f'{Config.CELERY_TASK_QUEUE}',
                    f'{Config.CELERY_TASK_QUEUE}_high',
                    f'{Config.CELERY_TASK_QUEUE}_medium',
                    f'{Config.CELERY_TASK_QUEUE}_low'
                ]
                
                queues_info = []
                for queue in default_queues:
                    queue_info = {
                        'name': queue,
                        'is_active': queue in active_queues,
                        'worker_count': sum(1 for w in stats.values() 
                                           if 'pool' in w and queue in w['pool'].get('queues', []))
                    }
                    queues_info.append(queue_info)
                
                return APIResponse(
                    success=True,
                    message="队列列表",
                    data={
                        "queues": queues_info,
                        "default_queue": Config.CELERY_TASK_QUEUE,
                        "total_workers": len(stats)
                    }
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 列出分布式队列失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        # ==================== 漏洞利用验证端点 ====================

        @app.post("/api/tasks/{task_id}/verify")
        async def trigger_exploit_verification(
            task_id: str,
            verify_count: int = 5,
            background_tasks: BackgroundTasks = None
        ):
            """
            触发漏洞利用验证
            
            Args:
                task_id: 任务 ID
                verify_count: 验证重复次数（默认: 5）
                background_tasks: 后台任务管理器
                
            Returns:
                验证任务状态
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            if task.get('status') != 'completed':
                raise HTTPException(status_code=400, detail="任务尚未完成，无法验证")
            
            exploit_result = task.get('result', {}).get('exploit_result')
            if not exploit_result or not exploit_result.get('success'):
                raise HTTPException(status_code=400, detail="没有可用的利用脚本")
            
            try:
                from modules.exploit_verifier import ExploitVerifier
                
                verifier = ExploitVerifier()
                
                def run_verification():
                    result = verifier.verify_exploit(
                        exploit_script=exploit_result.get('script_content', ''),
                        binary_path=task.get('request', {}).get('binary_name', ''),
                        verify_count=verify_count
                    )
                    task_manager.update_task(task_id, verification_result=result)
                    logger.info(f"[WebAPI] 利用验证完成: {task_id}")
                
                background_tasks.add_task(run_verification)
                
                return APIResponse(
                    success=True,
                    message="利用验证已触发",
                    data={
                        "task_id": task_id,
                        "verify_count": verify_count,
                        "status": "running",
                        "check_url": f"/api/tasks/{task_id}/verify/status"
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 触发利用验证失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/tasks/{task_id}/verify/status")
        async def get_verification_status(task_id: str):
            """
            获取漏洞利用验证状态
            
            Args:
                task_id: 任务 ID
                
            Returns:
                验证结果
            """
            task = task_manager.get_task(task_id)
            
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")
            
            verification_result = task.get('verification_result')
            
            if not verification_result:
                return APIResponse(
                    success=True,
                    message="验证未执行或正在进行中",
                    data={
                        "task_id": task_id,
                        "status": "pending"
                    }
                )
            
            return APIResponse(
                success=True,
                message="验证结果",
                data={
                    "task_id": task_id,
                    "status": "completed",
                    "verification_result": verification_result
                }
            )

        # ==================== 威胁情报端点 ====================

        class ThreatIntelQuery(BaseModel):
            """威胁情报查询模型"""
            task_id: Optional[str] = Field(None, description="关联的任务 ID")
            query_type: str = Field(..., description="查询类型: hash/cve/indicator")
            query_value: str = Field(..., description="查询值")
            provider: str = Field('all', description="提供商: misp/otx/all")
            anonymize: bool = Field(False, description="是否匿名查询")

        @app.post("/api/threat_intel/query")
        async def query_threat_intel(
            request: ThreatIntelQuery,
            background_tasks: BackgroundTasks = None
        ):
            """
            提交威胁情报查询
            
            Args:
                request: 查询参数
                background_tasks: 后台任务管理器
                
            Returns:
                查询任务状态
            """
            try:
                from modules.threat_intel import ThreatIntelClient
                
                client = ThreatIntelClient(providers=[request.provider])
                
                def run_query():
                    results = []
                    if request.query_type == 'hash':
                        results = client.query_by_hash(
                            sha256_hash=request.query_value,
                            task_id=request.task_id or '',
                            anonymize=request.anonymize
                        )
                    elif request.query_type == 'cve':
                        results = client.query_by_cve(
                            cve_id=request.query_value,
                            task_id=request.task_id or ''
                        )
                    elif request.query_type == 'indicator':
                        results = client.query_by_indicator(
                            indicator=request.query_value,
                            task_id=request.task_id or ''
                        )
                    
                    from modules.vuln_db import VulnerabilityDatabase
                    db = VulnerabilityDatabase()
                    client.save_results(results, db, task_id=request.task_id or '')
                    
                    return [r.to_dict() for r in results]
                
                background_tasks.add_task(run_query)
                
                return APIResponse(
                    success=True,
                    message="威胁情报查询已提交",
                    data={
                        "query_id": f"ti_{uuid.uuid4().hex[:8]}",
                        "query_type": request.query_type,
                        "query_value": request.query_value,
                        "provider": request.provider,
                        "status": "running",
                        "check_url": f"/api/threat_intel/results/{request.task_id}" if request.task_id else None
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 提交威胁情报查询失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/threat_intel/results/{task_id}")
        async def get_threat_intel_results(task_id: str):
            """
            获取威胁情报查询结果
            
            Args:
                task_id: 任务 ID
                
            Returns:
                威胁情报结果列表
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase
                
                db = VulnerabilityDatabase()
                results = db.get_threat_intel_results(task_id)
                
                return APIResponse(
                    success=True,
                    message="威胁情报查询结果",
                    data={
                        "task_id": task_id,
                        "results": results,
                        "count": len(results)
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取威胁情报结果失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ==================== 远程代理端点 ====================
        class AgentRegisterRequest(BaseModel):
            """代理注册请求模型"""
            agent_id: str = Field(..., description="代理唯一标识")
            capabilities: List[str] = Field(default_factory=list, description="代理能力列表")
            hostname: str = Field(..., description="主机名")
            pid: int = Field(..., description="进程ID")

        class AgentCommandRequest(BaseModel):
            """代理命令请求模型"""
            command: str = Field(..., description="命令: stop, ping, sync_capabilities")
            args: Optional[Dict[str, Any]] = Field(None, description="命令参数")

        class AgentTaskRequest(BaseModel):
            """代理任务请求模型"""
            task_type: str = Field(..., description="任务类型: binary_info, fuzz, taint, analysis")
            binary_path: str = Field(..., description="目标二进制文件路径")
            options: Optional[Dict[str, Any]] = Field(None, description="任务选项")

        @app.post("/api/agents/register", response_model=APIResponse)
        async def register_agent(request: AgentRegisterRequest):
            """
            代理注册
            
            Args:
                request: 注册请求
                
            Returns:
                包含代理令牌的响应
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                token = agent_manager.register_agent(
                    agent_id=request.agent_id,
                    capabilities=request.capabilities,
                    hostname=request.hostname,
                    pid=request.pid
                )
                
                return APIResponse(
                    success=True,
                    message="代理注册成功",
                    data={
                        "agent_id": request.agent_id,
                        "token": token,
                        "capabilities": request.capabilities
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 代理注册失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/agents/tasks")
        async def get_agent_tasks(token: str):
            """
            代理拉取待执行任务
            
            Args:
                token: 代理令牌
                
            Returns:
                待执行任务列表
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                tasks = agent_manager.get_pending_tasks()
                return {"tasks": [t.to_dict() for t in tasks]}
            except Exception as e:
                logger.error(f"[WebAPI] 获取代理任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.post("/api/agents/results")
        async def submit_agent_results(
            agent_id: str,
            token: str,
            task_id: str,
            result: Dict[str, Any]
        ):
            """
            代理提交任务结果
            
            Args:
                agent_id: 代理标识
                token: 代理令牌
                task_id: 任务ID
                result: 任务结果
                
            Returns:
                提交结果
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                if not agent_manager.validate_token(agent_id, token):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="无效的代理令牌"
                    )
                
                agent_manager.update_task_result(task_id, result)
                
                return APIResponse(
                    success=True,
                    message="任务结果提交成功",
                    data={"task_id": task_id}
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 提交代理结果失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.post("/api/agents/heartbeat")
        async def agent_heartbeat(
            agent_id: str,
            token: str,
            timestamp: Optional[str] = None,
            status: Optional[str] = "online"
        ):
            """
            代理心跳
            
            Args:
                agent_id: 代理标识
                token: 代理令牌
                timestamp: 时间戳
                status: 状态
                
            Returns:
                心跳确认
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                if not agent_manager.validate_token(agent_id, token):
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="无效的代理令牌"
                    )
                
                agent_manager.update_heartbeat(agent_id)
                
                return APIResponse(
                    success=True,
                    message="心跳已更新",
                    data={"agent_id": agent_id, "status": status}
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 代理心跳处理失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/agents", response_model=APIResponse)
        async def list_agents(admin_user = Depends(require_admin)):
            """
            列出所有在线代理（管理员权限）
            
            Args:
                admin_user: 当前管理员用户
                
            Returns:
                代理列表
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                online_agents = agent_manager.get_online_agents()
                return APIResponse(
                    success=True,
                    message="代理列表",
                    data={
                        "agents": online_agents,
                        "count": len(online_agents)
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 获取代理列表失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.get("/api/agents/{agent_id}", response_model=APIResponse)
        async def get_agent_info(agent_id: str, admin_user = Depends(require_admin)):
            """
            获取单个代理信息（管理员权限）
            
            Args:
                agent_id: 代理标识
                admin_user: 当前管理员用户
                
            Returns:
                代理信息
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                agent = agent_manager.get_agent_by_id(agent_id)
                
                if not agent:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"代理 {agent_id} 不存在"
                    )
                
                return APIResponse(
                    success=True,
                    message="代理信息",
                    data=agent
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 获取代理信息失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.delete("/api/agents/{agent_id}", response_model=APIResponse)
        async def revoke_agent(agent_id: str, admin_user = Depends(require_admin)):
            """
            吊销代理（管理员权限）
            
            Args:
                agent_id: 代理标识
                admin_user: 当前管理员用户
                
            Returns:
                吊销结果
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                success = agent_manager.revoke_agent(agent_id)
                
                if success:
                    return APIResponse(
                        success=True,
                        message=f"代理 {agent_id} 已吊销"
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"代理 {agent_id} 不存在"
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 吊销代理失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.post("/api/agents/{agent_id}/command", response_model=APIResponse)
        async def send_command_to_agent(
            agent_id: str,
            request: AgentCommandRequest,
            admin_user = Depends(require_admin)
        ):
            """
            向代理发送命令（管理员权限）
            
            Args:
                agent_id: 代理标识
                request: 命令请求
                admin_user: 当前管理员用户
                
            Returns:
                命令发送结果
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                agent = agent_manager.get_agent_by_id(agent_id)
                
                if not agent:
                    raise HTTPException(
                        status_code=status.HTTP_404_NOT_FOUND,
                        detail=f"代理 {agent_id} 不存在"
                    )
                
                if agent.get('status') != 'online':
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"代理 {agent_id} 离线"
                    )
                
                logger.info(f"[WebAPI] 向代理 {agent_id} 发送命令: {request.command}")
                
                return APIResponse(
                    success=True,
                    message=f"命令 {request.command} 已发送",
                    data={"agent_id": agent_id, "command": request.command}
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 发送命令失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.post("/api/agents/task/create", response_model=APIResponse)
        async def create_agent_task(
            request: AgentTaskRequest,
            admin_user = Depends(require_admin)
        ):
            """
            创建代理任务（管理员权限）
            
            Args:
                request: 任务请求
                admin_user: 当前管理员用户
                
            Returns:
                任务创建结果
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                task_id = agent_manager.create_task(
                    task_type=request.task_type,
                    binary_path=request.binary_path,
                    **(request.options or {})
                )
                
                return APIResponse(
                    success=True,
                    message="任务创建成功",
                    data={"task_id": task_id}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 创建代理任务失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.post("/api/agents/task/{task_id}/assign/{agent_id}", response_model=APIResponse)
        async def assign_task_to_agent(
            task_id: str,
            agent_id: str,
            admin_user = Depends(require_admin)
        ):
            """
            分配任务给代理（管理员权限）
            
            Args:
                task_id: 任务ID
                agent_id: 代理ID
                admin_user: 当前管理员用户
                
            Returns:
                分配结果
            """
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="远程代理功能不可用"
                )
            
            try:
                success = agent_manager.assign_task_to_agent(task_id, agent_id)
                
                if success:
                    return APIResponse(
                        success=True,
                        message=f"任务 {task_id} 已分配给代理 {agent_id}"
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="任务分配失败"
                    )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"[WebAPI] 任务分配失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        @app.websocket("/api/agents/ws")
        async def agent_websocket(websocket: WebSocket, token: str = None):
            """
            代理 WebSocket 连接端点
            
            Args:
                websocket: WebSocket 连接
                token: 代理令牌
            """
            if not WEBSOCKET_AVAILABLE:
                await websocket.close(code=1012, reason="WebSocket 不可用")
                return
            
            if not REMOTE_AGENT_AVAILABLE or not agent_manager:
                await websocket.close(code=1012, reason="远程代理功能不可用")
                return
            
            await websocket.accept()
            
            agent_id = None
            
            try:
                while True:
                    data = await websocket.receive_json()
                    msg_type = data.get('type')
                    
                    if msg_type == 'heartbeat':
                        agent_id = data.get('agent_id')
                        if agent_id and token:
                            if agent_manager.validate_token(agent_id, token):
                                agent_manager.update_heartbeat(agent_id)
                                await websocket.send_json({
                                    'type': 'pong',
                                    'timestamp': datetime.now().isoformat()
                                })
                    
                    elif msg_type == 'task_result':
                        agent_id = data.get('agent_id')
                        if agent_id and token:
                            if agent_manager.validate_token(agent_id, token):
                                task_id = data.get('task_id')
                                result = data.get('result')
                                agent_manager.update_task_result(task_id, result)
                    
                    elif msg_type == 'capabilities':
                        pass
                    
                    else:
                        logger.warning(f"[WebAPI] 未知的 WebSocket 消息类型: {msg_type}")
            
            except WebSocketDisconnect:
                if agent_id:
                    logger.info(f"[WebAPI] 代理 {agent_id} 断开连接")
            except Exception as e:
                logger.error(f"[WebAPI] WebSocket 错误: {e}")
                if agent_id:
                    logger.info(f"[WebAPI] 代理 {agent_id} 异常断开")

        logger.info("[WebAPI] API 应用创建完成")
        return app
    
    
    def start_server(
        host: str = "0.0.0.0",
        port: int = 8000,
        reload: bool = False,
        collaborate: bool = False
    ):
        """
        启动 API 服务器
        
        Args:
            host: 监听地址
            port: 监听端口
            reload: 热重载模式（开发用）
            collaborate: 是否启用多用户协作模式
        """
        if not FASTAPI_AVAILABLE:
            logger.error("[WebAPI] FastAPI 或 uvicorn 未安装，无法启动服务器")
            logger.error("[WebAPI] 请运行: pip install fastapi uvicorn python-multipart")
            return
        
        if collaborate:
            set_collaborate_mode(True)
        
        app = create_app()
        
        logger.info(f"[WebAPI] 启动 API 服务器: {host}:{port}")
        logger.info(f"[WebAPI] 文档地址: http://{host}:{port}/docs")
        if collaborate:
            logger.info(f"[WebAPI] 多用户协作模式: 已启用")
            logger.info(f"[WebAPI] 认证要求: {'启用' if Config.REQUIRE_AUTH else '禁用'}")
        
        uvicorn.run(
            app,
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    
    app = create_app()

else:
    
    def start_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
        """
        启动 API 服务器（占位符，当依赖未安装时）
        """
        logger.error("[WebAPI] FastAPI 或 uvicorn 未安装，无法启动服务器")
        logger.error("[WebAPI] 请运行: pip install fastapi uvicorn python-multipart")
        raise ImportError("FastAPI 和 uvicorn 必须安装才能使用 Web API 功能")
    
    app = None
