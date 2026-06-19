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
    from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
    from fastapi.responses import FileResponse, JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] FastAPI 或 uvicorn 未安装，Web API 服务不可用")


if FASTAPI_AVAILABLE:
    
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
            binary_name: str = None
        ):
            """
            查询外部漏洞数据源
            
            综合查询 NVD、OSV、GitHub Advisory 等外部数据源
            
            Args:
                package_name: 包名
                cve_id: CVE ID
                binary_name: 二进制文件名
                
            Returns:
                综合查询结果
            """
            try:
                from modules.vuln_db import VulnerabilityDatabase
                
                db = VulnerabilityDatabase()
                results = db.query_all_external(
                    package_name=package_name,
                    cve_id=cve_id,
                    binary_name=binary_name
                )
                
                return APIResponse(
                    success=True,
                    message="外部漏洞查询结果",
                    data=results
                )
            except Exception as e:
                logger.error(f"[WebAPI] 外部漏洞查询失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        logger.info("[WebAPI] API 应用创建完成")
        return app
    
    
    def start_server(
        host: str = "0.0.0.0",
        port: int = 8000,
        reload: bool = False
    ):
        """
        启动 API 服务器
        
        Args:
            host: 监听地址
            port: 监听端口
            reload: 热重载模式（开发用）
        """
        if not FASTAPI_AVAILABLE:
            logger.error("[WebAPI] FastAPI 或 uvicorn 未安装，无法启动服务器")
            logger.error("[WebAPI] 请运行: pip install fastapi uvicorn python-multipart")
            return
        
        app = create_app()
        
        logger.info(f"[WebAPI] 启动 API 服务器: {host}:{port}")
        logger.info(f"[WebAPI] 文档地址: http://{host}:{port}/docs")
        
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
