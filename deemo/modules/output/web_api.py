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

CELERY_AVAILABLE = False
try:
    import celery  # noqa: F401
    CELERY_AVAILABLE = True
except ImportError:
    logger.warning("[WebAPI] celery 未安装，分布式任务功能不可用")


if FASTAPI_AVAILABLE:

    class AnalysisRequest(BaseModel):
        """分析请求参数体"""
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
        """漏洞查询过滤条件"""
        vulnerability_type: Optional[str] = Field(None, description="漏洞类型")
        function_name: Optional[str] = Field(None, description="函数名")
        binary_format: Optional[str] = Field(None, description="文件格式")
        architecture: Optional[str] = Field(None, description="架构")
        severity: Optional[str] = Field(None, description="严重程度")
        limit: int = Field(20, ge=1, le=100, description="返回数量限制")
        offset: int = Field(0, ge=0, description="偏移量")

    class AnalysisTaskStatus(BaseModel):
        """分析任务状态快照"""
        task_id: str
        status: str
        created_at: str
        updated_at: Optional[str]
        progress: int
        message: Optional[str]
        result: Optional[Dict[str, Any]]

    class APIResponse(BaseModel):
        """统一 API 应答信封"""
        success: bool
        message: Optional[str]
        data: Optional[Any]


    class AnalysisTaskManager:
        """
        分析任务调度器。

        管理异步分析任务的创建、执行与状态追踪。
        """

        def __init__(self, tasks_dir: str = None):
            self.tasks: Dict[str, Dict[str, Any]] = {}
            self.tasks_dir = tasks_dir or os.path.join(Config.DATA_DIR, 'api_tasks')
            self._ensure_tasks_dir()

        def _ensure_tasks_dir(self):
            if not os.path.exists(self.tasks_dir):
                os.makedirs(self.tasks_dir, exist_ok=True)

        def create_task(self, request: AnalysisRequest) -> str:
            """新建分析任务并持久化。"""
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
            """按 ID 检索任务；内存未命中则回退磁盘加载。"""
            if task_id in self.tasks:
                return self.tasks[task_id]

            task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
            if os.path.exists(task_file):
                try:
                    import json
                    with open(task_file, 'r', encoding='utf-8') as f:
                        return json.load(f)
                except (OSError, json.JSONDecodeError):  # 异常窄化: bare except → OSError/JSONDecodeError
                    pass

            return None

        def update_task(self, task_id: str, **kwargs) -> bool:
            """合并更新任务字段并写回持久化存储。"""
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
            """JSON 序列化任务至磁盘文件。"""
            import json
            task_file = os.path.join(self.tasks_dir, f"{task_id}.json")
            try:
                with open(task_file, 'w', encoding='utf-8') as f:
                    json.dump(task, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logger.warning(f"[TaskManager] 保存任务失败: {e}")

        def list_tasks(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
            """枚举任务清单，支持按状态过滤。"""
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
        """后台执行完整分析流水线：收集→反编译→检查→产出报告。"""
        from modules.output.report import ReportGenerator

        logger.info(f"[TaskRunner] 开始执行任务: {task_id}")

        try:
            task_manager.update_task(task_id, status='running', progress=5, message='正在初始化分析...')

            reports_dir = os.path.join(task_manager.tasks_dir, task_id, 'reports')
            if not os.path.exists(reports_dir):
                os.makedirs(reports_dir, exist_ok=True)

            # 上传目录优先, 其次 binary_name 本身视为路径
            binary_path = os.path.join(
                task_manager.tasks_dir, 'uploads', request.binary_name)
            if not os.path.isfile(binary_path):
                binary_path = request.binary_name
            if not os.path.isfile(binary_path):
                task_manager.update_task(
                    task_id, status='failed', progress=100,
                    message='二进制文件不存在: 请先调用 /api/analyze/upload 上传')
                return

            task_manager.update_task(task_id, progress=20, message='正在收集二进制信息...')

            from core.pipeline import run_pipeline

            pipeline_result = run_pipeline(
                binary_path=binary_path,
                functions=request.function_names or None,
                max_funcs=20,
                include_lib=False,
                parallel=False,
                output_format='json',
                decompiler='auto',
                symbolic=request.enable_symbolic,
                fuzz=bool(request.fuzzer_type),
            )
            if 'error' in pipeline_result:
                task_manager.update_task(
                    task_id, status='failed', progress=100,
                    message=f"分析失败: {pipeline_result['error']}")
                return

            binfo = pipeline_result.get('binary_info', {})
            binary_info = {
                'binary_path': binary_path,
                'binary_name': request.binary_name,
                'binary_format': binfo.get('format', request.binary_format or 'unknown'),
                'arch': binfo.get('arch', request.architecture or 'unknown'),
                'bits': binfo.get('bits', 64 if request.architecture in ['amd64', 'x86_64'] else 32),
                'checksec': {},
                'symbols': {},
                'imports': [],
                'strings': []
            }

            task_manager.update_task(task_id, progress=50, message='正在分析函数...')

            func_analyses = []
            for r in pipeline_result.get('decomp_analysis', []):
                analysis = r.get('analysis', r) or {}
                vulns = analysis.get('vulnerabilities', [])
                func_analyses.append({
                    'function_name': r.get('function_name', r.get('function', '?')),
                    'pseudocode': analysis.get('pseudocode', ''),
                    'analysis': {
                        'vulnerabilities': vulns,
                        'risk_level': 'High' if vulns else 'Low',
                        'summary': analysis.get('summary', ''),
                    }
                })

            task_manager.update_task(task_id, progress=70, message='正在生成报告...')

            report_gen = ReportGenerator(output_dir=reports_dir)

            report_paths = {}
            if 'md' in request.report_formats:
                report_paths['markdown'] = report_gen.generate_report(
                    binary_path=binary_path,
                    binary_info=binary_info,
                    decomp_results=func_analyses,
                    crash_analysis=None,
                    exploit_result=None
                )

            if 'json' in request.report_formats:
                report_paths['json'] = report_gen.generate_json_report(
                    binary_path=binary_path,
                    binary_info=binary_info,
                    decomp_results=func_analyses,
                    crash_analysis=None,
                    exploit_result=None
                )

            if 'html' in request.report_formats:
                report_paths['html'] = report_gen.generate_html_report(
                    binary_path=binary_path,
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
        """构造带完整路由挂载的 FastAPI 实例。"""
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
            """根路径 — 服务状态快照"""
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
                    "tasks": "/api/tasks",
                    "diff": "/api/reports/diff",
                    "cvss_env": "/api/cvss/environmental",
                    "cache_stats": "/api/cache/stats"
                }
            }

        @app.get("/api/health")
        async def health_check():
            """存活探针：返回服务运行状态。"""
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
            提交异步分析请求。

            创建任务即返回；任务由 BackgroundTasks 异步调度执行。
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
            """上传二进制 → SHA-256 校验 → 入队分析任务。"""
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
            """列举已提交的分析任务。"""
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
            """按 ID 拉取单个任务的状态与结果载荷。"""
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
            """标记任务为已取消。"""
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
            """枚举某任务产出的所有报告文件及格式。"""
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
            """以 FileResponse 流式下发指定格式的报告文件。"""
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
                'pdf': 'application/pdf',
                'sarif': 'application/sarif+json'
            }

            return FileResponse(
                path=report_path,
                filename=os.path.basename(report_path),
                media_type=media_types.get(format, 'application/octet-stream')
            )

        @app.post("/api/vulnerabilities")
        async def query_vulnerabilities(query: VulnerabilityQuery):
            """按多种维度检索本地漏洞数据库。"""
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase

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
            拉取漏洞库聚合统计。
            """
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase

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
            """按主键取单个漏洞详情。"""
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase

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

# 增量报告与内容寻址缓存

        class DiffRequest(BaseModel):
            """增量差异请求体"""
            task_id_a: str = Field(..., description="基线任务 ID")
            task_id_b: str = Field(..., description="比较任务 ID")
            output_format: str = Field("md", description="输出格式: md")

        @app.post("/api/reports/diff")
        async def diff_reports(request: DiffRequest):
            """
            对比两次分析任务的发现集合，产出增量差异汇总。

            返回 added/removed/changed/unchanged 分类统计。
            """
            task_a = task_manager.get_task(request.task_id_a)
            task_b = task_manager.get_task(request.task_id_b)

            if not task_a:
                raise HTTPException(status_code=404, detail=f"任务不存在: {request.task_id_a}")
            if not task_b:
                raise HTTPException(status_code=404, detail=f"任务不存在: {request.task_id_b}")

            findings_a = task_a.get('result', {}).get('function_analyses', [])
            findings_b = task_b.get('result', {}).get('function_analyses', [])

            # 扁平化 function_analyses → 独立 finding 行
            def flatten_findings(analyses: List[Dict]) -> List[Dict]:
                result = []
                for fa in (analyses or []):
                    vulns = fa.get('analysis', {}).get('vulnerabilities', [])
                    for v in vulns:
                        v = dict(v)
                        v['function_name'] = fa.get('function_name', '')
                        result.append(v)
                return result

            flat_a = flatten_findings(findings_a)
            flat_b = flatten_findings(findings_b)

            from modules.output.src.report_differ import diff_findings
            diffs = diff_findings(flat_a, flat_b)

            diff_entries = []
            for d in diffs:
                diff_entries.append({
                    'status': d.status.value,
                    'finding_id': d.finding_id,
                    'summary': d.summary(),
                    'changed_fields': d.changed_fields,
                })

            return APIResponse(
                success=True,
                message=f"差异比较完成: {len(diffs)} 个变化",
                data={
                    'task_a': request.task_id_a,
                    'task_b': request.task_id_b,
                    'diff_count': len(diffs),
                    'added': sum(1 for d in diffs if d.status.value == 'added'),
                    'removed': sum(1 for d in diffs if d.status.value == 'removed'),
                    'changed': sum(1 for d in diffs if d.status.value == 'changed'),
                    'unchanged': sum(1 for d in diffs if d.status.value == 'unchanged'),
                    'differences': diff_entries,
                }
            )

        @app.get("/api/cache/stats")
        async def get_cache_stats():
            """返回内容寻址缓存的命中率与条目数。"""
            from modules.output.src.report_cache import ReportCache
            cache = ReportCache()
            stats = cache.stats
            stats['entries_on_disk'] = cache.count_entries()
            return APIResponse(
                success=True,
                message="缓存统计",
                data=stats
            )

# CVSS 环境评分 (从二进制加固自动推断)

        class EnvironmentalScoreRequest(BaseModel):
            """CVSS 环境评分请求"""
            vuln_type: str = Field("buffer_overflow", description="漏洞类型")
            severity: str = Field("high", description="严重度")
            checksec_nx: bool = Field(True, description="NX 启用")
            checksec_pie: bool = Field(True, description="PIE 启用")
            checksec_canary: bool = Field(True, description="Stack Canary 启用")
            checksec_relro: str = Field("full", description="RELRO: full/partial/none")
            checksec_fortify: bool = Field(False, description="FORTIFY_SOURCE 启用")
            cwe: str = Field("", description="CWE 编号")

        @app.post("/api/cvss/environmental")
        async def compute_environmental_score(request: EnvironmentalScoreRequest):
            """
            从二进制加固状态计算 CVSS 3.1 完整环境评分。

            自动推断 Modified Base Metrics 和安全需求 (CR/IR/AR)，
            返回三层评分 (基础/时间/环境) 及完整向量。
            """
            from modules.output.src.report_core import ReportGeneratorCore, round_up
            from modules.output.src.cvss_environmental import compute_environmental_score
            from modules.output.src.cvss_temporal import compute_full_temporal

            core = ReportGeneratorCore()
            vuln_info = {'type': request.vuln_type, 'severity': request.severity, 'cwe': request.cwe}
            base_result = core.calculate_cvss(vuln_info)
            temporal = compute_full_temporal(base_result['base_score'])

            checksec = {
                'NX': request.checksec_nx,
                'PIE': request.checksec_pie,
                'Canary': request.checksec_canary,
                'RELRO': request.checksec_relro,
                'FORTIFY': request.checksec_fortify,
            }
            env = compute_environmental_score(
                base_score=base_result['base_score'],
                temporal_score=temporal['temporal_score'],
                checksec=checksec,
                base_metrics=base_result['metrics'],
            )

            return APIResponse(
                success=True,
                message="环境评分计算完成",
                data={
                    'base_score': base_result['base_score'],
                    'temporal_score': temporal['temporal_score'],
                    'environmental_score': env['environmental_score'],
                    'security_requirements': env['security_requirements'],
                    'modified_metrics': env['modified_metrics'],
                    'full_vector': base_result['vector_string'] + temporal['vector_suffix'] + env['modified_vector_suffix'],
                }
            )

        @app.post("/api/vulnerabilities/external")
        async def query_external_vulnerabilities(
            package_name: str = None,
            cve_id: str = None,
            binary_name: str = None
        ):
            """联合查询外部漏洞源（NVD + OSV + GHSA）。"""
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase

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

        # ============ 前端契约路由: 轮询分析结果 ============

        @app.get("/api/analyze/{task_id}")
        async def get_analysis_result(task_id: str):
            """
            前端分析结果轮询端点。

            前端提交 POST /api/analyze 后持 task_id 轮询本端点；
            completed 时返回扁平化漏洞列表与精简二进制信息。
            """
            task = task_manager.get_task(task_id)
            if not task:
                raise HTTPException(status_code=404, detail=f"任务不存在: {task_id}")

            status = task.get('status')
            if status not in ('completed', 'failed'):
                return APIResponse(
                    success=True,
                    message=task.get('message', ''),
                    data={
                        'analysis_id': task_id,
                        'status': status,
                        'progress': task.get('progress', 0),
                        'message': task.get('message', '')
                    }
                )

            if status == 'failed':
                return APIResponse(
                    success=True,
                    message=task.get('message', '分析失败'),
                    data={
                        'analysis_id': task_id,
                        'status': 'failed',
                        'message': task.get('message', '')
                    }
                )

            result = task.get('result', {}) or {}

            # 从任务结果提取前端消费的字段
            raw_binfo = result.get('binary_info', {}) or {}
            binary_info = {
                'format': raw_binfo.get('binary_format', 'unknown'),
                'arch': raw_binfo.get('arch', 'unknown'),
                'bits': raw_binfo.get('bits', 0),
                'language': raw_binfo.get('language', ''),
                'size': raw_binfo.get('size', 0),
                'binary_path': raw_binfo.get('binary_path', ''),
                'binary_name': raw_binfo.get('binary_name', '')
            }

            # 漏洞列表扁平化: function_analyses[].analysis.vulnerabilities[]
            vulnerabilities = []
            for fa in result.get('function_analyses', []):
                analysis = fa.get('analysis', {}) or {}
                for v in analysis.get('vulnerabilities', []):
                    vulnerabilities.append({
                        'type': v.get('type', v.get('vulnerability_type', 'unknown')),
                        'severity': v.get('severity', 'Low'),
                        'function_name': v.get('function_name', fa.get('function_name', '')),
                        'description': str(v.get('description', v.get('message', '')))[:500],
                        'cwe': v.get('cwe', ''),
                        'exploitation': v.get('exploitation', '')
                    })

            report_paths = result.get('reports', {}) or {}
            report_paths_norm = {
                'markdown': report_paths.get('markdown', ''),
                'json': report_paths.get('json', ''),
                'html': report_paths.get('html', '')
            }

            return APIResponse(
                success=True,
                message='分析完成',
                data={
                    'analysis_id': task_id,
                    'status': 'completed',
                    'binary_info': binary_info,
                    'vulnerabilities': vulnerabilities,
                    'pseudocode': '',
                    'report_paths': report_paths_norm,
                    'created_at': task.get('created_at', '')
                }
            )

        # ============ 前端契约路由: 模糊测试会话 ============

        # 模块级会话表: session_id → FuzzManager 实例与元数据
        FUZZ_SESSIONS: Dict[str, Dict[str, Any]] = {}

        class FuzzStartRequest(BaseModel):
            """前端模糊测试启动请求体"""
            binary_path: str = Field(..., description="目标二进制路径")
            fuzzer_type: str = Field("auto", description="Fuzzer 类型: libfuzzer, afl, afl++, auto")
            duration: Optional[int] = Field(None, description="运行时长秒数(可选)")

        @app.post("/api/fuzz/start")
        async def start_fuzz_session(request: FuzzStartRequest):
            """启动模糊测试会话，包装 FuzzManager 真实执行。"""
            if not request.binary_path or not os.path.isfile(request.binary_path):
                raise HTTPException(
                    status_code=400,
                    detail=f"二进制文件不存在: {request.binary_path}"
                )

            from modules.fuzzing.fuzz_integration import FuzzManager

            try:
                manager = FuzzManager(
                    binary_path=request.binary_path,
                    fuzzer_type=request.fuzzer_type or 'auto'
                )
            except (ValueError, OSError) as e:
                raise HTTPException(status_code=400, detail=f"Fuzzer 初始化失败: {e}")

            timeout = None
            if request.duration:
                timeout = max(1, int(request.duration))

            try:
                start_result = manager.start(timeout=timeout)
            except Exception as e:
                logger.error(f"[WebAPI] 启动模糊测试失败: {e}")
                raise HTTPException(status_code=500, detail=f"启动失败: {e}")

            if not start_result.get('success'):
                raise HTTPException(
                    status_code=500,
                    detail=f"启动失败: {start_result.get('status', 'unknown')}"
                )

            session_id = start_result.get('session_id', str(uuid.uuid4()))
            FUZZ_SESSIONS[session_id] = {
                'manager': manager,
                'fuzzer_type': start_result.get('fuzzer_type', request.fuzzer_type),
                'binary_path': request.binary_path,
                'started_at': datetime.now().isoformat()
            }

            return APIResponse(
                success=True,
                message='模糊测试已启动',
                data=_fuzz_status_payload(session_id)
            )

        def _fuzz_status_payload(session_id: str) -> Dict[str, Any]:
            """组装 FuzzManager 状态为前端 FuzzSession 结构。"""
            entry = FUZZ_SESSIONS.get(session_id)
            if not entry:
                raise HTTPException(status_code=404, detail=f"模糊测试会话不存在: {session_id}")

            manager = entry['manager']
            status_raw = manager.get_status()
            return {
                'session_id': session_id,
                'fuzzer_type': entry.get('fuzzer_type', ''),
                'binary_path': entry.get('binary_path', ''),
                'status': status_raw.get('status', 'unknown'),
                'started_at': entry.get('started_at', ''),
                'coverage': status_raw.get('stats', {}).get('coverage', 0.0),
                'crashes': status_raw.get('crashes_found', 0)
            }

        @app.get("/api/fuzz/status/{session_id}")
        async def get_fuzz_session_status(session_id: str):
            """查询模糊测试会话状态。"""
            return APIResponse(
                success=True,
                message='会话状态',
                data=_fuzz_status_payload(session_id)
            )

        @app.post("/api/fuzz/stop/{session_id}")
        async def stop_fuzz_session(session_id: str):
            """停止模糊测试会话并返回停止后状态。"""
            entry = FUZZ_SESSIONS.get(session_id)
            if not entry:
                raise HTTPException(status_code=404, detail=f"模糊测试会话不存在: {session_id}")

            manager = entry['manager']
            try:
                manager.stop()
            except Exception as e:
                logger.error(f"[WebAPI] 停止模糊测试失败: {e}")

            return APIResponse(
                success=True,
                message='会话已停止',
                data=_fuzz_status_payload(session_id)
            )

        # ============ 前端契约路由: 项目管理 ============

        def _project_meta_to_item(meta: Dict[str, Any]) -> Dict[str, Any]:
            """ProjectManager meta → 前端 ProjectItem 字段映射。"""
            return {
                'id': meta.get('project_id', ''),
                'name': meta.get('name', ''),
                'binary_path': meta.get('binary_path', ''),
                'status': meta.get('state', 'active'),
                'current_step': '',
                'created_at': meta.get('created', ''),
                'updated_at': meta.get('modified', '')
            }

        @app.get("/api/projects")
        async def list_projects_for_frontend():
            """列出全部项目，返回前端期望的裸数组。"""
            try:
                from modules.project.project_manager import ProjectManager

                pm = ProjectManager()
                metas = pm.list_projects()
                items = [_project_meta_to_item(m) for m in (metas or [])]

                return APIResponse(
                    success=True,
                    message=f"共 {len(items)} 个项目",
                    data=items
                )
            except Exception as e:
                logger.error(f"[WebAPI] 列出项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        class ProjectCreateRequest(BaseModel):
            """前端项目创建请求体"""
            name: str = Field(..., description="项目名称")
            binary_path: str = Field("", description="关联二进制路径(可选)")

        @app.post("/api/projects")
        async def create_project_for_frontend(request: ProjectCreateRequest):
            """创建项目，返回创建后的完整项目条目。"""
            try:
                from modules.project.project_manager import ProjectManager

                pm = ProjectManager()
                project_id = pm.create_project(
                    name=request.name,
                    binary_path=request.binary_path or ""
                )

                return APIResponse(
                    success=True,
                    message='项目已创建',
                    data={'project_id': project_id, 'name': request.name}
                )
            except (ValueError, TypeError) as e:
                raise HTTPException(status_code=400, detail=f"项目创建失败: {e}")
            except Exception as e:
                logger.error(f"[WebAPI] 创建项目失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ============ 前端契约路由: 漏洞检索 ============

        class VulnSearchRequest(BaseModel):
            """前端漏洞检索请求体"""
            query: str = Field("", description="检索关键词")
            limit: int = Field(20, ge=1, le=100, description="返回数量限制")

        @app.post("/api/vuln/search")
        async def search_vulnerabilities_for_frontend(request: VulnSearchRequest):
            """关键词检索漏洞库: 非空关键词走综合模糊检索，空则回退全量。"""
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase

                db = VulnerabilityDatabase()
                keyword = (request.query or '').strip()

                if not keyword:
                    results = db.get_all(limit=request.limit, offset=0)
                else:
                    # 语义相似检索 + 函数名/类型精确检索并集去重
                    results = db.search_similar(
                        pseudocode=keyword,
                        limit=request.limit,
                        fuzzy_search=True
                    )
                    if not results:
                        results = db.search_by_function(keyword, limit=request.limit)
                    if not results:
                        results = db.search_by_vulnerability_type(keyword, limit=request.limit)

                return APIResponse(
                    success=True,
                    message=f"找到 {len(results)} 条记录",
                    data={'vulnerabilities': results, 'count': len(results)}
                )
            except Exception as e:
                logger.error(f"[WebAPI] 漏洞检索失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        # ============ 前端契约路由: 知识图谱 ============

        @app.get("/api/knowledge/graph")
        async def get_knowledge_graph(project_id: str = None):
            """
            基于漏洞库真实记录构建异构知识图谱。

            漏洞记录 → findings → build_vuln_graph_from_findings
            → 展平为前端 D3 消费的 nodes/links 结构。
            """
            try:
                from modules.vuln.vuln_db import VulnerabilityDatabase
                from modules.project.vuln_knowledge_graph import (
                    build_vuln_graph_from_findings, GraphSerializer
                )

                db = VulnerabilityDatabase()
                records = db.get_all(limit=100, offset=0)

                # 数据库行 → 图构建器期望的 findings 结构
                findings = []
                for r in records:
                    cwe = ''
                    desc = str(r.get('description', ''))
                    # 描述中的 CVE 编号用于命名节点
                    title = f"{r.get('vulnerability_type', 'unknown')}@{r.get('function_name', '')}"
                    findings.append({
                        'rule_id': f"db-{r.get('id', len(findings))}",
                        'title': title,
                        'severity': str(r.get('severity', 'medium')).lower(),
                        'file': r.get('binary_name', ''),
                        'line': 0,
                        'cwe': cwe,
                        'description': desc,
                        'function_name': r.get('function_name', '')
                    })

                component = project_id or 'vulnerability-database'
                graph = build_vuln_graph_from_findings(findings, component=component)
                serialized = GraphSerializer.to_dict(graph)

                # 展平: {node_type: {id: {...}}} → [{id, name, type}]
                nodes = []
                for node_type, node_map in (serialized.get('nodes', {}) or {}).items():
                    for node_id, node_info in node_map.items():
                        props = node_info.get('properties', {}) or {}
                        name = props.get('title') or props.get('name') or node_id
                        nodes.append({
                            'id': node_id,
                            'name': name,
                            'type': node_type,
                            'properties': props
                        })

                # 展平: {edge_type: [{source, target, ...}]} → [{source, target, type}]
                links = []
                for edge_type, edge_list in (serialized.get('edges', {}) or {}).items():
                    for e in edge_list:
                        links.append({
                            'source': e.get('source', ''),
                            'target': e.get('target', ''),
                            'type': edge_type,
                            'weight': e.get('weight', 1.0)
                        })

                return APIResponse(
                    success=True,
                    message=f"图谱构建完成: {len(nodes)} 节点, {len(links)} 边",
                    data={
                        'nodes': nodes,
                        'links': links,
                        'stats': serialized.get('stats', {})
                    }
                )
            except Exception as e:
                logger.error(f"[WebAPI] 构建知识图谱失败: {e}")
                raise HTTPException(status_code=500, detail=str(e))

        logger.info("[WebAPI] API 应用创建完成")
        return app


    def start_server(
        host: str = "0.0.0.0",
        port: int = 8000,
        reload: bool = False
    ):
        """通过 uvicorn 启动 API 服务进程。"""
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
        API 服务端占位符 — FastAPI/uvicorn 依赖缺失时抛出 ImportError。
        """
        logger.error("[WebAPI] FastAPI 或 uvicorn 未安装，无法启动服务器")
        logger.error("[WebAPI] 请运行: pip install fastapi uvicorn python-multipart")
        raise ImportError("FastAPI 和 uvicorn 必须安装才能使用 Web API 功能")

    app = None
