#!/usr/bin/env python3
"""
LLM 辅助二进制漏洞分析工具 - Web API 模块

提供 RESTful API 接口，支持项目管理和分析任务提交。
"""

import os
import sys
import json
import logging
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.project_manager import ProjectManager, ProjectState
from config import Config, ensure_directories, setup_logging

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Deemo Binary Vulnerability Analysis API",
    description="LLM 辅助的二进制漏洞分析工具 Web API",
    version="1.3.1"
)

project_manager = None


def init_app():
    """初始化应用"""
    global project_manager
    ensure_directories()
    project_manager = ProjectManager()
    logger.info("Web API 初始化完成")


class ProjectCreateRequest(BaseModel):
    """创建项目请求模型"""
    name: str = Field(..., description="项目名称")
    binary_path: str = Field(..., description="二进制文件路径")


class ProjectResumeRequest(BaseModel):
    """恢复项目请求模型"""
    resume_from_step: Optional[str] = Field(None, description="从指定步骤恢复")


class ProjectResponse(BaseModel):
    """项目响应模型"""
    id: str = Field(..., description="项目ID")
    name: str = Field(..., description="项目名称")
    binary_path: str = Field(..., description="二进制文件路径")
    created_at: str = Field(..., description="创建时间")
    last_modified: str = Field(..., description="最后修改时间")
    status: str = Field(..., description="项目状态")


class ProjectStateResponse(BaseModel):
    """项目状态响应模型"""
    project_id: str = Field(..., description="项目ID")
    current_step: str = Field(..., description="当前步骤")
    status: str = Field(..., description="项目状态")
    analyzed_functions: List[str] = Field(..., description="已分析的函数列表")
    discovered_vulnerabilities: List[Dict[str, Any]] = Field(..., description="已发现的漏洞")
    binary_info: Optional[Dict[str, Any]] = Field(None, description="二进制文件信息")
    created_at: str = Field(..., description="创建时间")
    last_modified: str = Field(..., description="最后修改时间")


@app.post("/api/projects", response_model=ProjectResponse, status_code=201)
async def create_project(request: ProjectCreateRequest):
    """
    创建新项目
    
    Args:
        request: 包含项目名称和二进制文件路径
    
    Returns:
        创建的项目信息
    """
    try:
        logger.info(f"创建新项目: {request.name}, 二进制文件: {request.binary_path}")
        
        if not project_manager:
            init_app()
        
        project_id = project_manager.create_project(request.name, request.binary_path)
        
        if not project_id:
            raise HTTPException(status_code=400, detail="创建项目失败")
        
        metadata = project_manager.get_project_metadata(project_id)
        
        if not metadata:
            raise HTTPException(status_code=500, detail="获取项目元数据失败")
        
        return ProjectResponse(
            id=metadata['id'],
            name=metadata['name'],
            binary_path=metadata['binary_path'],
            created_at=metadata['created_at'],
            last_modified=metadata.get('last_modified', metadata['created_at']),
            status='created'
        )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"创建项目失败: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")


@app.get("/api/projects", response_model=List[ProjectResponse])
async def list_projects():
    """
    列出所有项目
    
    Returns:
        项目列表
    """
    try:
        if not project_manager:
            init_app()
        
        projects = project_manager.list_projects()
        
        response = []
        for project in projects:
            response.append(ProjectResponse(
                id=project['id'],
                name=project['name'],
                binary_path=project['binary_path'],
                created_at=project['created_at'],
                last_modified=project.get('last_modified', project['created_at']),
                status=project.get('status', 'unknown')
            ))
        
        return response
    
    except Exception as e:
        logger.error(f"获取项目列表失败: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")


@app.get("/api/projects/{project_id}", response_model=ProjectStateResponse)
async def get_project(project_id: str):
    """
    获取项目状态
    
    Args:
        project_id: 项目ID
    
    Returns:
        项目状态信息
    """
    try:
        if not project_manager:
            init_app()
        
        state = project_manager.load_project(project_id)
        
        if not state:
            raise HTTPException(status_code=404, detail="项目不存在或无法加载")
        
        metadata = project_manager.get_project_metadata(project_id)
        
        return ProjectStateResponse(
            project_id=project_id,
            current_step=state.current_step,
            status=state.status,
            analyzed_functions=state.analyzed_functions,
            discovered_vulnerabilities=state.discovered_vulnerabilities,
            binary_info=state.binary_info,
            created_at=metadata.get('created_at', ''),
            last_modified=metadata.get('last_modified', '')
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"获取项目状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")


@app.post("/api/projects/{project_id}/resume")
async def resume_project(project_id: str, request: Optional[ProjectResumeRequest] = None):
    """
    恢复项目分析
    
    Args:
        project_id: 项目ID
        request: 恢复请求（可选）
    
    Returns:
        恢复结果
    """
    try:
        if not project_manager:
            init_app()
        
        state = project_manager.load_project(project_id)
        
        if not state:
            raise HTTPException(status_code=404, detail="项目不存在或无法加载")
        
        if request and request.resume_from_step:
            state.current_step = request.resume_from_step
        
        state.status = 'running'
        project_manager.save_state(project_id, state)
        
        logger.info(f"恢复项目分析: {project_id}, 从步骤: {state.current_step}")
        
        return {
            "message": "项目分析已恢复",
            "project_id": project_id,
            "current_step": state.current_step,
            "analyzed_functions_count": len(state.analyzed_functions),
            "vulnerabilities_found": len(state.discovered_vulnerabilities)
        }
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"恢复项目失败: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")


@app.delete("/api/projects/{project_id}", status_code=204)
async def delete_project(project_id: str):
    """
    删除项目
    
    Args:
        project_id: 项目ID
    """
    try:
        if not project_manager:
            init_app()
        
        success = project_manager.delete_project(project_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="项目不存在或删除失败")
        
        logger.info(f"删除项目: {project_id}")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"删除项目失败: {e}")
        raise HTTPException(status_code=500, detail=f"服务器内部错误: {str(e)}")


@app.get("/api/health")
async def health_check():
    """
    健康检查
    
    Returns:
        服务状态信息
    """
    return {
        "status": "healthy",
        "version": "1.3.1",
        "service": "Deemo Binary Vulnerability Analysis API"
    }


def run_server(host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
    """
    启动 API 服务器
    
    Args:
        host: 监听地址
        port: 监听端口
        reload: 是否自动重载
    """
    try:
        import uvicorn
        
        init_app()
        
        logger.info(f"启动 API 服务器: http://{host}:{port}")
        
        uvicorn.run(
            "web_api:app",
            host=host,
            port=port,
            reload=reload,
            log_level="info"
        )
    except ImportError:
        logger.error("uvicorn 未安装，请运行: pip install uvicorn")
        sys.exit(1)
    except Exception as e:
        logger.error(f"启动 API 服务器失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_server()