import os
import json
import uuid
import hashlib
import shutil
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import logging

from config import Config, mask_sensitive_data

logger = logging.getLogger(__name__)


class ProjectState:
    """
    项目状态对象，用于保存和恢复分析进度
    
    Attributes:
        project_id: 项目唯一标识符
        name: 项目名称
        binary_path: 分析的二进制文件路径
        created_at: 创建时间
        last_modified: 最后修改时间
        current_step: 当前分析步骤
        steps_completed: 已完成的步骤列表
        binary_info: 二进制文件信息
        decomp_results: 反编译分析结果
        symbolic_result: 符号执行结果
        crash_analysis: 崩溃分析结果
        exploit_result: 利用生成结果
        vulnerabilities: 发现的漏洞列表
        intermediate_results: 中间结果缓存
    """
    
    def __init__(self, project_id: str, name: str, binary_path: str):
        self.project_id = project_id
        self.name = name
        self.binary_path = binary_path
        self.created_at = datetime.now().isoformat()
        self.last_modified = self.created_at
        
        self.current_step = 'init'
        self.steps_completed: List[str] = []
        
        self.binary_info: Dict[str, Any] = {}
        self.decomp_results: List[Dict[str, Any]] = []
        self.symbolic_result: Optional[Dict[str, Any]] = None
        self.crash_analysis: Optional[Dict[str, Any]] = None
        self.exploit_result: Optional[Dict[str, Any]] = None
        self.vulnerabilities: List[Dict[str, Any]] = []
        self.intermediate_results: Dict[str, Any] = {}
    
    def update_step(self, step_name: str, data: Dict[str, Any] = None):
        """
        更新当前步骤并保存步骤数据
        
        Args:
            step_name: 步骤名称
            data: 步骤数据
        """
        self.current_step = step_name
        self.last_modified = datetime.now().isoformat()
        
        if step_name not in self.steps_completed:
            self.steps_completed.append(step_name)
        
        if data:
            self._update_data(step_name, data)
    
    def _update_data(self, step_name: str, data: Dict[str, Any]):
        """
        根据步骤名称更新对应的数据字段
        
        Args:
            step_name: 步骤名称
            data: 数据字典
        """
        if step_name == 'info_collect':
            self.binary_info = data
        elif step_name == 'decomp_analysis':
            self.decomp_results = data.get('results', [])
            self.vulnerabilities.extend(data.get('vulnerabilities', []

        elif step_name == 'symbolic_execution':
            self.symbolic_result = data
        elif step_name == 'crash_analysis':
            self.crash_analysis = data
        elif step_name == 'exploit_generation':
            self.exploit_result = data
        else:
            self.intermediate_results[step_name] = data
    
    def to_dict(self) -> Dict[str, Any]:
        """
        序列化为字典
        
        Returns:
            包含所有状态数据的字典
        """
        return {
            'project_id': self.project_id,
            'name': self.name,
            'binary_path': self.binary_path,
            'created_at': self.created_at,
            'last_modified': self.last_modified,
            'current_step': self.current_step,
            'steps_completed': self.steps_completed,
            'binary_info': self.binary_info,
            'decomp_results': self.decomp_results,
            'symbolic_result': self.symbolic_result,
            'crash_analysis': self.crash_analysis,
            'exploit_result': self.exploit_result,
            'vulnerabilities': self.vulnerabilities,
            'intermediate_results': self.intermediate_results
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectState':
        """
        从字典反序列化
        
        Args:
            data: 包含状态数据的字典
        
        Returns:
            ProjectState 对象
        """
        state = cls()
            project_id=data['project_id'],
            name=data['name'],
            binary_path=data['binary_path']
        
        state.created_at = data.get('created_at', datetime.now().isoformat(

        state.last_modified = data.get('last_modified', datetime.now().isoformat(

        state.current_step = data.get('current_step', 'init')
        state.steps_completed = data.get('steps_completed', [])
        state.binary_info = data.get('binary_info', {})
        state.decomp_results = data.get('decomp_results', [])
        state.symbolic_result = data.get('symbolic_result')
        state.crash_analysis = data.get('crash_analysis')
        state.exploit_result = data.get('exploit_result')
        state.vulnerabilities = data.get('vulnerabilities', [])
        state.intermediate_results = data.get('intermediate_results', {})
        
        return state
    
    def is_step_completed(self, step_name: str) -> bool:
        """
        检查步骤是否已完成
        
        Args:
            step_name: 步骤名称
        
        Returns:
            True 如果步骤已完成
        """
        return step_name in self.steps_completed


class ProjectManager:
    """
    项目管理器，负责项目的创建、加载、保存和删除
    
    Attributes:
        projects_dir: 项目存储目录
    """
    
    def __init__(self, projects_dir: str = None):
        """
        初始化项目管理器
        
        Args:
            projects_dir: 项目存储目录，默认为 data/projects/
        """
        self.projects_dir = projects_dir or os.path.join(Config.DATA_DIR, 'projects')
        self._ensure_dirs()
    
    def _ensure_dirs(self):
        """确保项目目录存在"""
        os.makedirs(self.projects_dir, exist_ok=True)
    
    def _validate_project_name(self, name: str) -> bool:
        """
        验证项目名称是否合法
        
        Args:
            name: 项目名称
        
        Returns:
            True 如果名称合法
        """
        import re
        
        if not name or not isinstance(name, str):
            return False
        
        if len(name) > 100:
            return False
        
        if re.search(r'[<>:"/\\|?*]', name):
            return False
        
        return True
    
    def _get_project_dir(self, project_id: str) -> str:
        """
        获取项目目录路径
        
        Args:
            project_id: 项目ID
        
        Returns:
            项目目录路径
        """
        return os.path.join(self.projects_dir, project_id)
    
    def _get_project_metadata_path(self, project_id: str) -> str:
        """
        获取项目元数据文件路径
        
        Args:
            project_id: 项目ID
        
        Returns:
            元数据文件路径
        """
        return os.path.join(self._get_project_dir(project_id), 'project.json')
    
    def _get_state_path(self, project_id: str) -> str:
        """
        获取状态文件路径
        
        Args:
            project_id: 项目ID
        
        Returns:
            状态文件路径
        """
        return os.path.join(self._get_project_dir(project_id), 'pipeline_state.json')
    
    def _get_results_dir(self, project_id: str) -> str:
        """
        获取结果目录路径
        
        Args:
            project_id: 项目ID
        
        Returns:
            结果目录路径
        """
        return os.path.join(self._get_project_dir(project_id), 'results')
    
    def create_project(self, name: str, binary_path: str) -> str:
        """
        创建新项目
        
        Args:
            name: 项目名称
            binary_path: 二进制文件路径
        
        Returns:
            项目ID
        
        Raises:
            ValueError: 如果项目名称无效或二进制路径不存在
        """
        if not self._validate_project_name(name):
            raise ValueError(f"无效的项目名称: {name}")
        
        if not os.path.exists(binary_path):
            raise ValueError(f"二进制文件不存在: {binary_path}")
        
        project_id = str(uuid.uuid4(

        project_dir = self._get_project_dir(project_id)
        results_dir = self._get_results_dir(project_id)
        
        os.makedirs(project_dir, exist_ok=True)
        os.makedirs(results_dir, exist_ok=True)
        
        metadata = {
            'project_id': project_id,
            'name': name,
            'binary_path': os.path.abspath(binary_path),
            'binary_hash': self._compute_file_hash(binary_path),
            'created_at': datetime.now().isoformat(),
            'status': 'active'
        }
        
        metadata_path = self._get_project_metadata_path(project_id)
        with open(metadata_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2, ensure_ascii=False)
        
        state = ProjectState(project_id, name, binary_path)
        self.save_state(project_id, state)
        
        logger.info(f"创建新项目: {name} (ID: {project_id})")
        return project_id
    
    def _compute_file_hash(self, file_path: str) -> str:
        """
        计算文件 SHA256 哈希
        
        Args:
            file_path: 文件路径
        
        Returns:
            SHA256 哈希值
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    
    def list_projects(self) -> List[Dict[str, Any]]:
        """
        列出所有项目
        
        Returns:
            项目列表，每个项目包含基本信息
        """
        projects = []
        
        if not os.path.exists(self.projects_dir):
            return projects
        
        for entry in os.listdir(self.projects_dir):
            entry_path = os.path.join(self.projects_dir, entry)
            if os.path.isdir(entry_path):
                metadata_path = self._get_project_metadata_path(entry)
                if os.path.exists(metadata_path):
                    try:
                        with open(metadata_path, 'r', encoding='utf-8') as f:
                            metadata = json.load(f)
                            projects.append(metadata)
                    except Exception as e:
                        logger.warning(f"读取项目元数据失败 {entry}: {e}")
        
        projects.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        return projects
    
    def load_project(self, project_id: str) -> Optional[ProjectState]:
        """
        加载项目状态
        
        Args:
            project_id: 项目ID
        
        Returns:
            ProjectState 对象，如果项目不存在返回 None
        """
        state_path = self._get_state_path(project_id)
        
        if not os.path.exists(state_path):
            logger.warning(f"项目状态文件不存在: {project_id}")
            return None
        
        try:
            with open(state_path, 'r', encoding='utf-8') as f:
                state_data = json.load(f)
                state = ProjectState.from_dict(state_data)
                return state
        except json.JSONDecodeError as e:
            logger.error(f"解析项目状态文件失败: {e}")
            return None
        except Exception as e:
            logger.error(f"加载项目状态失败: {e}")
            return None
    
    def get_project_metadata(self, project_id: str) -> Optional[Dict[str, Any]]:
        """
        获取项目元数据
        
        Args:
            project_id: 项目ID
        
        Returns:
            项目元数据字典，如果不存在返回 None
        """
        metadata_path = self._get_project_metadata_path(project_id)
        
        if not os.path.exists(metadata_path):
            return None
        
        try:
            with open(metadata_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"读取项目元数据失败: {e}")
            return None
    
    def save_state(self, project_id: str, state: ProjectState) -> bool:
        """
        保存项目状态
        
        Args:
            project_id: 项目ID
            state: ProjectState 对象
        
        Returns:
            True 如果保存成功
        """
        try:
            state_path = self._get_state_path(project_id)
            state.last_modified = datetime.now().isoformat()
            
            with open(state_path, 'w', encoding='utf-8') as f:
                json.dump(state.to_dict(), f, indent=2, ensure_ascii=False)
            
            metadata = self.get_project_metadata(project_id)
            if metadata:
                metadata['last_modified'] = state.last_modified
                metadata_path = self._get_project_metadata_path(project_id)
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"保存项目状态: {project_id}")
            return True
        except Exception as e:
            logger.error(f"保存项目状态失败: {e}")
            return False
    
    def delete_project(self, project_id: str) -> bool:
        """
        删除项目
        
        Args:
            project_id: 项目ID
        
        Returns:
            True 如果删除成功
        """
        project_dir = self._get_project_dir(project_id)
        
        if not os.path.exists(project_dir):
            logger.warning(f"项目目录不存在: {project_id}")
            return False
        
        try:
            shutil.rmtree(project_dir)
            logger.info(f"删除项目: {project_id}")
            return True
        except Exception as e:
            logger.error(f"删除项目失败: {e}")
            return False
    
    def save_intermediate_result(self, project_id: str, key: str, data: Any) -> bool:
        """
        保存中间结果到结果目录
        
        Args:
            project_id: 项目ID
            key: 结果键名
            data: 结果数据
        
        Returns:
            True 如果保存成功
        """
        try:
            results_dir = self._get_results_dir(project_id)
            file_name = f"{key}.json"
            file_path = os.path.join(results_dir, file_name)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            logger.debug(f"保存中间结果: {project_id}/{key}")
            return True
        except Exception as e:
            logger.error(f"保存中间结果失败: {e}")
            return False
    
    def load_intermediate_result(self, project_id: str, key: str) -> Optional[Any]:
        """
        加载中间结果
        
        Args:
            project_id: 项目ID
            key: 结果键名
        
        Returns:
            中间结果数据，如果不存在返回 None
        """
        try:
            results_dir = self._get_results_dir(project_id)
            file_path = os.path.join(results_dir, f"{key}.json")
            
            if not os.path.exists(file_path):
                return None
            
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载中间结果失败: {e}")
            return None
    
    def find_project_by_binary(self, binary_path: str) -> Optional[str]:
        """
        根据二进制文件路径查找项目
        
        Args:
            binary_path: 二进制文件路径
        
        Returns:
            项目ID，如果未找到返回 None
        """
        target_hash = self._compute_file_hash(binary_path)
        
        for project in self.list_projects():
            if project.get('binary_hash') == target_hash:
                return project.get('project_id')
        
        return None
    
    def has_pending_state(self, project_id: str) -> bool:
        """
        检查项目是否有未完成的状态
        
        Args:
            project_id: 项目ID
        
        Returns:
            True 如果项目有未完成的状态
        """
        state = self.load_project(project_id)
        if not state:
            return False
        
        all_steps = ['info_collect', 'decomp_analysis', 'symbolic_execution', 
                     'crash_analysis', 'exploit_generation', 'report_generation']
        
        return not all(step in state.steps_completed for step in all_steps)


# 全局项目管理器实例
_project_manager = None

def get_project_manager() -> ProjectManager:
    """
    获取全局项目管理器实例
    
    Returns:
        ProjectManager 实例
    """
    global _project_manager
    if _project_manager is None:
        _project_manager = ProjectManager()
    return _project_manager))))))))"