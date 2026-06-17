"""
核心模块测试
"""

import pytest
import tempfile
import os
from pathlib import Path
from typing import Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.task_scheduler import TaskScheduler, BaseTask, TaskStatus
from modules.plugin_manager import PluginManager, BaseAnalyzer, AnalyzerMetadata, AnalyzerType
from modules.config_manager import ConfigManager, get_config_manager, encrypt_value, decrypt_value
from modules.exception_handler import ExceptionHandler, AnalysisError, get_exception_handler
from modules.resource_control import (
    ResourceController, ResourceLimits, AnalysisType, 
    ResourceLimitFactory, EnhancedAnalysisCache
)


class TestTaskScheduler:
    """任务调度器测试"""
    
    def test_task_creation(self):
        """测试任务创建"""
        task = BaseTask(
            task_id="test_task",
            task_type="analysis",
            dependencies=[],
            config={"timeout": 30}
        )
        assert task.task_id == "test_task"
        assert task.task_type == "analysis"
        assert task.status == TaskStatus.PENDING
    
    def test_scheduler_initialization(self):
        """测试调度器初始化"""
        scheduler = TaskScheduler(max_workers=4)
        assert scheduler.max_workers == 4
        assert len(scheduler.tasks) == 0
    
    def test_add_task(self):
        """测试添加任务"""
        scheduler = TaskScheduler()
        task = BaseTask(
            task_id="test_add",
            task_type="analysis",
            dependencies=[]
        )
        scheduler.add_task(task)
        assert "test_add" in scheduler.tasks
    
    def test_dag_validation(self):
        """测试DAG验证"""
        scheduler = TaskScheduler()
        
        task1 = BaseTask(task_id="task1", task_type="analysis", dependencies=[])
        task2 = BaseTask(task_id="task2", task_type="analysis", dependencies=["task1"])
        task3 = BaseTask(task_id="task3", task_type="analysis", dependencies=["task2"])
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        scheduler.add_task(task3)
        
        assert scheduler.validate_dag() is True
    
    def test_circular_dependency(self):
        """测试循环依赖检测"""
        scheduler = TaskScheduler()
        
        task1 = BaseTask(task_id="task1", task_type="analysis", dependencies=["task2"])
        task2 = BaseTask(task_id="task2", task_type="analysis", dependencies=["task1"])
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        
        assert scheduler.validate_dag() is False


class TestPluginManager:
    """插件管理器测试"""
    
    def test_plugin_manager_initialization(self):
        """测试插件管理器初始化"""
        pm = PluginManager()
        assert pm is not None
    
    def test_list_analyzers(self):
        """测试列出分析器"""
        pm = PluginManager()
        analyzers = pm.list_analyzers()
        assert isinstance(analyzers, list)
    
    def test_get_analyzer_metadata(self):
        """测试获取分析器元数据"""
        pm = PluginManager()
        if pm.list_analyzers():
            first_analyzer = pm.list_analyzers()[0]
            metadata = pm.get_analyzer_metadata(first_analyzer)
            assert metadata is not None
            assert isinstance(metadata, AnalyzerMetadata)


class TestConfigManager:
    """配置管理器测试"""
    
    def test_config_manager_initialization(self):
        """测试配置管理器初始化"""
        cm = get_config_manager()
        cm.initialize()
        assert cm.is_initialized is True
    
    def test_config_get(self):
        """测试获取配置值"""
        cm = get_config_manager()
        cm.initialize()
        value = cm.get("logging.level", "INFO")
        assert value is not None
    
    def test_config_set(self):
        """测试设置配置值"""
        cm = get_config_manager()
        cm.initialize()
        result = cm.set("test.key", "test_value")
        assert result is True
        assert cm.get("test.key") == "test_value"


class TestExceptionHandler:
    """异常处理器测试"""
    
    def test_exception_handler_initialization(self):
        """测试异常处理器初始化"""
        eh = get_exception_handler()
        assert eh is not None
    
    def test_handle_exception(self):
        """测试处理异常"""
        eh = get_exception_handler()
        exc = AnalysisError("Test error")
        result = eh.handle_exception(exc)
        assert "message" in result
        assert result["message"] == "Test error"
    
    def test_error_count(self):
        """测试错误计数"""
        eh = get_exception_handler()
        initial_count = eh.error_count
        exc = AnalysisError("Count test")
        eh.handle_exception(exc)
        assert eh.error_count == initial_count + 1


class TestResourceControl:
    """资源控制测试"""
    
    def test_resource_limits_creation(self):
        """测试资源限制创建"""
        limits = ResourceLimits(timeout=60, memory_limit=1024)
        assert limits.timeout == 60
        assert limits.memory_limit == 1024
    
    def test_resource_limit_factory(self):
        """测试资源限制工厂"""
        limits = ResourceLimitFactory.create_limits(AnalysisType.SYMBOLIC_EXECUTION)
        assert limits.timeout == 600
        assert limits.memory_limit == 4096
    
    def test_enhanced_cache(self, temp_dir):
        """测试增强型缓存"""
        cache = EnhancedAnalysisCache(str(temp_dir / "cache"))
        
        test_key = "test_cache_key"
        test_data = {"result": "test", "value": 42}
        
        cache.save_to_cache(test_key, test_data)
        retrieved = cache.get_from_cache(test_key)
        
        assert retrieved is not None
        assert retrieved["result"] == "test"
        assert retrieved["value"] == 42
    
    def test_cache_invalidation(self, temp_dir):
        """测试缓存失效"""
        cache = EnhancedAnalysisCache(str(temp_dir / "cache"))
        
        test_key = "test_invalidate"
        test_data = {"value": 100}
        
        cache.save_to_cache(test_key, test_data)
        cache.invalidate_cache(test_key)
        
        retrieved = cache.get_from_cache(test_key)
        assert retrieved is None


class TestIntegration:
    """集成测试"""
    
    @pytest.mark.slow
    def test_full_pipeline(self, temp_dir):
        """测试完整分析流程"""
        scheduler = TaskScheduler(max_workers=2)
        
        task1 = BaseTask(
            task_id="preprocess",
            task_type="preprocess",
            dependencies=[],
            config={"timeout": 30}
        )
        
        task2 = BaseTask(
            task_id="analyze",
            task_type="analysis",
            dependencies=["preprocess"],
            config={"timeout": 60}
        )
        
        task3 = BaseTask(
            task_id="report",
            task_type="report",
            dependencies=["analyze"],
            config={}
        )
        
        scheduler.add_task(task1)
        scheduler.add_task(task2)
        scheduler.add_task(task3)
        
        assert scheduler.validate_dag() is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])