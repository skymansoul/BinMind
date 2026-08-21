
import unittest
from unittest.mock import Mock, patch
from modules.task_scheduler import (
    TaskScheduler,
    TaskStatus,
    TaskType,
    TaskResult,
    TaskDependency,
    BaseTask,
    SimpleTask,
    AnalysisTask,
    AnalysisPipeline,
    create_default_pipeline
)


class TestTaskStatus(unittest.TestCase):
    """测试任务状态枚举"""

    def test_status_values(self):
        """测试状态值"""
        self.assertEqual(TaskStatus.PENDING.value, 'pending')
        self.assertEqual(TaskStatus.RUNNING.value, 'running')
        self.assertEqual(TaskStatus.SUCCESS.value, 'success')
        self.assertEqual(TaskStatus.FAILED.value, 'failed')


class TestTaskType(unittest.TestCase):
    """测试任务类型枚举"""

    def test_type_values(self):
        """测试类型值"""
        self.assertEqual(TaskType.ANALYSIS.value, 'analysis')
        self.assertEqual(TaskType.TRANSFORMATION.value, 'transformation')
        self.assertEqual(TaskType.EXPORT.value, 'export')


class TestTaskResult(unittest.TestCase):
    """测试任务结果"""

    def test_result_creation(self):
        result = TaskResult(
            task_id='task1',
            status=TaskStatus.SUCCESS,
            result={'data': 'test'},
            error=None
        )
        self.assertEqual(result.task_id, 'task1')
        self.assertEqual(result.status, TaskStatus.SUCCESS)
        self.assertEqual(result.result, {'data': 'test'})


class TestTaskDependency(unittest.TestCase):
    """测试任务依赖"""

    def test_dependency_creation(self):
        """测试依赖创建"""
        dep = TaskDependency(
            task_id='dep_task',
            required_status=TaskStatus.SUCCESS
        )
        self.assertEqual(dep.task_id, 'dep_task')
        self.assertEqual(dep.required_status, TaskStatus.SUCCESS)


class TestSimpleTask(unittest.TestCase):
    """测试简单任务"""

    def test_simple_task_execution(self):
        """测试简单任务执行"""
        def test_func(context):
            return {'result': context.get('input')}

        task = SimpleTask(
            task_id='simple1',
            name='Test Task',
            func=test_func
        )
        result = task.execute({'input': 'hello'})
        self.assertEqual(result, {'result': 'hello'})


class TestAnalysisTask(unittest.TestCase):
    """测试分析任务"""

    def test_analysis_task_creation(self):
        """测试分析任务创建"""
        task = AnalysisTask(
            task_id='analysis1',
            name='Analysis Task',
            analyzer_name='test_analyzer',
            analyzer_params={'binary': 'test.bin'}
        )
        self.assertEqual(task.task_id, 'analysis1')
        self.assertEqual(task.analyzer_name, 'test_analyzer')


class TestTaskScheduler(unittest.TestCase):
    """测试任务调度器"""

    def setUp(self):
        """设置测试环境"""
        self.scheduler = TaskScheduler()

    def test_scheduler_initialization(self):
        self.assertIsNotNone(self.scheduler)
        self.assertEqual(len(self.scheduler.tasks), 0)


class TestAnalysisPipeline(unittest.TestCase):
    """测试分析流水线"""

    def test_pipeline_creation(self):
        """测试流水线创建"""
        pipeline = AnalysisPipeline()
        self.assertIsNotNone(pipeline)



if __name__ == '__main__':
    unittest.main()


