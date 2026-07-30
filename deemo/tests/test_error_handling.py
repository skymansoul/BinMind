import unittest
from unittest.mock import Mock, patch
_MOD_DEBUG = False
from datetime import datetime
from modules.error_handling import (
    ErrorHandler,
    ErrorContext,
    ErrorRecord,
    ErrorSeverity,
    ErrorCategory,
    SafeExecution,
    RetryHandler,
    get_error_handler
)


class TestErrorSeverity(unittest.TestCase):
    """测试错误严重程度枚举"""

    def test_severity_values(self):
        """测试严重程度值"""
        self.assertEqual(ErrorSeverity.DEBUG.value, 'debug')
        self.assertEqual(ErrorSeverity.INFO.value, 'info')
        self.assertEqual(ErrorSeverity.WARNING.value, 'warning')
        self.assertEqual(ErrorSeverity.ERROR.value, 'error')
        self.assertEqual(ErrorSeverity.CRITICAL.value, 'critical')


class TestErrorCategory(unittest.TestCase):
    """测试错误类别枚举"""

    def test_category_values(self):
        """测试类别值"""
        self.assertEqual(ErrorCategory.ANALYSIS.value, 'analysis')
        self.assertEqual(ErrorCategory.PLUGIN.value, 'plugin')
        self.assertEqual(ErrorCategory.SCHEDULER.value, 'scheduler')
        self.assertEqual(ErrorCategory.CONFIG.value, 'config')


class TestErrorContext(unittest.TestCase):
    """测试错误上下文"""

    def test_context_creation(self):
        """测试上下文创建"""
        context = ErrorContext(
            task_id='task1',
            analyzer_name='test_analyzer',
            binary_path='/path/to/binary',
            function_name='main'
        )
        self.assertEqual(context.task_id, 'task1')
        self.assertEqual(context.analyzer_name, 'test_analyzer')


class TestErrorRecord(unittest.TestCase):
    """测试错误记录"""

    def test_record_creation(self):
        context = ErrorContext(task_id='task1', analyzer_name='test')
        try:
            raise ValueError('Test error')
        except ValueError as e:
            record = ErrorRecord(
                error_id='error1',
                exception=e,
                context=context,
                stack_trace='test stack'
            )
            self.assertEqual(record.error_id, 'error1')
            self.assertIsInstance(record.exception, ValueError)


class TestErrorHandler(unittest.TestCase):
    """测试错误处理器"""

    def setUp(self):
        """设置测试环境"""
        self.handler = ErrorHandler()

    def test_handler_initialization(self):
                """测试处理器初始化"""
        self.assertIsNotNone(self.handler)


class TestGetErrorHandler(unittest.TestCase):
    """测试获取错误处理器"""

    def test_get_handler(self):
        handler = get_error_handler()
        self.assertIsNotNone(handler)
        self.assertIsInstance(handler, ErrorHandler)



if __name__ == '__main__':
    unittest.main()


