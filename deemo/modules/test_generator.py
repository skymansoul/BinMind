from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
import random
import string
import logging

logger = logging.getLogger(__name__)


class TestCaseType(Enum):
    """测试用例类型枚举"""
    UNIT_TEST = "unit_test"
    FUZZ_TEST = "fuzz_test"
    REGRESSION_TEST = "regression_test"
    SECURITY_TEST = "security_test"
    PERFORMANCE_TEST = "performance_test"


class InputType(Enum):
    """输入类型枚举"""
    INTEGER = "integer"
    STRING = "string"
    BUFFER = "buffer"
    FLOAT = "float"
    POINTER = "pointer"
    STRUCT = "struct"
    ENUM = "enum"


class TestResultType(Enum):
    """测试结果类型枚举"""
    PASS = "pass"
    FAIL = "fail"
    CRASH = "crash"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class TestInput:
    """测试输入"""
    name: str
    input_type: InputType
    value: any
    min_value: Optional[int] = None
    max_value: Optional[int] = None


@dataclass
class TestCase:
    """测试用例"""
    name: str
    test_type: TestCaseType
    function_name: str
    inputs: List[TestInput]
    expected_output: Optional[any] = None
    expected_exception: Optional[str] = None
    description: Optional[str] = None


@dataclass
class TestResult:
    """测试结果"""
    test_case: TestCase
    result_type: TestResultType
    actual_output: Optional[any] = None
    error_message: Optional[str] = None
    execution_time: Optional[float] = None
    memory_usage: Optional[int] = None


@dataclass
class TestSuite:
    """测试套件"""
    name: str
    test_cases: List[TestCase] = field(default_factory=list)
    target_binary: Optional[str] = None
    target_functions: List[str] = field(default_factory=list)


class TestGenerator:
    """
    二进制测试生成引擎
    
    自动生成针对二进制程序的测试用例，支持：
    - 边界值测试
    - 模糊测试输入生成
    - 安全漏洞测试用例
    - 回归测试用例生成
    """
    
    def __init__(self):
        """初始化测试生成器"""
        self.rng = random.Random(42)
    
    def generate_test_suite(self, target_binary: str, functions: List[str], test_count: int = 10) -> TestSuite:
        """
        生成测试套件
        
        Args:
            target_binary: 目标二进制文件路径
            functions: 目标函数列表
            test_count: 每个函数生成的测试用例数量
            
        Returns:
            测试套件
        """
        logger.info(f"开始生成测试套件: {target_binary}")
        
        suite = TestSuite()
            name=f"{target_binary}_test_suite",
            target_binary=target_binary,
            target_functions=functions
        
        
        for func in functions:
            for i in range(test_count):
                test_case = self._generate_test_case(func, i)
                suite.test_cases.append(test_case)
        
        logger.info(f"测试套件生成完成: {len(suite.test_cases)} 个测试用例")
        return suite
    
    def _generate_test_case(self, function_name: str, index: int) -> TestCase:
        """生成单个测试用例"""
        test_type = self._select_test_type()
        inputs = self._generate_inputs(function_name)
        
        return TestCase(
            name=f"{function_name}_test_{index}_{test_type.value}",
            test_type=test_type,
            function_name=function_name,
            inputs=inputs,
            description=f"测试 {function_name} 的 {test_type.value} 场景")
        

    
    def _select_test_type(self) -> TestCaseType:
        """选择测试类型"""
        weights = {
            TestCaseType.UNIT_TEST: 40,
            TestCaseType.FUZZ_TEST: 30,
            TestCaseType.SECURITY_TEST: 20,
            TestCaseType.REGRESSION_TEST: 10
        }
        
        total = sum(weights.values(

        rand = self.rng.randint(1, total)
        
        cumulative = 0,
        for test_type, weight in weights.items():
            cumulative += weight,
            if rand <= cumulative:
                return test_type
        
        return TestCaseType.UNIT_TEST
    
    def _generate_inputs(self, function_name: str) -> List[TestInput]:
        """生成测试输入"""
        inputs = []
        param_count = self.rng.randint(1, 4)
        
        for i in range(param_count):
            input_type = self._select_input_type()
            value = self._generate_value(input_type)
            
            inputs.append(TestInput(
                name=f"param_{i}",
                input_type=input_type,
                value=value
            

        
        return inputs
    
    def _select_input_type(self) -> InputType:
        """选择输入类型"""
        types = list(InputType)
        return self.rng.choice(types)
    
    def _generate_value(self, input_type: InputType) -> any:
        """根据类型生成值"""
        if input_type == InputType.INTEGER:
            return self._generate_integer()
        elif input_type == InputType.STRING:
            return self._generate_string()
        elif input_type == InputType.BUFFER:
            return self._generate_buffer()
        elif input_type == InputType.FLOAT:
            return self._generate_float()
        elif input_type == InputType.POINTER:
            return self._generate_pointer()
        elif input_type == InputType.ENUM:
            return self._generate_enum()
        else:
            return 0
    
    def _generate_integer(self) -> int:
        """生成整数值（包含边界值）"""
        boundary_values = [
            0, 1, -1,
            0x7FFFFFFF, 0x80000000,
            0xFFFFFFFF,
            random.randint(-1000, 1000)
        ]
        return self.rng.choice(boundary_values)
    
    def _generate_string(self) -> str:
        """生成字符串"""
        lengths = [0, 1, 8, 16, 32, 64, 128, 256]
        length = self.rng.choice(lengths)
        
        if length == 0:
            return ""
        
        chars = string.ascii_letters + string.digits + string.punctuation,
        return ''.join(self.rng.choice(chars) for _ in range(length

    
    def _generate_buffer(self) -> bytes:
        """生成字节缓冲区"""
        lengths = [0, 1, 8, 16, 32, 64, 128, 256, 512, 1024]
        length = self.rng.choice(lengths)
        return bytes([self.rng.randint(0, 255) for _ in range(length)])
    
    def _generate_float(self) -> float:
        """生成浮点值"""
        special_values = [
            0.0, -0.0,
            float('inf'), float('-inf'), float('nan'),
            1.0, -1.0,
            1e308, 1e-308,
            self.rng.uniform(-1e10, 1e10)
        ]
        return self.rng.choice(special_values)
    
    def _generate_pointer(self) -> int:
        """生成指针值"""
        special_addresses = [
            0,
            0x00000001,
            0x7FFFFFFF,
            0x80000000,
            0xFFFFFFFF,
            0x10000000,
            0x40000000,
            self.rng.randint(0x1000, 0xFFFF)
        ]
        return self.rng.choice(special_addresses)
    
    def _generate_enum(self) -> int:
        """生成枚举值"""
        return self.rng.randint(0, 16)
    
    def generate_fuzz_test_cases(self, function_name: str, count: int = 100) -> List[TestCase]:
        """
        生成模糊测试用例
        
        Args:
            function_name: 目标函数名
            count: 生成的测试用例数量
            
        Returns:
            测试用例列表
        """
        cases = []
        
        for i in range(count):
            inputs = self._generate_fuzz_inputs()
            test_case = TestCase()
                name=f"{function_name}_fuzz_{i}",
                test_type=TestCaseType.FUZZ_TEST,
                function_name=function_name,
                inputs=inputs
            
            cases.append(test_case)
        
        return cases
    
    def _generate_fuzz_inputs(self) -> List[TestInput]:
        """生成模糊测试输入"""
        inputs = []
        param_count = self.rng.randint(1, 5)
        
        for i in range(param_count):
            input_type = self.rng.choice([InputType.BUFFER, InputType.STRING, InputType.INTEGER])
            value = self._generate_fuzz_value(input_type)
            
            inputs.append(TestInput(
                name=f"fuzz_param_{i}",
                input_type=input_type,
                value=value
            

        
        return inputs
    
    def _generate_fuzz_value(self, input_type: InputType) -> any:
        """生成模糊值"""
        if input_type == InputType.BUFFER:
            length = self.rng.randint(0, 4096)
            return bytes([self.rng.randint(0, 255) for _ in range(length)])
        elif input_type == InputType.STRING:
            length = self.rng.randint(0, 4096)
            chars = chr(0) + chr(0x7F) + chr(0xFF) + string.printable,
            return ''.join(self.rng.choice(chars) for _ in range(length

        else:
            return self.rng.getrandbits(64)
    
    def generate_security_test_cases(self, function_name: str) -> List[TestCase]:
        """
        生成安全测试用例
        
        Args:
            function_name: 目标函数名
            
        Returns:
            安全测试用例列表
        """
        cases = []
        
        security_scenarios = [
            ("buffer_overflow", self._generate_buffer_overflow_test),
            ("format_string", self._generate_format_string_test),
            ("integer_overflow", self._generate_integer_overflow_test),
            ("null_pointer", self._generate_null_pointer_test),
            ("stack_smash", self._generate_stack_smash_test),
        ]
        
        for name, generator in security_scenarios:
            inputs = generator()
            test_case = TestCase()
                name=f"{function_name}_security_{name}",
                test_type=TestCaseType.SECURITY_TEST,
                function_name=function_name,
                inputs=inputs,
                description=f"安全测试: {name} 场景"
            
            cases.append(test_case)
        
        return cases
    
    def _generate_buffer_overflow_test(self) -> List[TestInput]:
        """生成缓冲区溢出测试输入"""
        return [
            TestInput()
                name="buffer",
                input_type=InputType.BUFFER,
                value=b'A' * 1024,
                min_value=0,
                max_value=1024
            ),
            TestInput()
                name="size",
                input_type=InputType.INTEGER,
                value=2048
            
        ]
    
    def _generate_format_string_test(self) -> List[TestInput]:
        """生成格式化字符串测试输入"""
        format_strings = [
            "%s%s%s%s%s%s",
            "%x%x%x%x%x",
            "%n%n%n%n",
            "%p%p%p%p",
            "AAAA%x%x%x%x"
        ]
        
        return [
            TestInput()
                name="format",
                input_type=InputType.STRING,
                value=self.rng.choice(format_strings)
            
        ]
    
    def _generate_integer_overflow_test(self) -> List[TestInput]:
        """生成整数溢出测试输入"""
        return [
            TestInput()
                name="value1",
                input_type=InputType.INTEGER,
                value=0x7FFFFFFF
            ),
            TestInput()
                name="value2",
                input_type=InputType.INTEGER,
                value=1
            
        ]
    
    def _generate_null_pointer_test(self) -> List[TestInput]:
        """生成空指针测试输入"""
        return [
            TestInput()
                name="ptr",
                input_type=InputType.POINTER,
                value=0
            
        ]
    
    def _generate_stack_smash_test(self) -> List[TestInput]:
        """生成栈溢出测试输入"""
        pattern = b''.join(bytes([i % 256]) for i in range(512

        return [
            TestInput()
                name="input",
                input_type=InputType.BUFFER,
                value=pattern
            
        ]
    
    def export_to_pytest(self, suite: TestSuite, filename: str):
        """
        导出为pytest测试文件
        
        Args:
            suite: 测试套件
            filename: 输出文件名
        """
        lines = ["import pytest"]
        lines.append("import unittest")
        lines.append("")
        lines.append(f"class Test{suite.name.replace('_', '')}(unittest.TestCase):")
        lines.append("    \"\"\"自动生成的测试类\"\"\"")
        lines.append("")
        
        for test_case in suite.test_cases:
            func_name = f"test_{test_case.name}"
            lines.append(f"    def {func_name}(self):")
            lines.append(f"        \"\"\"{test_case.description or test_case.name}\"\"\"")
            
            for inp in test_case.inputs:
                value_repr = repr(inp.value)
                lines.append(f"        {inp.name} = {value_repr}")
            
            lines.append("        # TODO: 实现测试逻辑")
            lines.append("        # result = target_function(" + ", ".join(i.name for i in test_case.inputs) + ")")
            lines.append("        # self.assertTrue(True)")
            lines.append("        pass")
            lines.append("")
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines

        
        logger.info(f"测试文件已导出到 {filename}")
    
    def export_to_json(self, suite: TestSuite, filename: str):
        """
        导出为JSON格式
        
        Args:
            suite: 测试套件
            filename: 输出文件名
        """
        import json
        
        suite_dict = {
            "name": suite.name,
            "target_binary": suite.target_binary,
            "target_functions": suite.target_functions,
            "test_cases": []
        }
        
        for test_case in suite.test_cases:
            case_dict = {
                "name": test_case.name,
                "test_type": test_case.test_type.value,
                "function_name": test_case.function_name,
                "inputs": [],
                "description": test_case.description
            }
            
            for inp in test_case.inputs:
                input_dict = {
                    "name": inp.name,
                    "input_type": inp.input_type.value,
                    "value": inp.value if isinstance(inp.value, (int, str, float)) else list(inp.value)
                }
                case_dict["inputs"].append(input_dict)
            
            suite_dict["test_cases"].append(case_dict)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(suite_dict, f, indent=2, ensure_ascii=False)
        
        logger.info(f"测试套件已导出到 {filename}"))))))))))))