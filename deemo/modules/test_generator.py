"""
二进制自动化单元测试生成与Fuzzer驱动模块

为二进制中的函数自动生成单元测试用例，并将测试用例转化为LibFuzzer/AFL的harness。
"""

import os
import json
import logging
import random
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Union
from pathlib import Path

try:
    from config import Config
except ImportError:
    class Config:
        TEST_GENERATOR_OUTPUT_DIR = "data/test_generator"
        LOG_LEVEL = "INFO"


logging.basicConfig(level=getattr(logging, Config.LOG_LEVEL, "INFO"))
logger = logging.getLogger(__name__)


class TestOutputLanguage(Enum):
    """测试输出语言枚举"""
    C = "c"
    PYTHON = "python"
    FUZZER = "fuzzer"


class ParameterType(Enum):
    """参数类型枚举"""
    INT = "int"
    UINT = "uint"
    CHAR = "char"
    STRING = "string"
    POINTER = "pointer"
    ARRAY = "array"
    STRUCT = "struct"
    VOID = "void"


@dataclass
class FunctionParameter:
    """函数参数"""
    name: str
    type: ParameterType
    size: Optional[int] = None  # for arrays
    is_pointer: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "type": self.type.value,
            "size": self.size,
            "is_pointer": self.is_pointer
        }


@dataclass
class FunctionSignature:
    """函数签名"""
    name: str
    return_type: ParameterType
    parameters: List[FunctionParameter]
    address: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "name": self.name,
            "return_type": self.return_type.value,
            "parameters": [p.to_dict() for p in self.parameters],
            "address": hex(self.address) if self.address else None
        }


@dataclass
class TestCase:
    """测试用例"""
    function_name: str
    parameters: List[Any]
    expected_result: Optional[Any] = None
    description: str = ""
    test_type: str = "normal"  # normal, boundary, fuzz
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "function_name": self.function_name,
            "parameters": self.parameters,
            "expected_result": self.expected_result,
            "description": self.description,
            "test_type": self.test_type
        }


@dataclass
class TestSuite:
    """测试套件"""
    binary_path: str
    functions: List[FunctionSignature]
    test_cases: List[TestCase]
    timestamp: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "binary_path": self.binary_path,
            "functions": [f.to_dict() for f in self.functions],
            "test_cases": [t.to_dict() for t in self.test_cases],
            "timestamp": self.timestamp
        }


class BinaryTestGenerator:
    """
    二进制测试生成器
    
    为二进制函数生成单元测试和Fuzz harness。
    """
    
    # 参数类型的边界值
    BOUNDARY_VALUES = {
        ParameterType.INT: [0, -1, 1, 0x7fffffff, 0x80000000, 0xffffffff],
        ParameterType.UINT: [0, 1, 0x7fffffff, 0xffffffff],
        ParameterType.CHAR: [0, 1, -1, 0x7f, 0x80, 0xff],
        ParameterType.STRING: ["", "A", "AAAA", "A" * 256, "A" * 4096],
        ParameterType.POINTER: [0, 0xdeadbeef, 0xffffffff],
    }
    
    # C类型映射
    C_TYPE_MAP = {
        ParameterType.INT: "int",
        ParameterType.UINT: "unsigned int",
        ParameterType.CHAR: "char",
        ParameterType.STRING: "char*",
        ParameterType.POINTER: "void*",
        ParameterType.ARRAY: "void*",
        ParameterType.STRUCT: "void*",
        ParameterType.VOID: "void"
    }
    
    def __init__(self, output_dir: Optional[str] = None):
        """
        初始化测试生成器
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = Path(output_dir or Config.TEST_GENERATOR_OUTPUT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"二进制测试生成器初始化，输出目录: {self.output_dir}")
    
    def extract_function_signatures(self, binary_path: str) -> List[FunctionSignature]:
        """
        从二进制中提取函数签名
        
        Args:
            binary_path: 二进制文件路径
            
        Returns:
            函数签名列表
        """
        signatures = []
        
        # 模拟提取函数签名（实际实现会使用反编译引擎）
        signatures.append(FunctionSignature(
            name="process_input",
            return_type=ParameterType.INT,
            parameters=[
                FunctionParameter(name="buf", type=ParameterType.POINTER, is_pointer=True),
                FunctionParameter(name="size", type=ParameterType.UINT)
            ],
            address=0x401000
        ))
        
        signatures.append(FunctionSignature(
            name="validate_user",
            return_type=ParameterType.INT,
            parameters=[
                FunctionParameter(name="username", type=ParameterType.STRING, is_pointer=True),
                FunctionParameter(name="password", type=ParameterType.STRING, is_pointer=True)
            ],
            address=0x401100
        ))
        
        signatures.append(FunctionSignature(
            name="parse_config",
            return_type=ParameterType.POINTER,
            parameters=[
                FunctionParameter(name="config_data", type=ParameterType.POINTER, is_pointer=True),
                FunctionParameter(name="length", type=ParameterType.UINT)
            ],
            address=0x401200
        ))
        
        signatures.append(FunctionSignature(
            name="calculate_checksum",
            return_type=ParameterType.UINT,
            parameters=[
                FunctionParameter(name="data", type=ParameterType.POINTER, is_pointer=True),
                FunctionParameter(name="len", type=ParameterType.UINT)
            ],
            address=0x401300
        ))
        
        return signatures
    
    def generate_test_cases(self, function_signature: FunctionSignature, 
                          num_cases: int = 5) -> List[TestCase]:
        """
        为单个函数生成测试用例
        
        Args:
            function_signature: 函数签名
            num_cases: 测试用例数量
            
        Returns:
            测试用例列表
        """
        test_cases = []
        
        # 生成边界值测试
        for i in range(min(num_cases, 3)):
            params = []
            for param in function_signature.parameters:
                # 根据参数类型生成边界值
                if param.type in self.BOUNDARY_VALUES:
                    values = self.BOUNDARY_VALUES[param.type]
                    params.append(values[i % len(values)])
                else:
                    params.append(0)
            
            test_cases.append(TestCase(
                function_name=function_signature.name,
                parameters=params,
                description=f"边界测试 {i+1}",
                test_type="boundary"
            ))
        
        # 生成随机测试
        for i in range(num_cases - 3):
            params = []
            for param in function_signature.parameters:
                params.append(self._generate_random_value(param.type))
            
            test_cases.append(TestCase(
                function_name=function_signature.name,
                parameters=params,
                description=f"随机测试 {i+1}",
                test_type="normal"
            ))
        
        return test_cases
    
    def _generate_random_value(self, param_type: ParameterType) -> Any:
        """
        生成随机参数值
        
        Args:
            param_type: 参数类型
            
        Returns:
            随机值
        """
        if param_type == ParameterType.INT:
            return random.randint(-1000000, 1000000)
        elif param_type == ParameterType.UINT:
            return random.randint(0, 1000000)
        elif param_type == ParameterType.CHAR:
            return chr(random.randint(0, 255))
        elif param_type == ParameterType.STRING:
            length = random.randint(0, 100)
            return ''.join(chr(random.randint(32, 126)) for _ in range(length))
        elif param_type == ParameterType.POINTER:
            return random.randint(0, 0xffffffff)
        else:
            return 0
    
    def generate_c_test_code(self, signatures: List[FunctionSignature], 
                           test_cases: List[TestCase]) -> str:
        """
        生成C语言测试代码
        
        Args:
            signatures: 函数签名列表
            test_cases: 测试用例列表
            
        Returns:
            C语言测试代码
        """
        code = []
        
        # 头文件
        code.append("#include <stdio.h>")
        code.append("#include <stdlib.h>")
        code.append("#include <string.h>")
        code.append("")
        
        # 函数声明
        code.append("// 目标函数声明")
        for sig in signatures:
            params_str = ", ".join([f"{self.C_TYPE_MAP[p.type]} {p.name}" for p in sig.parameters])
            return_type = self.C_TYPE_MAP[sig.return_type]
            code.append(f"extern {return_type} {sig.name}({params_str});")
        code.append("")
        
        # 测试宏
        code.append("#define TEST(name, expected, ...) \\")
        code.append("    do { \\")
        code.append("        printf(\"Testing %s... \", name); \\")
        code.append("        int result = __VA_ARGS__; \\")
        code.append("        if (result == expected) { \\")
        code.append("            printf(\"PASS\\\\n\"); \\")
        code.append("        } else { \\")
        code.append("            printf(\"FAIL (got %d, expected %d)\\\\n\", result, expected); \\")
        code.append("        } \\")
        code.append("    } while(0)")
        code.append("")
        
        # main函数
        code.append("int main() {")
        code.append("    printf(\"Running tests...\\\\n\\\\n\");")
        code.append("")
        
        # 生成测试调用
        for case in test_cases:
            func_name = case.function_name
            params = case.parameters
            
            # 转换参数为C表达式
            param_exprs = []
            for i, param in enumerate(params):
                if isinstance(param, str):
                    # 字符串需要转义
                    escaped = param.replace('\\', '\\\\').replace('"', '\\"')
                    param_exprs.append(f'"{escaped}"')
                elif isinstance(param, int):
                    param_exprs.append(str(param))
                else:
                    param_exprs.append("0")
            
            params_str = ", ".join(param_exprs)
            
            code.append(f"    // {case.description}")
            code.append(f"    {func_name}({params_str});")
            code.append("")
        
        code.append("    printf(\"\\\\nTests completed.\\\\n\");")
        code.append("    return 0;")
        code.append("}")
        
        return "\n".join(code)
    
    def generate_python_test_code(self, signatures: List[FunctionSignature], 
                                test_cases: List[TestCase]) -> str:
        """
        生成Python测试代码
        
        Args:
            signatures: 函数签名列表
            test_cases: 测试用例列表
            
        Returns:
            Python测试代码
        """
        code = []
        
        # 导入
        code.append("import ctypes")
        code.append("import unittest")
        code.append("")
        
        # 加载库
        code.append("# 加载目标库")
        code.append("lib = ctypes.CDLL('./target_binary.so')")
        code.append("")
        
        # 设置函数参数类型
        code.append("# 设置函数参数类型")
        for sig in signatures:
            # 设置返回类型
            code.append(f"lib.{sig.name}.restype = ctypes.c_int")
            
            # 设置参数类型
            param_types = []
            for p in sig.parameters:
                if p.type in [ParameterType.INT, ParameterType.CHAR]:
                    param_types.append("ctypes.c_int")
                elif p.type == ParameterType.UINT:
                    param_types.append("ctypes.c_uint")
                elif p.type in [ParameterType.STRING, ParameterType.POINTER]:
                    param_types.append("ctypes.c_char_p")
                else:
                    param_types.append("ctypes.c_void_p")
            
            if param_types:
                code.append(f"lib.{sig.name}.argtypes = [{', '.join(param_types)}]")
        code.append("")
        
        # 测试类
        code.append("class TestBinaryFunctions(unittest.TestCase):")
        code.append("    \"\"\"二进制函数测试类\"\"\"")
        code.append("")
        
        # 生成测试方法
        for case in test_cases:
            func_name = case.function_name
            params = case.parameters
            
            # 转换参数
            py_params = []
            for param in params:
                if isinstance(param, str):
                    py_params.append(f'b"{param}"')
                elif isinstance(param, int):
                    py_params.append(str(param))
                else:
                    py_params.append("0")
            
            params_str = ", ".join(py_params)
            
            test_name = f"test_{func_name}_{hash(tuple(params)) % 10000}"
            code.append(f"    def {test_name}(self):")
            code.append(f"        \"\"\"{case.description}\"\"\"")
            code.append(f"        result = lib.{func_name}({params_str})")
            code.append(f"        print(f\"{func_name}({params_str}) = {{{result}}}\")")
            code.append("")
        
        # 运行测试
        code.append("if __name__ == '__main__':")
        code.append("    unittest.main()")
        
        return "\n".join(code)
    
    def generate_fuzz_harness(self, signatures: List[FunctionSignature]) -> str:
        """
        生成LibFuzzer格式的fuzz harness
        
        Args:
            signatures: 函数签名列表
            
        Returns:
            LibFuzzer harness代码
        """
        code = []
        
        # 头文件
        code.append("#include <stddef.h>")
        code.append("#include <stdint.h>")
        code.append("#include <string.h>")
        code.append("#include <stdlib.h>")
        code.append("#include <stdio.h>")
        code.append("")
        
        # LibFuzzer头
        code.append("#include \"FuzzerDefs.h\"")
        code.append("")
        
        # 目标函数声明
        code.append("// 目标函数声明")
        for sig in signatures:
            params_str = ", ".join([f"{self.C_TYPE_MAP[p.type]} {p.name}" for p in sig.parameters])
            return_type = self.C_TYPE_MAP[sig.return_type]
            code.append(f"extern {return_type} {sig.name}({params_str});")
        code.append("")
        
        # Fuzz入口函数
        code.append("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
        code.append("    if (size == 0) return 0;")
        code.append("")
        
        # 为每个函数生成fuzz调用
        for i, sig in enumerate(signatures):
            code.append(f"    // Fuzz {sig.name}")
            
            # 构建参数
            params = []
            offset = 0
            
            for param in sig.parameters:
                if param.type == ParameterType.STRING or param.type == ParameterType.POINTER:
                    # 使用部分数据作为字符串
                    code.append(f"    const char *arg{i}_{param.name} = (const char *)data + {offset};")
                    params.append(f"(char*)arg{i}_{param.name}")
                    offset += min(256, size - offset)
                elif param.type == ParameterType.UINT:
                    # 使用数据的一部分作为整数
                    code.append(f"    unsigned int arg{i}_{param.name} = 0;")
                    code.append(f"    if ({offset} + sizeof(unsigned int) <= size) {{")
                    code.append(f"        memcpy(&arg{i}_{param.name}, data + {offset}, sizeof(unsigned int));")
                    code.append("    }")
                    params.append(f"arg{i}_{param.name}")
                    offset += 4
                elif param.type == ParameterType.INT:
                    code.append(f"    int arg{i}_{param.name} = 0;")
                    code.append(f"    if ({offset} + sizeof(int) <= size) {{")
                    code.append(f"        memcpy(&arg{i}_{param.name}, data + {offset}, sizeof(int));")
                    code.append("    }")
                    params.append(f"arg{i}_{param.name}")
                    offset += 4
                else:
                    params.append("0")
            
            params_str = ", ".join(params)
            code.append(f"    {sig.name}({params_str});")
            code.append("")
        
        code.append("    return 0;")
        code.append("}")
        
        return "\n".join(code)
    
    def generate_tests(self, binary_path: str, language: TestOutputLanguage = TestOutputLanguage.C,
                      num_cases_per_func: int = 5) -> TestSuite:
        """
        生成完整的测试套件
        
        Args:
            binary_path: 二进制文件路径
            language: 输出语言
            num_cases_per_func: 每个函数的测试用例数量
            
        Returns:
            TestSuite对象
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # 提取函数签名
        signatures = self.extract_function_signatures(binary_path)
        logger.info(f"提取到 {len(signatures)} 个函数")
        
        # 生成测试用例
        test_cases = []
        for sig in signatures:
            cases = self.generate_test_cases(sig, num_cases_per_func)
            test_cases.extend(cases)
        
        result = TestSuite(
            binary_path=binary_path,
            functions=signatures,
            test_cases=test_cases,
            timestamp=timestamp
        )
        
        # 生成测试代码文件
        self._generate_test_files(result, language)
        
        logger.info(f"生成 {len(test_cases)} 个测试用例")
        return result
    
    def _generate_test_files(self, suite: TestSuite, language: TestOutputLanguage) -> None:
        """
        生成测试文件
        
        Args:
            suite: 测试套件
            language: 输出语言
        """
        base_name = os.path.basename(suite.binary_path).replace('.', '_')
        
        if language == TestOutputLanguage.C:
            code = self.generate_c_test_code(suite.functions, suite.test_cases)
            filepath = self.output_dir / f"{base_name}_test.c"
        elif language == TestOutputLanguage.PYTHON:
            code = self.generate_python_test_code(suite.functions, suite.test_cases)
            filepath = self.output_dir / f"{base_name}_test.py"
        elif language == TestOutputLanguage.FUZZER:
            code = self.generate_fuzz_harness(suite.functions)
            filepath = self.output_dir / f"{base_name}_fuzz.c"
        else:
            return
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(code)
        
        logger.info(f"测试文件已生成: {filepath}")
    
    def generate_report(self, suite: TestSuite) -> str:
        """
        生成测试报告
        
        Args:
            suite: 测试套件
            
        Returns:
            Markdown格式报告
        """
        report_lines = [
            "# 二进制测试生成报告",
            "",
            f"**生成时间**: {suite.timestamp}",
            f"**目标文件**: {suite.binary_path}",
            "",
            "## 概览",
            "",
            f"- 分析函数数: **{len(suite.functions)}**",
            f"- 生成测试用例数: **{len(suite.test_cases)}**",
            "",
            "## 函数签名",
            "",
            "| 函数名 | 返回类型 | 参数数量 | 地址 |",
            "|--------|----------|----------|------|",
        ]
        
        for func in suite.functions:
            params_count = len(func.parameters)
            addr = hex(func.address) if func.address else "N/A"
            report_lines.append(f"| {func.name} | {func.return_type.value} | {params_count} | `{addr}` |")
        
        report_lines.extend([
            "",
            "## 测试用例",
            "",
            "| 函数名 | 测试类型 | 描述 |",
            "|--------|----------|------|",
        ])
        
        for case in suite.test_cases:
            report_lines.append(f"| {case.function_name} | {case.test_type} | {case.description} |")
        
        report_lines.extend([
            "",
            "## 参数类型统计",
            "",
            "| 参数类型 | 出现次数 |",
            "|----------|----------|",
        ])
        
        # 统计参数类型
        type_counts = {}
        for func in suite.functions:
            for param in func.parameters:
                type_counts[param.type.value] = type_counts.get(param.type.value, 0) + 1
        
        for type_name, count in type_counts.items():
            report_lines.append(f"| {type_name} | {count} |")
        
        return "\n".join(report_lines)
    
    def save_result(self, suite: TestSuite, filename: Optional[str] = None) -> str:
        """
        保存测试套件
        
        Args:
            suite: 测试套件
            filename: 文件名
            
        Returns:
            保存的文件路径
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"test_suite_{timestamp}"
        
        # 保存JSON结果
        json_path = self.output_dir / f"{filename}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(suite.to_dict(), f, indent=2, ensure_ascii=False)
        
        # 保存报告
        report_path = self.output_dir / f"{filename}.md"
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(self.generate_report(suite))
        
        logger.info(f"测试套件已保存: {json_path}")
        return str(json_path)


if __name__ == "__main__":
    # 示例用法
    import sys
    
    generator = BinaryTestGenerator()
    
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
        
        # 生成C测试
        suite = generator.generate_tests(binary_path, TestOutputLanguage.C)
        
        # 生成Python测试
        generator.generate_tests(binary_path, TestOutputLanguage.PYTHON)
        
        # 生成Fuzz harness
        generator.generate_tests(binary_path, TestOutputLanguage.FUZZER)
        
        generator.save_result(suite)
        
        print(f"测试生成完成!")
        print(f"分析 {len(suite.functions)} 个函数")
        print(f"生成 {len(suite.test_cases)} 个测试用例")
    else:
        print("用法: python test_generator.py <二进制文件路径>")