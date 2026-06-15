#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
基于差异测试的漏洞发现模块（Differential Fuzzing）

提供差异测试能力，用于发现跨版本或跨实现的安全漏洞：
- 跨版本差异测试：对比同一函数不同版本的输出差异
- 跨实现差异测试：对比多个实现相同功能的二进制的行为差异
- 自动生成模糊测试用例
- 差异检测与漏洞判定
"""

import logging
import os
import subprocess
import time
import hashlib
import random
import struct
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


class TestMode(Enum):
    """测试模式"""
    CROSS_VERSION = "cross_version"      # 跨版本测试
    CROSS_IMPLEMENTATION = "cross_impl"  # 跨实现测试


class DifferenceType(Enum):
    """差异类型"""
    OUTPUT_MISMATCH = "output_mismatch"        # 输出不匹配
    CRASH = "crash"                            # 崩溃
    HANG = "hang"                              # 挂起
    MEMORY_CORRUPTION = "memory_corruption"    # 内存损坏
    BEHAVIOR_CHANGE = "behavior_change"        # 行为变化
    PERFORMANCE_CHANGE = "performance_change"   # 性能变化
    NONE = "none"                              # 无差异


@dataclass
class TestCase:
    """测试用例"""
    test_id: str
    input_data: bytes
    input_type: str = "random"
    coverage: float = 0.0
    mutation_info: str = ""
    generated_at: float = 0.0


@dataclass
class ExecutionResult:
    """执行结果"""
    binary_path: str
    test_case: TestCase
    exit_code: int
    stdout: bytes
    stderr: bytes
    execution_time: float
    memory_usage: int = 0
    crashed: bool = False
    hung: bool = False
    error_message: str = ""


@dataclass
class Difference:
    """检测到的差异"""
    test_case: TestCase
    difference_type: DifferenceType
    description: str
    severity: str = "unknown"
    binary_a_result: Optional[ExecutionResult] = None
    binary_b_result: Optional[ExecutionResult] = None
    likely_vulnerability: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DifferentialTestResult:
    """差异测试结果"""
    success: bool
    test_mode: TestMode
    total_tests: int = 0
    total_differences: int = 0
    unique_inputs: int = 0
    execution_time: float = 0.0
    differences: List[Difference] = field(default_factory=list)
    potential_vulnerabilities: List[Difference] = field(default_factory=list)
    summary: str = ""
    coverage_stats: Dict[str, float] = field(default_factory=dict)


class InputGenerator:
    """
    测试输入生成器

    支持多种输入类型：
    - 随机字节流
    - 结构化数据
    - 边界值
    - 畸形数据变异
    """

    def __init__(self, seed: Optional[int] = None):
        """
        初始化输入生成器

        Args:
            seed: 随机种子
        """
        self.rng = random.Random(seed)
        self.generated_hashes: Set[str] = set()

    def generate_random(self, min_size: int = 1, max_size: int = 1024) -> bytes:
        """
        生成随机字节数据

        Args:
            min_size: 最小大小
            max_size: 最大大小

        Returns:
            随机字节数据
        """
        size = self.rng.randint(min_size, max_size)
        data = bytes(self.rng.randint(0, 255) for _ in range(size))

        # 去重
        data_hash = hashlib.sha256(data).hexdigest()
        if data_hash in self.generated_hashes:
            return self.generate_random(min_size, max_size)

        self.generated_hashes.add(data_hash)
        return data

    def generate_structured(self, format_type: str) -> bytes:
        """
        生成结构化数据

        Args:
            format_type: 数据格式类型

        Returns:
            结构化字节数据
        """
        generators = {
            'http_request': self._generate_http_request,
            'json_data': self._generate_json_data,
            'xml_data': self._generate_xml_data,
            'binary_header': self._generate_binary_header,
            'network_packet': self._generate_network_packet,
        }

        generator = generators.get(format_type, self.generate_random)
        return generator()

    def _generate_http_request(self) -> bytes:
        """生成HTTP请求"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
        paths = ['/', '/api', '/api/v1', '/api/data', '/admin', '/login']
        headers = ['Content-Type', 'User-Agent', 'Accept', 'Authorization']

        method = self.rng.choice(methods)
        path = self.rng.choice(paths)

        request = f"{method} {path} HTTP/1.1\r\n"
        request += "Host: example.com\r\n"

        for _ in range(self.rng.randint(0, 3)):
            header = self.rng.choice(headers)
            if header == 'Content-Type':
                value = self.rng.choice(['application/json', 'text/plain', 'application/x-www-form-urlencoded'])
            else:
                value = f"Test{random.randint(1000, 9999)}"
            request += f"{header}: {value}\r\n"

        request += "\r\n"

        if method in ['POST', 'PUT', 'PATCH']:
            body_size = self.rng.randint(10, 100)
            body = ''.join(chr(self.rng.randint(32, 126)) for _ in range(body_size))
            request += body

        return request.encode('utf-8')

    def _generate_json_data(self) -> bytes:
        """生成JSON数据"""
        structures = [
            {"key": "value"},
            {"name": "test", "id": 123, "active": True},
            {"array": [1, 2, 3], "nested": {"a": "b"}},
        ]

        data = self.rng.choice(structures)

        # 添加一些随机字段
        for _ in range(self.rng.randint(0, 3)):
            key = f"field_{random.randint(1, 100)}"
            value = self.rng.choice([
                random.randint(1, 1000),
                self.rng.random(),
                self.rng.choice(['value1', 'value2', 'value3']),
                True,
                None
            ])
            data[key] = value

        return json.dumps(data).encode('utf-8')

    def _generate_xml_data(self) -> bytes:
        """生成XML数据"""
        root = self.rng.choice(['root', 'data', 'document'])
        elements = ['item', 'entry', 'record']

        xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<{root}>\n'

        for _ in range(self.rng.randint(1, 5)):
            elem = self.rng.choice(elements)
            value = f"Value{random.randint(1, 1000)}"
            xml += f'  <{elem}><![CDATA[{value}]]></{elem}>\n'

        xml += f'</{root}>'
        return xml.encode('utf-8')

    def _generate_binary_header(self) -> bytes:
        """生成二进制头"""
        # 模拟常见文件格式头
        header = bytearray()

        # 添加魔数
        magic = self.rng.choice([
            b'\x89PNG\r\n\x1a\n',  # PNG
            b'\xff\xd8\xff',        # JPEG
            b'GIF87a',              # GIF
            b'GIF89a',              # GIF
            b'PK\x03\x04',          # ZIP
            b'\x7fELF',             # ELF
        ])
        header.extend(magic)

        # 添加随机扩展
        header.extend(bytes(self.rng.randint(0, 255) for _ in range(self.rng.randint(10, 50))))

        return bytes(header)

    def _generate_network_packet(self) -> bytes:
        """生成网络数据包"""
        # 简化实现：生成随机IP包
        packet = bytearray()

        # 版本和头长度
        packet.append(0x45)

        # TOS
        packet.append(self.rng.randint(0, 255))

        # 总长度
        length = self.rng.randint(20, 100)
        packet.extend(struct.pack('>H', length))

        # ID
        packet.extend(struct.pack('>H', self.rng.randint(1, 65535)))

        # 标志和片偏移
        packet.extend(struct.pack('>H', 0))

        # TTL和协议
        packet.append(self.rng.randint(1, 255))
        packet.append(self.rng.randint(0, 255))

        # 校验和（设为0）
        packet.extend(struct.pack('>H', 0))

        # 源IP
        packet.extend(struct.pack('>BBBB', 192, 168, self.rng.randint(1, 254), self.rng.randint(1, 254)))

        # 目标IP
        packet.extend(struct.pack('>BBBB', 10, self.rng.randint(0, 255), self.rng.randint(0, 255), self.rng.randint(1, 254)))

        # 负载
        payload_size = length - 20
        packet.extend(bytes(self.rng.randint(0, 255) for _ in range(payload_size)))

        return bytes(packet)

    def mutate(self, data: bytes, mutations: int = 3) -> bytes:
        """
        对输入数据进行变异

        Args:
            data: 原始数据
            mutations: 变异次数

        Returns:
            变异后的数据
        """
        mutation_types = [
            self._mutate_bitflip,
            self._mutate_byteflip,
            self._mutate_arithmetic,
            self._mutate_insert,
            self._mutate_delete,
            self._mutate_overwrite,
        ]

        result = bytearray(data)

        for _ in range(mutations):
            mutation = self.rng.choice(mutation_types)
            result = mutation(result)

        return bytes(result)

    def _mutate_bitflip(self, data: bytearray) -> bytearray:
        """位翻转"""
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        data[idx] ^= (1 << self.rng.randint(0, 7))
        return data

    def _mutate_byteflip(self, data: bytearray) -> bytearray:
        """字节翻转"""
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        data[idx] = self.rng.randint(0, 255)
        return data

    def _mutate_arithmetic(self, data: bytearray) -> bytearray:
        """算术变异"""
        if len(data) == 0:
            return data

        idx = self.rng.randint(0, len(data) - 1)
        delta = self.rng.randint(-10, 10)
        data[idx] = max(0, min(255, data[idx] + delta))
        return data

    def _mutate_insert(self, data: bytearray) -> bytearray:
        """插入字节"""
        pos = self.rng.randint(0, len(data))
        byte = self.rng.randint(0, 255)
        data.insert(pos, byte)
        return data

    def _mutate_delete(self, data: bytearray) -> bytearray:
        """删除字节"""
        if len(data) > 1:
            pos = self.rng.randint(0, len(data) - 1)
            del data[pos]
        return data

    def _mutate_overwrite(self, data: bytearray) -> bytearray:
        """覆盖数据"""
        if len(data) == 0:
            return data

        pos = self.rng.randint(0, len(data) - 1)
        size = min(self.rng.randint(1, 10), len(data) - pos)

        for i in range(size):
            data[pos + i] = self.rng.randint(0, 255)

        return data


class DifferentialTester:
    """
    差异测试器

    功能：
    1. 跨版本差异测试
    2. 跨实现差异测试
    3. 自动生成测试用例
    4. 差异检测与漏洞判定
    """

    def __init__(self, binary_a: str, binary_b: Optional[str] = None):
        """
        初始化差异测试器

        Args:
            binary_a: 第一个二进制文件路径
            binary_b: 第二个二进制文件路径（跨版本模式可选）
        """
        self.binary_a = self._validate_binary(binary_a)
        self.binary_b = self._validate_binary(binary_b) if binary_b else None
        self.test_mode = TestMode.CROSS_VERSION if binary_b else TestMode.CROSS_IMPLEMENTATION
        self.input_generator = InputGenerator()
        self.test_cases: List[TestCase] = []
        self.execution_results: Dict[str, List[ExecutionResult]] = defaultdict(list)

    def _validate_binary(self, path: str) -> str:
        """
        验证二进制文件

        Args:
            path: 二进制路径

        Returns:
            验证后的路径

        Raises:
            ValueError: 路径无效
        """
        if not path:
            raise ValueError("二进制路径不能为空")

        if not os.path.exists(path):
            raise ValueError(f"二进制文件不存在: {path}")

        if not os.access(path, os.R_OK):
            raise ValueError(f"无法读取二进制文件: {path}")

        return os.path.abspath(path)

    def _execute_binary(self, binary_path: str, input_data: bytes,
                        timeout: float = 5.0) -> ExecutionResult:
        """
        执行二进制文件

        Args:
            binary_path: 二进制路径
            input_data: 输入数据
            timeout: 超时时间

        Returns:
            ExecutionResult
        """
        test_case = TestCase(
            test_id=hashlib.md5(input_data).hexdigest()[:8],
            input_data=input_data,
            input_type="generated",
            generated_at=time.time()
        )

        start_time = time.time()

        try:
            # 创建临时输入文件
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix='.input') as f:
                f.write(input_data)
                input_file = f.name

            try:
                result = subprocess.run(
                    [binary_path, input_file],
                    capture_output=True,
                    timeout=timeout,
                    env={**os.environ, 'LD_LIBRARY_PATH': os.path.dirname(binary_path)}
                )

                execution_time = time.time() - start_time

                return ExecutionResult(
                    binary_path=binary_path,
                    test_case=test_case,
                    exit_code=result.returncode,
                    stdout=result.stdout,
                    stderr=result.stderr,
                    execution_time=execution_time,
                    crashed=result.returncode < 0,
                    error_message=""
                )
            finally:
                # 清理临时文件
                try:
                    os.unlink(input_file)
                except Exception:
                    pass

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                binary_path=binary_path,
                test_case=test_case,
                exit_code=-1,
                stdout=b"",
                stderr=b"",
                execution_time=timeout,
                hung=True,
                error_message="执行超时"
            )
        except Exception as e:
            return ExecutionResult(
                binary_path=binary_path,
                test_case=test_case,
                exit_code=-1,
                stdout=b"",
                stderr=b"",
                execution_time=time.time() - start_time,
                error_message=str(e)
            )

    def generate_test_cases(self, count: int, input_type: str = "random",
                           structured_format: Optional[str] = None) -> List[TestCase]:
        """
        生成测试用例

        Args:
            count: 生成数量
            input_type: 输入类型
            structured_format: 结构化数据格式

        Returns:
            测试用例列表
        """
        test_cases = []

        for i in range(count):
            if input_type == "random":
                data = self.input_generator.generate_random()
            elif input_type == "structured" and structured_format:
                data = self.input_generator.generate_structured(structured_format)
            elif input_type == "mutated" and self.test_cases:
                original = self.input_generator.rng.choice(self.test_cases).input_data
                data = self.input_generator.mutate(original)
            else:
                data = self.input_generator.generate_random()

            test_case = TestCase(
                test_id=f"tc_{i:04d}_{hashlib.md5(data).hexdigest()[:8]}",
                input_data=data,
                input_type=input_type,
                generated_at=time.time(),
                mutation_info=f"gen_{input_type}"
            )

            test_cases.append(test_case)
            self.test_cases.append(test_case)

        return test_cases

    def _compare_results(self, result_a: ExecutionResult,
                        result_b: Optional[ExecutionResult] = None) -> Difference:
        """
        比较执行结果

        Args:
            result_a: 第一个结果
            result_b: 第二个结果（可选）

        Returns:
            Difference 对象
        """
        difference = Difference(
            test_case=result_a.test_case,
            difference_type=DifferenceType.NONE,
            description="未检测到差异"
        )

        # 检测崩溃
        if result_a.crashed:
            difference.difference_type = DifferenceType.CRASH
            difference.description = f"Binary A 崩溃 (信号 {-result_a.exit_code})"
            difference.likely_vulnerability = True
            difference.severity = "high"
            difference.evidence['crash_signal'] = -result_a.exit_code

        if result_b:
            if result_b.crashed and not result_a.crashed:
                difference.difference_type = DifferenceType.CRASH
                difference.description = f"Binary B 崩溃但 Binary A 正常"
                difference.likely_vulnerability = True
                difference.severity = "high"
                difference.binary_b_result = result_b

            # 检测挂起
            elif result_b.hung and not result_a.hung:
                difference.difference_type = DifferenceType.HANG
                difference.description = f"Binary B 挂起但 Binary A 正常"
                difference.likely_vulnerability = True
                difference.severity = "medium"

            # 检测输出不匹配
            elif result_a.stdout != result_b.stdout or result_a.stderr != result_b.stderr:
                difference.difference_type = DifferenceType.OUTPUT_MISMATCH
                difference.description = "输出内容不匹配"
                difference.severity = "low"
                difference.binary_b_result = result_b

                # 分析输出差异
                if len(result_a.stdout) != len(result_b.stdout):
                    size_diff = abs(len(result_a.stdout) - len(result_b.stdout))
                    difference.evidence['size_difference'] = size_diff
                    if size_diff > 100:
                        difference.likely_vulnerability = True
                        difference.severity = "medium"
                        difference.description += f" (大小差异: {size_diff} 字节)"

            # 检测性能差异
            elif abs(result_a.execution_time - result_b.execution_time) > 1.0:
                if result_a.execution_time > result_b.execution_time * 2:
                    difference.difference_type = DifferenceType.PERFORMANCE_CHANGE
                    difference.description = f"Binary B 执行时间显著更长"
                    difference.severity = "low"

        # 设置结果引用
        difference.binary_a_result = result_a

        return difference

    def run_tests(self, test_cases: Optional[List[TestCase]] = None,
                  max_tests: int = 1000,
                  timeout: float = 5.0,
                  progress_callback: Optional[Callable[[int, int], None]] = None) -> DifferentialTestResult:
        """
        运行差异测试

        Args:
            test_cases: 测试用例列表（可选）
            max_tests: 最大测试数量
            timeout: 超时时间
            progress_callback: 进度回调函数

        Returns:
            DifferentialTestResult
        """
        start_time = time.time()
        result = DifferentialTestResult(
            success=False,
            test_mode=self.test_mode
        )

        try:
            # 生成测试用例
            if not test_cases:
                test_cases = self.generate_test_cases(max_tests, "mixed")

            result.total_tests = len(test_cases)

            # 执行测试
            for i, test_case in enumerate(test_cases):
                if progress_callback:
                    progress_callback(i, len(test_cases))

                # 执行 Binary A
                result_a = self._execute_binary(self.binary_a, test_case.input_data, timeout)
                self.execution_results[self.binary_a].append(result_a)

                # 执行 Binary B（如果存在）
                result_b = None
                if self.binary_b:
                    result_b = self._execute_binary(self.binary_b, test_case.input_data, timeout)
                    self.execution_results[self.binary_b].append(result_b)

                # 比较结果
                difference = self._compare_results(result_a, result_b)

                if difference.difference_type != DifferenceType.NONE:
                    result.differences.append(difference)
                    if difference.likely_vulnerability:
                        result.potential_vulnerabilities.append(difference)

                # 限制收集的结果数量
                if len(result.differences) > 100:
                    break

            result.total_differences = len(result.differences)
            result.unique_inputs = len(set(tc.test_id for tc in test_cases))
            result.execution_time = time.time() - start_time
            result.success = True

            # 生成摘要
            self._generate_summary(result)

        except Exception as e:
            logger.error(f"差异测试失败: {e}")
            result.summary = f"测试失败: {str(e)}"

        return result

    def _generate_summary(self, result: DifferentialTestResult):
        """生成测试结果摘要"""
        parts = [
            "# 差异测试结果",
            "",
            f"测试模式: {result.test_mode.value}",
            f"总测试数: {result.total_tests}",
            f"差异数量: {result.total_differences}",
            f"潜在漏洞: {len(result.potential_vulnerabilities)}",
            f"执行时间: {result.execution_time:.2f}秒",
        ]

        if result.differences:
            parts.extend(["", "## 差异详情"])
            for i, diff in enumerate(result.differences[:10], 1):
                parts.append(f"\n### 差异 #{i}")
                parts.append(f"- 类型: {diff.difference_type.value}")
                parts.append(f"- 描述: {diff.description}")
                parts.append(f"- 严重性: {diff.severity}")
                if diff.likely_vulnerability:
                    parts.append("- 可能是漏洞: **是**")

        result.summary = "\n".join(parts)

    def generate_fuzzing_corpus(self, output_dir: str) -> int:
        """
        生成模糊测试语料

        Args:
            output_dir: 输出目录

        Returns:
            生成的语料数量
        """
        os.makedirs(output_dir, exist_ok=True)

        count = 0
        for i, test_case in enumerate(self.test_cases):
            filename = f"corpus_{test_case.test_id}_{test_case.input_type}.bin"
            filepath = os.path.join(output_dir, filename)

            with open(filepath, 'wb') as f:
                f.write(test_case.input_data)

            count += 1

        return count


def run_differential_test(binary_a: str, binary_b: Optional[str] = None,
                           max_tests: int = 1000,
                           input_type: str = "random",
                           output_dir: Optional[str] = None) -> DifferentialTestResult:
    """
    运行差异测试的便捷函数

    Args:
        binary_a: 第一个二进制路径
        binary_b: 第二个二进制路径（可选）
        max_tests: 最大测试数量
        input_type: 输入类型
        output_dir: 输出目录（可选）

    Returns:
        DifferentialTestResult
    """
    tester = DifferentialTester(binary_a, binary_b)

    # 生成测试用例
    test_cases = tester.generate_test_cases(max_tests, input_type)

    # 运行测试
    result = tester.run_tests(test_cases)

    # 保存语料（如果指定了输出目录）
    if output_dir:
        corpus_count = tester.generate_fuzzing_corpus(output_dir)
        logger.info(f"已生成 {corpus_count} 个测试语料到 {output_dir}")

    return result


def format_differential_report(result: DifferentialTestResult) -> str:
    """
    格式化差异测试报告

    Args:
        result: 测试结果

    Returns:
        格式化的报告字符串
    """
    return result.summary


def export_differential_json(result: DifferentialTestResult, output_path: str) -> bool:
    """
    导出差异测试结果为JSON

    Args:
        result: 测试结果
        output_path: 输出路径

    Returns:
        是否成功
    """
    try:
        export_data = {
            'success': result.success,
            'test_mode': result.test_mode.value,
            'total_tests': result.total_tests,
            'total_differences': result.total_differences,
            'unique_inputs': result.unique_inputs,
            'execution_time': result.execution_time,
            'potential_vulnerabilities': [
                {
                    'test_id': diff.test_case.test_id,
                    'difference_type': diff.difference_type.value,
                    'description': diff.description,
                    'severity': diff.severity,
                    'evidence': diff.evidence
                }
                for diff in result.potential_vulnerabilities
            ],
            'all_differences': [
                {
                    'test_id': diff.test_case.test_id,
                    'difference_type': diff.difference_type.value,
                    'description': diff.description,
                    'severity': diff.severity
                }
                for diff in result.differences
            ],
            'summary': result.summary
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, ensure_ascii=False, indent=2)

        return True
    except Exception as e:
        logger.error(f"导出JSON失败: {e}")
        return False
