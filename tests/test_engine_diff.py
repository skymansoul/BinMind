"""
Tests for the engine differential testing module.

Covers:
- EngineInfo: build command from template
- EngineRegistry: register, list, count
- CrossEngineNormalizer: output normalization, comparison
- EngineDiffRunner: run_diff, categorize_differences
"""
import unittest

from modules.testing.src.engine_diff import (
    EngineInfo,
    EngineRegistry,
    CrossEngineNormalizer,
    EngineDiffRunner,
)


class TestEngineInfo(unittest.TestCase):
    """EngineInfo dataclass and command building."""

    def test_build_cmd_no_placeholder(self):
        """无 {} 占位符→保持原样"""
        info = EngineInfo(
            name="test_engine",
            binary_path="/usr/bin/analyzer",
            version="1.0",
            args_template="--input file.bin",
        )
        cmd = info.build_cmd("/tmp/test.bin")
        self.assertEqual(cmd, ["/usr/bin/analyzer", "--input", "file.bin"])

    def test_build_cmd_with_placeholder(self):
        """{} 占位符被替换为输入路径"""
        info = EngineInfo(
            name="engine",
            binary_path="/bin/tool",
            version="1.0",
            args_template="{} --verbose",
        )
        cmd = info.build_cmd("/tmp/input.bin")
        self.assertEqual(cmd, ["/bin/tool", "/tmp/input.bin", "--verbose"])

    def test_build_cmd_with_multiple_args(self):
        """多个参数正确拆分"""
        info = EngineInfo(
            name="tool",
            binary_path="/bin/tool",
            version="2.0",
            args_template="{} --format json --timeout 30",
        )
        cmd = info.build_cmd("/tmp/test")
        self.assertEqual(len(cmd), 5)
        self.assertEqual(cmd[0], "/bin/tool")
        self.assertEqual(cmd[1], "/tmp/test")


class TestEngineRegistry(unittest.TestCase):
    """Engine registry management."""

    def setUp(self):
        self.registry = EngineRegistry()

    def test_register_engine(self):
        """注册引擎成功"""
        self.registry.register(
            name="radare2",
            binary_path="/usr/bin/r2",
            args_template="{} -q -c 'aaa'",
            version="5.9.0",
        )
        self.assertIn("radare2", self.registry.engine_names())

    def test_get_engine(self):
        """按名获取引擎信息"""
        self.registry.register("ghidra", "/opt/ghidra/analyzeHeadless",
                               "{} -import", "11.0")
        info = self.registry.get_engine("ghidra")
        self.assertIsNotNone(info)
        self.assertEqual(info.name, "ghidra")
        self.assertEqual(info.version, "11.0")

    def test_get_nonexistent_engine(self):
        """获取不存在的引擎返回 None"""
        info = self.registry.get_engine("nonexistent")
        self.assertIsNone(info)

    def test_list_engines(self):
        """list_engines 返回 EngineInfo 列表"""
        self.registry.register("a", "/bin/a", "{}", "1")
        self.registry.register("b", "/bin/b", "{}", "1")
        engines = self.registry.list_engines()
        self.assertEqual(len(engines), 2)

    def test_count(self):
        """count 返回注册引擎数"""
        self.assertEqual(self.registry.count(), 0)
        self.registry.register("x", "/bin/x", "{}", "1")
        self.assertEqual(self.registry.count(), 1)


class TestCrossEngineNormalizer(unittest.TestCase):
    """Output normalization to eliminate superficial differences."""

    def setUp(self):
        self.normalizer = CrossEngineNormalizer()

    def test_strip_whitespace(self):
        """首尾空白移除"""
        result = self.normalizer.normalize("  hello world  ")
        self.assertEqual(result, "hello world")

    def test_hex_normalization(self):
        """0x 前缀的十六进制变为小写"""
        result = self.normalizer.normalize("0xABCD")
        self.assertEqual(result, "0xabcd")

    def test_remove_angr_suffix(self):
        """移除 @@suffix 后缀"""
        result = self.normalizer.normalize("func@@GLIBC_2.31")
        self.assertEqual(result, "func")

    def test_whitespace_compression(self):
        """多个连续空白压缩为单个空格"""
        result = self.normalizer.normalize("a   b\t\tc\n\nd")
        self.assertEqual(result, "a b c d")

    def test_normalize_binary(self):
        """二进制输出去首尾 NULL"""
        result = self.normalizer.normalize_binary(b"\x00\x00data\x00\x00")
        self.assertEqual(result, b"data")

    def test_compare_normalized_equal(self):
        """两个相同归一化输出判定为相等"""
        result = self.normalizer.compare_normalized(
            "func@@GLIBC_2.31", "func", "angr", "radare2"
        )
        self.assertTrue(result)

    def test_compare_normalized_different(self):
        """两个不同归一化输出判定为不等"""
        result = self.normalizer.compare_normalized(
            "output_a", "output_b", "a", "b"
        )
        self.assertFalse(result)


class TestEngineDiffRunner(unittest.TestCase):
    """Cross-engine differential test execution."""

    def setUp(self):
        self.registry = EngineRegistry()
        self.runner = EngineDiffRunner(self.registry)

    def test_register_executor(self):
        """注册执行器"""
        self.runner.register_executor("custom", lambda data: "output")
        # 不应抛出

    def test_run_diff_no_executors(self):
        """无执行器→返回空结果"""
        result = self.runner.run_diff(b"test input")
        self.assertEqual(len(result["raw_outputs"]), 0)

    def test_run_diff_single_executor(self):
        """单执行器返回该引擎的输出"""
        self.runner.register_executor("engine_a", lambda data: "result_a")
        result = self.runner.run_diff(b"hello")
        self.assertIn("engine_a", result["raw_outputs"])
        self.assertEqual(result["raw_outputs"]["engine_a"], "result_a")

    def test_run_diff_two_executors_same(self):
        """两个执行器相同输出→无差异"""
        self.runner.register_executor("a", lambda d: "same")
        self.runner.register_executor("b", lambda d: "same")
        result = self.runner.run_diff(b"test")
        self.assertFalse(result["has_semantic_diff"])

    def test_run_diff_executor_crash(self):
        """执行器异常→标记为 CRASH"""
        def crashy(data):
            raise RuntimeError("boom")
        self.runner.register_executor("crashy", crashy)
        result = self.runner.run_diff(b"test")
        self.assertTrue(result["has_crash"])

    def test_categorize_equivalent(self):
        """两引擎相同输出→EQUIVALENT"""
        normalized = {"a": "output", "b": "output"}
        cats = self.runner.categorize_differences(normalized)
        self.assertIn(("a", "b"), cats["EQUIVALENT"])

    def test_categorize_cosmetic(self):
        """仅空白不同的输出→COSMETIC"""
        normalized = {"a": "output  data", "b": "output data"}
        cats = self.runner.categorize_differences(normalized)
        self.assertIn(("a", "b"), cats["COSMETIC"])

    def test_categorize_semantic(self):
        """内容不同的输出→SEMANTIC"""
        normalized = {"a": "foo", "b": "bar"}
        cats = self.runner.categorize_differences(normalized)
        self.assertIn(("a", "b"), cats["SEMANTIC"])

    def test_hash_output(self):
        """hash_output 返回 SHA-256 前 16 位 hex"""
        h = self.runner.hash_output("test")
        self.assertEqual(len(h), 16)
        self.assertIsInstance(h, str)


if __name__ == "__main__":
    unittest.main()
