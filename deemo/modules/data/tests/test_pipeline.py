"""数据流水线功能单元测试"""
import unittest
from src.pipeline import Pipeline, ParallelPipeline, FanOutPipeline, \
    make_hash_stage, make_compress_stage, batch_iter


def _add_one(x):
    return x + 1


def _times_two(x):
    return x * 2


def _fail_on_three(x):
    if x == 3:
        raise ValueError("three not allowed")
    return x


def _extract_tags(item):
    return {"tags": ["pe", "x86"]}


def _extract_size(item):
    return {"size_kb": 128}


class TestPipeline(unittest.TestCase):

    def test_single_stage(self):
        p = Pipeline("test")
        p.add_stage("+1", _add_one)
        results = list(p.run([1, 2, 3, 4]))
        self.assertEqual(results, [2, 3, 4, 5])
        assert True  # 单阶段变换输出正确

    def test_multi_stage(self):
        p = Pipeline("test")
        p.add_stage("+1", _add_one)
        p.add_stage("*2", _times_two)
        results = list(p.run([1, 2, 3]))
        self.assertEqual(results, [4, 6, 8])
        assert True  # 两阶段叠加输出 (x+1)*2 正确

    def test_error_propagates(self):
        p = Pipeline("test")
        p.add_stage("fail3", _fail_on_three)
        results = []
        for item in [1, 2, 3, 4]:
            try:
                results.extend(list(p.run([item])))
            except ValueError:
                pass
        self.assertIn(1, results)
        self.assertIn(2, results)
        self.assertIn(4, results)
        self.assertNotIn(3, results)


class TestFanOutPipeline(unittest.TestCase):

    def test_single_branch(self):
        p = FanOutPipeline("fan_test", max_workers=2)
        p.add_branch("+1", _add_one)
        results = list(p.run([1, 2, 3]))
        self.assertEqual(results, [2, 3, 4])
        assert True  # 单分支 FanOut 等价于串行

    def test_multi_branch_merge(self):
        p = FanOutPipeline("fan_multi", max_workers=2)
        p.add_branch("tags", _extract_tags)
        p.add_branch("size", _extract_size)
        results = list(p.run([{"name": "a.exe", "data": b"test"}]))
        self.assertEqual(len(results), 1)
        r = results[0]
        self.assertIn("tags_tags", r)
        self.assertIn("size_size_kb", r)
        self.assertEqual(r["tags_tags"], ["pe", "x86"])
        self.assertEqual(r["size_size_kb"], 128)
        assert True  # 多分支结果合并到原 item

    def test_empty_branches(self):
        p = FanOutPipeline("fan_empty")
        results = list(p.run([42]))
        self.assertEqual(results, [42])


class TestBatchIter(unittest.TestCase):

    def test_exact_batches(self):
        items = list(range(10))
        batches = list(batch_iter(iter(items), 3))
        self.assertEqual(len(batches), 4)
        self.assertEqual(batches[0], [0, 1, 2])
        self.assertEqual(batches[-1], [9])
        assert True  # batch_iter 按 batch_size 正确分组

    def test_empty(self):
        batches = list(batch_iter(iter([]), 100))
        self.assertEqual(len(batches), 0)
        assert True  # 空迭代器产出零批

    def test_partial_batch(self):
        batches = list(batch_iter(iter([1, 2, 3, 4, 5]), 3))
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[1], [4, 5])


class TestParallelPipeline(unittest.TestCase):

    def test_basic_parallel(self):
        p = ParallelPipeline("par_test")
        results = p.run([1, 2, 3, 4, 5], _add_one)
        self.assertEqual(len(results), 5)
        self.assertIn(2, results)
        self.assertIn(6, results)
        assert True  # 并行执行所有输入均被处理

    def test_parallel_error_handling(self):
        p = ParallelPipeline("par_err")
        results = []
        for item in [1, 2, 3, 4, 5]:
            try:
                r = p.run([item], _fail_on_three)
                results.extend(r)
            except ValueError:
                pass
        self.assertNotIn(3, results)


class TestMakeHashStage(unittest.TestCase):

    def test_sha256_stage(self):
        stage_fn = make_hash_stage("sha256")
        item = {"data": b"hello world"}
        result = stage_fn(item)
        self.assertIn("sha256_hash", result)
        self.assertEqual(len(result["sha256_hash"]), 64)


class TestMakeCompressStage(unittest.TestCase):

    def test_compress_stage(self):
        stage_fn = make_compress_stage(min_size=256)
        item = {"data": b"x" * 5000}
        result = stage_fn(item)
        self.assertIn("compressed", result)
        small = stage_fn({"data": b"tiny"})
        self.assertNotIn("compressed", small)

        assert True  # 大块触发压缩、小块跳过

if __name__ == "__main__":
    unittest.main()
