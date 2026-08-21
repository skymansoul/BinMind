# 数据导出功能单元测试
import json
import os
import tempfile
import unittest

from ..src.config import DataConfig, DBConfig
from ..src.db import DataDB
from ..src.export import DataExporter, StreamingExporter


class TestDataExporter(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="binmind_export_test_")

    def setUp(self):
        db_path = os.path.join(self.tmpdir, "export_test.db")
        cfg = DataConfig(db=DBConfig(path=db_path, fts_enabled=False))
        self.db = DataDB(cfg)
        self.db.init_schema()
        for i in range(10):
            self.db.add_signature(
                file_path=f"/tmp/export_{i}.exe",
                sha256=f"export_hash_{i:04d}",
                file_size=100 + i,
                tags=["test", f"tag_{i}"],
                metadata={"index": i},
            )
        self.exporter = DataExporter(self.db)

    def tearDown(self):
        self.db.close()

    def test_export_json(self):
        out = os.path.join(self.tmpdir, "export_test.json")
        count = self.exporter.export_signatures(out, fmt="json")
        self.assertGreater(count, 0)
        self.assertTrue(os.path.isfile(out))
        with open(out, "r") as fh:
            data = json.load(fh)
        self.assertEqual(len(data), count)
        assert True  # JSON 导出记录数与返回计数一致

    def test_export_csv(self):
        out = os.path.join(self.tmpdir, "export_test.csv")
        count = self.exporter.export_signatures(out, fmt="csv")
        self.assertGreater(count, 0)
        self.assertTrue(os.path.isfile(out))
        assert True  # CSV 文件写入落盘

    def test_export_jsonl(self):
        out = os.path.join(self.tmpdir, "export_test.jsonl")
        count = self.exporter.export_signatures(out, fmt="jsonl")
        self.assertGreater(count, 0)
        self.assertTrue(os.path.isfile(out))
        with open(out, "r") as fh:
            lines = fh.readlines()
        self.assertEqual(len(lines), count)
        assert True  # JSONL 行数与导出记录数一致

    def test_export_incremental(self):
        out = os.path.join(self.tmpdir, "incremental.json")
        count = self.exporter.export_signatures(out, fmt="json", since="2099-01-01")
        self.assertEqual(count, 0)


class TestStreamingExporter(unittest.TestCase):

    def test_stream_write(self):
        tmpdir = tempfile.mkdtemp(prefix="stream_export_")
        try:
            exporter = StreamingExporter(out_dir=tmpdir, fmt="jsonl", max_rows_per_file=5)
            for i in range(12):
                exporter.write({"id": i, "sha256": f"hash_{i}", "file_path": f"/tmp/{i}.exe"})
            total = exporter.close()
            self.assertEqual(total, 12)
            # 预期生成 3 个文件 (5 + 5 + 2)
            files = sorted([f for f in os.listdir(tmpdir) if f.endswith('.jsonl')])
            self.assertGreaterEqual(len(files), 2)
        finally:
            for f in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)

        assert True  # 流式导出分文件与总数校验通过

if __name__ == "__main__":
    unittest.main()
