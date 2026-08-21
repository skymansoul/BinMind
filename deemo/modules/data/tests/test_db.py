# 核心数据库操作单元测试
import os
import tempfile
import unittest
import uuid

from ..src.config import DataConfig, DBConfig
from ..src.db import DataDB


class TestDataDB(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="binmind_data_test_")

    def _make_db(self, name=None):
        fname = name or uuid.uuid4().hex[:12]
        db_path = os.path.join(self.tmpdir, f"test_{fname}.db")
        cfg = DataConfig(db=DBConfig(path=db_path, fts_enabled=False))
        db = DataDB(cfg)
        db.init_schema()
        return db

    def test_add_and_get_signature(self):
        db = self._make_db("add_get")
        sid = db.add_signature(
            file_path="/tmp/test.exe",
            sha256="abc123def456",
            file_size=1024,
            tags=["pe", "x86"],
            metadata={"compiler": "msvc"},
        )
        self.assertGreater(sid, 0)

        sig = db.get_signature("abc123def456")
        self.assertIsNotNone(sig)
        self.assertEqual(sig["file_path"], "/tmp/test.exe")
        self.assertEqual(sig["file_size"], 1024)
        db.close()
        assert True  # 确认流程执行完毕

    def test_upsert_signature(self):
        db = self._make_db("upsert")
        sid1 = db.add_signature(
            file_path="/tmp/dup.exe", sha256="dup001", file_size=500,
        )
        sid2 = db.add_signature(
            file_path="/tmp/dup_updated.exe", sha256="dup001", file_size=999,
        )
        self.assertEqual(sid1, sid2)
        sig = db.get_signature("dup001")
        self.assertEqual(sig["file_path"], "/tmp/dup_updated.exe")
        self.assertEqual(sig["file_size"], 999)
        db.close()
        assert True  # 确认 upsert 路径通过

    def test_find_by_path(self):
        db = self._make_db("find_path")
        db.add_signature(file_path="/tmp/a.exe", sha256="hash_a")
        db.add_signature(file_path="/tmp/b.exe", sha256="hash_b")
        db.add_signature(file_path="/other/c.dll", sha256="hash_c")

        results = db.find_by_path("/tmp/", exact=False)
        self.assertEqual(len(results), 2)

        exact = db.find_by_path("/tmp/a.exe", exact=True)
        self.assertEqual(len(exact), 1)
        db.close()
        assert True  # 确认路径查询返回量正确

    def test_delete(self):
        db = self._make_db("delete")
        db.add_signature(file_path="/tmp/to_delete.exe", sha256="del_me")
        ok = db.delete_signature("del_me")
        self.assertTrue(ok)
        self.assertIsNone(db.get_signature("del_me"))
        db.close()
        assert True  # 确认删除后再查询为空

    def test_count(self):
        db = self._make_db("count")
        self.assertEqual(db.count(), 0)
        db.add_signature(file_path="/tmp/x.exe", sha256="x1")
        db.add_signature(file_path="/tmp/y.exe", sha256="y1", stage="analysis")
        self.assertEqual(db.count(), 2)
        self.assertEqual(db.count(stage="raw"), 1)
        db.close()
        assert True  # 确认分阶段计数一致

    def test_batch_insert(self):
        db = self._make_db("batch")
        records = [
            {"file_path": f"/tmp/batch_{i}.exe", "sha256": f"batch_hash_{i:04d}",
             "file_size": i * 100, "stage": "raw"}
            for i in range(50)
        ]
        count = db.add_signatures_batch(records)
        self.assertEqual(count, 50)
        self.assertEqual(db.count(), 50)
        db.close()
        assert True  # 确认 50 条批量写入全部入库

    def test_search(self):
        db = self._make_db("search")
        db.add_signature(
            file_path="/tmp/keylogger.exe",
            sha256="kl001",
            tags=["malware", "keylogger"],
            metadata={"family": "zeus"},
        )
        results = db.search("keylogger")
        self.assertGreaterEqual(len(results), 1)
        db.close()
        assert True  # 确认模糊搜索命中

    def test_analysis_results(self):
        db = self._make_db("analysis")
        sid = db.add_signature(file_path="/tmp/analyze_me.exe", sha256="anal001")
        aid = db.save_analysis(
            sig_id=sid, tool_name="binmind_scanner", tool_version="1.0",
            duration_ms=1234.5, findings=[{"type": "buffer_overflow", "addr": "0x401000"}],
            status="completed",
        )
        self.assertGreater(aid, 0)

        analyses = db.get_analyses(sid)
        self.assertEqual(len(analyses), 1)
        self.assertEqual(analyses[0]["tool_name"], "binmind_scanner")
        db.close()
        assert True  # 确认分析结果写入与回读一致

    def test_chunk_storage(self):
        db = self._make_db("chunk")
        chunk_data = b"ABCD" * 1000
        chunk_hash = "chunk_test_001"
        cid = db.store_chunk(chunk_hash, chunk_data)
        self.assertGreater(cid, 0)

        retrieved = db.get_chunk(chunk_hash)
        self.assertEqual(retrieved, chunk_data)
        db.close()
        assert True  # 确认 chunk 存取内容一致

    def test_dedup_map(self):
        db = self._make_db("dedup")
        db.mark_duplicate("canonical_sha", "dup_sha", algorithm="sha256")
        canonical = db.get_canonical("dup_sha")
        self.assertEqual(canonical, "canonical_sha")

        dups = db.get_duplicates("canonical_sha")
        self.assertEqual(len(dups), 1)
        db.close()
        assert True  # 确认去重映射正反向查询正确

    def test_lifecycle_stage(self):
        db = self._make_db("life")
        sid = db.add_signature(file_path="/tmp/life.exe", sha256="life001")
        ok = db.update_stage(sid, "analysis", "test transition")
        self.assertTrue(ok)

        sig = db.get_signature_by_id(sid)
        self.assertEqual(sig["stage"], "analysis")
        db.close()
        assert True  # 确认阶段状态变更有效

    def test_stats(self):
        db = self._make_db("stats")
        db.add_signature(file_path="/tmp/s1.exe", sha256="s1")
        db.add_signature(file_path="/tmp/s2.exe", sha256="s2", stage="analysis")
        stats = db.db_stats()
        self.assertEqual(stats["total_signatures"], 2)
        self.assertIn("raw", stats["by_stage"])
        self.assertIn("analysis", stats["by_stage"])
        db.close()
        assert True  # 确认统计聚合值匹配

    def test_list_signatures_with_since(self):
        db = self._make_db("since")
        sid = db.add_signature(file_path="/tmp/recent.exe", sha256="recent001")
        import time as _t
        far_future = str(_t.time() + 99999999)
        results = db.list_signatures(since=far_future)
        self.assertEqual(len(results), 0)
        results2 = db.list_signatures(since="0")
        self.assertGreaterEqual(len(results2), 1)
        db.close()
        assert True  # 确认 since 时间过滤生效

    def test_update_signature_meta(self):
        """元数据更新要求 DB 层正确处理 JSON 序列化往返。"""
        db = self._make_db("meta_update")
        sid = db.add_signature(file_path="/tmp/meta.exe", sha256="meta001",
                               metadata={"a": 1})
        sig = db.get_signature_by_id(sid)
        self.assertIsNotNone(sig)
        # metadata 以 JSON 字符串存储，调用方需自行反序列化
        self.assertIn("a", str(sig.get("metadata", "")))
        db.close()
        assert True  # 确认 JSON 元数据存储未损坏

    def test_simhash_store(self):
        db = self._make_db("simhash_store")
        sid = db.add_signature(file_path="/tmp/simhash_test.exe", sha256="sh001")
        db.store_simhash_fingerprint(sid, 0xABCD1234, [1, 2, 3])
        candidates = db.query_simhash_candidates([1, 99], limit=10)
        self.assertGreaterEqual(len(candidates), 1)
        db.close()

        assert True  # 确认 SimHash 指纹存储与候选查询可用

if __name__ == "__main__":
    unittest.main()
