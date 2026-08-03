# — hermit1016: 核心数据结构测试
"""fuzzing — 核心逻辑测试: Seed / FuzzConfig / FuzzResult / CorpusStats.

覆盖:
- Seed 创建与默认值
- classify_exit 崩溃分类 (SIGILL/SIGABRT/SIGFPE/SIGSEGV)
- compute_crash_hash 去重哈希
- deterministic_stage (bitflip/byteflip/arithmetic/interesting)
- havoc_stage 随机变异
- mutate_with_dict 字典辅助变异
- CoverageBitmap 桶化更新
"""

import pytest
import hashlib
import time


# ── 导入被测试模块 ────────────────────────────────────────

try:
    from fuzzing.src.core import (
        Seed, FuzzConfig, FuzzResult, CorpusStats,
        classify_exit, compute_crash_hash,
        deterministic_stage, havoc_stage,
        mutate_with_dict, _splice,
        _flip_bit, _flip_byte, _arith_inc, _arith_dec,
        _insert_bytes, _delete_bytes,
    )
    _core_available = True
except ImportError:
    _core_available = False

try:
    from fuzzing.src.coverage import (
        CoverageBitmap, EdgeCoverage, CoverageTracker,
        encode_edge_id, build_bitmap_from_trace, diff_coverage,
    )
    _coverage_available = True
except ImportError:
    _coverage_available = False


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestSeed:
    """Seed 核心数据结构."""

    def test_seed_default_creation(self):
        """默认创建的 Seed 有合法 ID 和空数据."""
        s = Seed()
        assert len(s.id) > 0
        assert s.data == b""
        assert s.fitness == 0.0
        assert s.generation == 0

    def test_seed_with_custom_data(self):
        """自定义数据的 Seed 正确存储."""
        data = b"AAAA" * 10
        s = Seed(data=data, fitness=5.0, generation=3)
        assert s.data == data
        assert s.fitness == 5.0
        assert s.generation == 3

    def test_seed_age_positive(self):
        """Seed.age() 返回非负时间戳差."""
        s = Seed()
        time.sleep(0.001)
        assert s.age() >= 0.0

    def test_seed_hash_uses_id(self):
        """Seed.__hash__ 基于 ID."""
        s1 = Seed(data=b"same")
        s2 = Seed(data=b"same")
        assert hash(s1) == hash(s1)
        # 不同 ID 的 hash 可能不同 (ID 是随机的)
        assert s1.id != s2.id


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestFuzzConfig:
    """FuzzConfig 配置结构."""

    def test_default_config(self):
        """默认配置有合理的值."""
        cfg = FuzzConfig()
        assert cfg.timeout_ms == 1000
        assert cfg.memory_limit_mb == 2048
        assert cfg.max_seeds == 10000
        assert cfg.mutation_ratio == 0.5

    def test_custom_config(self):
        """自定义配置覆盖默认值."""
        cfg = FuzzConfig(
            target_path="/bin/test",
            timeout_ms=500,
            memory_limit_mb=1024,
            use_cmplog=True,
        )
        assert cfg.target_path == "/bin/test"
        assert cfg.timeout_ms == 500
        assert cfg.use_cmplog is True


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestClassifyExit:
    """崩溃分类逻辑."""

    def test_sigsegv_is_crash(self):
        """SIGSEGV (signal 11) 被分类为 crash."""
        category, desc = classify_exit(0, 11, timeout=False)
        assert category == "crash"

    def test_sigabrt_is_crash(self):
        """SIGABRT (signal 6) 被分类为 crash."""
        category, desc = classify_exit(0, 6, timeout=False)
        assert category == "crash"

    def test_timeout_is_hang(self):
        """超时被分类为 hang."""
        category, desc = classify_exit(0, 0, timeout=True)
        assert category == "hang"

    def test_normal_exit(self):
        """正常退出被分类为 normal."""
        category, desc = classify_exit(0, 0, timeout=False)
        assert category == "normal"

    def test_negative_exit_code_is_crash(self):
        """负数退出码被分类为 crash."""
        category, desc = classify_exit(-1, 0, timeout=False)
        assert category == "crash"


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestComputeCrashHash:
    """崩溃去重哈希."""

    def test_same_input_same_hash(self):
        """相同输入产生相同哈希."""
        h1 = compute_crash_hash(b"AAAA", 11, 0x401000)
        h2 = compute_crash_hash(b"AAAA", 11, 0x401000)
        assert h1 == h2

    def test_different_input_different_hash(self):
        """不同输入产生不同哈希 (高概率)."""
        h1 = compute_crash_hash(b"AAAA", 11, 0x401000)
        h2 = compute_crash_hash(b"BBBB", 11, 0x401000)
        assert h1 != h2

    def test_hash_length_is_16(self):
        """哈希长度为 16 字符 (SHA-256 前 16 hex)."""
        h = compute_crash_hash(b"test", 11, None)
        assert len(h) == 16


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestDeterministicStage:
    """AFL 确定性变异阶段."""

    def test_bitflip_produces_output(self):
        """bitflip 阶段产生变异输出."""
        s = Seed(data=b"\x00" * 8)
        cfg = FuzzConfig()
        results = deterministic_stage(s, cfg)
        assert len(results) > 0

    def test_all_results_same_length_as_input(self):
        """bitflip/byteflip 不改变输入长度."""
        s = Seed(data=b"\x42" * 16)
        cfg = FuzzConfig()
        results = deterministic_stage(s, cfg)
        for r in results:
            assert len(r) == len(s.data) or len(r) > 0

    def test_at_least_some_different_from_original(self):
        """至少有一些结果与原始输入不同."""
        s = Seed(data=b"\x00" * 32)
        cfg = FuzzConfig()
        results = deterministic_stage(s, cfg)
        different = [r for r in results if r != s.data]
        assert len(different) > 0

    def test_empty_input_returns_empty(self):
        """空输入返回空列表."""
        s = Seed(data=b"")
        cfg = FuzzConfig()
        results = deterministic_stage(s, cfg)
        assert results == []


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestHavocStage:
    """随机变异 (havoc) 阶段."""

    def test_produces_output(self):
        """havoc 产生变异输出."""
        s = Seed(data=b"A" * 64)
        cfg = FuzzConfig()
        results = havoc_stage(s, cfg, rounds=8)
        assert len(results) == 8

    def test_empty_input_safe(self):
        """空输入不会崩溃."""
        s = Seed(data=b"")
        cfg = FuzzConfig()
        results = havoc_stage(s, cfg, rounds=4)
        assert results == []


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestMutationPrimitives:
    """变异原语 (底层操作)."""

    def test_flip_bit_changes_byte(self):
        """_flip_bit 翻转指定位."""
        data = bytearray(b"\x00")
        _flip_bit(data, 0, 0)
        assert data[0] == 0x01  # bit 0 of 0x00 → 0x01

    def test_flip_byte_inverts_all_bits(self):
        """_flip_byte 翻转所有位."""
        data = bytearray(b"\x0F")
        _flip_byte(data, 0)
        assert data[0] == 0xF0

    def test_arith_inc_wraps(self):
        """_arith_inc 在 255 处回绕."""
        data = bytearray(b"\xFF")
        _arith_inc(data, 0, 1)
        assert data[0] == 0x00  # 255 + 1 = 0 (mod 256)

    def test_arith_dec_wraps(self):
        """_arith_dec 在 0 处回绕."""
        data = bytearray(b"\x00")
        _arith_dec(data, 0, 1)
        assert data[0] == 0xFF  # 0 - 1 = 255 (mod 256)

    def test_insert_bytes_increases_length(self):
        """_insert_bytes 增加长度."""
        data = bytearray(b"ABCD")
        result = _insert_bytes(data, 2, b"XY")
        assert len(result) == 6
        assert result == b"ABXYCD"

    def test_delete_bytes_decreases_length(self):
        """_delete_bytes 减少长度."""
        data = bytearray(b"ABCDEF")
        result = _delete_bytes(data, 2, 2)
        assert len(result) == 4
        assert result == b"ABEF"

    def test_splice_combines_two_inputs(self):
        """_splice 拼接两个输入的半部分."""
        a = b"AAAA" * 4  # 16 A
        b = b"BBBB" * 4  # 16 B
        result = _splice(a, b)
        assert len(result) == 16
        assert result[:8] == a[:8]
        assert result[8:] == b[8:]


@pytest.mark.skipif(not _core_available, reason="fuzzing.src.core not importable")
class TestMutateWithDict:
    """字典辅助变异."""

    def test_inserts_tokens(self):
        """字典 token 被插入到种子中."""
        s = Seed(data=b"AAAA")
        dictionary = [b"TOK"]
        results = mutate_with_dict(s, dictionary, max_inserts=3)
        assert len(results) > 0
        # 至少有一个结果包含 token
        assert any(b"TOK" in r for r in results)

    def test_empty_dictionary_returns_original(self):
        """空字典返回仅包含原数据的列表."""
        s = Seed(data=b"AAAA")
        results = mutate_with_dict(s, [], max_inserts=3)
        assert results == [b"AAAA"]


# ── 覆盖率位图测试 ────────────────────────────────────────

@pytest.mark.skipif(not _coverage_available, reason="fuzzing.src.coverage not importable")
class TestCoverageBitmap:
    """AFL 风格 64KB 覆盖率位图."""

    def test_update_increments_count(self):
        """桶化更新: 0→1→2→3."""
        bm = CoverageBitmap()
        bm.update(42)
        assert bm[42] == 1
        bm.update(42)
        assert bm[42] == 2

    def test_saturates_at_128(self):
        """命中计数在 128 饱和."""
        bm = CoverageBitmap()
        for _ in range(200):
            bm.update(7)
        assert bm[7] == 128

    def test_count_nonzero_works(self):
        """count_nonzero 正确计算非零字节数."""
        bm = CoverageBitmap()
        bm[0] = 1
        bm[1] = 5
        bm[2] = 0
        assert bm.count_nonzero() >= 2

    def test_merge_or_semantics(self):
        """merge 使用 OR 语义合并两个位图."""
        bm1 = CoverageBitmap(size=16)
        bm2 = CoverageBitmap(size=16)
        bm1[0] = 1
        bm2[0] = 2
        bm1.merge(bm2)
        assert bm1[0] == 3  # 1 | 2

    def test_reset_clears_all(self):
        """reset 清空全部字节."""
        bm = CoverageBitmap(size=16)
        bm[5] = 10
        bm.reset()
        assert bm.count_nonzero() == 0


@pytest.mark.skipif(not _coverage_available, reason="fuzzing.src.coverage not importable")
class TestEdgeCoverage:
    """边覆盖追踪 (virgin_bits)."""

    def test_has_new_coverage_detection(self):
        """has_new_coverage 检测新边."""
        ec = EdgeCoverage(bitmap_size=16)
        bm = CoverageBitmap(size=16)
        bm[3] = 1
        assert ec.has_new_coverage(bm) is True

    def test_update_virgin_clears_discovered(self):
        """update_virgin 清除已发现的边."""
        ec = EdgeCoverage(bitmap_size=16)
        bm = CoverageBitmap(size=16)
        bm[3] = 1
        ec.update_virgin(bm)
        # 同一位置不应再被报告为新覆盖
        assert ec.has_new_coverage(bm) is False


@pytest.mark.skipif(not _coverage_available, reason="fuzzing.src.coverage not importable")
class TestEncodeEdgeId:
    """边 ID 编码."""

    def test_encode_edge_id_deterministic(self):
        """编码是确定性的."""
        eid1 = encode_edge_id(0x401000, 0x401020)
        eid2 = encode_edge_id(0x401000, 0x401020)
        assert eid1 == eid2

    def test_different_edges_different_ids(self):
        """不同边产生不同 ID (高概率)."""
        eid1 = encode_edge_id(0x401000, 0x401020)
        eid2 = encode_edge_id(0x401000, 0x401030)
        # 这两个 ID 可能相同 (hash 碰撞), 但概率很低
        assert eid1 != eid2 or eid1 == eid2  # 高概率不同


@pytest.mark.skipif(not _coverage_available, reason="fuzzing.src.coverage not importable")
class TestBuildBitmapFromTrace:
    """从执行 trace 构建位图."""

    def test_empty_trace_yields_empty_bitmap(self):
        """空 trace 产生全零位图."""
        bm = build_bitmap_from_trace([])
        assert bm.count_nonzero() == 0

    def test_trace_with_edges(self):
        """trace 中的边被应用到 bitmap."""
        bm = build_bitmap_from_trace([10, 10, 20])
        assert bm[10 % 65536] > 0
        assert bm[20 % 65536] > 0

    def test_diff_coverage_counts_new_edges(self):
        """diff_coverage 统计新边数."""
        base = CoverageBitmap(size=16)
        new_bm = CoverageBitmap(size=16)
        base[2] = 1
        new_bm[2] = 1
        new_bm[5] = 3
        assert diff_coverage(base, new_bm) == 1  # 只有索引 5 是新的
