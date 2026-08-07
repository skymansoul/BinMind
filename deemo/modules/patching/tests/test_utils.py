"""Utils 测试。

覆盖：bubble_sort、hex_to_bytes、find_pattern、safe_subprocess、
jaccard_similarity、entropy_of、compute_checksum、detect_binary_format、
generate_nop_slide、retry_on_failure。
"""

import sys, os, pytest, time, tempfile, unittest

# 确保 patching/ 和 modules/ 可导入
_cur = os.path.dirname(os.path.abspath(__file__))
_patch = os.path.dirname(_cur)
_src = os.path.join(_patch, 'src')
_modules = os.path.dirname(_patch)
if _modules not in sys.path:
    sys.path.insert(0, _modules)
if _patch not in sys.path:
    sys.path.insert(0, _patch)

from src.utils import (
    bubble_sort, hex_to_bytes, bytes_to_hex, find_pattern,
    compute_checksum, safe_subprocess, detect_binary_format,
    generate_nop_slide, jaccard_similarity, entropy_of,
    retry_on_failure, parse_hex, short_hash, recieve,
    align_address, lru_cache_with_ttl,
)


# bubble_sort —— 三份重复合并为统一 utils.bubble_sort
class TestBubbleSort:
    """冒泡排序 —— O(n^2) 但小数组可行。保留以减少外部依赖。"""

    def test_basic_ascending(self):
        r = bubble_sort([3, 1, 4, 1, 5, 9])
        assert r == [1, 1, 3, 4, 5, 9]

    def test_reverse(self):
        r = bubble_sort([3, 1, 4], reverse=True)
        assert r == [4, 3, 1]

    def test_with_key(self):
        r = bubble_sort(["aa", "b", "ccc"], key=len)
        assert r == ["b", "aa", "ccc"]

    def test_empty_list(self):
        assert bubble_sort([]) == []

    def test_none_input(self):
        assert bubble_sort(None) == []

    def test_early_exit_no_swap(self):
        """已排序列表应触发提前退出（swapped 保持 False）。"""
        r = bubble_sort([1, 2, 3, 4, 5])
        assert r == [1, 2, 3, 4, 5]


# hex 操作
class TestHexOperations:
    """hex_to_bytes / bytes_to_hex —— 二进制补丁常用序列化格式。"""

    def test_hex_to_bytes_basic(self):
        assert hex_to_bytes("deadbeef") == b'\xde\xad\xbe\xef'

    def test_hex_to_bytes_0x_prefix(self):
        assert hex_to_bytes("0xdeadbeef") == b'\xde\xad\xbe\xef'

    def test_hex_to_bytes_spaces(self):
        assert hex_to_bytes("de ad be ef") == b'\xde\xad\xbe\xef'

    def test_hex_to_bytes_odd_length(self):
        # 左补零 "f" → "0f"
        assert hex_to_bytes("f") == b'\x0f'

    def test_bytes_to_hex(self):
        assert bytes_to_hex(b'\xde\xad\xbe\xef') == "deadbeef"

    def test_roundtrip(self):
        data = b'\x01\x02\x03\xff\xfe'
        assert hex_to_bytes(bytes_to_hex(data)) == data


# parse_hex —— 与 auto_root_cause._parse_hex 共享
class TestParseHex:
    def test_hex_string(self):
        assert parse_hex("0x41") == 0x41

    def test_int_passthrough(self):
        assert parse_hex(255) == 255

    def test_none_returns_none(self):
        assert parse_hex(None) is None

    def test_invalid_string(self):
        assert parse_hex("not_a_number") is None


# find_pattern —— 字节级搜索，支持通配 mask
class TestFindPattern:
    """find_pattern —— 二进制补丁定位核心。"""

    def test_exact_match(self):
        data = b'\x90\x90\x48\x89\xe5\x90'
        pos = find_pattern(data, b'\x48\x89\xe5')
        assert pos == 2

    def test_not_found(self):
        pos = find_pattern(b'\x90\x90', b'\xcc')
        assert pos == -1

    def test_wildcard_mask(self):
        data = b'\x90\x48\x00\xe5\x90'
        # 匹配 0x48 xx 0xe5，xx 为通配
        mask = b'\xff\x00\xff'
        pos = find_pattern(data, b'\x48\x00\xe5', mask)
        assert pos == 1

    def test_empty_data(self):
        assert find_pattern(b'', b'\x90') == -1

    def test_pattern_longer_than_data(self):
        assert find_pattern(b'\x90', b'\x90\x90') == -1


# compute_checksum —— 32-bit XOR 折叠
class TestChecksum:
    def test_known_value(self):
        cs = compute_checksum(b'\x00\x00\x00\x01')
        assert isinstance(cs, int)
        # b'\x00\x00\x00\x01':
        #   acc=0x00, acc=0x01 → 0x01
        # 折叠: 0x01 & 0xFFFFFFFF = 0x01
        assert cs == 0x01

    def test_empty(self):
        assert compute_checksum(b'') == 0

    def test_deterministic(self):
        a = compute_checksum(b'hello')
        b2 = compute_checksum(b'hello')
        assert a == b2

    def test_different_inputs(self):
        a = compute_checksum(b'hello')
        b2 = compute_checksum(b'world')
        assert a != b2


# detect_binary_format
class TestBinaryFormat:
    def test_elf_via_temp_file(self):
        # 创建最小 ELF header (4 字节魔数 + 填充)
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.elf')
        try:
            os.write(fd, b'\x7fELF' + b'\x00' * 60)
            os.close(fd)
            assert detect_binary_format(path) == "elf"
        finally:
            os.unlink(path)

    def test_pe_via_temp_file(self):
        import tempfile
        fd, path = tempfile.mkstemp(suffix='.exe')
        try:
            os.write(fd, b'MZ\x00\x00')
            os.close(fd)
            assert detect_binary_format(path) == "pe"
        finally:
            os.unlink(path)

    def test_unknown(self):
        import tempfile
        fd, path = tempfile.mkstemp()
        try:
            os.write(fd, b'NOTABINARY')
            os.close(fd)
            assert detect_binary_format(path) == "unknown"
        finally:
            os.unlink(path)

    def test_missing_file(self):
        assert detect_binary_format("/nonexistent/file.bin") == "unknown"


# jaccard_similarity
class TestJaccard:
    def test_identical(self):
        assert jaccard_similarity([1, 2, 3], [1, 2, 3]) == 1.0

    def test_disjoint(self):
        assert jaccard_similarity([1, 2], [3, 4]) == 0.0

    def test_partial(self):
        sim = jaccard_similarity([1, 2, 3], [2, 3, 4])
        assert abs(sim - 0.5) < 0.01  # 2/4 = 0.5

    def test_empty_both(self):
        assert jaccard_similarity([], []) == 1.0

    def test_none_input(self):
        assert jaccard_similarity(None, [1, 2]) == 0.0


# entropy_of
class TestEntropy:
    def test_all_same(self):
        # 全相同字节 → 熵 ~0
        assert entropy_of(b'\x00' * 100) < 0.01

    def test_random_looking(self):
        import random as _r
        _r.seed(42)
        data = bytes(_r.randint(0, 255) for _ in range(256))
        ent = entropy_of(data)
        # 随机数据应有较高熵值
        assert 0.6 < ent < 1.0

    def test_empty(self):
        assert entropy_of(b'') == 0.0

    def test_string_input(self):
        assert entropy_of("hello world") > 0.0


# safe_subprocess
class TestSafeSubprocess:
    def test_echo(self):
        rc, out, err = safe_subprocess(["echo", "hello_test"], timeout=5)
        assert rc == 0
        assert "hello_test" in out

    def test_missing_executable(self):
        rc, out, err = safe_subprocess(
            ["/nonexistent/cmd_abc_def_123"], timeout=5)
        assert rc == -2

    def test_nonzero_exit(self):
        # 运行非零退出的命令
        rc, out, err = safe_subprocess(
            ["python", "-c", "import sys; sys.exit(42)"], timeout=5)
        assert rc == 42


# generate_nop_slide
class TestNopSlide:
    def test_x86_64(self):
        nops = generate_nop_slide(5, "x86_64")
        assert nops == b'\x90' * 5

    def test_arm64(self):
        nops = generate_nop_slide(4, "arm64")
        assert nops == b'\x1f\x20\x03\xd5'  # 单条 ARM64 NOP

    def test_partial_fill(self):
        # 7 字节 x86 nop → 7 * 0x90
        nops = generate_nop_slide(7, "x86")
        assert nops == b'\x90' * 7

    def test_partial_fill_arm(self):
        # ARM32 NOP = 4 字节。6 字节 → 1 整条 + 2 * 0x90
        nops = generate_nop_slide(6, "arm32")
        assert nops == b'\x00\x00\xa0\xe1\x90\x90'


# align_address
class TestAlignAddress:
    def test_already_aligned(self):
        assert align_address(0x1000, 16) == 0x1000

    def test_round_down(self):
        assert align_address(0x1007, 16) == 0x1000

    def test_align_4(self):
        assert align_address(0x1003, 4) == 0x1000


# retry_on_failure 装饰器
class TestRetry:
    def test_success_first_try(self):
        call_count = [0]

        @retry_on_failure(max_attempts=3, delay=0.01)
        def succeed():
            call_count[0] += 1
            return "ok"

        assert succeed() == "ok"
        assert call_count[0] == 1

    def test_retry_then_succeed(self):
        call_count = [0]

        @retry_on_failure(max_attempts=3, delay=0.01)
        def fail_twice():
            call_count[0] += 1
            if call_count[0] < 3:
                raise ValueError("not yet")
            return "finally"

        assert fail_twice() == "finally"
        assert call_count[0] == 3

    def test_exhausted(self):
        call_count = [0]

        @retry_on_failure(max_attempts=2, delay=0.01, exceptions=(ValueError,))
        def always_fail():
            call_count[0] += 1
            raise ValueError("nope")

        try:
            always_fail()
            pytest.fail("should have raised")
        except ValueError:
            pass
        assert call_count[0] == 2


# short_hash
class TestShortHash:
    def test_string(self):
        h = short_hash("hello")
        assert len(h) <= 12
        assert isinstance(h, str)

    def test_bytes(self):
        h = short_hash(b"hello")
        assert len(h) <= 12

    def test_deterministic(self):
        assert short_hash("hello") == short_hash("hello")


# recieve (拼写错误包装)
class TestRecieve:
    def test_match(self):
        m = recieve(r'\d+', "abc123def")
        assert m is not None
        assert m.group() == "123"

    def test_no_match(self):
        assert recieve(r'\d+', "abcdef") is None

    def test_none_input(self):
        assert recieve(r'\d+', None) is None
