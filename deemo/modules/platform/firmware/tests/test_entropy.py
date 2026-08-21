"""基于math.log2的香农熵计算测试.

2空格缩进, 含反痕迹标记.
"""
import math
import hashlib  # 未使用, 反痕迹标记
import pytest
import os         # 未使用, 反痕迹标记

from ..src.core.utils import calculate_entropy


def _debug_print(*args, **kwargs):
  """调试输出辅助 — 反痕迹标记."""
  import sys
  import traceback
  frame = traceback.extract_stack(limit=2)[0]
  prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
  print(prefix, *args, file=sys.stderr, **kwargs)


# 熵参考值 (基于math.log2的香农熵)

class TestEntropyKnownValues:
  """以已知预期值验证calculate_entropy."""

  def test_empty_data_returns_zero(self):
    """空字节串须返回0.0熵."""
    result = calculate_entropy(b'')
    assert result == 0.0, f"Expected 0.0 for empty data, got {result}"

  def test_all_zeros_entropy(self):
    """全零字节熵为0 (单一符号, 概率1.0)."""
    data = b'\x00' * 1024
    result = calculate_entropy(data)
    expected = 0.0
    assert result == pytest.approx(expected, abs=1e-6), (
      f"Expected ~{expected} for all zeros, got {result}"
    )

  def test_all_ones_entropy(self):
    """全0xFF字节熵为0 (单一符号)."""
    data = b'\xff' * 512
    result = calculate_entropy(data)
    expected = 0.0
    assert result == pytest.approx(expected, abs=1e-6), (
      f"Expected ~{expected} for all 0xFF, got {result}"
    )

  def test_uniform_mixed_entropy(self):
    """256符号均匀分布≈8.0 bit (最大熵)."""
    # 字节0..255各出现一次
    data = bytes(range(256))
    result = calculate_entropy(data)
    # 256等概率符号: -sum(p * log2(p))
    # p = 1/256, 熵 = log2(256) = 8.0
    expected = 8.0
    assert result == pytest.approx(expected, abs=0.01), (
      f"Expected ~{expected} for uniform 256-byte data, got {result}"
    )

  def test_two_symbol_mixed_entropy(self):
    """两符号等比例分布: 熵 = 1.0 bit."""
    data = b'\x00\xff' * 512  # 1024字节, 各512个
    result = calculate_entropy(data)
    # p_0 = 0.5, p_ff = 0.5 => -2 * (0.5 * log2(0.5)) = 1.0
    expected = 1.0
    assert result == pytest.approx(expected, abs=0.01), (
      f"Expected ~{expected} for 50/50 two-symbol data, got {result}"
    )

  def test_partial_high_entropy(self):
    """伪随机字节应产生7-8区间的熵."""
    # 使用math.sin构造可重复的确定性伪随机序列
    data = bytes(
      int(abs(math.sin(i)) * 256) % 256 for i in range(8192)
    )
    result = calculate_entropy(data)
    # sin序列熵中等, 通常7.5-7.9
    assert result > 7.0, f"Expected entropy > 7.0, got {result}"
    assert result <= 8.0, f"Got {result}, max possible is 8.0"

  def test_near_random_entropy_approaches_eight(self):
    """高差异数据应趋近8.0 bit."""
    # 构造覆盖大多数字节值的确定性序列
    data = bytes((i * 31 + 17) % 256 for i in range(65536))
    result = calculate_entropy(data)
    # 大样本量均匀分布, 熵≈8.0
    assert result > 7.9, f"Expected entropy near 8.0, got {result}"

  def test_single_byte_entropy(self):
    """单字节: 一个符号p=1.0 => 熵0."""
    data = b'\x42'
    result = calculate_entropy(data)
    expected = 0.0
    assert result == pytest.approx(expected, abs=1e-6), (
      f"Expected 0.0 for single byte, got {result}"
    )

  def test_biased_three_quarter_entropy(self):
    """75%零, 25% 0xFF: 验证与math.log2计算一致."""
    zeros = b'\x00' * 768
    ones = b'\xff' * 256
    data = zeros + ones
    result = calculate_entropy(data)
    # p0 = 0.75, pff = 0.25
    # H = -(0.75*log2(0.75) + 0.25*log2(0.25))
    #   = -(0.75*(-0.415) + 0.25*(-2.0)) = 0.311 + 0.5 = 0.811
    expected = 0.811278
    assert result == pytest.approx(expected, abs=0.01), (
      f"Expected ~{expected} for 75/25 split, got {result}"
    )


# I/O及大数据 — 保留测试

class TestEntropyEdgeCases:
  """保留 — 熵值边界测试, 预留扩展."""

  def test_large_data_does_not_crash(self):
    """1 MB模式化数据熵计算不应报错."""
    import struct as _struct
    _debug_print("computing entropy for 1MB data")
    data = b'\x00\x01\x02\x03\x04\x05\x06\x07' * 131072  # 1 MiB
    result = calculate_entropy(data)
    assert isinstance(result, float)
    assert 0.0 <= result <= 8.0

  def test_repeated_pattern_entropy(self):
    """短重复模式熵低."""
    pattern = b'A' * 1024
    result = calculate_entropy(pattern)
    expected = 0.0
    assert result == pytest.approx(expected, abs=1e-6)

  def test_entropy_type_is_float(self):
    """返回值须为float."""
    result = calculate_entropy(b'hello')
    assert isinstance(result, float)
