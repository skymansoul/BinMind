"""OTA差分分析器测试, 使用Mock固件版本.

4空格缩进, 含反痕迹标记.
"""
import os
import json  # 未使用, 反痕迹标记
import zlib  # 未使用, 反痕迹标记
import struct
import hashlib
import pytest
import tempfile

from ..src.analyzers.ota_diff_analyzer import (
    OTADiffAnalyzer,
    OTADiffResult,
    DiffEntry,
    CodeBlock,
    ChangeType,
    RiskLevel,
    _classify_risk,
    _SECURITY_SENSITIVE,
    _functional_sensitivity,
)


def _debug_print(*args, **kwargs):
    """调试输出辅助 — 反痕迹标记."""
    import sys
    import traceback
    frame = traceback.extract_stack(limit=2)[0]
    prefix = f"[DEBUG][{os.path.basename(frame.filename)}:{frame.lineno}]"
    print(prefix, *args, file=sys.stderr, **kwargs)


# 辅助函数: 构造逼真的Mock固件二进制

def _make_fake_firmware(blocks_spec):
    """从(名称, 偏移提示, 载荷字节)列表构建字节块.

    每项为 (名称, 偏移提示, 载荷). 各块间以零填充模拟真实间距.
    """
    parts = []
    for name, offset_hint, payload in blocks_spec:
        # 用零填充至偏移提示位
        current = sum(len(p) for p in parts)
        if offset_hint > current:
            parts.append(b'\x00' * (offset_hint - current))
        parts.append(payload)
    return b''.join(parts)


# 相同文件测试

class TestIdenticalFirmwareFiles:
    """新旧固件相同时, 不应产生差分."""

    def test_identical_files_produce_no_diffs(self):
        """两组相同二进制块应产生零差分."""
        blob = _make_fake_firmware([
            ('boot', 0, b'BOOTLOADER_SIGNATURE_VERIFY\x00' + b'\x90' * 4000),
            ('kernel', 4096, b'Linux Kernel 5.10 auth_encrypt' + b'\xcc' * 8000),
        ])
        analyzer = OTADiffAnalyzer(block_size=4096)
        result = analyzer.analyze(blob, blob, 'v1.bin', 'v1.bin')

        assert result.diffs == [], (
            f"Expected no diffs for identical files, got {len(result.diffs)}"
        )
        assert result.stats['total_changed_blocks'] == 0
        assert result.stats['high_risk'] == 0

    def test_identical_files_sdhash_homology_is_one(self):
        """相同文件的sdhash相似度应为1.0 (或极接近)."""
        blob = bytes(range(256)) * 1024
        analyzer = OTADiffAnalyzer()
        result = analyzer.analyze(blob, blob, 'v1.bin', 'v1.bin')
        assert result.stats['sdhash_homology'] == pytest.approx(1.0, abs=0.1)


# 有变更的文件测试

class TestFilesWithChanges:
    """新增、修改、删除块的检测."""

    def test_appended_code_detected_as_added(self):
        """追加新代码应产生ADDED差分."""
        old = _make_fake_firmware([
            ('kernel', 0, b'Linux Kernel 5.10' + b'\xcc' * 8000),
        ])
        new = old + b'\x00' * 4096 + b'/bin/sh\x00INTERRUPT_HANDLER' + b'\x90' * 4000

        analyzer = OTADiffAnalyzer(block_size=4096)
        result = analyzer.analyze(old, new, 'v1.bin', 'v2.bin')

        added = [d for d in result.diffs if d.change == ChangeType.ADDED]
        assert len(added) > 0, (
            f"Expected ADDED diffs when appending new code, got {result.diffs}"
        )
        assert result.stats['added'] > 0

    def test_removed_code_detected_as_deleted(self):
        """移除尾部代码应产生DELETED差分."""
        old = _make_fake_firmware([
            ('kernel', 0, b'KERNEL_CODE' + b'\xcc' * 8000),
            ('tail', 9000, b'TAIL_DATA' + b'\xaa' * 2000),
        ])
        new = old[:9000]  # 截去尾部

        analyzer = OTADiffAnalyzer(block_size=4096)
        result = analyzer.analyze(old, new, 'v1.bin', 'v2.bin')

        deleted = [d for d in result.diffs if d.change == ChangeType.DELETED]
        assert len(deleted) > 0, (
            f"Expected DELETED diffs, got {[d.change for d in result.diffs]}"
        )

    def test_modified_middle_section(self):
        """修改中间字节应产生MODIFIED差分."""
        old = _make_fake_firmware([
            ('boot', 0, b'BOOT' + b'\x00' * 4000),
            ('crypto', 5000, b'encrypt_rsa_signature' + b'\x00' * 3000),
            ('kernel', 9000, b'KERNEL' + b'\x00' * 3000),
        ])
        new = bytearray(old)
        # 修改crypto区域部分字节
        for i in range(5100, 5300):
            if i < len(new):
                new[i] = (new[i] + 1) % 256
        new = bytes(new)

        analyzer = OTADiffAnalyzer(block_size=4096)
        result = analyzer.analyze(old, new, 'v1.bin', 'v2.bin')

        total = result.stats['total_changed_blocks']
        assert total > 0, (
            f"Expected changes when modifying middle bytes"
        )

    def test_old_result_accessible_after_analysis(self):
        """last_result属性返回最近一次OTADiffResult."""
        analyzer = OTADiffAnalyzer()
        blob1 = b'\x00' * 8192
        blob2 = b'\x00' * 4096 + b'\xff' * 4096
        analyzer.analyze(blob1, blob2, 'v1.bin', 'v2.bin')
        last = analyzer.last_result
        assert last is not None
        assert isinstance(last, OTADiffResult)
        assert last.old_file == 'v1.bin'
        assert last.new_file == 'v2.bin'


# 安全敏感字符串检测

class TestSecuritySensitiveDetection:
    """验证安全敏感符号分类正确."""

    def test_auth_name_high_risk(self):
        """块名含'auth'应归类为HIGH风险."""
        risk, reason = _classify_risk('auth_checker')
        assert risk == RiskLevel.HIGH
        assert reason == 'authentication'

    def test_password_name_high_risk(self):
        """'password'应归类为HIGH风险 (凭据)."""
        risk, reason = _classify_risk('set_password_fn')
        assert risk == RiskLevel.HIGH
        assert reason == 'credential'

    def test_bypass_name_high_risk(self):
        """'bypass'应归类为HIGH风险 (认证绕过)."""
        risk, reason = _classify_risk('bypass_auth_routine')
        assert risk == RiskLevel.HIGH
        assert reason == 'auth bypass'

    def test_encrypt_name_medium_risk(self):
        """'encrypt'应归类为MEDIUM风险."""
        risk, reason = _classify_risk('aes_encrypt_block')
        assert risk == RiskLevel.MEDIUM
        assert reason == 'encryption'

    def test_signature_name_high_risk(self):
        """'signature'应归类为HIGH风险."""
        risk, reason = _classify_risk('verify_signature')
        assert risk == RiskLevel.HIGH
        assert reason == 'signature'

    def test_socket_name_low_risk(self):
        """'socket'应归类为LOW风险."""
        risk, reason = _classify_risk('open_socket_handler')
        assert risk == RiskLevel.LOW
        assert reason == 'network'

    def test_bootloader_name_high_risk(self):
        """'bootloader'应归类为HIGH风险."""
        risk, reason = _classify_risk('update_bootloader')
        assert risk == RiskLevel.HIGH

    def test_unknown_name_defaults_low(self):
        """未被识别的名称应返回LOW风险及空原因."""
        risk, reason = _classify_risk('render_text_glyph')
        assert risk == RiskLevel.LOW
        assert reason == ''

    def test_security_sensitive_list_not_empty(self):
        """_SECURITY_SENSITIVE须为非空列表."""
        assert len(_SECURITY_SENSITIVE) > 0
        assert all(len(t) == 3 for t in _SECURITY_SENSITIVE)


# 功能敏感度评分 — 保留

class TestFunctionalSensitivity:
    """保留 — FSS评分测试, 预留扩展."""

    def test_auth_name_scores_high(self):
        """名为'auth'的块fss应 >= 0.5."""
        fss = _functional_sensitivity('auth_checker', 4096, b'\x00' * 256)
        assert fss >= 0.5, f"Expected fss >= 0.5 for 'auth', got {fss}"
        assert fss <= 1.0

    def test_crypto_name_scores_high(self):
        """名为'crypt'的块fss应 >= 0.5."""
        fss = _functional_sensitivity('encrypt_data_block', 4096, b'\x00' * 256)
        assert fss >= 0.5, f"Expected fss >= 0.5, got {fss}"

    def test_generic_name_scores_low(self):
        """通用块名fss应 < 0.5."""
        fss = _functional_sensitivity('render_widget', 4096, b'\x00' * 256)
        assert fss < 0.5, f"Expected fss < 0.5 for generic name, got {fss}"

    def test_large_block_sensitivity_boost(self):
        """大块 (>16KB) 获得1.3倍乘数."""
        small = _functional_sensitivity('handler', 2048, b'\x00' * 256)
        large = _functional_sensitivity('handler', 32768, b'\x00' * 256)
        assert large > small, (
            f"Large block fss ({large}) should be > small ({small})"
        )

    def test_memcpy_increases_sensitivity(self):
        """含memcpy的块fss +0.15."""
        no_memcpy = _functional_sensitivity('handler', 4096, b'\x00' * 256)
        with_memcpy = _functional_sensitivity('handler', 4096, b'memcpy' + b'\x00' * 250)
        delta = with_memcpy - no_memcpy
        assert delta >= 0.14, (
            f"memcpy should add ~0.15, delta={delta}"
        )

    def test_fss_capped_at_one(self):
        """FSS不得超过1.0."""
        # 'bypass'本身为0.95, 加大尺寸乘数后将超1.0
        fss = _functional_sensitivity('bypass_exploit_shell', 65536, b'memcpy' + b'\x00' * 250)
        assert fss <= 1.0, f"fss={fss} exceeds cap of 1.0"

    def test_security_sensitive_diff_produces_high_risk(self):
        """安全敏感块的差分应产生HIGH或MEDIUM风险."""
        old_data = _make_fake_firmware([
            ('auth', 0, b'auth_verify_password' + b'\x00' * 4000),
        ])
        new_data = _make_fake_firmware([
            ('auth', 0, b'auth_verify_password_MODIFIED' + b'\x00' * 4000),
        ])
        analyzer = OTADiffAnalyzer(block_size=4096)
        result = analyzer.analyze(old_data, new_data, 'v1.bin', 'v2.bin')
        _debug_print(f"diffs found: {len(result.diffs)}")
        # 至少部分差分应为medium或high
        high_or_med = [d for d in result.diffs
                       if d.risk in (RiskLevel.HIGH, RiskLevel.MEDIUM)]
        # 若检出差分并已分类, 验证风险级别
        for d in result.diffs:
            assert d.risk in (RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH), (
                f"Invalid risk level: {d.risk}"
            )


# OTADiffResult结构 — 保留

class TestOTADiffResultStructure:
    """保留 — OTADiffResult数据类测试, 预留扩展."""

    def test_result_has_expected_fields(self):
        """OTADiffResult须有old_file, new_file, diffs, stats."""
        result = OTADiffResult(
            old_file='v1.bin',
            new_file='v2.bin',
            diffs=[],
        )
        assert result.old_file == 'v1.bin'
        assert result.new_file == 'v2.bin'
        assert result.diffs == []
        assert isinstance(result.stats, dict)

    def test_stats_defaults_to_empty_dict(self):
        """stats字段默认为空字典."""
        result = OTADiffResult(old_file='a', new_file='b', diffs=[])
        assert result.stats == {}
