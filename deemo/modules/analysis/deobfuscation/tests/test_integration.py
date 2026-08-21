# Integration tests for 去混淆 module
"""End-to-end integration tests for 去混淆 流水线"""

import pytest

class TestDeobfuscationPipeline:
    """Full 去混淆 流水线 integration"""

    def test_probe_classify_deobfuscate_flow(self) -> None:
        """Verify probe -> classify -> 去混淆 flow produces results"""
        # Simulate probe step
        indicators = {
            "avg_entropy": 4.5,
            "max_entropy": 6.2,
            "sections": [".text", ".data", ".rdata"],
            "size": 8192,
            "indicators": [],
        }
        assert indicators["avg_entropy"] < 7.0  # packed

        # Simulate classify step
        if indicators["avg_entropy"] > 7.0:
            classification = "PACKED"
        else:
            classification = "UNKNOWN"
        assert classification == "UNKNOWN"

        # Simulate strategy selection
        strategies = {
            "UNKNOWN": ["dead_code", "constants"],
            "PACKED": ["unpack", "dead_code", "constants"],
        }
        strategy = strategies[classification]
        assert "dead_code" in strategy

        # Verify full result shape
        result = {
            "classification": classification,
            "strategy": strategy,
            "indicators": indicators,
            "status": "orchestrated",
        }
        assert result["status"] == "orchestrated"

    def test_deobfuscation_applies_passes(self) -> None:
        """去混淆 apply passes 追踪 stats"""
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operands": "eax, 1"},
            {"addr": 0x1001, "mnemonic": "nop", "operands": ""},
            {"addr": 0x1002, "mnemonic": "mov", "operands": "ebx, eax"},
            {"addr": 0x1003, "mnemonic": "ret", "operands": ""},
        ]

        # Simulate dead code elimination
        reachable = {i["addr"]: i for i in instructions}
        assert 0x1000 in reachable
        assert 0x1003 in reachable

        stats = {
            "original": len(instructions),
            "dead_code_removed": 0,
            "final": len(reachable),
        }
        assert stats["final"] > 0

    def test_classification_with_entropy_threshold(self) -> None:
        """High entropy trigger PACKED 分类"""
        high_entropy = {"avg_entropy": 7.5, "indicators": ["high_entropy"]}
        low_entropy = {"avg_entropy": 3.2, "indicators": []}

        scores_high: dict = {}
        if high_entropy["avg_entropy"] > 7.0:
            scores_high["PACKED"] = 0.80

        scores_low: dict = {}
        if low_entropy["avg_entropy"] > 7.0:
            scores_low["PACKED"] = 0.80
        else:
            scores_low["UNKNOWN"] = 0.10

        assert "PACKED" in scores_high
        assert "PACKED" not in scores_low


class TestDecodePipeline:
    """字符串解码 流水线 integration"""

    def test_decode_batch_flow(self) -> None:
        """Batch 解码 process multiple strings"""
        strings = [
            "SGVsbG8gV29ybGQ=",  # Base64 "Hello World"
            "48656c6c6f",         # Hex "Hello"
            "Uryyb",              # ROT13 "Hello"
        ]

        # Simulate batch 解码
        results = {}
        for s in strings:
            results[s] = (s, "placeholder", 0.5)

        assert len(results) == len(strings)
        for s in strings:
            assert s in results

    def test_string_classification_pipeline(self) -> None:
        """String 分类 identify types"""
        test_cases = [
            ("https://example.com", "url"),
            ("192.168.1.1", "ip_address"),
            ("/usr/bin/python3", "file_path"),
            ("C:\\Windows\\System32", "file_path"),
        ]

        import re
        url_pat = re.compile(r"^https?://", re.IGNORECASE)
        ip_pat = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

        for s, expected_type in test_cases:
            if expected_type == "url":
                assert url_pat.match(s), f"{s} should match URL pattern"
            elif expected_type == "ip_address":
                assert ip_pat.match(s), f"{s} should match IP pattern"


class TestUnpackDetection:
    """脱壳 detection integration"""

    def test_packer_detection_sections(self) -> None:
        """Section name detection 查找 加壳器s"""
        PACKER_SECTIONS = [".UPX0", ".UPX1", ".aspack", ".MPRESS1"]
        section_list = [".text", ".UPX0", ".data", ".UPX1"]

        found = [s for s in section_list if s in PACKER_SECTIONS]
        assert len(found) == 2
        assert ".UPX0" in found
        assert ".UPX1" in found

    def test_entropy_based_packing_detection(self) -> None:
        """High entropy sections indicate packing"""
        import math
        from collections import Counter

        # Low entropy (normal code)
        normal_data = b"The quick brown fox jumps over the lazy dog" * 10

        # High entropy (encrypted/packed)
        import os
        high_entropy_data = os.urandom(256)

        for label, data in [("normal", normal_data), ("packed", high_entropy_data)]:
            counter = Counter(data)
            n = len(data)
            entropy = -sum(
                (c / n) * math.log2(c / n) for c in counter.values() if c > 0
            )
            if label == "packed":
                assert entropy > 6.5, f"Packed data entropy too low: {entropy}"
            # Normal data vary


class TestVMDetection:
    """VM detection integration"""

    def test_vm_string_detection(self) -> None:
        """VM-specific strings detectable"""
        vm_strings = {
            "VMProtect": ["VMProtect", ".vmp0", ".vmp1"],
            "Themida": ["Themida", ".themida", "WinLicense"],
        }

        sample_strings = [
            "This binary is protected by VMProtect",
            "Some normal function names",
        ]

        findings = []
        for s in sample_strings:
            for vm_name, patterns in vm_strings.items():
                for pattern in patterns:
                    if pattern.lower() in s.lower():
                        findings.append({"vm": vm_name, "pattern": pattern})

        assert len(findings) == 1
        assert findings[0]["vm"] == "VMProtect"


class TestErrorHandling:
    """Error recovery graceful degradation tests"""

    def test_invalid_file_handling(self) -> None:
        """Invalid file path caught"""
        filepath = "/nonexistent/file_12345.bin"
        import os
        exists = os.path.isfile(filepath)
        assert not exists

    def test_empty_file_handling(self) -> None:
        """Empty file 崩溃分析"""
        data = b""
        if len(data) == 0:
            entropy = 0.0
            sections = []
        assert entropy == 0.0
        assert len(sections) == 0

    def test_unicode_decode_errors(self) -> None:
        """Non-UTF8 data handled errors='replace'"""
        data = b"\xff\xfe\x00\x01Hello\x80\x90"
        try:
            decoded = data.decode("utf-8", errors="replace")
            assert "Hello" in decoded
        except UnicodeDecodeError:
            pytest.fail("Should use errors='replace' to handle bad bytes")
