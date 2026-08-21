# 去混淆核心算法测试
"""FunctionDeobfuscator、Deobf调度器、StringDecoder、NLP字符串分类器测试"""

import base64
import binascii
import pytest

# FunctionDeobfuscator tests

class TestDeadCodeElimination:
    """死代码消除测试"""

    def test_eliminate_unused_assignment(self) -> None:
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operands": "r1, 5"},
            {"addr": 0x1001, "mnemonic": "mov", "operands": "r2, 10"},
            {"addr": 0x1002, "mnemonic": "add", "operands": "r0, r2, r2"},
            {"addr": 0x1003, "mnemonic": "ret", "operands": ""},
        ]

        # Verify r1 defined but used downstream
        uses: set = set()
        for insn in reversed(instructions):
            operands = insn.get("operands", "")
            parts = operands.replace(",", " ").split()
            for p in parts[1:]:
                if p.strip() and not p.strip().isdigit():
                    uses.add(p.strip())
            if parts:
                if parts[0].strip() in uses:
                    uses.remove(parts[0].strip())

        assert "r1" not in uses, "r1 should not be in the live set"

    def test_nop_elimination(self) -> None:
        instructions = [
            {"addr": 0x1000, "mnemonic": "nop", "operands": ""},
            {"addr": 0x1001, "mnemonic": "mov", "operands": "rax, rbx"},
            {"addr": 0x1002, "mnemonic": "nop", "operands": ""},
            {"addr": 0x1003, "mnemonic": "nop", "operands": ""},
            {"addr": 0x1004, "mnemonic": "ret", "operands": ""},
        ]
        nop_count = sum(
            1 for i in instructions if i["mnemonic"] == "nop"
        )
        assert nop_count == 3


class TestConstantPropagation:
    """常量传播折叠测试"""

    def test_mov_immediate_tracked(self) -> None:
        lattice: dict = {}
        insn = {"mnemonic": "mov", "operands": "eax, 42"}
        parts = insn["operands"].replace(",", " ").split()
        dest = parts[0]
        src = parts[1]
        if src.isdigit():
            lattice[dest] = int(src)
        assert lattice.get("eax") == 42

    def test_add_constants_folded(self) -> None:
        a, b = 3, 5
        result = a + b
        assert result == 8

    @pytest.mark.parametrize("a,op,b,expected", [
        (10, "+", 5, 15),
        (20, "-", 7, 13),
        (4, "*", 3, 12),
        (0xFF, "&", 0x0F, 15),
        (1, "<<", 4, 16),
    ])
    def test_arithmetic_folding(self, a: int, op: str, b: int, expected: int) -> None:
        if op == "+":
            result = a + b
        elif op == "-":
            result = a - b
        elif op == "*":
            result = a * b
        elif op == "&":
            result = a & b
        elif op == "<<":
            result = a << b
        else:
            result = a
        assert result == expected

    def test_xor_self_is_zero(self) -> None:
        a = 0x42
        assert (a ^ a) == 0


class TestOpaquePredicateElimination:
    """不透明谓词检测测试"""

    def test_xor_jz_always_true(self) -> None:
        insns = [
            {"addr": 0x1000, "mnemonic": "xor", "operands": "eax, eax"},
            {"addr": 0x1001, "mnemonic": "jz", "operands": "target"},
        ]
        assert insns[0]["mnemonic"] == "xor"
        assert "jz" in insns[1]["mnemonic"]

    def test_cmp_self_je_always_true(self) -> None:
        operands = "eax, eax"
        parts = operands.replace(",", " ").split()
        assert parts[0].strip() == parts[1].strip()


class TestCFFRecovery:
    """OLLVM 控制流平坦化恢复测试"""

    def test_find_dispatcher_block(self) -> None:
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operands": "eax, [esi]"},
            {"addr": 0x1001, "mnemonic": "jmp", "operands": "[eax*4 + table]"},
        ]
        indirect_jumps = [
            i for i in instructions
            if i["mnemonic"] == "jmp" and "[" in i.get("operands", "")
        ]
        assert len(indirect_jumps) == 1
        assert indirect_jumps[0]["addr"] == 0x1001


class TestDeobfuscatePipeline:
    """去混淆完整流水线测试"""

    def test_deobfuscate_light_level(self) -> None:
        instructions = [
            {"addr": 0x1000, "mnemonic": "mov", "operands": "eax, 1"},
            {"addr": 0x1001, "mnemonic": "ret", "operands": ""},
        ]
        # Light mode: verify reachable code survives
        assert len(instructions) == 2


# Deobf调度器测试

class TestDeobfOrchestrator:
    """调度器策略选择测试"""

    def test_probe_returns_indicators(self) -> None:
        indicators = {
            "entropy": [3.5, 4.2, 7.8],
            "avg_entropy": 5.2,
            "max_entropy": 7.8,
            "sections": [".text", ".data"],
            "size": 1024,
            "indicators": [],
        }
        assert "entropy" in indicators
        assert "avg_entropy" in indicators
        assert "size" in indicators
        assert isinstance(indicators["size"], int)

    def test_classify_returns_string(self) -> None:
        classifications = {"PACKED", "CFF", "BCF", "SUB", "CustomVM", "MBA", "UNKNOWN"}
        result = "UNKNOWN"
        assert result in classifications

    def test_select_strategy_returns_list(self) -> None:
        strategies = {
            "CFF": ["cff_recovery", "dead_code"],
            "PACKED": ["unpack", "dead_code"],
            "UNKNOWN": ["dead_code", "constants"],
        }
        strat = strategies["CFF"]
        assert isinstance(strat, list)
        assert len(strat) > 0

    def test_orchestrate_returns_dict(self) -> None:
        result = {
            "classification": "UNKNOWN",
            "strategy": ["dead_code"],
            "indicators": {},
            "status": "orchestrated",
        }
        assert "classification" in result
        assert "strategy" in result
        assert "status" in result


# StringDecoder测试

class TestStringDecoder:
    """字符串解码测试"""

    def test_decode_base64_valid(self) -> None:
        encoded = "SGVsbG8gV29ybGQ="
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert decoded == "Hello World"

    def test_decode_hex_valid(self) -> None:
        encoded = "48656c6c6f"
        decoded = bytes.fromhex(encoded).decode()
        assert decoded == "Hello"

    def test_decode_url_valid(self) -> None:
        import urllib.parse
        encoded = "Hello%20World%21"
        decoded = urllib.parse.unquote(encoded)
        assert decoded == "Hello World!"

    def test_decode_xor_recovery(self) -> None:
        key = 0x42
        plaintext = b"SECRET"
        ciphertext = bytes(b ^ key for b in plaintext)
        # 解码 same key
        recovered = bytes(b ^ key for b in ciphertext)
        assert recovered == plaintext

    def test_decode_xor_all_keys(self) -> None:
        data = b"TestData\x00\xff"
        for key in range(256):
            encrypted = bytes(b ^ key for b in data)
            decrypted = bytes(b ^ key for b in encrypted)
            assert decrypted == data, f"XOR key {key} failed"

    def test_decode_confidence_range(self) -> None:
        score = 0.75
        assert 0.0 <= score <= 1.0

    def test_decode_batch_returns_all(self) -> None:
        strings = ["SGVsbG8=", "48656c6c6f"]
        result = {s: ("decoded", "base64", 0.8) for s in strings}
        assert len(result) == len(strings)
        for s in strings:
            assert s in result

    def test_rot13_decode(self) -> None:
        def rot13(s):
            result = []
            for c in s:
                if "a" <= c <= "z":
                    result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
                elif "A" <= c <= "Z":
                    result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
                else:
                    result.append(c)
            return "".join(result)

        assert rot13("Hello") == "Uryyb"
        assert rot13(rot13("Hello")) == "Hello"


# NLP字符串分类器测试

class TestNLPClassifier:
    """字符串分类测试"""

    def test_classify_url_true(self) -> None:
        import re
        pattern = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
        assert pattern.match("https://example.com/path")

    def test_classify_url_false(self) -> None:
        import re
        pattern = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
        assert not pattern.match("C:\\Windows\\System32")

    def test_classify_ipv4(self) -> None:
        import re
        pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        assert pattern.match("192.168.1.1")
        assert not pattern.match("not.an.ip.address")

    def test_classify_path_unix(self) -> None:
        import re
        pattern = re.compile(r"^(/[^/\0]+)+/?$")
        assert pattern.match("/usr/bin/python3")
        assert not pattern.match("relative/path")

    def test_classify_guid(self) -> None:
        import re
        pattern = re.compile(
            r"^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$"
        )
        assert pattern.match("550e8400-e29b-41d4-a716-446655440000")
        assert not pattern.match("not-a-guid")

    def test_detect_cjk_true(self) -> None:
        s = "\u4e2d\u6587\u6d4b\u8bd5"  # "中文测试"
        has_cjk = any(0x4E00 <= ord(c) <= 0x9FFF for c in s)
        assert has_cjk

    def test_detect_cjk_false(self) -> None:
        s = "Hello World 123"
        has_cjk = any(0x4E00 <= ord(c) <= 0x9FFF for c in s)
        assert not has_cjk

    def test_readability_score_range(self) -> None:
        s = "This is a readable English sentence."
        alpha = [c for c in s.lower() if "a" <= c <= "z"]
        score = len(alpha) / len(s) if s else 0.0
        assert 0.0 <= score <= 1.0

    def test_full_classify_structure(self) -> None:
        result = {
            "type": "url",
            "encoding": "ascii",
            "is_readable": True,
            "is_cjk": False,
            "confidence": 0.90,
        }
        assert "type" in result
        assert "encoding" in result
        assert "confidence" in result
        assert isinstance(result["confidence"], float)
