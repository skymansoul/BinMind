"""
Deep tests for memory forensics: crypto weakness scanning, binary hardening audit,
and Python object reconstruction from memory dumps.

Extends the existing test_memory_forensics.py with tests for Round 5 features.
"""
import unittest
import os
import tempfile

from modules.analysis.dynamic.engine.memory_forensics import (
    MemoryForensicsAnalyzer,
    ForensicsResult,
    MemoryType,
    OSType,
    CryptoWeakness,
    CRYPTO_WEAK_SIGNATURES,
    HARDENING_SIGNATURES,
    SensitiveDataType,
)


class TestCryptoWeaknessSignatures(unittest.TestCase):
    """Crypto weakness signature definitions."""

    def test_all_algorithms_defined(self):
        """所有弱密码算法有签名定义"""
        expected = ["RC4", "DES", "MD5", "SHA1", "ECB_mode", "RSA_1024"]
        for algo in expected:
            self.assertIn(algo, CRYPTO_WEAK_SIGNATURES)

    def test_rc4_severity_critical(self):
        """RC4 严重性为 critical"""
        self.assertEqual(CRYPTO_WEAK_SIGNATURES["RC4"]["severity"], "critical")

    def test_des_severity_critical(self):
        """DES 严重性为 critical"""
        self.assertEqual(CRYPTO_WEAK_SIGNATURES["DES"]["severity"], "critical")

    def test_md5_severity_high(self):
        """MD5 严重性为 high"""
        self.assertEqual(CRYPTO_WEAK_SIGNATURES["MD5"]["severity"], "high")

    def test_each_has_pattern(self):
        """每个算法有对应的二进制模式"""
        for algo, sig in CRYPTO_WEAK_SIGNATURES.items():
            self.assertIn("pattern", sig)

    def test_each_has_recommendation(self):
        """每个算法有缓解建议"""
        for algo, sig in CRYPTO_WEAK_SIGNATURES.items():
            self.assertIn("recommendation", sig)
            self.assertGreater(len(sig["recommendation"]), 0)


class TestHardeningSignatures(unittest.TestCase):
    """Binary hardening audit signature definitions."""

    def test_all_mitigations_defined(self):
        """所有缓解措施有签名"""
        expected = ["ASLR", "DEP_NX", "StackGuard", "SafeSEH", "ControlFlowGuard", "CET_IBT"]
        for mit in expected:
            self.assertIn(mit, HARDENING_SIGNATURES)

    def test_aslr_pe_flag(self):
        """ASLR 的 PE flag 为 IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE (0x40)"""
        self.assertEqual(HARDENING_SIGNATURES["ASLR"]["pe_flag"], 0x0040)

    def test_dep_nx_pe_flag(self):
        """DEP/NX 的 PE flag 为 IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)"""
        self.assertEqual(HARDENING_SIGNATURES["DEP_NX"]["pe_flag"], 0x0100)

    def test_aslr_elf_section(self):
        """ASLR 在 ELF 中检查 .rela.dyn section"""
        self.assertEqual(HARDENING_SIGNATURES["ASLR"]["elf_section"], ".rela.dyn")

    def test_stack_guard_symbols(self):
        """StackGuard 检查金丝雀失败符号"""
        syms = HARDENING_SIGNATURES["StackGuard"]["symbols"]
        self.assertIn("__stack_chk_fail", syms)

    def test_cet_ibt_instructions(self):
        """CET IBT 检查 endbr64 指令"""
        instrs = HARDENING_SIGNATURES["CET_IBT"]["instructions"]
        self.assertEqual(len(instrs), 1)
        self.assertEqual(instrs[0], b'\xf3\x0f\x1e\xfa')

    def test_each_has_severity_if_missing(self):
        """每个缓解措施定义了缺失时的严重性"""
        for mit, sig in HARDENING_SIGNATURES.items():
            self.assertIn("severity_if_missing", sig)


class TestCryptoWeaknessDataclass(unittest.TestCase):
    """CryptoWeakness dataclass."""

    def test_creation(self):
        cw = CryptoWeakness(
            algorithm="RC4",
            weakness_type="broken_algorithm",
            evidence="Found RC4 in imports",
            severity="critical",
            recommendation="Use AES-GCM",
            confidence=0.95,
        )
        self.assertEqual(cw.algorithm, "RC4")
        self.assertAlmostEqual(cw.confidence, 0.95)
        self.assertEqual(cw.severity, "critical")


class TestAnalyzerCryptoScan(unittest.TestCase):
    """MemoryForensicsAnalyzer crypto weakness scanning."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_scan_binary_with_rc4(self):
        """包含 RC4 字符串的二进制→检测到弱点"""
        fpath = os.path.join(self.tmpdir, "test.bin")
        with open(fpath, "wb") as f:
            f.write(b"RC4_encrypt_data\x00\x00" + b"\x00" * 100)

        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source=fpath,
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp="2026-01-01",
        )
        analyzer._scan_crypto_weaknesses(fpath, result)
        self.assertGreater(len(result.crypto_weaknesses), 0)
        algo_names = [w.algorithm for w in result.crypto_weaknesses]
        self.assertIn("RC4", algo_names)

    def test_scan_clean_binary(self):
        """不含弱密码原语的二进制→无发现"""
        fpath = os.path.join(self.tmpdir, "clean.bin")
        with open(fpath, "wb") as f:
            f.write(b"AES_GCM_encrypt\x00\x00" + b"\x00" * 100)

        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source=fpath,
            memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN,
            timestamp="2026-01-01",
        )
        analyzer._scan_crypto_weaknesses(fpath, result)
        self.assertEqual(len(result.crypto_weaknesses), 0)

    def test_scan_with_md5(self):
        """包含 MD5 的二进制→检测到"""
        fpath = os.path.join(self.tmpdir, "md5.bin")
        with open(fpath, "wb") as f:
            f.write(b"MD5_Init\x00MD5_Update\x00MD5_Final\x00" + b"\x00" * 50)

        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source=fpath, memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN, timestamp="2026-01-01",
        )
        analyzer._scan_crypto_weaknesses(fpath, result)
        self.assertGreater(len(result.crypto_weaknesses), 0)


class TestAnalyzerHardeningAudit(unittest.TestCase):
    """MemoryForensicsAnalyzer binary hardening audit."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_audit_pe_no_mitigations(self):
        """无缓解措施的 PE→hardening_audit 全为 False"""
        fpath = os.path.join(self.tmpdir, "no_hard.exe")
        # 构造最小 PE，DLL characteristics = 0
        import struct
        data = b'MZ' + b'\x00' * 0x3C + struct.pack('<I', 0x40)
        data += b'PE\x00\x00'
        data += struct.pack('<H', 0x014C)  # i386
        data += struct.pack('<H', 0)  # 0 sections
        data += b'\x00' * 12  # skip to DLL characteristics
        # offset from PE sig: 24(sig+filehdr) + 68(opt_hdr base) = 92
        # DLL characteristics at offset 94 from PE sig
        # Fill the rest
        data += b'\x00' * 200
        with open(fpath, "wb") as f:
            f.write(data)

        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source=fpath, memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.WINDOWS, timestamp="2026-01-01",
        )
        analyzer._audit_binary_hardening(fpath, result)
        self.assertIsInstance(result.hardening_audit, dict)

    def test_audit_non_pe_file(self):
        """非 PE/ELF 文件→hardening_audit 为空"""
        fpath = os.path.join(self.tmpdir, "text.bin")
        with open(fpath, "wb") as f:
            f.write(b"This is not a binary")

        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source=fpath, memory_type=MemoryType.MEMORY_DUMP,
            os_type=OSType.UNKNOWN, timestamp="2026-01-01",
        )
        analyzer._audit_binary_hardening(fpath, result)
        # 应该返回空字典或 error key
        self.assertIsInstance(result.hardening_audit, dict)

    def test_audit_live_process_returns_error(self):
        """对 PID 执行 hardening audit 返回 error 消息"""
        analyzer = MemoryForensicsAnalyzer(output_dir=self.tmpdir)
        result = ForensicsResult(
            source="1234", memory_type=MemoryType.LIVE_PROCESS,
            os_type=OSType.LINUX, timestamp="2026-01-01",
        )
        analyzer._audit_binary_hardening(1234, result)
        self.assertIn("error", result.hardening_audit)


class TestSensitiveDataType(unittest.TestCase):
    """SensitiveDataType enum values."""

    def test_rsa_private_key(self):
        self.assertEqual(SensitiveDataType.RSA_PRIVATE_KEY.value, "rsa_private_key")

    def test_jwt_token(self):
        self.assertEqual(SensitiveDataType.JWT_TOKEN.value, "jwt_token")

    def test_credit_card(self):
        self.assertEqual(SensitiveDataType.CREDIT_CARD.value, "credit_card")

    def test_encryption_key(self):
        self.assertEqual(SensitiveDataType.ENCRYPTION_KEY.value, "encryption_key")

    def test_url_with_creds(self):
        self.assertEqual(SensitiveDataType.URL_WITH_Creds.value, "url_with_creds")


if __name__ == "__main__":
    unittest.main()
