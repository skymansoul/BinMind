# 隐写检测器单元测试集
import pytest
import sys, os, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.steganography_detector import (
    SteganographyDetector, StegoFinding, MAGIC_DB,
    detect_overlay_data, detect_section_gaps,
    detect_embedded_archives, scan_high_entropy_regions,
    detect_eof_gaps, detect_lsb_stego, detect_bmp_lsb,
)
from src.utils import shannon_entropy

Z = bytes(1)


def make_minimal_pe(overlay_size=512):
    # DOS头: MZ + 0x3C填充 (总计64字节，e_lfanew位于偏移0x3C=60)
    dos = bytearray(64)
    dos[0:2] = b'MZ'
    pe_offset = 0x80
    struct.pack_into('<I', dos, 0x3C, pe_offset)
    # 补齐DOS存根至pe_offset
    dos_stub = Z * (pe_offset - 64)
    dos = bytes(dos) + dos_stub

    # PE签名 + COFF头 (24字节)
    coff = b'PE' + Z * 2  # 签名 (4字节)
    coff += struct.pack('<H', 0x8664)  # 目标架构
    coff += struct.pack('<H', 3)       # 节数量
    coff += Z * 16                     # COFF剩余字段

    num_sections = 3
    section_headers_size = num_sections * 40

    # PE32+可选头: 88字节 (magic 2 + 剩余86)
    # SizeOfImage在可选头偏移56处 (0x10B PE32:偏移56; 0x20B PE32+:偏移72)
    size_of_image = pe_offset + 24 + 88 + section_headers_size
    opt_real = struct.pack('<H', 0x20B)  # PE32+魔数
    opt_real += Z * 70                   # 跳至SizeOfImage (总偏移 = 2+70=72)
    opt_real += struct.pack('<I', size_of_image)
    opt_real += Z * 12                   # 补齐至88字节

    # 节表头 (3×40=120字节)
    sections = Z * 120

    # 文件体至SizeOfImage
    file_body = dos + coff + opt_real + sections

    # 覆盖区
    import random
    rng = random.Random(42)
    overlay = bytes(rng.randint(1, 255) for _ in range(overlay_size))

    return file_body + overlay, size_of_image


class TestShannonEntropy:
    def test_entropy_uniform(self):
        import random
        rng = random.Random(42)
        data = bytes(rng.randint(0, 255) for _ in range(10000))
        ent = shannon_entropy(data)
        assert ent > 0.98

    def test_entropy_zero(self):
        assert shannon_entropy(bytes(1000)) == 0.0

    def test_entropy_empty(self):
        assert shannon_entropy(b'') == 0.0


class TestPEMinimal:
    def test_not_pe(self):
        assert detect_overlay_data(Z * 100) is None

    def test_mz_but_no_pe_signature(self):
        data = b'MZ' + Z * 0x7C + b'NOTPE'
        assert detect_overlay_data(data) is None


class TestPEOverlayDetection:
    def test_overlay_detected(self):
        pe_data, soi = make_minimal_pe(overlay_size=512)
        result = detect_overlay_data(pe_data)
        assert result is not None
        assert result.format == 'PE_overlay'
        assert result.offset == soi
        assert result.confidence >= 0.5

    def test_no_overlay_returns_none(self):
        pe_data, soi = make_minimal_pe(overlay_size=0)
        result = detect_overlay_data(pe_data)
        assert result is None

    def test_overlay_confidence_entropy_correlation(self):
        pe1, soi1 = make_minimal_pe(overlay_size=512)
        file_body1 = pe1[:soi1]
        zero_overlay = Z * 512
        pe2 = file_body1 + zero_overlay
        r1 = detect_overlay_data(pe1)
        r2 = detect_overlay_data(pe2)
        assert r1 is not None and r2 is not None
        assert r1.confidence > r2.confidence


class TestMAGICDB:
    def test_magic_db_not_empty(self):
        assert len(MAGIC_DB) > 20

    def test_zip_magic_in_db(self):
        zip_magic = b'PK\x03\x04'
        found = any(entry[0] == zip_magic for entry in MAGIC_DB)
        assert found

    def test_png_magic_in_db(self):
        from src.steganography_detector import MAGIC_DB
        png_entry = [e for e in MAGIC_DB if e[1] == 'PNG']
        assert len(png_entry) == 1


class TestEmbeddedArchiveDetection:
    def test_zip_embedded(self):
        zip_data = b'PK\x03\x04' + Z * 100
        data = Z * 50 + zip_data + Z * 50
        results = detect_embedded_archives(data)
        assert len(results) >= 1
        assert results[0].format == 'embedded_ZIP'

    def test_no_archive_in_clean_data(self):
        data = b'\xAB' * 10000
        results = detect_embedded_archives(data)
        assert len(results) == 0


class TestHighEntropyRegions:
    def test_high_entropy_region_detected(self):
        import random
        rng = random.Random(42)
        # 生成更大随机块以稳定熵检测
        high_ent = bytes(rng.randint(0, 255) for _ in range(8192))
        data = Z * 1024 + high_ent + Z * 1024
        results = scan_high_entropy_regions(data)
        assert len(results) >= 1
        for r in results:
            assert r.format == 'high_entropy'
            assert r.confidence > 0.92

    def test_low_entropy_no_findings(self):
        data = b'\x41' * 10000
        results = scan_high_entropy_regions(data)
        assert len(results) == 0


class TestSteganographyDetectorIntegration:
    def test_run_all_aggregates(self):
        import random
        rng = random.Random(99)
        zip_magic = b'PK\x03\x04'
        high_ent = bytes(rng.randint(0, 255) for _ in range(4096))
        data = Z * 200 + zip_magic + Z * 200 + high_ent + Z * 500
        det = SteganographyDetector(data)
        findings = det.run_all()
        assert len(findings) >= 2
        for i in range(len(findings) - 1):
            assert findings[i].confidence >= findings[i + 1].confidence
