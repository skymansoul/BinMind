# 2026-08-02
# 壳/保护器检测 — 多特征融合的静态识别
# 参考: GUARD (Hwang et al., ACM SAC 2025) — 壳检测与模拟执行结合的 API 反混淆
# 参考: VMPredator (Kim et al., arXiv:2605.30902, May 2026) —
#       VMProtect/ Themida 等商业化混淆器的识别与自动解包
# 参考: DeepVMUnProtect (IEEE TIFS 2025) — 神经网络在 VM 保护壳识别中的应用

import struct as _struct
import math as _math

# ===== 壳特征签名库 =====
# 基于入口点字节模式、节名特征、导入表稀疏度的多维度检测
# 每条签名: {name, ep_bytes, section_pattern, import_count_threshold, entropy_threshold}

_PACKER_SIGNATURES: list[dict] = [
    {
        'name': 'UPX',
        'version_hint': '0.8x-4.x',
        'ep_pattern': [b'\x60', b'\xbe', b'\x8d\xbe', b'\x57'],
        'section_names': ['UPX0', 'UPX1', '.upx'],
        'min_imports': 1, 'max_imports': 10,
        'entropy_high_sections': 1,  # 至少一节高熵
    },
    {
        'name': 'ASPack',
        'version_hint': '2.x',
        'ep_pattern': [b'\x60', b'\xe8\x00\x00\x00\x00', b'\x5d'],
        'section_names': ['.aspack', '.adata'],
        'min_imports': 1, 'max_imports': 5,
        'entropy_high_sections': 0,
    },
    {
        'name': 'Themida',
        'version_hint': '2.x-3.x',
        'ep_pattern': [b'\xb8\x00\x00\x00\x00', b'\xe8'],
        'section_names': ['.themida', '.tsu', '.tata'],
        'min_imports': 0, 'max_imports': 3,
        'entropy_high_sections': 2,
    },
    {
        'name': 'VMProtect',
        'version_hint': '2.x-3.x',
        'ep_pattern': [b'\x50', b'\x51', b'\x52', b'\xe8'],
        'section_names': ['.vmp', '.vmp0', '.vmp1', '.text0', '.text1'],
        'min_imports': 0, 'max_imports': 5,
        'entropy_high_sections': 1,
    },
    {
        'name': 'Obsidium',
        'version_hint': '1.x',
        'ep_pattern': [b'\xe8', b'\x50', b'\x8b\xc4'],
        'section_names': ['.obs', '.obsc'],
        'min_imports': 1, 'max_imports': 3,
        'entropy_high_sections': 1,
    },
    {
        'name': 'Enigma',
        'version_hint': '1.x-5.x',
        'ep_pattern': [b'\x60', b'\xe8'],
        'section_names': ['.enigma', '.enigm'],
        'min_imports': 0, 'max_imports': 3,
        'entropy_high_sections': 1,
    },
    {
        'name': 'PECompact',
        'version_hint': '2.x-3.x',
        'ep_pattern': [b'\x55', b'\x8b\xec', b'\x83\xc4'],
        'section_names': ['.pec', '.pec1', '.pec2'],
        'min_imports': 1, 'max_imports': 10,
        'entropy_high_sections': 1,
    },
    {
        'name': 'MPRESS',
        'version_hint': '2.x',
        'ep_pattern': [b'\x60', b'\xe8'],
        'section_names': ['.mpr', '.MPRESS1', '.MPRESS2'],
        'min_imports': 1, 'max_imports': 2,
        'entropy_high_sections': 1,
    },
    {
        'name': 'NSIS',
        'version_hint': 'modern',
        'ep_pattern': [b'\x55', b'\x8b\xec', b'\x6a\xff'],
        'section_names': ['.ndata', '.rdata'],
        'min_imports': 3, 'max_imports': 20,
        'entropy_high_sections': 0,
    },
]


# ===== 检测引擎 =====
class PackerDetector:
    """多策略壳检测器。
    策略矩阵:
    1. 入口点字节码匹配 — 最可靠
    2. 节名模式匹配 — 壳特化节命名
    3. 导入表稀疏度 — 壳封装的 IAT 通常极小
    4. 分节熵分析 — 代码节高熵暗示加密/压缩
    5. 节名与标准名差异 — 非标准节名的数量"""

    def __init__(self):
        self._results: list[dict] = []

    def detect(self, pe_data: bytes) -> list[dict]:
        # 全维度 PE 壳检测 — 返回按置信度降序排列的匹配列表
        if len(pe_data) < 64 or pe_data[:2] != b'MZ':
            return [{'packer': 'not_a_valid_pe', 'confidence': 0.0}]

        results = []

        # 提取 PE 特征
        sections = self._extract_sections(pe_data)
        imports = self._count_imports(pe_data)
        ep_offset = self._get_entry_point_offset(pe_data)
        ep_bytes = pe_data[ep_offset:ep_offset + 32] if ep_offset + 32 <= len(pe_data) else b''

        for sig in _PACKER_SIGNATURES:
            score = 0.0
            evidence = []

            # 1. EP 字节匹配 (权重 0.40)
            ep_score = self._match_ep_bytes(ep_bytes, sig.get('ep_pattern', []))
            score += ep_score * 0.40
            if ep_score > 0:
                evidence.append(f'ep_match={ep_score:.2f}')

            # 2. 节名匹配 (权重 0.25)
            section_match = sum(1 for sname in sections
                               if any(sig_name in sname.lower()
                                     for sig_name in sig.get('section_names', [])))
            s_score = min(section_match / max(len(sig.get('section_names', [])), 1), 1.0)
            score += s_score * 0.25
            if s_score > 0:
                evidence.append(f'sections={section_match}')

            # 3. 导入表稀疏度 (权重 0.15)
            min_imp = sig.get('min_imports', 0)
            max_imp = sig.get('max_imports', 100)
            if min_imp <= imports <= max_imp:
                score += 0.15
                evidence.append(f'imports={imports} (in [{min_imp},{max_imp}])')

            # 4. 高熵节 (权重 0.20)
            high_ent_count = self._count_high_entropy_sections(pe_data, sections)
            expected = sig.get('entropy_high_sections', 0)
            ent_score = min(high_ent_count / max(expected, 1), 2.0) * 0.5 if expected > 0 else 0.20
            score += ent_score if expected > 0 else (0.20 if high_ent_count == 0 else 0.0)
            if high_ent_count > 0:
                evidence.append(f'high_entropy_sections={high_ent_count}')

            results.append({
                'packer': sig['name'],
                'version_hint': sig.get('version_hint', ''),
                'confidence': round(score, 2),
                'evidence': evidence,
            })

        results.sort(key=lambda r: -r['confidence'])
        # 截断到前 5 个
        top = [r for r in results[:5] if r['confidence'] > 0.1]
        if not top:
            top.append({'packer': 'none_or_unknown', 'confidence': 0.5,
                       'evidence': ['no signature matched']})
        return top

    # ---- 辅助方法 ----
    @staticmethod
    def _extract_sections(pe_data: bytes) -> list[str]:
        sections = []
        pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
        num_sec = _struct.unpack_from('<H', pe_data, pe_off + 6)[0]
        opt_hdr_size = _struct.unpack_from('<H', pe_data, pe_off + 20)[0]
        sec_hdr_off = pe_off + 24 + opt_hdr_size
        for i in range(num_sec):
            name_off = sec_hdr_off + i * 40
            if name_off + 8 <= len(pe_data):
                name = pe_data[name_off:name_off + 8].rstrip(b'\x00').decode('ascii', errors='replace')
                if name:
                    sections.append(name)
        return sections

    @staticmethod
    def _count_imports(pe_data: bytes) -> int:
        pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
        opt_hdr_off = pe_off + 24
        if opt_hdr_off + 112 > len(pe_data):
            return 0
        # DataDirectory[1] = Import Table
        import_rva = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 8)[0]
        import_size = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 12)[0]
        if import_size == 0:
            return 0
        # 粗略计数 — IAT 描述符大小为 20 字节
        return import_size // 20

    @staticmethod
    def _get_entry_point_offset(pe_data: bytes) -> int:
        pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
        opt_hdr_off = pe_off + 24
        ep_rva = _struct.unpack_from('<I', pe_data, opt_hdr_off + 16)[0]
        # RVA → offset (简化: 假设 .text 节含 EP)
        return ep_rva

    @staticmethod
    def _match_ep_bytes(actual: bytes, patterns: list[bytes]) -> float:
        """逐一比对入口点字节与签名模式。
        返回匹配模式的比例 — 而非连续匹配的长度。"""
        if not patterns or len(actual) == 0:
            return 0.0
        matched = 0
        for pat in patterns:
            if actual[:len(pat)] == pat:
                matched += 1
        return matched / len(patterns)

    @staticmethod
    def _count_high_entropy_sections(pe_data: bytes, section_names: list[str]) -> int:
        """统计熵 > 7.0 的节数量。
        高熵节的字节分布接近均匀 — 加密代码或压缩数据的特征。"""
        high_count = 0
        # 简化: 对整个文件做分块熵分析
        chunk_size = 4096
        for i in range(0, len(pe_data), chunk_size):
            chunk = pe_data[i:i + chunk_size]
            if len(chunk) < 256:
                continue
            freq = [0] * 256
            for b in chunk:
                freq[b] += 1
            ent = -sum((f / len(chunk)) * _math.log2(f / len(chunk))
                      for f in freq if f > 0)
            if ent > 7.0:
                high_count += 1
        return min(high_count, len(section_names)) if section_names else high_count


# ===== 全局熵分析 =====
def shannon_entropy(data: bytes) -> float:
    """字节级香农熵。值域 [0, 8] — 8 为完全均匀分布。
    此函数在 packer_detect 和 spectral_entropy 中均有引用。"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((f / n) * _math.log2(f / n) for f in freq if f > 0)


# ===== 导入表完整性评估 =====
# 壳常破坏或混淆 IAT — 导入函数数极少是典型信号
# 参考: GUARD 的 sIAT (scattered Import Address Table) 检测算法

def assess_iat_integrity(pe_data: bytes) -> dict:
    """评估 PE 导入表的完整性。
    正常程序的导入表 DLL 数 ≥ 2，函数数 ≥ 20；
    壳封装的可执行文件导入表通常仅 0-3 个函数 (GetProcAddress + LoadLibrary)。"""
    import_count = PackerDetector._count_imports(pe_data)
    dll_count = _estimate_dll_count(pe_data)

    if import_count <= 3:
        integrity = 'heavily_packed'  # 仅 kernel32!GetProcAddress + LoadLibrary
    elif import_count <= 10:
        integrity = 'likely_packed'
    elif import_count <= 50:
        integrity = 'possibly_packed_or_small'
    else:
        integrity = 'normal'

    return {
        'import_count_estimate': import_count,
        'dll_count_estimate': dll_count,
        'integrity': integrity,
        'heuristic': 'packed_binaries_typically_have_≤3_imports',
    }


def _estimate_dll_count(pe_data: bytes) -> int:
    """估算导入的 DLL 数量（从 .idata 节或导入目录）。"""
    pe_off = _struct.unpack_from('<I', pe_data, 0x3c)[0]
    opt_hdr_off = pe_off + 24
    import_rva = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 8)[0]
    import_size = _struct.unpack_from('<I', pe_data, opt_hdr_off + 64 + 12)[0]
    if import_size < 20:
        return 0
    # 每个 IMAGE_IMPORT_DESCRIPTOR 的长度是 20 字节
    # 以 null descriptor 结尾 (全零)
    count = 0
    descriptor_count = import_size // 20
    for i in range(descriptor_count):
        off = import_rva + i * 20
        if off + 20 <= len(pe_data):
            desc = pe_data[off:off + 20]
            if desc == b'\x00' * 20:
                break
            count += 1
    return count


# --- 多层壳检测 (嵌套壳) ---
# 商业保护方案常使用多层壳 — Themida + VMProtect 或自定义壳 + UPX 外层
# 参考: VMPredator 的三锚点检测法 — VM entry / exit / handler

def detect_nested_packer(pe_data: bytes) -> list[str]:
    """检测可能存在的嵌套壳。
    对同一 PE 文件递归执行检测: 外层 → 剥壳 → 内层，直至无壳。
    此函数仅执行首轮检测，剥壳由上游负责。"""
    detector = PackerDetector()
    results = detector.detect(pe_data)
    # 若多个壳签名置信度均 > 0.3，可能为嵌套
    nested_candidates = [r for r in results if r['confidence'] >= 0.3]
    return [r['packer'] for r in nested_candidates]
