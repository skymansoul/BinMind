# 二进制熵分析器-通过信息熵与统计特征检测加壳/混淆/加密段。
# Applied Network Science图基混淆检测及传统PEiD熵检测方法。
#
# 检测维度:
# 整体熵: Shannon熵 > 7.0暗示加密/压缩（正常代码~5.0-6.5）
# 分段熵: 按section/segment分别计算，高熵.text段异常
# 字节分布: chi-square检验观测分布与均匀分布的距离
# N-gram重复率: 重复模式密度高-加壳器存根可能性
# 可打印字符比: < 10%暗示二进制payload段
#
# 当前实现-Shannon熵+分段分析
# 增强-chi-square检验与ML分类器集成（sklearn可选）

import os, math, struct, logging, json
from typing import Dict, List, Optional, Any, Tuple
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PackingStatus(str, Enum):
    NOT_PACKED = "not_packed"
    LIKELY_PACKED = "likely_packed"
    PACKED = "packed"
    ENCRYPTED = "encrypted"
    OBFUSCATED = "obfuscated"


class SectionType(str, Enum):
    CODE = "code"
    DATA = "data"
    RODATA = "rodata"
    BSS = "bss"
    UNKNOWN = "unknown"


@dataclass
class SectionEntropy:
    """单段/节熵分析结果"""
    name: str
    section_type: SectionType
    offset: int = 0
    size: int = 0
    shannon_entropy: float = 0.0
    chi_square: float = 0.0
    printable_ratio: float = 0.0
    null_byte_ratio: float = 0.0
    avg_byte_value: float = 0.0
    anomaly_flags: List[str] = field(default_factory=list)


@dataclass
class EntropyReport:
    """完整熵分析报告"""
    file_path: str
    file_size: int = 0
    overall_entropy: float = 0.0
    overall_chi_square: float = 0.0
    packing_status: PackingStatus = PackingStatus.NOT_PACKED
    confidence: float = 0.0
    sections: List[SectionEntropy] = field(default_factory=list)
    anomaly_flags: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class BinaryEntropyAnalyzer:
    """二进制熵分析器-多维度信息熵检测。

    核心算法:
        1. Shannon熵: H = -Σ p_i * log2(p_i)，p_i为字节值i的概率
        2. Chi-square: χ² = Σ (o_i - e_i)² / e_i，衡量与均匀分布的偏离
        3. 分段分析: 固定窗口切分，检测熵的局部突变
        4. 启发式规则: 综合多指标判定加壳/混淆/加密状态

    Shannon熵阈值参考:
        < 5.0: 结构化数据/未压缩代码
        5.0–6.5: 典型编译代码（x86/x86_64）
        6.5–7.0: 可疑——轻量混淆或部分压缩
        > 7.0: 强加密或压缩数据段
        > 7.5: 几乎确定为加密/压缩payload
    """

    # 加壳器特征-常见加壳器节名与入口特征
    _PACKER_SIGNATURES = {
        'UPX': [b'UPX!', b'UPX0', b'UPX1'],
        'ASPack': [b'ASPack', b'.aspack'],
        'PECompact': [b'PE\x00Compact', b'PEC2'],
        'Themida': [b'Themida', b'WinLicense'],
        'VMProtect': [b'VMProtect', b'.vmp'],
        'Enigma': [b'Enigma'],
        'MPRESS': [b'MPRESS'],
    }

    def __init__(self, window_size: int = 256, slide_step: int = 128):
        self.window_sz = window_size
        self.slide_step = slide_step

    def analyze_file(self, file_path: str) -> EntropyReport:
        """完整分析一个二进制文件。

        返回EntropyReport。
        """
        if not os.path.exists(file_path):
            return EntropyReport(file_path=file_path,
                                  packing_status=PackingStatus.NOT_PACKED,
                                  anomaly_flags=['文件不存在'])

        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return EntropyReport(file_path=file_path,
                                  anomaly_flags=['文件读取失败'])

        report = self.analyze_bytes(data, file_path)
        return report

    def analyze_bytes(self, data: bytes, file_path: str = "") -> EntropyReport:
        """分析字节数据-不依赖文件系统。

        返回EntropyReport。
        """
        if not data:
            return EntropyReport(file_path=file_path, file_size=0)

        n = len(data)
        report = EntropyReport(file_path=file_path, file_size=n)

        # 1. 整体熵
        byte_counts = Counter(data)
        report.overall_entropy = self._shannon_entropy(byte_counts, n)

        # 2. Chi-square
        report.overall_chi_square = self._chi_square(byte_counts, n)

        # 3. 分段分析
        report.sections = self._section_analysis(data, n)

        # 4. 加壳器签名扫描
        packer_hits = self._scan_packer_signatures(data)
        if packer_hits:
            report.anomaly_flags.append(f'已知加壳器签名: {packer_hits}')

        # 5. 启发式判定
        report.packing_status, report.confidence = self._classify(report)
        report.recommendations = self._gen_recommendations(report)

        return report

    def _shannon_entropy(self, byte_counts: Counter, total: int) -> float:
        if total == 0:
            return 0.0
        ent = 0.0
        inv = 1.0 / total
        for cnt in byte_counts.values():
            p = cnt * inv
            if p > 0:
                ent -= p * math.log2(p)
        return round(ent, 3)

    def _chi_square(self, byte_counts, total):
        """Chi-square检验-衡量字节分布与均匀分布的偏离。

        自由度=255，均匀分布期望值=total/256。
        """
        if total == 0:
            return 0.0
        expected = total / 256.0
        chi2 = 0.0
        for b in range(256):
            observed = byte_counts.get(b, 0)
            diff = observed - expected
            chi2 += diff * diff / expected
        return round(chi2, 1)

    def _section_analysis(self, data, total_size):
        """滑动窗口分段分析-检测熵的局部突变。

        高熵窗口密集区域标识为可疑段。
        """
        sections = []
        if total_size < self.window_sz:
            return sections

        # 尝试解析ELF/PE节表
        sections = self._parse_sections_from_header(data)

        # 滑动窗口补充分析
        entropies = []
        for offset in range(0, total_size - self.window_sz, self.slide_step):
            window = data[offset:offset + self.window_sz]
            cnt = Counter(window)
            ent = self._shannon_entropy(cnt, self.window_sz)
            entropies.append((offset, ent))

        if entropies:
            # 寻找高熵连续段
            high_ent_windows = [(off, ent) for off, ent in entropies if ent > 7.0]
            if high_ent_windows:
                start = min(off for off, _ in high_ent_windows)
                end = max(off + self.window_sz for off, _ in high_ent_windows)
                window_data = data[start:min(end, total_size)]
                wcnt = Counter(window_data)
                sections.append(SectionEntropy(
                    name=f"high_entropy_{hex(start)}_{hex(end)}",
                    section_type=SectionType.UNKNOWN,
                    offset=start, size=min(end - start, total_size - start),
                    shannon_entropy=self._shannon_entropy(wcnt, len(window_data)),
                    chi_square=self._chi_square(wcnt, len(window_data)),
                    printable_ratio=self._printable_ratio(window_data),
                    null_byte_ratio=self._null_ratio(window_data),
                    avg_byte_value=sum(window_data) / max(len(window_data), 1),
                    anomaly_flags=['高熵连续段-可能为加密数据或压缩payload']))

        return sections

    def _parse_sections_from_header(self, data):
        """从ELF或PE头解析节表-提取各节熵信息"""
        sections = []
        if len(data) < 64:
            return sections

        # ELF解析
        if data[:4] == b'\x7fELF':
            try:
                is_64bit = data[4] == 2
                if is_64bit:
                    e_shoff = struct.unpack_from('<Q', data, 0x28)[0]
                    e_shentsize = struct.unpack_from('<H', data, 0x3A)[0]
                    e_shnum = struct.unpack_from('<H', data, 0x3C)[0]
                    e_shstrndx = struct.unpack_from('<H', data, 0x3E)[0]
                else:
                    e_shoff = struct.unpack_from('<I', data, 0x20)[0]
                    e_shentsize = struct.unpack_from('<H', data, 0x2E)[0]
                    e_shnum = struct.unpack_from('<H', data, 0x30)[0]
                    e_shstrndx = struct.unpack_from('<H', data, 0x32)[0]

                for i in range(min(e_shnum, 100)):
                    sh_offset = e_shoff + i * e_shentsize
                    if sh_offset + e_shentsize > len(data):
                        break
                    if is_64bit:
                        sh_name_idx, sh_type = struct.unpack_from('<II', data, sh_offset)
                        sh_addr = struct.unpack_from('<Q', data, sh_offset + 16)[0]
                        sh_size = struct.unpack_from('<Q', data, sh_offset + 32)[0]
                    else:
                        sh_name_idx, sh_type = struct.unpack_from('<II', data, sh_offset)
                        sh_addr = struct.unpack_from('<I', data, sh_offset + 12)[0]
                        sh_size = struct.unpack_from('<I', data, sh_offset + 20)[0]

                    if sh_size == 0 or sh_addr == 0:
                        continue
                    if sh_offset + sh_size > len(data):
                        sh_size = len(data) - sh_offset

                    sdata = data[sh_offset:sh_offset + min(sh_size, 65536)]
                    scnt = Counter(sdata)
                    s_size = min(sh_size, 65536)

                    stype = SectionType.CODE if sh_type == 1 else (
                        SectionType.DATA if sh_type == 8 else SectionType.UNKNOWN)
                    flags = []
                    ent = self._shannon_entropy(scnt, s_size)
                    if ent > 7.0 and stype == SectionType.CODE:
                        flags.append(f'.text段熵异常({ent:.2f})-可能为自修改代码或混淆')
                    if ent > 7.5:
                        flags.append(f'极高熵({ent:.2f})-强加密或压缩')

                    sections.append(SectionEntropy(
                        name=f"section_{i}", section_type=stype,
                        offset=sh_offset, size=sh_size,
                        shannon_entropy=ent,
                        chi_square=self._chi_square(scnt, s_size),
                        printable_ratio=self._printable_ratio(sdata),
                        null_byte_ratio=self._null_ratio(sdata),
                        avg_byte_value=sum(sdata) / max(len(sdata), 1),
                        anomaly_flags=flags))
            except Exception:
                pass

        # PE解析
        elif data[:2] == b'MZ':
            try:
                pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
                if pe_offset + 4 > len(data):
                    return sections
                if data[pe_offset:pe_offset + 4] != b'PE\x00\x00':
                    return sections
                coff_nsections = struct.unpack_from('<H', data, pe_offset + 6)[0]
                opt_header_size = struct.unpack_from('<H', data, pe_offset + 20)[0]
                section_start = pe_offset + 24 + opt_header_size

                for i in range(min(coff_nsections, 50)):
                    secoff = section_start + i * 40
                    if secoff + 40 > len(data):
                        break
                    sec_name = data[secoff:secoff + 8].rstrip(b'\x00').decode(
                        'ascii', errors='ignore').strip('\x00')
                    sec_vsize = struct.unpack_from('<I', data, secoff + 8)[0]
                    sec_raw_off = struct.unpack_from('<I', data, secoff + 20)[0]
                    sec_raw_sz = struct.unpack_from('<I', data, secoff + 16)[0]

                    if sec_raw_sz > 0 and sec_raw_off + sec_raw_sz <= len(data):
                        sdata = data[sec_raw_off:sec_raw_off + min(sec_raw_sz, 65536)]
                        scnt = Counter(sdata)
                        s_sz = min(sec_raw_sz, 65536)
                        ent = self._shannon_entropy(scnt, s_sz)
                        stype = SectionType.CODE if '.text' in sec_name else (
                            SectionType.DATA if '.data' in sec_name else
                            SectionType.RODATA if '.rdata' in sec_name else
                            SectionType.UNKNOWN)
                        flags = []
                        if ent > 7.0:
                            flags.append(f'{sec_name}熵异常({ent:.2f})')
                        sections.append(SectionEntropy(
                            name=sec_name, section_type=stype,
                            offset=sec_raw_off, size=sec_raw_sz,
                            shannon_entropy=ent,
                            chi_square=self._chi_square(scnt, s_sz),
                            printable_ratio=self._printable_ratio(sdata),
                            null_byte_ratio=self._null_ratio(sdata),
                            avg_byte_value=sum(sdata) / max(len(sdata), 1),
                            anomaly_flags=flags))
            except Exception:
                pass

        return sections

    def _scan_packer_signatures(self, data):
        """扫描已知加壳器字节签名"""
        hits = []
        for packer, sigs in self._PACKER_SIGNATURES.items():
            for sig in sigs:
                if sig in data:
                    hits.append(packer)
                    break
        return hits

    def _classify(self, report):
        """基于多指标启发式分类打包状态。

        决策树:
            entropy > 7.5 AND chi_square < 500 - 加密
            entropy > 7.0 AND 段异常存在 - 压缩/加壳
            entropy > 6.5 AND 加壳器签名存在 - 确认加壳
            printable_ratio < 0.05 - 二进制payload（可能混淆）
            null_ratio > 0.30 → 未充分使用（可能未初始化段）
            else → 未加壳
        """
        flags = report.anomaly_flags
        ent = report.overall_entropy
        chi2 = report.overall_chi_square

        confidence = 0.0
        status = PackingStatus.NOT_PACKED

        if ent > 7.5 and chi2 < 500:
            status = PackingStatus.ENCRYPTED
            confidence = min(0.95, 0.7 + (ent - 7.5) * 0.5)
            flags.append(f'熵{ent:.2f} + 低chi²({chi2:.0f}) - 加密数据')
        elif ent > 7.0:
            if flags:
                status = PackingStatus.PACKED
                confidence = 0.75
                flags.append('高熵+已知加壳器签名-确认加壳')
            else:
                status = PackingStatus.LIKELY_PACKED
                confidence = 0.55 + min(0.3, (ent - 7.0) * 0.6)

        # 段异常检测
        for sec in report.sections:
            if sec.anomaly_flags:
                flags.extend(sec.anomaly_flags)
            if sec.shannon_entropy > 7.0 and sec.section_type == SectionType.CODE:
                status = max(status, PackingStatus.OBFUSCATED, key=lambda s: (
                    ['not_packed', 'likely_packed', 'packed', 'obfuscated', 'encrypted'].index(s)))

        report.anomaly_flags = flags
        return status, min(1.0, confidence)

    def _gen_recommendations(self, report):
        recs = []
        if report.packing_status == PackingStatus.ENCRYPTED:
            recs.append('文件整体高熵+低chi²分布-强加密数据。'
                         '建议在分析前解密或dump内存中的运行时映像。')
        elif report.packing_status == PackingStatus.PACKED:
            recs.append('检测到加壳迹象-使用UPX -d或专用脱壳工具处理后再分析。')
        elif report.packing_status == PackingStatus.LIKELY_PACKED:
            recs.append('疑似加壳-建议检查节表异常、入口点特征，并对比运行时内存dump。')
        elif report.packing_status == PackingStatus.OBFUSCATED:
            recs.append('.text段高熵-可能存在代码混淆或自修改代码。'
                         '建议跳过静态反汇编，使用动态追踪或符号执行。')
        if report.overall_entropy > 6.5:
            recs.append(f'整体高熵({report.overall_entropy:.2f})-'
                         '字符串搜索和静态模式匹配的有效性将降低。')
        return recs

    # 统计辅助函数

    @staticmethod
    def _printable_ratio(data):
        if not data:
            return 0.0
        printable = sum(1 for b in data if 0x20 <= b <= 0x7e)
        return printable / len(data)

    @staticmethod
    def _null_ratio(data):
        if not data:
            return 0.0
        return data.count(0) / len(data)


# 便捷函数

def analyze_entropy(file_path: str) -> EntropyReport:
    """分析二进制文件熵与加壳检测"""
    analyzer = BinaryEntropyAnalyzer()
    return analyzer.analyze_file(file_path)


def quick_entropy_check(data: bytes) -> Tuple[float, str]:
    """快速熵检查-返回(熵值, 评估字符串)"""
    if not data:
        return 0.0, "无数据"
    cnt = Counter(data)
    ent = BinaryEntropyAnalyzer._shannon_entropy.__func__(
        None, cnt, len(data))
    if ent > 7.5:
        desc = "强加密/压缩"
    elif ent > 7.0:
        desc = "加密/压缩"
    elif ent > 6.5:
        desc = "轻度混淆"
    else:
        desc = "正常代码/数据"
    return ent, desc
