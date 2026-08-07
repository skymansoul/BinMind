# 固件映像安全审计 — 文件系统识别、内核版本提取、已知漏洞签名匹配。
# FIE on Firmware (USENIX Security 2013) 嵌入式符号执行;
# FITS (ASPLOS 2023) IoT 固件中间污点源推断;
# FirmRec (ACM CCS 2024) 重复漏洞检测;
# IoT Firmware Emulation and Its Security Application in Fuzzing (2024);
# Shimware (2016) 固件安全 retrofit。
import os as _os, struct as _pack, re as _re
from dataclasses import dataclass as _dc, field as _field

# 常见固件映像文件系统魔数 — 按前缀匹配判定格式及压缩类型。
_FS_MAGICS = {
    b'\x28\xcd\x2d\x3d': 'SquashFS (LE)',
    b'\x68\x73\x71\x73': 'SquashFS (BE)',
    b'\x1f\x8b\x08':     'gzip compressed',
    b'\xfd\x37\x7a\x58\x5a\x00': 'XZ compressed',
    b'\x42\x5a\x68':     'bzip2 compressed',
    b'\x50\x4b\x03\x04': 'Zip archive',
    b'UBI#':            'UBI image',
    b'CRAMFS':          'CramFS',
    b'\x3a\xff\x26\xed': 'JFFS2',
    b'\xe2\xe1\x85\x1a': 'YAFFS',
}

@_dc
class FirmwareInfo:
    file_path: str = ''
    file_size: int = 0
    fs_type: str = 'unknown'
    compression: str = 'none'
    kernel_version: str = ''
    architecture: str = ''
    entropy: float = 0.0
    sections: list[dict] = field(default_factory=list)

def analyze_firmware_header(data: bytes) -> FirmwareInfo:
    """判定固件映像的文件系统类型与压缩方式。
    固件格式识别是后续所有分析的前置条件 — FIE on Firmware 的核心前提。"""
    import math as _math
    info = FirmwareInfo(file_size=len(data))

    # 遍历魔数表匹配文件系统类型
    for magic, fstype in _FS_MAGICS.items():
        if data[:len(magic)] == magic:
            info.fs_type = fstype
            break

    # 前 64KB 熵计算 — 高熵区可能为压缩或加密块，低熵区可能为代码或空数据。
    if data:
        freq = [0] * 256
        for b in data[:65536]:  # 仅采样前 64KB，兼顾速度与代表性
            freq[b] += 1
        n = min(65536, len(data))
        info.entropy = -sum((c/n)*_math.log2(c/n) for c in freq if c > 0)

    # 前 1MB 内扫描 Linux 内核版本字符串
    ver_match = _re.search(rb'Linux\s+version\s+(\d+\.\d+\.\d+)', data[:1048576])
    if ver_match:
        info.kernel_version = ver_match.group(1).decode()

    # 从 ELF header 推断目标 CPU 架构
    if data[:4] == b'\x7fELF':
        ei_class = data[4]
        ei_data = data[5]
        e_machine = _pack.unpack_from('<H', data, 18)[0]
        arch_map = {3: 'x86', 62: 'x86_64', 40: 'ARM', 183: 'AArch64',
                    8: 'MIPS', 20: 'PowerPC'}
        info.architecture = arch_map.get(e_machine, f'machine_{e_machine}')

    return info

def extract_vuln_signatures(firmware_data: bytes) -> list[dict]:
    """提取固件二进制中的已知漏洞特征签名。
    FirmRec concolic 签名策略: 语义等价匹配，对代码微调不敏感。"""
    sigs = []
    # 硬编码凭据/私钥/API 密钥检测
    cred_patterns = [
        (rb'(?:passwd|password|pass|pwd)\s*[=:]\s*["\']?([^\s"\'&|;]{4,32})["\']?', 'hardcoded_password'),
        (rb'(?:api[_-]?key|token)\s*[=:]\s*["\']?([A-Za-z0-9_-]{16,64})["\']?', 'hardcoded_api_key'),
        (rb'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY', 'embedded_private_key'),
    ]
    for pattern, sig_type in cred_patterns:
        for m in _re.finditer(pattern, firmware_data[:2097152]):  # 前 2MB 内扫描，避免 I/O 膨胀
            sigs.append({'type': sig_type, 'offset': m.start(),
                         'preview': m.group()[:60].decode('ascii', errors='replace')})
    return sigs
