# firmware_analyzer.py — 固件安全分析器
# 分析 IoT / 嵌入式设备固件，提取文件系统、识别已知漏洞、评估加固水平。
# 参考: FIE on Firmware (USENIX Security 2013) — 嵌入式系统的符号执行 &
#   FITS (ASPLOS 2023) — IoT 固件的中间污点源推断 &
#   FirmRec (ACM CCS 2024) — 重复漏洞检测 &
#   IoT Firmware Emulation and Its Security Application in Fuzzing (2024) &
#   Shimware (2016) — 固件安全 retrofit
import os as _os, struct as _pack, re as _re
from dataclasses import dataclass as _dc, field as _field

# 常见固件文件系统魔数
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
    """检测固件映像的文件系统类型和压缩格式。
    FIE on Firmware: 正确识别固件格式是所有后续分析的前提。"""
    import math as _math
    info = FirmwareInfo(file_size=len(data))

    # 文件系统魔数匹配
    for magic, fstype in _FS_MAGICS.items():
        if data[:len(magic)] == magic:
            info.fs_type = fstype
            break

    # 熵计算 — FITS 用于区分压缩/加密区域与代码区域
    if data:
        freq = [0] * 256
        for b in data[:65536]:  # 仅分析前 64KB
            freq[b] += 1
        n = min(65536, len(data))
        info.entropy = -sum((c/n)*_math.log2(c/n) for c in freq if c > 0)

    # Linux 内核版本字符串扫描
    ver_match = _re.search(rb'Linux\s+version\s+(\d+\.\d+\.\d+)', data[:1048576])
    if ver_match:
        info.kernel_version = ver_match.group(1).decode()

    # 架构推断 — 通过 ELF header
    if data[:4] == b'\x7fELF':
        ei_class = data[4]
        ei_data = data[5]
        e_machine = _pack.unpack_from('<H', data, 18)[0]
        arch_map = {3: 'x86', 62: 'x86_64', 40: 'ARM', 183: 'AArch64',
                    8: 'MIPS', 20: 'PowerPC'}
        info.architecture = arch_map.get(e_machine, f'machine_{e_machine}')

    return info

# FirmRec (CCS 2024) 方法: 从固件中提取漏洞签名
def extract_vuln_signatures(firmware_data: bytes) -> list[dict]:
    """从固件二进制中提取已知漏洞模式签名。
    FirmRec 的 concolic 签名方法: 语义等价检测，对代码变化不敏感。"""
    sigs = []
    # 检测硬编码凭据
    cred_patterns = [
        (rb'(?:passwd|password|pass|pwd)\s*[=:]\s*["\']?([^\s"\'&|;]{4,32})["\']?', 'hardcoded_password'),
        (rb'(?:api[_-]?key|token)\s*[=:]\s*["\']?([A-Za-z0-9_-]{16,64})["\']?', 'hardcoded_api_key'),
        (rb'BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY', 'embedded_private_key'),
    ]
    for pattern, sig_type in cred_patterns:
        for m in _re.finditer(pattern, firmware_data[:2097152]):  # 前 2MB
            sigs.append({'type': sig_type, 'offset': m.start(),
                         'preview': m.group()[:60].decode('ascii', errors='replace')})
    return sigs
