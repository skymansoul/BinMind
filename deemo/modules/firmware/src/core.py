# 2026-07-18
# 固件核心数据模型和检测工具 — 枚举、数据类、熵计算、文件系统/固件类型识别
# 2026-07 新增: Wairz 风格 RTOS 向量表解析 + OFRAK 资源树 + 固件年龄估算

import math
import enum
import re
import struct
from dataclasses import dataclass, field
from typing import Optional


class FirmwareType(enum.Enum):
    UNKNOWN = "unknown"; UBOOT = "u-boot"; BUILDROOT = "buildroot"
    OPENWRT = "openwrt"; ANDROID = "android"; FREERTOS = "freertos"
    ZEPHYR = "zephyr"; UEFI = "uefi"; BIOS = "bios"; BAREBOX = "barebox"


class RiskLevel(enum.Enum):
    INFO = 0; LOW = 1; MEDIUM = 2; HIGH = 3; CRITICAL = 4


@dataclass
class FirmwareImage:
    path: str; data: bytes; size: int
    ftype: FirmwareType = FirmwareType.UNKNOWN; entropy: float = 0.0
    fs_type: str = ""; metadata: dict = field(default_factory=dict)
    extracted_path: Optional[str] = None; sections: list = field(default_factory=list)


@dataclass
class ExtractionResult:
    success: bool = False; files_extracted: int = 0
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    extraction_time: float = 0.0; root_path: str = ""


# OFRAK 风格资源树: 固件镜像的多层嵌套结构表示。
# 每个 ResourceNode 描述一个解包层（如 uImage→SquashFS→ext4→文件），
# 形成从原始镜像到单个文件的完整祖先链。
# 参考: Red Balloon Security, "OFRAK: unpack, modify, and repack binaries"
@dataclass
class ResourceNode:
    label: str                # 人类可读标签: "uImage header", "SquashFS", "busybox ELF"
    offset: int = 0
    size: int = 0
    fmt: str = ""             # 格式名: "gzip", "cpio", "elf", "script"
    children: list = field(default_factory=list)  # 嵌套子节点
    metadata: dict = field(default_factory=dict)

    def add_child(self, child):
        self.children.append(child)
        return child

    def flatten(self) -> list[dict]:
        """展平为线性列表，每个节点携带从根到此节点的路径"""
        result = [{"path": self.label, "fmt": self.fmt, "offset": self.offset, "size": self.size}]
        for c in self.children:
            for sub in c.flatten():
                result.append({"path": f"{self.label}/{sub['path']}", "fmt": sub['fmt'],
                               "offset": sub['offset'], "size": sub['size']})
        return result


magic_bytes = {
    b"hsqs": "squashfs", b"sqsh": "squashfs", b"shsq": "squashfs", b"qshs": "squashfs",
    b"\x19\x85": "jffs2", b"\x85\x19": "jffs2",
    b"\x45\x3d\xcd\x28": "cramfs", b"\x28\xcd\x3d\x45": "cramfs",
    b"\x30\x37\x30\x37\x30\x31": "cpio", b"\x30\x37\x30\x37\x30\x32": "cpio", b"\xc7\x71": "cpio",
    b"\x31\x18\x10\x06": "ubifs", b"\x06\x10\x18\x31": "ubifs",
    b"\x03\x00\x00\x00\x01\x00\x00\x00\xff\xff": "yaffs",
    b"\x53\xef": "ext", b"\x55\xaa": "fat",
    b"-rom1fs-": "romfs", b"_BHRfS_M": "btrfs", b"\x10\x20\xf5\xf2": "f2fs",
}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    _h = [0] * 256; _len = len(data)
    for _b in data:
        _h[_b] += 1
    _ent = 0.0; _inv = 1.0 / _len
    for _cnt in _h:
        if _cnt:
            _p = _cnt * _inv; _ent -= _p * math.log2(_p)
    return _ent / 8.0


def detect_file_system(data: bytes) -> str:
    _head = data[:8]
    for _magic, _fs in magic_bytes.items():
        if len(_magic) <= 8 and _head[:len(_magic)] == _magic:
            return _fs
    if len(data) > 1080 and data[1080:1082] == b"\x53\xef":
        return "ext"
    if len(data) > 65600 and data[65600:65608] == b"_BHRfS_M":
        return "btrfs"
    if len(data) > 512:
        if data[510:512] == b"\x55\xaa":
            _fstype = data[54:62].strip(b"\x00").decode("ascii", errors="ignore")
            if "FAT" in _fstype:
                return "fat"
    if len(data) >= 4 and data[:4] in (b"\x31\x18\x10\x06", b"\x06\x10\x18\x31"):
        return "ubifs"
    if len(data) > 1028 and data[1024:1028] == b"\x10\x20\xf5\xf2":
        return "f2fs"
    return "unknown"


def _compute_section_bounds(data: bytes) -> list:
    _sections = []; _pos = 0; _size = len(data)
    _uboot_magic = b"\x27\x05\x19\x56"
    _android_magic = b"ANDROID!"; _fdt_magic = b"\xd0\x0d\xfe\xed"
    while _pos < _size:
        _window = data[_pos:_pos + 256]; _label = None
        if _window.startswith(_uboot_magic):
            _label = "U-Boot header"
        elif _android_magic in _window:
            _label = "Android boot image"
        elif _window[:4] == _fdt_magic:
            _label = "FDT/Device Tree"
        elif _window.startswith(b"BZh") or _window.startswith(b"\x1f\x8b"):
            _label = "Compressed data"
        if _label:
            _sections.append((_pos, 256, _label))
        _pos += 512
    return _sections


def parse_cortexm_vector_table(data: bytes) -> dict:
    if len(data) < 64:
        return {}
    sp_init = struct.unpack_from("<I", data, 0)[0]
    reset_vec = struct.unpack_from("<I", data, 4)[0]
    if reset_vec == 0 or reset_vec == 0xFFFFFFFF:
        return {}
    vectors = {}
    names = ["SP_initial", "Reset", "NMI", "HardFault", "MemManage",
             "BusFault", "UsageFault", "Reserved7", "Reserved8",
             "Reserved9", "Reserved10", "SVCall", "DebugMon", "Reserved13",
             "PendSV", "SysTick"]
    for i, name in enumerate(names[:min(16, len(data) // 4)]):
        val = struct.unpack_from("<I", data, i * 4)[0]
        if val != 0 and val != 0xFFFFFFFF:
            vectors[name] = val
    return {"sp_initial": sp_init, "vectors": vectors,
            "irq_count_estimate": max(0, (len(data) // 4) - 16)}


_BUILD_TIMESTAMP_RE = [
    (re.compile(rb'#\d+\s+(?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\w+\s+\d{4}'), "Linux build timestamp"),
    (re.compile(rb'(?:gcc|clang)\s+version\s+(\d+\.\d+\.\d+)'), "compiler version"),
    (re.compile(rb'Linux\s+version\s+(\d+\.\d+\.\d+(?:-rc\d+)?)'), "kernel version"),
]


def estimate_firmware_age(data: bytes) -> dict:
    sample = data[:2097152]; findings = {}
    for pat, label in _BUILD_TIMESTAMP_RE:
        m = pat.search(sample)
        if m:
            findings[label] = m.group(0).decode('ascii', errors='replace')[:80]
    findings["sample_size"] = min(len(data), 2097152)
    return findings


# VFF 风格验证器函数基本块布局模式: 基于 BB 的特征识别加密/签名验证函数。
# 参考: "VFF: Precise Identification of Firmware Validator Functions Based on
# Basic Block Layout Patterns and LLM-based Semantic Validation" (Jan 2026)
_VALIDATOR_BB_PATTERNS: list[tuple[bytes, str, str]] = [
    # 签名验证: cmp + bne → 错误路径; ldr + bl → 加载下一个公钥/证书
    (b'\x00\x28', "cmp_r0_zero", "signature check result comparison"),
    # memcmp 后紧跟条件分支 → 哈希/签名比对模式
    (b'\x00\xf0\x00\x80', "memcmp_branch", "memcmp result conditional branch"),
    # 加载 x509/ASN.1 OID 后跟验证调用
    (b'\x06\x03\x55\x1d', "x509_oid", "X.509 certificate extension OID reference"),
    # RSA public exponent 0x10001
    (b'\x00\x01\x00\x01', "rsa_f4_exponent", "RSA F4 public exponent constant"),
]


def detect_validator_functions(data: bytes) -> list[dict]:
    """VFF 风格: 扫描固件中可能为签名/加密验证函数的基本块布局模式"""
    candidates = []
    for pattern, tag, desc in _VALIDATOR_BB_PATTERNS:
        off = 0
        while True:
            idx = data.find(pattern, off)
            if idx == -1:
                break
            # 验证附近是否有函数入口特征 (push/prologue)
            ctx_start = max(0, idx - 64)
            ctx = data[ctx_start:idx + len(pattern) + 64]
            has_prologue = (b'\x80\xb5' in ctx[:64] or    # Thumb push {r4-r7, lr}
                            b'\x2d\xe9' in ctx[:64] or    # ARM32 push
                            b'\x55\x48\x89' in ctx[:64])   # x86 push rbp; mov rsp, rbp
            candidates.append({
                "offset": idx, "tag": tag, "description": desc,
                "near_prologue": has_prologue,
                "ctx_preview": ctx[:32].hex(),
            })
            off = idx + len(pattern)
    return candidates


def detect_firmware_type(data: bytes) -> FirmwareType:
    _head = data[:4096]; _text = _head.decode("ascii", errors="ignore")
    if _head[:4] == b"\x27\x05\x19\x56":
        return FirmwareType.UBOOT
    if b"ANDROID!" in _head:
        return FirmwareType.ANDROID
    if _head[:4] == b"_FVH" or b"UE" b"FI" in _head:
        return FirmwareType.UEFI
    if _head[:8] == b"barebox\n" or _head[:4] == b"\xce\xfa\xad\x0b":
        return FirmwareType.BAREBOX
    if b"Linux version" in data[:65536]:
        if b"OpenWrt" in data[:131072]:
            return FirmwareType.OPENWRT
        if b"buildroot" in data[:131072].lower():
            return FirmwareType.BUILDROOT
        if b"Zephyr" in data[:65536]:
            return FirmwareType.ZEPHYR
    if b"FreeRTOS" in _head:
        return FirmwareType.FREERTOS
    if b"Award" in data[:262144] or b"AMIBIOS" in data[:262144]:
        return FirmwareType.BIOS
    if _head[:2] == b"\x1f\x8b":
        _inner = data[2:1024]
        if b"Linux" in _inner or b"vmlinu" in _inner:
            if b"OpenWrt" in data[:131072]:
                return FirmwareType.OPENWRT
            return FirmwareType.BUILDROOT
    if len(data) >= 64:
        vec = parse_cortexm_vector_table(data)
        if vec and vec.get("sp_initial", 0) > 0x20000000:
            if b"FreeRTOS" in data[:65536]:
                return FirmwareType.FREERTOS
            if b"Zephyr" in data[:65536]:
                return FirmwareType.ZEPHYR
    return FirmwareType.UNKNOWN
