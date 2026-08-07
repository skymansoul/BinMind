# 统一入口，避免各处散落魔数

from enum import Enum, IntEnum


# 指令集架构

class Arch(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "ppc"
    PPC64 = "ppc64"
    RISCV = "riscv"
    UNKNOWN = "unknown"

    @classmethod
    def from_r2_arch(cls, r2_str: str) -> "Arch":
        """从 radare2 架构字符串推断 Arch 枚举值"""
        s = r2_str.lower().strip()
        _map = {
            "x86": cls.X86,
            "x86_64": cls.X86_64,
            "amd64": cls.X86_64,
            "arm": cls.ARM,
            "arm64": cls.ARM64,
            "aarch64": cls.ARM64,
            "mips": cls.MIPS,
            "mips64": cls.MIPS64,
            "ppc": cls.PPC,
            "powerpc": cls.PPC,
            "ppc64": cls.PPC64,
            "powerpc64": cls.PPC64,
            "riscv": cls.RISCV,
            "riscv64": cls.RISCV,
        }
        return _map.get(s, cls.UNKNOWN)

    @classmethod
    def from_elf_machine(cls, e_machine: int) -> "Arch":
        """从 ELF e_machine 字段映射架构"""
        # //// EM_* 常量 (linux/elf-em.h)
        _em_map = {
            3:   cls.X86,         # EM_386
            8:   cls.MIPS,        # EM_MIPS
            20:  cls.PPC,         # EM_PPC
            21:  cls.PPC64,       # EM_PPC64
            40:  cls.ARM,         # EM_ARM
            62:  cls.X86_64,      # EM_X86_64
            183: cls.ARM64,       # EM_AARCH64
            243: cls.RISCV,       # EM_RISCV
        }
        return _em_map.get(e_machine, cls.UNKNOWN)


# 中间表示类型

class IRType(Enum):
    VEX = "vex"
    ESIL = "esil"
    LLVM_IR = "llvm_ir"
    BNIL = "bnil"


# //// 严重性等级（数值越大越严重）

class Severity(IntEnum):
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def from_cvss_score(cls, score: float) -> "Severity":
        """CVSS v3.x 分数 -> Severity"""
        if score <= 0.0:
            return cls.INFO
        elif score < 4.0:
            return cls.LOW
        elif score < 7.0:
            return cls.MEDIUM
        elif score < 9.0:
            return cls.HIGH
        return cls.CRITICAL


# 二进制文件格式

class BinaryFormat(Enum):
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach_o"
    RAW = "raw"
    UNKNOWN = "unknown"

    @classmethod
    def from_magic(cls, header: bytes) -> "BinaryFormat":
        if len(header) < 4:
            return cls.UNKNOWN
        # MZ (PE / DOS)
        if header[:2] == b"MZ":
            return cls.PE
        # ELF
        if header[:4] == b"\x7fELF":
            return cls.ELF
        # Mach-O (32/64-bit / FAT binary)
        mach_magics = (
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
            b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
        )
        if header[:4] in mach_magics:
            return cls.MACH_O
        return cls.RAW

    @classmethod
    def from_extension(cls, filename: str) -> "BinaryFormat":
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        _ext_map = {
            "elf": cls.ELF, "out": cls.ELF, "o": cls.ELF, "so": cls.ELF,
            "exe": cls.PE, "dll": cls.PE, "sys": cls.PE, "efi": cls.PE,
            "macho": cls.MACH_O, "dylib": cls.MACH_O, "bundle": cls.MACH_O,
            "bin": cls.RAW, "raw": cls.RAW, "hex": cls.RAW,
        }
        return _ext_map.get(ext, cls.UNKNOWN)


# 常见壳/加壳特征节区名

PACKER_SECTIONS: frozenset[str] = frozenset([
    "upx0", "upx1", "UPX0", "UPX1",
    ".aspack", ".adata", ".aspdata",
    ".petite",
    ".mackt",  # MPRESS
    ".pec", ".pec1", ".pec2",  # PECRYPT / PECompact
    ".y0da", ".yP",  # yoda's protector
    ".enigma", ".enigma0", ".enigma1",
    ".taz",  # telock
    ".svkp",  # SVKP
    "vlmpxc",  # VMProtect
    ".vmp0", ".vmp1",
    ".vip0",  # Code Virtualizer / Orion
    "vprot", "vprot2",
    "rstub",  # rlpacK
    ".nsp0", ".nsp1", ".nsp2",  # NsPacK
    ".wwpack", ".wwp32",
    ".mcode",  # Morphine
    "poly",  # polyene
    ".cid",  # Crunch/PEtite
    "pcle",  # PCLee
    ".ccg",  # CCG
    "themida", "winlic",  # Themida/WinLicense
    "obsidium",  # Obsidium
    ".pelock", ".perplex",
    ".se0", ".se1",  # SecuROM
    ".neolite",
    "armadillo",
])
