# 2026-07-26
# 固件安全分析器 — 引导加载器审计、内核配置审计、二进制加固检查 + ELF段权限

import re
import struct
from typing import Optional
from .core import RiskLevel


class BootloaderAuditor:
    _BOOTLOADER_CVES = {
        "U-Boot": [
            ("CVE-2022-30790", "命令注入 — 构造环境变量", "CRITICAL", "<=2022.04"),
            ("CVE-2022-34835", "缓冲区溢出 — NFS处理", "HIGH", "<=2022.07"),
            ("CVE-2021-27138", "越界写 — ext4文件系统", "HIGH", "<=2021.01"),
            ("CVE-2020-10648", "任意写 — FIT镜像签名绕过", "HIGH", "<=2020.04"),
            ("CVE-2019-14192", "无限循环 — 畸形网络包DoS", "MEDIUM", "<=2019.07"),
            ("CVE-2021-27097", "未初始化内存 — tftp", "MEDIUM", "<=2021.04"),
            ("CVE-2019-13103", "堆栈溢出 — 超长路径名", "HIGH", "<=2019.07"),
        ],
        "GRUB": [
            ("CVE-2023-4692", "堆越界写 — NTFS", "HIGH", "<=2.12"),
            ("CVE-2023-4693", "堆越界读 — NTFS", "MEDIUM", "<=2.12"),
            ("CVE-2022-28736", "使用已释放内存 — 链式加载", "HIGH", "<=2.06"),
            ("CVE-2021-3695", "堆缓冲区溢出 — PNG", "MEDIUM", "<=2.06"),
            ("CVE-2020-14372", "ACPI表绕过安全启动", "CRITICAL", "<=2.06"),
            ("CVE-2020-10713", "缓冲区溢出 — 启动配置文件", "CRITICAL", "<=2.06"),
        ],
        "Barebox": [("CVE-2021-3638", "内存损坏 — USB gadget", "MEDIUM", "<=2021.06")],
        "Coreboot": [("CVE-2022-29264", "SMM权限提升 — 未验证输入", "HIGH", "<=4.16")],
    }

    def audit(self, data: bytes) -> list[dict]:
        _bl = self._detect_bootloader(data)
        if not _bl:
            return [{"bootloader": "unknown", "finding": "无法识别引导加载器", "severity": "MEDIUM"}]
        _ver = self._version_extract(data)
        _cves = self._check_cves(_bl, _ver)
        _findings = [{"bootloader": _bl, "version_detected": _ver,
                      "finding": f"检测到 {_bl} 版本 {_ver}", "severity": "INFO"}]
        if _bl == "U-Boot":
            _findings.extend(self._audit_uboot_config(data))
        for _cid, _desc, _sev, _aff in _cves:
            _findings.append({"bootloader": _bl, "version_detected": _ver, "cve_id": _cid,
                              "finding": _desc, "severity": _sev, "affected_versions": _aff})
        return _findings

    def _detect_bootloader(self, data: bytes) -> Optional[str]:
        _txt = data[:65536].decode("ascii", errors="ignore")
        if data[:4] == b"\x27\x05\x19\x56":
            return "U-Boot"
        if "U-Boot" in _txt or "u-boot" in _txt.lower():
            return "U-Boot"
        if b"GRUB " in data[:32768] or b"GRUB2" in data[:32768]:
            return "GRUB"
        if "GRUB" in _txt:
            return "GRUB"
        if data[:8] == b"barebox\n" or b"barebox" in data[:16384].lower():
            return "Barebox"
        if b"coreboot" in data[:32768].lower() or b"CBFS" in data[:4096]:
            return "Coreboot"
        return None

    def _version_extract(self, data: bytes) -> str:
        _txt = data[:131072].decode("ascii", errors="ignore")
        _m = re.search(r"U-Boot\s+(?:SPL\s+)?(\d{4}\.\d{2}(?:-rc\d+)?)", _txt)
        if _m:
            return _m.group(1)
        _m = re.search(r"(?:GNU\s+)?GRUB\s+(\d+\.\d+(?:\.\d+)?)", _txt)
        if _m:
            return _m.group(1)
        _m = re.search(r"barebox\s+(\d{4}\.\d{2}(?:\.\d+)?)", _txt, re.IGNORECASE)
        if _m:
            return _m.group(1)
        _m = re.search(r"coreboot[- ](\d+\.\d+(?:\.\d+)?)", _txt, re.IGNORECASE)
        if _m:
            return _m.group(1)
        return "unknown"

    def _audit_uboot_config(self, data: bytes) -> list[dict]:
        risks = []; txt = data[:262144].decode('ascii', errors='ignore')
        unsafe_cmds = {'CONFIG_CMD_SOURCE': '允许从任意介质 source 脚本',
                       'CONFIG_CMD_IMI': '允许查看/修改镜像头',
                       'CONFIG_CMD_I2C': 'I2C 总线访问', 'CONFIG_AUTOBOOT_KEYED': '自动启动可中断'}
        for cmd, reason in unsafe_cmds.items():
            if cmd in txt:
                risks.append({"type": "uboot_config", "bootloader": "U-Boot",
                              "finding": f"U-Boot 不安全编译选项: {cmd} — {reason}", "severity": "MEDIUM"})
        delay_m = re.search(r'CONFIG_BOOTDELAY=(-?\d+)', txt)
        if delay_m and delay_m.group(1) != '-1':
            risks.append({"type": "uboot_config", "bootloader": "U-Boot",
                          "finding": f"U-Boot BOOTDELAY={delay_m.group(1)}", "severity": "LOW"})
        return risks

    def _check_cves(self, bl_name: str, version: str) -> list:
        _cves = self._BOOTLOADER_CVES.get(bl_name, []); _matched = []
        for _cid, _desc, _sev, _aff_ver in _cves:
            if version == "unknown":
                _matched.append((_cid, _desc, _sev, _aff_ver))
            elif self._version_le(version, _aff_ver.lstrip("<=")):
                _matched.append((_cid, _desc, _sev, _aff_ver))
        return _matched

    @staticmethod
    def _version_le(v1: str, v2: str) -> bool:
        try:
            _p1 = [int(x) for x in v1.split(".")[:3]]; _p2 = [int(x) for x in v2.split(".")[:3]]
            while len(_p1) < 3: _p1.append(0)
            while len(_p2) < 3: _p2.append(0)
            return _p1 <= _p2
        except ValueError:
            return False


class KernelConfigAuditor:
    _KSPP_BASELINE = {
        "CONFIG_STRICT_KERNEL_RWX": ("y", "CRITICAL", "内核代码段只读不可执行"),
        "CONFIG_STRICT_MODULE_RWX": ("y", "CRITICAL", "内核模块只读不可执行"),
        "CONFIG_RANDOMIZE_BASE": ("y", "CRITICAL", "KASLR基址随机化"),
        "CONFIG_RANDOMIZE_MEMORY": ("y", "HIGH", "内存布局随机化"),
        "CONFIG_SLAB_FREELIST_RANDOM": ("y", "HIGH", "SLAB空闲链表随机化"),
        "CONFIG_SLAB_FREELIST_HARDENED": ("y", "HIGH", "SLAB空闲链表加固"),
        "CONFIG_HARDENED_USERCOPY": ("y", "HIGH", "用户空间拷贝边界检查"),
        "CONFIG_FORTIFY_SOURCE": ("y", "HIGH", "编译时内存操作强化"),
        "CONFIG_STACKPROTECTOR": ("y", "MEDIUM", "栈溢出保护"),
        "CONFIG_STACKPROTECTOR_STRONG": ("y", "CRITICAL", "栈溢出保护（加强）"),
        "CONFIG_SCHED_STACK_END_CHECK": ("y", "MEDIUM", "调度栈溢出检测"),
        "CONFIG_DEBUG_LIST": ("y", "MEDIUM", "链表损坏检测"),
        "CONFIG_DEBUG_SG": ("y", "LOW", "scatter-gather验证"),
        "CONFIG_DEBUG_CREDENTIALS": ("y", "LOW", "凭证结构验证"),
        "CONFIG_DEBUG_NOTIFIERS": ("y", "MEDIUM", "通知链健全检查"),
        "CONFIG_BUG_ON_DATA_CORRUPTION": ("y", "HIGH", "数据损坏触发BUG"),
        "CONFIG_SHUFFLE_PAGE_ALLOCATOR": ("y", "MEDIUM", "页面分配器随机化"),
        "CONFIG_PAGE_TABLE_ISOLATION": ("y", "CRITICAL", "KPTI页表隔离"),
        "CONFIG_RETPOLINE": ("y", "CRITICAL", "Retpoline（Spectre v2）"),
        "CONFIG_UNMAP_KERNEL_AT_EL0": ("y", "CRITICAL", "ARM64 EL0内核映射解除"),
        "CONFIG_HARDEN_BRANCH_PREDICTOR": ("y", "CRITICAL", "分支预测器加固"),
        "CONFIG_ARM64_SW_TTBR0_PAN": ("y", "HIGH", "ARM64软件PAN"),
        "CONFIG_ARM64_SSBD": ("y", "MEDIUM", "ARM64推测存储绕过禁用"),
        "CONFIG_INIT_ON_ALLOC_DEFAULT_ON": ("y", "HIGH", "分配时内存清零"),
        "CONFIG_ZERO_CALL_USED_REGS": ("y", "MEDIUM", "函数返回时寄存器清零"),
        "CONFIG_IOMMU_DEFAULT_DMA_STRICT": ("y", "MEDIUM", "IOMMU严格DMA"),
        "CONFIG_DEFAULT_MMAP_MIN_ADDR": ("65536", "HIGH", "mmap最小地址"),
        "CONFIG_SECURITY": ("y", "HIGH", "安全子系统"), "CONFIG_SECURITY_SELINUX": ("y", "HIGH", "SELinux"),
        "CONFIG_SECURITY_YAMA": ("y", "MEDIUM", "Yama ptrace"), "CONFIG_SECCOMP": ("y", "HIGH", "Seccomp"),
        "CONFIG_SECCOMP_FILTER": ("y", "HIGH", "Seccomp BPF"),
        "CONFIG_INTEGRITY": ("y", "MEDIUM", "完整性子系统"), "CONFIG_IMA": ("y", "HIGH", "IMA"),
        "CONFIG_EVM": ("y", "MEDIUM", "EVM"), "CONFIG_LOCK_DOWN_KERNEL": ("y", "CRITICAL", "内核锁定"),
        "CONFIG_MODULE_SIG": ("y", "HIGH", "内核模块签名"),
        "CONFIG_MODULE_SIG_ALL": ("y", "MEDIUM", "所有模块签名"),
        "CONFIG_MODULE_SIG_SHA512": ("y", "MEDIUM", "SHA-512签名"),
        "CONFIG_SYN_COOKIES": ("y", "MEDIUM", "SYN cookie"),
        "CONFIG_RANDSTRUCT": ("y", "MEDIUM", "内核结构体随机化"),
        "CONFIG_GCC_PLUGIN_STACKLEAK": ("y", "MEDIUM", "StackLeak"),
        "CONFIG_RESET_ATTACK_MITIGATION": ("y", "HIGH", "重启攻击缓解"),
        "CONFIG_ARM64_PTR_AUTH": ("y", "MEDIUM", "ARM64 指针认证 (PAC)"),
    }

    def audit_config(self, config_text: str) -> dict:
        _parsed = self._parse_kconfig(config_text); _results = []
        _passed = _failed = _warnings = _score = _max_score = 0
        for _opt, (_expected, _sev, _rationale) in self._KSPP_BASELINE.items():
            _severity_weight = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}
            _w = _severity_weight.get(_sev, 1); _max_score += _w
            _actual = _parsed.get(_opt)
            if _actual is None:
                _results.append({"option": _opt, "status": "not_found", "expected": _expected,
                                 "actual": None, "severity": _sev, "rationale": _rationale})
                _failed += 1; _warnings += 1
            elif _actual == _expected:
                _results.append({"option": _opt, "status": "pass", "expected": _expected,
                                 "actual": _actual, "severity": _sev, "rationale": _rationale})
                _passed += 1; _score += _w
            else:
                _results.append({"option": _opt, "status": "fail", "expected": _expected,
                                 "actual": _actual, "severity": _sev, "rationale": _rationale})
                _failed += 1
        _pct = round(_score / _max_score * 100, 1) if _max_score > 0 else 0
        _grade = self._compute_grade(_pct)
        return {"filename": "kernel_config", "passed": _passed, "failed": _failed,
                "warnings": _warnings, "total_checks": len(self._KSPP_BASELINE),
                "score": _score, "max_score": _max_score, "percentage": _pct,
                "grade": _grade, "results": _results}

    def _parse_kconfig(self, text: str) -> dict:
        _cfg = {}
        for _line in text.splitlines():
            _line = _line.strip()
            if not _line or _line.startswith("#"):
                continue
            _m = re.match(r"^CONFIG_(\w+)=(.*)$", _line)
            if _m:
                _cfg[f"CONFIG_{_m.group(1)}"] = _m.group(2).strip('"')
            _m2 = re.match(r"^#\s*CONFIG_(\w+)\s+is not set", _line)
            if _m2:
                _cfg[f"CONFIG_{_m2.group(1)}"] = "n"
        return _cfg

    def _compute_grade(self, percentage: float) -> str:
        if percentage >= 95: return "A+"
        elif percentage >= 90: return "A"
        elif percentage >= 80: return "B"
        elif percentage >= 70: return "C"
        elif percentage >= 60: return "D"
        return "F"


def binary_hardening(data: bytes, arch: str = "arm") -> dict:
    _elf = _parse_elf_header(data)
    if not _elf:
        return {}
    _phdrs = _parse_program_headers(data, _elf); _dyn = _find_dynamic_section(data, _phdrs, _elf)
    _nx = True
    for _ph in _phdrs:
        if _ph.get("type") == 0x6474E551 and (_ph.get("flags", 0) & 1):
            _nx = False
    if not any(_ph.get("type") == 0x6474E551 for _ph in _phdrs):
        _nx = not any(_ph.get("type") == 1 and (_ph.get("flags", 0) & 1) for _ph in _phdrs)
    _has_relro = any(_ph.get("type") == 0x6474E552 for _ph in _phdrs)
    _bind_now = _dyn.get("BIND_NOW", False); _full_relro = _has_relro and _bind_now
    _pie = _elf.get("type") == 3
    _canary = b"__stack_chk_fail" in data[:65536] or b"__stack_chk_guard" in data[:65536]
    _fortify = b"__fortify_fail" in data[:65536] or b"__chk_fail" in data[:65536]
    _has_rwx = any(_ph.get("type") == 1 and (_ph.get("flags", 0) & 3) == 3 for _ph in _phdrs)
    _grade_points = sum([_nx, _full_relro, _pie, _canary, _fortify])
    _grade_map = {5: "A", 4: "B", 3: "C", 2: "D", 1: "E", 0: "F"}
    return {"arch": arch, "nx": _nx,
            "relro": "full" if _full_relro else ("partial" if _has_relro else "none"),
            "pie": _pie, "canary": _canary, "fortify_source": _fortify,
            "has_rwx_segment": _has_rwx, "grade": _grade_map.get(_grade_points, "F")}


def _parse_elf_header(data: bytes) -> Optional[dict]:
    if len(data) < 64:
        return None
    if data[:4] != b"\x7fELF":
        return None
    _class = data[4]; _endian = "little" if data[5] == 1 else "big"; _fmt_prefix = "<" if _endian == "little" else ">"
    if _class == 2:
        _hdr = struct.unpack_from(f"{_fmt_prefix}HHIQQQIHHHHHH", data, 16)
        _type, _machine, _version, _entry, _phoff, _shoff = _hdr[0], _hdr[1], _hdr[2], _hdr[3], _hdr[4], _hdr[5]
        _flags, _ehsize, _phentsize, _phnum, _shentsize, _shnum = _hdr[6], _hdr[7], _hdr[8], _hdr[9], _hdr[10], _hdr[11]
    else:
        _hdr = struct.unpack_from(f"{_fmt_prefix}HHIIIIIHHHHHH", data, 16)
        _type, _machine, _version, _entry, _phoff, _shoff = _hdr[0], _hdr[1], _hdr[2], _hdr[3], _hdr[4], _hdr[5]
        _flags, _ehsize, _phentsize, _phnum, _shentsize, _shnum = _hdr[6], _hdr[7], _hdr[8], _hdr[9], _hdr[10], _hdr[11]
    return {"class": _class, "endian": _endian, "type": _type, "machine": _machine,
            "entry": _entry, "phoff": _phoff, "phnum": _phnum, "phentsize": _phentsize}


def _parse_program_headers(data: bytes, elf_hdr: dict) -> list:
    _phdrs = []; _fmt_prefix = "<" if elf_hdr["endian"] == "little" else ">"; _is_64 = elf_hdr["class"] == 2
    for _i in range(elf_hdr["phnum"]):
        _off = elf_hdr["phoff"] + _i * elf_hdr["phentsize"]
        if _off + elf_hdr["phentsize"] > len(data):
            break
        if _is_64:
            _p = struct.unpack_from(f"{_fmt_prefix}IIQQQQQ", data, _off)
            _type, _flags, _offset, _vaddr, _paddr, _filesz, _memsz = _p
        else:
            _p = struct.unpack_from(f"{_fmt_prefix}IIIIIIII", data, _off)
            _type, _offset, _vaddr, _paddr, _filesz, _memsz = _p[0], _p[1], _p[2], _p[3], _p[4], _p[5]
            _flags = _p[6]
        _phdrs.append({"type": _type, "flags": _flags, "offset": _offset,
                       "vaddr": _vaddr, "filesz": _filesz, "memsz": _memsz})
    return _phdrs


def _find_dynamic_section(data: bytes, phdrs: list, elf_hdr: dict) -> dict:
    _result = {"BIND_NOW": False}; _fmt_prefix = "<" if elf_hdr["endian"] == "little" else ">"; _is_64 = elf_hdr["class"] == 2
    for _ph in phdrs:
        if _ph["type"] != 2:
            continue
        _off = _ph["offset"]; _sz = _ph["filesz"]; _tag_size = 16 if _is_64 else 8
        _pos = 0
        while _pos + _tag_size <= _sz:
            _abs = _off + _pos
            if _is_64:
                _tag, _val = struct.unpack_from(f"{_fmt_prefix}QQ", data, _abs)
            else:
                _tag, _val = struct.unpack_from(f"{_fmt_prefix}iI", data, _abs)
            if _tag == 0:
                break
            if _tag == 0x6FFFFFFB and (_val & 8):
                _result["BIND_NOW"] = True
            _pos += _tag_size
    return _result
