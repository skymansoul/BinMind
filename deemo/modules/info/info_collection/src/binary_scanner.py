# binary_scanner — 二进制格式/语言检测、危险函数库、信息提取
# 多级分析管线：格式→架构→熵→签名→混淆检测→网络IOC→段解析

import logging, os, math, re, struct
from collections import Counter

DANGEROUS_FUNCTIONS = {"gets", "strcpy", "system", "execve", "scanf", "free",
                       "sprintf", "strcat", "memcpy", "popen"}
KEY_STRING_PATTERNS = {"system", "bin/sh", "flag", "password", "secret", "key"}
KERNEL_DANGEROUS_FUNCTIONS = ["copy_from_user", "copy_to_user", "sprintf",
                               "strcpy", "strncpy", "memcpy"]
KERNEL_DRIVER_DANGEROUS_FUNCTIONS = ["IoControlCode", "MmMapIoSpace",
                                      "ExAllocatePool", "ZwOpenProcess"]


def detect_language(binary):
    return "unknown"


def detect_binary_format(path):
    """魔数字节比对：\\x7fELF→ELF, MZ→PE, FEEDFACE→Mach-O，否则 unknown。"""
    if not os.path.exists(path):
        return "unknown"
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic[:4] == b"\x7fELF":
        return "ELF"
    if magic[:2] == b"MZ":
        return "PE"
    if magic[:4] in (b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"):
        return "Mach-O"
    return "unknown"


def format_info_for_report(info):
    """二进制信息字典渲染为中文标签摘要，用于报告输出。"""
    if not info:
        return "无info"
    lines = []
    if "format" in info:
        lines.append(f"格式: {info['format']}")
    if "size" in info:
        lines.append(f"size: {info['size']} 字节")
    if "arch" in info:
        lines.append(f"architecture: {info['arch']}")
    if "strings" in info:
        key_strs = [s for s in info.get("strings", [])
                    if any(p in s.lower() for p in KEY_STRING_PATTERNS)]
        if key_strs:
            lines.append(f"关keystring: {', '.join(key_strs[:5])}")
    if "dangerous" in info:
        lines.append(f"dangerous function: {', '.join(info['dangerous'][:10])}")
    return "\n".join(lines) if lines else "无可报告info"


def _extract_pe_arch(raw: bytes) -> str:
    """PE optional header Machine 字段映射至架构标识。"""
    if len(raw) < 64:
        return "unknown"
    try:
        pe_off = struct.unpack_from("<I", raw, 0x3C)[0]
        machine = struct.unpack_from("<H", raw, pe_off + 4)[0]
        return {0x014C: "x86", 0x8664: "x64", 0x01C4: "ARM",
                0xAA64: "ARM64", 0x0200: "IA64"}.get(machine, f"machine_{machine:#06x}")
    except Exception:
        return "unknown"


def _extract_elf_arch(raw: bytes) -> str:
    """ELF e_machine + EI_CLASS 合成架构字符串。"""
    if len(raw) < 20:
        return "unknown"
    try:
        ei_class = raw[4]
        bits = "64" if ei_class == 2 else "32"
        machine = struct.unpack_from("<H", raw, 18)[0]
        arch_map = {3: "x86", 62: "x64", 40: "ARM", 183: "ARM64",
                    8: "MIPS", 21: "PPC", 43: "SPARC"}
        base = arch_map.get(machine, f"elf_machine_{machine}")
        return f"{base}_{bits}"
    except Exception:
        return "unknown"


def _extract_ascii_strings(raw: bytes, min_len: int = 4) -> list[str]:
    """逐字节扫描 ASCII 可打印字符序列，返回字符串列表。"""
    strings = []
    run = b""
    i, n = 0, len(raw)
    while i < n:
        b = raw[i]
        if 0x20 <= b <= 0x7E:
            run += bytes([b])
        else:
            if len(run) >= min_len:
                strings.append(run.decode("ascii", errors="replace"))
            run = b""
        i += 1
    if len(run) >= min_len:
        strings.append(run.decode("ascii", errors="replace"))
    return strings


def get_binary_info(path):
    """提取二进制文件的格式、尺寸、架构及安全指标。
    大文件只采样前 2MB 做熵/ngram/加密常量分析。
    """
    if not os.path.exists(path):
        return {"error": "file not found"}

    from ..info_collect import (
        _SUSPICIOUS_ENTROPY_RATIO,
        analyze_pe_sections,
        analyze_import_table_anomalies,
        extract_network_iocs,
        detect_shellcode_patterns,
        detect_api_hashing,
        detect_xor_obfuscated_strings,
        analyze_elf_segments,
        parse_pe_rich_header,
        check_pe_signature,
        detect_pe_overlay,
        enumerate_pe_resources,
        analyze_pe_exports,
        parse_pe_debug_directory,
        analyze_pe_relocations,
        extract_named_objects,
        compute_section_entropy_profile,
        compute_ngram_fingerprint,
        scan_crypto_constants,
    )

    fmt = detect_binary_format(path)
    size = os.path.getsize(path)
    arch = "unknown"
    entropy_profile = None
    ngram_fp = None
    crypto_hits = None
    section_analysis = None
    import_anomalies = None

    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError:
        raw = b""

    if raw:
        if fmt == "PE":
            arch = _extract_pe_arch(raw)
            section_analysis = analyze_pe_sections(raw)
        elif fmt == "ELF":
            arch = _extract_elf_arch(raw)
        sample = raw[:2_097_152] if len(raw) > 2_097_152 else raw
        entropy_profile = compute_section_entropy_profile(sample)
        ngram_fp = compute_ngram_fingerprint(sample)
        crypto_hits = scan_crypto_constants(sample)
        strings = _extract_ascii_strings(raw)
        import_anomalies = analyze_import_table_anomalies(strings)

    result = {
        "format": fmt,
        "size": size,
        "arch": arch,
        "strings": [],
        "dangerous": [],
    }
    if entropy_profile:
        result["entropy"] = entropy_profile
        if entropy_profile["high_window_ratio"] > _SUSPICIOUS_ENTROPY_RATIO:
            result["suspicious_packing"] = True
    if ngram_fp:
        result["ngram_fingerprint"] = ngram_fp
        if ngram_fp["unique_ngram_ratio"] < 0.02 and len(raw) > 1024:
            result["repetitive_structure"] = True
    if crypto_hits:
        result["crypto_constants"] = crypto_hits
        result["crypto_algorithms"] = sorted(set(h["algorithm"] for h in crypto_hits))
    if section_analysis:
        result["section_analysis"] = section_analysis
        if section_analysis["wxe_violations"] > 0:
            result["wxe_warning"] = (
                f"检测到 {section_analysis['wxe_violations']} 个可写可执行节区，"
                "可能为自修改代码或 shellcode 执行"
            )
    if import_anomalies and import_anomalies.get("likely_hashed_imports"):
        result["import_anomaly"] = import_anomalies

    if strings:
        net_iocs = extract_network_iocs(strings)
        if net_iocs["total"] > 0:
            result["network_iocs"] = net_iocs

    if raw:
        shellcode = detect_shellcode_patterns(raw)
        if shellcode["patterns_found"]:
            result["shellcode_analysis"] = shellcode

    if raw:
        hashing = detect_api_hashing(raw)
        if hashing["likely_api_hashing"]:
            result["api_hashing"] = hashing

    if raw and entropy_profile:
        xor_result = detect_xor_obfuscated_strings(raw, entropy_profile)
        if xor_result["xor_obfuscation_likely"]:
            result["xor_obfuscation"] = xor_result

    if raw and fmt == "ELF":
        elf_seg = analyze_elf_segments(raw)
        if elf_seg["segments"]:
            result["elf_segments"] = elf_seg
            if elf_seg["needed"]:
                result["elf_needed_libs"] = elf_seg["needed"]
            if elf_seg["interp"]:
                result["elf_interp"] = elf_seg["interp"]
            wxe_segments = [s for s in elf_seg["segments"] if s.get("is_wxe")]
            if wxe_segments:
                result["elf_wxe_warning"] = f"检测到 {len(wxe_segments)} 个可写可执行 PT_LOAD 段"
            if elf_seg["has_gnu_stack"] and elf_seg["gnu_stack_exec"]:
                result["elf_exec_stack"] = True

    if raw and fmt == "PE":
        rich = parse_pe_rich_header(raw)
        if rich:
            result["rich_header"] = rich

        sig_info = check_pe_signature(raw)
        result["signature"] = sig_info
        if not sig_info["signed"]:
            result["unsigned"] = True

        overlay_info = detect_pe_overlay(raw)
        if overlay_info["has_overlay"]:
            result["overlay"] = overlay_info

        res_info = enumerate_pe_resources(raw)
        if res_info["total_resources"] > 0:
            result["resources"] = res_info
            if res_info["embedded_pe"]:
                result["embedded_pe_in_resources"] = True
                result["embedded_pe_details"] = res_info["embedded_pe"]

        exp_info = analyze_pe_exports(raw)
        if exp_info["export_count"] > 0:
            result["export_table"] = exp_info
            if exp_info["suspicious_patterns"]:
                result["suspicious_exports"] = True

        debug_info = parse_pe_debug_directory(raw)
        if debug_info["has_debug"]:
            result["debug_directory"] = debug_info
            if debug_info["info_leak_risk"]:
                result["pdb_path_leak"] = True

        reloc_info = analyze_pe_relocations(raw)
        if not reloc_info["aslr_compatible"]:
            result["no_aslr"] = True
            result["relocation_info"] = reloc_info
        elif reloc_info["suspicious_large_relocs"]:
            result["relocation_info"] = reloc_info

    if strings:
        named_objs = extract_named_objects(strings)
        if named_objs["total"] > 0:
            result["named_objects"] = named_objs

    return result


def get_language_specific_dangerous_functions(lang):
    """按语言返回危险函数列表，当前仅支持 C/C++。"""
    if lang == "c" or lang == "c++":
        return list(DANGEROUS_FUNCTIONS)
    return []


def validate_elf_file(path):
    """验证偏移 0 处的 ELF 魔数。"""
    if not os.path.exists(path):
        return False
    with open(path, "rb") as f:
        return f.read(4) == b"\x7fELF"

def get_language_specific_dangerous_functions(lang): return []

def get_language_analysis_hints(lang): return []

# 占位符号表——由语言特定插件在集成时扩展
GO_SYMBOLS = []

RUST_SYMBOLS = []

GO_SECTIONS = []

RUST_SECTIONS = []

GO_DANGEROUS_FUNCTIONS = []

RUST_DANGEROUS_FUNCTIONS = []
