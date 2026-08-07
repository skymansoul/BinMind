# EDK2/Tianocore固件缺陷扫描
# 自动检测UEFI固件EDK2源码/产物中的已知缺陷
#
#   "Uncovering EDK2 Firmware Flaws"
#     — Coverity/SonarQube/CodeQL审计EDK2仓库，200+缺陷
#     分类：内存安全(35%)、并发缺陷(18%)、整数问题(15%)、资源泄漏(12%)、逻辑错误(10%)、其他(10%)
#   UEFI Forum "EDK II Secure Coding Guide" (Rev 2.1)
#   "UEFI Vulnerability Signature Generation" (arXiv 2407.07166)

import os, re
import logging
from dataclasses import dataclass, field
from typing import Optional

_log = logging.getLogger(__name__)


# EDK2内存分配函数 — 对应FreePool常被遗漏
_EDK2_ALLOC_FUNCS = [
    "AllocatePool", "AllocateZeroPool", "AllocateCopyPool",
    "AllocateRuntimePool", "AllocateRuntimeZeroPool",
    "AllocateReservedPool", "AllocateReservedZeroPool",
    "AllocatePages", "AllocateRuntimePages", "AllocateReservedPages",
    "ReallocatePool", "ReallocateRuntimePool", "ReallocateReservedPool",
]

_EDK2_FREE_FUNCS = [
    "FreePool", "FreePages", "FreeRuntimePool", "FreeReservedPool",
]

# EDK2不安全字符串函数（应替换为StrCpyS/StrCatS安全版本）
_EDK2_UNSAFE_STR_FUNCS = [
    "AsciiStrCpy", "AsciiStrCat", "AsciiStrnCpy", "AsciiStrnCat",
    "StrCpy", "StrCat", "StrnCpy", "StrnCat",
    "UnicodeStrCpy", "UnicodeStrCat",
    "sprintf", "vsprintf", "strcpy", "strcat",
]

# 整型溢出候选宏 — 旧版本缺乏溢出检查
_EDK2_INTEGER_OVERFLOW_MACROS = [
    "EFI_SIZE_TO_PAGES", "EFI_PAGES_TO_SIZE",
    "ALIGN_VALUE", "ALIGN_VARIABLE",
]

# SMM专属缺陷 — 参考arXiv 2407.07166符号执行方法
_SMM_VULN_PATTERNS = [
    {
        "id": "EDK2-SMM-001",
        "pattern": re.compile(
            r'(?:CopyMem|SetMem|ZeroMem|CompareMem|GuidedExtract|GuidedHash)\s*\([^)]*\bCommBuffer\b[^)]*\)',
            re.IGNORECASE
        ),
        "title": "CommBuffer 直接传递给 Mem 函数且无长度验证",
        "cwe": "CWE-120",
        "severity": "Critical",
    },
    {
        "id": "EDK2-SMM-002",
        "pattern": re.compile(
            r'(?:SmmIsBufferOutsideSmmValid|SmmIsCommunicateBufferValid)\s*\([^)]*\)\s*;'
            r'\s*(?://.*\n\s*)?(?:return\s+EFI_ACCESS_DENIED|goto\s+\w+)',
            re.IGNORECASE
        ),
        "title": "验证检查后缺少立即 return/goto — 可能 fall-through",
        "cwe": "CWE-670",
        "severity": "High",
    },
    {
        "id": "EDK2-SMM-003",
        "pattern": re.compile(
            r'SmmRegisterHandler\s*\(\s*([^,]+)\s*,',
            re.IGNORECASE
        ),
        "title": "SmmRegisterHandler 的 HandlerType 未验证",
        "cwe": "CWE-20",
        "severity": "Medium",
    },
]


@dataclass
class EDK2Flaw:
    flaw_id: str
    cwe: str
    severity: str
    title: str = ""
    file_path: str = ""
    line_number: int = 0
    snippet: str = ""
    recommendation: str = ""
    reference: str = ""


class EDK2FlawScanner:
    """EDK2固件源码缺陷扫描引擎。

    arXiv 2409.14416揭示EDK2仓库200+静态分析可检测缺陷。
    本扫描器覆盖高优先级子集：内存泄漏、缓冲区溢出、SMM逻辑缺陷、
    整数溢出、并发竞态。

    属性：
        source_dir: EDK2源码根目录（或单个.c/.h/.inf/.dsc文件）
        rules_active: 启用的规则集
        findings: 累积缺陷列表
    """

    def __init__(self, source_path: str, rules_active: list[str] | None = None):
        self.source_path = source_path
        self.findings: list[EDK2Flaw] = []
        self._active = rules_active or ["memory_leak", "unsafe_string", "integer_overflow",
                                         "smm_vuln", "concurrency", "resource_leak"]
        self._scan_files: list[str] = []
        self._gather_targets()

    def _gather_targets(self):
        if os.path.isfile(self.source_path):
            self._scan_files = [self.source_path]
            return
        for dirpath, _, fnames in os.walk(self.source_path):
            for fn in fnames:
                if fn.endswith((".c", ".h", ".inf", ".dsc", ".fdf", ".asl", ".aslc")):
                    self._scan_files.append(os.path.join(dirpath, fn))
        if not self._scan_files:
            _log.info("EDK2 scanner: no source files found in %s", self.source_path)
        elif len(self._scan_files) < 10:
            _log.info("EDK2 scanner: %d source files", len(self._scan_files))
        # 文件数多，跳过日志

    def scan(self) -> list[EDK2Flaw]:
        for fpath in self._scan_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                    lines = fh.readlines()
            except (OSError, UnicodeDecodeError):
                continue
            file_basename = os.path.basename(fpath)
            if "memory_leak" in self._active:
                self._scan_memory_leak(fpath, lines)
            if "unsafe_string" in self._active:
                self._scan_unsafe_string(fpath, lines)
            if "integer_overflow" in self._active:
                self._scan_integer_overflow(fpath, lines)
            if "smm_vuln" in self._active:
                self._scan_smm_patterns(fpath, lines)
            if "concurrency" in self._active:
                self._scan_concurrency(fpath, lines)
            if "resource_leak" in self._active:
                self._scan_resource_leak(fpath, lines)
        self.findings.sort(key=lambda f: (
            0 if f.severity == "Critical" else 1 if f.severity == "High" else 2,
            f.file_path))
        _log.info("EDK2 scan complete: %d findings", len(self.findings))
        return self.findings

    def _scan_memory_leak(self, path: str, lines: list[str]):
        for i, line in enumerate(lines, 1):
            for af in _EDK2_ALLOC_FUNCS:
                if af + " (" in line or af + "(" in line:
                    # 检查同函数内是否有对应FreePool（简化：扫描后100行）
                    freed = False
                    end = min(i + 99, len(lines))
                    for j in range(i, end):
                        for ff in _EDK2_FREE_FUNCS:
                            if ff + " (" in lines[j] or ff + "(" in lines[j]:
                                freed = True
                                break
                        if freed:
                            break
                    if not freed:
                        self.findings.append(EDK2Flaw(
                            flaw_id="EDK2-MEM-001", cwe="CWE-401",
                            severity="High",
                            title=f"Allocate without Free: {af} at line {i}",
                            file_path=path, line_number=i,
                            snippet=line.strip()[:120],
                            recommendation=f"Ensure every {af} has a corresponding FreePool/FreePages in all exit paths",
                            reference="arXiv 2409.14416 (Memory safety: 35% of EDK2 flaws)"
                        ))

    def _scan_unsafe_string(self, path: str, lines: list[str]):
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if line_stripped.startswith("//") or line_stripped.startswith("/*"):
                continue
            for uf in _EDK2_UNSAFE_STR_FUNCS:
                if uf + " (" in line_stripped or uf + "(" in line_stripped:
                    # 跳过已注释行
                    self.findings.append(EDK2Flaw(
                        flaw_id="EDK2-STR-001", cwe="CWE-120",
                        severity="Medium",
                        title=f"Unsafe string function: {uf}",
                        file_path=path, line_number=i,
                        snippet=line_stripped[:120],
                        recommendation=f"Replace {uf} with safe variant (StrCpyS/AsciiStrCpyS)",
                        reference="EDK II Secure Coding Guide Section 4.3"
                    ))

    def _scan_integer_overflow(self, path: str, lines: list[str]):
        for i, line in enumerate(lines, 1):
            for macro in _EDK2_INTEGER_OVERFLOW_MACROS:
                if macro in line:
                    self.findings.append(EDK2Flaw(
                        flaw_id="EDK2-INT-001", cwe="CWE-190",
                        severity="Medium",
                        title=f"Potential integer overflow via macro: {macro}",
                        file_path=path, line_number=i,
                        snippet=line.strip()[:120],
                        recommendation="Use SafeIntLib or EDK2 BaseLib overflow-checked variants",
                        reference="arXiv 2409.14416 (Integer issues: 15% of EDK2 flaws)"
                    ))

    def _scan_smm_patterns(self, path: str, lines: list[str]):
        combined = "\n".join(lines)
        for rule in _SMM_VULN_PATTERNS:
            for m in rule["pattern"].finditer(combined):
                lineno = combined[:m.start()].count("\n") + 1
                self.findings.append(EDK2Flaw(
                    flaw_id=rule["id"], cwe=rule["cwe"],
                    severity=rule["severity"],
                    title=rule["title"],
                    file_path=path, line_number=lineno,
                    snippet=m.group(0)[:120],
                    recommendation="See arXiv 2407.07166 for symbolic-execution-based fix generation",
                    reference="arXiv 2407.07166 (UEFI Vuln Signature Generation)"
                ))

    def _scan_concurrency(self, path: str, lines: list[str]):
        # 检测EDK2中无锁保护的共享变量
        # 启发式：全局变量 + TPL提升 + 无SpinLock
        has_spinlock = any("SpinLock" in l or "AcquireLock" in l for l in lines)
        has_global_var = any(l.strip().startswith("STATIC ") or l.strip().startswith("UINTN ")
                             for l in lines)
        if has_global_var and not has_spinlock:
            for i, line in enumerate(lines, 1):
                if "EFI_TPL" in line or "TPL_" in line:
                    self.findings.append(EDK2Flaw(
                        flaw_id="EDK2-CONC-001", cwe="CWE-362",
                        severity="Low",
                        title="TPL manipulation in file without SpinLock usage",
                        file_path=path, line_number=i,
                        snippet=line.strip()[:120],
                        recommendation="Add SpinLock or ensure operations are atomic at the given TPL",
                        reference="arXiv 2409.14416 (Concurrency: 18% of EDK2 flaws)"
                    ))
                    break

    def _scan_resource_leak(self, path: str, lines: list[str]):
        # 检测OpenProtocol后缺少CloseProtocol
        has_open_proto = any("OpenProtocol" in l for l in lines)
        has_close_proto = any("CloseProtocol" in l for l in lines)
        if has_open_proto and not has_close_proto:
            for i, line in enumerate(lines, 1):
                if "OpenProtocol" in line:
                    self.findings.append(EDK2Flaw(
                        flaw_id="EDK2-RES-001", cwe="CWE-404",
                        severity="Low",
                        title="OpenProtocol without corresponding CloseProtocol",
                        file_path=path, line_number=i,
                        snippet=line.strip()[:120],
                        recommendation="Call gBS->CloseProtocol in all exit paths",
                        reference="UEFI Driver Writer's Guide 10.2"
                    ))


def scan_edk2_source(source_path: str, rules: list[str] | None = None) -> list[EDK2Flaw]:
    scanner = EDK2FlawScanner(source_path, rules_active=rules)
    return scanner.scan()
