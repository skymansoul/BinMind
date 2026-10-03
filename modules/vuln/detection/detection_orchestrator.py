"""检测编排器 - 统一调度新旧检测器, 合并去重, 标准化输出。"""
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Any


@dataclass
class UnifiedFinding:
    finding_id: str
    vuln_type: str
    location: str
    confidence: str
    source_detector: str
    details: Dict[str, Any] = field(default_factory=dict)
    severity: str = "medium"


def _fid(vt, loc):
    return hashlib.md5(f"{vt}:{loc}".encode()).hexdigest()[:12]


def _dedup(findings):
    seen = {}
    co = {"confirmed": 4, "likely": 3, "possible": 2, "low_confidence": 1}
    for f in findings:
        k = (f.vuln_type, f.location)
        if k not in seen or co.get(f.confidence, 0) > co.get(seen[k].confidence, 0):
            seen[k] = f
    res = list(seen.values())
    res.sort(key=lambda f: co.get(f.confidence, 0), reverse=True)
    return res


def _severity(vt, conf):
    base = {"heap_overflow": "high", "uaf": "high", "format_string": "high",
            "stack_overflow": "high", "integer_overflow": "medium"}
    return "low" if conf == "low_confidence" else base.get(vt, "medium")


def _disasm(path):
    try:
        from modules.vuln.detection.binary_loader import load_text_section
        result = load_text_section(path)
        if result:
            code, vaddr = result
        else:
            import capstone
            with open(path, "rb") as f:
                code = f.read()[:0x10000]
            vaddr = 0x1000
        import capstone
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        return [f"{i.mnemonic} {i.op_str}" for i in md.disasm(code, vaddr)]
    except Exception:
        return None


def _get_import_names(binary_path: str) -> set:
    """提取二进制的所有导入函数名集合。用于检测器做模式匹配。"""
    try:
        from modules.vuln.detection.plt_resolver import resolve_imports
        imports = resolve_imports(binary_path)
        return set(imports.values())
    except ImportError:
        return set()


def _resolve_calls(instructions: list, binary_path: str) -> list:
    """将call 0xABCD替换为call 函数名（若导入表中有映射）。"""
    try:
        from modules.vuln.detection.plt_resolver import resolve_imports
        imports = resolve_imports(binary_path)
        if not imports: return instructions
        import re
        resolved = []
        for insn in instructions:
            m = re.search(r'0x([0-9a-fA-F]+)', insn)
            if m and int(m.group(1), 16) in imports:
                resolved.append(f'call {imports[int(m.group(1), 16)]}')
            else:
                resolved.append(insn)
        return resolved
    except ImportError:
        return instructions


def run_all_detectors(binary_path, enable_obfuscation_check=True):
    findings = []
    insns = _disasm(binary_path)
    if not insns:
        return findings
    insns = _resolve_calls(insns, binary_path)
    import_names = _get_import_names(binary_path)
    # 导入能力标记：基于导入表推断二进制具有哪些漏洞类型的风险
    heap_danger = {'malloc', 'calloc', 'realloc', 'free', 'memcpy', 'memmove',
                   'strcpy', 'strncpy', 'gets', 'HeapAlloc', 'VirtualAlloc'}
    fmt_danger = {'printf', 'fprintf', 'sprintf', 'snprintf', 'syslog', 'vprintf'}
    uaf_danger = {'free', 'delete', 'realloc', 'HeapFree', 'VirtualFree'}
    has_heap_ops = bool(import_names & heap_danger)
    has_fmt_ops = bool(import_names & fmt_danger)
    has_uaf_ops = bool(import_names & uaf_danger)

    reliability = 1.0
    if enable_obfuscation_check:
        try:
            from modules.vuln.detection.obfuscation_resilience import detect_obfuscation
            reliability = detect_obfuscation().overall_reliability
        except ImportError:
            pass

    try:
        from modules.vuln.detection.heap_overflow_detector import detect_heap_overflow
        for hf in detect_heap_overflow(insns):
            conf = hf.confidence if reliability >= 0.4 else "low_confidence"
            findings.append(UnifiedFinding(
                finding_id=_fid("heap_overflow", hf.location),
                vuln_type="heap_overflow", location=hf.location, confidence=conf,
                source_detector="heap_overflow_detector",
                details={"alloc": hf.alloc_func, "write": hf.write_func,
                         "bytes": hf.overflow_bytes}))
    except ImportError:
        pass

    try:
        from modules.vuln.detection.uaf_detector import detect_uaf
        for uf in detect_uaf(insns):
            conf = uf.confidence if reliability >= 0.4 else "low_confidence"
            findings.append(UnifiedFinding(
                finding_id=_fid("uaf", uf.location),
                vuln_type="uaf", location=uf.location, confidence=conf,
                source_detector="uaf_detector",
                details={"ptr": uf.dangling_pointer, "gap": uf.instruction_gap}))
    except ImportError:
        pass

    try:
        from modules.vuln.detection.format_string_detector import detect_format_string
        for ff in detect_format_string(insns):
            conf = ff.confidence if reliability >= 0.4 else "low_confidence"
            findings.append(UnifiedFinding(
                finding_id=_fid("format_string", ff.location),
                vuln_type="format_string", location=ff.location, confidence=conf,
                source_detector="format_string_detector",
                details={"func": ff.format_func, "pct_n": ff.pct_n_available}))
    except ImportError:
        pass

    # 导入能力检测: 基于导入表的快速风险标记
    if has_heap_ops and 'malloc' in import_names and ('memcpy' in import_names or 'strcpy' in import_names):
        findings.append(UnifiedFinding(
            finding_id=_fid('heap_capability', 'import_table'),
            vuln_type='heap_overflow', location='import_table',
            confidence='possible', source_detector='import_capability',
            details={'imports': sorted(import_names & heap_danger)},
            severity='medium'))
    if has_uaf_ops and 'free' in import_names:
        findings.append(UnifiedFinding(
            finding_id=_fid('uaf_capability', 'import_table'),
            vuln_type='uaf', location='import_table',
            confidence='possible', source_detector='import_capability',
            details={'imports': sorted(import_names & uaf_danger)},
            severity='medium'))
    if has_fmt_ops and any(f in import_names for f in ('printf','sprintf','fprintf')):
        findings.append(UnifiedFinding(
            finding_id=_fid('fmt_capability', 'import_table'),
            vuln_type='format_string', location='import_table',
            confidence='possible', source_detector='import_capability',
            details={'imports': sorted(import_names & fmt_danger)},
            severity='low'))

    for f in findings:
        f.severity = _severity(f.vuln_type, f.confidence)
    return _dedup(findings)


def detect_vulnerabilities(binary_path):
    """外部入口: 返回 UnifiedFinding 列表"""
    return run_all_detectors(binary_path)
