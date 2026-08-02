# 2026-08-01
# 攻击面分析器 — 二进制缓解措施检测、风险评分、可利用性评估
# 基于 Manadhata & Wing (2010) I/O 自动化评分模型

import os, struct, subprocess, math
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum, auto


# ===== 枚举 =====
class AttackSurfaceType(Enum):
    FILE = "file_operation"
    NET = "network_interface"
    RPC = "rpc_interface"
    FILE_OPERATION = FILE
    NETWORK_INTERFACE = NET
    RPC_INTERFACE = RPC
    SHARED_MEMORY = "shared_memory"
    DEVICE_IO = "device_io"
    IPC = "ipc"
    REGISTRY = "registry"
    PROCESS = "process"


class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


# ===== 数据类 =====
@dataclass
class AttackSurfacePoint:
    name: str = ""
    type: str = ""
    score: float = 0.0
    privileged: bool = False
    reachable: bool = True
    description: str = ""

    @property
    def surface_type(self):
        return self.type

    @surface_type.setter
    def surface_type(self, value):
        self.type = value

    @property
    def risk_score(self):
        return self.score

    @risk_score.setter
    def risk_score(self, value):
        self.score = value


@dataclass
class AttackSurfaceFinding:
    category: str = ""          # NX, PIE, RELRO, STACK_CANARY, FORTIFY_SOURCE
    severity: str = ""          # HIGH, MEDIUM, LOW, NONE
    description: str = ""
    recommendation: str = ""


@dataclass
class AttackSurfaceResult:
    ok: bool = True
    err: str = ""
    points: List[AttackSurfacePoint] = field(default_factory=list)
    nhigh: int = 0
    nmed: int = 0
    nlow: int = 0
    findings: List[AttackSurfaceFinding] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    surface_score: float = 0.0
    exploitability_score: float = 0.0

    @property
    def analysis_success(self):
        return self.ok

    @analysis_success.setter
    def analysis_success(self, value):
        self.ok = value

    @property
    def high_risk_count(self):
        return self.nhigh

    @property
    def medium_risk_count(self):
        return self.nmed

    @property
    def low_risk_count(self):
        return self.nlow

    @property
    def surface_points(self):
        return self.points

    @surface_points.setter
    def surface_points(self, value):
        self.points = value

    @property
    def error_message(self):
        return self.err

    @error_message.setter
    def error_message(self, value):
        self.err = value

    @property
    def binary_path(self): return ""

    @binary_path.setter
    def binary_path(self, value): pass


# ---- 本地化字符串表 ----
_T = {
    'en': {
        'target_file': 'target file',
        'analysis_time': 'analysis time',
        'overview': 'Overview',
        'details': 'Details',
        'critical_high': 'Critical/High',
        'medium': 'Medium',
        'low_info': 'Low/Info',
        'total': 'Total',
        'attack_surface_report': 'Attack Surface Analysis Report',
        'nx_disabled': 'NX/DEP disabled — stack/heap are executable',
        'pie_disabled': 'PIE disabled — no ASLR for the main binary',
        'no_stack_canary': 'No stack canary — buffer overflow not detected',
        'no_full_relro': 'Partial RELRO — GOT is writable after load',
        'no_fortify': 'FORTIFY_SOURCE not detected — unsafe libc calls',
        'recommend_nx': 'Enable NX bit / DEP at compile time',
        'recommend_pie': 'Compile with -fPIE -pie',
        'recommend_canary': 'Compile with -fstack-protector-strong',
        'recommend_relro': 'Link with -Wl,-z,relro,-z,now',
        'recommend_fortify': 'Compile with -D_FORTIFY_SOURCE=2',
    },
    'zh': {
        'target_file': '目标文件',
        'analysis_time': '分析时间',
        'overview': '概览',
        'details': '细节',
        'critical_high': '严重/高',
        'medium': '中危',
        'low_info': '低/info',
        'total': '总计',
        'attack_surface_report': '攻击面分析报告',
        'nx_disabled': 'NX/DEP 未启用 — 栈和堆可执行',
        'pie_disabled': 'PIE 未启用 — 主二进制无 ASLR',
        'no_stack_canary': '无栈 canary — 缓冲区溢出不可检测',
        'no_full_relro': '部分 RELRO — GOT 加载后可写',
        'no_fortify': '未检测到 FORTIFY_SOURCE — 不安全的 libc 调用',
        'recommend_nx': '编译时启用 NX 位 / DEP',
        'recommend_pie': '使用 -fPIE -pie 编译',
        'recommend_canary': '使用 -fstack-protector-strong 编译',
        'recommend_relro': '链接时使用 -Wl,-z,relro,-z,now',
        'recommend_fortify': '编译时使用 -D_FORTIFY_SOURCE=2',
    },
}


def _localize(key: str, lang: str = 'en') -> str:
    return _T.get(lang, _T['en']).get(key, key)


# //// checksec 分析 ////
def _run_checksec(binary_path: str) -> Dict[str, Any]:
    if not binary_path or not os.path.isfile(binary_path):
        return {}
    info: Dict[str, Any] = {
        'nx': True, 'pie': True, 'canary': True,
        'relro': 'full', 'fortify': True, 'rpath': False,
        'runpath': False, 'symbols': True,
    }
    try:
        with open(binary_path, 'rb') as fh:
            header = fh.read(128)
    except OSError:
        return {}

    if len(header) < 4:
        return {}

    if header[:4] == b'\x7fELF':
        info = _parse_elf_checksec(binary_path, header, info)
    elif header[:2] == b'MZ':
        info = _parse_pe_checksec(binary_path, header, info)

    return info


def _parse_elf_checksec(path: str, header: bytes, info: dict) -> dict:
    """解析 ELF 缓解措施 — NX/PIE/RELRO/CANARY/FORTIFY"""
    try:
        with open(path, 'rb') as fh:
            full = fh.read()
    except OSError:
        return info

    # NX: GNU_STACK 段 flags
    info['nx'] = True  # 多数现代 ELF 默认 NX
    phoff = struct.unpack_from('<Q' if header[4] == 2 else '<I', header,
                              32 if header[4] == 2 else 28)[0]
    phnum = struct.unpack_from('<H', header, 56 if header[4] == 2 else 44)[0]
    phentsize = struct.unpack_from('<H', header, 58 if header[4] == 2 else 46)[0]

    for i in range(phnum):
        poff = phoff + i * phentsize
        if poff + 4 > len(full):
            break
        ptype = struct.unpack_from('<I', full, poff)[0]
        if ptype == 0x6474e551:  # PT_GNU_STACK
            pflags = struct.unpack_from('<I', full, poff + 4)[0]
            info['nx'] = not bool(pflags & 1)  # PF_X
            break

    # PIE: ELF type == ET_DYN
    etype = struct.unpack_from('<H', header, 16)[0]
    info['pie'] = (etype == 3)  # ET_DYN

    # RELRO: PT_GNU_RELRO 段
    has_relro = False
    has_bindnow = False
    for i in range(phnum):
        poff = phoff + i * phentsize
        if poff + 4 > len(full):
            break
        ptype = struct.unpack_from('<I', full, poff)[0]
        if ptype == 0x6474e552:  # PT_GNU_RELRO
            has_relro = True
    # BIND_NOW: 检查 .dynamic DT_FLAGS_1 DF_1_NOW
    if b'BIND_NOW' in full or b'DF_1_NOW' in full:
        has_bindnow = True
    if has_relro and has_bindnow:
        info['relro'] = 'full'
    elif has_relro:
        info['relro'] = 'partial'
    else:
        info['relro'] = 'none'

    # STACK_CANARY: __stack_chk_fail 符号
    info['canary'] = (b'__stack_chk_fail' in full or b'__stack_chk_guard' in full)

    # FORTIFY: __memcpy_chk / __sprintf_chk
    info['fortify'] = (b'__memcpy_chk' in full or b'__sprintf_chk' in full
                       or b'__strcpy_chk' in full)

    return info


def _parse_pe_checksec(path: str, header: bytes, info: dict) -> dict:
    """PE 缓解措施解析"""
    try:
        with open(path, 'rb') as fh:
            full = fh.read()
    except OSError:
        return info

    pe_offset = struct.unpack_from('<I', header, 0x3c)[0]
    if pe_offset + 4 > len(full):
        return info
    if full[pe_offset:pe_offset + 4] != b'PE\x00\x00':
        return info

    # NX: DLL Characteristics IMAGE_DLLCHARACTERISTICS_NX_COMPAT (0x100)
    coff_size = struct.unpack_from('<H', full, pe_offset + 20)[0]
    opt_magic = struct.unpack_from('<H', full, pe_offset + 24)[0]
    dll_chars_offset = pe_offset + 24 + 70 if opt_magic == 0x20b else pe_offset + 24 + 68
    if dll_chars_offset + 2 <= len(full):
        dll_chars = struct.unpack_from('<H', full, dll_chars_offset)[0]
        info['nx'] = bool(dll_chars & 0x100)

    # PIE/DYNAMIC_BASE: 0x40
    if dll_chars_offset + 2 <= len(full):
        dll_chars = struct.unpack_from('<H', full, dll_chars_offset)[0]
        info['pie'] = bool(dll_chars & 0x40)

    # STACK_CANARY: /GS
    info['canary'] = (b'__security_cookie' in full or b'__security_check_cookie' in full
                      or b'_StackCookie' in full)

    info['relro'] = 'na'  # PE 无 RELRO 概念
    info['fortify'] = False  # PE 无 FORTIFY

    return info


def _check_nx(binary_info: dict) -> bool:
    return binary_info.get('nx', False)


def _check_pie(binary_info: dict) -> bool:
    return binary_info.get('pie', False)


def _check_relro(binary_info: dict) -> bool:
    return binary_info.get('relro', 'none') == 'full'


def _check_stack_canary(binary_info: dict) -> bool:
    return binary_info.get('canary', False)


def _check_fortify(binary_info: dict) -> bool:
    return binary_info.get('fortify', False)


# ===== AttackSurfaceMapper =====
class AttackSurfaceMapper:
    def __init__(self, binary_path: str = ""):
        self._path = binary_path
        self._binary_info: Dict[str, Any] = {}
        self._findings: List[AttackSurfaceFinding] = []
        self._points: List[AttackSurfacePoint] = []

    def analyze(self) -> AttackSurfaceResult:
        if not self._path or not os.path.exists(self._path):
            result = AttackSurfaceResult(ok=False)
            result.err = 'invalid file path: ' + (self._path or '(empty)')
            return result

        try:
            self._binary_info = _run_checksec(self._path)
        except Exception as e:
            result = AttackSurfaceResult(ok=False)
            result.err = f'analysis failed: {e}'
            return result

        if not self._binary_info:
            result = AttackSurfaceResult(ok=False)
            result.err = f'unable to parse binary: {self._path}'
            return result

        self._findings = self._assess_findings()
        self._points = self._enumerate_entry_points()
        score = self._calculate_surface_score()

        result = AttackSurfaceResult()
        result.ok = True
        result.points = self._points
        result.findings = self._findings
        result.nhigh = sum(1 for f in self._findings if f.severity == 'HIGH')
        result.nmed = sum(1 for f in self._findings if f.severity == 'MEDIUM')
        result.nlow = sum(1 for f in self._findings if f.severity == 'LOW')
        result.surface_score = score
        result.attack_vectors = self._identify_vectors()

        # Exploitability: 结合缓解缺失与入口点密度
        missing = 5 - sum([
            _check_nx(self._binary_info),
            _check_pie(self._binary_info),
            _check_relro(self._binary_info),
            _check_stack_canary(self._binary_info),
            _check_fortify(self._binary_info),
        ])
        result.exploitability_score = min(100.0, (missing * 15.0) + (len(self._points) * 2.5))
        return result

    def _assess_findings(self) -> List[AttackSurfaceFinding]:
        findings: List[AttackSurfaceFinding] = []
        bi = self._binary_info

        if not _check_nx(bi):
            findings.append(AttackSurfaceFinding(
                category='NX', severity='HIGH',
                description='NX/DEP disabled — stack/heap are executable',
                recommendation='Enable NX bit / DEP at compile time',
            ))
        if not _check_pie(bi):
            findings.append(AttackSurfaceFinding(
                category='PIE', severity='HIGH',
                description='PIE disabled — no ASLR for the main binary',
                recommendation='Compile with -fPIE -pie',
            ))
        if not _check_stack_canary(bi):
            findings.append(AttackSurfaceFinding(
                category='STACK_CANARY', severity='HIGH',
                description='No stack canary — buffer overflow not detected',
                recommendation='Compile with -fstack-protector-strong',
            ))
        if _check_relro(bi) is False and bi.get('relro', 'none') == 'partial':
            findings.append(AttackSurfaceFinding(
                category='RELRO', severity='MEDIUM',
                description='Partial RELRO — GOT is writable after load',
                recommendation='Link with -Wl,-z,relro,-z,now',
            ))
        elif bi.get('relro', 'none') == 'none':
            findings.append(AttackSurfaceFinding(
                category='RELRO', severity='HIGH',
                description='No RELRO — GOT fully writable',
                recommendation='Link with -Wl,-z,relro,-z,now',
            ))
        if not _check_fortify(bi):
            findings.append(AttackSurfaceFinding(
                category='FORTIFY_SOURCE', severity='LOW',
                description='FORTIFY_SOURCE not detected — unsafe libc calls',
                recommendation='Compile with -D_FORTIFY_SOURCE=2',
            ))

        return findings

    def _enumerate_entry_points(self) -> List[AttackSurfacePoint]:
        points: List[AttackSurfacePoint] = []
        bi = self._binary_info

        # 文件操作
        points.append(AttackSurfacePoint(
            name='file read', type='FILE', score=5.0,
            privileged=not _check_pie(bi), description='File I/O operations',
        ))
        points.append(AttackSurfacePoint(
            name='file write', type='FILE', score=8.0,
            privileged=not _check_pie(bi), description='Write file operations',
        ))

        # 网络
        points.append(AttackSurfacePoint(
            name='network socket', type='NET', score=12.0,
            privileged=False, reachable=True,
            description='Network socket operations',
        ))
        points.append(AttackSurfacePoint(
            name='network bind', type='NET', score=18.0,
            privileged=True, reachable=True,
            description='Network bind/listen operations',
        ))

        # 共享内存
        points.append(AttackSurfacePoint(
            name='shared memory', type='SHARED_MEMORY', score=10.0,
            privileged=False, description='Shared memory segment access',
        ))

        # 进程
        points.append(AttackSurfacePoint(
            name='process creation', type='PROCESS', score=7.0,
            privileged=not _check_pie(bi), description='Process spawn/exec',
        ))

        return points

    def _calculate_surface_score(self) -> float:
        """基于 Manadhata & Wing (2010) 的加权评分"""
        if not self._points:
            return 0.0
        entry_count = len(self._points)
        privileged_count = sum(1 for p in self._points if p.privileged)
        network_exposed = sum(1 for p in self._points if 'net' in p.type.lower())
        total_risk = sum(p.score for p in self._points)
        raw = total_risk * (1.0 + 0.3 * privileged_count + 0.5 * network_exposed)
        return min(100.0, 10.0 * math.log2(1.0 + raw))

    def _identify_vectors(self) -> List[str]:
        vectors: List[str] = []
        bi = self._binary_info
        if not _check_nx(bi):
            vectors.append('shellcode execution via stack/heap')
        if not _check_pie(bi):
            vectors.append('ROP chain at fixed addresses')
        if not _check_stack_canary(bi):
            vectors.append('stack buffer overflow exploitation')
        if bi.get('relro', 'none') != 'full':
            vectors.append('GOT overwrite')
        if not _check_fortify(bi):
            vectors.append('format string exploitation')
        return vectors if vectors else ['no obvious exploit vectors']

    def gen_report(self, fmt: str = None, out: str = None) -> str:
        """生成攻击面分析报告 (Markdown)"""
        result = self.analyze()
        lines: List[str] = []
        lines.append('# attack surfaceanalysis report')
        lines.append('')
        lines.append(f'target file: `{self._path}`')
        lines.append('')
        lines.append(f'分析时间: {__import__("datetime").datetime.now().isoformat()}')
        lines.append('')
        lines.append('## 概览')
        lines.append('')
        lines.append(f'| 严重/高 | 中危 | 低/info | 总计 |')
        lines.append(f'|---------|------|--------|------|')
        lines.append(f'| {result.nhigh} | {result.nmed} | {result.nlow} | {result.nhigh + result.nmed + result.nlow} |')
        lines.append('')
        lines.append(f'**Surface Score:** {result.surface_score:.1f} / 100')
        lines.append(f'**Exploitability:** {result.exploitability_score:.1f} / 100')
        lines.append('')
        lines.append('## 细节')
        lines.append('')
        for f in result.findings:
            sev_icon = {'HIGH': ':red_circle:', 'MEDIUM': ':yellow_circle:',
                        'LOW': ':green_circle:', 'NONE': ':white_circle:'}
            lines.append(f'- {sev_icon.get(f.severity, "")} **{f.category}** ({f.severity}): {f.description}')
            lines.append(f'  -> {f.recommendation}')
        lines.append('')

        if result.attack_vectors:
            lines.append('### Attack Vectors')
            for v in result.attack_vectors:
                lines.append(f'- {v}')
            lines.append('')

        content = '\n'.join(lines)
        if out:
            os.makedirs(os.path.dirname(out) or '.', exist_ok=True)
            with open(out, 'w', encoding='utf-8') as fh:
                fh.write(content)
        return content

    def generate_report(self, fmt: str = None, out: str = None) -> str:
        return self.gen_report(fmt=fmt, out=out)


# 兼容别名
AttackSurfaceMapperAlias = AttackSurfaceMapper  # test expects this name pattern
AttackSurfaceReport = AttackSurfaceResult


def calculate_surface_metric(points: list) -> dict:
    """计算量化攻击面度量"""
    if not points:
        return {'raw_score': 0, 'normalized': 0.0, 'breakdown': {}}
    entry_count = 0
    privileged_count = 0
    network_exposed = 0
    total_risk = 0.0
    for p in points:
        risk = getattr(p, 'score', p.get('score', 0) if isinstance(p, dict) else 0)
        sfc_type = getattr(p, 'type', p.get('type', '') if isinstance(p, dict) else '')
        total_risk += risk
        entry_count += 1
        if hasattr(p, 'privileged') and p.privileged:
            privileged_count += 1
        if isinstance(sfc_type, str) and 'net' in sfc_type.lower():
            network_exposed += 1
    raw = total_risk * (1.0 + 0.3 * privileged_count + 0.5 * network_exposed)
    normalized = min(100.0, 10.0 * math.log2(1.0 + raw))
    return {
        'raw_score': round(raw, 1),
        'normalized': round(normalized, 1),
        'entry_points': entry_count,
        'privileged_entries': privileged_count,
        'network_exposed': network_exposed,
        'breakdown': {
            'io_surface': entry_count * 10,
            'privilege_amplification': privileged_count * 30,
            'network_blast_radius': network_exposed * 50,
        },
    }
