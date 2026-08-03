"""注入技术检测 — API 字符串引用 + 邻接上下文加权 + PE 节区感知 + YARA 规则生成。"""
import os as _os
import struct as _st
from datetime import datetime

# 注入技术签名映射：(触发字符串, 分类标签, 权重)
# 权重依据：API 在注入链中的位置 — 越接近执行入口权重越高
_INJ_PATS = (
    ('VirtualAllocEx',       'Code Injection',         0.9),
    ('VirtualAlloc',         'Code Injection',         0.7),
    ('WriteProcessMemory',   'Process Injection',      0.8),
    ('CreateRemoteThread',   'Thread Injection',       0.9),
    ('NtCreateThreadEx',     'Thread Injection',       0.9),
    ('VirtualProtect',       'Memory Protection Change',0.6),
    ('VirtualProtectEx',     'Memory Protection Change',0.7),
    ('LoadLibrary',          'DLL Injection',          0.6),
    ('GetProcAddress',       'API Resolution',         0.4),
    ('ShellExecute',         'Command Execution',      0.7),
    ('system(',              'System Command',         0.6),
    ('execvp',               'Process Execution',      0.6),
    ('WinExec',              'Windows Execution',      0.7),
    ('CreateProcess',        'Process Creation',       0.5),
    ('NtUnmapViewOfSection', 'Process Hollowing',      0.8),
    ('SetThreadContext',     'Thread Hijack',          0.8),
    ('ResumeThread',         'Thread Hijack',          0.7),
    ('QueueUserAPC',         'APC Injection',          0.8),
    ('SetWindowsHookEx',     'Hook Injection',         0.7),
)

# 在 PE 可执行节区内命中可获得额外风险加成
_EXEC_SECTION_NAMES = {b'.text', b'CODE', b'.code', b'INIT'}

# 反分析技术签名
# 参照 wshobson/anti-reversing-techniques (35K★) 的反调试/反VM 分类体系。
# 三类检测：调试器检测、VM/Sandbox 检测、时序检测。
_ANTI_ANALYSIS_PATS: tuple[tuple[str, str, float], ...] = (
    # 调试器检测
    ('IsDebuggerPresent',        'Anti-Debug',        0.7),
    ('CheckRemoteDebuggerPresent','Anti-Debug',        0.7),
    ('NtQueryInformationProcess','Anti-Debug',        0.5),
    ('NtGlobalFlag',             'Anti-Debug',        0.6),
    ('DbgBreakPoint',            'Anti-Debug',        0.6),
    ('OutputDebugStringA',       'Anti-Debug',        0.5),
    ('BeingDebugged',            'Anti-Debug',        0.8),
    # VM/Sandbox 检测
    ('cpuid',                    'Anti-VM',           0.4),
    ('vmware',                   'Anti-VM',           0.7),
    ('VBox',                     'Anti-VM',           0.7),
    ('QEMU',                     'Anti-VM',           0.7),
    ('Red Pill',                 'Anti-VM',           0.9),
    ('\\\\.\\VBoxGuest',         'Anti-VM',           0.9),
    ('sandbox',                  'Anti-Sandbox',      0.6),
    ('Cuckoo',                   'Anti-Sandbox',      0.7),
    # 时序检测 — 通过短时间差判断是否被加速/暂停
    ('QueryPerformanceCounter',  'Timing Check',      0.4),
    ('GetTickCount',             'Timing Check',      0.4),
    ('rdtsc',                    'Timing Check',      0.6),
    ('NtDelayExecution',         'Timing Check',      0.3),
)


def _parse_pe_section_bounds(raw: bytes) -> list[tuple[int, int, bytes]]:
    """PE 节区表解析：返回 (va_start, va_end_bytes, name) 列表。"""
    if len(raw) < 64 or raw[:2] != b'MZ':
        return []
    try:
        pe_off = _st.unpack_from("<I", raw, 0x3C)[0]
        num_sections = _st.unpack_from("<H", raw, pe_off + 6)[0]
        opt_hdr_size = _st.unpack_from("<H", raw, pe_off + 20)[0]
        sec_start = pe_off + 24 + opt_hdr_size
        sections = []
        for i in range(num_sections):
            off = sec_start + i * 40
            name = raw[off:off + 8].rstrip(b'\x00')
            vsize = _st.unpack_from("<I", raw, off + 8)[0]
            vaddr = _st.unpack_from("<I", raw, off + 12)[0]
            sections.append((vaddr, vaddr + vsize, name))
        return sections
    except Exception:
        return []


def _section_for_rva(sections, rva: int) -> bytes | None:
    for va_start, va_end, name in sections:
        if va_start <= rva < va_end:
            return name
    return None


def _generate_yara_rule_template(points: list[dict], binary_name: str) -> str:
    """从检测到的注入点生成 YARA 规则。

    参照 yarGen 的规则结构：meta 含生成时间/置信度，strings 以检测到的
    注入 API 为锚点，condition 使用 any of them。
    标注为 template — 需人工审核后部署。
    """
    if not points:
        return ""
    unique_apis = sorted(set(p['type'] for p in points[:20]))
    safe_name = ''.join(c if c.isalnum() else '_' for c in binary_name)

    lines = [
        "/*",
        " * YARA rule template — 需人工审核后部署",
        f" * 生成时间: {datetime.now().isoformat()}",
        f" * 源文件: {binary_name}",
        f" * 检测到的注入技术: {len(points)} 种",
        " */",
        "",
        f"rule Injection_{safe_name}",
        "{",
        "    meta:",
        '        author = "BinMind Injection Detector"',
        f'        date = "{datetime.now().strftime("%Y-%m-%d")}"',
        '        category = "injection"',
        '        confidence = "medium"',
        f'        injection_types = "{", ".join(unique_apis[:8])}"',
        "",
        "    strings:",
    ]
    # 每个注入 API 作为一条 string，wide+ascii 双模式
    seen = set()
    idx = 0
    for p in points[:15]:
        api = p['type']
        if api in seen:
            continue
        seen.add(api)
        lines.append(f'        $s{idx} = "{api}" wide ascii')
        idx += 1

    lines.append("")
    lines.append("    condition:")
    lines.append(f"        uint16(0) == 0x5A4D and any of ({'$s*' if idx > 0 else 'false'})")
    lines.append("}")

    return "\n".join(lines)


def detect_injection(f_path=None, f_outdir=None):
    """扫描二进制文件中与注入相关的 API 字符串引用。

    增强点：
    - 邻接上下文评分：同一 API 出现密度高则置信度递增
    - PE 节区感知：位于可执行节的命中获得额外风险加成
    - YARA 规则自动生成（输出到 f_outdir）
    """
    if f_path is None:
        return {'success': False, 'error': 'path is None'}
    if not _os.path.isfile(f_path):
        return {'success': False, 'error': f'file not found: {f_path}'}

    try:
        points = []

        with open(f_path, 'rb') as fh:
            raw = fh.read()
        content = raw.decode('latin-1', errors='ignore')
        sections = _parse_pe_section_bounds(raw)

        # 跟踪每条签名的命中位置，用于密度评分
        hit_positions: list[tuple[int, str, float]] = []

        pi = 0
        pn = len(_INJ_PATS)
        while pi < pn:
            pat, ptype, base_weight = _INJ_PATS[pi]
            pos = -1
            while True:
                pos = content.find(pat, pos + 1)
                if pos == -1:
                    break
                hit_positions.append((pos, ptype, base_weight))
            pi += 1

        # 反分析模式扫描
        anti_positions: list[tuple[int, str, float]] = []
        ai = 0
        an = len(_ANTI_ANALYSIS_PATS)
        while ai < an:
            apat, atype, aweight = _ANTI_ANALYSIS_PATS[ai]
            apos = -1
            while True:
                apos = content.find(apat, apos + 1)
                if apos == -1:
                    break
                anti_positions.append((apos, atype, aweight))
            ai += 1

        # 按位置排序，计算邻接密度评分
        hit_positions.sort()
        merged = _merge_adjacent_hits(hit_positions, sections, raw)

        # 反分析命中独立聚合（不经邻接评分，因反分析 API 通常单独出现）
        anti_merged: list[dict] = []
        for apos, atype, aweight in anti_positions:
            anti_merged.append({
                'location': f'{atype} @ offset {apos:#x}',
                'type': atype, 'weight': aweight,
                'adjacency_bonus': 0, 'group_size': 1, 'section': None,
            })

        # 按类型聚合（注入 + 反分析）
        type_aggr: dict[str, dict] = {}
        for entry in merged + anti_merged:
            t = entry['type']
            if t not in type_aggr:
                type_aggr[t] = {
                    'location': entry['location'],
                    'type': t,
                    'risk': 'Low',
                    'hit_count': 0,
                    'max_weight': 0.0,
                    'adjacency_bonus': 0,
                }
            rec = type_aggr[t]
            rec['hit_count'] += 1
            rec['max_weight'] = max(rec['max_weight'], entry['weight'])
            rec['adjacency_bonus'] = max(rec['adjacency_bonus'], entry.get('adjacency_bonus', 0))

        for t, rec in type_aggr.items():
            # 综合评分 = 基础权重 x 命中次数因子 + 邻接加成
            density_factor = min(rec['hit_count'] / 3.0, 1.0)
            composite = rec['max_weight'] * (0.6 + 0.4 * density_factor) + rec['adjacency_bonus']
            if composite >= 0.85:
                rec['risk'] = 'High'
            elif composite >= 0.6:
                rec['risk'] = 'Medium'
            elif composite >= 0.35:
                rec['risk'] = 'Low'
            else:
                rec['risk'] = 'Info'
            rec['confidence'] = round(composite, 2)
            points.append(rec)

        # YARA 规则生成
        yara_rule = None
        binary_name = _os.path.basename(f_path) if f_path else "unknown"
        if points:
            yara_rule = _generate_yara_rule_template(points, binary_name)

        rpt = None
        if f_outdir is not None:
            _os.makedirs(f_outdir, exist_ok=True)
            rpt = _os.path.join(f_outdir, 'injection_report.txt')
            with open(rpt, 'w', encoding='utf-8') as fh:
                fh.write("Memory Injection Detection Report\n")
                fh.write("=" * 50 + "\n")
                fh.write(f"Binary: {f_path}\n")
                fh.write(f"Injection Points: {len(points)}\n\n")
                qi = 0
                while qi < len(points):
                    p = points[qi]
                    fh.write(f"- Loc: {p['location']}\n")
                    fh.write(f"  Type: {p['type']}\n")
                    fh.write(f"  Risk: {p['risk']}\n")
                    fh.write(f"  Confidence: {p.get('confidence', 'N/A')}\n\n")
                    qi += 1

            if yara_rule:
                yara_path = _os.path.join(f_outdir, 'injection_rules.yar')
                with open(yara_path, 'w', encoding='utf-8') as fh:
                    fh.write(yara_rule)

        result = {
            'success': True,
            'injection_points': points,
            'report_path': rpt,
        }
        # C2 通信指标 — 检测网络通信 API 以评估注入后的通信能力
        c2_apis = {'socket', 'connect', 'send', 'recv', 'WSASend', 'WSARecv',
                   'InternetOpen', 'InternetConnect', 'HttpOpenRequest',
                   'URLDownloadToFile', 'WinHttpOpen', 'WinHttpConnect',
                   'bind', 'listen', 'accept', 'getaddrinfo'}
        c2_hits = [api for api in c2_apis if api.lower() in content.lower()]
        if c2_hits:
            result['c2_indicators'] = {
                'apis': c2_hits,
                'count': len(c2_hits),
                'has_connectivity': any(
                    x in {s.lower() for s in c2_hits}
                    for x in ('socket', 'connect', 'internetconnect',
                              'winhttpconnect', 'httpopenrequest')
                ),
            }
        if yara_rule:
            result['yara_rule'] = yara_rule
            if f_outdir:
                result['yara_rule_path'] = _os.path.join(f_outdir, 'injection_rules.yar')
        return result

    except Exception as _e:
        return {'success': False, 'error': str(_e)}


def _merge_adjacent_hits(
    positions: list[tuple[int, str, float]],
    sections: list,
    raw: bytes,
    window: int = 512,
) -> list[dict]:
    """合并邻接命中：同一窗口内多个注入 API 命中 → 邻接加成。

    窗口定义 [pos, pos + window)，同一窗口内每多一个不同类注入 API，
    该窗口内所有命中 +0.05 加成。可执行节区命中额外 +0.1。
    """
    if not positions:
        return []
    merged: list[dict] = []
    i, n = 0, len(positions)
    while i < n:
        pos, ptype, weight = positions[i]
        window_end = pos + window
        group_types = {ptype}
        j = i + 1
        while j < n and positions[j][0] < window_end:
            group_types.add(positions[j][1])
            j += 1
        group_size = j - i
        bonus = (group_size - 1) * 0.05 if group_size > 1 else 0
        sec_name = _section_for_rva(sections, pos) if sections else None
        sec_bonus = 0.1 if sec_name and sec_name in _EXEC_SECTION_NAMES else 0

        for k in range(i, j):
            mpos, mtype, mweight = positions[k]
            merged.append({
                'location': f'{mtype} @ offset {mpos:#x}',
                'type': mtype,
                'weight': mweight,
                'adjacency_bonus': round(bonus + sec_bonus, 2),
                'group_size': group_size,
                'section': sec_name.decode('ascii', errors='replace') if sec_name else None,
            })
        i = j
    return merged
