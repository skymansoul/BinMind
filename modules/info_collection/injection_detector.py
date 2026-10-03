import os as _os

# 注入技术签名映射：(触发字符串, 分类标签)
_INJ_PATS = (
    ('VirtualAlloc',       'Code Injection'),
    ('WriteProcessMemory', 'Process Injection'),
    ('CreateRemoteThread', 'Thread Injection'),
    ('VirtualProtect',     'Memory Protection Change'),
    ('LoadLibrary',        'DLL Injection'),
    ('GetProcAddress',     'API Resolution'),
    ('ShellExecute',       'Command Execution'),
    ('system(',            'System Command'),
    ('execvp',             'Process Execution'),
    ('WinExec',            'Windows Execution'),
)

def detect_injection(f_path, f_outdir=None):
    """扫描二进制文件中与注入相关的 API 字符串引用。

    返回 {'success': bool, 'injection_points': list, 'report_path': str|None}
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

        pi = 0
        pn = len(_INJ_PATS)
        while pi < pn:
            pat, ptype = _INJ_PATS[pi]
            if pat in content:
                points.append({
                    'location': f'contains {pat}',
                    'type': ptype,
                    'risk': 'Medium',
                })
            pi += 1

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
                    fh.write(f"  Risk: {p['risk']}\n\n")
                    qi += 1

        return {
            'success': True,
            'injection_points': points,
            'report_path': rpt,
        }

    except Exception as _e:
        return {'success': False, 'error': str(_e)}
