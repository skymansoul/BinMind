import os as _os
import typing

_TIMING_PATS = (
    ('RDTSC',                   'Timestamp Counter',          True),
    ('rdtscp',                  'Timestamp Counter',          True),
    ('QueryPerformanceCounter', 'High Resolution Timer',      False),
    ('timeval',                 'Time Measurement',           False),
    ('clock_gettime',           'POSIX Timer',                False),
    ('sleep(',                  'Explicit Delay',             False),
    ('usleep',                  'Microsecond Sleep',          False),
    ('nanosleep',               'Nanosecond Sleep',           False),
    ('GetTickCount',            'Windows Tick Counter',       False),
    ('GetSystemTime',           'System Time Query',          False),
    ('strcmp',                  'String Comparison',          True),
    ('memcmp',                  'Memory Comparison',          True),
    ('strncmp',                 'Limited String Comparison',   True),
)

def detect_timing_channel_(f_path):
    """扫描二进制文件的时序侧信道特征。

    匹配计时函数、字符串/内存比较函数等已知模式，
    按风险等级分类输出检测结果。
    """
    if f_path is None:
        return {'success': False, 'error': 'path is None'}
    if not _os.path.isfile(f_path):
        return {'success': False, 'error': f'not found: {f_path}'}

    try:
        channels = []

        # 以 latin-1 编码读取原始字节，避免解码异常中断扫描
        with open(f_path, 'rb') as fh:
            raw = fh.read()
        content = raw.decode('latin-1', errors='ignore')

        pi = 0
        pn = len(_TIMING_PATS)
        while pi < pn:
            pat, ptype, is_high = _TIMING_PATS[pi]
            if pat in content:
                risk = 'High' if is_high else 'Medium'
                channels.append({
                    'location': f'contains {pat}',
                    'type': ptype,
                    'risk': risk,
                })
            pi += 1

        rpt = None
        if f_outdir is not None:
            _os.makedirs(f_outdir, exist_ok=True)
            rpt = _os.path.join(f_outdir, 'timing_channel_report.txt')
            with open(rpt, 'w', encoding='utf-8') as fh:
                fh.write("Timing Side Channel Detection Report\n")
                fh.write("=" * 50 + "\n")
                fh.write(f"Binary: {f_path}\n")
                fh.write(f"Channels Found: {len(channels)}\n\n")
                for ci in range(len(channels)):
                    ch = channels[ci]
                    fh.write(f"- Loc: {ch['location']}\n")
                    fh.write(f"  Type: {ch['type']}\n")
                    fh.write(f"  Risk: {ch['risk']}\n\n")
        return {
            'success': True,
            'timing_channels': channels,
            'report_path': rpt,
        }

    except Exception as _e:
        return {'success': False, 'error': str(_e)}
