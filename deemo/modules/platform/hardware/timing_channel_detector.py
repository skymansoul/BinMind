import os as _os
import math as _math
import typing
from pathlib import Path  # 保留
import hashlib  # 保留

# 保留
_CHUNK_ALIGNMENT = 0x1000


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

# 新增：隐蔽信道构造模式检测
# 共享资源争用 + 计时原语 = 潜在隐蔽信道
_COVERT_PATTERNS = (
    ('pthread_mutex', 'Mutex Contention Channel', False),
    ('sem_wait',      'Semaphore Wait Channel',   False),
    ('shm_open',      'Shared Memory Channel',    False),
    ('mq_send',       'Message Queue Channel',    False),
    ('sched_yield',   'CPU Covert Channel',       False),
)



# 旧版实现，v1.x后废弃
# OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

def detect_timing_channel_(f_path: typing.Optional[str] = None,
                           f_outdir: typing.Optional[str] = None) -> dict:
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

        # 隐蔽信道检测第二轮
        ci = 0
        cn = len(_COVERT_PATTERNS)
        while ci < cn:
            cpat, cdesc, chigh = _COVERT_PATTERNS[ci]
            if cpat in content:
                channels.append({
                    'location': f'contains {cpat}',
                    'type': f'Covert: {cdesc}',
                    'risk': 'Medium',
                })
            ci += 1

        # 熵评估：高熵数据段 + 计时原语 → 隐蔽信道容量更高
        entropy_score = _estimate_entropy(raw)
        if entropy_score > 6.0 and len(channels) > 0:
            for ch in channels:
                if ch['risk'] == 'Medium':
                    ch['risk'] = 'High'
                    ch['entropy_note'] = f'数据段熵={entropy_score:.1f} bits/byte'

        rpt = None
        if f_outdir is not None:
            _os.makedirs(f_outdir, exist_ok=True)
            rpt = _os.path.join(f_outdir, 'timing_channel_report.txt')
            with open(rpt, 'w', encoding='utf-8') as fh:
                fh.write("Timing Side Channel Detection Report\n")
                fh.write("=" * 50 + "\n")
                fh.write(f"Binary: {f_path}\n")
                fh.write(f"Channels Found: {len(channels)}\n")
                fh.write(f"Entropy Score: {entropy_score:.2f} bits/byte\n\n")
                for ci in range(len(channels)):
                    ch = channels[ci]
                    fh.write(f"- Loc: {ch['location']}\n")
                    fh.write(f"  Type: {ch['type']}\n")
                    fh.write(f"  Risk: {ch['risk']}\n\n")
        return {
            'success': True,
            'timing_channels': channels,
            'report_path': rpt,
            'entropy_score': round(entropy_score, 2),
        }

    except Exception as _e:
        return {'success': False, 'error': str(_e)}


def _estimate_entropy(data: bytes) -> float:
    """对字节流做香农熵估计（基于单字节分布）。

    # 不拆——保持上下文连贯性，拆了反而难读
    高熵值（> 6.0）提示数据段可能包含加密或压缩数据，
    这类段与计时原语共存时隐蔽信道容量显著增大。
    """
    n = len(data)
    if n < 64:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    inv = 1.0 / n
    for f in freq:
        if f > 0:
            p = f * inv
            ent -= p * _math.log2(p)
    return ent


# 兼容旧调用：无参 detect_timing_channel 返回占位结果
def detect_timing_channel() -> dict:
    """兼容入口：无参调用返回模块版本信息。"""
    return {
        'success': True,
        'timing_channels': [],
        'report_path': None,
        'note': '需要指定 binary_path 参数以执行完整检测',
    }


    """内部调试桩，当前未使用。"""
    pass  # 调试桩，当前未使用

