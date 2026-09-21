"""

包含: c_to_ir / BinMind / Angr / Ghidra / QEMU / compute_metrics.
"""
import os, re, time, json, subprocess

EVAL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'eval')


def c_to_ir(c_source: str) -> list:
    """C源码转IR行 — 剥离类型声明/控制流关键字/无关函数调用."""
    lines = []
    for line in c_source.splitlines():
        s = line.strip()
        if s.startswith('#') or s.startswith('//') or s.startswith('/*'):
            continue
        if s.startswith('*') or s.startswith('}') or s.startswith(')'):
            continue
        if not s or s in ('{', '}'):
            continue
        s = re.sub(r'\(\s*(?:char|int|void|size_t|unsigned|float|double|'
                   r'uint\d+_t|int\d+_t|long)\s*\**\s*\)', '', s)
        s = re.sub(r'\b(?:char|int|short|long|void|float|double|size_t|'
                   r'ssize_t|unsigned|signed|uint\d+_t|int\d+_t|const|static|'
                   r'volatile|extern|register|struct\s+\w+)\s*\**\s*', '', s)
        s = re.sub(r'typedef\s+struct\s*\{?', '', s)
        s = re.sub(r'\b(?:if|while|for|else)\s*\(', '(', s)
        if re.match(r'\s*(?:return|free|printf|puts|fprintf|exit)\s*[\(;]', s):
            continue
        s = s.rstrip(';').strip()
        if s:
            lines.append(s)
    return lines


def _run_hosv_source(source: str, sample_name: str) -> dict:
    """堆写模式验证源级堆溢出检测 — 保留完整C语义, 绕过有损IR转换.

    strict判定: 仅VULN触发detected=True, UNCERTAIN保留为参考不触发检出.
    no_vuln: 无VULN判定 (可以有SAFE/UNCERTAIN), 用于跨通道否决.
    all_safe: 全部SAFE且无UNCERTAIN, 用于更强的否决.
    返回dict格式与run_binmind_pipeline对齐.
    """
    t0 = time.time()
    try:
        from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
        v = HeapOverflowSrcVerifier()
        results = v.verify(source)
        from analysis.heap_overflow_types import HoVerdict
        vuln_results = [r for r in results if r.verdict == HoVerdict.VULN]
        uncertain_results = [r for r in results if r.verdict == HoVerdict.UNCERTAIN]
        safe_results = [r for r in results if r.verdict == HoVerdict.SAFE]
        detected = len(vuln_results) > 0
        no_vuln = len(vuln_results) == 0 and len(results) > 0
        all_safe = len(safe_results) > 0 and len(vuln_results) == 0 and len(uncertain_results) == 0
        return {
            'tool': 'BinMind-HOSV', 'sample': sample_name,
            'detected': detected,
            'n_vuln': len(vuln_results),
            'n_uncertain': len(uncertain_results),
            'n_safe': len(safe_results),
            'no_vuln': no_vuln,
            'all_safe': all_safe,
            'max_confidence': max((r.confidence for r in vuln_results), default=0),
            'duration_ms': (time.time() - t0) * 1000,
        }
    except Exception as e:
        return {'tool': 'BinMind-HOSV', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'no_vuln': False, 'all_safe': False,
                'duration_ms': (time.time() - t0) * 1000}


def _run_csa_source(source: str, sample_name: str) -> dict:
    """源码直扫通道 — extract_heap_ops_c + classify_finding.

    独立于堆写模式验证, 提供互补的模式匹配能力:
    - 多行写入/指针解引用写入/跨函数分配/跨函数写入
    - 别名传播/数组索引写入/free检测
    strict判定: 仅hard overflow触发detected=True, UNCERTAIN保留为参考不触发检出.
    """
    t0 = time.time()
    try:
        from tests.source_scanner import extract_heap_ops_c
        from tests.source_classifier import classify_finding
        ops = extract_heap_ops_c(source)
        overflow = sum(1 for o in ops if o.get('is_overflow'))
        uncertain = sum(1 for o in ops
                        if not o.get('is_overflow')
                        and classify_finding(o) == 'UNCERTAIN')
        detected = overflow > 0
        return {
            'tool': 'BinMind-CSA', 'sample': sample_name,
            'detected': detected,
            'n_overflow': overflow,
            'n_uncertain': uncertain,
            'n_total': len(ops),
            'duration_ms': (time.time() - t0) * 1000,
        }
    except Exception as e:
        return {'tool': 'BinMind-CSA', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': (time.time() - t0) * 1000}


def run_binmind_pipeline(source: str, sample_name: str) -> dict:
    """SRC-IR Bridge: 三通道联合检测.

    通道1 堆写模式验证 — 精确5阶段验证 (分配→写入→边界→约束→APAS)
    通道2 CSA  — 源码直扫模式匹配 (多行写入/跨函数/别名)
    通道3 IR   — 二进制管线回退 (c_to_ir→detect_heap_overflows_full)

    strict联合判定:
    - 堆写模式验证 VULN → 检出
    - CSA hard overflow → 检出, 但堆写模式验证 all_safe时否决CSA (跨通道否决)
    - 前两者无检出时回退IR管线
    UNCERTAIN保留为参考不触发检出.
    """
    t_total = time.time()

    ch1 = _run_hosv_source(source, sample_name)
    ch2 = _run_csa_source(source, sample_name)

    csa_detected = ch2['detected']
    if csa_detected and ch1.get('all_safe', False):
        csa_detected = False

    if ch1['detected'] or csa_detected:
        bridge = []
        if ch1['detected']:
            bridge.append('HOSV')
        if csa_detected:
            bridge.append('CSA')
        return {
            'tool': 'BinMind-Full', 'sample': sample_name,
            'detected': True,
            'n_candidates': ch1.get('n_vuln', 0) + ch1.get('n_uncertain', 0)
                            + ch2.get('n_overflow', 0) + ch2.get('n_uncertain', 0),
            'max_confidence': max(ch1.get('max_confidence', 0), 0.7),
            'pipeline_stats': {
                'source': '+'.join(bridge),
                'hosv_vuln': ch1.get('n_vuln', 0),
                'hosv_uncertain': ch1.get('n_uncertain', 0),
                'hosv_safe': ch1.get('n_safe', 0),
                'csa_overflow': ch2.get('n_overflow', 0),
                'csa_uncertain': ch2.get('n_uncertain', 0),
                'csa_vetoed': ch2['detected'] and not csa_detected,
            },
            'duration_ms': (time.time() - t_total) * 1000,
        }

    t0 = time.time()
    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        ir_lines = c_to_ir(source)
        candidates, stats = detect_heap_overflows_full(ir_lines, source)
        detected = len(candidates) > 0
        if detected and ch1.get('all_safe', False):
            detected = False
        return {
            'tool': 'BinMind-Full', 'sample': sample_name,
            'detected': detected,
            'n_candidates': len(candidates),
            'max_confidence': max((getattr(c, 'confidence', 0) for c in candidates), default=0),
            'pipeline_stats': {k: v for k, v in stats.items() if isinstance(v, (int, float, str))},
            'pipeline_stats_bridge': 'IR-fallback',
            'duration_ms': (time.time() - t_total) * 1000,
        }
    except Exception as e:
        return {'tool': 'BinMind-Full', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': (time.time() - t_total) * 1000}


def run_angr(binary_path: str, sample_name: str) -> dict:
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'Angr', 'sample': sample_name,
                'detected': False, 'error': 'binary not found',
                'duration_ms': 0}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        danger = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove',
                  'strcpy', 'strncpy', 'sprintf', 'gets', 'scanf',
                  'fgets', 'read', 'recv', 'memset'}
        findings = 0
        danger_list = []
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        try:
                            tgt = cfg.functions.get(insn.operands[0].imm)
                            if tgt and tgt.name in danger:
                                findings += 1
                                danger_list.append(tgt.name)
                        except Exception:
                            pass
        sym_findings = 0
        try:
            state = proj.factory.blank_state(addr=proj.entry)
            simgr = proj.factory.simulation_manager(state)
            simgr.explore(n=50, step_func=lambda lsm: lsm.prune())
            sym_findings = len(simgr.active) if simgr.active else 0
        except Exception:
            pass
        has_alloc = any(f in ('malloc', 'calloc', 'realloc') for f in danger_list)
        has_write = any(f in ('memcpy', 'memmove', 'strcpy', 'strncpy',
                              'sprintf', 'gets', 'memset') for f in danger_list)
        detected = has_alloc and has_write
        return {'tool': 'Angr', 'sample': sample_name,
                'detected': detected,
                'danger_calls': findings,
                'func_count': len(cfg.functions),
                'symbolic_paths': sym_findings,
                'duration_ms': int((time.time() - t0) * 1000)}
    except ImportError:
        return {'tool': 'Angr', 'sample': sample_name,
                'detected': False, 'error': 'angr not installed',
                'duration_ms': 0}
    except Exception as e:
        return {'tool': 'Angr', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def run_ghidra(binary_path: str, sample_name: str) -> dict:
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'Ghidra', 'sample': sample_name,
                'detected': False, 'error': 'binary not found',
                'duration_ms': 0}
    ghidra_home = os.environ.get('GHIDRA_HOME', '')
    script_dir = EVAL_DIR
    scan_script = os.path.join(script_dir, 'ghidra_heap_scan.py')
    if not ghidra_home or not os.path.isfile(scan_script):
        return {'tool': 'Ghidra', 'sample': sample_name,
                'detected': False, 'error': 'Ghidra not configured',
                'duration_ms': 0}
    headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
    try:
        import tempfile
        proj_dir = tempfile.mkdtemp(prefix='ghidra_bench_')
        proc = subprocess.run(
            [headless, proj_dir, 'BenchProj',
             '-import', binary_path,
             '-scriptPath', script_dir,
             '-postScript', 'ghidra_heap_scan.py'],
            capture_output=True, text=True, timeout=120)
        findings = 0
        for line in (proc.stdout or '').splitlines():
            if 'GHIDRA_RESULT:' in line:
                try:
                    data = json.loads(line.split('GHIDRA_RESULT:', 1)[1])
                    findings = data.get('heap_danger_calls', 0)
                except Exception:
                    pass
        detected = findings > 0
        return {'tool': 'Ghidra', 'sample': sample_name,
                'detected': detected,
                'dangerous_calls': findings,
                'duration_ms': int((time.time() - t0) * 1000)}
    except Exception as e:
        return {'tool': 'Ghidra', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def run_qemu(binary_path: str, sample_name: str) -> dict:
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'QEMU', 'sample': sample_name,
                'detected': False, 'error': 'binary not found',
                'duration_ms': 0}
    try:
        proc = subprocess.run(
            ['qemu-x86_64', '-d', 'cpu', '-D', '/dev/stdout', binary_path],
            capture_output=True, text=True, timeout=10)
        stdout = proc.stdout or ''
        has_heap_ops = ('malloc' in stdout or 'calloc' in stdout or
                        'mmap' in stdout)
        has_write_ops = ('memcpy' in stdout or 'memmove' in stdout or
                         'store' in stdout.lower())
        detected = has_heap_ops and has_write_ops
        return {'tool': 'QEMU', 'sample': sample_name,
                'detected': detected,
                'insn_lines': len(stdout.splitlines()) if stdout else 0,
                'duration_ms': int((time.time() - t0) * 1000)}
    except FileNotFoundError:
        return {'tool': 'QEMU', 'sample': sample_name,
                'detected': False, 'error': 'qemu-x86_64 not found',
                'duration_ms': 0}
    except subprocess.TimeoutExpired:
        return {'tool': 'QEMU', 'sample': sample_name,
                'detected': False, 'error': 'timeout',
                'duration_ms': 10000}
    except Exception as e:
        return {'tool': 'QEMU', 'sample': sample_name,
                'detected': False, 'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def compute_metrics(results):
    """计算指标. 所有CVE样本ground truth = VULN."""
    tp = fp = tn = fn = 0
    for r in results:
        if r.get('detected', False):
            tp += 1
        else:
            fn += 1
    total = tp + fn
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)
    return {'total': total, 'TP': tp, 'FP': fp, 'TN': tn, 'FN': fn,
            'precision': round(precision, 4), 'recall': round(recall, 4),
            'f1': round(f1, 4)}


__all__ = [
    'c_to_ir', '_run_hosv_source', '_run_csa_source', 'run_binmind_pipeline',
    'run_angr', 'run_ghidra', 'run_qemu', 'compute_metrics',
]
