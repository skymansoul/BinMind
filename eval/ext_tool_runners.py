"""
外部工具运行器 — Angr / QEMU / Ghidra headless 的封装。
"""
import os, json, time, subprocess

TIMEOUT_PER_SAMPLE = 120


def run_angr(binary_path: str) -> dict:
    """Angr: CFG恢复 + 危险函数调用点搜索 + 简易符号执行探测。"""
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'Angr', 'success': False,
                'error': 'binary not found', 'duration_ms': 0}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        heap_funcs = {'malloc', 'calloc', 'realloc', 'memcpy', 'memmove',
                      'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',
                      'fgets', 'read', 'recv'}
        danger_sites = []
        for func in cfg.functions.values():
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic != 'call':
                        continue
                    try:
                        target = cfg.functions.get(insn.operands[0].imm)
                        if target and target.name in heap_funcs:
                            danger_sites.append({
                                'func': target.name,
                                'addr': hex(insn.address),
                                'caller': func.name,
                            })
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
        return {'tool': 'Angr', 'success': True,
                'functions': len(cfg.functions),
                'dangerous_calls': len(danger_sites),
                'dangerous_sites': danger_sites[:20],
                'symbolic_paths': sym_findings,
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except ImportError:
        return {'tool': 'Angr', 'success': False,
                'error': 'angr not installed', 'duration_ms': 0}
    except Exception as e:
        return {'tool': 'Angr', 'success': False,
                'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def run_qemu(binary_path: str) -> dict:
    """QEMU user-mode: 执行并捕获内存操作日志作为ground truth。"""
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'QEMU', 'success': False,
                'error': 'binary not found', 'duration_ms': 0}
    try:
        proc = subprocess.run(
            ['qemu-x86_64', '-d', 'cpu', '-D', '/dev/stdout', binary_path],
            capture_output=True, text=True, timeout=10,
        )
        stdout = proc.stdout or ''
        mallocs = stdout.count('malloc') + stdout.count('calloc') + stdout.count('mmap')
        memcpys = stdout.count('memcpy') + stdout.count('memmove')
        writes = stdout.count('storer') + stdout.count('storew') + stdout.count('storel')
        return {'tool': 'QEMU', 'success': True,
                'mallocs_detected': mallocs,
                'memcpys_detected': memcpys,
                'writes_detected': writes,
                'insn_lines': len(stdout.splitlines()) if stdout else 0,
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except FileNotFoundError:
        return {'tool': 'QEMU', 'success': False,
                'error': 'qemu-x86_64 not found', 'duration_ms': 0}
    except subprocess.TimeoutExpired:
        return {'tool': 'QEMU', 'success': False,
                'error': 'timeout', 'duration_ms': 10000}
    except Exception as e:
        return {'tool': 'QEMU', 'success': False,
                'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def run_ghidra_headless(binary_path: str) -> dict:
    """Ghidra headless: 自动分析并提取堆操作点。"""
    t0 = time.time()
    if not os.path.isfile(binary_path):
        return {'tool': 'Ghidra', 'success': False,
                'error': 'binary not found', 'duration_ms': 0}
    ghidra_home = os.environ.get('GHIDRA_HOME', '')
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scan_script = os.path.join(script_dir, 'ghidra_heap_scan.py')
    if not os.path.isfile(scan_script):
        return {'tool': 'Ghidra', 'success': False,
                'error': 'ghidra_heap_scan.py not found', 'duration_ms': 0}
    if not ghidra_home:
        return {'tool': 'Ghidra', 'success': False,
                'error': 'GHIDRA_HOME not set', 'duration_ms': 0}
    headless = os.path.join(ghidra_home, 'support', 'analyzeHeadless')
    if not os.path.isfile(headless) and not os.path.isfile(headless + '.bat'):
        return {'tool': 'Ghidra', 'success': False,
                'error': 'analyzeHeadless not found at GHIDRA_HOME', 'duration_ms': 0}
    try:
        import tempfile
        proj_dir = tempfile.mkdtemp(prefix='ghidra_bench_')
        proc = subprocess.run(
            [headless, proj_dir, 'BenchProj',
             '-import', binary_path,
             '-scriptPath', script_dir,
             '-postScript', 'ghidra_heap_scan.py'],
            capture_output=True, text=True, timeout=TIMEOUT_PER_SAMPLE,
        )
        findings = 0
        for line in (proc.stdout or '').splitlines():
            if 'GHIDRA_RESULT:' in line:
                try:
                    data = json.loads(line.split('GHIDRA_RESULT:', 1)[1])
                    findings = data.get('heap_danger_calls', 0)
                except Exception:
                    pass
        return {'tool': 'Ghidra', 'success': proc.returncode == 0,
                'dangerous_calls': findings,
                'output_lines': len((proc.stdout or '').splitlines()),
                'duration_ms': int((time.time() - t0) * 1000),
                'error': (proc.stderr or '')[:200] if proc.returncode != 0 else ''}
    except FileNotFoundError:
        return {'tool': 'Ghidra', 'success': False,
                'error': 'analyzeHeadless not found', 'duration_ms': 0}
    except subprocess.TimeoutExpired:
        return {'tool': 'Ghidra', 'success': False,
                'error': 'timeout', 'duration_ms': TIMEOUT_PER_SAMPLE * 1000}
    except Exception as e:
        return {'tool': 'Ghidra', 'success': False,
                'error': str(e)[:200],
                'duration_ms': int((time.time() - t0) * 1000)}


def run_binmind_baseline(ir_lines: list, binary_path: str) -> dict:
    """基线regex检测器。"""
    t0 = time.time()
    try:
        from core.heap_overflow_pipeline import detect_heap_overflows_full
        candidates, stats = detect_heap_overflows_full(ir_lines, '')
        n = len(candidates)
        return {'tool': 'BinMind-baseline', 'success': True,
                'detections': n, 'candidates': n,
                'duration_ms': int((time.time() - t0) * 1000), 'error': ''}
    except Exception as e:
        return {'tool': 'BinMind-baseline', 'success': False,
                'detections': 0, 'duration_ms': int((time.time() - t0) * 1000),
                'error': str(e)[:200]}


def run_binmind_enhanced(ir_lines: list, binary_path: str) -> dict:
    """增强5-stage检测器。"""
    t0 = time.time()
    try:
        from core.heap_overflow_enhanced import detect_heap_overflow_enhanced
        candidates, stats = detect_heap_overflow_enhanced(ir_lines, binary_path)
        confirmed = [c for c in candidates
                      if getattr(c, 'verdict', '') == 'CONFIRMED']
        return {'tool': 'BinMind-enhanced', 'success': True,
                'detections': len(confirmed), 'candidates_total': len(candidates),
                'fp_filtered': stats.get('fp_filtered', 0),
                'duration_ms': int((time.time() - t0) * 1000), 'error': '',
                'verdicts': [getattr(c, 'verdict', '?') for c in candidates]}
    except ImportError:
        return {'tool': 'BinMind-enhanced', 'success': False,
                'detections': 0, 'duration_ms': 0,
                'error': 'heap_overflow_enhanced module not found'}
    except Exception as e:
        return {'tool': 'BinMind-enhanced', 'success': False,
                'detections': 0, 'duration_ms': int((time.time() - t0) * 1000),
                'error': str(e)[:200]}
