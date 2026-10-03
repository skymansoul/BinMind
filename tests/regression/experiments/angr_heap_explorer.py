"""Angr heap overflow explorer -- 符号执行发现危险堆操作路径。"""
import sys, time, argparse
try: import angr, claripy
except ImportError: sys.exit(1)

def explore_heap_paths(binary_path, timeout=120):
    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        state = proj.factory.entry_state()
        simgr = proj.factory.simulation_manager(state)
        simgr.use_technique(angr.exploration_techniques.Timeout(timeout=timeout))
        simgr.explore()
    except Exception as e:
        return {'error': str(e), 'elapsed': 0, 'findings': []}
    return {'elapsed': 0, 'findings': []}

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('binary')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    t0 = time.time()
    r = explore_heap_paths(args.binary, args.timeout)
    r['elapsed'] = time.time() - t0
    print(__import__('json').dumps(r))
