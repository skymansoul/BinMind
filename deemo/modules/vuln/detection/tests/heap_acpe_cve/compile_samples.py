"""编译 ACPE 样本集 — MinGW gcc 双档 (O0/O2), 可跳过缺失工具.

创建: 2025-04-17
用法:
  python compile_samples.py [样本根目录] [--gcc D:/mingw64/bin/gcc]
输出:
  每个样本目录下 bin/plain/<name>.exe 与 bin/packed/<name>.exe
  顶层 compile_report.json

设计决策:
  - O0 档: 保留清晰 malloc→mov→memcpy 链, 供符号追踪解析。
  - O2 档: 编译器优化后的真实形态, 验证稳健性(失败不算致命)。
  - 无 gcc 环境: 报 warning 并继续, 回归测试仍可扫描预编译产物。
"""

import argparse
import json
import shutil
import subprocess
from pathlib import Path


def find_gcc(preferred: str = "") -> str:
    if preferred and Path(preferred).exists():
        return preferred
    for cand in ('gcc', 'x86_64-w64-mingw32-gcc', 'cc'):
        p = shutil.which(cand)
        if p:
            return p
    return ''


def compile_one(gcc: str, src: Path, out: Path, opt: str) -> bool:
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = [gcc, opt, '-fno-pic', '-fno-stack-protector']
    if opt == '-O2':
        # 保留漏洞逻辑: 防止死代码消除抹掉未使用结果的示例,
        # 并强制 memcpy/malloc 保持真实库调用而非内联序列
        flags += ['-fno-tree-dce', '-fno-tree-dse', '-fno-inline',
                  '-fno-builtin']
    flags += [str(src), '-o', str(out)]
    try:
        proc = subprocess.run(
            flags, capture_output=True, text=True, timeout=60,
            encoding='utf-8', errors='replace')
        if proc.returncode != 0:
            print(f'[compile] FAIL {src.name}: {proc.stderr[:200]}')
            return False
        return True
    except Exception as exc:
        print(f'[compile] ERR {src.name}: {exc}')
        return False


def compile_all(root: Path, gcc: str) -> dict:
    report = {'gcc': gcc, 'samples': []}
    if not gcc:
        print('[compile] gcc not found — skipping compilation')
        report['skipped'] = True
        return report
    # 遍历样本目录
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = next(d.glob('*.c'), None)
        if src is None:
            continue
        name = src.stem
        entry = {'id': d.name, 'name': name,
                 'plain': False, 'packed': False}
        entry['plain'] = compile_one(gcc, src, d / 'bin' / 'plain' / f'{name}.exe', '-O0')
        entry['packed'] = compile_one(gcc, src, d / 'bin' / 'packed' / f'{name}.exe', '-O2')
        report['samples'].append(entry)
        print(f"[compile] {d.name:22s} plain={entry['plain']} packed={entry['packed']}")
    (root / 'compile_report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('root', nargs='?', default=None)
    ap.add_argument('--gcc', default='')
    args = ap.parse_args()
    here = Path(__file__).resolve().parent
    root = Path(args.root) if args.root else here / 'samples'
    gcc = find_gcc(args.gcc)
    compile_all(root, gcc)


if __name__ == '__main__':
    main()
