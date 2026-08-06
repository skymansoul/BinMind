"""编译CVE测试样本 -- 自动编译所有CVE样本目录下的vuln.c文件。

用法: python compile_samples.py [--clean]
  不带--clean: 编译所有样本
  --clean: 删除所有编译产物
"""
import os, subprocess, sys, glob

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), '..', 'cve_samples')
CC = os.environ.get('CC', 'gcc')
CFLAGS = ['-fno-stack-protector', '-no-pie', '-z', 'execstack', '-g', '-O0']

def compile_all():
    results = {'ok': [], 'fail': []}
    for root, dirs, files in os.walk(SAMPLES_DIR):
        for f in files:
            if f.endswith('.c'):
                src = os.path.join(root, f)
                out = os.path.join(root, os.path.splitext(f)[0])
                cmd = [CC] + CFLAGS + ['-o', out, src]
                try:
                    subprocess.run(cmd, check=True, capture_output=True, text=True)
                    results['ok'].append(src)
                except subprocess.CalledProcessError as e:
                    results['fail'].append((src, e.stderr[:200]))
    return results

def clean_all():
    for root, dirs, files in os.walk(SAMPLES_DIR):
        for f in files:
            if not f.endswith('.c') and not f.endswith('.md'):
                os.remove(os.path.join(root, f))

if __name__ == '__main__':
    if '--clean' in sys.argv:
        clean_all()
        print("Cleaned all compiled binaries")
    else:
        r = compile_all()
        print(f"Compiled: {len(r['ok'])} ok, {len(r['fail'])} failed")
        for src, err in r['fail']:
            print(f"  FAIL {src}: {err[:100]}")
