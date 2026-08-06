"""批量编译所有堆溢出测试样本。"""
import os, subprocess, sys, glob

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'samples')
CC = os.environ.get('CC', 'gcc')
CFLAGS = ['-g', '-O0', '-fno-stack-protector', '-no-pie', '-z', 'execstack']

def compile_all():
    ok, fail = [], []
    for root, dirs, files in os.walk(SAMPLES_DIR):
        for f in files:
            if not f.endswith('.c'):
                continue
            src = os.path.join(root, f)
            out = os.path.join(root, os.path.splitext(f)[0])
            cmd = [CC] + CFLAGS + ['-o', out, src]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                ok.append(src)
            else:
                fail.append((src, r.stderr[:200]))
    return ok, fail

if __name__ == '__main__':
    ok, fail = compile_all()
    print(f'Compiled: {len(ok)} ok, {len(fail)} failed')
    for src, err in fail:
        print(f'  FAIL {os.path.basename(os.path.dirname(src))}: {err[:80]}')
