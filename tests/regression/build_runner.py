# 编译模块 — 自动编译所有CVE样本
import os, subprocess, sys

def build_all(samples_dir):
    results = {}
    for d in sorted(os.listdir(samples_dir)):
        dp = os.path.join(samples_dir, d)
        if not os.path.isdir(dp): continue
        src = os.path.join(dp, 'vuln.c')
        if not os.path.isfile(src): continue
        build = os.path.join(dp, 'build.sh')
        if os.path.isfile(build):
            try:
                subprocess.run(['bash', build], cwd=dp, capture_output=True, timeout=30)
                results[d] = 'ok'
            except Exception as e:
                results[d] = str(e)[:100]
    return results

if __name__ == '__main__':
    sd = sys.argv[1] if len(sys.argv) > 1 else '../cve_samples'
    r = build_all(sd)
    for k, v in r.items(): print(f'{k}: {v}')
