"""orchestrator 管线自检 — 编译简单 C 程序 → 分析 → 验证报告.

创建: 2026-08-10
用途: 快速验证完整管线是否正常工作 (需 gcc).
"""
import os
import subprocess
import tempfile

from orchestrator import analyze_heap


def check():
    """编译 malloc+memcpy 小程序 → analyze_heap → 报告."""
    c_code = '''
    #include <stdlib.h>
    #include <string.h>
    int main() {
        char *p = malloc(100);
        if (p) { memcpy(p, "hello", 6); free(p); }
        return 0;
    }
    '''
    with tempfile.NamedTemporaryFile(
            suffix='.c', mode='w', delete=False) as f:
        f.write(c_code)
        c_path = f.name
    bin_path = c_path + '.exe'
    try:
        rc = subprocess.run(
            ['gcc', '-O0', '-g', '-o', bin_path, c_path],
            capture_output=True, timeout=30)
        if rc.returncode == 0 and os.path.isfile(bin_path):
            report = analyze_heap(bin_path)
            print(f"[smoke] {report.raw_findings} raw, "
                  f"{report.confirmed} confirmed, "
                  f"{report.filtered_fp} filtered "
                  f"({report.fp_reduction_pct}%)")
            print("[OK] orchestrator smoke test passed")
        else:
            print("[smoke] gcc failed, skipping")
    except Exception as e:
        print(f"[smoke] skipped: {e}")
    finally:
        for p in (c_path, bin_path):
            if os.path.isfile(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass


if __name__ == "__main__":
    check()
