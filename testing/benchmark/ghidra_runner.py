# Ghidra headless脚本自动化 - 批量分析二进制并导出漏洞相关特征。
# 需要: Ghidra安装目录 + analyzeHeadless可执行文件。

import os, subprocess, time

GHIDRA_HOME = os.environ.get("GHIDRA_HOME", "")
GHIDRA_HEADLESS = (
    os.path.join(GHIDRA_HOME, "support", "analyzeHeadless")
    if GHIDRA_HOME else ""
)


def run_ghidra_scan(binaries: dict, timeout_sec: int = 300) -> list:
    """Ghidra headless 批量分析。"""
    results = []
    if not os.path.exists(GHIDRA_HEADLESS):
        return results

    script_path = os.path.join(os.path.dirname(__file__), "ghidra_scan.py")

    for name, info in binaries.items():
        if not isinstance(info, dict) or not info.get("success"):
            continue
        binary_path = info.get("binary_path", "")
        if not os.path.exists(binary_path):
            continue

        t0 = time.time()
        tmp_dir = os.path.join(os.path.dirname(binary_path), "ghidra_tmp")
        os.makedirs(tmp_dir, exist_ok=True)

        cmd = [
            GHIDRA_HEADLESS, tmp_dir, f"tmp_{name}",
            "-import", binary_path,
            "-scriptPath", os.path.dirname(script_path),
            "-postScript", os.path.basename(script_path),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_sec)
            dt = time.time() - t0
            results.append(type('R', (), {
                'success': proc.returncode == 0,
                'sample_name': name, 'binary_path': binary_path,
                'stdout': proc.stdout, 'stderr': proc.stderr,
                'duration_sec': dt, 'exit_code': proc.returncode,
            })())
        except subprocess.TimeoutExpired:
            results.append(type('R', (), {
                'success': False, 'sample_name': name,
                'binary_path': binary_path, 'stdout': '',
                'stderr': 'Ghidra timeout', 'duration_sec': timeout_sec,
                'exit_code': -1,
            })())
        except Exception as e:
            results.append(type('R', (), {
                'success': False, 'sample_name': name,
                'binary_path': binary_path, 'stdout': '',
                'stderr': str(e), 'duration_sec': 0, 'exit_code': -1,
            })())

    return results
