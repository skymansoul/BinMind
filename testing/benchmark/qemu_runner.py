# QEMU user mode + 自定义插桩 - 动态执行追踪危险函数调用。
# 需要: qemu-x86_64 和自定义plugin, 当前为框架级实现。
# 注: 完整QEMU plugin需编译C共享库(.so), 本模块提供Python侧调度逻辑;
#     plugin源码应放在 testing/benchmark/qemu_plugin/ 下单独编译。

import os, shutil, subprocess, time

QEMU_BIN = shutil.which("qemu-x86_64") or ""

def run_qemu_scan(binaries: dict, timeout_sec: int = 120) -> list:
    """QEMU user mode扫描 - 检查qemu是否可用, 调用plugin。"""
    results = []
    if not QEMU_BIN:
        return results

    for name, info in binaries.items():
        if not isinstance(info, dict) or not info.get("success"):
            continue
        binary_path = info.get("binary_path", "")
        if not os.path.exists(binary_path):
            continue

        t0 = time.time()
        plugin_path = os.path.join(os.path.dirname(__file__),
                                    "qemu_plugin", "libdetect.so")
        cmd = [QEMU_BIN]
        if os.path.exists(plugin_path):
            cmd += ["-plugin", plugin_path]
        cmd += [binary_path]

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout_sec)
            dt = time.time() - t0
            results.append(type('R', (), {
                'success': proc.returncode >= 0,
                'sample_name': name, 'binary_path': binary_path,
                'stdout': proc.stdout, 'stderr': proc.stderr,
                'duration_sec': dt, 'exit_code': proc.returncode,
            })())
        except subprocess.TimeoutExpired:
            results.append(type('R', (), {
                'success': False, 'sample_name': name,
                'binary_path': binary_path, 'stdout': '',
                'stderr': 'QEMU timeout', 'duration_sec': timeout_sec,
                'exit_code': -1,
            })())
        except Exception as e:
            results.append(type('R', (), {
                'success': False, 'sample_name': name,
                'binary_path': binary_path, 'stdout': '',
                'stderr': str(e), 'duration_sec': 0, 'exit_code': -1,
            })())

    return results
