# QEMU user mode tracer — 运行时内存操作捕获作为 ground truth
"""通过QEMU user mode运行binary并检测崩溃(SIGSEGV/SIGABRT)。
实际内存操作的精确分析需要自定义QEMU插桩插件(qemu-trace-mem plugin)，
本脚本使用qemu-x86_64的默认行为检测信号崩溃。"""
import os, sys, json, time, subprocess, tempfile

def trace_binary(binary_path: str, args: list = None) -> dict:
    t0 = time.time()
    result = {"tool": "QEMU+Trace", "binary": binary_path, "crashed": False,
              "exit_code": 0, "signal": 0, "time_secs": 0, "error": None}
    try:
        cmd = ["qemu-x86_64", binary_path] + (args or [])
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        result["exit_code"] = proc.returncode
        result["crashed"] = proc.returncode < 0
        result["signal"] = -proc.returncode if proc.returncode < 0 else 0
    except FileNotFoundError:
        result["error"] = "qemu-x86_64 not found (install: apt install qemu-user)"
    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
        result["crashed"] = False
    except Exception as e:
        result["error"] = str(e)[:200]
    result["time_secs"] = round(time.time() - t0, 2)
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python qemu_tracer.py <binary> [args...]"); sys.exit(1)
    r = trace_binary(sys.argv[1], sys.argv[2:] if len(sys.argv) > 2 else None)
    print(json.dumps(r, indent=2))
