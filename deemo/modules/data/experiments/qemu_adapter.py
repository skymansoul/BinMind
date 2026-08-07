# QEMU User Mode 适配器 — 自定义插桩包装
# 在 user mode 下运行二进制, 用 -d exec 追踪执行流,
# 或用自定义 instrumentation plugin 检测危险模式.
# 创建: 2026-05-06

import os, sys, json, time, subprocess, tempfile

def find_qemu() -> str:
    """查找系统上的 qemu-user 二进制."""
    for name in ["qemu-x86_64", "qemu-x86_64-static", "qemu-i386"]:
        path = subprocess.run(["which", name], capture_output=True, text=True)
        if path.returncode == 0:
            return path.stdout.strip()
    return ""

class QEMUAdapter:
    """QEMU user mode 包装器.

    两种模式:
      1. 轻量: -strace 追踪系统调用, 检测危险 syscall 序列
      2. 插桩: 用 -d exec,in_asm 输出执行指令, 离线分析
    """

    DANGEROUS_SYSCALLS = {
        "mmap", "mprotect", "execve", "ptrace",
        "memfd_create", "process_vm_writev",
    }

    def __init__(self, qemu_path: str = ""):
        self._qemu = qemu_path or find_qemu()
        self._results = []

    def scan_strace(self, binary_path: str, timeout_sec: int = 60) -> list:
        """轻量模式: -strace 追踪系统调用."""
        if not self._qemu:
            return [{"error": "qemu_not_found"}]

        try:
            proc = subprocess.run(
                [self._qemu, "-strace", binary_path],
                capture_output=True, text=True, timeout=timeout_sec)
            findings = []
            for line in proc.stderr.split("\n"):
                for syscall in self.DANGEROUS_SYSCALLS:
                    if syscall in line:
                        findings.append({
                            "type": "dangerous_syscall",
                            "syscall": syscall,
                            "line": line.strip()[:200],
                        })
            return findings
        except subprocess.TimeoutExpired:
            return [{"error": "timeout"}]
        except FileNotFoundError:
            return [{"error": "qemu_not_found"}]

    def scan_with_input(self, binary_path: str, input_data: bytes = b"",
                         timeout_sec: int = 60) -> list:
        """带输入的扫描: QEMU user mode + stdin重定向.

        输入数据触发不同的执行路径, 提高覆盖率.
        """
        if not self._qemu:
            return [{"error": "qemu_not_found"}]
        try:
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(input_data)
                input_path = tf.name
            proc = subprocess.run(
                [self._qemu, "-strace", binary_path],
                stdin=open(input_path, "rb"),
                capture_output=True, text=True, timeout=timeout_sec)
            os.unlink(input_path)
            findings = []
            for line in proc.stderr.split("\n"):
                for syscall in self.DANGEROUS_SYSCALLS:
                    if syscall in line:
                        findings.append({
                            "type": "dangerous_syscall",
                            "syscall": syscall,
                            "line": line.strip()[:200],
                        })
            return findings
        except subprocess.TimeoutExpired:
            return [{"error": "timeout"}]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: python qemu_adapter.py <binary> [input_file]"}))
        sys.exit(1)

    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error": f"file not found: {binary}"}))
        sys.exit(1)

    adapter = QEMUAdapter()
    t0 = time.time()

    if len(sys.argv) >= 3 and os.path.isfile(sys.argv[2]):
        with open(sys.argv[2], "rb") as f:
            findings = adapter.scan_with_input(binary, f.read(), timeout_sec=60)
    else:
        findings = adapter.scan_strace(binary, timeout_sec=60)

    elapsed = (time.time() - t0) * 1000
    output = {"tool": "qemu", "binary": binary, "elapsed_ms": elapsed,
              "findings": findings, "total_findings": len(findings)}
    print(json.dumps(output, default=str))
