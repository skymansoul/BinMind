# QEMU User Mode Tracer - 轻量插桩获取运行时内存操作
# 用 -strace 追踪系统调用, 提取 heap 相关操作作为 ground truth.

import os, sys, json, time, subprocess

def find_qemu() -> str:
    for name in ["qemu-x86_64", "qemu-x86_64-static"]:
        try:
            r = subprocess.run(["which", name], capture_output=True, text=True)
            if r.returncode == 0: return r.stdout.strip()
        except Exception: pass
    return ""

DANGEROUS_SYSCALLS = {"mmap","mprotect","brk","mremap",
                       "memfd_create","process_vm_writev"}

def trace_binary(binary_path: str, timeout: int = 60) -> list:
    qemu = find_qemu()
    if not qemu: return [{"error": "qemu_not_found"}]
    try:
        proc = subprocess.run([qemu, "-strace", binary_path],
                              capture_output=True, text=True, timeout=timeout)
        findings = []
        for line in proc.stderr.split("\n") + proc.stdout.split("\n"):
            for sc in DANGEROUS_SYSCALLS:
                if sc in line.lower():
                    findings.append({"type":"heap_syscall","syscall":sc,
                                     "detail": line.strip()[:200]})
        return findings
    except subprocess.TimeoutExpired:
        return [{"error": "timeout"}]

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: qemu_tracer.py <binary>"}))
        sys.exit(1)
    binary = sys.argv[1]
    if not os.path.isfile(binary):
        print(json.dumps({"error": f"not_found:{binary}"}))
        sys.exit(1)
    t0 = time.time()
    findings = trace_binary(binary)
    elapsed = (time.time() - t0) * 1000
    result = {"tool": "qemu", "binary": binary, "elapsed_ms": elapsed,
              "findings": findings, "total": len(findings)}
    print(json.dumps(result, default=str))
