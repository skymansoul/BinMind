"""
Angr 堆溢出检测脚本 — 通过符号执行追踪 malloc 大小与 memcpy 写入量。
供 experiment_runner.py 调用，输出 JSON。
用法: python angerscan_heap.py <binary_path>
"""
import json
import sys

def scan_with_angr(binary_path: str) -> dict:
    result = {"binary": binary_path, "findings": 0, "details": [], "error": ""}
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        for func in cfg.functions.values():
            malloc_calls = []
            memcpy_calls = []
            for block in func.blocks:
                for insn in block.capstone.insns:
                    if insn.mnemonic == 'call':
                        target = insn.operands[0].imm if insn.operands else 0
                        callee = cfg.functions.get(target)
                        name = callee.name if callee else ""
                        if 'malloc' in name:
                            malloc_calls.append(block.addr)
                        elif 'memcpy' in name or 'strcpy' in name:
                            memcpy_calls.append(block.addr)

            if malloc_calls and memcpy_calls:
                result["findings"] += 1
                result["details"].append({
                    "function": func.name,
                    "malloc_sites": [hex(a) for a in malloc_calls],
                    "memcpy_sites": [hex(a) for a in memcpy_calls],
                })
    except ImportError:
        result["error"] = "angr not installed"
    except Exception as e:
        result["error"] = str(e)
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: angerscan_heap.py <binary>"}))
        sys.exit(1)
    print(json.dumps(scan_with_angr(sys.argv[1]), indent=2))
