"""
栈溢出 canary 检测 —— 识别目标函数是否启用栈保护。

"""


import logging

_log = logging.getLogger(__name__)


def detect_canary_in_function(binary_path: str, func_name: str) -> bool:
    """
    检测目标函数是否启用了栈 canary 保护。

    通过 r2 反汇编搜索 __stack_chk_fail 调用来判断。
    """
    try:
        import subprocess
        from config import R2_PATH

        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdf~__stack_chk', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        if '__stack_chk_fail' in proc.stdout:
            return True
    except Exception:
        pass

    # angr 回退
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        for f in cfg.functions.values():
            if f.name == func_name:
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            target = insn.operands[0].imm
                            callee = cfg.functions.get(target)
                            if callee and callee.name == '__stack_chk_fail':
                                return True
    except Exception:
        pass

    return False
