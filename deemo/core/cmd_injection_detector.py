# 命令注入的核心是外部输入到达命令执行函数的第一个参数.
# 检测策略: 追踪shell元字符($()|;&)出现在system/popen参数中
# 且该参数可追溯到用户输入源的情况.
import re
from dataclasses import dataclass, field

_CMD_EXEC = {'system','popen','execve','execvp','execvpe','execl','execlp','execle'}
_SHELL_META = {';','|','&','$','`','(',')','<','>','\n','&&','||','$('}
_TAINT_SRC = {'read','recv','fgets','scanf','gets','argv','getenv','fread','recvfrom','recvmsg','stdin','socket','accept'}

@dataclass
class CmdInjFinding:
    finding_id: str = ""
    func_name: str = ""       # 命令执行函数名
    line: int = 0
    has_shell_meta: bool = False
    tainted: bool = False
    confidence: float = 0.5
    severity: str = "high"
    cwe: str = "CWE-78"
    description: str = ""

def detect_cmd_injection(ir_lines, func_name=""):
    """检测命令注入: system/popen参数来自用户输入且含shell元字符."""
    findings = []
    code = '\n'.join(ir_lines)
    # 第一遍: 标记污点变量
    tainted = set()
    for lineno, line in enumerate(ir_lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip().lower()
        if any(src in rhs for src in _TAINT_SRC):
            tainted.add(lhs)
    # 第二遍: 传播一步
    for lineno, line in enumerate(ir_lines):
        eq = line.find('=')
        if eq < 0: continue
        lhs = line[:eq].strip().split()[-1].strip('*').strip()
        rhs = line[eq+1:].strip()
        for tv in list(tainted):
            if tv in rhs and lhs != tv:
                tainted.add(lhs)
    # 第三遍: 检测命令执行函数调用
    for lineno, line in enumerate(ir_lines):
        line_l = line.lower()
        for cmd_func in _CMD_EXEC:
            if cmd_func not in line_l: continue
            # 提取第一个参数
            arg_start = line_l.find(cmd_func) + len(cmd_func)
            arg_str = line[arg_start:].strip().lstrip('(').split(',')[0].strip().strip('"').strip("'")
            has_meta = any(m in arg_str for m in _SHELL_META)
            is_tainted = any(tv in arg_str for tv in tainted)
            if is_tainted:
                conf = 0.85 if has_meta else 0.60
                findings.append(CmdInjFinding(
                    finding_id=f"CMD_{cmd_func}_{lineno}",
                    func_name=cmd_func, line=lineno,
                    has_shell_meta=has_meta, tainted=True,
                    confidence=conf,
                    severity="critical" if has_meta else "high",
                    description=f"{cmd_func}参数来自用户输入{'且含shell元字符' if has_meta else ''}"))
    return findings
