# 反汇编 + CRT过滤共享工具
# 为 scan_runner 和各个检测器提供一致的 objdump 解析和库函数过滤.
# 提取自 scan_runner.py v3

import re
import subprocess
from typing import Dict, List, Optional, Tuple

# CRT/库函数名标识子串: 含以下任一子串的函数视为CRT/库代码, 在用户函数范围计算中排除.
_CRT_FUNC_MARKERS = (
    "mingw", "acrt", "scrt", "tmain", "mainCRT",
    "WinMainCRT", "atexit", "setvbuf", "pre_c_init", "pre_cpp_init",
    "do_global", "__register", "dyn_tls", "cpu_features",
    "chkstk", "mingwthr", "w64_mingwthr",
    "__main", "_pei386_runtime_relocator", "do_pseudo_reloc",
    "mark_section_writable", "restore_modified_sections",
    "_gnu_exception_handler", "C_specific_handler", "mingw_SEH_error_handler",
    "__gdtoa", "__pformat", "__fpclassify",
    "__d2b", "__b2d", "__mult", "__pow5mult",
    "__rv_alloc", "__nrv_alloc", "_Balloc", "_Bfree", "_i2b",
    "__trailz", "__hi0bits", "__lo0bits",
    "__cmp_D2A", "__diff_D2A", "__rshift_D2A", "__lshift_D2A",
    "__quorem_D2A", "__strcp_D2A", "bitstob", "pmem_next",
    "dtoa_lock", "dtoa_unlock",
    "_amsg_exit", "_cexit", "_crt_atexit", "_errno", "_fpreset",
    "_matherr", "configthreadlocale", "_initterm",
    "_setargv", "check_managed_app", "_lock_file", "_unlock_file",
    "get_invalid_parameter_handler", "set_invalid_parameter_handler",
    "__report_error", "__write_memory", "duplicate_ppstrings",
    "_FindPESection", "_GetPEImageBase", "_IsNonwritableInCurrentImage",
    "_ValidateImageBase", "mingw_GetSectionForAddress",
    "mingw_GetSectionCount", "mingw_enum_import_library_names",
    "EH_FRAME_BEGIN", "gcc_register_frame", "gcc_deregister_frame",
    "RUNTIME_PSEUDO_RELOC_LIST",
)


# 用户入口函数名白名单: 这些函数名即使匹配CRT marker也不应被排除.
# '__main' marker strip后变成'main', 会误匹配用户main函数.
_USER_ENTRY_POINTS = {"main", "winmain", "wmain", "wwinmain", "dllmain"}


def is_crt_func(func_name: str) -> bool:
    """判断函数名是否属于CRT/库代码 (子串匹配)."""
    n = func_name.lower()
    # 用户入口点白名单: main/WinMain/wmain等精确匹配时不是CRT函数.
    # 注意: 用原始名称(不去下划线)比较, 避免 __main→main 误判.
    if n in _USER_ENTRY_POINTS:
        return False
    n_stripped = n.strip("_")
    for marker in _CRT_FUNC_MARKERS:
        if marker.lower().strip("_") in n_stripped:
            return True
    return False


def parse_func_ranges(objdump_out: str) -> Tuple[Dict[str, Tuple[int, int]], List[Tuple[int, int]]]:
    """从objdump输出提取函数地址范围, 分类为用户/CRT.
    返回: (all_ranges={name:(start,end)}, user_ranges=[(start,end),...])."""
    func_starts = []
    for line in objdump_out.split("\n"):
        line = line.strip()
        if line.endswith(">:") and "<" in line:
            m = re.search(r'<([^>]+)>', line)
            if not m:
                continue
            name = m.group(1)
            if "+0x" in name.lower() or name.startswith("."):
                continue
            try:
                addr = int(line.split()[0].rstrip(":"), 16)
                func_starts.append((name, addr))
            except ValueError:
                pass

    if not func_starts:
        return {}, []

    all_ranges, user_ranges = {}, []
    max_addr = 0x7FFFFFFFFFFF
    for i, (name, start) in enumerate(func_starts):
        end = func_starts[i + 1][1] if i + 1 < len(func_starts) else max_addr
        all_ranges[name] = (start, end)
        if not is_crt_func(name):
            user_ranges.append((start, end))
    return all_ranges, user_ranges


def filter_import_stubs(instructions: List[dict],
                        user_ranges: List[Tuple[int, int]]
                        ) -> List[Tuple[int, int]]:
    """从user_ranges中移除PE导入桩函数.

    PE导入桩特征:
      - 函数体仅含 jmp [rip+...] (# <__imp_XXX>) + nop填充
      - 8字节大小 (6字节jmp + 2字节nop)
      - 集中在.text末尾的高地址区域
    这些是链接器生成的跳板, 不是用户代码.
    """
    if not user_ranges:
        return user_ranges

    # 按地址排序以加速查找
    sorted_ranges = sorted(user_ranges, key=lambda r: r[0])
    # 构建 {start_addr: (start, end)} 映射 (导入桩只查小范围)
    range_by_start = {lo: (lo, hi) for lo, hi in sorted_ranges}

    # 收集每个函数范围内的指令分类
    # 导入桩判定: 范围≤16字节 且 全部指令为 jmp[rip+__imp_*] 或 nop
    stub_starts: set = set()
    for lo, hi in sorted_ranges:
        func_size = hi - lo
        # 导入桩≤16字节 (通常8: jmp[6] + nop[1] + nop[1])
        if func_size > 16:
            continue
        func_ins = [i for i in instructions
                    if lo <= i.get("address", 0) < hi]
        if not func_ins:
            continue
        is_stub = True
        has_imp_jmp = False
        for ins in func_ins:
            mnem = ins.get("mnemonic", "").lower()
            ops_str = " ".join(ins.get("operands", []))
            if mnem == "jmp" and "rip" in ops_str.lower() \
               and "__imp_" in ops_str.lower():
                has_imp_jmp = True
                continue
            if mnem == "nop":
                continue
            # 其他指令 → 不是纯导入桩
            is_stub = False
            break
        if is_stub and has_imp_jmp:
            stub_starts.add(lo)

    if not stub_starts:
        return user_ranges

    return [(lo, hi) for lo, hi in user_ranges if lo not in stub_starts]


def disassemble_binary(binary: str) -> Tuple[List[dict], str, int, List[Tuple[int, int]]]:
    """用objdump反汇编为统一格式的指令列表.
    返回: (instructions, file_format, main_addr, user_func_ranges)."""
    instructions, file_format, main_addr = [], "", 0
    try:
        out = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary],
            capture_output=True, timeout=30
        ).stdout.decode("utf-8", errors="replace")
    except Exception:
        return instructions, file_format, main_addr, []

    all_ranges, user_ranges = parse_func_ranges(out)
    for name, (start, _) in all_ranges.items():
        if name.lower() == "main":
            main_addr = start
            break

    for line in out.split("\n"):
        line = line.strip()
        if "file format" in line:
            file_format = line.split("file format")[-1].strip()
            continue
        if not line or line.startswith("Disassembly"):
            continue
        if line.endswith(">:") and "<" in line:
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            try:
                addr = int(parts[0].strip().rstrip(":"), 16)
                mnem = parts[2].split()[0] if parts[2].split() else ""
                ops_str = " ".join(parts[2].split()[1:]) if len(parts[2].split()) > 1 else ""
                instructions.append({
                    "address": addr,
                    "mnemonic": mnem,
                    "operands": [o.strip() for o in ops_str.split(",") if o.strip()],
                })
            except ValueError:
                continue
    # 过滤PE导入桩: 链接器生成的 jmp [rip+...] 跳板, 非用户代码
    user_ranges = filter_import_stubs(instructions, user_ranges)

    return instructions, file_format, main_addr, user_ranges


# 指令/寄存器/地址 通用工具 (供各检测器复用)

_W32_TO_W64 = {
    "eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
    "esi":"rsi","edi":"rdi","r8d":"r8","r9d":"r9",
    "ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
    "si":"rsi","di":"rdi",
}


def norm_reg(reg: str) -> str:
    """寄存器归一化: ecx→rcx, eax→rax (32→64bit). 剥离objdump注释."""
    r = reg.strip().lower().lstrip("%").replace("$", "")
    if "#" in r:
        r = r.split("#")[0].strip()  # 剥离 "rax # 0x140009080 <symbol>" 的注释
    if "[" in r:
        return r
    return _W32_TO_W64.get(r, r)


def extract_stack_slot(operand: str) -> Optional[str]:
    """提取栈槽标识: [rbp-0x8]→'rbp-0x8', [rsp+0x28]→'rsp+0x28', 或 None.

    O2/Os使用rsp直接寻址而非rbp帧指针, 需同时匹配两种.
    """
    op = operand.strip().lower()
    op = re.sub(r'(qword|dword|word|byte)\s+ptr\s+', '', op)
    cleaned = op.replace(' ', '')
    m = re.search(r'\[(r[bs]p[-+]0x[0-9a-f]+)\]', cleaned)
    if m:
        return m.group(1)
    m = re.search(r'\[(r[bs]p)\]', cleaned)
    if m:
        return m.group(1)
    return None


def resolve_rip_relative(ins: dict, operand: str, addr: int) -> Optional[int]:
    """解析RIP相对地址为绝对地址.
    mov [rip+0xd902], rax → RIP=addr+ins_len, target=RIP+offset.
    也支持直接地址: [0x14000f080]."""
    op = operand.strip().lower()
    m = re.search(r'rip\s*([+-]\s*0x[0-9a-f]+|[-+]\s*\d+)', op)
    if m:
        offset_str = m.group(1).replace(" ", "")
        try:
            offset = int(offset_str, 16) if "0x" in offset_str.lower() else int(offset_str)
        except ValueError:
            return None
        ins_len = _estimate_ins_len(ins)
        return addr + ins_len + offset
    m2 = re.search(r'\[(0x[0-9a-f]+)\]', op)
    if m2:
        return int(m2.group(1), 16)
    return None


def _estimate_ins_len(ins: dict) -> int:
    """估算指令字节长度.

    对RIP相对寻址, 编码为 REX.W + opcode + ModR/M + disp32 (+ imm32).
    无立即数=7字节, 有立即数=11字节 (mov [rip+...], imm32).
    """
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    ops_str = " ".join(ops)
    if mnem == "call":
        return 5
    if "rip" in ops_str.lower():
        # mov [rip+...], imm → REX.W(1) + C7(1) + ModR/M(1) + disp32(4) + imm32(4) = 11
        if len(ops) >= 2:
            src = ops[1].strip()
            # 剥离注释: "0x0 # comment" → "0x0"
            src_clean = src.split("#")[0].strip() if "#" in src else src
            # 检测立即数
            if src_clean.startswith(("0x", "$")) or \
               (src_clean.lstrip("-").isdigit() and not _is_register(src_clean)):
                return 11
        return 7
    if mnem == "lea":
        return 7
    if mnem == "mov" and any(o.startswith("$") or o.startswith("0x") for o in ops):
        return 6
    return 6


def _is_register(s: str) -> bool:
    """检查字符串是否为寄存器名."""
    s = s.strip().lower().lstrip("%")
    return s in _W32_TO_W64 or s in _W32_TO_W64.values()


_32BIT_REGS = {
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
}


def is_32bit_reg(reg: str) -> bool:
    """判断寄存器是否为 32 位变体."""
    return reg.strip().lower().lstrip("%") in _32BIT_REGS


def parse_imm_signed(operand: str, reg: str = "") -> Optional[int]:
    """解析立即数, 依据目标寄存器宽度做符号扩展.

    决策: x86 编译器的负数常以无符号形式编码 (如 -128 写作
    0xffffff80), 无符号解析会把 sub eax, 0xffffff80 算成
    eax = eax - 4294967168 而非 eax + 128, 直接导致堆大小
    负化 → 误判安全. 必须按操作数宽度回绕.
    """
    s = operand.strip().lower().lstrip("$").split("#")[0].strip()
    try:
        if s.startswith("0x"):
            v = int(s, 16)
        elif s.isdigit():
            v = int(s)
        elif s.startswith("-") and s[1:].isdigit():
            v = int(s)
        else:
            return None
    except ValueError:
        return None

    if v < 0:
        return v
    reg_norm = reg.strip().lower().lstrip("%")
    if "[" in reg_norm or not reg_norm:
        return v  # 非寄存器目标: 不适用宽度回绕
    if reg_norm in _32BIT_REGS:
        if v >= 0x80000000:
            return v - 0x100000000
        return v
    if v >= 0x8000000000000000:
        return v - 0x10000000000000000
    return v


# MinGW 函数名归一化表: __mingw_xxx → xxx
_MINGW_NORMALIZE = {
    "__mingw_printf": "printf",
    "__mingw_sprintf": "sprintf",
    "__mingw_snprintf": "snprintf",
    "__mingw_fprintf": "fprintf",
    "__mingw_vfprintf": "vfprintf",
    "__mingw_vsprintf": "vsprintf",
    "__mingw_vsnprintf": "vsnprintf",
    "__mingw_scanf": "scanf",
    "__mingw_sscanf": "sscanf",
    "__mingw_fscanf": "fscanf",
    "__mingw_malloc": "malloc",
    "__mingw_free": "free",
    "__mingw_realloc": "realloc",
    "__mingw_calloc": "calloc",
    "__mingw_strcpy": "strcpy",
    "__mingw_strncpy": "strncpy",
    "__mingw_strcat": "strcat",
    "__mingw_strncat": "strncat",
    "__mingw_strlen": "strlen",
    "__mingw_strcmp": "strcmp",
    "__mingw_strncmp": "strncmp",
    "__mingw_memcpy": "memcpy",
    "__mingw_memmove": "memmove",
    "__mingw_memset": "memset",
    "__mingw_memcmp": "memcmp",
    "__mingw_fopen": "fopen",
    "__mingw_fclose": "fclose",
    "__mingw_fread": "fread",
    "__mingw_fwrite": "fwrite",
    "__mingw_fgets": "fgets",
    "__mingw_fputs": "fputs",
    "__mingw_puts": "puts",
    "__mingw_putchar": "putchar",
}


def extract_func_name(target: str) -> str:
    """从call操作数提取函数名, MinGW重命名自动归一化.
    'call 140003368 <__mingw_printf>' → 'printf'."""
    t = target.strip().lower()
    for p in ("call ", "callq "):
        if t.startswith(p):
            t = t[len(p):]
    m = re.search(r"<([^>]+)>", t)
    if m:
        t = m.group(1)
    name = t.split("@")[0].split("(")[0].split(".")[-1]
    return _MINGW_NORMALIZE.get(name, name)


__all__ = ["is_crt_func", "parse_func_ranges", "filter_import_stubs",
           "disassemble_binary",
           "norm_reg", "extract_stack_slot", "resolve_rip_relative",
           "extract_func_name", "parse_imm_signed", "is_32bit_reg"]
