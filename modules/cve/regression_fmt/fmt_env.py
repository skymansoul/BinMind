# 格式化字符串检测共享常量 - 判定级别、printf 家族、ABI 参数寄存器.
#

class FmtVerdict:
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    BENIGN = "benign"

# puts 不解析格式串, 非格式化字符串汇点.
PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "vdprintf",
    "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
    "__mingw_snprintf", "__mingw_vprintf", "__mingw_vfprintf",
    "__mingw_vsprintf", "__mingw_vsnprintf",
}

# 格式串参数索引: printf=0, fprintf/dprintf=1, snprintf/vsnprintf=2.
FMT_ARG_IDX = {
    "printf": 0, "vprintf": 0, "dprintf": 0, "vdprintf": 0,
    "sprintf": 1, "fprintf": 1, "vfprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}

ARG_REGS_WIN64 = ("rcx", "rdx", "r8", "r9")
ARG_REGS_SYSV = ("rdi", "rsi", "rdx", "rcx")

# 输入函数: 返回值/写入缓冲为攻击者可控.
INPUT_FUNCS = {"gets", "scanf", "__isoc99_scanf", "recv", "recvfrom",
               "read", "fgets", "fread", "getenv", "strtok"}


__all__ = ["FmtVerdict", "PRINTF_FAMILY", "FMT_ARG_IDX",
           "ARG_REGS_WIN64", "ARG_REGS_SYSV", "INPUT_FUNCS"]
