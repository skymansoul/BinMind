# 拆分自 integer_overflow_detector.py — 正则模式与工具函数.
# 独立模块: 所有模式常量集中管理, 便于模式扩展时不触碰核心检测逻辑.
import re

# 阈值
INT32_MAX = 0x7FFFFFFF
UINT32_MAX = 0xFFFFFFFF
SIZE_T_MAX = 0xFFFFFFFFFFFFFFFF  # 64-bit

# 模式
# 乘/加赋值: sz = a * b, sz = a + b, sz = n * sizeof(...)
_MUL_ASSIGN = re.compile(
    r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*\*\s*(\w[\w\d_]*|sizeof\s*\([^)]+\)|\d+)')
_ADD_ASSIGN = re.compile(
    r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*\+\s*(\w[\w\d_]*|\d+)')
# 窄类型声明: unsigned short n, uint16_t n, WORD n, etc.
_NARROW_TYPE = re.compile(
    r'\b(?:unsigned\s+short|uint16_t|WORD|unsigned\s+char|uint8_t|BYTE|'
    r'short\s+int|short)\s+(\w[\w\d_]*)')
# 真正宽类型: 在64位平台上不会常规溢出
# 注意: unsigned int / uint32_t / u32 是32位的, CAN溢出! 不在宽类型列表中.
_WIDE_TYPE = re.compile(
    r'\b(?:size_t|uint64_t|unsigned\s+long\s+long|ssize_t|int64_t|'
    r'unsigned\s+long)\s+(\w[\w\d_]*)')
# alloc调用
_ALLOC_CALL = re.compile(
    r'(?:malloc|calloc|realloc|kmalloc|kzalloc|kcalloc|vmalloc|'
    r'krealloc)\s*\(([^)]+)\)')
# calloc风格
_CALLOC = re.compile(
    r'(?:calloc|kcalloc)\s*\(\s*(\w[\w\d_]*)\s*,\s*(\w[\w\d_]*|sizeof\s*\([^)]+\)|\d+)\s*\)')
# 移位溢出: sz = 1 << c, sz = n << shift
_SHIFT_ASSIGN = re.compile(
    r'(\w[\w\d_]*)\s*=\s*(?:1\s*<<\s*(\w[\w\d_]*)|(\w[\w\d_]*)\s*<<\s*(\w[\w\d_]*|\d+))')
# 溢出守卫
_OVERFLOW_GUARD = re.compile(
    r'if\s*\(\s*(\w[\w\d_]*)\s*[<>]\s*(?:\w+\s*/\s*\w+|MAX\w*|UINT\w*_MAX|SIZE_MAX|'
    r'0x[7F]+\s*/\s*\w+)')

# 已知安全的常量/模式
_SAFE_CONSTANTS = {'sizeof', 'MAX', 'SIZE_MAX', 'UINT_MAX', 'INT_MAX'}


def _extract_balanced_args(text: str, open_paren_pos: int) -> str:
    """从 open_paren_pos 处的 '(' 提取平衡括号内的参数.
    处理嵌套括号 (如强制转换、sizeof). 返回括号间文本, 不含外围括号.
    """
    depth = 0
    for i in range(open_paren_pos, len(text)):
        ch = text[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return text[open_paren_pos + 1:i]
    return text[open_paren_pos + 1:]  # 不平衡, 返回到行尾


# 编译后的 alloc/mem 函数名模式 (不含括号捕获, 用于平衡提取)
_ALLOC_FUNC = re.compile(
    r'(?:malloc|calloc|realloc|kmalloc|kzalloc|kcalloc|vmalloc|krealloc)\s*\(')
_MEM_OPS_FUNC = re.compile(
    r'(?:memcpy|memmove|memset|strcpy|strncpy|bcopy|bzero|'
    r'copy_to_user|copy_from_user)\s*\(')
