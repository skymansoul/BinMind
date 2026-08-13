# UAF 检测辅助: 回跳循环体检测 + rip-relative 槽位键归一
# 职责:
#   detect_backward_jumps — 识别循环体指令索引集合 (循环内 free 双释放)
#   rip_slot_key — 同一符号的 rip disp 因指令长度而异, 键须用
#     objdump 注释中的目标绝对地址 (# 14000f080 <g_p>)
import re
from typing import List, Set


def detect_backward_jumps(instructions: List[str],
                          addrs: List[int]) -> Set[int]:
    """回跳指令识别: 返回循环体内指令索引集合.

    用于循环内 free 的双重释放识别 (循环 ≥2 次迭代语义).
    """
    body: Set[int] = set()
    if not addrs or len(addrs) != len(instructions):
        return body
    for i, line in enumerate(instructions):
        parts = line.strip().replace(',', ' ').split()
        if not parts:
            continue
        if not parts[0].startswith('j') or parts[0] in ('jmp',):
            continue
        if len(parts) < 2:
            continue
        target_str = parts[1].split('<')[0].strip()
        try:
            target = int(target_str, 16)
        except ValueError:
            continue
        if target < addrs[i]:
            # 后向跳转: 循环回边, 体 = [目标, 当前]
            for k, a in enumerate(addrs):
                if a == target:
                    body.update(range(k, i + 1))
                    break
    return body


def rip_slot_key(raw_line: str, fallback_off: int) -> int:
    """rip-relative 槽位的绝对地址键.

    无注释时回退 disp.
    """
    m = re.search(r'#\s*([0-9a-fA-F]+)\b', raw_line)
    if m:
        return int(m.group(1), 16)
    return fallback_off


# CRT 噪声: 非用户代码函数, UAF 检测需跳过
_CRT_NOISE = {
    'duplicate_ppstrings', '__do_global_dtors', '__do_global_ctors',
    '__gcc_register_frame', '__gcc_deregister_frame',
    '__tmainCRTStartup', 'WinMainCRTStartup', 'mainCRTStartup',
    'atexit', 'check_managed_app', 'safe_flush',
    '__mingw_invalidParameterHandler', 'dtoa_lock',
    '__mingw_glob', '__mingw_dirname', '__mingw_basename',
    '__set_errno', 'abort', 'exit',
}
_CRT_PREFIXES = ('__', '_.', '<', '_Unwind', '__cxa', '__mingw_')
_AUTO_FUNC_RE = __import__('re').compile(r'^func_\d+$')


def is_crt_function(fname: str) -> bool:
    """判断函数名是否为 CRT/编译器生成的非用户代码."""
    if fname == '_entry_':
        return True
    if _AUTO_FUNC_RE.match(fname):
        return True
    if fname in _CRT_NOISE:
        return True
    if fname.startswith(_CRT_PREFIXES):
        return True
    return False
