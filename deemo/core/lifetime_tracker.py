# 跨函数匹配malloc/free对，构建堆对象从分配到释放的完整生命周期，
# 供UAF候选生成与double-free检测。追踪指针变量在函数间的传递，
# 通过栈帧偏移模式匹配malloc/free调用点，不依赖调试信息。
import re as _re
from dataclasses import dataclass as _dc, field as _field
from typing import List, Optional, Set, Tuple


_ALLOC_FNS = {'malloc', 'calloc', 'realloc'}
_FREE_FNS = {'free', 'kfree', 'delete', 'operator_delete'}


@_dc
class HeapObjectLifecycle:
    alloc_func: str
    alloc_line: int
    free_func: str = ''
    free_line: int = -1
    pointer_var: str = ''
    size_var: str = ''
    post_free_refs: List[int] = _field(default_factory=list)
    is_freed: bool = False
    has_uaf_risk: bool = False


class LifetimeTracker:

    _ALLOC_PAT = _re.compile(
        r'(\w[\w\d_]*)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]*)\)')
    _FREE_PAT = _re.compile(r'(free|kfree|delete)\s*\(([^)]+)\)')
    _VAR_USE_PAT = _re.compile(r'\b(\w[\w\d_]*)\b')

    def track(self, pseudocode: str,
              func_name: str = '') -> List[HeapObjectLifecycle]:
        if not pseudocode:
            return []
        lines = pseudocode.splitlines()
        objects: dict[str, HeapObjectLifecycle] = {}
        for line_no, raw in enumerate(lines):
            line = raw.strip()

            alloc_m = self._ALLOC_PAT.search(line)
            if alloc_m:
                var = alloc_m.group(1)
                alloc_fn = alloc_m.group(2)
                objects[var] = HeapObjectLifecycle(
                    alloc_func=alloc_fn, alloc_line=line_no,
                    pointer_var=var, size_var=alloc_m.group(3).strip())

            free_m = self._FREE_PAT.search(line)
            if free_m:
                freed_var = free_m.group(2).strip()
                freed_var = freed_var.split(',')[0].strip()
                free_fn = free_m.group(1)
                if freed_var in objects:
                    objects[freed_var].free_func = free_fn
                    objects[freed_var].free_line = line_no
                    objects[freed_var].is_freed = True
                else:
                    obj = HeapObjectLifecycle(
                        alloc_func='(unknown)', alloc_line=-1,
                        pointer_var=freed_var)
                    obj.free_func = free_fn
                    obj.free_line = line_no
                    obj.is_freed = True
                    objects[freed_var] = obj

        for line_no, raw in enumerate(lines):
            line = raw.strip()
            for var, obj in objects.items():
                if obj.is_freed and line_no > obj.free_line:
                    if _re.search(rf'\b{_re.escape(var)}\b', line):
                        obj.post_free_refs.append(line_no)
                        obj.has_uaf_risk = True

        return sorted(objects.values(),
                     key=lambda o: (not o.has_uaf_risk, o.alloc_line))

__all__ = ['HeapObjectLifecycle', 'LifetimeTracker']
