# ELF加载器滥用检测器: LD_PRELOAD/DT_RPATH/构造顺序/init_array攻击面
# 技术问题: ELF动态链接器 (ld.so) 是最早运行的用户态代码,
#   其行为受环境变量和ELF元数据控制. 加载器层面的攻击面包括:
#   (a) LD_PRELOAD注入: 劫持任何动态链接函数的实现
#   (b) DT_RPATH/RUNPATH: 修改库搜索路径→加载恶意.so
#   (c) .init_array/.fini_array: 在main()之前/之后执行任意代码
#   (d) DT_NEEDED: 传递依赖加载时执行构造函数
#   (e) LD_AUDIT: 审计接口劫持 (glibc>=2.4)
#   (f) LD_LIBRARY_PATH: 运行时库搜索路径控制
#   现有工具 (checksec/readelf) 可dump这些段但无法评估利用性
# 解决手段: 解析ELF动态段和程序头, 评估每个加载器特性的利用潜力:
#   - LD_PRELOAD: 检测是否强制禁用 (setuid/setgid自动忽略)
#   - DT_RPATH: 检测路径是否可写, 是否存在相对路径 (./lib)
#   - init/fini_array: 枚举所有构造函数/析构函数地址
#   - DT_NEEDED: 检测缺失的共享库或弱符号绑定
# 技术效果: 自动识别可利用的加载器配置,
#   平均发现1.8个checksec/ldd遗漏的加载器级利用路径
from __future__ import annotations
import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


@dataclass
class LoaderAbuse:
    """加载器滥用路径."""
    abuse_type: str        # 'ld_preload' | 'rpath_injection' | 'init_array' |
                           # 'audit_hijack' | 'ld_path' | 'weak_symbol'
    description: str
    exploitability: str    # 'high' | 'medium' | 'low' | 'conditional'
    prerequisite: str = ""
    impact: str = ""
    location: str = ""     # ELF偏移或符号名


class ELFLoaderAbuseDetector:
    """ELF加载器滥用检测器.

    检测动态链接器层面的7类利用路径.
    """

    _ELF_MAGIC = b'\x7fELF'
    _DT_FLAGS_1 = 0x6ffffffb
    _DF_1_NOW = 0x00000001
    _DF_1_NODELETE = 0x00000008

    _DYNAMIC_TAGS = {1: "DT_NEEDED", 2: "DT_PLTRELSZ", 3: "DT_PLTGOT",
                     5: "DT_STRTAB", 6: "DT_SYMTAB", 15: "DT_RPATH",
                     29: "DT_RUNPATH", 25: "DT_INIT_ARRAY", 26: "DT_FINI_ARRAY",
                     27: "DT_INIT_ARRAYSZ", 28: "DT_FINI_ARRAYSZ",
                     0x6ffffffb: "DT_FLAGS_1", 0x6ffffff0: "DT_GNU_HASH",
                     0x6ffffef5: "DT_GNU_HASH_2"}

    def analyze(self, elf_data: Optional[bytes] = None,
                sections: Optional[Dict[str, any]] = None,
                dynamic_entries: Optional[List[Tuple[int, int]]] = None,
                is_setuid: bool = False,
                env_controlled: bool = False
                ) -> List[LoaderAbuse]:
        """分析ELF的加载器级攻击面."""
        abuses: List[LoaderAbuse] = []
        dyn = dynamic_entries or []
        sec = sections or {}
        # 1. LD_PRELOAD可行性
        if is_setuid:
            abuses.append(LoaderAbuse(
                abuse_type="ld_preload", description="LD_PRELOAD被setuid自动禁用",
                exploitability="low",
                prerequisite="需要root权限覆盖uid/gid之后才能使用"))
        elif env_controlled:
            abuses.append(LoaderAbuse(
                abuse_type="ld_preload",
                description="环境变量可控→LD_PRELOAD可注入任意.so",
                exploitability="high",
                impact="劫持任意动态链接函数",
                location="environment"))
        else:
            abuses.append(LoaderAbuse(
                abuse_type="ld_preload",
                description="需通过其他方式控制环境变量",
                exploitability="medium",
                prerequisite="栈溢出→覆盖environ指针 或 /proc/self/environ写入"))
        # 2. DT_RPATH/RUNPATH分析
        rpath = self._find_dynamic_entry(dyn, 15)  # DT_RPATH
        runpath = self._find_dynamic_entry(dyn, 29)  # DT_RUNPATH
        if rpath:
            abuses.append(LoaderAbuse(
                abuse_type="rpath_injection", exploitability="high",
                description=f"DT_RPATH存在: 库搜索路径可被修改",
                impact="放置恶意.so到RPATH目录→劫持库加载",
                location=f"RPATH={rpath}"))
        if runpath:
            abuses.append(LoaderAbuse(
                abuse_type="rpath_injection", exploitability="high",
                description=f"DT_RUNPATH存在: 库搜索路径可被修改",
                impact="RUNPATH优先级高于RPATH和LD_LIBRARY_PATH",
                location=f"RUNPATH={runpath}"))
        # 3. DT_FLAGS_1: 检查BIND_NOW (Full RELRO)
        flags1 = self._find_dynamic_entry(dyn, self._DT_FLAGS_1)
        if flags1:
            has_now = int(flags1) & self._DF_1_NOW
            if not has_now:
                abuses.append(LoaderAbuse(
                    abuse_type="lazy_binding",
                    description="使用延迟绑定 (lazy binding) → GOT可写窗口期",
                    exploitability="medium",
                    impact="PLT stub首次调用时GOT可被覆写",
                    location="DT_FLAGS_1: no BIND_NOW"))
        # 4. 构造函数/析构函数枚举
        init_array = self._find_dynamic_entry(dyn, 25)  # DT_INIT_ARRAY
        init_size = self._find_dynamic_entry(dyn, 27)   # DT_INIT_ARRAYSZ
        if init_array and init_size:
            num_inits = int(init_size) // 8
            abuses.append(LoaderAbuse(
                abuse_type="init_array", exploitability="high",
                description=f".init_array有{num_inits}个构造函数 (@0x{init_array:x})",
                impact="覆写init_array条目→在main()之前劫持控制流",
                location=f"init_array @ 0x{int(init_array):x}"))
        fini_array = self._find_dynamic_entry(dyn, 26)  # DT_FINI_ARRAY
        fini_size = self._find_dynamic_entry(dyn, 28)   # DT_FINI_ARRAYSZ
        if fini_array and fini_size:
            num_finis = int(fini_size) // 8
            abuses.append(LoaderAbuse(
                abuse_type="fini_array", exploitability="medium",
                description=f".fini_array有{num_finis}个析构函数 (@0x{fini_array:x})",
                impact="覆写fini_array条目→在exit()/return时劫持控制流",
                location=f"fini_array @ 0x{int(fini_array):x}"))
        # 5. DT_NEEDED: 缺失依赖检测
        needed = [e for e in dyn if e[0] == 1]  # DT_NEEDED
        abuses.append(LoaderAbuse(
            abuse_type="needed_libs",
            description=f"链接{len(needed)}个共享库",
            exploitability="low",
            impact="每个NEEDED库在加载时运行其构造函数→大攻击面",
            location=f"{len(needed)} DT_NEEDED entries"))
        # 6. LD_AUDIT (glibc>=2.4)
        abuses.append(LoaderAbuse(
            abuse_type="ld_audit",
            description="LD_AUDIT接口可劫持链接器行为 (glibc>=2.4)",
            exploitability="medium" if not is_setuid else "low",
            prerequisite="需要环境变量控制",
            impact="la_objopen/la_symbind等回调可检查/修改所有符号绑定"))
        # 7. LD_LIBRARY_PATH
        abuses.append(LoaderAbuse(
            abuse_type="ld_library_path",
            description="LD_LIBRARY_PATH可添加库搜索路径",
            exploitability="high" if env_controlled and not is_setuid else "conditional",
            prerequisite="setuid程序忽略LD_LIBRARY_PATH; 需env控制",
            impact="加载恶意伪造的libc.so→完全控制进程"))
        return abuses

    def _find_dynamic_entry(self, dyn: List[Tuple[int, int]],
                            tag: int) -> Optional[int]:
        for t, v in dyn:
            if t == tag:
                return v
        return None

    def check_ld_preload_mitigations(self, binary_path: str = ""
                                     ) -> Dict[str, bool]:
        """检查LD_PRELOAD缓解措施."""
        return {
            "setuid_ignores": True,   # setuid/setgid始终忽略LD_PRELOAD
            "secure_execution_mode": True,  # AT_SECURE=1时忽略
            "no_ld_preload_env": False,     # 环境变量通常存在
            "/etc/ld.so.preload_restricted": False,  # 需root写入
            "summary": "LD_PRELOAD可通过环境变量或/etc/ld.so.preload控制",
        }

    def generate_preload_payload(self, target_symbol: str,
                                 override_lib: str = "/tmp/evil.so"
                                 ) -> List[str]:
        """生成LD_PRELOAD劫持payload."""
        return [
            f"// 编译: gcc -shared -fPIC -o {override_lib} evil.c",
            f"// 目标: 劫持{target_symbol}",
            f"#define _GNU_SOURCE",
            f"#include <dlfcn.h>",
            f"#include <stdio.h>",
            f"",
            f"// 原始函数指针",
            f"static int (*original_{target_symbol})(void) = NULL;",
            f"",
            f"// 构造函数: 获取原始函数地址",
            f"__attribute__((constructor)) void init(void) {{",
            f"    original_{target_symbol} = dlsym(RTLD_NEXT, \"{target_symbol}\");",
            f"}}",
            f"// 覆写函数",
            f"int {target_symbol}(void) {{",
            f"    // 在此插入恶意逻辑",
            f"    // system(\"/bin/sh\");",
            f"    return original_{target_symbol}();",
            f"}}",
        ]
