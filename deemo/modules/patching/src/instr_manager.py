import logging
from abc import ABC, abstractmethod
from typing import Dict, Optional, List, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


class InstrumentationBackend(ABC):
    """动态插桩抽象后端 —— Frida / DynamoRIO / Intel PIN。

    设计取舍：
    - 每个后端返回对应引擎的原生代码片段（JS / C / C++），
      不做跨引擎抽象（强行归一化只会丢失各引擎优势）。
    - generate_* 返回字符串而非写文件，调用方自行决定内联或保存。
    """

    @abstractmethod
    def generate_hook(self, target_address: int, hook_code: str) -> str:
        ...

    @abstractmethod
    def generate_trace(self, target_address: int) -> str:
        ...

    @abstractmethod
    def generate_patch(self, target_address: int, original_bytes: bytes, patch_bytes: bytes) -> str:
        ...

    @abstractmethod
    def get_engine_name(self) -> str:
        ...

    def supported_archs(self) -> List[str]:
        return ["x86_64"]


# ============================================================
# FridaBackend：JavaScript 片段生成器
# 内存操作走 Memory.protect + Memory.writeByteArray，
# 比直接 NativeCallback 慢但跨平台稳定
# ============================================================
class FridaBackend(InstrumentationBackend):

    def get_engine_name(self) -> str:
        return "frida"

    def supported_archs(self) -> List[str]:
        return ["x86_64", "x86", "arm64", "arm32", "aarch64"]

    def generate_hook(self, target_address: int, hook_code: str = "") -> str:
        _addr = hex(target_address)
        _snippet = """// Frida hook @ {addr}
Interceptor.attach(ptr("{addr}"), {{
    onEnter(args) {{
        console.log("[Frida] enter @ {addr}");
        {hook_body}
    }},
    onLeave(retval) {{
        console.log("[Frida] leave @ {addr} -> " + retval);
    }}
}});""".format(addr=_addr, hook_body=hook_code if hook_code else "// no custom hook body")
        return _snippet

    def generate_trace(self, target_address: int) -> str:
        _addr = hex(target_address)
        _snippet = """// Frida instruction trace @ {addr}
var trace_addr = ptr("{addr}");
// 单步 trace：设临时断点，记录寄存器后立即 continue
Interceptor.attach(trace_addr, {{
    onEnter(args) {{
        var ctx = this.context;
        var regs = {{
            rax: ctx.rax, rbx: ctx.rbx, rcx: ctx.rcx, rdx: ctx.rdx,
            rsi: ctx.rsi, rdi: ctx.rdi, rsp: ctx.rsp, rbp: ctx.rbp,
            r8: ctx.r8, r9: ctx.r9, r10: ctx.r10, r11: ctx.r11,
            rip: ctx.rip
        }};
        send({{type: "trace", address: "{addr}", regs: regs}});
        // 仅记录不做 stop
    }}
}});""".format(addr=_addr)
        return _snippet

    def generate_patch(self, target_address: int, original_bytes: bytes, patch_bytes: bytes) -> str:
        _addr = hex(target_address)
        _orig_hex = original_bytes.hex()
        _patch_hex = patch_bytes.hex()
        _snippet = """// Frida runtime patch @ {addr}
var patch_addr = ptr("{addr}");
var orig = [{orig}];
var patch = [{patch}];

// 1. 解除写保护
var old_prot = Memory.protect(patch_addr, patch.length, 'rwx');

// 2. 写入补丁字节
Memory.writeByteArray(patch_addr, patch);

// 3. 恢复保护
Memory.protect(patch_addr, patch.length, old_prot);

console.log("[Frida] patched " + patch.length + " bytes @ {addr}");
""".format(addr=_addr,
           orig=",".join("0x{:02x}".format(b) for b in original_bytes),
           patch=",".join("0x{:02x}".format(b) for b in patch_bytes))
        return _snippet


# //// DynamoRIOBackend：C 代码生成 —— 直接编译进 DynamoRIO client ////
class DynamoRIOBackend(InstrumentationBackend):

    def get_engine_name(self) -> str:
        return "dynamorio"

    def supported_archs(self) -> List[str]:
        return ["x86_64", "x86", "arm64", "aarch64"]

    def generate_hook(self, target_address: int, hook_code: str = "") -> str:
        _snippet = """/* DynamoRIO hook @ 0x{addr:x} */
#include "dr_api.h"
#include "drwrap.h"

static void pre_hook_cb(void *wrapcxt, OUT void **user_data) {{
    dr_fprintf(STDERR, "[DynamoRIO] pre-hook @ 0x{addr:x}\\n");
    {hook_body}
}}

static void post_hook_cb(void *wrapcxt, void *user_data) {{
    dr_fprintf(STDERR, "[DynamoRIO] post-hook @ 0x{addr:x}\\n");
}}

static void install_hook(void *drcontext) {{
    app_pc target = (app_pc)0x{addr:x};
    drwrap_wrap(target, pre_hook_cb, post_hook_cb);
}}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {{
    dr_set_client_name("binmind_patch_hook", "https://binmind.dev");
    dr_register_bb_event(install_hook);
}}
""".format(addr=target_address,
           hook_body=hook_code if hook_code else "/* no custom hook body */")
        return _snippet

    def generate_trace(self, target_address: int) -> str:
        return """/* DynamoRIO instruction trace @ 0x{addr:x} */
#include "dr_api.h"

static dr_emit_flags_t trace_bb(void *drcontext, void *tag, instrlist_t *bb,
                                 bool for_trace, bool translating) {{
    app_pc target = (app_pc)0x{addr:x};
    instr_t *instr;
    for (instr = instrlist_first(bb); instr != NULL; instr = instr_get_next(instr)) {{
        app_pc pc = instr_get_app_pc(instr);
        if (pc >= target && pc < target + 4096) {{
            dr_insert_clean_call(drcontext, bb, instr,
                (void *)trace_callback, false, 1, OPND_CREATE_INTPTR(pc));
        }}
    }}
    return DR_EMIT_DEFAULT;
}}

static void trace_callback(app_pc pc) {{
    dr_fprintf(STDERR, "[DynamoRIO] executed @ %p\\n", pc);
}}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {{
    dr_register_bb_event(trace_bb);
}}
""".format(addr=target_address)

    def generate_patch(self, target_address: int, original_bytes: bytes, patch_bytes: bytes) -> str:
        _patch_hex_str = ", ".join("0x{:02x}".format(b) for b in patch_bytes)
        return """/* DynamoRIO runtime patch @ 0x{addr:x} */
#include "dr_api.h"

static void apply_patch(void) {{
    byte *target = (byte *)0x{addr:x};
    byte patch_bytes[] = {{ {patch_bytes} }};
    size_t patch_len = {patch_len};

    /* 1. 修改页保护 */
    dr_memory_protect(target, patch_len, DR_MEMPROT_READ | DR_MEMPROT_WRITE | DR_MEMPROT_EXEC);

    /* 2. 写入 */
    memcpy(target, patch_bytes, patch_len);

    /* 3. 刷新指令缓存 */
    dr_flush_region(target, patch_len);
    dr_fprintf(STDERR, "[DynamoRIO] patched %zu bytes @ %p\\n", patch_len, target);
}}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {{
    apply_patch();
}}
""".format(addr=target_address, patch_bytes=_patch_hex_str, patch_len=len(patch_bytes))


# //// 未完整测试 —— Intel PIN 工具链集成待完善 ////
class PinBackend(InstrumentationBackend):

    def get_engine_name(self) -> str:
        return "pin"

    def supported_archs(self) -> List[str]:
        return ["x86_64", "x86"]

    def generate_hook(self, target_address: int, hook_code: str = "") -> str:
        _snippet = """// Intel PIN function hook @ 0x{addr:x}
#include "pin.H"

VOID pre_hook_cb(CONTEXT *ctx) {{
    std::cerr << "[PIN] pre-hook @ 0x{addr:x}" << std::endl;
    {hook_body}
}}

VOID post_hook_cb(CONTEXT *ctx) {{
    std::cerr << "[PIN] post-hook @ 0x{addr:x}" << std::endl;
}}

VOID ImageLoad(IMG img, VOID *v) {{
    RTN rtn = RTN_FindByAddress(0x{addr:x});
    if (RTN_Valid(rtn)) {{
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)pre_hook_cb, IARG_CONTEXT, IARG_END);
        RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)post_hook_cb, IARG_CONTEXT, IARG_END);
        RTN_Close(rtn);
    }}
}}

int main(int argc, char *argv[]) {{
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    IMG_AddInstrumentFunction(ImageLoad, 0);
    PIN_StartProgram();
    return 0;
}}
""".format(addr=target_address,
           hook_body=hook_code if hook_code else "// no custom hook body")
        return _snippet

    def generate_trace(self, target_address: int) -> str:
        return """// Intel PIN instruction trace @ 0x{addr:x}
#include "pin.H"

VOID trace_cb(ADDRINT pc) {{
    std::cerr << "[PIN] executed @ 0x" << std::hex << pc << std::dec << std::endl;
}}

VOID Instruction(INS ins, VOID *v) {{
    ADDRINT addr = INS_Address(ins);
    if (addr >= 0x{addr:x} && addr < 0x{addr:x} + 4096) {{
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)trace_cb,
                       IARG_INST_PTR, IARG_END);
    }}
}}

int main(int argc, char *argv[]) {{
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_StartProgram();
    return 0;
}}
""".format(addr=target_address)

    def generate_patch(self, target_address: int, original_bytes: bytes, patch_bytes: bytes) -> str:
        _patch_hex_str = ", ".join("0x{:02x}".format(b) for b in patch_bytes)
        return """// Intel PIN runtime patch @ 0x{addr:x}
#include "pin.H"

VOID apply_patch() {{
    ADDRINT target = 0x{addr:x};
    unsigned char patch_data[] = {{ {patch_bytes} }};
    size_t patch_len = {patch_len};

    size_t written = 0;
    PIN_SafeCopy(&written, patch_data, (VOID *)target, patch_len);

    if (written == patch_len) {{
        std::cerr << "[PIN] patched " << patch_len << " bytes @ 0x" << std::hex << target << std::endl;
    }} else {{
        std::cerr << "[PIN] PATCH FAILED: wrote " << written << "/" << patch_len << std::endl;
    }}
}}

int main(int argc, char *argv[]) {{
    PIN_Init(argc, argv);
    apply_patch();
    PIN_StartProgram();
    return 0;
}}
""".format(addr=target_address, patch_bytes=_patch_hex_str, patch_len=len(patch_bytes))


# ============================================================
# InstrumentationManager：注册表 + 分发
# 允许外部注册自定义 backend
# ============================================================
class InstrumentationManager:
    """动态插桩后端注册表与分发器。"""

    def __init__(self):
        self._backends: Dict[str, InstrumentationBackend] = {}
        # 自动注册默认后端
        for _cls in [FridaBackend, DynamoRIOBackend, PinBackend]:
            _inst = _cls()
            self._backends[_inst.get_engine_name()] = _inst
        logger.info("InstrumentationManager initialized with %d backends: %s",
                    len(self._backends), list(self._backends.keys()))

    def register_backend(self, backend: InstrumentationBackend):
        _name = backend.get_engine_name()
        self._backends[_name] = backend
        logger.info("registered instrumentation backend: %s", _name)

    def dispatch(self, engine: str, operation: str, **kwargs) -> str:
        """将操作路由到对应后端方法。

        支持操作：'hook'、'trace'、'patch'。
        """
        _backend = self._backends.get(engine)
        if _backend is None:
            _avail = list(self._backends.keys())
            raise ValueError("unknown engine '{}' — available: {}".format(engine, _avail))
        _ops = {
            "hook":  _backend.generate_hook,
            "trace": _backend.generate_trace,
            "patch": _backend.generate_patch,
        }
        _fn = _ops.get(operation)
        if _fn is None:
            raise ValueError("unknown operation '{}' — use: {}".format(operation, list(_ops.keys())))
        return _fn(**kwargs)

    def get_available_backends(self) -> List[str]:
        return list(self._backends.keys())

    def backend_for_arch(self, arch: str) -> List[str]:
        _names = []
        for _name, _b in self._backends.items():
            if arch in _b.supported_archs():
                _names.append(_name)
        return _names
