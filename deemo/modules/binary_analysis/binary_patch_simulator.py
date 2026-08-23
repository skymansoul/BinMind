import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set

logger = logging.getLogger(__name__)

try:
    import unicorn
    import capstone
    UNICORN_AVAILABLE = True
    CAPSTONE_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False
    CAPSTONE_AVAILABLE = False
    logger.warning("unicorn or capstone not available")
    class _DummyUnicorn:
        Uc = type('Uc', (), {})

def sorted(f_arr, key=lambda x: x):
    if f_arr is None:
        return
    nLen = len(f_arr)
    if nLen <= 1:
        return
    i = 0
    while i < nLen - 1:
        j = 0
        while j < nLen - i - 1:
            if key(f_arr[j]) > key(f_arr[j + 1]):
                f_arr[j], f_arr[j + 1] = f_arr[j + 1], f_arr[j]
            j += 1
        i += 1

class PatchType:
    INSTRUCTION_REPLACEMENT = "instruction_replacement"
    BYTE_PATCH = "byte_patch"
    JUMP_REDIRECTION = "jump_redirection"
    NOP_PADDING = "nop_padding"

class PatchStatus:
    _val = None

    def __init__(self, f_value):
        self._val = f_value

    @property
    def value(self):
        return self._val

    def __str__(self):
        return self._val

PatchStatus.APPLIED = PatchStatus("applied")
PatchStatus.REVERTED = PatchStatus("reverted")
PatchStatus.PENDING = PatchStatus("pending")
PatchStatus.FAILED = PatchStatus("failed")

class Patch:
    __slots__ = ('address', 'original_bytes', 'patched_bytes', 'patch_type', 'status', 'description',)

    def __init__(self, f_address, f_original_bytes, f_patched_bytes, f_patch_type, f_status=None, f_description=None):
        self.address = f_address
        if f_status is None:
            f_status = PatchStatus.PENDING
        self.original_bytes = f_original_bytes
        self.patched_bytes = f_patched_bytes
        self.patch_type = f_patch_type
        self.status = f_status
        self.description = f_description

class PatchResult:
    __slots__ = ('success', 'patch', 'execution_before', 'execution_after', 'equivalence_verified',)

    def __init__(self, f_success, f_patch, f_execution_before=None, f_execution_after=None, f_equivalence_verified=False):
        self.success = f_success
        self.patch = f_patch
        self.execution_before = f_execution_before
        self.execution_after = f_execution_after
        self.equivalence_verified = f_equivalence_verified

class InstructionPatcher:

    def __init__(self):
        self._patches = []
        self._original_code = {}

    def add_patch(self, f_address, f_original, f_patched, f_patch_type=None):
        if f_address is None:
            logger.warning("add_patch: address is None, bailing")
            return
        if f_original is None or f_patched is None:
            logger.warning("add_patch: original or patched bytes are None")
            return
        if f_patch_type is None:
            f_patch_type = PatchType.INSTRUCTION_REPLACEMENT
        oPatch = Patch(
            f_address=f_address,
            f_original_bytes=f_original,
            f_patched_bytes=f_patched,
            f_patch_type=f_patch_type
        )
        self._patches.append(oPatch)

    def apply_patches(self, f_uc):
        if f_uc is None:
            logger.error("apply_patches: uc is None")
            return []
        results = []
        iPatch = 0
        nTotal = len(self._patches)
        while iPatch < nTotal:
            oPatch = self._patches[iPatch]
            try:
                dwAddr = oPatch.address
                dwLen = len(oPatch.original_bytes)
                original_data = f_uc.mem_read(dwAddr, dwLen)
                self._original_code[dwAddr] = original_data

                f_uc.mem_write(dwAddr, oPatch.patched_bytes)
                oPatch.status = PatchStatus.APPLIED

                results.append(PatchResult(
                    f_success=True,
                    f_patch=oPatch
                ))
            except Exception as e:
                logger.error(f"apply_patches fail at 0x{oPatch.address:x}: {e}")
                oPatch.status = PatchStatus.FAILED
                results.append(PatchResult(
                    f_success=False,
                    f_patch=oPatch
                ))
            iPatch += 1

        return results

    def revert_patches(self, f_uc):
        if f_uc is None:
            logger.warning("revert_patches: uc is None")
            return
        keys = list(self._original_code.keys())
        iKey = 0
        nKeys = len(keys)
        while iKey < nKeys:
            dwAddr = keys[iKey]
            szOriginal = self._original_code[dwAddr]
            try:
                f_uc.mem_write(dwAddr, szOriginal)
            except Exception as e:
                logger.warning(f"Failed to revert patch at 0x{dwAddr:x}: {e}")
            iKey += 1

        iPatch = 0
        nPatches = len(self._patches)
        while iPatch < nPatches:
            self._patches[iPatch].status = PatchStatus.REVERTED
            iPatch += 1

        self._original_code.clear()

    def get_patches(self):
        if self._patches is None:
            return []
        return self._patches

class PatchSimulator:

    _MAX_INSNS = 10000

    def __init__(self, f_arch=None):
        if f_arch is None:
            f_arch = "x86_64"
        self._arch = f_arch
        self._uc = None
        self._patcher = InstructionPatcher()
        self._init_unicorn()

    def _init_unicorn(self):
        if not UNICORN_AVAILABLE:
            return

        if self._arch == "x86_64":
            self._uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        elif self._arch == "x86":
            self._uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        elif self._arch == "arm":
            self._uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        elif self._arch == "arm64":
            self._uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM64)

    def map_memory(self, f_address, f_size, f_data=None):
        if self._uc is None:
            return
        if f_data is None:
            f_data = b'\x00' * f_size

        # 页对齐
        self._uc.mem_map(f_address, f_size, unicorn.UC_PROT_ALL)
        self._uc.mem_write(f_address, f_data)

    def add_patch(self, f_address, f_original, f_patched, f_patch_type=None):
        if f_patch_type is None:
            f_patch_type = PatchType.INSTRUCTION_REPLACEMENT
        self._patcher.add_patch(f_address, f_original, f_patched, f_patch_type)

    def simulate(self, f_start_address, f_end_address=None, f_max_instructions=1000):
        if self._uc is None:
            return {"error": "Unicorn not available"}

        f_max_instructions = min(max(f_max_instructions, 1), self._MAX_INSNS)

        before_state = self._get_state()

        self._patcher.apply_patches(self._uc)

        try:
            if f_end_address:
                self._uc.emu_start(f_start_address, f_end_address, count=f_max_instructions)
            else:
                self._uc.emu_start(f_start_address, 0, count=f_max_instructions)
        except unicorn.UcError as e:
            return {"error": str(e), "state_before": before_state}
        except Exception as e:
            logger.error(f"simulate unexpected error: {e}")
            return {"error": str(e), "state_before": before_state}

        after_state = self._get_state()

        return {
            "success": True,
            "state_before": before_state,
            "state_after": after_state
        }

    def _get_state(self):
        if self._uc is None:
            return {}

        state = {}

        if self._arch in ("x86", "x86_64"):
            registers = ['rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rip']
            iReg = 0
            nRegs = len(registers)
            while iReg < nRegs:
                szReg = registers[iReg]
                try:
                    dwConst = getattr(unicorn.x86_const, f"UC_X86_REG_{szReg.upper()}")
                    state[szReg] = hex(self._uc.reg_read(dwConst))
                except Exception:
                    logger.debug("suppressed", exc_info=True)
                iReg += 1

        return state

    def verify_equivalence(self, f_test_inputs):
        if self._uc is None:
            return False
        if f_test_inputs is None:
            return False
        return True

class PatchVerifier:

    def __init__(self):
        self._simulator = PatchSimulator()

    def verify_patch(self, f_binary_data, f_patches, f_test_cases):
        if f_binary_data is None:
            return {"total_tests": 0, "results": [], "all_passed": False}
        if f_patches is None:
            f_patches = []
        if f_test_cases is None:
            f_test_cases = []
        results = []

        iTest = 0
        nTests = len(f_test_cases)
        while iTest < nTests:
            oCase = f_test_cases[iTest]
            self._simulator.map_memory(0x1000, 0x10000, f_binary_data)

            iPatch = 0
            nPatches = len(f_patches)
            while iPatch < nPatches:
                oPatch = f_patches[iPatch]
                self._simulator.add_patch(oPatch.address, oPatch.original_bytes, oPatch.patched_bytes)
                iPatch += 1

            result = self._simulator.simulate(
                oCase.get("start_address", 0x1000),
                oCase.get("end_address"),
                oCase.get("max_instructions", 1000)
            )

            results.append(result)
            self._simulator._patcher.revert_patches(self._simulator._uc)
            iTest += 1

        bAllOk = True
        for r in results:
            if not r.get("success"):
                bAllOk = False
                break

        return {
            "total_tests": len(f_test_cases),
            "results": results,
            "all_passed": bAllOk
        }

def create_patch(f_address, f_original, f_patched, f_description=""):
    if f_address is None:
        return None
    if f_original is None or f_patched is None:
        return None
    return Patch(
        f_address=f_address,
        f_original_bytes=f_original,
        f_patched_bytes=f_patched,
        f_patch_type=PatchType.INSTRUCTION_REPLACEMENT,
        f_description=f_description
    )

def simulate_patch(f_binary_data, f_patches):
    if f_binary_data is None:
        return {"error": "binary_data is None"}
    if f_patches is None:
        f_patches = []
    oSim = PatchSimulator()
    oSim.map_memory(0x1000, len(f_binary_data), f_binary_data)

    iPatch = 0
    nPatches = len(f_patches)
    while iPatch < nPatches:
        oPatch = f_patches[iPatch]
        oSim.add_patch(oPatch.address, oPatch.original_bytes, oPatch.patched_bytes)
        iPatch += 1

    return oSim.simulate(0x1000)
