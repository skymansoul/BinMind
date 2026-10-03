/* FindHeapOverflow.java — Ghidra headless analysis script
 * Detects potential heap overflow patterns: malloc(N) followed by memcpy with M > N.
 *
 * Usage: analyzeHeadless <project> <folder> -import <binary> -postScript FindHeapOverflow.java
 */

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;

public class FindHeapOverflow extends GhidraScript {

    // Heap allocation functions
    private static final String[] ALLOC_FUNCS = {
        "malloc", "calloc", "realloc", "_Znwm", "_Znam"
    };

    // Dangerous write functions (commonly follow alloc functions)
    private static final String[] WRITE_FUNCS = {
        "memcpy", "memmove", "strcpy", "strncpy", "sprintf",
        "snprintf", "strcat", "strncat", "fgets", "read"
    };

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionManager funcMgr = currentProgram.getFunctionManager();

        // Iterate over all defined functions
        for (Function func : funcMgr.getFunctions(true)) {
            String name = func.getName().toLowerCase();

            // Check for alloc functions
            for (String allocFn : ALLOC_FUNCS) {
                if (name.contains(allocFn)) {
                    // Found an alloc call — now look for subsequent write calls
                    Instruction instr = listing.getInstructionAt(func.getEntryPoint());
                    if (instr == null) continue;

                    // Search forward in the same function for write calls
                    Function parent = funcMgr.getFunctionContaining(func.getEntryPoint());
                    if (parent == null) continue;

                    Address addr = func.getEntryPoint();
                    Address endAddr = parent.getBody().getMaxAddress();

                    while (addr != null && addr.compareTo(endAddr) <= 0) {
                        Instruction nextInstr = listing.getInstructionAfter(addr);
                        if (nextInstr == null) break;
                        addr = nextInstr.getAddress();

                        // Check if this instruction is a call to a dangerous write
                        Reference[] refs = nextInstr.getReferencesFrom();
                        for (Reference ref : refs) {
                            if (ref.getReferenceType().isCall()) {
                                String calleeName = "";
                                Symbol sym = currentProgram.getSymbolTable()
                                    .getPrimarySymbol(ref.getToAddress());
                                if (sym != null) {
                                    calleeName = sym.getName().toLowerCase();
                                }

                                for (String writeFn : WRITE_FUNCS) {
                                    if (calleeName.contains(writeFn)) {
                                        printf("HEAP_OVERFLOW_CANDIDATE: alloc=%s@0x%x write=%s@0x%x\n",
                                            allocFn, func.getEntryPoint().getOffset(),
                                            calleeName, addr.getOffset());
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Check for direct dangerous function calls
            for (String writeFn : WRITE_FUNCS) {
                if (name.contains(writeFn)) {
                    printf("DANGEROUS_CALL: %s@0x%x\n",
                        func.getName(), func.getEntryPoint().getOffset());
                }
            }
        }
    }
}
