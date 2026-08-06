# Ghidra headless heap overflow scanner
# Usage: analyzeHeadless <project> <dir> -import <binary> -postScript ghidra_heap_scan.py
# Output: prints HEAP_OVERFLOW:<func_name>:<addr> for each detected overflow site

import re

_HEAP_ALLOCS = {'malloc', 'calloc', 'realloc', '_malloc_r', '__libc_malloc'}
_DANGER_WRITES = {'memcpy', 'strcpy', 'strcat', 'memmove', 'read', 'fread', 'recv'}

def main():
    program = getCurrentProgram()
    listing = program.getListing()
    fm = program.getFunctionManager()

    for func in fm.getFunctions(True):
        body = func.getBody()
        code = ''
        for addr in body:
            try:
                inst = listing.getInstructionAt(addr)
                if inst:
                    code += inst.toString() + '\n'
            except:
                pass

        # Find allocations: var = malloc(size)
        allocs = {}
        for m in re.finditer(r'(\w+)\s*=\s*\w*\s*(?:malloc|calloc)\s*\(\s*(\d+)', code):
            allocs[m.group(1)] = int(m.group(2))

        # Find dangerous writes to allocated vars
        for var, alloc_sz in allocs.items():
            for dw in _DANGER_WRITES:
                for m in re.finditer(
                    rf'{dw}\s*\(\s*{re.escape(var)}\s*,.+?,\s*(\d+)', code):
                    write_sz = int(m.group(1))
                    if write_sz > alloc_sz:
                        print(f'HEAP_OVERFLOW:{func.getName()}:{func.getEntryPoint()}:'
                              f'{var}:alloc={alloc_sz}:write={write_sz}:{dw}')

if __name__ == '__main__':
    main()
