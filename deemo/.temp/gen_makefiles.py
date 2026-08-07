import os

base = r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow'
samples = {
    'cve_20_cross_func_guard': 'cross_func_guard',
    'cve_21_cross_func_write': 'cross_func_write',
    'cve_22_fm_boundary_safe': 'fm_boundary_safe',
    'cve_23_fm_boundary_overflow': 'fm_boundary_overflow',
    'cve_24_multiple_constraints': 'multi_constraint',
    'cve_25_nested_loop_overflow': 'nested_loop',
    'cve_26_realloc_grow_safe': 'realloc_grow',
    'cve_27_struct_array_overflow': 'struct_array',
    'cve_28_guarded_loop_safe': 'guarded_loop',
    'cve_29_alignment_slack_safe': 'alignment_slack',
    'cve_30_cross_func_alloc_only': 'cross_func_alloc',
    'cve_31_copy_size_external': 'copy_size_external',
    'cve_32_deeply_nested_safe': 'deeply_nested',
}

for dirname, target in samples.items():
    content = (
        f"CC=gcc\n"
        f"CFLAGS=-O2 -Wall -fno-stack-protector\n"
        f"TARGET={target}\n"
        f"\n"
        f"all: $(TARGET).exe\n"
        f"\n"
        f"$(TARGET).exe: $(TARGET).c\n"
        f"\t$(CC) $(CFLAGS) -o $@ $<\n"
        f"\n"
        f"clean:\n"
        f"\trm -f $(TARGET).exe\n"
    )
    path = os.path.join(base, dirname, 'Makefile')
    with open(path, 'w') as f:
        f.write(content)

print(f'Created {len(samples)} Makefiles')
