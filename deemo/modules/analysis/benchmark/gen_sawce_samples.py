# coding: utf-8
# SAWCE + Loop Accumulate benchmark sample generator
#
# Generates 5 new heap overflow sample categories targeting SAWCE and loop accumulation:
#   1. same_source_fp: malloc(x); memcpy(p, src, x) - should NOT alert (FP test for SAWCE)
#   2. derived_source_fp: malloc(x); memcpy(p, src, x+1) - boundary safe (padding test)
#   3. loop_accumulate: malloc(256); loop 5x memcpy(p+i*64, src, 64) - cumulative overflow
#   4. nested_call_safe: malloc(get_size()); memcpy(p, src, get_size()) - same call-ret source
#   5. arithmetic_safe: malloc(x*4); memcpy(p, src, x*4) - same binop source
#
# Created: 2026-06-03

import os
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SAMPLES_DIR = ROOT / "samples_sawce"

SAMPLE_DEFS = [
    # (dir_name, desc, pattern, alloc_expr, write_expr, expected_vuln, challenge)
    ("sawce_same_source",
     "malloc(x); memcpy(p, src, x) - same variable for alloc and write size",
     "same_source", "arg0", "arg0", False,
     "SAWCE must prove alloc_size and write_size are structurally equivalent"),

    ("sawce_derived_boundary",
     "malloc(x); memcpy(p, src, x+1) - write is alloc+1, within padding",
     "derived_boundary", "arg0", "arg0+1", False,
     "SAWCE must detect sub-expression containment + padding threshold"),

    ("sawce_loop_accumulate",
     "malloc(256); loop 5x memcpy(p+offset, src, 64) - cumulative 320 > 256",
     "loop_accumulate", "256", "5*64", True,
     "Stage 10 must detect loop back-edge, estimate trip count, multiply"),

    ("sawce_nested_call",
     "malloc(get_size()); memcpy(p, src, get_size()) - same call-ret source",
     "nested_call", "callret(get_size)", "callret(get_size)", False,
     "SAWCE must track call-ret expressions as same base node"),

    ("sawce_arithmetic",
     "malloc(x*4); memcpy(p, src, x*4) - same binop expression",
     "arithmetic_equiv", "arg0*4", "arg0*4", False,
     "SAWCE must prove binop expressions are structurally equivalent"),
]


def _c_source(name, desc, pattern, expected_vuln, challenge):
    """Generate C source for SAWCE test samples."""
    if pattern == "same_source":
        return _src_same_source(name, desc)
    elif pattern == "derived_boundary":
        return _src_derived_boundary(name, desc)
    elif pattern == "loop_accumulate":
        return _src_loop_accumulate(name, desc)
    elif pattern == "nested_call":
        return _src_nested_call(name, desc)
    elif pattern == "arithmetic_equiv":
        return _src_arithmetic(name, desc)
    return ""


def _src_same_source(name, desc):
    return f'''/**
 * {name} - {desc}
 *
 * SAWCE test: alloc and write size come from the same variable.
 * Expected: NO alert (SAWCE should prove structural equivalence).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[1024];

void {name}_vuln(void) {{
    /* Volatile to prevent constant folding */
    volatile unsigned int sz = 128;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    /* alloc size == write size (both = sz) -> SAFE by SAWCE */
    memcpy(buf, payload, sz);
    printf("{name}: ok\\n");
    free(buf);
}}

/* Different source: should alert */
void {name}_diff(void) {{
    char *buf = (char *)malloc(64);
    if (!buf) return;
    volatile unsigned int wlen = 128;
    memcpy(buf, payload, wlen);  /* 128 > 64 -> OVERFLOW */
    printf("{name}_diff: overflow\\n");
    free(buf);
}}

int main(void) {{
    memset(payload, 'A', sizeof(payload));
    {name}_vuln();
    {name}_diff();
    return 0;
}}
'''


def _src_derived_boundary(name, desc):
    return f'''/**
 * {name} - {desc}
 *
 * SAWCE test: write size = alloc size + 1, within allocator padding.
 * Expected: NO alert (boundary safe within glibc 16-byte padding).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[1024];

void {name}_vuln(void) {{
    volatile unsigned int sz = 128;
    char *buf = (char *)malloc(sz);
    if (!buf) return;
    /* write = sz + 1 = 129, alloc = 128, overflow=1 -> within padding */
    memcpy(buf, payload, sz + 1);
    printf("{name}: boundary safe\\n");
    free(buf);
}}

int main(void) {{
    memset(payload, 'A', sizeof(payload));
    {name}_vuln();
    return 0;
}}
'''


def _src_loop_accumulate(name, desc):
    return f'''/**
 * {name} - {desc}
 *
 * Stage 10 test: loop accumulation overflow.
 * Each iteration writes 64 bytes (safe), but 5 iterations = 320 > 256.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[512];

void {name}_vuln(void) {{
    char *buf = (char *)malloc(256);
    if (!buf) return;
    char *ptr = buf;
    int i;
    /* BUG: 5 * 64 = 320 > 256 allocation */
    for (i = 0; i < 5; i++) {{
        memcpy(ptr, payload, 64);
        ptr += 64;
    }}
    printf("{name}: loop accumulate overflow\\n");
    free(buf);
}}

/* Safe: 3 iterations * 64 = 192 <= 256 */
void {name}_safe(void) {{
    char *buf = (char *)malloc(256);
    if (!buf) return;
    char *ptr = buf;
    int i;
    for (i = 0; i < 3; i++) {{
        memcpy(ptr, payload, 64);
        ptr += 64;
    }}
    printf("{name}_safe: ok\\n");
    free(buf);
}}

int main(void) {{
    memset(payload, 'A', sizeof(payload));
    {name}_vuln();
    {name}_safe();
    return 0;
}}
'''


def _src_nested_call(name, desc):
    return f'''/**
 * {name} - {desc}
 *
 * SAWCE test: alloc and write size both come from same function return.
 * Expected: NO alert (same call-ret base node).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[256];

static unsigned int get_size(void) {{
    return 128;
}}

void {name}_vuln(void) {{
    char *buf = (char *)malloc(get_size());
    if (!buf) return;
    /* Both alloc and write use get_size() return -> same call-ret expr */
    memcpy(buf, payload, get_size());
    printf("{name}: ok\\n");
    free(buf);
}}

int main(void) {{
    memset(payload, 'A', sizeof(payload));
    {name}_vuln();
    return 0;
}}
'''


def _src_arithmetic(name, desc):
    return f'''/**
 * {name} - {desc}
 *
 * SAWCE test: alloc = count*4, write = count*4 -> same binop expression.
 * Expected: NO alert (structural equivalence of binop exprs).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char payload[512];

void {name}_vuln(void) {{
    volatile unsigned int count = 32;
    char *buf = (char *)malloc(count * 4);
    if (!buf) return;
    /* Both alloc and write = count*4 -> structurally equivalent */
    memcpy(buf, payload, count * 4);
    printf("{name}: ok\\n");
    free(buf);
}}

int main(void) {{
    memset(payload, 'A', sizeof(payload));
    {name}_vuln();
    return 0;
}}
'''


def _makefile(name, src):
    T = "\t"
    return f'''# {name} - SAWCE benchmark sample
CC = gcc
CFLAGS = -Wall -no-pie -fno-pie -fno-builtin

all: {name}_O0 {name}_O2 {name}_Os

{name}_O0: {src}
{T}$(CC) $(CFLAGS) -O0 -o $@ $<

{name}_O2: {src}
{T}$(CC) $(CFLAGS) -O2 -o $@ $<

{name}_Os: {src}
{T}$(CC) $(CFLAGS) -Os -o $@ $<

clean:
{T}rm -f {name}_O0 {name}_O2 {name}_Os
'''


def generate_all():
    """Generate all SAWCE benchmark samples."""
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    manifest = []

    for dirname, desc, pattern, alloc_expr, write_expr, expected_vuln, challenge in SAMPLE_DEFS:
        sample_dir = SAMPLES_DIR / dirname
        sample_dir.mkdir(parents=True, exist_ok=True)

        src_name = f"{dirname}.c"
        target_name = dirname
        src_path = sample_dir / src_name
        src_path.write_text(
            _c_source(dirname, desc, pattern, expected_vuln, challenge),
            encoding="utf-8")

        mf_path = sample_dir / "Makefile"
        mf_path.write_text(
            _makefile(target_name, src_name), encoding="utf-8")

        for opt in ("O0", "O2", "Os"):
            manifest.append({
                "name": dirname,
                "pattern": pattern,
                "binary": str((sample_dir / f"{target_name}_{opt}").resolve()),
                "compiler": "gcc",
                "opt": opt,
                "expected_vulnerable": expected_vuln,
                "alloc_expr": alloc_expr,
                "write_expr": write_expr,
                "challenge": challenge,
                "compiled": False,
                "source": str(src_path.resolve()),
            })

        print("  Generated: %s (%s)" % (dirname, pattern))

    manifest_path = SAMPLES_DIR / "sawce_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False))
    print("\nManifest: %s (%d entries)" % (manifest_path, len(manifest)))
    return manifest


if __name__ == "__main__":
    print("Generating %d SAWCE benchmark samples..." % len(SAMPLE_DEFS))
    generate_all()
    print("Done. Run 'make' in each sample directory to compile.")
