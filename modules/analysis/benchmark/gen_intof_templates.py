# 整数溢出基准测试模板 v4 (Integer Overflow Benchmark Templates)
# 12个独立CVE溢出模式, O2/Os抗优化消除.
# v2: volatile vuln_sink (失败 — 常量传播)
# v3: noinline + volatile count + vuln_sink (失败 — GCC O2仍消除函数体)
# v5: asm volatile barriers (防止常量传播/死代码消除), 允许O2优化非关键路径.
#     比 optimize("O0") 更真实: 保留大部分O2优化, 仅保护漏洞路径.

SAMPLE_DEFS = [
    ("CVE-2010-3089", "cve_2010_3089_mailto",  "mul overflow: count*sizeof(T) wraps before malloc", "mul_overflow"),
    ("CVE-2014-2851", "cve_2014_2851_ping",    "u16 overflow: ICMP payload length calc wraps", "u16_overflow"),
    ("CVE-2017-7184", "cve_2017_7184_xfrm",    "addition overflow: offset+len wraps u32", "add_overflow"),
    ("CVE-2018-1000026", "cve_2018_1000026_bcm", "shift overflow: 1<<n with n>31 wraps int", "shl_overflow"),
    ("CVE-2016-6187", "cve_2016_6187_compat",  "truncation: u64->u32 compat ioctl bypasses size check", "truncation"),
    ("CVE-2015-8958", "cve_2015_8958_sunras",  "signed mul: (int)rows*(int)cols overflows int32", "signed_mul"),
    ("CVE-2020-10757", "cve_2020_10757_mremap", "shift+mul: nr<<12 wraps before page alloc", "shl_mul"),
    ("CVE-2019-11479", "cve_2019_11479_mss",   "add overflow loop: loop accumulator wraps u16", "loop_add"),
    ("CVE-2022-42703", "cve_2022_42703_mm",    "add+sub underflow: len+addr overflows then underflows check", "add_underflow"),
    ("CVE-2013-1959", "cve_2013_1959_userns",  "truncation downcast: uid_t (u32) truncated from u64", "downcast"),
    ("CVE-2016-9555", "cve_2016_9555_sctp",    "signed negative: ssize_t bypasses negative check, becomes huge size_t", "signed_negative"),
    ("CVE-2019-19332", "cve_2019_19332_kvm",   "calloc dual: nmemb*size wraps inside calloc wrapper", "calloc_dual"),
]

_NOINLINE = "__attribute__((noinline))"
_SINK = "static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */"
# asm barrier: 阻止GCC常量传播/分支预测消除漏洞路径
_ASM_CLOBBER = '__asm__ __volatile__("" : "+r"(count));'
_ASM_MEM = '__asm__ __volatile__("" : : "r"(buf) : "memory");'


def _build(safe_name, comment, vuln_lines, safe_lines):
    """构建漏洞+安全函数对 + main().
    v5: noinline + asm barrier (count clobber + memory clobber) 防止O2消除."""
    # 在 free() 前注入 asm memory barrier, 防止GCC将volatile写入+free一起消除
    vl_parts = []
    for l in vuln_lines:
        if "free(" in l or "free (" in l:
            vl_parts.append(f"    {_ASM_MEM}")
        vl_parts.append("    " + l)
    vl = "\n".join(vl_parts)
    sl = "\n".join("    " + l for l in safe_lines)
    return f'''// {comment}
{_SINK}

{_NOINLINE}
void {safe_name}_vuln(int count) {{
    {_ASM_CLOBBER}
{vl}
    printf("{safe_name}: done\\n");
}}

{_NOINLINE}
void {safe_name}_safe(int count) {{
    {_ASM_CLOBBER}
{sl}
    printf("{safe_name}: ok\\n");
}}

int main(int argc, char **argv) {{
    int count = 1073741824;
    if (argc > 1) count = atoi(argv[1]);
    printf("intof test\\n");
    {safe_name}_vuln(count);
    {safe_name}_safe(count);
    return 0;
}}'''


def get_template(pattern: str, safe_name: str) -> str:
    """返回对应模式的C源码 (v3: noinline + volatile count, 三重O2/Os防护)."""

    # 1. mul_overflow: count*sizeof(T) wraps before malloc
    if pattern == "mul_overflow":
        return _build(safe_name, "mul_overflow: count*sizeof(T) wraps",
            ['size_t sz = (size_t)count * sizeof(int);',
             'if (sz < 4096) {  /* guard bypassed when sz wraps to 0 */',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, sz > 0 ? sz : 4096);  /* write beyond alloc */',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['size_t sz = (size_t)count * sizeof(int);',
             'if (sz / sizeof(int) != (size_t)count) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

    # 2. u16_overflow: 16-bit multiplication wraps
    if pattern == "u16_overflow":
        return _build(safe_name, "u16_overflow: 16-bit mul wraps before promotion",
            ['uint16_t c16 = (uint16_t)count;',
             'size_t sz = (size_t)(c16 * sizeof(int));  /* Bug: 16-bit compute first */',
             'if (sz > 0 && sz < 65536) {',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, sz + 16);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['uint16_t c16 = (uint16_t)count;',
             'size_t sz = (size_t)c16 * sizeof(int);  /* Correct: promote BEFORE mul */',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

    # 3. add_overflow: offset+len wraps u32, 用count控制offset使编译器无法静态证明
    if pattern == "add_overflow":
        return _build(safe_name, "add_overflow: offset+len wraps u32",
            ['uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;  /* offset depends on count */',
             'uint32_t len = (uint32_t)(count + 256);',
             'uint32_t end = offset + len;  /* wraps when count large enough */',
             'if (end < offset) {  /* overflow detected: end wrapped around */',
             '  char *buf = (char *)malloc(end);  /* end is small after wrap */',
             '  if (!buf) return;',
             '  memcpy(buf, "data", 4);  /* write to small buffer */',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['uint32_t offset = (uint32_t)count * 256U + 0xFFFFFF00U;',
             'uint32_t len = (uint32_t)(count + 256);',
             'if (len > UINT32_MAX - offset) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'uint32_t end = offset + len;',
             'char *buf = (char *)malloc(end);',
             'if (!buf) return;',
             'memcpy(buf, "data", 4);',
             'free(buf);'])

# 4. shl_overflow: 1<<n wraps when n>=32
    if pattern == "shl_overflow":
        return _build(safe_name, "shl_overflow: 1<<n wraps when n>=32",
            ['int shift = count % 64;  /* could be 32..63 */',
             'int sz = 1 << shift;  /* wraps to 0/negative */',
             'if (sz > 0 && sz < 4096) {',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, abs(sz));',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['int shift = count % 64;',
             'if (shift >= 31) {',
             '  printf("shift too large\\n");',
             '  return;',
             '}',
             'int sz = 1 << shift;',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

# 5. truncation: u64->u32 compat ioctl
    if pattern == "truncation":
        return _build(safe_name, "truncation: u64->u32 bypasses size check",
            ['uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;',
             'uint32_t count32 = (uint32_t)num_entries;  /* truncation! */',
             'size_t sz = (size_t)count32 * sizeof(int);',
             'if (sz < 65536) {  /* bypassed: count32 is small */',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  for (uint64_t i = 0; i < num_entries && i < 100; i++) buf[i] = 0;',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['uint64_t num_entries = (uint64_t)count * 7ULL + 0x100000001ULL;',
             'if (num_entries > UINT32_MAX) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'uint32_t count32 = (uint32_t)num_entries;',
             'size_t sz = count32 * sizeof(int);',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

# 6. signed_mul: int*int overflows int32
    if pattern == "signed_mul":
        return _build(safe_name, "signed_mul: int*int overflows int32",
            ['int rows = count;',
             'int cols = count;',
             'int total = rows * cols;  /* signed overflow -> UB! */',
             'if (total > 0 && total < 8192) {',
             '  char *buf = (char *)malloc(total);',
             '  if (!buf) return;',
             '  memset(buf, 0, total);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['int rows = count;',
             'int cols = count;',
             'size_t total = (size_t)rows * (size_t)cols;  /* promote BEFORE mul */',
             'if (total > 65536) {',
             '  printf("too large\\n");',
             '  return;',
             '}',
             'char *buf = (char *)malloc(total);',
             'if (!buf) return;',
             'memset(buf, 0, total);',
             'free(buf);'])

    # 7. shl_mul: nr<<12 wraps before page alloc
    if pattern == "shl_mul":
        return _build(safe_name, "shl_mul: nr<<12 wraps before page alloc",
            ['int nr_pages = count;',
             'size_t sz = (size_t)(nr_pages << 12);  /* wraps when nr>=0x100000 */',
             'if (sz > 0 && sz < 0x100000) {',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, sz);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['int nr_pages = count;',
             'if (nr_pages > 0xFFFFF) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'size_t sz = (size_t)nr_pages << 12;',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

    # 8. loop_add: accumulator wraps u16 in loop
    if pattern == "loop_add":
        return _build(safe_name, "loop_add: u16 accumulator wraps in loop",
            ['uint16_t total = 0;',
             'int n = count;',
             'for (int i = 0; i < n; i++) {',
             '  total += 64;  /* wraps when n>1024 */',
             '}',
             'if (total > 0 && total < 8192) {',
             '  char *buf = (char *)malloc(total);',
             '  if (!buf) return;',
             '  memset(buf, 0, total);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['int n = count;',
             'if (n > 1024) {  /* 1024*64=65536 -> wraps u16 */',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'uint16_t total = 0;',
             'for (int i = 0; i < n; i++) total += 64;',
             'char *buf = (char *)malloc(total);',
             'if (!buf) return;',
             'memset(buf, 0, total);',
             'free(buf);'])

    # 9. add_underflow: len+addr overflows, subtraction underflows
    if pattern == "add_underflow":
        return _build(safe_name, "add_underflow: len+addr wraps 64-bit",
            ['uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;',
             'uint64_t len = (uint64_t)count;',
             'uint64_t end = addr + len;  /* wraps on 64-bit! */',
             'size_t sz = (size_t)(end - addr);',
             'if (sz == len && sz < 4096) {  /* sz!=len when wraps */',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, sz);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['uint64_t addr = 0xFFFFFFFFFFFFFF00ULL;',
             'uint64_t len = (uint64_t)count;',
             'if (len > UINT64_MAX - addr) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'uint64_t end = addr + len;',
             'size_t sz = (size_t)(end - addr);',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

    # 10. downcast: uid_t (u32) truncated from u64, 用除法代替乘法防止常量折叠
    if pattern == "downcast":
        return _build(safe_name, "downcast: u64->u32 truncation to uid_t",
            ['uint64_t kuid = (uint64_t)count * 0x10000001ULL;  /* large factor */',
             'uint32_t uid = (uint32_t)kuid;  /* truncation! */',
             'int ngroups = (int)uid;  /* truncated value: small when count*mult wraps to <2^31 */',
             'if (ngroups > 0 && ngroups < 65536) {  /* bypassed */',
             '  char *buf = (char *)malloc(ngroups * 8 + 1);',
             '  if (!buf) return;',
             '  memset(buf, 0, ngroups * 8 + 1);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['uint64_t kuid = (uint64_t)count * 0x10000001ULL;',
             'if (kuid < (uint64_t)count) {  /* wrapped in 64-bit? should not happen */',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'if (kuid > (UINT32_MAX / 16)) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'uint32_t uid = (uint32_t)kuid;',
             'int ngroups = (int)uid;',
             'char *buf = (char *)malloc(ngroups * 8 + 1);',
             'if (!buf) return;',
             'memset(buf, 0, ngroups * 8 + 1);',
             'free(buf);'])

    # 11. signed_negative: ssize_t evades check, becomes huge size_t
    if pattern == "signed_negative":
        return _build(safe_name, "signed_negative: negative ssize_t -> huge size_t",
            ['ssize_t len = (ssize_t)count;  /* count is volatile, may be large */',
             'int narrow = (int)(unsigned int)count;  /* truncate then sign-extend */',
             'len = (ssize_t)narrow;',
             'size_t sz = (size_t)len;  /* negative -> huge size_t */',
             'if (sz > 0 && sz < 65536) {  /* bypassed: sz is huge */',
             '  char *buf = (char *)malloc(sz);',
             '  if (!buf) return;',
             '  memset(buf, 0, 16);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['ssize_t len = (ssize_t)count;',
             'if (len < 0 || len > 65536) {',
             '  printf("invalid len\\n");',
             '  return;',
             '}',
             'size_t sz = (size_t)len;',
             'char *buf = (char *)malloc(sz);',
             'if (!buf) return;',
             'memset(buf, 0, sz);',
             'free(buf);'])

    # 12. calloc_dual: nmemb*size wraps inside calloc wrapper
    if pattern == "calloc_dual":
        return _build(safe_name, "calloc_dual: nmemb*size wraps in calloc wrapper",
            ['size_t nmemb = (size_t)count;',
             'size_t elem_size = 16;',
             'size_t total = nmemb * elem_size;  /* wraps silently! */',
             'if (total < 65536 && total > 0) {',
             '  char *buf = (char *)calloc(1, total);',
             '  if (!buf) return;',
             '  memset(buf, 0, total > 0 ? total : 65536);',
             '  volatile_vuln_sink = buf;',
             '  free(buf);',
             '}'],
            ['size_t nmemb = (size_t)count;',
             'size_t elem_size = 16;',
             'if (nmemb > SIZE_MAX / elem_size) {',
             '  printf("overflow rejected\\n");',
             '  return;',
             '}',
             'size_t total = nmemb * elem_size;',
             'char *buf = (char *)calloc(1, total);',
             'if (!buf) return;',
             'memset(buf, 0, total);',
             'free(buf);'])

    # 未知模式降级
    return _build(safe_name, "mul_overflow (fallback)",
        ['size_t sz = (size_t)count * sizeof(int);',
         'if (sz < 4096) {',
         '  char *buf = (char *)malloc(sz);',
         '  if (!buf) return;',
         '  memset(buf, 0, sz > 0 ? sz : 4096);',
         '  volatile_vuln_sink = buf;',
         '  free(buf);',
         '}'],
        ['size_t sz = (size_t)count * sizeof(int);',
         'if (sz / sizeof(int) != (size_t)count) return;',
         'char *buf = (char *)malloc(sz);',
         'if (!buf) return;',
         'memset(buf, 0, sz);',
         'free(buf);'])
