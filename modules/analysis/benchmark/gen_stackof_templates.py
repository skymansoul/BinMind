# 栈溢出基准测试模板生成器 (Stack Overflow Benchmark Templates)
# 12个CVE复现样本: O0/O2/Os × 12 = 36个二进制.
# v1: asm barrier反优化, 保持O2/Os下的漏洞函数体存活.

SAMPLE_DEFS = [
    ("CVE-2014-9322", "cve_2014_9322_badiret", "gets(stack_buf) 无界读取", "gets"),
    ("CVE-2016-7855", "cve_2016_7855_ntoskrnl", "strcpy(dst,src) 无界拷贝到栈缓冲区", "strcpy"),
    ("CVE-2015-0235", "cve_2015_0235_ghost", "sprintf(buf,fmt,...) 无界格式化输出", "sprintf"),
    ("CVE-2018-14634", "cve_2018_14634_kernel", "scanf(\"%s\",buf) 无界输入到栈", "scanf_pct_s"),
    ("CVE-2017-7269", "cve_2017_7269_iis", "memcpy(stack_buf,src,oversize) 超界拷贝", "memcpy_oversized"),
    ("CVE-2016-5696", "cve_2016_5696_tcp", "read(fd,stack_buf,oversize) 超界读取", "read_oversized"),
    ("CVE-2014-3610", "cve_2014_3610_kvm", "strncpy(buf,src,sizeof(buf)) 无null终止符", "strncpy_offbyone"),
    ("CVE-2020-25636", "cve_2020_25636_wifi", "strcpy+strcat 累积溢出链", "strcat_chain"),
    ("CVE-2012-0809", "cve_2012_0809_sudo", "sprintf计算格式 栈溢出", "sprintf_chain"),
    ("CVE-2019-9213", "cve_2019_9213_nullptr", "while循环拷贝到栈缓冲区", "loop_copy"),
    ("CVE-2016-7117", "cve_2016_7117_recv", "recv(sock,buf,size) 网络数据超界", "recv_oversized"),
    ("CVE-2019-14814", "cve_2019_14814_mwifiex", "snprintf(buf,err_size,...) 大小误算", "snprintf_miscalc"),
]

_NOINLINE = "__attribute__((noinline))"
_SINK = "static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */"
_CLOBBER = '__asm__ __volatile__("" : "+r"(count));'
_STR_CLOBBER = '__asm__ __volatile__("" : "+r"(src_str));'
_MEM_BARRIER = '__asm__ __volatile__("" : : "r"(buf) : "memory");'
_BARRIER = '__asm__ __volatile__("" : : : "memory");'


def _kbuf(name="buf", size=32):
    """声明栈缓冲区."""
    return f"    char {name}[{size}];"


def _vuln(name, pattern, code_lines):
    """生成vuln函数: __asm clobber + 漏洞代码 + sink."""
    body = "\n".join(f"    {l}" for l in code_lines)
    return f'''{_NOINLINE}
void {name}_vuln(int count) {{
    __asm__ __volatile__("" : "+r"(count));
{_kbuf()}
{body}
    printf("{name}: done\\n");
}}'''


def _safe(name, pattern, code_lines):
    """生成safe函数: __asm clobber + 有边界检查 + 安全操作."""
    body = "\n".join(f"    {l}" for l in code_lines)
    return f'''{_NOINLINE}
void {name}_safe(int count) {{
    __asm__ __volatile__("" : "+r"(count));
{_kbuf()}
{body}
    printf("{name}: ok\\n");
}}'''


def _main(safe_name):
    return f'''int main(int argc, char **argv) {{
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("stack of test\\n");
    {safe_name}_vuln(count);
    {safe_name}_safe(count);
    return 0;
}}'''


def get_template(pattern: str, safe_name: str) -> str:
    """返回给定溢出模式的C源码."""
    S = _SINK

    # 1. gets - 无界读取
    if pattern == "gets":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'A\', count < 256 ? count : 255);',
            'src[(count < 256 ? count : 255)] = 0;',
            'gets(buf);  /* 无界: 输入>32字节 → 栈溢出 */',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'A\', count < 32 ? count : 31);',
            'src[31] = 0;',
            'strncpy(buf, src, sizeof(buf) - 1);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 2. strcpy - 无界拷贝
    if pattern == "strcpy":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'A\', count < 256 ? count : 255);',
            'src[(count < 256 ? count : 255)] = 0;',
            'strcpy(buf, src);  /* src可能>32字节 → 溢出 */',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'A\', count < 32 ? count : 31);',
            'src[31] = 0;',
            'strncpy(buf, src, sizeof(buf) - 1);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 3. sprintf - 无界格式化
    if pattern == "sprintf":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'const char *fmt = count > 100 ? "%064d" : "%s";',
            'sprintf(buf, fmt, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'snprintf(buf, sizeof(buf), "%d", count);',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 4. scanf %s — 无界输入 (使用sscanf模拟, 因为scanf需要stdin)
    if pattern == "scanf_pct_s":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'A\', count < 256 ? count : 255);',
            'src[(count < 256 ? count : 255)] = 0;',
            'sscanf(src, "%s", buf);  /* sscanf(buf, "%s", stack_buf) 无界 */',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[64];',
            'memset(src, \'A\', 30); src[30]=0;',
            'snprintf(buf, sizeof(buf), "%s", src);',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 5. memcpy_oversized
    if pattern == "memcpy_oversized":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', sizeof(src));',
            'size_t sz = (size_t)count;',
            'memcpy(buf, src, sz);  /* buf只有32字节, sz可很大 → 溢出 */',
            _MEM_BARRIER,  # 阻止O2消除buf写入
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', sizeof(src));',
            'size_t sz = (size_t)count;',
            'if (sz > sizeof(buf)) sz = sizeof(buf) - 1;',
            'memcpy(buf, src, sz);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 6. read_oversized (使用memcpy模拟read到栈缓冲区)
    if pattern == "read_oversized":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', sizeof(src));',
            'size_t sz = (size_t)count;',
            'memcpy(buf, src, sz);  /* sz可>32 → read-like溢出 */',
            _MEM_BARRIER,  # 阻止O2消除buf写入
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', sizeof(src));',
            'size_t sz = (size_t)count;',
            'if (sz > sizeof(buf)) sz = sizeof(buf) - 1;',
            'memcpy(buf, src, sz);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 7. strncpy_offbyone
    if pattern == "strncpy_offbyone":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[64];',
            'memset(src, \'A\', sizeof(src) - 1);',
            'src[63] = 0;',
            'strncpy(buf, src, sizeof(buf));  /* sizeof(buf)无null终止符空间 */',
            _MEM_BARRIER,  # 阻止O2/Os消除buf写入
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[64];',
            'memset(src, \'A\', sizeof(src) - 1);',
            'src[63] = 0;',
            'strncpy(buf, src, sizeof(buf) - 1);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 8. strcat_chain
    if pattern == "strcat_chain":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', count < 512 ? count : 511);',
            'src[(count < 512 ? count : 511)] = 0;',
            'buf[0] = 0;',
            'strcat(buf, "prefix_");',
            'strcat(buf, src);  /* src可能很长 → 累积溢出 */',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[512];',
            'memset(src, \'A\', count < 20 ? count : 19);',
            'src[19] = 0;',
            'snprintf(buf, sizeof(buf), "prefix_%s", src);',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 9. sprintf_chain
    if pattern == "sprintf_chain":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char *p = buf;',
            'p += sprintf(p, "hdr:%d:", count);',
            'p += sprintf(p, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA");',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'snprintf(buf, sizeof(buf), "hdr:%d:%s", count, "AAA");',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 10. loop_copy - CVE-2019-9213: 循环拷贝后off-by-one写null终止符
    #  模拟: while循环计数漏-1 → memcpy(buf,src,sizeof(buf)) 然后 buf[sizeof(buf)]=0
    if pattern == "loop_copy":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'B\', count < 256 ? count : 255);',
            'src[(count < 256 ? count : 255)] = 0;',
            'size_t cp_len = (size_t)(count + 1);  /* BUG: off-by-one, count+1应-1 */',
            'memcpy(buf, src, cp_len);  /* cp_len至少1, count=65536→cp_len=65537>32溢出 */',
            _MEM_BARRIER,
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[256];',
            'memset(src, \'B\', count < 32 ? count : 31);',
            'src[31] = 0;',
            'size_t cp_len = (size_t)count;',
            'if (cp_len > sizeof(buf) - 1) cp_len = sizeof(buf) - 1;',
            'memcpy(buf, src, cp_len);',
            'buf[cp_len] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 11. recv_oversized (使用memcpy模拟recv到栈缓冲区 + 网络数据大小)
    if pattern == "recv_oversized":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'char src[4096];',
            'memset(src, \'C\', sizeof(src));',
            'size_t sz = (size_t)count;  /* 网络传来的大小字段 */',
            'memcpy(buf, src, sz);  /* sz来自网络 → recv-like溢出 */',
            _MEM_BARRIER,  # 阻止O2消除buf写入
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'char src[4096];',
            'memset(src, \'C\', sizeof(src));',
            'size_t sz = (size_t)count;',
            'if (sz > sizeof(buf)) sz = sizeof(buf) - 1;',
            'memcpy(buf, src, sz);',
            'buf[sizeof(buf) - 1] = 0;',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 12. snprintf_miscalc
    if pattern == "snprintf_miscalc":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'size_t wrong_size = (size_t)(count + 32);  /* 故意计算错误 */',
            'snprintf(buf, wrong_size, "%s", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");',
            'volatile_vuln_sink = buf;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'snprintf(buf, sizeof(buf), "%s", "short_string");',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # fallback
    return f'// unknown pattern: {pattern}\n'


__all__ = ["get_template", "SAMPLE_DEFS"]
