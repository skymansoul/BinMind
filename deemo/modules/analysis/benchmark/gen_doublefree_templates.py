# 双重释放基准测试模板生成器 (Double-Free Benchmark Templates)
# 12个CVE复现样本: O0/O2/Os × 12 = 36个二进制.
# v1: asm barrier反优化, 保持O2/Os下漏洞函数体存活.

SAMPLE_DEFS = [
    ("CVE-2018-7566", "cve_2018_7566_alsa", "simple double free: free(p);free(p)", "simple_df"),
    ("CVE-2021-3156", "cve_2021_3156_sudo", "alias: q=p;free(p);free(q)", "alias_df"),
    ("CVE-2017-7857", "cve_2017_7857_freetype", "realloc失败→double free", "realloc_path_df"),
    ("CVE-2019-15107", "cve_2019_15107_webmin", "栈重载: 存栈→free→再加载→free", "stack_reload_df"),
    ("CVE-2016-10190", "cve_2016_10190_ffmpeg", "错误路径: if(err)free(p); free(p)", "error_path_df"),
    ("CVE-2015-7547", "cve_2015_7547_getaddrinfo", "循环: for(i=0;i<2;i++)free(p)", "loop_df"),
    ("CVE-2014-9319", "cve_2014_9319_ffmpeg", "goto错误标签: goto err; err:free(p);free(p)", "goto_error_df"),
    ("CVE-2022-23222", "cve_2022_23222_kernel", "全局指针: 两个路径分别free同一全局", "global_ptr_df"),
    ("CVE-2019-15666", "cve_2019_15666_xfrm", "条件释放: cond?free(p):0; free(p)", "cond_free_df"),
    ("CVE-2018-1000200", "cve_2018_1000200_kvm", "结构体字段: obj->p别名后双重释放", "struct_field_df"),
    ("CVE-2020-14356", "cve_2020_14356_kernel", "realloc(ptr,0)释放→再次free(ptr)", "realloc_zero_df"),
    ("CVE-2016-2177", "cve_2016_2177_openssl", "多级错误路径: err1:free(p);err2:free(p)", "multi_error_df"),
]

_NOINLINE = "__attribute__((noinline))"
_SINK = "static volatile void *volatile_vuln_sink;  /* 阻止O2/Os编译期消除 */"
_CLOBBER = '__asm__ __volatile__("" : "+r"(count));'


def _vuln(name, pattern, code_lines, alloc_type="malloc"):
    body = "\n".join(f"    {l}" for l in code_lines)
    return f'''{_NOINLINE}
void {name}_vuln(int count) {{
    __asm__ __volatile__("" : "+r"(count));
    void *p = {alloc_type}(64);
    if (!p) return;
    volatile_vuln_sink = p;
{body}
    printf("{name}: done\\n");
}}'''


def _safe(name, pattern, code_lines, alloc_type="malloc"):
    body = "\n".join(f"    {l}" for l in code_lines)
    return f'''{_NOINLINE}
void {name}_safe(int count) {{
    __asm__ __volatile__("" : "+r"(count));
    void *p = {alloc_type}(64);
    if (!p) return;
    volatile_vuln_sink = p;
{body}
    printf("{name}: ok\\n");
}}'''


def _main(safe_name):
    return f'''int main(int argc, char **argv) {{
    int count = 65536;
    if (argc > 1) count = atoi(argv[1]);
    printf("double free test\\n");
    {safe_name}_vuln(count);
    {safe_name}_safe(count);
    return 0;
}}'''


def get_template(pattern: str, safe_name: str) -> str:
    S = _SINK

    # 1. simple_df: free(p); free(p)
    if pattern == "simple_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER, 'free(p);', 'free(p);  /* double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER, 'free(p);', 'p = NULL;  /* null after free */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 2. alias_df: q=p; free(p); free(q)
    if pattern == "alias_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'void *q = p;  /* alias */',
            'free(p);',
            'free(q);  /* double free via alias */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'void *q = p;',
            'free(p);',
            'if (q == p) q = NULL;  /* break alias */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 3. realloc_path_df: p=realloc(p,N); free(p); free(p)
    if pattern == "realloc_path_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'void *q = realloc(p, 128);  /* realloc可能移动或释放旧块 */',
            'if (q) p = q;',
            'free(p);',
            'free(p);  /* double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'void *q = realloc(p, 128);',
            'if (q) {{ free(p); p = NULL; }}  /* old ptr recorded */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 4. stack_reload_df: store to stack, free, reload from stack, free
    if pattern == "stack_reload_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'void *save = p;  /* 栈槽保存指针 */',
            'free(p);',
            'p = save;  /* 从栈重载 */',
            'free(p);  /* double free via stack reload */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'void *save = p;',
            'free(p);',
            'if (save) save = NULL;  /* 清除栈副本 */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 5. error_path_df: if(err) free(p); free(p)
    if pattern == "error_path_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'if (count > 0) free(p);  /* 错误路径 */',
            'free(p);  /* 总是执行 → 若count>0则double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'if (count > 0) {{ free(p); p = NULL; }}',
            'if (p) free(p);  /* null check */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 6. loop_df: for(i=0;i<2;i++) free(p)
    if pattern == "loop_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER, 'int i;',
            'for (i = 0; i < 2; i++) free(p);  /* 第二次free是double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'free(p); p = NULL;',
            'if (p) free(p);  /* unreachable because p=NULL */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 7. goto_error_df: goto err; err:free(p); ... free(p)
    if pattern == "goto_error_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'if (count < 0) goto err;',
            'goto cleanup;',
            'err:',
            '    free(p);',
            'cleanup:',
            '    free(p);  /* 若走err路径 → double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'int freed = 0;',
            'if (count < 0) {{ free(p); freed = 1; }}',
            'if (!freed) free(p);',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 8. global_ptr_df: global ptr freed in two branches
    if pattern == "global_ptr_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'static void *gp = NULL;',
            'gp = p;',
            'if (count > 100) {{ free(gp); }}',
            'free(gp);  /* 二者之中必有一个double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'static void *gp = NULL;',
            'gp = p;',
            'free(gp); gp = NULL;',
            'if (gp) free(gp);  /* null check prevents DF */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 9. cond_free_df: (cond ? free(p) : 0); free(p)
    if pattern == "cond_free_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'if (count & 1) free(p);  /* 条件释放 */',
            'free(p);  /* 无条件释放 → 若条件为真, double free */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'if (count & 1) {{ free(p); p = NULL; }}',
            'if (p) free(p);',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 10. struct_field_df: obj->ptr alias then double free
    if pattern == "struct_field_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'typedef struct { void *data; int len; } Obj;',
            'Obj obj; obj.data = p; obj.len = 64;',
            'void *alias = obj.data;  /* 结构体字段别名 */',
            'free(obj.data);',
            'free(alias);  /* double free via struct field alias */',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'typedef struct { void *data; int len; } Obj;',
            'Obj obj; obj.data = p; obj.len = 64;',
            'free(obj.data);',
            'obj.data = NULL;  /* 清除字段 */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 11. realloc_zero_df: realloc(p,0) frees p, then free(p) again
    if pattern == "realloc_zero_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'void *q = realloc(p, 0);  /* realloc(ptr,0) ≡ free(ptr), q=NULL */',
            'free(p);  /* p已被realloc释放 → double free */',
            'volatile_vuln_sink = q;',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'free(p);',
            'p = NULL;',
            'if (p) free(p);  /* null check */',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    # 12. multi_error_df: multiple error labels, each frees p
    if pattern == "multi_error_df":
        vuln = _vuln(safe_name, pattern, [
            _CLOBBER,
            'if (count < 0) goto err1;',
            'if (count > 1000) goto err2;',
            'goto done;',
            'err1:',
            '    free(p);',
            'err2:',
            '    free(p);  /* err1落入err2 → double free */',
            'done:',
            '    printf("ok\\n");',
        ])
        safe = _safe(safe_name, pattern, [
            _CLOBBER,
            'int freed = 0;',
            'if (count < 0) {{ free(p); freed = 1; }}',
            'if (!freed) {{ free(p); freed = 1; }}',
        ])
        return f'{S}\n\n{vuln}\n{safe}\n{_main(safe_name)}'

    return f'// unknown pattern: {pattern}\n'


__all__ = ["get_template", "SAMPLE_DEFS"]
