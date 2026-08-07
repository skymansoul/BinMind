# UAF C源码模板 (UAF C Source Templates)
# 15种UAF漏洞模式的C代码模板, 供 gen_uaf_samples.py 调用.
# 每种模式模拟一个真实CVE的核心UAF机制.
# 创建: 2026-05-06

SAMPLE_DEFS = [
    ("CVE-2016-10150", "cve_2016_10150_kvm",
     "KVM kvm_vcpu_ioctl_device_add dangling pointer UAF",
     "simple_uaf_global_ptr"),
    ("CVE-2017-7533", "cve_2017_7533_inode",
     "Linux kernel inode->i_cdev UAF via race in __inode_add",
     "aliased_ptr_uaf"),
    ("CVE-2018-7566", "cve_2018_7566_alsa",
     "ALSA sequencer ioctl race → UAF on struct snd_seq_client",
     "conditional_free_uaf"),
    ("CVE-2018-17182", "cve_2018_17182_vmac",
     "Linux kernel vmacache_flush_all UAF via mmap race",
     "cross_function_uaf"),
    ("CVE-2019-2215", "cve_2019_2215_binder",
     "Android Binder driver epoll UAF via ioctl",
     "double_free_uaf"),
    ("CVE-2019-15291", "cve_2019_15291_brcm",
     "Broadcom WiFi driver UAF via cfg80211_scan_done",
     "null_after_free_defense"),
    ("CVE-2019-19532", "cve_2019_19532_hid",
     "Linux HID driver UAF via hiddev_disconnect race",
     "struct_field_uaf"),
    ("CVE-2020-0022", "cve_2020_0022_bt",
     "Android Bluetooth L2CAP packet fragment reassembly UAF",
     "realloc_uaf"),
    ("CVE-2020-14386", "cve_2020_14386_afpacket",
     "Linux AF_PACKET ring buffer UAF via setsockopt overflow",
     "loop_iteration_uaf"),
    ("CVE-2020-25211", "cve_2020_25211_netfilter",
     "Linux netfilter ctnetlink UAF via conntrack delete",
     "error_path_uaf"),
    ("CVE-2021-32399", "cve_2021_32399_blk",
     "Linux block layer UAF via blkdev_get_by_dev race",
     "callback_uaf"),
    ("CVE-2021-34866", "cve_2021_34866_ebpf",
     "Linux eBPF verifier UAF via bpf_map_update_elem",
     "argument_uaf"),
    ("CVE-2022-0995", "cve_2022_0995_watch",
     "Linux watch_queue UAF via free in event handler",
     "list_node_uaf"),
    ("CVE-2023-0461", "cve_2023_0461_iouring",
     "Linux io_uring IORING_OP_ACCEPT UAF via socket lifecycle",
     "lifecycle_race_uaf"),
    ("CVE-2017-2636", "cve_2017_2636_n_hdlc",
     "Linux n_hdlc line discipline UAF via tty race",
     "reassign_after_free_uaf"),
]


def get_template(pattern: str, name: str) -> str:
    """返回指定UAF模式的C源码模板."""
    templates = {
        "simple_uaf_global_ptr": _pat_simple,
        "aliased_ptr_uaf": _pat_aliased,
        "conditional_free_uaf": _pat_cond_free,
        "cross_function_uaf": _pat_cross_func,
        "double_free_uaf": _pat_double_free,
        "null_after_free_defense": _pat_null_defense,
        "struct_field_uaf": _pat_struct_field,
        "realloc_uaf": _pat_realloc,
        "loop_iteration_uaf": _pat_loop,
        "error_path_uaf": _pat_error_path,
        "callback_uaf": _pat_callback,
        "argument_uaf": _pat_argument,
        "list_node_uaf": _pat_list_node,
        "lifecycle_race_uaf": _pat_lifecycle,
        "reassign_after_free_uaf": _pat_reassign,
    }
    return templates.get(pattern, _pat_simple)(name)


# 15种UAF模式模板

def _pat_simple(name: str) -> str:
    return f'''static char *g_ptr_{name};

void {name}_alloc(void) {{
    g_ptr_{name} = (char *)malloc(256);
    if (g_ptr_{name}) memset(g_ptr_{name}, 0, 256);
}}

void {name}_free(void) {{
    free(g_ptr_{name});  /* 缺少 g_ptr = NULL → UAF */
}}

void {name}_use(void) {{
    if (g_ptr_{name}) {{
        printf("%c", g_ptr_{name}[0]);  /* UAF: free后使用 */
    }}
}}

int main(void) {{
    printf("=== {name} UAF test ===\\n");
    {name}_alloc(); {name}_free(); {name}_use();
    return 0;
}}
'''


def _pat_aliased(name: str) -> str:
    return f'''static char *g_ptr_{name};

void {name}_run(void) {{
    char *p = (char *)malloc(256);
    char *alias = p;
    g_ptr_{name} = p;
    memset(p, 0, 256);
    free(alias);       /* 通过别名释放 */
    if (p) printf("%c", p[0]);  /* UAF: p是悬垂指针 */
}}

int main(void) {{
    printf("=== {name} aliased UAF test ===\\n");
    {name}_run();
    return 0;
}}
'''


def _pat_cond_free(name: str) -> str:
    return f'''static char *g_buf_{name};

void {name}_process(int err) {{
    g_buf_{name} = (char *)malloc(128);
    if (!g_buf_{name}) return;
    memset(g_buf_{name}, 'X', 128);
    if (err) {{
        free(g_buf_{name});  /* 错误路径释放 */
        return;
    }}
    printf("%c", g_buf_{name}[0]);  /* 正常路径使用 */
    free(g_buf_{name}); g_buf_{name} = NULL;
}}

int main(void) {{
    printf("=== {name} conditional free UAF ===\\n");
    {name}_process(1);  /* err=1: free但不置NULL → 但main无后续使用 */
    return 0;
}}
'''


def _pat_cross_func(name: str) -> str:
    return f'''static char *g_obj_{name};

void {name}_cleanup(void) {{
    free(g_obj_{name});  /* 被调用者释放但不置NULL */
}}

void {name}_setup(void) {{
    g_obj_{name} = (char *)malloc(512);
    if (g_obj_{name}) memset(g_obj_{name}, 0, 512);
}}

void {name}_process(void) {{
    printf("%c", g_obj_{name}[64]);  /* UAF: cleanup已释放 */
}}

int main(void) {{
    printf("=== {name} cross-function UAF ===\\n");
    {name}_setup(); {name}_cleanup(); {name}_process();
    return 0;
}}
'''


def _pat_double_free(name: str) -> str:
    return f'''void {name}_run(void) {{
    char *p = (char *)malloc(64);
    if (!p) return;
    memset(p, 'A', 64);
    free(p);
    free(p);  /* double free */
    printf("double-free done\\n");
}}

int main(void) {{
    printf("=== {name} double free test ===\\n");
    {name}_run();
    return 0;
}}
'''


def _pat_null_defense(name: str) -> str:
    return f'''static char *g_h_{name};

void {name}_init(void) {{
    g_h_{name} = (char *)malloc(256);
    if (g_h_{name}) memset(g_h_{name}, 0, 256);
}}

void {name}_release(void) {{
    free(g_h_{name});
    g_h_{name} = NULL;  /* 防御性置空 */
}}

void {name}_safe_use(void) {{
    if (g_h_{name}) {{
        printf("%c", g_h_{name}[0]);
    }} else {{
        printf("safe: pointer is NULL\\n");
    }}
}}

int main(void) {{
    printf("=== {name} null-after-free defense ===\\n");
    {name}_init(); {name}_release(); {name}_safe_use();
    return 0;
}}
'''


def _pat_struct_field(name: str) -> str:
    return f'''typedef struct {{
    int len; char *data; void (*cb)(void);
}} Obj_{name};
static Obj_{name} *g_obj_{name};

void {name}_make(void) {{
    g_obj_{name} = (Obj_{name} *)malloc(sizeof(Obj_{name}));
    if (g_obj_{name}) {{
        g_obj_{name}->len = 256;
        g_obj_{name}->data = (char *)malloc(256);
        g_obj_{name}->cb = NULL;
    }}
}}

void {name}_destroy(void) {{
    if (g_obj_{name}) {{
        free(g_obj_{name}->data); free(g_obj_{name});
    }}
}}

void {name}_use(void) {{
    if (g_obj_{name} && g_obj_{name}->data)
        printf("%c", g_obj_{name}->data[0]);  /* UAF */
}}

int main(void) {{
    printf("=== {name} struct field UAF ===\\n");
    {name}_make(); {name}_destroy(); {name}_use();
    return 0;
}}
'''


def _pat_realloc(name: str) -> str:
    return f'''void {name}_bug(void) {{
    char *p = (char *)malloc(64);
    char *old = p;
    if (!p) return;
    memset(p, 'B', 64);
    p = (char *)realloc(p, 128);
    if (p) {{ printf("realloc OK\\n"); free(p); }}
    printf("%c", old[0]);  /* UAF: old可能已失效 */
}}

int main(void) {{
    printf("=== {name} realloc UAF ===\\n");
    {name}_bug();
    return 0;
}}
'''


def _pat_loop(name: str) -> str:
    return f'''static char *g_items_{name}[4];

void {name}_loop_free(void) {{
    for (int i = 0; i < 4; i++) {{
        g_items_{name}[i] = (char *)malloc(64);
        if (g_items_{name}[i]) memset(g_items_{name}[i], i, 64);
    }}
    for (int i = 0; i < 4; i++)
        free(g_items_{name}[i]);  /* 缺少 g_items[i]=NULL */
    printf("%d", g_items_{name}[2][0]);  /* UAF */
}}

int main(void) {{
    printf("=== {name} loop iteration UAF ===\\n");
    {name}_loop_free();
    return 0;
}}
'''


def _pat_error_path(name: str) -> str:
    return f'''static char *g_res_{name};

int {name}_allocate(void) {{
    g_res_{name} = (char *)malloc(128);
    return g_res_{name} ? 0 : -1;
}}

void {name}_cleanup_on_error(void) {{
    if (g_res_{name}) {{ free(g_res_{name}); }}
}}

void {name}_use_resource(void) {{
    if (g_res_{name}) printf("%c", g_res_{name}[0]);  /* 可能UAF */
}}

int main(void) {{
    printf("=== {name} error path UAF ===\\n");
    if ({name}_allocate() == 0) {{
        {name}_cleanup_on_error();  /* 错误路径释放 */
        {name}_use_resource();      /* 继续使用 → UAF */
    }}
    return 0;
}}
'''


def _pat_callback(name: str) -> str:
    return f'''static char *g_ctx_{name};
static char *g_old_{name};

void {name}_setup(void) {{
    g_ctx_{name} = (char *)malloc(256);
    if (g_ctx_{name}) memset(g_ctx_{name}, 'C', 256);
    g_old_{name} = g_ctx_{name};  /* 保存旧引用 */
}}

void {name}_teardown(void) {{
    free(g_ctx_{name});
    g_ctx_{name} = (char *)malloc(64);  /* 重赋值g_ctx */
    /* g_old仍指向已释放内存 → UAF */
}}

void {name}_use_old(void) {{
    if (g_old_{name}) printf("%c", g_old_{name}[0]);  /* UAF */
}}

int main(void) {{
    printf("=== {name} callback UAF ===\\n");
    {name}_setup(); {name}_teardown(); {name}_use_old();
    return 0;
}}
'''


def _pat_argument(name: str) -> str:
    return f'''static char *g_msg_{name};

void {name}_log(char *msg) {{
    printf("log: %c\\n", msg[0]);
}}

void {name}_cleanup(char *msg) {{
    free(msg);
}}

void {name}_run(void) {{
    g_msg_{name} = (char *)malloc(128);
    if (!g_msg_{name}) return;
    memset(g_msg_{name}, 'D', 128);
    {name}_log(g_msg_{name});      /* 安全: 先使用 */
    {name}_cleanup(g_msg_{name});  /* 释放 */
    {name}_log(g_msg_{name});      /* UAF: 释放后传参 */
}}

int main(void) {{
    printf("=== {name} argument UAF ===\\n");
    {name}_run();
    return 0;
}}
'''


def _pat_list_node(name: str) -> str:
    return f'''typedef struct Node_{name} {{ int val; struct Node_{name} *next; }} Node_{name};
static Node_{name} *g_head_{name};

void {name}_build(void) {{
    g_head_{name} = (Node_{name} *)malloc(sizeof(Node_{name}));
    if (g_head_{name}) {{
        g_head_{name}->val = 1;
        g_head_{name}->next = (Node_{name} *)malloc(sizeof(Node_{name}));
        if (g_head_{name}->next) {{
            g_head_{name}->next->val = 2; g_head_{name}->next->next = NULL;
        }}
    }}
}}

void {name}_free_list(void) {{
    Node_{name} *cur = g_head_{name};
    while (cur) {{ Node_{name} *tmp = cur; cur = cur->next; free(tmp); }}
}}

void {name}_traverse(void) {{
    Node_{name} *cur = g_head_{name};
    while (cur) {{ printf("%d", cur->val); cur = cur->next; }}  /* UAF */
}}

int main(void) {{
    printf("=== {name} list node UAF ===\\n");
    {name}_build(); {name}_free_list(); {name}_traverse();
    return 0;
}}
'''


def _pat_lifecycle(name: str) -> str:
    return f'''typedef struct {{ int fd; char *rx_buf; int state; }} Conn_{name};
static Conn_{name} *g_conn_{name};

void {name}_open(void) {{
    g_conn_{name} = (Conn_{name} *)malloc(sizeof(Conn_{name}));
    if (g_conn_{name}) {{
        g_conn_{name}->fd = 42;
        g_conn_{name}->rx_buf = (char *)malloc(1024);
        g_conn_{name}->state = 1;
    }}
}}

void {name}_close(void) {{
    if (g_conn_{name}) {{
        free(g_conn_{name}->rx_buf); free(g_conn_{name});
    }}
}}

void {name}_read(void) {{
    if (g_conn_{name} && g_conn_{name}->state == 1)
        printf("%c", g_conn_{name}->rx_buf[0]);  /* UAF */
}}

int main(void) {{
    printf("=== {name} lifecycle race UAF ===\\n");
    {name}_open(); {name}_close(); {name}_read();
    return 0;
}}
'''


def _pat_reassign(name: str) -> str:
    return f'''static char *g_ptr_{name};
static char *g_saved_{name};

void {name}_alloc(void) {{
    g_ptr_{name} = (char *)malloc(64);
    if (g_ptr_{name}) memset(g_ptr_{name}, 'E', 64);
    g_saved_{name} = g_ptr_{name};  /* 保存副本 */
}}

void {name}_free_and_reassign(void) {{
    free(g_ptr_{name});
    g_ptr_{name} = (char *)malloc(128);  /* 重赋值: g_ptr安全 */
    /* 但 g_saved 仍指向已释放内存 → UAF */
    if (g_ptr_{name}) memset(g_ptr_{name}, 'F', 128);
}}

void {name}_use_saved(void) {{
    if (g_saved_{name})
        printf("%c", g_saved_{name}[0]);  /* UAF: g_saved指向已释放内存 */
}}

int main(void) {{
    printf("=== {name} saved-alias UAF ===\\n");
    {name}_alloc(); {name}_free_and_reassign(); {name}_use_saved();
    return 0;
}}
'''
