# 格式字符串C源码模板 (Format String C Source Templates)
# 15种格式字符串漏洞模式的C代码模板.
# 创建: 2026-05-04

SAMPLE_DEFS = [
    ("CVE-2012-0809", "cve_2012_0809_sudo",
     "sudo debug() passes prog arg directly to fprintf as format",
     "cross_func_fmtstr"),
    ("CVE-2013-4118", "cve_2013_4118_freerdp",
     "FreeRDP ssl_verify() passes cert subject to printf without format",
     "direct_fmtstr"),
    ("CVE-2014-0015", "cve_2014_0015_curl",
     "curl URL-parsed hostname passed to printf → format string injection",
     "url_fmtstr"),
    ("CVE-2014-1475", "cve_2014_1475_openssh",
     "OpenSSH PAM conversation passes user input to syslog as format",
     "syslog_fmtstr"),
    ("CVE-2015-5677", "cve_2015_5677_bsd",
     "FreeBSD routed set_metric() passes interface name as snprintf format",
     "snprintf_fmtstr"),
    ("CVE-2015-8612", "cve_2015_8612_bluetooth",
     "BlueZ bluetoothd passes device name to sprintf as format string",
     "struct_field_fmtstr"),
    ("CVE-2016-1686", "cve_2016_1686_libpng",
     "libpng png_set_PLTE passes tEXt chunk to fprintf via log callback",
     "callback_fmtstr"),
    ("CVE-2016-1908", "cve_2016_1908_mupdf",
     "MuPDF xps_parse_color passes XML attr value as printf format",
     "xml_fmtstr"),
    ("CVE-2017-7308", "cve_2017_7308_kernel",
     "Linux kernel packet_sock uses ring buffer content as printk format",
     "ringbuf_fmtstr"),
    ("CVE-2017-1000370", "cve_2017_1000370_shiftfs",
     "Linux shiftfs passes dentry name as format to vprintk_emit",
     "dentry_fmtstr"),
    ("CVE-2017-16995", "cve_2017_16995_kernel",
     "Linux BPF verifier passes user-controlled value to print_bpf_insn",
     "bpf_fmtstr"),
    ("CVE-2018-12020", "cve_2018_12020_gnupg",
     "GnuPG gpg passes sig-check result to log_printf as format",
     "logwrap_fmtstr"),
    ("CVE-2018-14618", "cve_2018_14618_curl",
     "curl NTLM type-2 message parser passes server field to printf",
     "ntlm_fmtstr"),
    ("CVE-2019-11477", "cve_2019_11477_kernel",
     "Linux SCTP passes sack gap blocks as printk format → kernel crash",
     "sack_fmtstr"),
    ("CVE-2020-27820", "cve_2020_27820_kernel",
     "Linux drm/nouveau passes GPU name as dev_err format string",
     "driver_fmtstr"),
]


def get_template(pattern: str, name: str) -> str:
    return {
        "cross_func_fmtstr": _pat_cross_func,
        "direct_fmtstr": _pat_direct,
        "url_fmtstr": _pat_direct,
        "syslog_fmtstr": _pat_syslog,
        "snprintf_fmtstr": _pat_direct,
        "struct_field_fmtstr": _pat_struct,
        "callback_fmtstr": _pat_callback,
        "xml_fmtstr": _pat_direct,
        "ringbuf_fmtstr": _pat_direct,
        "dentry_fmtstr": _pat_cross_func,
        "bpf_fmtstr": _pat_callback,
        "logwrap_fmtstr": _pat_cross_func,
        "ntlm_fmtstr": _pat_direct,
        "sack_fmtstr": _pat_direct,
        "driver_fmtstr": _pat_cross_func,
    }.get(pattern, _pat_direct)(name)


def _pat_direct(name: str) -> str:
    return f'''void {name}_vuln(char *user_input) {{
    printf(user_input);  /* BUG: 用户输入作为格式字符串 */
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    printf("=== {name} fmt test ===\\n");
    {name}_vuln(argv[1]);
    return 0;
}}
'''


def _pat_cross_func(name: str) -> str:
    return f'''void {name}_log(char *msg) {{
    fprintf(stderr, msg);  /* BUG: msg可能来自用户输入 */
}}

void {name}_process(char *input) {{
    {name}_log(input);  /* 跨函数传播 — 来源需追踪 */
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    printf("=== {name} cross-func fmt test ===\\n");
    {name}_process(argv[1]);
    return 0;
}}
'''


def _pat_syslog(name: str) -> str:
    return f'''#include <stdio.h>
#include <stdlib.h>

void {name}_log_user(char *user) {{
    fprintf(stderr, user);  /* BUG: 模拟syslog(user_input) */
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    printf("=== {name} syslog fmt test ===\\n");
    {name}_log_user(argv[1]);
    return 0;
}}
'''


def _pat_struct(name: str) -> str:
    return f'''#include <stdlib.h>
#include <string.h>

typedef struct {{
    char name[64];
    int id;
}} Dev_{name};

void {name}_show(Dev_{name} *d) {{
    printf(d->name);  /* BUG: name字段可能含格式说明符 */
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    Dev_{name} *d = (Dev_{name} *)malloc(sizeof(Dev_{name}));
    if (d) {{
        strncpy(d->name, argv[1], 63);
        d->name[63] = '\\0';
        d->id = 1;
        printf("=== {name} struct fmt test ===\\n");
        {name}_show(d);
        free(d);
    }}
    return 0;
}}
'''


def _pat_callback(name: str) -> str:
    return f'''typedef void (*LogCb_{name})(const char *);

static LogCb_{name} g_log_{name};

void {name}_set_logger(LogCb_{name} cb) {{
    g_log_{name} = cb;
}}

void {name}_on_data(char *data) {{
    if (g_log_{name}) g_log_{name}(data);  /* 回调使用原始data作为格式 */
}}

int main(int argc, char **argv) {{
    if (argc < 2) return 1;
    {name}_set_logger((LogCb_{name})printf);
    printf("=== {name} callback fmt test ===\\n");
    {name}_on_data(argv[1]);
    return 0;
}}
'''
