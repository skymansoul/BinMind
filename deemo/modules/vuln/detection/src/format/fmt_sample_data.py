"""格式化字符串测试样本 — 16 个 C 源码格式串模式，12 TP + 4 TN 对照.
"""

FMT_SAMPLES = [
    {
        'id': 'sample01_direct_fmt_vuln',
        'title': 'Direct Format String — user input as format',
        'pattern': 'printf(user_input) — format string directly controlled',
        'expected': 'TP',
        'trigger': 'pass untrusted string directly to printf',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: user input directly as format string */
    printf(argv[1]);
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'sample02_fmt_str_write_pct_n',
        'title': 'Format String Write — %n in format',
        'pattern': 'printf(user_input) containing %n → arbitrary write',
        'expected': 'TP',
        'trigger': 'format string with %n writes to stack address',
        'code': r'''#include <stdio.h>

int main(void) {
    int written = 0;
    /* VULN: controllable format with write capability */
    char *fmt = "AAAA%n";
    printf(fmt, &written);
    printf("bytes written: %d\n", written);
    return 0;
}
''',
    },
    {
        'id': 'sample03_indirect_fmt_leak',
        'title': 'Indirect Format String — readable via buffer overflow',
        'pattern': 'format string constructed from initially safe buffer → overflow makes it controllable',
        'expected': 'TP',
        'trigger': 'sprintf into small buffer → overflow into format ptr',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt_buf[16];
    if (argc < 2) return 1;
    /* overflow fmt_buf → can inject format specifiers */
    snprintf(fmt_buf, sizeof(fmt_buf), "Value: %s", argv[1]);
    printf(fmt_buf);  /* potential vuln if overflow injects % */
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'sample04_sprintf_fmt_vuln',
        'title': 'sprintf Format String Vulnerability',
        'pattern': 'sprintf(dst, user_fmt, ...) — format controllable',
        'expected': 'TP',
        'trigger': 'sprintf with user-controlled format string',
        'code': r'''#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char dst[256];
    if (argc < 2) return 1;
    /* VULN: user format string in sprintf */
    sprintf(dst, argv[1], 0x41414141);
    printf("result: %s\n", dst);
    return 0;
}
''',
    },
    {
        'id': 'sample05_fprintf_fmt_vuln',
        'title': 'fprintf Format String Vulnerability',
        'pattern': 'fprintf(stderr, user_input) — format controllable',
        'expected': 'TP',
        'trigger': 'fprintf with user-controlled format to stderr',
        'code': r'''#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: arbitrary format to stderr */
    fprintf(stderr, argv[1]);
    return 0;
}
''',
    },
    {
        'id': 'sample06_syslog_fmt_vuln',
        'title': 'syslog Format String Vulnerability',
        'pattern': 'syslog(LOG_ERR, user_input) — format controllable',
        'expected': 'TP',
        'trigger': 'syslog with user input as format',
        'code': r'''#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    openlog("fmt_test", LOG_PID, LOG_USER);
    /* VULN: user input as syslog format */
    syslog(LOG_ERR, argv[1]);
    closelog();
    return 0;
}
''',
    },
    {
        'id': 'sample07_info_leak_stack_read',
        'title': 'Information Leak — %x/%p stack read',
        'pattern': 'printf(user_input) → leaks stack values via %x',
        'expected': 'TP',
        'trigger': '%x%x%x%x in format → stack content leaked',
        'code': r'''#include <stdio.h>

int main(int argc, char **argv) {
    int secret = 0xdeadbeef;
    if (argc < 2) return 1;
    /* VULN: format string leaks stack data */
    printf(argv[1], secret);
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'sample08_wrapper_fmt_vuln',
        'title': 'Wrapper Function Format String',
        'pattern': 'wrapper(log_fmt, ...) → vprintf(log_fmt) — format propagates',
        'expected': 'TP',
        'trigger': 'varargs wrapper passes format through to printf',
        'code': r'''#include <stdio.h>
#include <stdarg.h>

void log_message(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    /* VULN: fmt passed through without validation */
    vprintf(fmt, args);
    va_end(args);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    log_message(argv[1]);
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'sample09_fmt_str_const_safe',
        'title': 'Safe: Constant Format String (no vuln)',
        'pattern': 'printf("%s", user_input) — safe, format is constant',
        'expected': 'TN',
        'trigger': 'format is compile-time constant string',
        'code': r'''#include <stdio.h>

int main(int argc, char **argv) {
    const char *user = argc > 1 ? argv[1] : "default";
    /* SAFE: constant format string, user data as argument */
    printf("User input: %s\n", user);
    return 0;
}
''',
    },
    {
        'id': 'sample10_debug_log_safe',
        'title': 'Safe: Debug Log with Constant Format',
        'pattern': 'printf("[DEBUG] %s", value) — safe debug output',
        'expected': 'TN',
        'trigger': 'constant debug prefix, no format control',
        'code': r'''#include <stdio.h>

int main(void) {
    int status = 42;
    /* SAFE: constant debug format */
    printf("[DEBUG] status=%d\n", status);
    printf("[INFO] initialization complete\n");
    printf("[WARN] threshold exceeded: %d\n", 100);
    return 0;
}
''',
    },
    {
        'id': 'sample11_fmt_str_in_rodata_safe',
        'title': 'Safe: Format in .rodata (read-only section)',
        'pattern': 'printf(rodata_fmt, ...) → not controllable',
        'expected': 'TN',
        'trigger': 'format string in read-only data section',
        'code': r'''#include <stdio.h>

static const char *STATUS_FMT = "Status: %s (code=%d)\n";

int main(void) {
    const char *name = "test_service";
    int code = 200;
    /* SAFE: format string from read-only data */
    printf(STATUS_FMT, name, code);
    return 0;
}
''',
    },
    {
        'id': 'sample12_snprintf_bounded_safe',
        'title': 'Safe: snprintf with Bounded Size',
        'pattern': 'snprintf(buf, sizeof(buf), "%s", input) → safe',
        'expected': 'TN',
        'trigger': 'format constant, size bounded',
        'code': r'''#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[128];
    const char *input = argc > 1 ? argv[1] : "default";
    /* SAFE: constant format, bounded output */
    snprintf(buf, sizeof(buf), "Input: %s", input);
    printf("%s\n", buf);
    return 0;
}
''',
    },
    {
        'id': 'sample13_dynamic_fmt_controlled',
        'title': 'Dynamic Format String Construction',
        'pattern': 'format string built at runtime from user data',
        'expected': 'TP',
        'trigger': 'snprintf builds format, result used as format',
        'code': r'''#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char fmt[64];
    if (argc < 2) return 1;
    /* format string partially from user input */
    snprintf(fmt, sizeof(fmt), "Value: %s", argv[1]);
    /* VULN: result contains user data as format */
    printf(fmt);
    printf("\n");
    return 0;
}
''',
    },
    {
        'id': 'sample14_wide_char_fmt',
        'title': 'Wide Character Format String',
        'pattern': 'wprintf(user_input) — wide char format controllable',
        'expected': 'TP',
        'trigger': 'wprintf with user-controlled wide string',
        'code': r'''#include <stdio.h>
#include <wchar.h>
#include <locale.h>

int main(int argc, char **argv) {
    setlocale(LC_ALL, "");
    /* VULN: wide char printf with user input */
    wchar_t msg[256];
    if (argc > 1) {
        mbstowcs(msg, argv[1], 256);
        wprintf(msg);
        wprintf(L"\n");
    }
    return 0;
}
''',
    },
    {
        'id': 'sample15_pct_n_write_primitive',
        'title': '%n Write Primitive — modify target variable',
        'pattern': 'printf(user_input, &target) with %n → overwrite target',
        'expected': 'TP',
        'trigger': '%n modifier writes byte count to address on stack',
        'code': r'''#include <stdio.h>

int main(int argc, char **argv) {
    int target = 0;
    if (argc < 2) return 1;
    /* VULN: %n writes to &target via format string */
    printf(argv[1], &target);
    printf("target after fmt: %d (0x%x)\n", target, target);
    return 0;
}
''',
    },
    {
        'id': 'sample16_buffered_fmt_leak',
        'title': 'Buffered Format Leak — leak through dprintf',
        'pattern': 'dprintf(fd, user_fmt, ...) → fd could be socket',
        'expected': 'TP',
        'trigger': 'dprintf with user format to file descriptor',
        'code': r'''#include <stdio.h>

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    /* VULN: format string to stdout (fd=1) */
    dprintf(1, argv[1]);
    dprintf(1, "\n");
    return 0;
}
''',
    },
]
