"""
FSTP回归测试样本 — 格式说明符语义感知污点传播的C源码样本.

样本分类:
  - CONST (3):   常量字符串 — 安全
  - USER_INPUT (4): 用户输入 — CWE-134
  - SANITIZED (4): 清理后 — 过滤FP
  - EDGE (4):    边界情况 — 复杂赋值/snprintf链接/嵌套
  - FMT_SPEC (2): 格式说明符语义分类
"""

# 常量样本 (CONST)

CONST_FMT = """
const char *fmt = "Hello %s";
printf(fmt, name);
"""

CONST_PURE = """
char *msg = "System ready.";
printf(msg);
"""

CONST_FORMATTED = """
char *prefix = "[%s:%d] ";
printf(prefix, file, line);
"""

# 用户输入样本 (USER_INPUT)

USER_INPUT_SCANF = """
char buf[256];
scanf("%s", buf);
printf(buf);
"""

USER_INPUT_FGETS = """
char input[128];
fgets(input, sizeof(input), stdin);
printf(input);
"""

USER_INPUT_RECV = """
char data[512];
recv(sock, data, sizeof(data), 0);
fprintf(stderr, data);
"""

USER_INPUT_ARGV = """
int main(int argc, char **argv) {
    printf(argv[1]);
}
"""

# 清理样本 (SANITIZED)

SANITIZED_STRREPLACE = """
char buf[256];
scanf("%s", buf);
strreplace(buf, "%", "%%");
printf(buf);
"""

SANITIZED_SANITIZE = """
char *input = getenv("USER");
sanitize(input);
printf(input);
"""

SANITIZED_G_STRDUP_PRINTF = """
char *name = getenv("LOGNAME");
char *safe = g_strdup_printf("%s", name);
syslog(LOG_INFO, safe);
"""

SANITIZED_ESCAPE_FORMAT = """
char *user = argv[1];
char *escaped = escape_format(user);
printf(escaped);
"""

# 边界情况 (EDGE)

EDGE_SNPRINTF_CHAIN = """
char buf[256];
fgets(buf, sizeof(buf), stdin);
char output[512];
snprintf(output, sizeof(output), buf, extra);
printf(output);
"""

EDGE_ASSIGN_CHAIN = """
char *user = getenv("QUERY");
char *fmt = user;
printf(fmt);
"""

EDGE_NO_FORMAT_INPUT = """
char msg[64] = "Hello";
printf(msg);
"""

EDGE_WRAPPER_PATTERN = """
void my_log(const char *fmt, ...) {
    printf(fmt);
}
void caller() {
    char *input = getenv("MSG");
    my_log(input);
}
"""

# 格式说明符语义分类样本 (FMT_SPEC)

FMT_SPEC_WRITE_CAPABLE = """
char payload[256];
recv(sock, payload, 256, 0);
printf(payload);
"""

FMT_SPEC_READ_ONLY = """
char name[64];
printf("Enter name: ");
fgets(name, sizeof(name), stdin);
printf(name);
"""

# 基准期望映射

BENCHMARK_SAMPLES = {
    'const_fmt':              CONST_FMT,
    'const_pure':             CONST_PURE,
    'const_formatted':        CONST_FORMATTED,
    'user_scanf':             USER_INPUT_SCANF,
    'user_fgets':             USER_INPUT_FGETS,
    'user_recv':              USER_INPUT_RECV,
    'user_argv':              USER_INPUT_ARGV,
    'san_strreplace':         SANITIZED_STRREPLACE,
    'san_sanitize':           SANITIZED_SANITIZE,
    'san_g_strdup_printf':    SANITIZED_G_STRDUP_PRINTF,
    'san_escape_format':      SANITIZED_ESCAPE_FORMAT,
    'edge_snprintf_chain':    EDGE_SNPRINTF_CHAIN,
    'edge_assign_chain':      EDGE_ASSIGN_CHAIN,
    'edge_no_format':         EDGE_NO_FORMAT_INPUT,
    'edge_sem_class':         FMT_SPEC_WRITE_CAPABLE,
}

# 期望: True=CWE-134, False=SAFE
EXPECTED_CWE = {
    'const_fmt': False, 'const_pure': False, 'const_formatted': False,
    'user_scanf': True, 'user_fgets': True, 'user_recv': True,
    'user_argv': True,
    'san_strreplace': False, 'san_sanitize': False,
    'san_g_strdup_printf': False, 'san_escape_format': False,
    'edge_snprintf_chain': True, 'edge_assign_chain': True,
    'edge_no_format': False, 'edge_sem_class': True,
}
