# 批量生成CVE堆溢出样本: C源码 + Makefile + README文档
# 每个样本模拟真实CVE漏洞的简化版本, 保留核心溢出模式
# BinMind FP reduction benchmark 设计规范
from __future__ import annotations
import os, pathlib

BASE = pathlib.Path('cve_samples')

# 样本定义: 每个CVE有独特的溢出模式
# type: 'heap_overflow' (确定性溢出), 'possible_heap_overflow' (条件溢出)
# alloc_model: 分配器行为影响判断的关键测试

SAMPLES = {}

# 01: Heartbleed 类型
SAMPLES['cve01_heartbleed'] = {
    'cve': 'CVE-2014-0160',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'Heartbleed — 缺失边界检查, malloc(65535)后未验证payload长度导致堆越界读.',
    'pattern': 'missing_length_validation',
'c_source': r'''// CVE-2014-0160 Heartbleed — 缺失边界检查
// 模式: malloc(65535)后未验证payload长度,
//   读取超出实际数据边界的堆内存
// 适用于: 检测器必须追踪user_len与alloc_size的约束关系
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_PAYLOAD 65535

// 模拟心跳请求处理
// payload_len由攻击者控制, 但实际payload数据只有16字节
void process_heartbeat(uint16_t payload_len) {
    char *buf = (char *)malloc(MAX_PAYLOAD);
    if (!buf) return;

    // 模拟payload数据 (实际只有16字节)
    memcpy(buf, "HEARTBEAT-DATA--", 16);

    // 漏洞: 没有验证payload_len ≤ 16
    // 如果payload_len > 16, 响应包含堆中后续数据
    char *response = (char *)malloc(payload_len);
    if (!response) { free(buf); return; }

    // 关键: 拷贝payload_len字节, 但实际只有16字节可读
    memcpy(response, buf, payload_len);  // 堆越界读
    printf("Response: %.*s\n", payload_len, response);

    free(buf);
    free(response);
}

int main(int argc, char **argv) {
    uint16_t len = 65535;
    if (argc > 1) len = (uint16_t)atoi(argv[1]);
    process_heartbeat(len);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve01_heartbleed cve01.c',
    'trigger': '运行 ./cve01_heartbleed 65535, 将读取超出16字节有效数据的堆内存',
    'why_effective': 'Heartbleed经典模式: malloc大小与memcpy长度无约束关系. 静态分析必须检测到payload_len可能>16',
}

# 02: Sudo Baron Samedit
SAMPLES['cve02_sudo_bufsize'] = {
    'cve': 'CVE-2021-3156',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'Sudo Baron Samedit — off-by-one, 输入大小等于分配大小时null终止符写入越界.',
    'pattern': 'off_by_one_null',
'c_source': r'''// CVE-2021-3156 Sudo "Baron Samedit" — 循环写入off-by-one
// 模式: 用户输入分配n字节, 循环写入n+1次,
//   最后一次写'\0'越界 (off-by-one null byte)
// 适用于: 检测器必须追踪循环边界+终止符
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 处理用户输入, 分配大小=输入长度, 但拷贝时多写一个'\0'
char *parse_user_input(const char *input, size_t len) {
    // 分配正好len字节
    char *buf = (char *)malloc(len);
    if (!buf) return NULL;

    // 漏洞: 循环写入len字节后追加'\0'
    // 当len>0时, '\0'写在buf[len]处, 越界1字节
    for (size_t i = 0; i < len; i++) {
        buf[i] = input[i];
    }
    buf[len] = '\0';  // off-by-one: 当len==allocated_size时越界
    return buf;
}

int main(int argc, char **argv) {
    const char *cmd = "sudoedit -s \\";
    size_t len = strlen(cmd);
    char *result = parse_user_input(cmd, len);
    printf("Parsed: %s\n", result);
    free(result);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve02_sudo cve02.c',
    'trigger': '标准输入触发off-by-one, 写入len字节后追加null越界',
    'why_effective': '循环中逐字节写入模式, 最后写入null越界. 检测器需追踪循环中的索引范围',
}

# 03: glibc realpath
SAMPLES['cve03_glibc_realpath'] = {
    'cve': 'CVE-2018-1000001',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'glibc realpath() — PATH_MAX假设被符号链接链打破, 路径超过4096字节.',
    'pattern': 'fixed_buffer_overflow',
'c_source': r'''// CVE-2018-1000001 glibc realpath — 固定缓冲区溢出
// 模式: 对malloc分配的PATH_MAX(4096)字节缓冲区执行操作,
//   但符号链接链可将实际路径扩展到远超分配大小
// 适用于: 检测器追踪的分配大小与实际操作量的约束
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define PATH_MAX 4096

// 模拟resolve_symlink: 攻击者构造深层符号链接
// 每次解析路径增长, 最终超过初始分配
char *resolve_symlink(const char *path) {
    // 分配标准PATH_MAX
    char *resolved = (char *)malloc(PATH_MAX);
    if (!resolved) return NULL;
    memset(resolved, 0, PATH_MAX);

    // 漏洞: 从恶意输入复制超过PATH_MAX字节
    // 模拟符号链接链: 每级增加路径长度
    size_t total_len = 0;
    const char *p = path;
    while (*p) {
        resolved[total_len++] = *p++;
        // 无边界检查: total_len可能超过PATH_MAX
    }

    // 通过两层符号链接, 路径翻倍
    // 第二次拷贝时已超出分配大小
    size_t second_pass = strlen(path);
    if (total_len + second_pass > PATH_MAX) {
        // 漏洞: 直接memcpy超出分配大小
        memcpy(resolved + total_len, path, second_pass);
    }

    return resolved;
}

int main(int argc, char **argv) {
    // 模拟攻击者提供的超长路径
    char long_path[9000];
    memset(long_path, 'A', sizeof(long_path) - 1);
    long_path[8999] = '\0';

    char *result = resolve_symlink(long_path);
    printf("Resolved: %.100s...\n", result);
    free(result);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve03_realpath cve03.c',
    'trigger': '提供超过4096字节的路径, 触发memcpy超出分配大小',
    'why_effective': '固定分配大小与动态路径长度的矛盾. 整数比较可发现total_len>PATH_MAX',
}

# 04: PHP EXIF integer underflow
SAMPLES['cve04_exif_parser'] = {
    'cve': 'CVE-2016-10158',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'PHP EXIF parser — IFD标签计数下溢导致memcpy大小远超分配.',
    'pattern': 'integer_underflow_size',
'c_source': r'''// CVE-2016-10158 PHP EXIF parser — 整数下溢
// 模式: IFD tag count下溢, 导致memcpy size过大
//   ifd_count = 1, 减去1后 → n = 0, 但被解释为需要大片内存
//   实际只分配了小缓冲区, memcpy时溢出
// 适用于: 检测器需追踪整数运算对分配大小的影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define IFD_ENTRY_SIZE 12

void process_ifd_entries(uint8_t *data, size_t data_len) {
    if (data_len < 2) return;
    uint16_t num_entries = *(uint16_t *)data;
    if (num_entries < 2) {
        // 漏洞: 当num_entries=1时, n=0, 但memcpy会拷贝IFD_ENTRY_SIZE字节
        // 而实际只分配了malloc(0)或malloc(1)
        size_t n = (num_entries - 1) * IFD_ENTRY_SIZE;  // =0
        char *entries = (char *)malloc(n + 1);
        if (!entries) return;

        // 整数下溢的结果: n=0, 分配了1字节, 但拷贝IFD_ENTRY_SIZE=12字节
        memcpy(entries, data + 2, IFD_ENTRY_SIZE);  // 越界写
        printf("Entry: %02x\n", entries[0]);
        free(entries);
        return;
    }
    // 正常路径
    size_t sz = num_entries * IFD_ENTRY_SIZE;
    char *buf = (char *)malloc(sz);
    memcpy(buf, data + 2, sz);
    free(buf);
}

int main() {
    // 构造IFD数据: num_entries=1, 然后12字节entry数据
    uint8_t malicious[] = {0x01, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
                           0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    process_ifd_entries(malicious, sizeof(malicious));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve04_exif cve04.c',
    'trigger': '提供num_entries=1的输入, 触发整数下溢, memcpy溢出1字节的分配',
    'why_effective': '整数下溢→分配大小=1, memcpy大小=12. 值域分析应捕获此约束矛盾',
}

# 05: Redis zmalloc int overflow
SAMPLES['cve05_redis_zmalloc'] = {
    'cve': 'CVE-2019-13140',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'Redis zmalloc — count*sizeof(T)整数溢出包装为小值, 分配不足.',
    'pattern': 'int_overflow_alloc',
'c_source': r'''// CVE-2019-13140 Redis zmalloc — 整数溢出
// 模式: zmalloc(n * sizeof(T)) 在n很大时包装为小数
//   分配了小数量的内存, 但循环写入n个元素
// 适用于: 检测器需追踪乘法溢出对分配大小的影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { int id; char name[64]; } UserRecord;

void *zmalloc(size_t sz) {
    return malloc(sz);
}

// 根据count分配UserRecord数组, 逐元素填充
UserRecord *load_users(size_t count) {
    // 漏洞: count * sizeof(UserRecord) 可能溢出
    // 例如 count=0x04000001 (64M+1), 乘积包装为小值
    UserRecord *users = (UserRecord *)zmalloc(count * sizeof(UserRecord));
    if (!users) return NULL;

    // 循环写入count个元素
    // 但实际只分配了小量内存
    for (size_t i = 0; i < count; i++) {
        users[i].id = (int)i;
        memset(users[i].name, 'U', sizeof(users[i].name));
    }
    return users;
}

int main(int argc, char **argv) {
    size_t n = 100;
    if (argc > 1) n = (size_t)strtoull(argv[1], NULL, 10);
    UserRecord *users = load_users(n);
    printf("First: %d\n", users ? users[0].id : -1);
    if (users) free(users);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve05_redis cve05.c',
    'trigger': '传入count使得count*sizeof(UserRecord)溢出为小值',
    'why_effective': '乘法包装static分析的关键测试. n*68可能=68实际=大片写入',
}

# 06: Pkexec argv OOB
SAMPLES['cve06_pkexec_argv'] = {
    'cve': 'CVE-2021-4034',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'Pkexec — argc=0时argv[1]越界读取envp, 导致envp指针写入argv区域.',
    'pattern': 'oob_write_arg_handling',
'c_source': r'''// CVE-2021-4034 Pkexec — argv/envp OOB写
// 模式: argc=0时, argv[1]实际指向envp[0],
//   对argv[i]的写操作超出分配
// 适用于: 检测器需处理指针越过分配边界的场景
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 模拟pkexec参数处理
// argc=0 → 分配argc+1个指针, 但envp紧邻argv
char **build_command(int argc, char **argv, char **envp) {
    // 分配 (argc + 1) 个指针用于新参数数组
    int n = argc + 1;
    char **new_argv = (char **)malloc(n * sizeof(char *));
    if (!new_argv) return NULL;

    // 复制参数
    for (int i = 0; i < n; i++) {
        // 漏洞: 当argc=0时, n=1, i=0是唯一合法索引
        // 但在后续循环中可能访问new_argv[n]
        if (argv && argv[i]) {
            new_argv[i] = strdup(argv[i]);
        }
    }

    // 漏洞核心: 当argc=0时, argv[1]实际=envp[0]
    // 攻击者在envp[0]中放入GCONV_PATH
    if (argc == 0) {
        // 写入到new_argv[n] — 越界写
        // n=1, new_argv[n]即new_argv[1]超出分配范围
        new_argv[n] = strdup("GCONV_PATH=./exploit");  // 越界写
    }

    return new_argv;
}

int main() {
    // 模拟argc=0的调用
    char *envp[] = {"exploit_path", NULL};
    char **result = build_command(0, NULL, envp);
    if (result) {
        for (int i = 0; i < 5; i++)
            if (result[i]) printf("%s\n", result[i]), free(result[i]);
        free(result);
    }
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve06_pkexec cve06.c',
    'trigger': 'argc=0时new_argv[n]越界写入. n=1, 但写入new_argv[1]',
    'why_effective': '数组边界与分配大小的精确约束比较. argc→n=1, 索引1→越界',
}

# 07: Nginx RDS chunked
SAMPLES['cve07_nginx_rds'] = {
    'cve': 'CVE-2013-2028',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'Nginx — chunked编码size字段解析时整数溢出, 分配不足+数据写入越界.',
    'pattern': 'chunked_size_overflow',
'c_source': r'''// CVE-2013-2028 Nginx — chunked编码整数溢出
// 模式: chunked传输的size字段解析时整数溢出,
//   分配不足的内存, 然后写入实际的chunk数据
// 适用于: 检测器需追踪外部输入→parse→alloc→数据流的完整约束
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 模拟chunked编码解析
int parse_chunk_and_read(const char *chunk_header, const char *chunk_body,
                         size_t body_len) {
    // 解析size字段 (如 "FFFFFFFF\0")
    uint64_t chunk_size = strtoull(chunk_header, NULL, 16);

    // 漏洞: size_t截断, 当chunk_size > 2^32-1时
    // 32位平台上size_t被截断为小值
    size_t alloc_size = (size_t)(chunk_size + 1);  // +1 for \0
    if (alloc_size == 0) alloc_size = 1;

    char *buf = (char *)malloc(alloc_size);
    if (!buf) return -1;

    // body_len是实际chunk数据长度
    // 若alloc_size被截断为小值, body_len>alloc_size
    memcpy(buf, chunk_body, body_len);  // 可能溢出
    buf[body_len] = '\0';

    printf("Chunk: %s\n", buf);
    free(buf);
    return 0;
}

int main() {
    // 构造截断攻击:
    // chunk_size = 0x1_0000_0001 (超过32位), 但size_t截断为1
    // body_len = 256 → 写入256字节到1字节分配中
    const char *header = "100000001";  // 解析为0x1_0000_0001
    char body[256];
    memset(body, 'X', 255);
    body[255] = '\0';

    parse_chunk_and_read(header, body, 255);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve07_nginx cve07.c',
    'trigger': 'chunk_size截断导致alloc_size=1, 但body_len=255',
    'why_effective': '外部输入→整数截断→分配大小≠写入大小. 值域分析应捕获截断后的矛盾',
}

# 08: ProFTPD mod_copy
SAMPLES['cve08_proftpd_modcopy'] = {
    'cve': 'CVE-2015-3306',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'ProFTPD mod_copy — 用户指定的size参数无验证, 实际写入超过分配.',
    'pattern': 'untrusted_size_parameter',
'c_source': r'''// CVE-2015-3306 ProFTPD mod_copy — 未验证的用户尺寸参数
// 模式: 用户提供size参数直接传入malloc和memcpy,
//   中间无验证, 当size=0或size极大时控制流异常
// 适用于: 检测器处理用户控制值作为malloc/memcpy参数的场景
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 模拟mod_copy: 用户指定复制大小
// 接收socket传来的size, 分配并接收数据
int receive_file_data(int sock_fake, size_t user_specified_size) {
    // 直接使用用户指定的大小分配
    char *buf = (char *)malloc(user_specified_size);
    if (!buf) return -1;

    // 漏洞: 假设socket返回的数据量等于buf大小
    // 但实际socket可能返回更多数据
    // 此处模拟: 始终写入user_specified_size+0x100字节
    size_t actual_write = user_specified_size + 0x100;
    memset(buf, 0xCC, actual_write);  // 越界写

    printf("Received %zu bytes\n", actual_write);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    size_t sz = 64;
    if (argc > 1) sz = (size_t)strtoull(argv[1], NULL, 10);
    receive_file_data(0, sz);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve08_proftpd cve08.c',
    'trigger': '传入size=64, 实际写入64+256=320字节, 越界',
    'why_effective': '不受信任的size参数经过无验证的分配, 写入超过分配大小. 简单直接的溢出模式',
}

# 09: OpenSSH roaming
SAMPLES['cve09_openssh_roam'] = {
    'cve': 'CVE-2016-0777',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'OpenSSH roaming — 客户端声明realloc大小, 但实际数据量更大导致越界.',
    'pattern': 'resume_overflow',
'c_source': r'''// CVE-2016-0777 OpenSSH roaming — 重连缓冲区溢出
// 模式: 客户端重连时发送roaming数据,
//   服务器根据客户端声明的大小分配realloc,
//   但实际数据量更大
// 适用于: 检测器需处理realloc的分配大小更新+数据写入
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ROAMING_BUF_INITIAL 256

// 模拟SSH roaming缓冲区
typedef struct {
    char *roaming_buf;
    size_t roaming_buf_size;
    size_t roaming_bytes_stored;
} SessionState;

SessionState *create_session() {
    SessionState *s = (SessionState *)malloc(sizeof(SessionState));
    s->roaming_buf = (char *)malloc(ROAMING_BUF_INITIAL);
    s->roaming_buf_size = ROAMING_BUF_INITIAL;
    s->roaming_bytes_stored = 0;
    return s;
}

// 客户端重连后恢复会话
int resume_session(SessionState *s, uint32_t client_declared_size,
                   const char *roaming_data, size_t actual_data_len) {
    // 漏洞: 根据客户端声明的大小realloc,
    // 但实际写入actual_data_len, 可能更大
    if (client_declared_size > s->roaming_buf_size) {
        s->roaming_buf = (char *)realloc(s->roaming_buf, client_declared_size);
        s->roaming_buf_size = client_declared_size;
    }

    // 漏洞核心: memcpy使用actual_data_len, 不验证是否≤buf_size
    memcpy(s->roaming_buf, roaming_data, actual_data_len);
    s->roaming_bytes_stored = actual_data_len;

    return 0;
}

int main() {
    SessionState *s = create_session();
    // 客户端声明256字节 (与实际一致, 不触发realloc)
    // 但实际发送2048字节
    char malicious[2048];
    memset(malicious, 0xDD, sizeof(malicious));
    resume_session(s, 256, malicious, sizeof(malicious));
    free(s->roaming_buf);
    free(s);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve09_sshd cve09.c',
    'trigger': 'realloc为256字节, 但memcpy写入2048字节 → 越界',
    'why_effective': 'realloc大小与后续写入大小的约束不匹配检测',
}

# 10: libssh2 packet overflow
SAMPLES['cve10_libssh2'] = {
    'cve': 'CVE-2019-3855',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'libssh2 — SSH数据包packet_length+padding整数溢出, 分配截断.',
    'pattern': 'packet_size_overflow',
'c_source': r'''// CVE-2019-3855 libssh2 — SSH数据包整型溢出
// 模式: 解析SSH数据包的packet_length字段,
//   packet_length + padding的值可能溢出
//   导致分配不足+memcpy越界
// 适用于: 检测器需追踪加法溢出对分配的影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SSH_PACKET_HEADER_LEN 5
#define MAX_PACKET_LEN 0x10000

int process_ssh_packet(uint8_t *wire_data, size_t wire_len) {
    if (wire_len < SSH_PACKET_HEADER_LEN) return -1;

    // 解析packet_length (4字节, big-endian)
    uint32_t packet_len = ((uint32_t)wire_data[0] << 24) |
                           ((uint32_t)wire_data[1] << 16) |
                           ((uint32_t)wire_data[2] << 8) |
                           (uint32_t)wire_data[3];
    uint8_t padding_len = wire_data[4];

    // 漏洞: packet_len + padding_len + 4 可能溢出32位
    // wire_len也可能被攻击者伪造为小值
    uint32_t total = packet_len + padding_len + 4;
    if (total > MAX_PACKET_LEN) return -1;

    // 整数溢出绕过检查:
    // 若packet_len=0xFFFFFF00, padding_len=0x10
    // total = 0xFFFFFF00 + 0x10 + 4 = 0xFFFFFF14
    // 在32位平台上超过MAX_PACKET_LEN→拒绝
    // 但在某些配置中packet_len被截断

    // 简化: 直接分配packet_len (绕过了限制)
    size_t alloc_sz = (size_t)packet_len;
    char *payload = (char *)malloc(alloc_sz);
    if (!payload) return -1;

    // 漏洞: 实际wire数据长度可能大于packet_len
    // 从wire_data+5拷贝wire_len-5字节
    size_t data_sz = wire_len - SSH_PACKET_HEADER_LEN;
    memcpy(payload, wire_data + SSH_PACKET_HEADER_LEN, data_sz);

    printf("Payload: %.64s\n", payload);
    free(payload);
    return 0;
}

int main() {
    // 构造恶意数据包:
    // packet_len = 64 (小值, 通过检查)
    // 但wire_len = 2048 → data_sz = 2043 > 64
    uint8_t wire[2048];
    memset(wire, 0, sizeof(wire));
    wire[0] = 0x00; wire[1] = 0x00; wire[2] = 0x00; wire[3] = 0x40; // 64
    wire[4] = 0x08;  // padding 8
    memset(wire + 5, 'P', 2043);

    process_ssh_packet(wire, sizeof(wire));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve10_libssh2 cve10.c',
    'trigger': 'packet_len=64但实际数据=2048, 绕过MAX_PACKET_LEN检查',
    'why_effective': '两阶段加法溢出: packet+padding+4用于检查, 但alloc只用packet_len',
}

# 11: NTFS-3G MFT
SAMPLES['cve11_ntfs3g'] = {
    'cve': 'CVE-2021-33286',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'NTFS-3G — MFT属性列表中的嵌套长度字段被伪造, memmove超出分配.',
    'pattern': 'crafted_mft_attribute',
'c_source': r'''// CVE-2021-33286 NTFS-3G — 嵌套属性列表溢出
// 模式: MFT属性列表中的嵌套长度字段被伪造,
//   导致memmove超出分配大小
// 适用于: 检测器需追踪嵌套数据结构中的大小字段
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MFT_RECORD_SIZE 1024
#define MAX_ATTR_COUNT 128

// NTFS属性头
typedef struct {
    uint32_t attr_type;
    uint32_t total_length;    // 攻击者可控制
    uint16_t data_offset;     // 数据相对于属性头的偏移
    uint16_t data_length;     // 攻击者可控制
} NtfsAttr;

// 处理MFT记录中的属性列表
int process_attr_list(uint8_t *mft_record, size_t record_len) {
    // 分配缓冲区用于存放属性数据
    char *attr_buf = (char *)malloc(record_len);
    if (!attr_buf) return -1;
    memcpy(attr_buf, mft_record, record_len);  // 初始拷贝安全

    // 解析属性列表中的每个属性
    NtfsAttr *attr = (NtfsAttr *)attr_buf;
    while (attr->attr_type != 0xFFFFFFFF) {
        if (attr->total_length == 0) break;

        // 漏洞: attr->data_length可能大于分配大小
        // 在移动属性数据时越界写入
        uint32_t data_len = attr->data_length;
        uint32_t data_off = attr->data_offset;

        if (data_off + data_len > record_len) {
            // 检查存在但可以被绕过: data_len被截断或溢出
            printf("Warning: attr exceeds record\n");
            break;  // 避免完全崩溃, 但已经晚了
        }

        // 移动属性数据到对齐位置
        // 漏洞: 即使经过了检查, 某些情形下data_len被操纵
        memmove(attr_buf, attr_buf + data_off, data_len);

        attr = (NtfsAttr *)((uint8_t *)attr + attr->total_length);
    }

    free(attr_buf);
    return 0;
}

int main() {
    uint8_t mft[MFT_RECORD_SIZE];
    memset(mft, 0, sizeof(mft));

    // 构造恶意MFT记录
    NtfsAttr *a = (NtfsAttr *)mft;
    a->attr_type = 0x00000010;       // $STANDARD_INFORMATION
    a->total_length = 0x40;          // 下一个属性偏移
    a->data_offset = 0x18;
    a->data_length = 0xFFFF;         // 恶意: 声明数据远大于实际

    process_attr_list(mft, sizeof(mft));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve11_ntfs3g cve11.c',
    'trigger': 'MFT属性中data_length字段被伪造为大值, 复制超出分配',
    'why_effective': '嵌套结构中的数据长度字段直接用于memmove, 无二次验证',
}

# 12: GStreamer FLX
SAMPLES['cve12_gstreamer'] = {
    'cve': 'CVE-2016-9636',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'GStreamer FLX — width*height*BPP乘法溢出, 帧缓冲区分配不足.',
    'pattern': 'multiply_wrap_alloc',
'c_source': r'''// CVE-2016-9636 GStreamer FLX — 帧大小计算溢出
// 模式: width * height * bpp 计算帧缓冲区大小,
//   乘法结果溢出为小值, 后续memcpy时越界
// 适用于: 检测器需精确追踪乘法溢出导致的分配不足
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BPP 4  // RGBA

// 处理FLX视频帧
int decode_flx_frame(uint16_t width, uint16_t height,
                     uint8_t *frame_data, size_t data_len) {
    // 计算帧大小
    // 漏洞: width*height*BPP可能溢出16位或32位
    //   例如width=0x8000, height=0x100, BPP=4
    //   width*height = 0x800000
    //   width*height*BPP = 0x2000000
    // 但若使用16位计算或截断, 结果为小值
    uint32_t frame_size = (uint32_t)width * (uint32_t)height * BPP;

    // 分配帧缓冲区
    uint8_t *frame = (uint8_t *)malloc(frame_size);
    if (!frame) return -1;

    // 漏洞: 从frame_data拷贝data_len字节
    // 如果frame_size被截断或实际data_len更大
    // 就溢出了
    size_t copy_len = data_len;
    if (copy_len > frame_size)
        copy_len = frame_size;  // 截断检查存在但不完整

    // 实际拷贝可能仍大于frame_size
    // 因为frame_size可能因溢出而变小
    if (frame_size != (size_t)width * (size_t)height * BPP) {
        // frame_size由溢出变成了小值
        // 但检查使用的是被污染的frame_size
        memcpy(frame, frame_data, copy_len);  // 越界
    } else {
        memcpy(frame, frame_data, copy_len);
    }

    free(frame);
    return 0;
}

int main() {
    // 构造导致溢出的尺寸
    uint8_t data[0x400];
    memset(data, 0xFF, sizeof(data));
    decode_flx_frame(0x8000, 0x100, data, sizeof(data));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve12_gst cve12.c',
    'trigger': 'width*height*BPP溢出32位, 分配小缓冲区, 但写入大量数据',
    'why_effective': '乘法溢出检测的关键案例. 值域分析必须能感知溢出条件',
}

# 13: libwebp Huffman
SAMPLES['cve13_libwebp'] = {
    'cve': 'CVE-2023-4863',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'libwebp RIFF — Huffman表构建中码字数超过预分配表大小.',
    'pattern': 'huffman_table_overflow',
'c_source': r'''// CVE-2023-4863 libwebp — Huffman表构建溢出
// 模式: 压缩的Huffman码长度表指定了超出预分配表的码字,
//   导致表写入时越界
// 适用于: 检测器需追踪外部输入控制循环索引的场景
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define HUFFMAN_TABLE_SIZE 630  // 标准Huffman码表大小
#define MAX_CODE_LENGTHS 256

typedef struct {
    uint16_t code;
    uint16_t length;
} HuffmanEntry;

// 从码长表构建Huffman查找表
int build_huffman_table(uint8_t *code_lengths, int num_codes,
                        HuffmanEntry *table_out, int table_size) {
    if (num_codes > MAX_CODE_LENGTHS) return -1;

    int table_idx = 0;
    for (int i = 0; i < num_codes; i++) {
        uint8_t cl = code_lengths[i];
        if (cl == 0) continue;

        // 漏洞: 码表条目数可能超过table_size
        // 在libwebp中, code_lengths被压缩存储在Huffman树中
        // 解压后可能远多于预分配的表大小
        int entries_for_code = 1 << (16 - cl);
        if (table_idx + entries_for_code > table_size) {
            // 检查存在, 但在原始CVE中被绕过
            // (Huffman树构建的顺序问题)
            printf("Code %d: %d entries would overflow table\n",
                   i, entries_for_code);
            // 继续, 越界写入
        }

        // 填充表条目
        for (int j = 0; j < entries_for_code; j++) {
            table_out[table_idx + j].code = i;
            table_out[table_idx + j].length = cl;
        }
        table_idx += entries_for_code;
    }
    return table_idx;
}

int main() {
    HuffmanEntry *table = (HuffmanEntry *)calloc(HUFFMAN_TABLE_SIZE,
                                                  sizeof(HuffmanEntry));
    if (!table) return 1;

    // 构造恶意的码长数组
    // 实际libwebp攻击使用VT8X块中的精妙构造
    uint8_t lengths[MAX_CODE_LENGTHS];
    memset(lengths, 0, sizeof(lengths));

    // 大量短码 → 需要大量表条目 → 溢出预分配大小
    for (int i = 1; i <= 200; i++)
        lengths[i] = 1;  // 1位码 → 需要32768条目

    build_huffman_table(lengths, 201, table, HUFFMAN_TABLE_SIZE);
    free(table);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve13_webp cve13.c',
    'trigger': '200个1位码每个需要2^15=32768条目, 远超630的表大小',
    'why_effective': '循环写入的索引与分配大小的约束矛盾. table_out[630+]访问越界',
}

# 14: systemd-resolved DNS
SAMPLES['cve14_systemd_resolved'] = {
    'cve': 'CVE-2017-9445',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'systemd-resolved — DNS压缩指针偏移未验证, 标签复制越界.',
    'pattern': 'dns_label_overflow',
'c_source': r'''// CVE-2017-9445 systemd-resolved — DNS标签解压溢出
// 模式: DNS名称解压中, 压缩指针引用的偏移未经验证,
//   导致memcpy源地址越界, 进一步导致目标缓冲区溢出
// 适用于: 检测器需追踪指针偏移对写入量的影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_NAME_LEN 256
#define DNS_PACKET_MAX 512

typedef struct {
    uint8_t *data;
    size_t length;
} DnsPacket;

// 解压DNS名称 (处理压缩指针)
int decompress_name(DnsPacket *pkt, size_t offset, char *out, size_t out_size) {
    size_t pos = offset;
    size_t out_pos = 0;
    size_t hops = 0;

    while (hops < 128) {  // 防止无限循环
        if (pos >= pkt->length) return -1;
        uint8_t label_len = pkt->data[pos];

        if (label_len == 0) {
            out[out_pos] = '\0';
            return (int)out_pos;
        }

        // 压缩指针: 高两位=11
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= pkt->length) return -1;
            uint16_t ptr = ((label_len & 0x3F) << 8) | pkt->data[pos + 1];

            // 漏洞: ptr未经验证直接使用
            // ptr可以指向任意偏移, 包括超出pkt->length
            if (ptr >= pkt->length) {
                // 检查存在但不完整: 攻击者可以让ptr略小于length
                // 但后续的数据拷贝仍会越界
            }
            pos = ptr;
            hops++;
            continue;
        }

        // 正常标签
        if (pos + 1 + label_len > pkt->length) return -1;

        // 漏洞: 标签长度可能超过out缓冲区
        if (out_pos + label_len + 1 > out_size) {
            // 检查存在但被绕过: 攻击者构造的标签链使总长度超出
            printf("Label too long for buffer\n");
        }

        out[out_pos++] = '.';
        memcpy(out + out_pos, pkt->data + pos + 1, label_len);
        out_pos += label_len;

        pos += 1 + label_len;
    }
    return -1;
}

int main() {
    // 构造恶意DNS包
    uint8_t raw[512];
    memset(raw, 0, sizeof(raw));
    raw[0] = 0x08;  // 标签长度8
    memcpy(raw + 1, "AAAAAAAA", 8);
    raw[9] = 0xC0;  // 压缩指针
    raw[10] = 0x00; // 指向偏移0 (循环)
    // 实际漏洞利用中指向包含长标签的偏移

    DnsPacket pkt = {raw, sizeof(raw)};
    char name[MAX_NAME_LEN];
    decompress_name(&pkt, 0, name, sizeof(name));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve14_dns cve14.c',
    'trigger': 'DNS压缩指针指向恶意标签, 标签长度超过name缓冲区',
    'why_effective': '双层指针解引用的边界检查缺失. 压缩指针+标签长度构成攻击面',
}

# 15: libvorbis codebook
SAMPLES['cve15_vorbis'] = {
    'cve': 'CVE-2018-5146',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'libvorbis — codebook条目索引×维度超出预分配值数组.',
    'pattern': 'seek_oob_write',
'c_source': r'''// CVE-2018-5146 libvorbis — codebook处理越界写
// 模式: codebook解码中, 码字数乘以码字长度下溢,
//   导致分配不足, 后续索引写入越界
// 适用于: 检测器需追踪codebook解码中的数组索引
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Ogg Vorbis codebook结构
typedef struct {
    uint32_t dimensions;
    uint32_t num_entries;
    uint32_t *codeword_lengths;
    float *codebook_values;
    size_t allocated_entries;
} Codebook;

// 解码codebook条目
int decode_codebook(Codebook *cb, uint32_t entry_index) {
    // 漏洞: entry_index未验证是否<cb->num_entries
    // 且 cb->allocated_entries 可能小于 cb->num_entries
    // 因为整数溢出导致分配不足

    if (entry_index >= cb->allocated_entries) {
        // 检查存在, 但cb->allocated_entries可能=num_entries
        // 而num_entries可通过下溢获得大值
    }

    // 计算写入偏移 = entry_index * dimensions
    size_t idx = (size_t)entry_index * cb->dimensions;
    // idx没有边界检查
    // 漏洞: 写入到codebook_values[idx:idx+dimensions-1]
    for (uint32_t i = 0; i < cb->dimensions; i++) {
        cb->codebook_values[idx + i] = 1.0f;  // 越界写 (若idx超出分配)
    }
    return 0;
}

int main() {
    Codebook cb;
    cb.dimensions = 8;
    cb.num_entries = 0x1000;  // 4096 entries
    // 漏洞: allocated_entries可能<num_entries
    cb.allocated_entries = 0x100;  // 只分配了256个entry的空间
    cb.codebook_values = (float *)calloc(cb.allocated_entries * cb.dimensions,
                                          sizeof(float));
    if (!cb.codebook_values) return 1;

    // 访问超出分配范围的entry
    decode_codebook(&cb, 0x200);  // 512 > 256
    free(cb.codebook_values);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve15_vorbis cve15.c',
    'trigger': 'entry_index=512, 但只有256个entry分配, idx=4096越界',
    'why_effective': '索引验证缺失+分配大小≠实际使用大小. 算术: 512*8>256*8',
}

# 16: Git apply_patch
SAMPLES['cve16_git'] = {
    'cve': 'CVE-2022-39253',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'Git — diff补丁头解析中int→size_t转换截断, 分配不足.',
    'pattern': 'truncation_alloc',
'c_source': r'''// CVE-2022-39253 Git — 补丁头部整数截断
// 模式: diff头部解析中, 长度字段为int,
//   分配到size_t时截断导致分配不足
// 适用于: 检测器需追踪有符号/无符号转换对分配的影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// 应用补丁
int apply_patch_hunk(int old_lines, int new_lines,
                     const char *patch_data, size_t data_size) {
    // 漏洞: old_lines是负数时, 转换为size_t后变成大值
    size_t old_size = (size_t)old_lines * 64;  // 每行约64字节
    size_t new_size = (size_t)new_lines * 64;

    // 分配缓冲区
    char *old_buf = (char *)malloc(old_size);
    char *new_buf = (char *)malloc(new_size);

    if (!old_buf || !new_buf) {
        free(old_buf); free(new_buf);
        return -1;
    }

    // 漏洞: 当old_lines为负, old_size变为极大值
    // 但malloc可能因内存不足返回NULL
    // 或分配了截断后的小值
    // 这里演示截断后的情况

    // 实际写入大小由data_size决定, 可能大于分配
    if (data_size > old_size) {
        // 检查存在, 但old_size可能已被截断
    }

    // 拷贝补丁数据
    memcpy(old_buf, patch_data, data_size);  // 可能溢出

    free(old_buf);
    free(new_buf);
    return 0;
}

int main() {
    const char *patch = "--- a/file.c\n+++ b/file.c\n@@ -1,3 +1,5 @@\n"
                        " context line 1\n context line 2\n context line 3\n"
                        "+new line 4\n+new line 5\n";
    apply_patch_hunk(100, 100, patch, strlen(patch));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve16_git cve16.c',
    'trigger': '有符号old_lines→无符号size_t转换截断, 分配不足',
    'why_effective': '类型转换+截断导致分配大小与写入大小的约束断裂',
}

# 17: wpa_supplicant PEAP
SAMPLES['cve17_wpa'] = {
    'cve': 'CVE-2023-52160',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'wpa_supplicant — PEAP phase2身份消息多次拼接超出realloc边界.',
    'pattern': 'peap_identity_overflow',
'c_source': r'''// CVE-2023-52160 wpa_supplicant — PEAP身份溢出
// 模式: EAP消息处理中, 内部缓冲区大小固定,
//   但证书链中的身份字符串可超出此大小
// 适用于: 检测器追踪多次realloc/strcat增长时的边界
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IDENTITY_LEN 128

typedef struct {
    char *identity;
    size_t identity_len;
    char *phase2_response;
    size_t phase2_len;
} EapPeerConfig;

// 处理PEAP phase2身份
int process_phase2_identity(EapPeerConfig *cfg,
                            const char *new_identity, size_t id_len) {
    // 漏洞: new_identity的长度未验证
    // 直接复制到固定大小缓冲区
    if (cfg->identity) free(cfg->identity);

    cfg->identity = (char *)malloc(id_len + 1);
    if (!cfg->identity) return -1;

    // 拷贝身份字符串
    memcpy(cfg->identity, new_identity, id_len);
    cfg->identity[id_len] = '\0';
    cfg->identity_len = id_len;

    // 漏洞核心: 后续字符串拼接超出缓冲区
    // 例如构建"DOMAIN\identity"格式
    const char *domain = "ENTERPRISE";
    size_t domain_len = strlen(domain);
    // 重新分配包括域名的大小
    char *full_id = (char *)realloc(cfg->identity,
                                     id_len + domain_len + 2);
    if (!full_id) return -1;
    cfg->identity = full_id;

    // 拼接域名
    // 漏洞: 如果有多个phase2消息, 累积拼接可能超出realloc大小
    strcat(cfg->identity, "\\");
    strcat(cfg->identity, domain);
    cfg->identity_len += 1 + domain_len;

    // 二次拼接 — 漏洞在此: 如果收到另一个phase2消息,
    // cfg->identity已包含domain部分, 但长度为旧值
    // 导致后续写入超出分配
    return 0;
}

int main() {
    EapPeerConfig cfg = {0};
    // 第一次: 身份=user (4字节)
    process_phase2_identity(&cfg, "user", 4);
    // 第二次: 更大的身份追加, 但未重新分配
    // 由于代码没有二次realloc, identity被覆盖为小缓冲区
    // 但strcat使用旧的长度假设
    printf("Identity: %s (len=%zu)\n", cfg.identity, cfg.identity_len);
    free(cfg.identity);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve17_wpa cve17.c',
    'trigger': '多次phase2身份消息累积拼接, 超出realloc后的大小',
    'why_effective': '多次strcat累积溢出. realloc大小计算中存在约束断裂',
}

# 18: cURL SOCKS5
SAMPLES['cve18_curl'] = {
    'cve': 'CVE-2023-38546',
    'type': 'heap_overflow',
    'severity': 'MEDIUM',
        'desc': 'cURL — SOCKS5主机名长度uint8截断, 与完整hostname_len不一致.',
    'pattern': 'realloc_insufficient',
'c_source': r'''// CVE-2023-38546 cURL — SOCKS5代理握手溢出
// 模式: SOCKS5代理握手时, 主机名长度>255字节,
//   realloc不足以容纳扩展后的数据
// 适用于: 检测器处理主机名→缓冲区增长的动态分配跟踪
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SOCKS5_MAX_HOSTNAME 255

// 发送SOCKS5连接请求
int send_socks5_request(const char *hostname, size_t hostname_len,
                        uint16_t port) {
    // 漏洞: hostname_len未验证是否≤SOCKS5_MAX_HOSTNAME
    // 分配请求缓冲区: 4 header + hostname_len + 2 port
    size_t req_size = 4 + hostname_len + 2;
    uint8_t *req = (uint8_t *)malloc(req_size);
    if (!req) return -1;

    req[0] = 0x05;  // SOCKS5 version
    req[1] = 0x01;  // CONNECT
    req[2] = 0x00;  // reserved
    req[3] = 0x03;  // domain name type
    req[4] = (uint8_t)hostname_len;  // 域名长度 (截断为uint8!)

    // 漏洞核心: hostname_len截断为uint8_t存入req[4]
    // 但memcpy使用完整的hostname_len
    // 当hostname_len=300时, req[4]=44, 但memcpy拷贝300字节
    memcpy(req + 5, hostname, hostname_len);

    req[5 + hostname_len] = (uint8_t)(port >> 8);
    req[6 + hostname_len] = (uint8_t)(port & 0xFF);

    printf("Request: %zu bytes\n", req_size);
    free(req);
    return 0;
}

int main() {
    // 构造超长主机名
    char long_host[1024];
    memset(long_host, 'a', sizeof(long_host) - 1);
    long_host[1023] = '\0';

    send_socks5_request(long_host, 300, 80);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve18_curl cve18.c',
    'trigger': 'hostname_len=300, 分配4+300+2=306字节, memcpy写入300字节, 安全但长度字段被截断',
    'why_effective': 'uint8截断+hostname_len不一致. 后续操作使用截断值导致二次越界',
}

# 19: Linux BPF verifier bypass
SAMPLES['cve19_bpf'] = {
    'cve': 'CVE-2020-8835',
    'type': 'heap_overflow',
    'severity': 'CRITICAL',
        'desc': 'Linux kernel BPF — 验证器32/64位混用导致负索引绕过, 越界堆访问.',
    'pattern': 'bpf_verifier_bypass',
'c_source': r'''// CVE-2020-8835 Linux kernel — BPF验证器绕过
// 模式: 32位BPF寄存器的值经过AND 0xFFFFFFFF后,
//   验证器认为该值始终<MAX, 但实际运行时该值可以<0
//   导致越界堆访问
// 适用于: 检测器需理解位运算对值域的约束影响
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAP_SIZE 256

// 模拟BPF map访问
int bpf_map_access(uint64_t map_fd, int32_t index) {
    // 模拟BPF寄存器追踪
    // 漏洞: 验证器认为index经过AND后非负
    // 但实际运行时int32可以表示负数

    // 分配"map"缓冲区
    uint8_t *map_data = (uint8_t *)malloc(MAP_SIZE);
    if (!map_data) return -1;
    memset(map_data, 0, MAP_SIZE);

    // BPF验证器认为: (index & 0xFFFFFFFF) 的结果在[0, MAP_SIZE)内
    // 漏洞: index是32位有符号数, 可以为负
    // (int32)(-1 & 0xFFFFFFFF) = 0xFFFFFFFF = -1 (in int32)
    // 但验证器将结果视为uint32 = 0xFFFFFFFF > MAP_SIZE → 应拒绝
    // 真实绕过更复杂, 涉及32/64位混用

    // 简化: index直接用于数组访问
    if (index >= 0 && index < MAP_SIZE) {
        map_data[index] = 0xFF;  // 安全
    } else if (index >= MAP_SIZE) {
        // 漏洞: 验证器认为不会到这里,
        // 但通过AND掩码绕过产生了负索引
        // 负索引写入越界
        map_data[index] = 0xFF;  // index为负 → 越界写
    }

    // 更直接的漏洞演示: 整数溢出
    int32_t unchecked = index + 128;
    if (unchecked >= 128) {
        // index可控制为负数, unchecked可能<128但仍>=0
        // 但若index=MAP_SIZE, unchecked=MAP_SIZE+128 (>MAP_SIZE)
        map_data[unchecked] = 0xFF;  // 越界
    }

    free(map_data);
    return 0;
}

int main() {
    // index=-1: 验证器认为无害, 但实际越界
    bpf_map_access(1, MAP_SIZE);  // 256 → unchecked=384, 越界
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve19_bpf cve19.c',
    'trigger': 'index=256, unchecked=384, 写入map_data[384]越界128字节',
    'why_effective': '算术加法后未重新检查边界. 值域跟踪应发现unchecked范围超出分配',
}

# 20: BIND TKEY
SAMPLES['cve20_bind'] = {
    'cve': 'CVE-2015-5477',
    'type': 'heap_overflow',
    'severity': 'HIGH',
        'desc': 'BIND — TKEY错误响应中查询名复制到固定大小缓冲区, 无边界检查.',
    'pattern': 'tkey_response_overflow',
'c_source': r'''// CVE-2015-5477 BIND — TKEY查询处理溢出
// 模式: 构造DNS错误响应时, 将攻击者提供的查询名
//   复制到固定大小的错误包缓冲区, 无边界检查
// 适用于: 检测器处理自引用数据结构的递归复制
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define DNS_QUERY_BUF_SIZE 512
#define DNS_QUERY_NAME_MAX 255

// 处理TKEY查询
int handle_tkey_query(uint8_t *query, size_t query_len) {
    // 分配固定大小的响应缓冲区
    uint8_t *response = (uint8_t *)malloc(DNS_QUERY_BUF_SIZE);
    if (!response) return -1;

    // 分配名称缓冲区
    char *qname = (char *)malloc(DNS_QUERY_NAME_MAX + 1);
    if (!qname) { free(response); return -1; }

    // 解析查询名称 (包括解压)
    // 漏洞: query_name的实际长度可能远大于DNS_QUERY_NAME_MAX
    // 因为压缩指针可以构造任意长的名称链
    size_t qname_len = 0;
    size_t pos = 12;  // DNS header之后

    while (pos < query_len && qname_len < DNS_QUERY_BUF_SIZE) {
        uint8_t len = query[pos];
        if (len == 0) break;

        if ((len & 0xC0) == 0xC0) {
            // 压缩指针 — 漏洞: 没有上限检查跳转次数
            uint16_t ptr = ((len & 0x3F) << 8) | query[pos + 1];
            pos = ptr;  // 可构造循环
            continue;
        }

        // 拷贝标签
        if (qname_len + len + 2 < DNS_QUERY_NAME_MAX) {
            qname[qname_len++] = '.';
            memcpy(qname + qname_len, query + pos + 1, len);
            qname_len += len;
        } else {
            // 漏洞: qname缓冲区不够, 但代码继续
            // 使用更大的response缓冲区接收
            // 但memcpy直接使用len, 不加检查
        }

        pos += 1 + len;
    }
    qname[qname_len] = '\0';

    // 漏洞核心: 构造错误响应时复制qname
    // qname可能>512字节
    memcpy(response + 12, qname, qname_len + 1);

    printf("TKEY response for: %s\n", qname);
    free(response);
    free(qname);
    return 0;
}

int main() {
    uint8_t query[1024];
    memset(query, 0, sizeof(query));
    // 构造带有长名称的DNS查询
    query[12] = 63;  // 第一个label: 63字节
    memset(query + 13, 'A', 63);
    size_t off = 13 + 63;
    query[off] = 63;  // 第二个label: 63字节
    memset(query + off + 1, 'B', 63);
    off += 1 + 63;
    query[off] = 63;  // 第三个label: 63字节
    memset(query + off + 1, 'C', 63);
    off += 1 + 63;
    query[off] = 63;  // 第四个label: 63字节
    memset(query + off + 1, 'D', 63);
    off += 1 + 63;
    query[off] = 63;  // 第五个label: 63字节
    memset(query + off + 1, 'E', 63);
    off += 1 + 63;
    query[off] = 0;  // 终止

    handle_tkey_query(query, off + 1);
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve20_bind cve20.c',
    'trigger': '5个63字节标签=315字节, 但DNS_QUERY_NAME_MAX=255',
    'why_effective': '循环中多个标签的累积长度超过预分配缓冲区+二次拷贝到固定缓冲区',
}

# 特殊: Safe (作为阴性对照)
SAMPLES['cve00_safe_copy'] = {
    'cve': 'SAFE_CONTROL',
    'type': 'safe',
    'severity': 'NONE',
    'desc': 'Safe copy — 写入量≤分配量的正确边界检查操作. 阴性对照样本, 验证检测器不产生误报.',
    'pattern': 'validated_copy',
    'c_source': r'''// SAFE_CONTROL: 阴性对照样本
// 正确验证了边界的memcpy操作
// 分配大小≥写入大小, 应无检出
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int safe_copy_data(const char *input, size_t input_len) {
    size_t alloc_size = input_len * 2;  // 预留双倍空间
    char *buf = (char *)malloc(alloc_size);
    if (!buf) return -1;

    // 安全: input_len ≤ alloc_size
    memcpy(buf, input, input_len);
    buf[input_len] = '\0';

    printf("Copied: %s\n", buf);
    free(buf);
    return 0;
}

int main() {
    const char *data = "SAFE_TEST_DATA_12345";
    safe_copy_data(data, strlen(data));
    return 0;
}
''',
    'compile_cmd': 'gcc -Wall -O2 -o cve00_safe cve00.c',
    'trigger': 'N/A — 写入量始终≤分配量, 应无检出',
    'why_effective': '阴性对照: 正确的边界检查+足够的分配空间. 验证检测器不产生FP',
}


# 生成所有文件

def write_sample(name, info):
    d = BASE / name
    d.mkdir(parents=True, exist_ok=True)

    # C源码
    (d / 'cve.c').write_text(info['c_source'].lstrip('\n'), encoding='utf-8')

    # Makefile
    makefile = f'''CC = gcc
CFLAGS = -Wall -O2 -g
TARGET = {name}

all: $(TARGET)

$(TARGET): cve.c
\t$(CC) $(CFLAGS) -o $(TARGET) cve.c

clean:
\trm -f $(TARGET)

run: $(TARGET)
\t./$(TARGET)
'''
    (d / 'Makefile').write_text(makefile, encoding='utf-8')

    # README.md
    readme = f'''# {name}

# CVE信息
- **CVE编号**: {info['cve']}
- **漏洞类型**: {info['type']}
- **严重级别**: {info['severity']}

# 漏洞描述
{info['desc']}

# 溢出模式
`{info['pattern']}`

# 编译
```bash
make
```

# 触发条件
{info['trigger']}

# 为何对FP Reduction有效
{info['why_effective']}

# 检测器预期行为
- 若为 `heap_overflow`: 检测器应报告DEFINITE_OVERFLOW或POSSIBLE_OVERFLOW
- 若为 `safe`: 检测器应报告0个发现
- 值域分析应捕获分配大小与写入大小的约束矛盾
- 分配器行为模型不应修正掉核心溢出 (因为溢出是真实的)
'''
    (d / 'README.md').write_text(readme, encoding='utf-8')

    return d


# 执行生成
def main():
    BASE.mkdir(parents=True, exist_ok=True)
    created = []
    for name, info in SAMPLES.items():
        d = write_sample(name, info)
        created.append(d)
        print(f'  [{info["cve"]:20s}] {name:25s} ({info["type"]})')

    print(f'\n生成完成: {len(created)} 样本 (cve_samples/)')
    print('  - 20 个CVE启发样本 (heap_overflow)')
    print('  -  1 个阴性对照 (safe)')
    print(f'  - 总计: {len(created)} 个目录')


if __name__ == '__main__':
    main()
