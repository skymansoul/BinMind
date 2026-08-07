#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2021_33624 Format String Vuln: bpf_trace_printk(fmt): BPF fmt injection

void ebpf_fmt_vuln(char *user_input) {
    // 危险: 用户输入直接作为格式字符串 (而非%s参数)
    printf(user_input);
}

void ebpf_fmt_vuln2(char *user_input) {
    fprintf(stderr, user_input);
}

void ebpf_fmt_safe() {
    printf("%s\n", "literal format string");
}

int main() {
    char payload[] = "%x %x %x %x %x %x %x %n";  // 攻击payload: 含%n写入
    printf("cve_2021_33624 fmt test\n");
    ebpf_fmt_vuln(payload);
    ebpf_fmt_vuln2(payload);
    ebpf_fmt_safe();
    return 0;
}
