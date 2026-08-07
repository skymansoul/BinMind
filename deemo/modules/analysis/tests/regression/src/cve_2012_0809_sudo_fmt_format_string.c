#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// cve_2012_0809 Format String Vuln: printf(user_input): argv[0] as format string

void sudo_fmt_vuln(char *user_input) {
    // 危险: 用户输入直接作为格式字符串 (而非%s参数)
    printf(user_input);
}

void sudo_fmt_vuln2(char *user_input) {
    fprintf(stderr, user_input);
}

void sudo_fmt_safe() {
    printf("%s\n", "literal format string");
}

int main() {
    char payload[] = "%x %x %x %x %x %x %x %n";  // 攻击payload: 含%n写入
    printf("cve_2012_0809 fmt test\n");
    sudo_fmt_vuln(payload);
    sudo_fmt_vuln2(payload);
    sudo_fmt_safe();
    return 0;
}
