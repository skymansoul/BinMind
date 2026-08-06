/* CVE-2024-6387 — regreSSHion (OpenSSH signal handler race / UAF)
 * 漏洞: SIGALRM handler中调用非异步安全函数 (free/syslog) → race→UAF
 * 编译: gcc -o regresshion regresshion.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
void *global_ptr = NULL;
void sigalrm_handler(int sig) {
    /* BUG: 信号处理器中调用 free — 非异步安全! */
    if (global_ptr) { free(global_ptr); global_ptr = NULL; }
    write(1, "timeout\n", 8);
}
int main() {
    signal(SIGALRM, sigalrm_handler);
    global_ptr = malloc(128);
    alarm(1);
    /* race: 若SIGALRM在free(global_ptr)之后、use之前到达 */
    for (int i = 0; i < 1000000; i++) {
        if (global_ptr) { ((char*)global_ptr)[0] = 'X'; } /* POTENTIAL UAF */
    }
    return 0;
}
