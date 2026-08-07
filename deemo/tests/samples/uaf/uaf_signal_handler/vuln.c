#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
/* UAF-12: 信号处理器中的UAF — 信号触发时访问已释放的全局指针 */
static char *g_data = NULL;
void sig_handler(int sig) {
    if (g_data) printf("signal: %s\n", g_data);  /* 可能在free后触发 */
}
int main(void) {
    g_data = (char *)malloc(128);
    if (!g_data) return 1;
    strcpy(g_data, "signal_data");
    signal(SIGUSR1, sig_handler);
    free(g_data);  /* 释放后若信号到达, handler访问悬挂指针 */
    printf("freed g_data, send SIGUSR1 to trigger\n");
    return 0;
}
