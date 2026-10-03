/* CVE-2022-2639 — Linux kernel pipe UAF via splice / CWE-416 */
#include <stdlib.h>
#include <string.h>
typedef struct { char *buf; int len; } pipe_buf_t;
pipe_buf_t *g_pipe = NULL;
void pipe_release(void) { free(g_pipe->buf); free(g_pipe); /* g_pipe not NULL'd */ }
void pipe_write(char *data, int len) {
    if (!g_pipe) g_pipe = malloc(sizeof(pipe_buf_t));
    g_pipe->buf = malloc(len); memcpy(g_pipe->buf, data, len);
    pipe_release();
    memcpy(g_pipe->buf, data, len); /* UAF: g_pipe->buf already freed */
}
int main(void) { pipe_write("AAAA", 4); return 0; }
