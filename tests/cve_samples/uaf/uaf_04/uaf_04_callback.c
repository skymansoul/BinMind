/* UAF-04: Callback-based use-after-free (TP) */
#include <stdlib.h>
#include <stdio.h>

typedef void (*log_cb)(const char *);

static log_cb g_logger = NULL;

void set_logger(log_cb cb) { g_logger = cb; }

void do_work(char *data) {
    free(data);
    /* BUG: freed data passed to callback */
    if (g_logger) g_logger(data);
}

void my_log(const char *s) { printf("LOG: %s\n", s); }

int main(void) {
    set_logger(my_log);
    do_work((char *)malloc(128));
    return 0;
}
