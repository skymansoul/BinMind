/* UAF-02: Alias-based use-after-free — free via alias, use via original (TP) */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void process(void) {
    char *buf = (char *)malloc(64);
    if (!buf) return;
    strcpy(buf, "data");
    char *alias = buf;  /* alias points to same heap memory */
    free(alias);        /* free via alias */
    /* BUG: buf still points to freed memory — use via original pointer */
    printf("%s\n", buf);
}

int main(void) {
    process();
    return 0;
}
