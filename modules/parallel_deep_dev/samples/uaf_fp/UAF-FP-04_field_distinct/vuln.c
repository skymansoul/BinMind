#include <stdio.h>
#include <stdlib.h>

struct item {
    char *buf;
    int len;
};

static void safe_field_distinct(void)
{
    struct item *b = (struct item *)malloc(sizeof(struct item));
    if (!b)
        return;
    b->buf = (char *)malloc(32);
    free(b->buf);
    b->len = 5;
    free(b);
}

int main(void)
{
    safe_field_distinct();
    return 0;
}
