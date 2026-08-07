#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct Node {
    int a;
    int b;
    int c;
};

static void safe_struct(void)
{
    struct Node *n = (struct Node *)malloc(sizeof(struct Node));
    if (!n)
        return;
    n->a = 1;
    n->b = 2;
    n->c = 3;
    free(n);
}

int main(void)
{
    safe_struct();
    return 0;
}
