#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct {
    unsigned int magic;
    unsigned char data[];
} Pkt;

int main(int argc, char **argv) {
    unsigned int len = 0x40;
    if (argc > 1) len = (unsigned int)atoi(argv[1]);
    Pkt *p = (Pkt *)malloc(sizeof(Pkt) + len);
    char *src = (char *)malloc(len);
    if (!p || !src) return 1;
    memset(src, 'e', len);
    memcpy(p->data, src, len);
    printf("%u\n", p->magic);
    free(p); free(src);
    return 0;
}
