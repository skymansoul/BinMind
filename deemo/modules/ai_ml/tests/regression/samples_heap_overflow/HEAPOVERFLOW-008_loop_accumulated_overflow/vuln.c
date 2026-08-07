#include <string.h>
#include <stdlib.h>
/* 循环内累计写超出分配 */
void loop_accumulate(const char *chunks[4], int n_chunks, int chunk_size) {
    char *buf = malloc(64);
    if (!buf) return;
    int offset = 0;
    for (int i = 0; i < n_chunks; i++) {
        memcpy(buf + offset, chunks[i], chunk_size);
        offset += chunk_size; /* VULN: offset超出64 */
    }
    free(buf);
}
int main() {
    const char *chunks[4];
    char c1[32], c2[32], c3[32], c4[32];
    for(int i=0;i<32;i++){c1[i]='a';c2[i]='b';c3[i]='c';c4[i]='d';}
    chunks[0]=c1;chunks[1]=c2;chunks[2]=c3;chunks[3]=c4;
    loop_accumulate(chunks, 4, 32); /* 32*4=128 > 64 */
    return 0;
}
