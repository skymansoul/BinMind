/* UAF-16: 嵌套结构释放后访问 */
#include <stdlib.h>
#include <string.h>
typedef struct { char *buf; int len; } Chunk;
int main() { Chunk *c=malloc(sizeof(Chunk)); c->buf=malloc(128); free(c->buf); memset(c->buf,0,128); free(c); return 0; }
