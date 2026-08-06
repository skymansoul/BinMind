#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF: stale pointer to freed pipe buffer */
typedef struct{char*data;int len;}PipeBuf;
PipeBuf*buf=NULL;
void alloc_buf(){buf=malloc(sizeof(PipeBuf));buf->data=strdup("secret");buf->len=6;}
void free_buf(){if(buf){free(buf->data);free(buf);}}
void splice_buf(){if(buf)printf("splice:%s",buf->data);/* UAF */}
int main(){alloc_buf();free_buf();splice_buf();return 0;}