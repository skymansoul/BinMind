#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct io_buf { char *data; int len; int refs; };
void submit(struct io_buf *b) { b->refs++; }
void complete(struct io_buf *b) { b->refs--; if(b->refs<=0){free(b->data);free(b);} }
int main() { struct io_buf *b=malloc(sizeof(*b));
b->data=strdup("x");b->refs=1;complete(b);submit(b);return 0;}
