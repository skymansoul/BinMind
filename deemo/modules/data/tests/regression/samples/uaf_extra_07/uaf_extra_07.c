#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct { char *data; int size; int freed; } Buffer;
Buffer *make_buf(int n) { Buffer *b=malloc(sizeof(Buffer)); b->data=malloc(n); b->size=n; b->freed=0; return b; }
void del_buf(Buffer *b) { if(b){free(b->data); b->freed=1; free(b);} }
int use_freed(Buffer *b) { return b->data[0]; }
int main() { Buffer *p=make_buf(64); del_buf(p); return use_freed(p); }
