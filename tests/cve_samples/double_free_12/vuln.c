/* double_free_12 — 缓存淘汰时双重释放(LRU简化) */
#include <stdio.h>
#include <stdlib.h>
typedef struct Entry{char*key;char*val;struct Entry*next;}Entry;
int main(){Entry*e=malloc(sizeof(Entry));e->key=malloc(16);e->val=e->key;free(e->key);free(e->val);free(e);return 0;}
