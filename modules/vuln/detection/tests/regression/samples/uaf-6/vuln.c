/* UAF-6: realloc后使用旧指针 */
#include <stdlib.h>
#include <string.h>
int main() { char *p=malloc(64); char *q=realloc(p,128); strcpy(p,"old"); free(q); return 0; }
