/* UAF-12: 结构体成员指针释放后访问 */
#include <stdlib.h>
#include <string.h>
typedef struct { char *name; int id; } Rec;
int main() { Rec *r=malloc(sizeof(Rec)); r->name=malloc(32); free(r->name); strcpy(r->name,"uaf"); free(r); return 0; }
