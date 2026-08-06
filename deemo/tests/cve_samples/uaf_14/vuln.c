#include <stdio.h>
#include <stdlib.h>
typedef struct Obj{struct Obj*ref;int data;}Obj;
int main(){Obj*a=malloc(sizeof(Obj));Obj*b=malloc(sizeof(Obj));a->ref=b;b->ref=a;free(a);return 0;}
