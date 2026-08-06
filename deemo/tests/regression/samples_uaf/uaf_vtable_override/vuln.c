#include <stdio.h>
#include <stdlib.h>
typedef void(*fn)(void);struct vt{fn f;};void cb(){}
int main(){struct vt *v=malloc(sizeof(*v));v->f=cb;free(v);v->f();return 0;}
