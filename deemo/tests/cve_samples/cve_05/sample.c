#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct{int id;char*d;}Obj;
Obj*g=NULL;
Obj*make(int i,const char*s){Obj*o=malloc(sizeof(Obj));o->id=i;o->d=strdup(s);return o;}
void kill(Obj*o){if(o){free(o->d);free(o);}}
void use(Obj*o){if(o&&o->d)printf("Obj[%d]:%s\n",o->id,o->d);}
int main(void){
  g=make(1,"sensitive");
  kill(g); /* g not set to NULL */
  use(g);  /* UAF */
  return 0;
}
