#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct{char*p;char*n;}Route;
Route*rt=NULL;
void cleanup(Route*r){if(r){free(r->p);free(r->n);free(r);}}
void remove_rt(const char*k){
  if(rt&&strcmp(rt->p,k)==0){free(rt->p);free(rt->n);free(rt);}
  cleanup(rt); /* BUG: double free */
}
int main(void){
  rt=malloc(sizeof(Route));rt->p=strdup("10.0.0.0/8");rt->n=strdup("gw");
  remove_rt("10.0.0.0/8");
  return 0;
}
