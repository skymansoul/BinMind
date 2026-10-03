#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void(*cleanup_fn)(void*);
struct dw{void*d;cleanup_fn f;struct dw*n;};
struct dw*q=NULL;
void queue(void*d,cleanup_fn f){struct dw*w=malloc(sizeof(*w));w->d=d;w->f=f;w->n=q;q=w;}
void run(void){while(q){struct dw*w=q;q=w->n;if(w->f)w->f(w->d);free(w);}}
void work(int id){char b[32];snprintf(b,32,"r%d",id);queue(b,(cleanup_fn)puts);}
int main(void){work(42);run();return 0;}
