#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* UAF via race: elem freed while still referenced */
typedef struct{int val;char*n;}Elem;
Elem*pool[4];
void add(int i){pool[i]=malloc(sizeof(Elem));pool[i]->val=i;}
void del(int i){if(pool[i]){free(pool[i]);}}
void use_pooled(int i){if(pool[i])printf("v=%d",pool[i]->val);/* UAF if freed */}
int main(){add(0);del(0);use_pooled(0);return 0;}