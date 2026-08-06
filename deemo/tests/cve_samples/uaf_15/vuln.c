#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef struct{char*name;int id;}User;
User*make_user(char*n){User*u=malloc(sizeof(User));u->name=strdup(n);free(u->name);return u;}
int main(){User*u=make_user("alice");free(u);return 0;}
