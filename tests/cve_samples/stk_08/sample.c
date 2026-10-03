#include <stdio.h>
#include <string.h>
void resolve_path(char*path){char resolved[512];strcpy(resolved,path);printf("%s",resolved);}
int main(int c,char**v){resolve_path(v[1]?v[1]:"/tmp");return 0;}