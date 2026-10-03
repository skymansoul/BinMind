#include <stdio.h>
#include <string.h>
void parse_submodule_url(char*url){char buf[256];strcpy(buf,url);printf("%s",buf);}
int main(int c,char**v){parse_submodule_url(v[1]?v[1]:"git://");return 0;}