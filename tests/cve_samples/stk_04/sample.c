#include <stdio.h>
#include <string.h>
void parse_log(char*line){char tok[128];char*pos=line;while(*pos&&*pos!=" ")pos++;int l=pos-line;memcpy(tok,line,l);tok[l]=0;printf("%s",tok);}
int main(int c,char**v){parse_log(v[1]?v[1]:"AAAAAAA");return 0;}