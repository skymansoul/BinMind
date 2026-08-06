#include <stdio.h>
#include <string.h>
void json_log(char*key){fprintf(stdout,key);}
int main(int c,char**v){if(c>1)json_log(v[1]);return 0;}