/* GENERIC-race-getenv CWE-362: getenv后使用——环境变量可能被修改 */
#include <stdlib.h>
#include <string.h>
void env_race(){char*p=getenv("PATH");if(p){char*b=malloc(strlen(p)+1);strcpy(b,p);free(b);}}
int main(){env_race();return 0;}
