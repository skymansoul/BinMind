/* GENERIC-race-toctou-open CWE-367: TOCTOU: access检查后open——检查和使用之间可被替换 */
#include <unistd.h>
#include <fcntl.h>
void toctou(char*p){if(access(p,R_OK)==0){int fd=open(p,O_RDONLY);read(fd,0,0);close(fd);}}
int main(int c,char**v){toctou(c>1?v[1]:"/tmp/x");return 0;}
