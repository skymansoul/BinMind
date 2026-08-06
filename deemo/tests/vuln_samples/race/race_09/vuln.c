/* GENERIC-race-symlink CWE-363: symlink竞态——检查符号链接目标后使用 */
#include <unistd.h>
#include <fcntl.h>
void sym_race(char*p){if(access(p,R_OK)==0){int fd=open(p,O_RDONLY);close(fd);}}
int main(int c,char**v){sym_race(c>1?v[1]:"/tmp/x");return 0;}
