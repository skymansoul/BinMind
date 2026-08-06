/* GENERIC-race-chdir CWE-362: chdir后操作相对路径——目录可能被替换 */
#include <unistd.h>
#include <fcntl.h>
void chdir_race(char*dir,char*file){chdir(dir);int fd=open(file,O_RDONLY);close(fd);}
int main(int c,char**v){chdir_race(c>1?v[1]:"/tmp",c>2?v[2]:"x");return 0;}
