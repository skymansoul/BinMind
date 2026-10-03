/* GENERIC-fmt-syslog CWE-134: syslog格式串来自输入 */
#include <syslog.h>
void lr(char*d){syslog(LOG_INFO,d);}
int main(int c,char**v){lr(c>1?v[1]:"test");return 0;}
