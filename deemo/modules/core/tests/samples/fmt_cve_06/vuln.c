#include <syslog.h>
void vuln(char *m) { syslog(LOG_ERR, m); }
int main(){vuln("%n");}