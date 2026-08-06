/* CVE-2015-0235 variant — format string in ghost resolver
   Type: format_string   gcc -O0 ghost_fmt.c -o ghost_fmt
   glibc gethostbyname could pass crafted hostname to syslog. */
#include <stdio.h>
#include <string.h>
void log_dns_error(const char *hostname) {
    char buf[512];
    sprintf(buf, hostname);  /* BUG: hostname as format string */
    printf("DNS error: %s\n", buf);
}
int main(int argc, char **argv) {
    log_dns_error(argc>1 ? argv[1] : "%%n%%n%%n%%n");
    return 0;
}
