/* CVE-2001-0134 — wu-ftpd 2.6.1 site exec format string vulnerability
   Type: format_string
   gcc -O0 wuftpd_fmt.c -o wuftpd_fmt

   Classic format string attack: user-supplied input passed
   directly as format string to printf-family function. */

#include <stdio.h>
#include <string.h>

void vulnerable_site_exec(const char *user_command) {
    char buf[1024];
    /* BUG: user_command passed directly as format string */
    snprintf(buf, sizeof(buf), user_command);
    printf("Executing: ");
    printf(buf);  /* format string vulnerability */
    printf("\n");
}

int main(int argc, char **argv) {
    const char *input = (argc > 1) ? argv[1] : "%x%x%x%x%n";
    vulnerable_site_exec(input);
    return 0;
}
