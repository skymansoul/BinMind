/* CVE-2010-0230 — Linux kernel stack buffer overflow via SCSI ioctl / CWE-121 */
#include <string.h>
void scsi_ioctl(char *user_data, int len) {
    char buf[64];
    if (len > 0) memcpy(buf, user_data, len); /* BUG: no upper bound */
}
int main(void) { char d[128]; memset(d,'A',128); scsi_ioctl(d,128); return 0; }
