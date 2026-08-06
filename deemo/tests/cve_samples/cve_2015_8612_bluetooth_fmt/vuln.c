/* CVE-2015-8612 — BlueZ bluetoothd 格式化字符串 / CWE-134 */
#include <stdio.h>
void bt_log(const char *dev) { fprintf(stderr, dev); } /* BUG: device name as fmt */
int main(int argc, char **argv) {
    if (argc>1) bt_log(argv[1]); return 0;
}
