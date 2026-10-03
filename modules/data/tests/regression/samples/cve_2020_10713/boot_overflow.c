/* CVE-2020-10713 — GRUB2 BootHole buffer overflow
   Type: buffer_overflow (stack)
   gcc -O0 boot_overflow.c -o boot_overflow

   Original: GRUB2 bootloader had a buffer overflow in the
   grub_cmd_initrd function when parsing crafted initrd images.
   This simplified version shows the overflow pattern in config parsing. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_MAX 256

typedef struct {
    char kernel_path[128];
    char initrd_path[128];
    char cmdline[CONFIG_MAX];
} BootConfig;

/* VULNERABLE: config value can overflow fixed-size buffer */
int parse_grub_config(const char *line, BootConfig *cfg) {
    const char *key = line;
    const char *val = strchr(line, '=');
    if (!val) return -1;
    val++; /* skip '=' */

    if (strncmp(key, "initrd", 6) == 0) {
        /* BUG: strcpy without bounds check on val */
        strcpy(cfg->initrd_path, val);
    } else if (strncmp(key, "linux", 5) == 0) {
        strcpy(cfg->kernel_path, val);
    } else if (strncmp(key, "cmdline", 7) == 0) {
        /* BUG: val can be up to 65535 in crafted grub.cfg files */
        strcpy(cfg->cmdline, val);
    }
    return 0;
}

int main() {
    BootConfig cfg = {0};
    /* Crafted grub.cfg with oversized initrd path */
    char line[512];
    memset(line, 'A', 510); line[510] = '\0';
    memcpy(line, "initrd=", 7);
    parse_grub_config(line, &cfg);
    return 0;
}
