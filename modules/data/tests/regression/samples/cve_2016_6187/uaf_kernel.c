/* CVE-2016-6187 — Linux kernel AppArmor UAF in /proc/pid/attr
   Type: use_after_free
   gcc -O0 uaf_kernel.c -o uaf_kernel

   Simplified: AppArmor profile replacement freed old profile
   but didn't clear the dangling reference. A subsequent read
   accessed the freed memory. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *name; int mode; } AppArmorProfile;

static AppArmorProfile *current_profile = NULL;

int replace_profile(const char *new_name) {
    AppArmorProfile *old = current_profile;
    current_profile = (AppArmorProfile *)malloc(sizeof(AppArmorProfile));
    current_profile->name = strdup(new_name);
    current_profile->mode = 0644;
    free(old);   /* BUG: doesn't set old=NULL; old->name may have been freed but is reused below */
    return 0;
}

int read_profile(int fd, char *buf, int len) {
    /* BUG: old pointer may be dangling if replace_profile was called */
    if (current_profile)
        snprintf(buf, len, "%s (mode=%o)", current_profile->name, current_profile->mode);
    return 0;
}

int main() {
    replace_profile("enforcing");
    replace_profile("complain");
    char buf[256];
    read_profile(0, buf, sizeof(buf));
    return 0;
}
