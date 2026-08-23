/* strcat appends to already-full buffer */
#include <stdlib.h>
#include <string.h>

void edge_strcat_overflow(char *input) {
    char *buf = (char *)malloc(128);
    if (buf) {
        strcpy(buf, "fixed_prefix_that_is_very_long_");  /* likely >100 chars */
        strcat(buf, input);  /* unbounded append �� OVERFLOW risk */
        free(buf);
    }
}

int main(void) {
    static char in[] =
        "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP"
        "PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP";
    edge_strcat_overflow(in);  /* prefix + input overruns 128-byte buf */
    return 0;
}
