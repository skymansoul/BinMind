#include <stdio.h>
#include <stdarg.h>

static void vlog_trigger(const char *fmt, va_list ap)
{
    char buf[128];
    vsnprintf(buf, sizeof(buf), fmt, ap);
}

static void log_wrap(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog_trigger(fmt, ap);
    va_end(ap);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    log_wrap(argv[1]);
    return 0;
}
