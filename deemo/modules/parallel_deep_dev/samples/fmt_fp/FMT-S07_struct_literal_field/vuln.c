#include <stdio.h>

struct Logger {
    const char *fmt;
};

static void safe_struct_fmt(struct Logger *lg, const char *user)
{
    printf(lg->fmt, user);
}

int main(int argc, char **argv)
{
    if (argc < 2)
        return 1;
    struct Logger lg = {"user=%s"};
    safe_struct_fmt(&lg, argv[1]);
    return 0;
}
