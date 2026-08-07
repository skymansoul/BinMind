"""

包含 MUTEX (14) + EARLY_RETURN (8) = 22样本.
"""
from typing import List, Tuple


MUTEX_SAMPLES: List[Tuple[str, str, str, str]] = [
    ('cve_mutex_01', """char *p = malloc(64);
if (error) {
    free(p);
}
if (!error) {
    *p = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_02', """char *p = malloc(64);
if (error) {
    free(p);
} else {
    *p = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_03', """char *p = malloc(64);
if (mode == 1) {
    free(p);
}
if (mode != 1) {
    *p = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_04', """char *p = malloc(64);
if (flag) {
    free(p);
}
if (!flag) {
    p[0] = 42;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_05', """char *p = malloc(64);
int saved = active;
if (active) {
    free(p);
}
active = saved;
if (!active) {
    *p = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_06', """char *p = malloc(64);
if (status) {
    free(p);
    return;
}
if (!status) {
    *p = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_07', """char *p = malloc(64);
if (err_code) {
    free(p);
}
if (!err_code) {
    p->field = 0;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_08', """char *p = malloc(64);
if (enabled) {
    free(p);
}
if (!enabled) {
    memcpy(p, src, 32);
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_09', """char *buf = malloc(128);
if (state == 2) {
    free(buf);
}
if (state != 2) {
    buf[0] = 'x';
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_10', """char *ptr = malloc(256);
if (debug) {
    free(ptr);
}
if (!debug) {
    ptr->next = NULL;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_11', """char *data = malloc(64);
if (type == 3) {
    free(data);
}
if (type != 3) {
    *data = 0;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_12', """char *cache = malloc(128);
if (expired) {
    free(cache);
}
if (!expired) {
    cache->valid = 1;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_13', """char *entry = malloc(64);
if (remove) {
    free(entry);
}
if (!remove) {
    entry->key = 0;
}
""", 'SAFE', 'MUTEX'),
    ('cve_mutex_14', """char *node = malloc(128);
if (delete) {
    free(node);
}
if (!delete) {
    node->val = 42;
}
""", 'SAFE', 'MUTEX'),
]


EARLY_SAMPLES: List[Tuple[str, str, str, str]] = [
    ('cve_early_01', """char *p = malloc(64);
if (error) {
    free(p);
    return;
}
*p = 1;
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_02', """char *p = malloc(64);
if (error) {
    free(p);
    return -1;
}
p[0] = 42;
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_03', """char *p = malloc(64);
if (fatal) {
    free(p);
    exit(1);
}
*p = 1;
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_04', """char *p = malloc(64);
if (bad) {
    free(p);
    return;
}
if (good) {
    *p = 1;
}
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_05', """char *buf = malloc(256);
if (err) {
    free(buf);
    return NULL;
}
buf->len = 0;
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_06', """char *data = malloc(128);
if (fail) {
    free(data);
    return;
}
data[0] = 'A';
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_07', """char *ctx = malloc(64);
if (invalid) {
    free(ctx);
    abort();
}
ctx->state = 0;
""", 'SAFE', 'EARLY_RETURN'),
    ('cve_early_08', """char *obj = malloc(256);
if (error) {
    free(obj);
    return -1;
}
obj->ref = 1;
""", 'SAFE', 'EARLY_RETURN'),
]


__all__ = ['MUTEX_SAMPLES', 'EARLY_SAMPLES']
