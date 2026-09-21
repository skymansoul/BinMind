"""
"""
from __future__ import annotations
from typing import List, Tuple

MUTEX_SAMPLES: List[Tuple[str, str, str]] = [
    ('mutex_01', """char *p = malloc(64);
if (error) {
    free(p);
}
if (!error) {
    *p = 1;
}
""", 'SAFE'),
    ('mutex_02', """char *p = malloc(64);
if (error) {
    free(p);
} else {
    *p = 1;
}
""", 'SAFE'),
    ('mutex_03', """char *p = malloc(64);
if (mode == 1) {
    free(p);
}
if (mode != 1) {
    *p = 1;
}
""", 'SAFE'),
    ('mutex_04', """char *p = malloc(64);
if (flag) {
    free(p);
}
if (!flag) {
    p[0] = 42;
}
""", 'SAFE'),
    ('mutex_05', """char *p = malloc(64);
int saved = active;
if (active) {
    free(p);
}
active = saved;
if (!active) {
    *p = 1;
}
""", 'SAFE'),
    ('mutex_06', """char *p = malloc(64);
if (status) {
    free(p);
    return;
}
if (!status) {
    *p = 1;
}
""", 'SAFE'),
    ('mutex_07', """char *p = malloc(64);
if (err_code) {
    free(p);
}
if (!err_code) {
    p->field = 0;
}
""", 'SAFE'),
    ('mutex_08', """char *p = malloc(64);
if (enabled) {
    free(p);
}
if (!enabled) {
    memcpy(p, src, 32);
}
""", 'SAFE'),
]

EARLY_SAMPLES: List[Tuple[str, str, str]] = [
    ('early_01', """char *p = malloc(64);
if (error) {
    free(p);
    return;
}
*p = 1;
""", 'SAFE'),
    ('early_02', """char *p = malloc(64);
if (error) {
    free(p);
    return -1;
}
p[0] = 42;
""", 'SAFE'),
    ('early_03', """char *p = malloc(64);
if (fatal) {
    free(p);
    exit(1);
}
*p = 1;
""", 'SAFE'),
    ('early_04', """char *p = malloc(64);
if (bad) {
    free(p);
    return;
}
if (good) {
    *p = 1;
}
""", 'SAFE'),
]

REASSIGN_SAMPLES: List[Tuple[str, str, str]] = [
    ('reassign_01', """char *p = malloc(64);
if (error) {
    free(p);
}
p = malloc(128);
*p = 1;
""", 'SAFE'),
]

CONFIRMED_SAMPLES: List[Tuple[str, str, str]] = [
    ('conf_01', """char *p = malloc(64);
if (cond) {
    free(p);
    *p = 1;
}
""", 'CONFIRMED'),
    ('conf_02', """char *p = malloc(64);
if (error) {
    free(p);
}
*p = 1;
""", 'CONFIRMED'),
    ('conf_03', """char *p = malloc(64);
free(p);
*p = 1;
""", 'CONFIRMED'),
    ('conf_04', """char *p = malloc(64);
if (a) {
    free(p);
}
if (b) {
    *p = 1;
}
""", 'CONFIRMED'),
    ('conf_05', """char *p = malloc(64);
if (error) {
    free(p);
}
if (error) {
    *p = 1;
}
""", 'CONFIRMED'),
    ('conf_06', """char *p = malloc(64);
char *q = p;
free(p);
*q = 42;
""", 'CONFIRMED'),
    ('conf_07', """char *p = malloc(64);
if (cond) {
    free(p);
    return;
}
free(p);
*p = 1;
""", 'CONFIRMED'),
]

NULLIFY_SAMPLES: List[Tuple[str, str, str]] = [
    ('nullify_01', """char *p = malloc(64);
if (error) {
    free(p);
    p = NULL;
}
*p = 1;
""", 'SAFE'),
]

ALL_SAMPLES = (MUTEX_SAMPLES + EARLY_SAMPLES + REASSIGN_SAMPLES
               + CONFIRMED_SAMPLES + NULLIFY_SAMPLES)

__all__ = [
    'MUTEX_SAMPLES', 'EARLY_SAMPLES', 'REASSIGN_SAMPLES',
    'CONFIRMED_SAMPLES', 'NULLIFY_SAMPLES', 'ALL_SAMPLES',
]
