"""UAF 样本定义 (CVE 9-16) — 生成样本集的源数据。"""

import textwrap
SAMPLE_DEFS_B = [
    # 9. CVE-2021-27365: 释放后在循环中使用
    {
        'name': 'CVE-2021-27365_iscsi',
        'cve': 'CVE-2021-27365',
        'category': 'uaf',
        'func': 'iscsi_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_loop_use',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux iSCSI 会话管理 use-after-free。复现: free(se)\n'
                  '后循环读 se->cmd[i]。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct iscsi_sess {
                int cmd[8];
            };

            static void iscsi_trigger(void)
            {
                struct iscsi_sess *se =
                    (struct iscsi_sess *)malloc(sizeof(struct iscsi_sess));
                int i, t = 0;
                if (!se)
                    return;
                free(se);
                for (i = 0; i < 8; i++)
                    t += se->cmd[i];
                printf("%d\\n", t);
            }

            int main(void)
            {
                iscsi_trigger();
                return 0;
            }
        '''),
    },
    # 10. CVE-2022-0995: 字段指针释放后使用
    {
        'name': 'CVE-2022-0995_watch_queue',
        'cve': 'CVE-2022-0995',
        'category': 'uaf',
        'func': 'watch_trigger',
        'truth': {'is_vuln': True, 'pattern': 'field_free_then_use',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux watch_queue 通知对象 use-after-free: 内部缓冲\n'
                  '释放后仍被写入。复现: free(w->buf) 后写 w->buf[i]。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct watch {
                char *buf;
                int len;
            };

            static void watch_trigger(int i)
            {
                struct watch *w = (struct watch *)malloc(sizeof(struct watch));
                if (!w)
                    return;
                w->buf = (char *)malloc(64);
                free(w->buf);
                w->buf[i] = 1;
                free(w);
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                watch_trigger(atoi(argv[1]));
                return 0;
            }
        '''),
    },
    # 11. CVE-2023-0461: 释放后解引用
    {
        'name': 'CVE-2023-0461_kernel',
        'cve': 'CVE-2023-0461',
        'category': 'uaf',
        'func': 'kobj_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_deref',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux 内核对象 release 竞态导致 use-after-free。\n'
                  '复现: free(ko) 后读 ko->name。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct kobj {
                char *name;
            };

            static void kobj_trigger(void)
            {
                struct kobj *ko = (struct kobj *)malloc(sizeof(struct kobj));
                if (!ko)
                    return;
                ko->name = "dev";
                free(ko);
                printf("%s\\n", ko->name);
            }

            int main(void)
            {
                kobj_trigger();
                return 0;
            }
        '''),
    },
    # 12. CVE-2024-22033: 释放后读字段
    {
        'name': 'CVE-2024-22033_v4l2',
        'cve': 'CVE-2024-22033',
        'category': 'uaf',
        'func': 'v4l2_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_read',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux v4l2 缓冲管理 use-after-free。复现: free(b)\n'
                  '后读 b->index。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct v4l2_buf {
                int index;
            };

            static void v4l2_trigger(void)
            {
                struct v4l2_buf *b =
                    (struct v4l2_buf *)malloc(sizeof(struct v4l2_buf));
                if (!b)
                    return;
                b->index = 0;
                free(b);
                printf("%d\\n", b->index);
            }

            int main(void)
            {
                v4l2_trigger();
                return 0;
            }
        '''),
    },
    # 13. CVE-2019-15291: 字段释放后写
    {
        'name': 'CVE-2019-15291_brcmfmac',
        'cve': 'CVE-2019-15291',
        'category': 'uaf',
        'func': 'brcm_trigger',
        'truth': {'is_vuln': True, 'pattern': 'field_free_then_write',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'brcmfmac 驱动 use-after-free: 内部指针释放后仍被\n'
                  '写入。复现: free(d->data) 后写 d->data[0]。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct brcm_dev {
                char *data;
            };

            static void brcm_trigger(void)
            {
                struct brcm_dev *d =
                    (struct brcm_dev *)malloc(sizeof(struct brcm_dev));
                if (!d)
                    return;
                d->data = (char *)malloc(16);
                free(d->data);
                d->data[0] = 0xff;
                free(d);
            }

            int main(void)
            {
                brcm_trigger();
                return 0;
            }
        '''),
    },
    # 14. CVE-2020-0022: 释放后传参
    {
        'name': 'CVE-2020-0022_btusb',
        'cve': 'CVE-2020-0022',
        'category': 'uaf',
        'func': 'bt_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_callarg',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Android btusb 蓝牙驱动 use-after-free: 释放后传入\n'
                  '接收处理。复现: free(h) 后 consume(h)。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            static void consume(char *h)
            {
                h[3] = 1;
            }

            static void bt_trigger(void)
            {
                char *h = (char *)malloc(8);
                if (!h)
                    return;
                free(h);
                consume(h);
            }

            int main(void)
            {
                bt_trigger();
                return 0;
            }
        '''),
    },
    # 15. CVE-2022-25636: 条件释放后使用
    {
        'name': 'CVE-2022-25636_nf_tables',
        'cve': 'CVE-2022-25636',
        'category': 'uaf',
        'func': 'nft_use_trigger',
        'truth': {'is_vuln': True, 'pattern': 'cond_free_then_use',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux nf_tables 对象引用计数缺陷: 条件释放后仍被\n'
                  '使用。复现: if 条件释放 e 后无条件写 e->key。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct nft_elem {
                int key;
            };

            static void nft_use_trigger(int flag)
            {
                struct nft_elem *e =
                    (struct nft_elem *)malloc(sizeof(struct nft_elem));
                if (!e)
                    return;
                if (flag)
                    free(e);
                e->key = 5;
            }

            int main(int argc, char **argv)
            {
                if (argc < 2)
                    return 1;
                nft_use_trigger(atoi(argv[1]));
                return 0;
            }
        '''),
    },
    # 16. CVE-2021-32399: 释放后循环写
    {
        'name': 'CVE-2021-32399_blk',
        'cve': 'CVE-2021-32399',
        'category': 'uaf',
        'func': 'blk_trigger',
        'truth': {'is_vuln': True, 'pattern': 'free_then_loop_write',
                  'overflow_kind': 'uaf', 'cwe': 'CWE-416'},
        'readme': 'Linux block 层请求对象 use-after-free。复现: free(r)\n'
                  '后循环写 r->data[i]。',
        'source': textwrap.dedent('''\
            #include <stdio.h>
            #include <stdlib.h>

            struct blk_req {
                int data[4];
            };

            static void blk_trigger(void)
            {
                struct blk_req *r =
                    (struct blk_req *)malloc(sizeof(struct blk_req));
                int i;
                if (!r)
                    return;
                free(r);
                for (i = 0; i < 4; i++)
                    r->data[i] = i;
            }

            int main(void)
            {
                blk_trigger();
                return 0;
            }
        '''),
    },
]
