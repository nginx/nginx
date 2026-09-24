#include <errno.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/bpf.h>
/*
 * the bpf_helpers.h is not included into linux-headers, only available
 * with kernel sources in "tools/lib/bpf/bpf_helpers.h" or in libbpf.
 */
#include <bpf/bpf_helpers.h>


#if !defined(SEC)
#define SEC(NAME)  __attribute__((section(NAME), used))
#endif


#if defined(LICENSE_GPL)

/*
 * To see debug:
 *
 *  echo 1 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 *  cat /sys/kernel/debug/tracing/trace_pipe
 *  echo 0 > /sys/kernel/debug/tracing/events/bpf_trace/enable
 */

#define debugmsg(fmt, ...)                                                    \
do {                                                                          \
    char __buf[] = fmt;                                                       \
    bpf_trace_printk(__buf, sizeof(__buf), ##__VA_ARGS__);                    \
} while (0)

#else

#define debugmsg(fmt, ...)

#endif

char _license[] SEC("license") = LICENSE;

/*****************************************************************************/

#define NGX_QUIC_PKT_LONG        0x80  /* header form */
#define NGX_QUIC_SERVER_CID_LEN  20


#define ngx_quic_parse_uint64(p)                                              \
    (((__u64)(p)[0] << 56) |                                                  \
     ((__u64)(p)[1] << 48) |                                                  \
     ((__u64)(p)[2] << 40) |                                                  \
     ((__u64)(p)[3] << 32) |                                                  \
     ((__u64)(p)[4] << 24) |                                                  \
     ((__u64)(p)[5] << 16) |                                                  \
     ((__u64)(p)[6] << 8)  |                                                  \
     ((__u64)(p)[7]))

/*
 * actual map object is created by the "bpf" system call,
 * all pointers to this variable are replaced by the bpf loader
 */
extern int ngx_quic_sockmap;


SEC(PROGNAME)
int ngx_quic_select_socket_by_dcid(struct sk_reuseport_md *ctx)
{
    int             rc;
    long            err;
    __u64           key;
    size_t          len, offset;
    unsigned char  *start, *end, *data, dcid[8], byte;

    start = ctx->data;
    end = (unsigned char *) ctx->data_end;

    offset = sizeof(struct udphdr) + 1;

    if (start + offset > end) {
        if (offset > ctx->len) {
            goto failed;
        }

        err = bpf_skb_load_bytes(ctx, offset - 1, &byte, 1);
        if (err != 0) {
            goto failed;
        }

        data = &byte;

    } else {
        data = start + offset - 1;
    }

    if (data[0] & NGX_QUIC_PKT_LONG) {

        offset += 5;

        if (start + offset > end) {
            if (offset > ctx->len) {
                goto failed;
            }

            err = bpf_skb_load_bytes(ctx, offset - 1, &byte, 1);
            if (err != 0) {
                goto failed;
            }

            len = byte;

        } else {
            len = start[offset - 1];
        }

        if (len < 8) {
            /* it's useless to search for key in such short DCID */
            return SK_PASS;
        }

    } else {
        len = NGX_QUIC_SERVER_CID_LEN;
    }

    if (start + offset + 8 > end) {
        if (offset + 8 > ctx->len) {
            goto failed;
        }

        err = bpf_skb_load_bytes(ctx, offset, dcid, 8);
        if (err != 0) {
            goto failed;
        }

    } else {
        __builtin_memcpy(dcid, start + offset, 8);
    }

    key = ngx_quic_parse_uint64(dcid);

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_sockmap, &key, 0);

    switch (rc) {
    case 0:
        debugmsg("nginx quic socket selected by key 0x%llx", key);
        return SK_PASS;

    /* kernel returns positive error numbers, errno.h defines positive */
    case -ENOENT:
        debugmsg("nginx quic default route for key 0x%llx", key);
        /* let the default reuseport logic decide which socket to choose */
        return SK_PASS;

    default:
        debugmsg("nginx quic bpf_sk_select_reuseport err: %d key 0x%llx",
                 rc, key);
        goto failed;
    }

failed:
    /*
     * SK_DROP will generate ICMP, but we may want to process "invalid" packet
     * in userspace quic to investigate further and finally react properly
     * (maybe ignore, maybe send something in response or close connection)
     */
    return SK_PASS;
}
