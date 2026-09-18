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


/*
 * The map objects are created by userspace and linked to these symbols.
 */
struct {} ngx_quic_listen0 SEC(".maps");
struct {} ngx_quic_listen1 SEC(".maps");
struct {} ngx_quic_connections SEC(".maps");
struct {} ngx_quic_worker_counts SEC(".maps");


SEC(PROGNAME)
int ngx_quic_reuseport_select(struct sk_reuseport_md *ctx)
{
    void           *listen_map;
    unsigned char  *start, *end, dcid[NGX_QUIC_SERVER_CID_LEN];
    unsigned char   byte;
    int             rc, master_index, flags, i;
    long            err;
    __u32           key, listener_idx, *worker_count;
    size_t          len, offset;

    start = ctx->data;
    end = ctx->data_end;

    offset = sizeof(struct udphdr) + 1; /* UDP header + QUIC flags */

    if (start + offset > end) {
        if (offset > ctx->len) {
            goto bad_dgram;
        }

        err = bpf_skb_load_bytes(ctx, offset - 1, &byte, 1);
        if (err != 0) {
            goto bad_dgram;
        }

        flags = byte;

    } else {
        flags = start[offset - 1];
    }

    if (flags & NGX_QUIC_PKT_LONG) {

        offset += 5; /* QUIC version + DCID len */
        if (start + offset > end) {
            if (offset > ctx->len) {
                goto bad_dgram;
            }

            err = bpf_skb_load_bytes(ctx, offset - 1, &byte, 1);
            if (err != 0) {
                goto bad_dgram;
            }

            len = byte;

        } else {
            len = start[offset - 1];
        }

        if (len != NGX_QUIC_SERVER_CID_LEN) {
            goto new_conn;
        }
    }

    if (start + offset + NGX_QUIC_SERVER_CID_LEN > end) {
        if (offset + NGX_QUIC_SERVER_CID_LEN > ctx->len) {
            goto bad_dgram;
        }

        err = bpf_skb_load_bytes(ctx, offset, dcid,
                                 NGX_QUIC_SERVER_CID_LEN);
        if (err != 0) {
            goto bad_dgram;
        }

    } else {
        memcpy(dcid, start + offset, NGX_QUIC_SERVER_CID_LEN);
    }

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_connections, dcid, 0);

    if (rc == 0) {
        debugmsg("nginx quic worker socket selected by dcid");
        return SK_PASS;
    }

    if (rc != -ENOENT) {
        debugmsg("nginx quic bpf_sk_select_reuseport() failed: %d", rc);
        return SK_DROP;
    }

new_conn:

    master_index = ctx->hash >> 31;

    for (i = 0; i < 2; i++) {

        key = master_index;

        worker_count = bpf_map_lookup_elem(&ngx_quic_worker_counts, &key);

        if (worker_count == NULL) {
            debugmsg("nginx quic master index %d worker count undefined",
                     master_index);
            return SK_DROP;
        }

        if (*worker_count) {
            listener_idx = ctx->hash % *worker_count;

            listen_map = master_index ? (void *) &ngx_quic_listen1
                                      : (void *) &ngx_quic_listen0;

            rc = bpf_sk_select_reuseport(ctx, listen_map, &listener_idx, 0);

            if (rc == 0) {
                debugmsg("nginx quic listener socket selected "
                         "master index:%d listener index:%d",
                         master_index, (int) listener_idx);
                return SK_PASS;
            }

            if (rc != -ENOENT) {
                debugmsg("nginx quic bpf_sk_select_reuseport() failed: %d", rc);
                return SK_DROP;
            }

            debugmsg("nginx quic listener socket missing "
                     "master index:%d listener index:%d",
                     master_index, (int) listener_idx);
        }

        master_index = !master_index;
    }

    return SK_DROP;

bad_dgram:

    debugmsg("nginx quic bad datagram");

    return SK_DROP;
}
