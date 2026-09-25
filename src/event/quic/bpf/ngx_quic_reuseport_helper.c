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
 * The map objects are created by userspace and linked to these symbols.
 */
struct {} ngx_quic_connections SEC(".maps");
struct {} ngx_quic_worker_counts SEC(".maps");

#define NGX_QUIC_BPF_LISTEN_KEY(master_index, worker)                         \
    (((__u64) 0xFF << 56) | ((__u64) (master_index) << 48)                    \
     | ((__u64) (worker) & 0xFFFFFFFFFFFFULL))


SEC(PROGNAME)
int ngx_quic_reuseport_select(struct sk_reuseport_md *ctx)
{
    unsigned char  *start, *end, dcid[NGX_QUIC_SERVER_CID_LEN];
    unsigned char   byte;
    int             rc, master_index, flags, i, worker_idx;
    long            err;
    __u32           wc_key, *worker_count;
    __u64           map_key;
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
        __builtin_memcpy(dcid, start + offset, NGX_QUIC_SERVER_CID_LEN);
    }

    map_key = ngx_quic_parse_uint64(dcid);

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_connections, &map_key, 0);

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

        wc_key = master_index;

        worker_count = bpf_map_lookup_elem(&ngx_quic_worker_counts, &wc_key);

        if (worker_count == NULL) {
            debugmsg("nginx quic master index %d worker count undefined",
                     master_index);
            return SK_DROP;
        }

        if (*worker_count) {
            worker_idx = ctx->hash % *worker_count;

            map_key = NGX_QUIC_BPF_LISTEN_KEY(master_index, worker_idx);

            rc = bpf_sk_select_reuseport(ctx, &ngx_quic_connections,
                                         &map_key, 0);

            if (rc == 0) {
                debugmsg("nginx quic listener socket selected "
                         "master index:%d worker index:%d",
                         master_index, worker_idx);
                return SK_PASS;
            }

            if (rc != -ENOENT) {
                debugmsg("nginx quic bpf_sk_select_reuseport() failed: %d",
                         rc);
                return SK_DROP;
            }

            debugmsg("nginx quic listener socket missing "
                     "master index:%d worker index:%d",
                     master_index, worker_idx);
        }

        master_index = !master_index;
    }

    return SK_DROP;

bad_dgram:

    debugmsg("nginx quic bad datagram");

    return SK_DROP;
}
