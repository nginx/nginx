
/*
 * Copyright (C) Nginx, Inc.
 */

#include <errno.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <linux/bpf.h>
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

#define NGX_QUIC_BPF_NMASTERS_IDX 2
#define NGX_QUIC_BPF_ACT_MASTER_IDX 3


struct {} ngx_quic_master_state SEC(".maps") ;
struct {} ngx_quic_listen_maps SEC(".maps") ;
struct {} ngx_quic_connections SEC(".maps") ;


SEC(PROGNAME)
int ngx_quic_select_socket_by_dcid(struct sk_reuseport_md *ctx)
{
    int             rc, flags;
    long            err;
    __u32           idx, *val, *lmap_ptr, nwrk, ns, active;
    size_t          len, offset;
    unsigned char  *start, *end, dcid[NGX_QUIC_SERVER_CID_LEN];

    /* direct packet access pointers, [s..e] may be less than ctx->len */
    start = ctx->data;
    end = ctx->data_end;

    offset = sizeof(struct udphdr) + 1; /* UDP header + QUIC flags */

    if (start + offset > end) {

        /* direct access is not guaranteed, we may need to load data */
        if (offset >= ctx->len) {
            goto bad_dgram;
        }

        err = bpf_skb_load_bytes(ctx, offset - 1, dcid, 1);
        if (err != 0) {
            goto bad_dgram;
        }

        flags = dcid[0];

    } else {
        flags = start[offset - 1];
    }

    if (flags & NGX_QUIC_PKT_LONG) {
        offset += 5; /* QUIC version + DCID len */
        if (start + offset > end) {

            if (offset >= ctx->len) {
                goto bad_dgram;
            }

            err = bpf_skb_load_bytes(ctx, offset - 1, dcid,  1);
            if (err != 0) {
                goto bad_dgram;
            }

            len = dcid[0];

        } else {
            len = start[offset - 1];
        }

        if (len != NGX_QUIC_SERVER_CID_LEN) {
            goto new_conn;
        }
    }

    if (start + offset + NGX_QUIC_SERVER_CID_LEN > end) {

        if ((offset + NGX_QUIC_SERVER_CID_LEN) >= ctx->len) {
            goto bad_dgram;
        }

        err = bpf_skb_load_bytes(ctx, offset, dcid, NGX_QUIC_SERVER_CID_LEN);
        if (err != 0) {
            goto bad_dgram;
        }

    } else {
        memcpy(dcid, start + offset, NGX_QUIC_SERVER_CID_LEN);
    }

    rc = bpf_sk_select_reuseport(ctx, &ngx_quic_connections, dcid, 0);

    if (rc == 0) {
        debugmsg("nginx quic socket selected by dcid");
        return SK_PASS;
    }

    if (rc != -ENOENT) {
        debugmsg("nginx quic bpf_sk_select_reuseport() failed:%d", rc);
        /*
         * we don't know which worker owns the connection
         * - consider this packet a martian and drop
         */
        return SK_DROP;
    }

new_conn:

    debugmsg("nginx quic new connection");

    idx = NGX_QUIC_BPF_NMASTERS_IDX;

    val = bpf_map_lookup_elem(&ngx_quic_master_state, &idx);
    if (val == NULL) {
        /*
         * we expect that map always has entries at predefined indexes;
         * map is constructed and updated before the program is attached,
         * so something is very wrong here;
         * drop the packet, so anyone will notice the problem and read logs
         */
        debugmsg("nginx quic master_state map is inconsistent");
        return SK_DROP;
    }

    debugmsg("nginx quic master count %d", *val);

    if (*val == 2) {
        /* two masters, select randomly which to use */
        active = (bpf_get_prandom_u32() % 2);

        debugmsg("nginx quic selected randomly master #%d", active);

    } else {
        /* single master running, choose active */
        idx = NGX_QUIC_BPF_ACT_MASTER_IDX;

        val = bpf_map_lookup_elem(&ngx_quic_master_state, &idx);
        if (val == NULL) {
            /*
             * shouldn't normally happen, but in case of abnormal
             * process termination this could be left in inconsistent
             * state;
             * we don't know how to pass packet to proper worker,
             * so just drop it
             */
            debugmsg("nginx quic master_state map state is inconsistent");
            return SK_DROP;
        }
        active = *val;

        debugmsg("nginx quic selected active master: #%d", active);
    }


    /* select the number of workers in active master */
    val = bpf_map_lookup_elem(&ngx_quic_master_state, &active);
    if (val == NULL) {
        /* again, map state is inconsistent, drop the packet */
        debugmsg("nginx quic master_state map state is inconsistent");
        return SK_DROP;
    }

    nwrk = *val;
    debugmsg("  nginx quic nworkers is %d", nwrk);

    /* get the pointer to the inner map - with listen sockets */
    lmap_ptr = bpf_map_lookup_elem(&ngx_quic_listen_maps, &active);
    if (lmap_ptr == NULL) {
        /*
         * the active master entry does not point to valid inner map;
         * something is very bad, drop it
         */
        debugmsg("nginx quic listen_maps failed");
        return SK_DROP;
    }

    /* select the worker to use */
    ns = ctx->hash % nwrk;

    rc = bpf_sk_select_reuseport(ctx, lmap_ptr, &ns, 0);
    if (rc == 0) {
        debugmsg("nginx quic socket selected by hash:%d of %d", (int) ns, nwrk);
        return SK_PASS;
    }

    /* again, our map is in inconsistent state, drop the packet */
    debugmsg("nginx quic select_reuseport failed:%d", rc);

    return SK_DROP;

bad_dgram:

    debugmsg("nginx quic bad datagram");

    /* we cannot even parse this as QUIC - drop it */
    return SK_DROP;
}
