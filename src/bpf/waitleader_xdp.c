#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include "waitleader_maps.h"

#define FNV_OFFSET_BASIS_64 14695981039346656037ULL
#define FNV_PRIME_64        1099511628211ULL
#define MAX_URI_LENGTH      64

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct leader_metadata);
} inflight_registry SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, WAITLEADER_METRIC_MAX);
    __type(key, __u32);
    __type(value, __u64);
} waitleader_metrics SEC(".maps");

static __always_inline void increment_metric(__u32 metric)
{
    __u64 *value = bpf_map_lookup_elem(&waitleader_metrics, &metric);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int pass_with_metric(__u32 metric)
{
    increment_metric(metric);
    increment_metric(WAITLEADER_METRIC_XDP_PASS_TOTAL);
    return XDP_PASS;
}

SEC("xdp")
int waitleader_stampede_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    increment_metric(WAITLEADER_METRIC_PACKETS_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return pass_with_metric(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return pass_with_metric(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return pass_with_metric(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (iph->protocol != IPPROTO_TCP)
        return pass_with_metric(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    __u32 ip_header_len = iph->ihl * 4;
    if (ip_header_len < sizeof(*iph))
        return pass_with_metric(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    struct tcphdr *tcph = (void *)iph + ip_header_len;
    if ((void *)(tcph + 1) > data_end)
        return pass_with_metric(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (tcph->dest != bpf_htons(8080))
        return pass_with_metric(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    increment_metric(WAITLEADER_METRIC_IPV4_TCP_8080_TOTAL);

    __u32 tcp_header_len = tcph->doff * 4;
    unsigned char *payload = (unsigned char *)tcph + tcp_header_len;

    if ((void *)(payload + 5) > data_end)
        return pass_with_metric(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (payload[0] != 'G' || payload[1] != 'E' || payload[2] != 'T' || payload[3] != ' ')
        return pass_with_metric(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    increment_metric(WAITLEADER_METRIC_HTTP_GET_TOTAL);

    __u64 uri_hash = FNV_OFFSET_BASIS_64;
    unsigned char *uri_ptr = payload + 4;

#pragma unroll
    for (int i = 0; i < MAX_URI_LENGTH; i++) {
        if ((void *)(uri_ptr + 1) > data_end)
            break;

        unsigned char c = *uri_ptr;
        if (c == ' ' || c == '\r' || c == '\n')
            break;

        uri_hash ^= c;
        uri_hash *= FNV_PRIME_64;
        uri_ptr++;
    }

    struct leader_metadata *leader_active = bpf_map_lookup_elem(&inflight_registry, &uri_hash);

    if (leader_active) {
        leader_active->suppressed_followers_count += 1;
        increment_metric(WAITLEADER_METRIC_XDP_DROP_TOTAL);
        return XDP_DROP;
    }

    return pass_with_metric(WAITLEADER_METRIC_URI_HASH_MISS_TOTAL);
}

char _license[] SEC("license") = "GPL";
