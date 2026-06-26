#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

#include "waitleader_maps.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct leader_metadata);
} inflight_registry SEC(".maps");

SEC("xdp")
int waitleader_stampede_guard(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    __u32 ip_header_len = iph->ihl * 4;
    if (ip_header_len < sizeof(*iph))
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + ip_header_len;
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    if (tcph->dest != bpf_htons(8080))
        return XDP_PASS;

    __u64 request_key = ((__u64)tcph->source << 32) | (__u64)bpf_ntohl(tcph->seq);
    __u64 *leader_active = bpf_map_lookup_elem(&inflight_registry, &request_key);

    if (leader_active)
        return XDP_DROP;

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

