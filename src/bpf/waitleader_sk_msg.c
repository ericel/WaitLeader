#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "waitleader_maps.h"

#define FNV_OFFSET_BASIS_64 14695981039346656037ULL
#define FNV_PRIME_64        1099511628211ULL
#define MAX_URI_LENGTH      64
#define MAX_H2_HEADER_BLOCK 128
#define HTTP2_FRAME_HEADERS 0x01
#define HTTP2_FLAG_PADDED   0x08
#define HTTP2_FLAG_PRIORITY 0x20

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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct h2_stream_key);
    __type(value, struct leader_metadata);
} waitleader_h2_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 65535);
    __type(key, __u32);
    __type(value, __u32);
} waitleader_sockmap SEC(".maps");

static __always_inline void increment_metric(__u32 metric)
{
    __u64 *value = bpf_map_lookup_elem(&waitleader_metrics, &metric);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int pass_sk_msg(__u32 metric)
{
    increment_metric(metric);
    increment_metric(WAITLEADER_METRIC_SK_MSG_PASS_TOTAL);
    return SK_PASS;
}

static __always_inline int looks_like_http2_preface(unsigned char *data, void *data_end)
{
    if ((void *)(data + 14) > data_end)
        return 0;

    return data[0] == 'P' && data[1] == 'R' && data[2] == 'I' && data[3] == ' ' &&
           data[4] == '*' && data[5] == ' ' && data[6] == 'H' && data[7] == 'T' &&
           data[8] == 'T' && data[9] == 'P' && data[10] == '/' && data[11] == '2' &&
           data[12] == '.' && data[13] == '0';
}

static __always_inline int verdict_for_hash(__u64 uri_hash)
{
    struct leader_metadata *leader_active = bpf_map_lookup_elem(&inflight_registry, &uri_hash);
    if (leader_active) {
        leader_active->suppressed_followers_count += 1;
        increment_metric(WAITLEADER_METRIC_SK_MSG_DROP_TOTAL);
        increment_metric(WAITLEADER_METRIC_RETRANSMISSION_DROP_TOTAL);
        return SK_DROP;
    }

    return pass_sk_msg(WAITLEADER_METRIC_URI_HASH_MISS_TOTAL);
}

static __always_inline __u32 compute_conn_id(struct sk_msg_md *msg)
{
    return msg->remote_ip4 ^ msg->local_ip4 ^ msg->remote_port ^ msg->local_port;
}

static __always_inline __u32 read_http2_stream_id(unsigned char *data)
{
    return ((__u32)(data[5] & 0x7f) << 24) | ((__u32)data[6] << 16) |
           ((__u32)data[7] << 8) | data[8];
}

static __always_inline int verdict_for_h2_stream(struct sk_msg_md *msg, __u32 stream_id)
{
    struct h2_stream_key key = {};
    key.conn_id = compute_conn_id(msg);
    key.stream_id = stream_id;

    struct leader_metadata *policy = bpf_map_lookup_elem(&waitleader_h2_streams, &key);
    if (policy) {
        policy->suppressed_followers_count += 1;
        increment_metric(WAITLEADER_METRIC_H2_STREAM_POLICY_HIT_TOTAL);
        increment_metric(WAITLEADER_METRIC_H2_STREAM_POLICY_DROP_TOTAL);
        increment_metric(WAITLEADER_METRIC_SK_MSG_DROP_TOTAL);
        increment_metric(WAITLEADER_METRIC_RETRANSMISSION_DROP_TOTAL);
        return SK_DROP;
    }

    return SK_PASS;
}

static __always_inline int parse_http2_headers(unsigned char *data, void *data_end)
{
    if ((void *)(data + 9) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    __u32 frame_len = ((__u32)data[0] << 16) | ((__u32)data[1] << 8) | data[2];
    if (data[3] != HTTP2_FRAME_HEADERS)
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_UNSUPPORTED_TOTAL);

    increment_metric(WAITLEADER_METRIC_TLS_HTTP2_HEADERS_TOTAL);

    if (frame_len == 0 || frame_len > MAX_H2_HEADER_BLOCK)
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);

    unsigned char *frame_end = data + 9 + frame_len;
    if ((void *)frame_end > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    unsigned char flags = data[4];
    if (flags & (HTTP2_FLAG_PADDED | HTTP2_FLAG_PRIORITY))
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);

    unsigned char *cursor = data + 9;
    if ((void *)(cursor + 1) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (*cursor != 0x82)
        return pass_sk_msg(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    cursor++;
    if ((void *)(cursor + 1) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    unsigned char field = *cursor;
    if (field == 0x84) {
        __u64 slash_hash = FNV_OFFSET_BASIS_64;
        slash_hash ^= '/';
        slash_hash *= FNV_PRIME_64;
        increment_metric(WAITLEADER_METRIC_TLS_HTTP2_PATH_TOTAL);
        return verdict_for_hash(slash_hash);
    }

    unsigned char name_index = 0;
    if ((field & 0xc0) == 0x40) {
        name_index = field & 0x3f;
    } else if ((field & 0xf0) == 0x00 || (field & 0xf0) == 0x10) {
        name_index = field & 0x0f;
    } else {
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);
    }

    if (name_index != 4)
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);

    cursor++;
    if ((void *)(cursor + 1) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    unsigned char value_len_byte = *cursor;
    if (value_len_byte & 0x80)
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);

    __u32 value_len = value_len_byte & 0x7f;
    if (value_len > MAX_URI_LENGTH)
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_HPACK_UNSUPPORTED_TOTAL);

    cursor++;
    if ((void *)(cursor + value_len) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    __u64 path_hash = FNV_OFFSET_BASIS_64;
#pragma unroll
    for (int j = 0; j < MAX_URI_LENGTH; j++) {
        if (j >= value_len)
            break;
        if ((void *)(cursor + j + 1) > data_end)
            break;
        unsigned char c = *(cursor + j);
        path_hash ^= c;
        path_hash *= FNV_PRIME_64;
    }

    increment_metric(WAITLEADER_METRIC_TLS_HTTP2_PATH_TOTAL);
    return verdict_for_hash(path_hash);
}

SEC("sk_msg")
int waitleader_tls_plaintext_guard(struct sk_msg_md *msg)
{
    unsigned char *data = (unsigned char *)(long)msg->data;
    void *data_end = (void *)(long)msg->data_end;

    increment_metric(WAITLEADER_METRIC_SK_MSG_TOTAL);

    if ((void *)(data + 1) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (looks_like_http2_preface(data, data_end)) {
        increment_metric(WAITLEADER_METRIC_TLS_HTTP2_PREFACE_TOTAL);
        return pass_sk_msg(WAITLEADER_METRIC_TLS_HTTP2_UNSUPPORTED_TOTAL);
    }

    if ((void *)(data + 9) <= data_end) {
        __u32 stream_id = read_http2_stream_id(data);
        if (stream_id != 0) {
            int stream_verdict = verdict_for_h2_stream(msg, stream_id);
            if (stream_verdict == SK_DROP)
                return SK_DROP;
        }
    }

    if ((void *)(data + 9) <= data_end && data[3] == HTTP2_FRAME_HEADERS)
        return parse_http2_headers(data, data_end);

    if ((void *)(data + 5) > data_end)
        return pass_sk_msg(WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL);

    if (data[0] != 'G' || data[1] != 'E' || data[2] != 'T' || data[3] != ' ')
        return pass_sk_msg(WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL);

    increment_metric(WAITLEADER_METRIC_TLS_HTTP1_GET_TOTAL);

    __u64 uri_hash = FNV_OFFSET_BASIS_64;
    unsigned char *uri_ptr = data + 4;

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

    return verdict_for_hash(uri_hash);
}

char _license[] SEC("license") = "GPL";
