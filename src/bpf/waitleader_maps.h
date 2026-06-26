#ifndef WAITLEADER_MAPS_H
#define WAITLEADER_MAPS_H

struct leader_metadata {
    __u64 start_timestamp_ns;
    __u32 origin_pid;
    __u32 suppressed_followers_count;
};

#endif
