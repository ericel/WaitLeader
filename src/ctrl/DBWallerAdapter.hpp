#pragma once

#include <iostream>
#include <string_view>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "../bpf/waitleader_maps.h"

class DBWallerXDPAdapter {
private:
    int map_fd;

    __u64 compute_fnv1a(std::string_view uri) const
    {
        __u64 hash = 14695981039346656037ULL;
        for (char c : uri) {
            hash ^= static_cast<unsigned char>(c);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

public:
    explicit DBWallerXDPAdapter(const char *pinned_map_path)
    {
        map_fd = bpf_obj_get(pinned_map_path);
        if (map_fd < 0) {
            std::cerr << "[!] WARNING: eBPF map not found. DBWaller running in User-Space-Only mode.\n";
        }
    }

    [[nodiscard]] bool is_ready() const
    {
        return map_fd >= 0;
    }

    ~DBWallerXDPAdapter()
    {
        if (map_fd >= 0) {
            close(map_fd);
        }
    }

    class InflightGuard {
    private:
        int fd;
        __u64 key_hash;
        bool active;

    public:
        InflightGuard(int map_fd, __u64 hash)
            : fd(map_fd), key_hash(hash), active(false)
        {
            if (fd >= 0) {
                leader_metadata value {};
                value.start_timestamp_ns = 1;
                value.origin_pid = static_cast<__u32>(getpid());
                value.suppressed_followers_count = 0;

                if (bpf_map_update_elem(fd, &key_hash, &value, BPF_ANY) == 0) {
                    active = true;
                }
            }
        }

        ~InflightGuard()
        {
            if (active && fd >= 0) {
                bpf_map_delete_elem(fd, &key_hash);
            }
        }
    };

    [[nodiscard]] InflightGuard acquire_kernel_guard(std::string_view cache_key) const
    {
        return InflightGuard(map_fd, compute_fnv1a(cache_key));
    }
};
