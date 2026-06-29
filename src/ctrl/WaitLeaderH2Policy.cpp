#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "../bpf/waitleader_maps.h"

namespace {

class H2PolicyMap {
public:
    explicit H2PolicyMap(const char *path)
        : fd_(bpf_obj_get(path))
    {
        if (fd_ < 0) {
            throw std::runtime_error("CRITICAL: Failed to open HTTP/2 stream policy map.");
        }
    }

    ~H2PolicyMap()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    void register_policy(h2_stream_key key)
    {
        leader_metadata value {};
        value.start_timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()
        ).count();
        value.origin_pid = static_cast<__u32>(getpid());
        value.suppressed_followers_count = 0;

        if (bpf_map_update_elem(fd_, &key, &value, BPF_ANY) != 0) {
            throw std::runtime_error("CRITICAL: Failed to register HTTP/2 stream policy.");
        }
    }

    void release_policy(h2_stream_key key)
    {
        if (bpf_map_delete_elem(fd_, &key) != 0) {
            std::cerr << "[!] HTTP/2 stream policy was already absent.\n";
        }
    }

private:
    int fd_;
};

std::uint32_t parse_u32(const char *value)
{
    return static_cast<std::uint32_t>(std::stoul(value, nullptr, 0));
}

} // namespace

int main(int argc, char **argv)
{
    const char *map_path = "/sys/fs/bpf/waitleader_h2_streams";
    h2_stream_key key {};
    key.conn_id = 0xC001D00D;
    key.stream_id = 1;
    int hold_seconds = 5;

    if (argc > 1) {
        key.conn_id = parse_u32(argv[1]);
    }
    if (argc > 2) {
        key.stream_id = parse_u32(argv[2]);
    }
    if (argc > 3) {
        hold_seconds = std::stoi(argv[3]);
    }

    try {
        H2PolicyMap policies(map_path);
        std::cout << "=== WaitLeader HTTP/2 Semantic Policy Controller ===\n";
        std::cout << "[+] Registering ConnID=" << key.conn_id
                  << " StreamID=" << key.stream_id << " for "
                  << hold_seconds << "s\n";

        policies.register_policy(key);
        std::this_thread::sleep_for(std::chrono::seconds(hold_seconds));
        policies.release_policy(key);

        std::cout << "[-] Released ConnID=" << key.conn_id
                  << " StreamID=" << key.stream_id << "\n";
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        std::cerr << "Tip: pin the map at /sys/fs/bpf/waitleader_h2_streams from the SK_MSG object.\n";
        return 1;
    }

    return 0;
}
