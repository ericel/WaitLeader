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

class WaitLeaderMapBridge {
private:
    int map_fd;

public:
    explicit WaitLeaderMapBridge(const char *pinned_map_path)
    {
        map_fd = bpf_obj_get(pinned_map_path);
        if (map_fd < 0) {
            throw std::runtime_error("CRITICAL: Failed to open eBPF pinned map. Is it pinned and attached?");
        }
    }

    ~WaitLeaderMapBridge()
    {
        if (map_fd >= 0) {
            close(map_fd);
        }
    }

    void register_leader(__u64 request_key)
    {
        leader_metadata value {};
        value.start_timestamp_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::high_resolution_clock::now().time_since_epoch()
        ).count();
        value.origin_pid = static_cast<__u32>(getpid());
        value.suppressed_followers_count = 0;

        int res = bpf_map_update_elem(map_fd, &request_key, &value, BPF_ANY);
        if (res != 0) {
            std::cerr << "[!] Kernel map insert failed for key: " << request_key << "\n";
            return;
        }

        std::cout << "[+] [DBWaller Leader Elected] Key " << request_key
                  << " registered in Kernel. Stampedes will now be dropped at NIC.\n";
    }

    void release_leader(__u64 request_key)
    {
        int res = bpf_map_delete_elem(map_fd, &request_key);
        if (res == 0) {
            std::cout << "[-] [DBWaller Cache Warm] Key " << request_key
                      << " removed from Kernel. Traffic flowing normally.\n";
            return;
        }

        std::cerr << "[!] Kernel map delete failed for key: " << request_key << "\n";
    }
};

int main()
{
    std::cout << "=== WaitLeader Control Plane Gateway (v1.0) ===\n";

    const char *map_path = "/sys/fs/bpf/waitleader_map";

    try {
        WaitLeaderMapBridge bridge(map_path);

        __u64 simulated_api_key = 1337;

        std::cout << "\n[1] Simulating Cache Miss. DBWaller elects Leader Thread...\n";
        bridge.register_leader(simulated_api_key);

        std::cout << "[2] Leader is querying origin DB (Simulating 5s slow query)...\n";
        std::cout << "    --> Try spamming packets to port 8080 right now! Kernel will drop them.\n";
        std::this_thread::sleep_for(std::chrono::seconds(5));

        std::cout << "[3] Origin query complete! DBWaller RAM populated.\n";
        bridge.release_leader(simulated_api_key);
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        std::cerr << "Tip: Pin the map first with something like:\n";
        std::cerr << "     sudo bpftool map pin id <MAP_ID> /sys/fs/bpf/waitleader_map\n";
        return 1;
    }

    return 0;
}

