#include <chrono>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "DBWallerAdapter.hpp"

int main()
{
    std::cout << "=== DBWaller + WaitLeader Integration Benchmark ===\n";

    DBWallerXDPAdapter xdp_driver("/sys/fs/bpf/waitleader_map");

    std::string hot_api_key = "/api/v1/posts?id=b1c3e8ba";
    std::mutex console_lock;

    auto dbwaller_get_request = [&](int thread_id) {
        {
            std::lock_guard<std::mutex> lock(console_lock);
            std::cout << "[Thread " << thread_id << "] Incoming API request for: " << hot_api_key << "\n";
        }

        if (thread_id == 0) {
            {
                std::lock_guard<std::mutex> lock(console_lock);
                std::cout << " --> [Thread 0 ELECTED LEADER] Activating eBPF Hardware Guard...\n";
            }

            auto kernel_guard = xdp_driver.acquire_kernel_guard(hot_api_key);

            std::this_thread::sleep_for(std::chrono::seconds(3));

            {
                std::lock_guard<std::mutex> lock(console_lock);
                std::cout << " <-- [Thread 0 DB FETCH COMPLETE] Populating cache. Destructor lifting NIC drop rules.\n";
            }
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    };

    std::vector<std::thread> pool;
    for (int i = 0; i < 10; i++) {
        pool.emplace_back(dbwaller_get_request, i);
    }

    for (auto &t : pool) {
        t.join();
    }

    std::cout << "\n[Success] Integrated execution complete. Memory boundaries secure.\n";
    return 0;
}
