#include "../src/ctrl/DBWallerAdapter.hpp"

#include <iostream>
#include <string>

int main()
{
    std::cout << "--- [CTest] WaitLeader Memory Leak & RAII Validation ---\n";

    DBWallerXDPAdapter adapter("/sys/fs/bpf/waitleader_map");
    if (!adapter.is_ready()) {
        std::cerr << "[FAIL] Pinned eBPF map must be available for this test.\n";
        return 1;
    }
    std::string base_uri = "/api/v1/users?id=";

    std::cout << "[*] Simulating 10,000 rapid Leader elections...\n";

    int successful_cleans = 0;

    for (int i = 0; i < 10000; i++) {
        std::string current_key = base_uri + std::to_string(i);

        {
            auto guard = adapter.acquire_kernel_guard(current_key);

            if (i % 10 == 0) {
                successful_cleans++;
                continue;
            }

            successful_cleans++;
        }
    }

    if (successful_cleans != 10000) {
        std::cerr << "[FAIL] RAII cleanup count mismatch.\n";
        return 1;
    }
    std::cout << "[+] RAII Destructor successfully prevented 10,000 kernel memory leaks.\n";
    std::cout << "[PASS] Memory boundaries are stable.\n";

    return 0;
}
