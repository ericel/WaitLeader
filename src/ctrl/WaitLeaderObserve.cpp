#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <thread>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>

#include "../bpf/waitleader_maps.h"

namespace {

struct MetricView {
    waitleader_metric id;
    const char *name;
};

constexpr MetricView kMetrics[] = {
    {WAITLEADER_METRIC_PACKETS_TOTAL, "packets_total"},
    {WAITLEADER_METRIC_XDP_PASS_TOTAL, "xdp_pass_total"},
    {WAITLEADER_METRIC_XDP_DROP_TOTAL, "xdp_drop_total"},
    {WAITLEADER_METRIC_IPV4_TCP_8080_TOTAL, "ipv4_tcp_8080_total"},
    {WAITLEADER_METRIC_HTTP_GET_TOTAL, "http_get_total"},
    {WAITLEADER_METRIC_URI_HASH_MISS_TOTAL, "uri_hash_miss_total"},
    {WAITLEADER_METRIC_MALFORMED_PACKET_TOTAL, "malformed_packet_total"},
    {WAITLEADER_METRIC_NON_HTTP_PASS_TOTAL, "non_http_pass_total"},
};

class Fd {
public:
    explicit Fd(const char *path)
        : fd_(bpf_obj_get(path))
    {
    }

    ~Fd()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }

    Fd(const Fd &) = delete;
    Fd &operator=(const Fd &) = delete;

    [[nodiscard]] int get() const
    {
        return fd_;
    }

    [[nodiscard]] bool ok() const
    {
        return fd_ >= 0;
    }

private:
    int fd_;
};

struct LeaderSummary {
    std::uint64_t active_leaders = 0;
    std::uint64_t suppressed_followers = 0;
};

std::uint64_t read_metric(int metrics_fd, waitleader_metric metric)
{
    __u32 key = static_cast<__u32>(metric);
    __u64 value = 0;
    if (bpf_map_lookup_elem(metrics_fd, &key, &value) != 0) {
        return 0;
    }
    return value;
}

LeaderSummary summarize_leaders(int leader_fd)
{
    LeaderSummary summary;
    __u64 key = 0;
    __u64 next_key = 0;
    bool have_key = false;

    while (bpf_map_get_next_key(leader_fd, have_key ? &key : nullptr, &next_key) == 0) {
        leader_metadata value {};
        if (bpf_map_lookup_elem(leader_fd, &next_key, &value) == 0) {
            summary.active_leaders++;
            summary.suppressed_followers += value.suppressed_followers_count;
        }
        key = next_key;
        have_key = true;
    }

    return summary;
}

void print_text(int metrics_fd, int leader_fd)
{
    const LeaderSummary leaders = summarize_leaders(leader_fd);

    std::cout << "=== WaitLeader Observability Snapshot ===\n";
    std::cout << "active_leaders: " << leaders.active_leaders << "\n";
    std::cout << "suppressed_followers_active: " << leaders.suppressed_followers << "\n";

    for (const auto &metric : kMetrics) {
        std::cout << metric.name << ": " << read_metric(metrics_fd, metric.id) << "\n";
    }
    std::cout << std::flush;
}

void print_json(int metrics_fd, int leader_fd)
{
    const LeaderSummary leaders = summarize_leaders(leader_fd);

    std::cout << "{";
    std::cout << "\"active_leaders\":" << leaders.active_leaders << ",";
    std::cout << "\"suppressed_followers_active\":" << leaders.suppressed_followers;

    for (const auto &metric : kMetrics) {
        std::cout << ",\"" << metric.name << "\":" << read_metric(metrics_fd, metric.id);
    }
    std::cout << "}\n" << std::flush;
}

} // namespace

int main(int argc, char **argv)
{
    std::string metrics_path = "/sys/fs/bpf/waitleader_metrics";
    std::string leader_path = "/sys/fs/bpf/waitleader_map";
    bool json = false;
    bool once = false;
    int interval_ms = 1000;

    for (int i = 1; i < argc; i++) {
        std::string_view arg = argv[i];
        if (arg == "--json") {
            json = true;
        } else if (arg == "--once") {
            once = true;
        } else if (arg == "--metrics-map" && i + 1 < argc) {
            metrics_path = argv[++i];
        } else if (arg == "--leader-map" && i + 1 < argc) {
            leader_path = argv[++i];
        } else if (arg == "--interval-ms" && i + 1 < argc) {
            interval_ms = std::stoi(argv[++i]);
        } else {
            std::cerr << "Usage: waitleader_observe [--json] [--once] [--interval-ms N]"
                      << " [--metrics-map PATH] [--leader-map PATH]\n";
            return 2;
        }
    }

    Fd metrics_fd(metrics_path.c_str());
    if (!metrics_fd.ok()) {
        std::cerr << "CRITICAL: Failed to open metrics map at " << metrics_path << "\n";
        std::cerr << "Tip: pin the XDP metrics map to /sys/fs/bpf/waitleader_metrics.\n";
        return 1;
    }

    Fd leader_fd(leader_path.c_str());
    if (!leader_fd.ok()) {
        std::cerr << "CRITICAL: Failed to open leader map at " << leader_path << "\n";
        return 1;
    }

    do {
        if (json) {
            print_json(metrics_fd.get(), leader_fd.get());
        } else {
            print_text(metrics_fd.get(), leader_fd.get());
        }

        if (!once) {
            std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms));
        }
    } while (!once);

    return 0;
}
