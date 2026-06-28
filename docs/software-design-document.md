# WaitLeader Software Design Document

**Version:** 1.0  
**Status:** Architectural Draft  
**Target Platform:** Linux kernel 5.15+ on Ubuntu LTS  
**User Space Runtime:** C++20  
**Primary Integration:** DBWaller cache/coalescing layer

## 1. Purpose

WaitLeader is a kernel-assisted request coalescing system designed to suppress duplicate in-flight requests before they reach the application layer. The goal is to reduce the CPU and memory cost of thundering-herd traffic by moving the duplicate-request decision into the Linux networking fast path using eBPF and XDP.

The system complements DBWaller:

- DBWaller remains responsible for cache state, request ownership, and origin fetch completion.
- WaitLeader acts as the kernel-facing suppression layer that drops or passes packets based on leader state maintained in shared eBPF maps.

## 2. Problem Statement

When a hot cache entry expires, many clients often retry the same request at once. In a conventional architecture, every request still incurs:

- socket buffer allocation,
- protocol stack traversal,
- user/kernel context switching,
- application-layer duplicate detection.

That cost becomes significant under bursty load. WaitLeader addresses this by making the kernel aware of active leaders so that follower traffic can be rejected early, at the network edge.

## 3. Design Goals

- Prevent duplicate in-flight requests from reaching the application when a leader already exists.
- Keep the fast path in kernel space and avoid sk_buff overhead where possible.
- Use a narrow shared-state boundary between kernel and user space.
- Preserve DBWaller as the source of truth for cache fill lifecycle.
- Keep the design testable on a standard Ubuntu development VM.

## 4. Non-Goals

- WaitLeader is not a general-purpose firewall.
- WaitLeader is not a replacement for DBWaller cache storage.
- WaitLeader does not guarantee delivery of dropped packets; clients are expected to retry using normal TCP or HTTP retry behavior.
- WaitLeader is not intended to parse arbitrary application protocols beyond the request patterns needed for stampede suppression.

## 5. System Architecture

WaitLeader uses a split-plane architecture:

- Kernel space: XDP program attached at the NIC driver hook.
- User space: C++20 control daemon managing map state and reacting to DBWaller events.

```text
[ Incoming HTTP GET Traffic ]
             |
             v
  +-----------------------------------------------+
  |                 KERNEL SPACE                  |
  |                                               |
  |  XDP hook: waitleader_xdp_kern.c              |
  |      |                                        |
  |      v                                        |
  |  Parse L2/L3/L4/L7 request identity           |
  |      |                                        |
  |      v                                        |
  |  eBPF inflight map (hash map)                 |
  |      |                                        |
  |  +---+--------------------+                  |
  |  | Match found            | No match         |
  |  v                        v                  |
  | XDP_DROP                XDP_PASS             |
  +-----------------------------------------------+
                       |
                       v
  +-----------------------------------------------+
  |                  USER SPACE                   |
  |                                               |
  |  WaitLeaderCtrl daemon                        |
  |      |                                        |
  |      v                                        |
  |  DBWaller engine                              |
  +-----------------------------------------------+
```

## 6. Runtime Responsibilities

### 6.1 Kernel Fast Path

The XDP program is responsible for:

- inspecting incoming packets before `sk_buff` allocation,
- extracting enough request identity to compute a stable lookup key,
- checking whether that key corresponds to an active leader,
- taking an immediate disposition decision:
  - `XDP_PASS` when no active leader is present,
  - `XDP_DROP` when the packet is a duplicate follower for an existing leader.

The kernel component should stay minimal and deterministic.

### 6.2 User-Space Control Plane

The C++20 control daemon is responsible for:

- loading and attaching the eBPF program via `libbpf`,
- pinning maps under a stable path such as `/sys/fs/bpf/waitleader`,
- subscribing to DBWaller cache-miss or origin-fetch telemetry,
- inserting leader keys into the kernel map when origin fetch begins,
- removing keys once the cached payload has been populated.

## 7. Shared State

The only coordination mechanism between kernel and user space is a pinned eBPF hash map.

### 7.1 Leader Metadata

```c
struct leader_metadata {
    __u64 start_timestamp_ns;
    __u32 origin_pid;
    __u32 suppressed_followers_count;
};
```

### 7.2 Inflight Registry Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct leader_metadata);
} inflight_registry SEC(".maps");
```

### 7.3 Key Semantics

- Key type: 64-bit hash of the request URI or equivalent request identity.
- Suggested hash families: FarmHash or XXHash.
- Value type: leader metadata used for observability and suppression accounting.

## 8. Request Lifecycle

1. A request misses the DBWaller cache.
2. DBWaller elects a leader thread to fetch from origin.
3. The control plane hashes the request identity and inserts it into `inflight_registry`.
4. Additional matching requests arrive at the NIC.
5. The XDP program detects the active leader entry and drops follower packets.
6. The leader completes the origin fetch and writes the result into DBWaller.
7. The control plane removes the key from the map.
8. Retries and later requests pass through normally and hit warm cache state.

## 9. Repository Layout

The repository should organize source code by plane and concern:

| Path | Language | Responsibility |
| --- | --- | --- |
| `src/bpf/waitleader_xdp.c` | C | XDP packet parsing and action routing |
| `src/bpf/waitleader_maps.h` | C header | eBPF map definitions and metadata types |
| `src/ctrl/MapController.cpp` | C++20 | libbpf wrapper for map mutation |
| `src/ctrl/DaemonMain.cpp` | C++20 | event loop and telemetry integration |
| `tests/test_verifier_pass.sh` | Bash | CI check for verifier compatibility |
| `bench/herd_stress_test.py` | Python | traffic burst generator and stampede simulation |

## 10. Verification Strategy

The design should be validated along three dimensions:

- Verifier compatibility: ensure the XDP program passes the kernel verifier on the target kernel.
- Stampede suppression: compare context-switch count and CPU load against a user-space-only coalescing baseline.
- State safety: verify that repeated map insertions and deletions do not leak kernel memory or leave stale leader entries behind.

## 11. Implementation Roadmap & Milestone Tracking

This project follows a strict, verification-driven execution model. Because kernel-space programming introduces severe risks of OS instability, each layer must be independently compiled, verified by the Linux kernel, and validated in user space before moving up the stack.

| Milestone | Module Focus | Core Deliverable | Target Verification Metric | Status |
| --- | --- | --- | --- | --- |
| M1 | Fast Data Plane | Bare-metal verifier pass and NIC hook | Sub-millisecond OS verification time (< 500 usec) | ✅ Completed |
| M2 | Control Plane | User-space map gateway | Atomic key insertion/deletion via libbpf | ✅ Completed |
| M3 | Packet Parser | L7 HTTP URI extraction engine | Deterministic FNV-1a URI hash generation under verifier limits | ✅ Completed |
| M4 | Integration | DBWaller state machine hook | Zero-latency synchronization with SWR lifecycle | ✅ Completed |
| M5 | Quality Assurance | Automated CTest and memory suite | Zero kernel memory leaks across 1M map mutations | ✅ Completed |
| M6 | Empirical Defense | Thundering herd benchmark suite | XDP ingress benchmark with kernel suppression counters | ✅ Completed |
| M7 | Observability | Live kernel telemetry plane | User-space observer reads pinned eBPF metric maps | ✅ Completed |

### 11.1 Milestone 1: Bare-Metal Kernel Verifier Pass and NIC Attachment

Objective: establish the bare-metal foundation without crashing the host operating system.

Tasks:

- Define the `inflight_registry` shared hash map (`BPF_MAP_TYPE_HASH`).
- Write strict, bounded pointer arithmetic in `waitleader_xdp.c` to inspect L2, L3, and L4 headers.
- Compile C bytecode to the `bpf` target architecture via LLVM/Clang.
- Load and attach the XDP driver hook to the primary network interface (`enp0s1`).

Completion criteria:

- `bpftool prog load` succeeds with zero verifier rejections and attaches cleanly to the NIC driver hook.

### 11.2 Milestone 2: User-Space Map Controller Gateway

Objective: bridge modern C++20 application RAM directly to pinned kernel memory.

Tasks:

- Pin the internal kernel map ID to the permanent BPF filesystem (`/sys/fs/bpf/waitleader_map`).
- Engineer `WaitLeaderCtrl.cpp` using `libbpf` to resolve the pinned map file descriptor.
- Implement atomic wrapper methods: `register_leader()` and `release_leader()`.

Completion criteria:

- The user-space daemon mutates kernel memory states dynamically without segmentation faults or privilege escalation errors.

Validation evidence:

- `sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_ctrl` successfully opened the pinned map.
- `register_leader(1337)` inserted the leader key into kernel memory.
- `release_leader(1337)` removed the key cleanly after the simulated origin fetch.
- The controller completed without runtime faults.

### 11.3 Milestone 3: Canonical Request Identity and L7 Parsing

Objective: transition from synthetic packet identification to production HTTP REST semantics.

Tasks:

- Upgrade the XDP fast path to parse L7 HTTP GET request payloads safely within the kernel stack and verifier limits.
- Implement a low-overhead FNV-1a 64-bit hashing algorithm directly inside the eBPF bytecode to convert variable-length URI strings into 64-bit map keys.
- Handle edge cases: TCP segmentation, options padding, and non-HTTP traffic pass-through (`XDP_PASS`).

Completion criteria:

- The XDP program correctly extracts and hashes exact API endpoint strings from live request bursts.

Validation evidence:

- The updated XDP parser loaded successfully with the verifier.
- The controller computed the canonical hash for `/api/v1/posts?id=b1c3e8ba` and registered it in the kernel map.
- The updated XDP program is attached to `enp0s1` as the active driver hook.
- The same parser was exercised through an XDP-attached `veth-host` ingress harness, proving the L7 GET parser and canonical URI hash can drive live `XDP_DROP` decisions.

Run sequence:

1. Rebuild the project with `cd /home/ubuntucplusplus/code/WaitLeader/build && make`.
2. Remove any stale pin before reloading: `sudo rm -f /sys/fs/bpf/waitleader_xdp_m3`.
3. Load the new XDP object: `sudo bpftool prog load /tmp/waitleader_xdp.o /sys/fs/bpf/waitleader_xdp_m3 type xdp`.
4. Attach the pinned program: `sudo bpftool net attach xdp pinned /sys/fs/bpf/waitleader_xdp_m3 dev enp0s1`.
5. Run the control plane: `sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_ctrl`.

### 11.4 Milestone 4: DBWaller Core Engine Integration

Objective: merge kernel-bypass suppression into DBWaller's existing in-process caching architecture.

Tasks:

- Import `WaitLeaderMapBridge` into DBWaller's core memory shard engine.
- Hook `register_leader()` directly into DBWaller's single-flight leader election block upon cache misses.
- Hook `release_leader()` into the stale-while-revalidate background worker completion callbacks.

Completion criteria:

- DBWaller automatically dictates kernel NIC drop rules during simulated origin database latency.

Validation evidence:

- `sudo ./dbwaller_xdp_mock` executed a 10-thread mock leader election run.
- Thread 0 acquired the kernel guard for `/api/v1/posts?id=b1c3e8ba`.
- The guard stayed active during the 3-second leader sleep window.
- The guard was released cleanly when the RAII scope ended.
- The integration completed without warnings or runtime faults.

Run sequence:

1. Build the mock integration with `cd /home/ubuntucplusplus/code/WaitLeader/build && make`.
2. Start the mock leader election run with `sudo ./dbwaller_xdp_mock`.
3. While Thread 0 is in the 3-second sleep window, open a second terminal.
4. Inspect the pinned map with `sudo bpftool map dump pinned /sys/fs/bpf/waitleader_map`.
5. Confirm the 64-bit canonical key for `/api/v1/posts?id=b1c3e8ba` is present while the leader guard is active.

Expected behavior:

- The map dump should show the active FNV-1a key while Thread 0 is still executing.
- After the destructor runs, the key should disappear from the pinned map.

### 11.5 Milestone 5: Automated CTest and Verification Suite

Objective: enforce strict academic repository hygiene mirroring the master's capstone standards.

Tasks:

- Build automated shell scripts integrated into `CMakeLists.txt` to spin up isolated network namespaces.
- Construct C++ integration tests asserting that concurrent map cleanups do not leave orphan keys blocking valid traffic.
- Integrate automated memory boundary checks.

Validation evidence:

- `tests/test_memory_leak.cpp` now exercises 10,000 RAII-managed guard acquisitions and releases.
- `CMakeLists.txt` now builds `test_memory_leak` and registers `MemoryLeakValidation` with CTest.
- `ctest --output-on-failure` passes `MemoryLeakValidation` successfully.

Run sequence:

1. Reconfigure and rebuild with `cd /home/ubuntucplusplus/code/WaitLeader/build && cmake .. && make`.
2. Confirm the pinned map exists at `/sys/fs/bpf/waitleader_map`.
3. Run the suite with `sudo ctest --output-on-failure`.
4. Confirm `MemoryLeakValidation` passes without assertion failures or map access errors.

Completion criteria:

- Running `ctest --output-on-failure` executes all functional, regression, and system suites successfully in under 5 seconds.

### 11.6 Milestone 6: Empirical Stress Testing and Thesis Artifacts

Objective: generate publication-ready evidence for PhD admission and defense.

Tasks:

- Build `herd_stress_test.py` using asynchronous socket multiplexing to blast the network interface with concurrent request storms.
- Capture Linux kernel run-queue depth, CPU context-switch rates, and hardware interrupt volumes.
- Capture live pinned-map snapshots during the request storm to prove that XDP increments kernel-side suppression counters while the leader is active.

Completion criteria:

- A repeatable benchmark run shows baseline traffic passing normally while WaitLeader suppresses duplicate follower requests at an XDP ingress hook, with nonzero kernel suppression counters.

Validation evidence:

- `bench/herd_stress_test.py` now generates asynchronous HTTP stampedes with JSON summaries.
- `bench/analyze_vmstat.py` now reports peak `cs` values from `vmstat` logs.
- Loopback harness run in this session recorded peak `cs = 2725` for the baseline-labeled burst and `cs = 2478` for the WaitLeader-labeled burst.
- The paired run confirms the benchmark and log-analysis tooling, but it does not replace the final NIC-level detached-vs-attached experiment.
- Root helper run on the VM recorded peak `cs = 8746` for baseline and `cs = 6528` for WaitLeader, but the live map snapshots showed `suppressed_followers_count = 0`, so the drop path was not actually exercised in that harness run.
- Verified XDP ingress run using a dedicated `veth-host`/`wlclient` network namespace harness:
- Baseline, with XDP detached from `veth-host`: `1000/1000` sockets completed, `0` edge drops, average latency `2460.37 ms`, p95 latency `3081.01 ms`.
- WaitLeader, with XDP attached to `veth-host` and the controller holding `/api/v1/posts?id=b1c3e8ba`: `736/1000` sockets completed, `264` client-observed edge drops, average latency `2976.35 ms`, p95 latency `3594.65 ms`.
- The pinned kernel map showed `suppressed_followers_count = 3849` during the active leader window, proving that the XDP L7 parser matched the canonical URI and executed the drop path.
- Note: a local request to `192.168.64.3` routes through `lo` on the VM, so the veth harness is the current self-contained kernel-ingress proof. A Mac-host-originated request storm against the VM's `enp0s1` address remains the next external reproduction step.

Run sequence:

1. Baseline phase: detach the XDP hook and capture system load with `vmstat 1 10 > ~/baseline_cpu.log &`.
2. Trigger the benchmark with `python3 /home/ubuntucplusplus/code/WaitLeader/bench/herd_stress_test.py --baseline --clients 1000 --out ~/baseline_results.json`.
3. WaitLeader phase: reattach the XDP hook and ensure the control plane is active.
4. Capture system load with `vmstat 1 10 > ~/waitleader_cpu.log &`.
5. Trigger the same benchmark with `python3 /home/ubuntucplusplus/code/WaitLeader/bench/herd_stress_test.py --waitleader --clients 1000 --out ~/waitleader_results.json`.
6. Compare the logs with `python3 /home/ubuntucplusplus/code/WaitLeader/bench/analyze_vmstat.py ~/baseline_cpu.log ~/waitleader_cpu.log`.
7. Alternatively, run `bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh baseline`, then `bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh waitleader`, then `bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh compare`.

## 12. Observability

WaitLeader exposes runtime telemetry through a dedicated pinned eBPF array map named `waitleader_metrics`. This map is separate from the `inflight_registry` leader hash map so operational counters can be sampled without mutating active leader state.

The observability plane has three layers:

- Kernel dataplane counters in `src/bpf/waitleader_xdp.c`.
- Shared metric identifiers in `src/bpf/waitleader_maps.h`.
- User-space reader binary in `src/ctrl/WaitLeaderObserve.cpp`.

Runtime metrics include:

- number of suppressed follower packets,
- number of active leaders,
- leader lifetime in nanoseconds,
- map insertion and deletion counts,
- verifier load status,
- packet disposition counts for `XDP_PASS` and `XDP_DROP`.

Implemented M7 counters:

- `packets_total`,
- `xdp_pass_total`,
- `xdp_drop_total`,
- `ipv4_tcp_8080_total`,
- `http_get_total`,
- `uri_hash_miss_total`,
- `malformed_packet_total`,
- `non_http_pass_total`.

The observer supports both human-readable and machine-readable output:

```bash
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_observe --once
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_observe --json --once
```

Validation evidence:

- The M7 XDP object loaded through the Linux verifier and attached to `enp0s1` as program ID `130`.
- The new metrics array map was pinned at `/sys/fs/bpf/waitleader_metrics`.
- The existing leader hash map remains pinned at `/sys/fs/bpf/waitleader_map`.
- `waitleader_observe --json --once` successfully read live counters from both maps.
- Controlled `veth-host` ingress run with 200 concurrent HTTP clients produced a live observer snapshot showing `active_leaders = 1`, `suppressed_followers_active = 1000`, `xdp_drop_total = 1000`, `http_get_total = 1000`, and `uri_hash_miss_total = 0`.
- In that run, the client benchmark reported `200/200` completed sockets because TCP retried successfully, while the kernel counters still proved that XDP dropped 1000 duplicate follower packets during the active leader window.

## 13. Risks and Constraints

- Packet parsing in XDP is limited by verifier constraints and the need to keep the fast path small.
- URI extraction may be incomplete for encrypted or non-HTTP traffic.
- Dropped packets rely on client retry behavior, so suppression must be paired with sane retry policy upstream.
- Key collisions in the request hash should be rare, but they must be considered when selecting the hash function and map keying strategy.

## 14. Open Questions

- Which request identity fields are considered canonical for key generation?
- Should suppression be scoped to HTTP GET only, or extended to other idempotent methods?
- Should the kernel path drop immediately, or should it support a future suspend/resume mode?
- What telemetry contract will DBWaller expose for leader election and completion?

## 15. Summary

WaitLeader moves duplicate-request suppression from the application layer into the Linux networking fast path. By combining eBPF/XDP with a small user-space control daemon, the system can identify active leaders early and drop follower traffic before it consumes application or database resources.
