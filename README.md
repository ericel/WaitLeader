# WaitLeader

WaitLeader is a kernel-assisted request coalescing prototype built around eBPF and XDP. It moves duplicate-request suppression into the Linux networking fast path so a live leader can block follower traffic before it reaches the application layer.

## What’s In The Repo

- `src/bpf/` - XDP/eBPF fast data plane
- `src/ctrl/` - C++20 control plane and map bridge
- `tests/` - verifier and integration checks
- `bench/` - stress and benchmark tooling
- `docs/` - software design documentation and milestone tracking

## Current Status

- `✅ M1` Fast Data Plane: loaded, verified, and attached to `enp0s1`
- `✅ M2` Control Plane: pinned-map bridge implemented and validated
- `✅ M3` L7 Parser: HTTP GET URI extraction and FNV-1a canonical hashing validated
- `✅ M4` DBWaller integration mock validated
- `✅ M5` CTest memory suite validated
- `✅ M6` Empirical study: XDP ingress benchmark validated with kernel suppression counters
- `✅ M7` Observability: live pinned-map telemetry exposed through `waitleader_observe`
- `✅ M8` Protocol Resilience: IPv6 branch, IPv4 fragmentation pass-through, and TCP retransmission model implemented
- `✅ M9` Encrypted Data Plane: verifier-accepted SK_MSG hook for post-decryption plaintext inspection
- `✅ M10` Semantic-Aware Controller: HTTP/2 user-space semantics with kernel stream-policy enforcement

## Build

```bash
cd /home/ubuntucplusplus/code/WaitLeader
cmake -S . -B build
cmake --build build
```

This builds:

- `build/waitleader_xdp.o`
- `build/waitleader_sk_msg.o`
- `build/waitleader_ctrl`
- `build/waitleader_observe`
- `build/waitleader_h2_policy`

## Run

### 1. Load and attach the XDP program

The object can be loaded with `bpftool` and attached to the NIC:

```bash
sudo bpftool -d prog load /home/ubuntucplusplus/code/WaitLeader/build/waitleader_xdp.o /sys/fs/bpf/waitleader_xdp type xdp
sudo bpftool net attach xdp pinned /sys/fs/bpf/waitleader_xdp dev enp0s1
```

### 2. Pin the inflight and metrics maps

Find the map IDs:

```bash
sudo bpftool map show
```

Then pin the maps:

```bash
sudo bpftool map pin id <INFLIGHT_MAP_ID> /sys/fs/bpf/waitleader_map
sudo bpftool map pin id <METRICS_MAP_ID> /sys/fs/bpf/waitleader_metrics
```

### 3. Run the user-space controller

```bash
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_ctrl
```

### 4. Reload the M3 parser

If you are swapping in the URI-parsing XDP program, remove any stale pin first and then reload:

```bash
sudo rm -f /sys/fs/bpf/waitleader_xdp_m3
sudo bpftool prog load /tmp/waitleader_xdp.o /sys/fs/bpf/waitleader_xdp_m3 type xdp
sudo bpftool net attach xdp pinned /sys/fs/bpf/waitleader_xdp_m3 dev enp0s1
```

Then verify the active hook:

```bash
sudo bpftool net show
```

### 5. Milestone 4 mock integration

Run the DBWaller integration mock and inspect the pinned map from a second terminal while Thread 0 sleeps:

```bash
cd /home/ubuntucplusplus/code/WaitLeader/build
make
sudo ./dbwaller_xdp_mock
```

In another terminal:

```bash
sudo bpftool map dump pinned /sys/fs/bpf/waitleader_map
```

You should see the canonical 64-bit key for `/api/v1/posts?id=b1c3e8ba` while the leader is active.

### 6. Milestone 5 memory suite

Reconfigure, rebuild, and run the CTest suite:

```bash
cd /home/ubuntucplusplus/code/WaitLeader/build
cmake ..
make
sudo ctest --output-on-failure
```

The `MemoryLeakValidation` test checks that the RAII guard cleans up the pinned map across 10,000 leader elections.

### 7. Milestone 6 empirical study

Capture baseline and WaitLeader CPU logs, run the benchmark, then compare peak context-switch rates:

```bash
vmstat 1 10 > ~/baseline_cpu.log &
python3 /home/ubuntucplusplus/code/WaitLeader/bench/herd_stress_test.py --baseline --clients 1000 --out ~/baseline_results.json

vmstat 1 10 > ~/waitleader_cpu.log &
python3 /home/ubuntucplusplus/code/WaitLeader/bench/herd_stress_test.py --waitleader --clients 1000 --out ~/waitleader_results.json

python3 /home/ubuntucplusplus/code/WaitLeader/bench/analyze_vmstat.py ~/baseline_cpu.log ~/waitleader_cpu.log
```

Or use the helper script:

```bash
bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh baseline
bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh waitleader
bash /home/ubuntucplusplus/code/WaitLeader/bench/run_m6.sh compare
```

For a self-contained XDP ingress proof on the VM, use a veth/network-namespace harness rather than localhost. Local requests to `192.168.64.3` route through `lo`, which bypasses the `enp0s1` XDP hook.

Latest validated veth results:

- Baseline with XDP detached from `veth-host`: `1000/1000` sockets completed, `0` edge drops.
- WaitLeader with XDP attached to `veth-host`: `736/1000` sockets completed, `264` client-observed edge drops.
- Live pinned-map inspection during the leader window showed `suppressed_followers_count = 3849`.

### 8. Milestone 7 observability

Read live dataplane and leader-state telemetry:

```bash
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_observe --once
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_observe --json --once
```

Available counters include:

- `packets_total`
- `xdp_pass_total`
- `xdp_drop_total`
- `ipv4_tcp_8080_total`
- `http_get_total`
- `uri_hash_miss_total`
- `malformed_packet_total`
- `non_http_pass_total`
- `ipv6_tcp_8080_total`
- `fragmented_pass_total`
- `retransmission_drop_total`
- `sk_msg_total`
- `sk_msg_pass_total`
- `sk_msg_drop_total`
- `tls_http1_get_total`
- `tls_http2_preface_total`
- `tls_http2_unsupported_total`
- `tls_http2_headers_total`
- `tls_http2_path_total`
- `tls_http2_hpack_unsupported_total`
- `h2_stream_policy_hit_total`
- `h2_stream_policy_drop_total`
- `active_leaders`
- `suppressed_followers_active`
- `active_h2_stream_policies`
- `suppressed_h2_stream_followers_active`

Latest observability validation:

- Controlled `veth-host` ingress run: `active_leaders = 1`.
- Kernel dataplane reported `xdp_drop_total = 1000`.
- Kernel dataplane reported `http_get_total = 1000`.
- Active leader record reported `suppressed_followers_active = 1000`.

Defense artifacts:

- Raw observer capture: `docs/artifacts/m7_defense_metrics.jsonl`
- Figure 4 SVG: `docs/artifacts/m7_xdp_pass_vs_drop.svg`
- Plot generator: `bench/plot_m7_metrics.py`

### 9. Milestone 8 protocol resilience

The XDP fast path now supports production variability without trying to do unsafe stream reconstruction in kernel space:

- IPv4 and IPv6 branch separately at Layer 3.
- IPv4 fragments pass immediately to DBWaller user space.
- IPv6 TCP traffic is parsed when `nexthdr == IPPROTO_TCP`.
- IPv6 extension-header chains pass to user space.
- XDP drops rely on the client TCP retransmission timeout as the external waiting queue.

Latest M8 validation:

- M8 bytecode loaded through the Linux verifier.
- Active `enp0s1` XDP program ID: `74`.
- Dual-stack veth harness observed `ipv4_tcp_8080_total = 60`.
- Dual-stack veth harness observed `ipv6_tcp_8080_total = 60`.
- Forced oversized IPv4 packet observed `fragmented_pass_total = 2`.

Defense artifacts:

- Raw observer capture: `docs/artifacts/m8_protocol_resilience_metrics.jsonl`
- Summary JSON: `docs/artifacts/m8_protocol_resilience_summary.json`
- Figure 5 SVG: `docs/artifacts/m8_protocol_resilience.svg`
- Plot generator: `bench/plot_m8_resilience.py`

### 10. Milestone 9 encrypted data plane

XDP cannot inspect TLS ciphertext, so M9 adds a separate SK_MSG eBPF program for post-decryption socket-message inspection.

Build and verifier-load the SK_MSG bytecode:

```bash
cd /home/ubuntucplusplus/code/WaitLeader
cmake --build build --target sk_msg_bytecode
sudo rm -f /sys/fs/bpf/waitleader_sk_msg_m9
sudo bpftool prog load build/waitleader_sk_msg.o /sys/fs/bpf/waitleader_sk_msg_m9 type sk_msg
sudo bpftool prog show pinned /sys/fs/bpf/waitleader_sk_msg_m9
```

Latest M9 validation:

- `waitleader_sk_msg.o` compiled successfully.
- Kernel verifier accepted `BPF_PROG_TYPE_SK_MSG`.
- Initial loaded SK_MSG program ID: `104`.
- HTTP/2 bounded-HEADERS SK_MSG program ID: `117`.
- Latest JITed size: `9880B`.

Defense artifacts:

- Verifier summary JSON: `docs/artifacts/m9_sk_msg_verifier_summary.json`
- Figure 6 SVG: `docs/artifacts/m9_encrypted_dataplane.svg`

Current boundary:

- Decrypted HTTP/1.1-style `GET` text can be hashed and suppressed with `SK_DROP`.
- HTTP/2 HEADERS frames are supported when `:method GET` is static-indexed and `:path` is either static-indexed `/` or a non-Huffman literal using the static indexed `:path` name.
- HTTP/2 Huffman strings, dynamic-table references, PADDED/PRIORITY HEADERS, and CONTINUATION frames pass to user space until broader HPACK support or a user-space canonical-key assist is implemented.

### 11. Milestone 10 semantic-aware controller

M10 implements the hybrid-offload strategy for full HTTP/2 correctness:

- DBWaller/nghttp2 decodes HPACK and computes the semantic cache key in user space.
- User space installs a compact `{conn_id, stream_id}` policy into `/sys/fs/bpf/waitleader_h2_streams`.
- SK_MSG checks the stream policy map and can return `SK_DROP` without decoding HPACK.

Register a sample semantic policy:

```bash
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_h2_policy 0xC001D00D 7 3
```

Observe stream policies:

```bash
sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_observe --json --once \
  --metrics-map /sys/fs/bpf/waitleader_h2_metrics \
  --leader-map /sys/fs/bpf/waitleader_h2_uri_map \
  --stream-map /sys/fs/bpf/waitleader_h2_streams
```

Latest M10 validation:

- Hybrid SK_MSG verifier load program ID: `124`.
- JITed size: `10648B`.
- `waitleader_h2_policy` inserted `{conn_id = 0xC001D00D, stream_id = 7}`.
- Observer reported `active_h2_stream_policies = 1` during the hold window.
- Observer reported `active_h2_stream_policies = 0` after release.

Defense artifacts:

- Summary JSON: `docs/artifacts/m10_semantic_policy_summary.json`
- Figure 7 SVG: `docs/artifacts/m10_hybrid_offload.svg`

## Notes

- The controller expects the pinned map at `/sys/fs/bpf/waitleader_map`.
- The observer expects the metrics map at `/sys/fs/bpf/waitleader_metrics`.
- The XDP program parses HTTP `GET` payloads and hashes the request URI with the same FNV-1a 64-bit algorithm used by the C++ control plane.
- See `docs/software-design-document.md` for the milestone roadmap and validation evidence.
