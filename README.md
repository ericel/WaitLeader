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
- `Pending` M3 through M6

## Build

```bash
cd /home/ubuntucplusplus/code/WaitLeader
cmake -S . -B build
cmake --build build
```

This builds:

- `build/waitleader_xdp.o`
- `build/waitleader_ctrl`

## Run

### 1. Load and attach the XDP program

The object can be loaded with `bpftool` and attached to the NIC:

```bash
sudo bpftool -d prog load /home/ubuntucplusplus/code/WaitLeader/build/waitleader_xdp.o /sys/fs/bpf/waitleader_xdp type xdp
sudo bpftool net attach xdp pinned /sys/fs/bpf/waitleader_xdp dev enp0s1
```

### 2. Pin the inflight map

Find the map ID:

```bash
sudo bpftool map show
```

Then pin the map:

```bash
sudo bpftool map pin id <MAP_ID> /sys/fs/bpf/waitleader_map
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

## Notes

- The controller expects the pinned map at `/sys/fs/bpf/waitleader_map`.
- The XDP program currently uses a synthetic key derived from TCP source port and sequence number for the first milestone flow.
- See `docs/software-design-document.md` for the milestone roadmap and validation evidence.
