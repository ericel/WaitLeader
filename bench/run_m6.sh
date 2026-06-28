#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="/home/ubuntucplusplus/code/WaitLeader"
BENCH="${ROOT_DIR}/bench/herd_stress_test.py"
ANALYZER="${ROOT_DIR}/bench/analyze_vmstat.py"

baseline_phase() {
  sudo bpftool net detach xdp dev enp0s1 || true
  vmstat 1 10 > "${HOME}/baseline_cpu.log" &
  local vmstat_pid=$!
  python3 "${BENCH}" --baseline --clients 1000 --out "${HOME}/baseline_results.json"
  wait "${vmstat_pid}" || true
}

waitleader_phase() {
  sudo bpftool net attach xdp pinned /sys/fs/bpf/waitleader_xdp_m3 dev enp0s1
  sudo /home/ubuntucplusplus/code/WaitLeader/build/waitleader_ctrl &
  local ctrl_pid=$!
  sleep 2
  vmstat 1 10 > "${HOME}/waitleader_cpu.log" &
  local vmstat_pid=$!
  (
    : > "${HOME}/m6_waitleader_map_snapshots.log"
    for _ in $(seq 1 10); do
      sudo bpftool map dump pinned /sys/fs/bpf/waitleader_map >> "${HOME}/m6_waitleader_map_snapshots.log" 2>/dev/null || true
      printf '\n---\n' >> "${HOME}/m6_waitleader_map_snapshots.log"
      sleep 1
    done
  ) &
  local mapwatch_pid=$!
  python3 "${BENCH}" --waitleader --clients 1000 --out "${HOME}/waitleader_results.json"
  wait "${vmstat_pid}" || true
  wait "${mapwatch_pid}" || true
  kill "${ctrl_pid}" || true
}

case "${1:-}" in
  baseline)
    baseline_phase
    ;;
  waitleader)
    waitleader_phase
    ;;
  compare)
    python3 "${ANALYZER}" "${HOME}/baseline_cpu.log" "${HOME}/waitleader_cpu.log"
    ;;
  *)
    cat <<'EOF'
Usage: bench/run_m6.sh {baseline|waitleader|compare}
EOF
    exit 1
    ;;
esac
