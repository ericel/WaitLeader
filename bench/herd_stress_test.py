#!/usr/bin/env python3
"""Asynchronous thundering-herd benchmark harness for WaitLeader."""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8080
DEFAULT_CONCURRENT_CLIENTS = 1000
PAYLOAD = b"GET /api/v1/posts?id=b1c3e8ba HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


@dataclass
class BenchmarkResult:
    phase: str
    host: str
    port: int
    concurrent_clients: int
    completed: int
    dropped: int
    failed: int
    duration_s: float
    avg_latency_ms: float | None
    p95_latency_ms: float | None
    max_latency_ms: float | None


async def spam_client(host: str, port: int, stats: dict[str, object], timeout_s: float) -> None:
    start_t = time.perf_counter_ns()
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout_s)
        writer.write(PAYLOAD)
        await asyncio.wait_for(writer.drain(), timeout=timeout_s)

        try:
            await asyncio.wait_for(reader.read(1024), timeout=timeout_s)
        except asyncio.TimeoutError:
            pass

        end_t = time.perf_counter_ns()
        latency_ms = (end_t - start_t) / 1e6

        stats["completed"] = int(stats["completed"]) + 1
        latencies = stats["latencies"]
        assert isinstance(latencies, list)
        latencies.append(latency_ms)

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        stats["dropped"] = int(stats["dropped"]) + 1


async def trigger_stampede(host: str, port: int, concurrent_clients: int, timeout_s: float) -> BenchmarkResult:
    print(f"[*] Launching thundering herd burst: {concurrent_clients} concurrent sockets against {host}:{port}")
    stats: dict[str, object] = {"completed": 0, "dropped": 0, "latencies": []}

    start_time = time.perf_counter()
    tasks = [spam_client(host, port, stats, timeout_s) for _ in range(concurrent_clients)]
    await asyncio.gather(*tasks)
    duration = time.perf_counter() - start_time

    latencies = stats["latencies"]
    assert isinstance(latencies, list)
    avg_latency_ms = statistics.fmean(latencies) if latencies else None
    p95_latency_ms = _percentile(latencies, 95) if latencies else None
    max_latency_ms = max(latencies) if latencies else None

    return BenchmarkResult(
        phase="unspecified",
        host=host,
        port=port,
        concurrent_clients=concurrent_clients,
        completed=int(stats["completed"]),
        dropped=int(stats["dropped"]),
        failed=0,
        duration_s=duration,
        avg_latency_ms=avg_latency_ms,
        p95_latency_ms=p95_latency_ms,
        max_latency_ms=max_latency_ms,
    )


def _percentile(values: list[float], pct: int) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * (pct / 100.0)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _phase_label(baseline: bool, waitleader: bool) -> str:
    if baseline and waitleader:
        return "invalid"
    if baseline:
        return "baseline"
    if waitleader:
        return "waitleader"
    return "unspecified"


def _write_json(path: Path, result: BenchmarkResult) -> None:
    path.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="WaitLeader thundering-herd benchmark")
    parser.add_argument("--host", default=TARGET_HOST)
    parser.add_argument("--port", type=int, default=TARGET_PORT)
    parser.add_argument("--clients", type=int, default=DEFAULT_CONCURRENT_CLIENTS)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--baseline", action="store_true", help="Label the run as the traditional user-space baseline")
    parser.add_argument("--waitleader", action="store_true", help="Label the run as the eBPF/XDP run")
    parser.add_argument("--out", type=Path, help="Write a JSON summary to this path")
    args = parser.parse_args()

    phase = _phase_label(args.baseline, args.waitleader)
    if phase == "invalid":
        print("Choose exactly one of --baseline or --waitleader.", file=sys.stderr)
        return 2

    result = asyncio.run(trigger_stampede(args.host, args.port, args.clients, args.timeout))
    result.phase = phase

    print(f"\n--- Benchmark Results ({result.duration_s:.2f} seconds) ---")
    print(f" [+] Successfully Processed Sockets : {result.completed}")
    print(f" [-] Suppressed/Dropped at Edge   : {result.dropped}")
    if result.avg_latency_ms is not None:
        print(f" [~] Average Latency (Passed Req) : {result.avg_latency_ms:.2f} ms")
        print(f" [~] P95 Latency (Passed Req)     : {result.p95_latency_ms:.2f} ms")
        print(f" [~] Max Latency (Passed Req)     : {result.max_latency_ms:.2f} ms")

    if args.out:
        _write_json(args.out, result)
        print(f"\n[+] Wrote JSON summary to {args.out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
