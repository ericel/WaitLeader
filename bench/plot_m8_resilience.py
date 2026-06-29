#!/usr/bin/env python3
"""Render WaitLeader M8 protocol-resilience counters as a vector SVG chart."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


SERIES = [
    ("ipv4_tcp_8080_total", "IPv4 TCP/8080 classified", "#1f66d1"),
    ("ipv6_tcp_8080_total", "IPv6 TCP/8080 classified", "#0b7a28"),
    ("fragmented_pass_total", "IPv4 fragments passed", "#b45309"),
    ("malformed_packet_total", "Malformed/partial packets passed", "#b42318"),
]


def load_samples(path: Path) -> list[dict[str, int]]:
    samples: list[dict[str, int]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            samples.append(json.loads(line))
    if not samples:
        raise SystemExit(f"No JSON samples found in {path}")
    return samples


def delta_series(samples: list[dict[str, int]], key: str) -> list[int]:
    first = int(samples[0].get(key, 0))
    return [int(sample.get(key, 0)) - first for sample in samples]


def make_points(values: list[int], width: int, height: int, margin: int, max_value: int) -> str:
    chart_width = width - (2 * margin)
    chart_height = height - (2 * margin)
    if len(values) == 1:
        xs = [margin]
    else:
        xs = [margin + idx * chart_width / (len(values) - 1) for idx in range(len(values))]
    ys = [height - margin - (value / max_value * chart_height) for value in values]
    return " ".join(f"{x:.2f},{y:.2f}" for x, y in zip(xs, ys))


def render_svg(samples: list[dict[str, int]], output: Path) -> None:
    width = 1200
    height = 720
    margin = 92
    chart_height = height - (2 * margin)

    deltas = {key: delta_series(samples, key) for key, _, _ in SERIES}
    max_value = max(max(values) for values in deltas.values())
    max_value = max(max_value, 1)

    grid = []
    labels = []
    for idx in range(6):
        y = height - margin - (idx * chart_height / 5)
        value = round(max_value * idx / 5)
        grid.append(f'<line x1="{margin}" y1="{y:.2f}" x2="{width - margin}" y2="{y:.2f}" class="grid" />')
        labels.append(f'<text x="{margin - 18}" y="{y + 5:.2f}" class="tick" text-anchor="end">{value}</text>')

    x_labels = []
    for idx in range(6):
        x = margin + idx * (width - 2 * margin) / 5
        sample_idx = round((len(samples) - 1) * idx / 5)
        x_labels.append(f'<text x="{x:.2f}" y="{height - 42}" class="tick" text-anchor="middle">{sample_idx}</text>')

    polylines = []
    legend = []
    for idx, (key, label, color) in enumerate(SERIES):
        pts = make_points(deltas[key], width, height, margin, max_value)
        dash = ' stroke-dasharray="10 8"' if "fragmented" in key else ""
        polylines.append(
            f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="4"'
            f' stroke-linejoin="round" stroke-linecap="round"{dash} />'
        )
        y = 142 + (idx * 36)
        legend.append(f'<line x1="805" y1="{y}" x2="860" y2="{y}" stroke="{color}" stroke-width="4"{dash} />')
        legend.append(
            f'<text x="875" y="{y + 6}" class="label">{label}: '
            f'<tspan class="metric">{deltas[key][-1]}</tspan></text>'
        )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <style>
    .bg {{ fill: #fbfaf7; }}
    .title {{ font: 700 34px Georgia, serif; fill: #202020; }}
    .subtitle {{ font: 18px Georgia, serif; fill: #555; }}
    .axis {{ stroke: #222; stroke-width: 2; }}
    .grid {{ stroke: #d7d2c8; stroke-width: 1; }}
    .tick {{ font: 15px Georgia, serif; fill: #666; }}
    .label {{ font: 18px Georgia, serif; fill: #333; }}
    .metric {{ font: 700 18px Georgia, serif; fill: #222; }}
    .legend-box {{ fill: #ffffff; stroke: #e4ded2; stroke-width: 1; }}
  </style>
  <rect class="bg" width="100%" height="100%" />
  <text x="{margin}" y="52" class="title">WaitLeader M8 Protocol Resilience</text>
  <text x="{margin}" y="84" class="subtitle">Dual-stack classification and graceful pass-through counters from pinned eBPF maps</text>
  {''.join(grid)}
  {''.join(labels)}
  {''.join(x_labels)}
  <line x1="{margin}" y1="{height - margin}" x2="{width - margin}" y2="{height - margin}" class="axis" />
  <line x1="{margin}" y1="{margin}" x2="{margin}" y2="{height - margin}" class="axis" />
  <text x="{width / 2}" y="{height - 14}" class="label" text-anchor="middle">Observer sample index</text>
  <text x="30" y="{height / 2}" class="label" text-anchor="middle" transform="rotate(-90 30 {height / 2})">Cumulative packets</text>
  {''.join(polylines)}
  <rect x="780" y="108" width="335" height="176" rx="18" class="legend-box" />
  {''.join(legend)}
  <text x="{margin}" y="{height - 82}" class="subtitle">Policy: IPv4 fragments and IPv6 extension chains degrade to user-space coalescing.</text>
</svg>
"""
    output.write_text(svg, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot WaitLeader M8 protocol resilience JSONL as SVG")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    render_svg(load_samples(args.input), args.output)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
