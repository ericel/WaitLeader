#!/usr/bin/env python3
"""Render WaitLeader M7 JSONL observer output as a vector SVG chart."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_samples(path: Path) -> list[dict[str, int]]:
    samples: list[dict[str, int]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        samples.append(json.loads(line))
    if not samples:
        raise SystemExit(f"No JSON samples found in {path}")
    return samples


def delta_series(samples: list[dict[str, int]], key: str) -> list[int]:
    first = int(samples[0].get(key, 0))
    return [int(sample.get(key, 0)) - first for sample in samples]


def points(values: list[int], width: int, height: int, margin: int, max_value: int) -> str:
    if len(values) == 1:
        x_values = [margin]
    else:
        x_values = [
            margin + (idx * (width - 2 * margin) / (len(values) - 1))
            for idx in range(len(values))
        ]

    y_values = [
        height - margin - ((value / max_value) * (height - 2 * margin))
        for value in values
    ]
    return " ".join(f"{x:.2f},{y:.2f}" for x, y in zip(x_values, y_values))


def render_svg(samples: list[dict[str, int]], output: Path) -> None:
    width = 1200
    height = 720
    margin = 92

    pass_values = delta_series(samples, "xdp_pass_total")
    drop_values = delta_series(samples, "xdp_drop_total")
    http_values = delta_series(samples, "http_get_total")
    max_value = max(max(pass_values), max(drop_values), max(http_values), 1)

    pass_points = points(pass_values, width, height, margin, max_value)
    drop_points = points(drop_values, width, height, margin, max_value)
    http_points = points(http_values, width, height, margin, max_value)

    x_axis_y = height - margin
    chart_width = width - 2 * margin
    chart_height = height - 2 * margin

    grid_lines = []
    y_labels = []
    for idx in range(6):
        value = round(max_value * idx / 5)
        y = x_axis_y - (idx * chart_height / 5)
        grid_lines.append(
            f'<line x1="{margin}" y1="{y:.2f}" x2="{width - margin}" y2="{y:.2f}" class="grid" />'
        )
        y_labels.append(f'<text x="{margin - 18}" y="{y + 5:.2f}" class="tick" text-anchor="end">{value}</text>')

    x_labels = []
    for idx in range(6):
        x = margin + (idx * chart_width / 5)
        sample_index = round((len(samples) - 1) * idx / 5)
        x_labels.append(f'<text x="{x:.2f}" y="{height - 42}" class="tick" text-anchor="middle">{sample_index}</text>')

    final_pass = pass_values[-1]
    final_drop = drop_values[-1]
    final_http = http_values[-1]
    active_leaders = max(int(sample.get("active_leaders", 0)) for sample in samples)
    suppressed = max(int(sample.get("suppressed_followers_active", 0)) for sample in samples)

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
    .pass {{ fill: none; stroke: #1f66d1; stroke-width: 4; stroke-linejoin: round; stroke-linecap: round; }}
    .drop {{ fill: none; stroke: #b42318; stroke-width: 4; stroke-linejoin: round; stroke-linecap: round; }}
    .http {{ fill: none; stroke: #0b7a28; stroke-width: 3; stroke-dasharray: 10 8; stroke-linejoin: round; stroke-linecap: round; }}
    .legend-box {{ fill: #ffffff; stroke: #e4ded2; stroke-width: 1; }}
  </style>
  <rect class="bg" width="100%" height="100%" />
  <text x="{margin}" y="52" class="title">WaitLeader M7 Observability: XDP Packet Disposition</text>
  <text x="{margin}" y="84" class="subtitle">Cumulative counter deltas from pinned eBPF maps during a sustained stampede burst</text>

  {''.join(grid_lines)}
  {''.join(y_labels)}
  {''.join(x_labels)}

  <line x1="{margin}" y1="{x_axis_y}" x2="{width - margin}" y2="{x_axis_y}" class="axis" />
  <line x1="{margin}" y1="{margin}" x2="{margin}" y2="{x_axis_y}" class="axis" />
  <text x="{width / 2}" y="{height - 14}" class="label" text-anchor="middle">Observer sample index</text>
  <text x="30" y="{height / 2}" class="label" text-anchor="middle" transform="rotate(-90 30 {height / 2})">Cumulative packets</text>

  <polyline points="{pass_points}" class="pass" />
  <polyline points="{drop_points}" class="drop" />
  <polyline points="{http_points}" class="http" />

  <rect x="{width - 405}" y="108" width="310" height="146" rx="18" class="legend-box" />
  <line x1="{width - 375}" y1="142" x2="{width - 320}" y2="142" class="pass" />
  <text x="{width - 305}" y="148" class="label">xdp_pass_total delta: <tspan class="metric">{final_pass}</tspan></text>
  <line x1="{width - 375}" y1="182" x2="{width - 320}" y2="182" class="drop" />
  <text x="{width - 305}" y="188" class="label">xdp_drop_total delta: <tspan class="metric">{final_drop}</tspan></text>
  <line x1="{width - 375}" y1="222" x2="{width - 320}" y2="222" class="http" />
  <text x="{width - 305}" y="228" class="label">http_get_total delta: <tspan class="metric">{final_http}</tspan></text>

  <text x="{margin}" y="{height - 82}" class="subtitle">Peak active leaders: {active_leaders} | Peak suppressed followers on active leader: {suppressed}</text>
</svg>
"""
    output.write_text(svg, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Plot WaitLeader M7 observer JSONL as SVG")
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    render_svg(load_samples(args.input), args.output)
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
