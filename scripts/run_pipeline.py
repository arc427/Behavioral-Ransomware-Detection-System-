"""Build a labelled, windowed dataset from Sysmon XML or EVTX inputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline.event_filter import filter_sysmon_events
from pipeline.evtx_reader import read_events
from pipeline.temporal_aggregator import aggregate_process_windows
from pipeline.vectorizer import vectorize


def scenario_metadata(path: Path) -> tuple[str, str]:
    parts = path.parts
    try:
        index = parts.index("attack_techniques")
        return parts[index + 1], parts[index + 2]
    except (ValueError, IndexError):
        return "unknown", path.parent.name


def build_dataset(inputs: list[Path], window_seconds: int, label: int, source_kind: str) -> pd.DataFrame:
    windows: list[pd.DataFrame] = []
    for source in inputs:
        events = filter_sysmon_events(read_events(source))
        frame = aggregate_process_windows(events, window_seconds)
        if frame.empty:
            continue
        technique, scenario = scenario_metadata(source)
        frame["label"] = label
        frame["technique_id"] = technique
        frame["scenario"] = scenario
        frame["source"] = str(source)
        frame["source_kind"] = source_kind
        windows.append(frame)
    return pd.concat(windows, ignore_index=True) if windows else pd.DataFrame()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=ROOT / "data/datasets/splunk_attack_data/datasets", help="Attack Sysmon log or directory")
    parser.add_argument("--benign-input", type=Path, action="append", default=[], help="Benign Sysmon log or directory; may be supplied more than once")
    parser.add_argument("--output", type=Path, default=ROOT / "data/processed/sysmon_attack_windows.csv")
    parser.add_argument("--window-seconds", type=int, default=5)
    args = parser.parse_args()
    attack_inputs = sorted(args.input.rglob("windows-sysmon.log")) if args.input.is_dir() else [args.input]
    dataset = build_dataset(attack_inputs, args.window_seconds, label=1, source_kind="attack")
    benign_frames = []
    for benign_path in args.benign_input:
        benign_inputs = sorted(benign_path.rglob("*.log")) if benign_path.is_dir() else [benign_path]
        benign_frames.append(build_dataset(benign_inputs, args.window_seconds, label=0, source_kind="benign"))
    if benign_frames:
        dataset = pd.concat([dataset, *benign_frames], ignore_index=True)
    if dataset.empty:
        raise SystemExit("No supported Sysmon events were found.")
    _, columns = vectorize(dataset)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    dataset.to_csv(args.output, index=False)
    print(f"Wrote {len(dataset)} windows with {len(columns)} numeric features to {args.output}")


if __name__ == "__main__":
    main()
