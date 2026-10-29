"""Compile and run the C analyzer against real_packet_fixtures.json.

Use a host C99 compiler selected from --compiler, CC, or PATH. On hosts without
a native compiler, --prepare-only exports the runner's binary input.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import shutil
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "firmware" / "generated_batch" / "real_packet_fixtures.json"
HARNESS = ROOT / "tools" / "batch_fixture_replay.c"
ANALYZER_DIR = ROOT / "rmii" / "examples" / "analyzer"
MODEL_DIR = ROOT / "firmware" / "generated_batch"


def write_string(output, value: str) -> None:
    encoded = value.encode("utf-8")
    if len(encoded) > 65535:
        raise ValueError("fixture string exceeds binary format limit")
    output.write(struct.pack("<H", len(encoded)))
    output.write(encoded)


def write_fixture_binary(fixture: dict, output_path: Path) -> None:
    prefixes = fixture["capture_prefixes"]
    cases_by_capture: dict[str, list[dict]] = {}
    for case in fixture["cases"]:
        cases_by_capture.setdefault(case["capture_file"], []).append(case)

    with output_path.open("wb") as output:
        output.write(b"BPF1")
        output.write(struct.pack("<I", len(prefixes)))
        for prefix in prefixes:
            write_string(output, prefix["capture_file"])
            frames = prefix["frames"]
            output.write(struct.pack("<I", len(frames)))
            for frame in frames:
                packet = base64.b64decode(frame["ethernet_frame_base64"], validate=True)
                timestamp_us = round(float(frame["timestamp"]) * 1_000_000)
                output.write(struct.pack("<IQI", int(frame["frame_index"]), timestamp_us, len(packet)))
                output.write(packet)

            cases = cases_by_capture.get(prefix["capture_file"], [])
            output.write(struct.pack("<I", len(cases)))
            for case in cases:
                protocol = 0 if case["protocol"] == "GOOSE" else 1
                indices = [int(index) for index in case["batch_frame_indices"]]
                if len(indices) > 255:
                    raise ValueError("fixture case has too many batch frame indices")
                names = case["feature_names"]
                if len(names) not in (52, 72) or set(names) != set(case["features"]):
                    raise ValueError(f"{case['case_id']} feature order does not match the feature map")
                output.write(struct.pack("<B", protocol))
                write_string(output, case["case_id"])
                output.write(struct.pack("<B", len(indices)))
                for index in indices:
                    output.write(struct.pack("<I", index))
                output.write(struct.pack("<I", len(names)))
                for name in names:
                    write_string(output, name)
                    output.write(struct.pack("<f", float(case["features"][name])))
                output.write(struct.pack(
                    "<ff",
                    float(case["expected_probability_float32_inputs"]),
                    float(case["threshold"]),
                ))


def locate_compiler(requested: str | None) -> list[str] | None:
    candidate = requested or os.environ.get("CC")
    if candidate:
        command = shlex.split(candidate, posix=os.name != "nt")
        if command and (Path(command[0]).is_file() or shutil.which(command[0])):
            return command
        return None
    for name in ("clang", "gcc", "cc"):
        found = shutil.which(name)
        if found:
            return [found]
    return None


def compiler_environment(compiler: list[str]) -> dict[str, str]:
    environment = os.environ.copy()
    compiler_path = Path(compiler[0])
    if not compiler_path.is_file():
        located = shutil.which(compiler[0])
        if located:
            compiler_path = Path(located)
    if compiler_path.is_file():
        compiler_directory = str(compiler_path.resolve().parent)
        path_entries = environment.get("PATH", "").split(os.pathsep)
        if compiler_directory not in path_entries:
            environment["PATH"] = compiler_directory + os.pathsep + environment.get("PATH", "")
    return environment


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--compiler", help="host C99 compiler command (or set CC)")
    parser.add_argument("--prepare-only", action="store_true", help="write the binary runner input without compiling")
    parser.add_argument("--binary", type=Path, help="binary input output path with --prepare-only")
    args = parser.parse_args()

    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    if not fixture.get("model_inputs_exclude_labels"):
        raise ValueError("fixture does not certify that labels are excluded from model inputs")
    if args.prepare_only:
        if args.binary is None:
            parser.error("--prepare-only requires --binary")
        args.binary.parent.mkdir(parents=True, exist_ok=True)
        write_fixture_binary(fixture, args.binary)
        print(f"wrote {args.binary} ({args.binary.stat().st_size} bytes)")
        return 0

    compiler = locate_compiler(args.compiler)
    if compiler is None:
        print("No native C99 compiler found. Install clang/gcc or set CC; "
              "the analyzer ARM executable cannot run on the host. Use --prepare-only --binary <path> to export input.")
        return 2

    compiler_env = compiler_environment(compiler)

    with tempfile.TemporaryDirectory(prefix="batch-fixture-") as temp_dir:
        temp_path = Path(temp_dir)
        binary = temp_path / "fixture.bin"
        executable = temp_path / ("fixture_replay.exe" if os.name == "nt" else "fixture_replay")
        write_fixture_binary(fixture, binary)
        command = [
            *compiler,
            "-std=c99",
            "-O2",
            "-Wall",
            "-Wextra",
            "-I",
            str(ANALYZER_DIR),
            "-I",
            str(MODEL_DIR),
            str(HARNESS),
            str(ANALYZER_DIR / "analyzer.c"),
            str(MODEL_DIR / "generated_batch_models.c"),
            "-lm",
            "-o",
            str(executable),
        ]
        subprocess.run(command, cwd=ROOT, env=compiler_env, check=True)
        result = subprocess.run(
            [str(executable), str(binary)], cwd=ROOT, env=compiler_env, check=False
        )
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
