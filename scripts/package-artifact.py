"""Create a deterministic, self-describing WutherCore build archive."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--profile", default="release")
    parser.add_argument("--version", default="")
    parser.add_argument("--tags", default="standard (default)")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    return parser.parse_args()


def copy_payload(stage: Path, binary: Path, metadata: str) -> None:
    stage.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, stage / binary.name)
    for pattern in ("*.dylib", "*.so", "*.so.*", "*.dll"):
        for runtime in sorted(binary.parent.glob(pattern)):
            destination = stage / runtime.name
            if not destination.exists():
                shutil.copy2(runtime.resolve(strict=True), destination)
    shutil.copy2(ROOT / "README.md", stage / "README.md")
    shutil.copy2(ROOT / "LICENSE", stage / "LICENSE")

    license_dir = stage / "licenses"
    license_dir.mkdir()
    shutil.copy2(
        ROOT / "third_party/xray-transport/LICENSE-MPL-2.0",
        license_dir / "xray-transport-MPL-2.0.txt",
    )
    shutil.copytree(ROOT / "examples", stage / "examples")
    (stage / "BUILD-COMPONENTS.txt").write_text(metadata, encoding="utf-8")


def add_file(archive: zipfile.ZipFile, source: Path, relative: Path) -> None:
    info = zipfile.ZipInfo(relative.as_posix(), FIXED_TIMESTAMP)
    mode = source.stat().st_mode
    info.external_attr = (stat.S_IMODE(mode) & 0xFFFF) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    with source.open("rb") as handle:
        archive.writestr(info, handle.read(), compresslevel=9)


def create_archive(stage: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, "w", allowZip64=True) as archive:
        for source in sorted(path for path in stage.rglob("*") if path.is_file()):
            add_file(archive, source, source.relative_to(stage))


def main() -> int:
    args = arguments()
    executable = "wuther-core.exe" if "windows" in args.target else "wuther-core"
    binary = ROOT / "target" / args.target / args.profile / executable
    if not binary.is_file():
        raise FileNotFoundError(f"build artifact not found: {binary}")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    suffix = f"-{args.version}" if args.version else ""
    archive_path = output / f"wuther-core{suffix}-{args.platform}.zip"
    stage = output / f".stage-{args.platform}"
    if stage.exists():
        shutil.rmtree(stage)

    metadata = (
        f"version={args.version or 'workspace'}\n"
        f"target={args.target}\n"
        f"tags={args.tags}\n"
    )
    try:
        copy_payload(stage, binary, metadata)
        create_archive(stage, archive_path)
    finally:
        if stage.exists():
            shutil.rmtree(stage)

    relative = archive_path.relative_to(ROOT) if archive_path.is_relative_to(ROOT) else archive_path
    print(relative.as_posix())
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with Path(github_output).open("a", encoding="utf-8") as handle:
            handle.write(f"archive={relative.as_posix()}\n")
            handle.write(f"name={archive_path.name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
