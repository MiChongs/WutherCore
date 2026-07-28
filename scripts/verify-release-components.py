"""Assert that release archives carry the component set each platform promises.

The build matrix picks a component preset per target, so a preset regression is
invisible from the outside: the release still produces nine archives, they still
install, and the missing protocol only surfaces when a user loads a config that
needs it. This check reads the BUILD-COMPONENTS.txt that ships inside every
archive and fails the release when a platform lost a component it is expected
to carry.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path


# Presets that pull in with_young; see crates/wuther-core/Cargo.toml.
YOUNG_TAGS = frozenset({"with_young", "standard", "all_components"})

# Platform -> components that must be compiled into that release archive.
#
# Young embeds Mozilla NSS through nss-rs, so it reaches every target that has
# an NSS build chain. The single exception is Windows ARM64, which has no
# native NSS build and whose runner image ships no MSYS2.
EXPECTED_COMPONENTS: dict[str, frozenset[str]] = {
    "linux-amd64": frozenset({"with_young"}),
    "linux-arm64": frozenset({"with_young"}),
    "linux-amd64-musl": frozenset({"with_young"}),
    "linux-arm64-musl": frozenset({"with_young"}),
    "android-arm64": frozenset({"with_young"}),
    "android-arm": frozenset({"with_young"}),
    "windows-amd64-msvc": frozenset({"with_young"}),
    "windows-arm64-msvc": frozenset(),
    "macos-arm64": frozenset({"with_young"}),
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--version", required=True)
    return parser.parse_args()


def read_tags(archive: Path) -> set[str]:
    with zipfile.ZipFile(archive) as bundle:
        metadata = bundle.read("BUILD-COMPONENTS.txt").decode("utf-8")

    for line in metadata.splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip() == "tags":
            # Labels carry a trailing note, for example
            # "portable,with_young (platform default)".
            label = value.split("(")[0]
            return {tag.strip() for tag in label.split(",") if tag.strip()}

    raise ValueError(f"{archive.name} has no tags entry in BUILD-COMPONENTS.txt")


def resolve(tags: set[str]) -> set[str]:
    """Expand preset names into the component tags callers ask about."""
    resolved = set(tags)
    if tags & YOUNG_TAGS:
        resolved.add("with_young")
    return resolved


def main() -> int:
    args = arguments()
    failures: list[str] = []

    for platform, required in sorted(EXPECTED_COMPONENTS.items()):
        archive = args.dist / f"wuther-core-{args.version}-{platform}.zip"
        if not archive.is_file():
            failures.append(f"{platform}: archive not found at {archive}")
            continue

        try:
            tags = read_tags(archive)
        except (KeyError, ValueError, zipfile.BadZipFile) as error:
            failures.append(f"{platform}: {error}")
            continue

        resolved = resolve(tags)
        missing = sorted(required - resolved)
        label = ",".join(sorted(tags)) or "<none>"
        if missing:
            failures.append(f"{platform}: missing {', '.join(missing)} (tags: {label})")
        else:
            print(f"ok {platform}: {label}")

    if failures:
        for failure in failures:
            print(f"::error::{failure}", file=sys.stderr)
        return 1

    print(f"verified {len(EXPECTED_COMPONENTS)} release archives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
