"""Validate repository-facing files without third-party dependencies."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "ROADMAP.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "GOVERNANCE.md",
    "SECURITY.md",
    "SUPPORT.md",
    ".github/CODEOWNERS",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    "docs/README.md",
    "docs/FEATURES.md",
    "docs/CONFIGURATION.md",
    "docs/ARCHITECTURE.md",
    "docs/API.md",
    "docs/TROUBLESHOOTING.md",
    "docs/RELEASING.md",
    "docs/assets/wuthercore-hero.jpg",
)

MARKDOWN_LINK = re.compile(r"!?\[[^\]]*]\(([^)\s]+)")
HTML_LINK = re.compile(r"""(?:href|src)=["']([^"']+)["']""", re.IGNORECASE)
IGNORED_SCHEMES = {"http", "https", "mailto", "data", "javascript"}


def markdown_files() -> list[Path]:
    excluded_parts = {".git", "target", "dist", ".codebase-memory"}
    return sorted(
        path
        for path in ROOT.rglob("*.md")
        if not excluded_parts.intersection(path.relative_to(ROOT).parts)
    )


def local_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().strip("<>")
    if not target or target.startswith("#") or "${{" in target:
        return None

    parsed = urlsplit(target)
    if parsed.scheme.lower() in IGNORED_SCHEMES or parsed.netloc:
        return None

    path_part = unquote(parsed.path)
    if not path_part:
        return None

    if path_part.startswith("/"):
        return ROOT / path_part.lstrip("/")
    return source.parent / path_part


def check_required_files(errors: list[str]) -> None:
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).exists():
            errors.append(f"missing required file: {relative}")


def check_local_links(errors: list[str]) -> int:
    checked = 0
    for source in markdown_files():
        text = source.read_text(encoding="utf-8")
        targets = [match.group(1) for match in MARKDOWN_LINK.finditer(text)]
        targets.extend(match.group(1) for match in HTML_LINK.finditer(text))
        for raw_target in targets:
            target = local_target(source, raw_target)
            if target is None:
                continue
            checked += 1
            if not target.exists():
                source_name = source.relative_to(ROOT).as_posix()
                errors.append(f"broken local link: {source_name} -> {raw_target}")
    return checked


def check_hero(errors: list[str]) -> None:
    hero = ROOT / "docs/assets/wuthercore-hero.jpg"
    if not hero.exists():
        return
    size = hero.stat().st_size
    if size >= 1_048_576:
        errors.append(f"hero image must stay below 1 MiB, got {size} bytes")
    with hero.open("rb") as handle:
        if handle.read(2) != b"\xff\xd8":
            errors.append("hero image is not a valid JPEG file")


def main() -> int:
    errors: list[str] = []
    check_required_files(errors)
    checked_links = check_local_links(errors)
    check_hero(errors)

    if errors:
        print("Repository checks failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(
        f"Repository checks passed: {len(markdown_files())} Markdown files, "
        f"{checked_links} local links"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
