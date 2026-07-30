#!/usr/bin/env python3
"""Generate a consolidated third-party license file for the runtime image.

Walks every installed distribution in the current environment and writes its
name, version, declared license, and license file text (when available) into
one file. Run inside the built venv so it reflects exactly what ships in the
container.
"""

import sys
from importlib import metadata
from pathlib import Path

_LICENSE_FILE_CANDIDATES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING")


def _license_text(dist: metadata.Distribution) -> str | None:
    # PEP 639 declares bundled license file name(s) via the `License-File`
    # metadata field. Packaging tools commonly place the file itself under a
    # `licenses/` subdirectory of the dist-info directory, so try both.
    for license_file in dist.metadata.get_all("License-File", []):
        for candidate in (license_file, f"licenses/{license_file}"):
            text = dist.read_text(candidate)
            if text:
                return text
    for name in _LICENSE_FILE_CANDIDATES:
        text = dist.read_text(name)
        if text:
            return text
    return None


def _declared_license(dist: metadata.Distribution) -> str:
    expression = dist.metadata.get("License-Expression")
    if expression:
        return expression
    license_field = dist.metadata.get("License")
    if license_field and license_field != "UNKNOWN":
        return license_field
    for classifier in dist.metadata.get_all("Classifier", []):
        if classifier.startswith("License ::"):
            return classifier.rsplit("::", 1)[-1].strip()
    return "UNKNOWN"


def main() -> int:
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("THIRD_PARTY_LICENSES.txt")

    distributions = sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower())

    sections = [
        "Third-party licenses for fossa-mcp's runtime dependencies.",
        "Generated from the packages actually installed in this image's venv.",
        "",
    ]
    for dist in distributions:
        name = dist.metadata["Name"]
        version = dist.metadata["Version"]
        license_name = _declared_license(dist)
        sections.append("=" * 80)
        sections.append(f"{name} {version} — {license_name}")
        sections.append("=" * 80)
        text = _license_text(dist)
        sections.append(
            text.strip() if text else "(no bundled license file; see declared license above)"
        )
        sections.append("")

    output_path.write_text("\n".join(sections), encoding="utf-8")
    print(f"Wrote {len(distributions)} package entries to {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
