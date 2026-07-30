#!/usr/bin/env python3
"""Script to update the FOSSA OpenAPI specification."""

import json
import sys
import os
from datetime import datetime
import hashlib
import httpx

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from fossa_mcp.config import Settings


def main():
    """Update the FOSSA OpenAPI specification."""

    # Define the source URL and target file paths
    source_url = "https://app.fossa.com/api/api-docs/swagger.json"
    target_file = os.path.join("spec", "fossa-openapi.json")
    readme_file = os.path.join("spec", "README.md")

    # Create spec directory if it doesn't exist
    os.makedirs("spec", exist_ok=True)

    try:
        # Fetch the OpenAPI specification
        print(f"Fetching OpenAPI specification from {source_url}...")
        response = httpx.get(source_url, timeout=30.0)
        response.raise_for_status()

        # Parse JSON
        spec_data = response.json()

        # Validate the specification
        if not spec_data.get("openapi", "").startswith("3."):
            raise ValueError("Invalid OpenAPI version - expected 3.x")

        if spec_data.get("info", {}).get("title") != "FOSSA API":
            raise ValueError("Invalid API title - expected 'FOSSA API'")

        if not spec_data.get("paths"):
            raise ValueError("No paths found in specification")

        # Pretty-print and save the specification
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(spec_data, f, indent=2, ensure_ascii=False)

        print(f"Saved OpenAPI specification to {target_file}")

        # Calculate SHA-256
        with open(target_file, "rb") as f:
            sha256_hash = hashlib.sha256(f.read()).hexdigest()

        # Create/update README.md
        timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        version = spec_data.get("info", {}).get("version", "unknown")

        readme_content = f"""# FOSSA OpenAPI Specification

Retrieved: {timestamp} UTC

- API Version: {version}
- Source URL: {source_url}
- SHA-256: {sha256_hash}

This specification is vendored from the official FOSSA API documentation.
"""

        with open(readme_file, "w", encoding="utf-8") as f:
            f.write(readme_content)

        print(f"Updated README in {readme_file}")
        print("OpenAPI specification updated successfully!")

    except Exception as e:
        print(f"Error updating OpenAPI specification: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()