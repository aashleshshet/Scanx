"""Copy the shared browser assets to the standalone Sites static deployment directory."""

import shutil
from pathlib import Path

root = Path(__file__).resolve().parents[1]
source = root / "src/api_sentry/web/static"
destination = root / "work/scanx-site/dist"
destination.mkdir(parents=True, exist_ok=True)
for file in source.iterdir():
    if file.is_file():
        shutil.copy2(file, destination / file.name)
print(f"Static site prepared at {destination}")
