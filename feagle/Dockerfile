FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
RUN python - <<'PY'
import subprocess
import sys
import tomllib
from pathlib import Path

project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
deps = list(project["project"].get("dependencies", []))
deps.extend(project["project"].get("optional-dependencies", {}).get("dev", []))
subprocess.check_call([sys.executable, "-m", "pip", "install", *deps])
PY

COPY src ./src
COPY alembic.ini ./alembic.ini

RUN pip install -e . --no-deps

EXPOSE 8000

CMD ["sh", "-c", "alembic -c alembic.ini upgrade head && uvicorn pyshare_api.main:app --host 0.0.0.0 --port 8000"]
