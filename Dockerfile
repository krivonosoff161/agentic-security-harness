# Local/offline image for the Agentic Security Harness CLI and the fake-server demo.
# No secrets, no network at runtime by default. The external path stays opt-in: it only
# calls a model endpoint when you run `ash run-external` (without --dry-run) yourself.
FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9

# Don't write .pyc, unbuffered stdout for clean container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install the package (only runtime dep is pydantic). Copy the project in, then install.
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
COPY examples ./examples
RUN python -m pip install --no-cache-dir . \
    && python -c "import agentic_security_harness as a; print('installed', a.__version__)"

# A non-root user; /work is a writable mount point for run artifacts.
RUN useradd --create-home --uid 10001 ash && mkdir -p /work && chown ash:ash /work
USER ash
WORKDIR /work

# Default: show the environment is ready (no network). Override CMD to run benchmarks.
# Examples:
#   docker run --rm -v "$PWD/reports:/work/reports" <image> \
#     ash run --target toy-rag --out reports/demo
#   docker run --rm -p 8766:8766 <image> python /app/examples/fake_openai_server.py
CMD ["ash", "doctor"]
