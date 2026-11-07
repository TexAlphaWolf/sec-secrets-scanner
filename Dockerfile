FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# secscan calls git, so the image needs it. `safe.directory *` lets git read a repository that
# is mounted from the host with a different owner; the container only ever reads it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && git config --system --add safe.directory '*'

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install . && useradd --system --no-create-home --uid 10001 secscan

# Nothing here needs the network, root or a writable filesystem.
USER secscan
WORKDIR /repo
ENTRYPOINT ["secscan"]
CMD ["--help"]
