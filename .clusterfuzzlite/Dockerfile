FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:635367b3c16779796388edfd88d5677bc6ff72b084f441b9ab21d555829661ab

COPY . $SRC/agentic-security-harness
WORKDIR $SRC/agentic-security-harness

COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh

