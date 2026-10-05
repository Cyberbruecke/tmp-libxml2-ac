# Tier 1 of the artifact: rebuild Table 3 from the saved fuzzer inputs.
#
#   docker build -t ac-libxml2 .
#   docker run --rm ac-libxml2 scripts/score.sh --verify
#   docker run --rm ac-libxml2 scripts/score.sh --ops 8e6
#   docker run --rm ac-libxml2 scripts/score.sh --bar 5
#
# The image builds an AFL-instrumented libxml2, which is what the paper's CPU
# figures were measured on. The operation criterion is unaffected by the choice;
# the CPU criteria are. See README.md.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git autoconf automake libtool pkg-config python3 \
      ca-certificates clang llvm-dev libclang-dev lld \
    && rm -rf /var/lib/apt/lists/*

# AFL++ supplies afl-clang-fast, needed to match the paper's CPU measurements.
ENV AFL_PATH=/opt/AFLplusplus
RUN git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus "$AFL_PATH" \
    && make -C "$AFL_PATH" -j"$(nproc)" >/dev/null \
    && ln -sf "$AFL_PATH/afl-clang-fast" /usr/local/bin/afl-clang-fast

WORKDIR /artifact
COPY . /artifact

# Build at image-build time so `docker run` goes straight to scoring.
RUN bash scripts/build.sh --instrumented

ENTRYPOINT ["bash"]
CMD ["scripts/score.sh", "--ops", "8e6"]
