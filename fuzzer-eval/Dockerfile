# Artifact image: Tier 1 scoring and Tier 2 fuzzing.
#
#   docker build -t ac-libxml2 .                            Tier 1 only
#   docker build --build-arg ENGINES=all -t ac-libxml2 .    + Tier 2 engines
#   docker run --rm ac-libxml2 scripts/score.sh --ops 8e6
#
# Ubuntu 24.04 carries the compilers the campaign used: clang 18.1.3 for AFL++
# and SlowFuzz, gcc 13 for PerfFuzz. libxml2's autogen.sh needs automake 1.16.3
# or later. libclang-rt-18-dev supplies the runtime that SlowFuzz's
# -fsanitize-coverage build links against.
FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git autoconf automake libtool pkg-config python3 \
      ca-certificates clang-18 llvm-18-dev libclang-18-dev lld-18 \
      libclang-rt-18-dev \
 && ln -sf /usr/bin/clang-18   /usr/local/bin/clang \
 && ln -sf /usr/bin/clang++-18 /usr/local/bin/clang++ \
 && rm -rf /var/lib/apt/lists/*

# Pin the compilers the engine builds pick up.
ENV CLANG=/usr/bin/clang-18 \
    CLANGXX=/usr/bin/clang++-18 \
    LLVM_CONFIG=/usr/bin/llvm-config-18

# AFL++ 5.03a, the release the paper reports. It instruments the libxml2 that
# Tier 1 measures CPU time on, so it is pinned.
ENV AFL_PATH=/opt/AFLplusplus
ARG AFLPP_REV=9f835097c2991dbb198cb67e86cc1f4344d1079f
RUN git init -q "$AFL_PATH" \
 && git -C "$AFL_PATH" fetch -q --depth 1 https://github.com/AFLplusplus/AFLplusplus "$AFLPP_REV" \
 && git -C "$AFL_PATH" checkout -q FETCH_HEAD \
 && make -C "$AFL_PATH" CC=clang-18 CXX=clang++-18 LLVM_CONFIG=llvm-config-18 \
      -j"$(nproc)" >/dev/null \
 && ln -sf "$AFL_PATH/afl-clang-fast" /usr/local/bin/afl-clang-fast \
 && ln -sf "$AFL_PATH/afl-fuzz" /usr/local/bin/afl-fuzz

WORKDIR /artifact
COPY . /artifact
# COPY keeps the build context's permissions; make everything readable so the
# image also works with `docker run --user`. /artifact/runs is the default
# output directory for fuzz.sh.
RUN chmod -R a+rX /artifact \
 && mkdir -p /artifact/runs && chmod 1777 /artifact/runs

# Any scripts/build.sh flag, so the image can target another libxml2 revision:
#   docker build --build-arg BUILD_ARGS="--commit latest --instrumented" .
ARG ENGINES=""
ARG BUILD_ARGS="--instrumented"
RUN bash scripts/build.sh $BUILD_ARGS

# Tier 2 targets: aflpp, perffuzz, slowfuzz or all. Empty by default so the
# Tier 1 image stays small.
#
#   docker build --build-arg ENGINES=all --build-arg PERFFUZZ_LLVM=1 -t ac-libxml2 .
ARG PERFFUZZ_LLVM=0
RUN if [ -n "$ENGINES" ] && [ "$PERFFUZZ_LLVM" = "1" ]; then \
      apt-get update && apt-get install -y --no-install-recommends curl xz-utils \
   && mkdir -p /opt/llvm-13 \
   && curl -sL --retry 3 \
        https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz \
      | tar xJ -C /opt/llvm-13 --strip-components=1 \
   && /opt/llvm-13/bin/llvm-config --version \
   && rm -rf /var/lib/apt/lists/*; \
    fi

RUN [ -z "$ENGINES" ] || env \
      $([ "$PERFFUZZ_LLVM" = "1" ] && echo "PERFFUZZ_LLVM=1 LLVM_CONFIG=/opt/llvm-13/bin/llvm-config") \
      bash scripts/build-engines.sh $ENGINES

ENTRYPOINT ["bash"]
