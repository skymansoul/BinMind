# Deemo - LLM 辅助二进制漏洞分析工具 Docker 环境
# 用于安全执行漏洞利用和二进制分析

FROM ubuntu:22.04

LABEL version="1.4.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ENV HOME=/root
WORKDIR /app

# Base toolchain
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    vim \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    cmake \
    gdb \
    gdbserver \
    netcat \
    socat \
    telnet \
    strace \
    ltrace \
    file \
    binutils \
    patchelf \
    libc6-dbg \
    libc6-dev \
    gcc-multilib \
    g++-multilib \
    lib32gcc-s1 \
    lib32stdc++6 \
    lib32z1 \
    libssl-dev \
    libffi-dev \
    qemu-user-static \
    binfmt-support \
    libcapstone-dev \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

# i386 support
RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    libc6:i386 \
    libncurses5:i386 \
    libstdc++6:i386 \
    lib32z1 \
    && rm -rf /var/lib/apt/lists/*

# Python deps
RUN pip3 install --upgrade pip setuptools wheel

COPY requirements.txt /app/
RUN pip3 install -r requirements.txt || \
    (echo "warning: some optional deps failed to install" && true)

COPY . /app

RUN mkdir -p /tmp/binmind_exploits /tmp/binmind_binaries /tmp/binmind_reports /workspace

ENV BINMIND_WORKSPACE=/workspace
ENV BINMIND_SANDBOX=true
ENV PYTHONUNBUFFERED=1

VOLUME ["/workspace"]
VOLUME ["/tmp/binmind_exploits"]

EXPOSE 4444 9999

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from cli.commands import build_parser; print('ready')" || exit 1

CMD ["/bin/bash", "-c", "tail -f /dev/null"]

LABEL org.opencontainers.image.title="Deemo Binary Analysis Tool"
LABEL org.opencontainers.image.description="Docker environment for safe binary analysis and exploit validation"
LABEL org.opencontainers.image.vendor="Deemo Project"
LABEL org.opencontainers.image.licenses="MIT"
