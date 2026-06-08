# Deemo - LLM 辅助二进制漏洞分析工具 Docker 环境
# 用于安全执行漏洞利用和二进制分析

FROM ubuntu:22.04

LABEL maintainer="Deemo Binary Analysis Tool"
LABEL description="LLM-assisted Binary Vulnerability Analysis Environment"
LABEL version="1.0"

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

ENV HOME=/root
WORKDIR /app

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
    && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    libc6:i386 \
    libncurses5:i386 \
    libstdc++6:i386 \
    lib32z1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install \
    pwntools \
    ropper \
    ROPgadget \
    angr \
    cle \
    r2pipe \
    capstone \
    unicorn \
    keystone-engine \
    pefile \
    lief \
    pyelftools \
    macholib \
    requests \
    python-dotenv \
    prompt-toolkit \
    pygments \
    rich \
    click \
    colorama

RUN pip3 install --no-cache-dir \
    "git+https://github.com/Gallopsled/pwntools.git@dev#egg=pwntools" \
    2>/dev/null || true

RUN mkdir -p /tmp/deemo_exploits /tmp/deemo_binaries /tmp/deemo_reports

ENV DEEMO_WORKSPACE=/workspace
ENV DEEMO_SANDBOX=true
ENV PYTHONUNBUFFERED=1

VOLUME ["/workspace"]
VOLUME ["/tmp/deemo_exploits"]

EXPOSE 4444 9999

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import pwn; print('pwnlib available')" || exit 1

CMD ["/bin/bash", "-c", "tail -f /dev/null"]

LABEL org.opencontainers.image.title="Deemo Binary Analysis Tool"
LABEL org.opencontainers.image.description="Docker environment for safe binary analysis and exploit validation"
LABEL org.opencontainers.image.vendor="Deemo Project"
LABEL org.opencontainers.image.licenses="MIT"
