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
    libcapstone-dev \
    libz3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y \
    libc6:i386 \
    libncurses5:i386 \
    libstdc++6:i386 \
    lib32z1 \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip setuptools wheel poetry

COPY pyproject.toml poetry.lock /app/

RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --without dev

COPY . /app

RUN mkdir -p /tmp/deemo_exploits /tmp/deemo_binaries /tmp/deemo_reports /workspace

ENV DEEMO_WORKSPACE=/workspace
ENV DEEMO_SANDBOX=true
ENV PYTHONUNBUFFERED=1

VOLUME ["/workspace"]
VOLUME ["/tmp/deemo_exploits"]

EXPOSE 4444 9999

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "from modules.cli import app; print('Deemo CLI available')" || exit 1

CMD ["/bin/bash", "-c", "tail -f /dev/null"]

LABEL org.opencontainers.image.title="Deemo Binary Analysis Tool"
LABEL org.opencontainers.image.description="Docker environment for safe binary analysis and exploit validation"
LABEL org.opencontainers.image.vendor="Deemo Project"
LABEL org.opencontainers.image.licenses="MIT"