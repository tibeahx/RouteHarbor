# Native host system emulators; no binfmt/user-mode emulation inside the guest.
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
ARG QEMU_SYSTEM_VERSION=1:7.2+dfsg-7+deb12u18+b3
RUN apt-get update && apt-get install -y --no-install-recommends \
    "qemu-system-mips=${QEMU_SYSTEM_VERSION}" openssh-client python3 ca-certificates && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
