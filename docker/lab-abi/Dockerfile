# Emulators are host-side laboratory tools, not router package dependencies.
FROM routeharbor-path-lab:local
ARG QEMU_USER_VERSION=1:7.2+dfsg-7+deb12u18+b3
RUN apt-get update && \
    apt-get install -y --no-install-recommends "qemu-user-static=${QEMU_USER_VERSION}" && \
    rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
