FROM openrhp-path-lab:local
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      arm64) sing_arch=arm64; sing_sha=04d9b40bc98dc55b6f509ce3292145c65478f65866bea64826ebb2f382385088 ;; \
      amd64) sing_arch=amd64; sing_sha=2375de6999f4f56ab46b4fc5ddf26a6aba1d3e61a0f4e7ddec2f4690457d5f63 ;; \
      *) echo 'Native engine lab supports amd64 and arm64 only.' >&2; exit 1 ;; \
    esac && \
    curl --fail --silent --show-error --location --proto '=https' "https://github.com/SagerNet/sing-box/releases/download/v1.14.0/sing-box-1.14.0-linux-${sing_arch}.tar.gz" -o /tmp/sing.tar.gz && \
    printf '%s  /tmp/sing.tar.gz\n' "$sing_sha" | sha256sum --check && \
    tar -xzf /tmp/sing.tar.gz -C /tmp && \
    install -m 0755 "/tmp/sing-box-1.14.0-linux-${sing_arch}/sing-box" /usr/bin/sing-box && \
    rm -rf /tmp/sing.tar.gz "/tmp/sing-box-1.14.0-linux-${sing_arch}"
RUN case "$TARGETARCH" in \
      arm64) xray_arch=arm64-v8a; xray_sha=4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c ;; \
      amd64) xray_arch=64; xray_sha=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae ;; \
      *) exit 1 ;; \
    esac && \
    curl --fail --silent --show-error --location --proto '=https' "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-${xray_arch}.zip" -o /tmp/xray.zip && \
    printf '%s  /tmp/xray.zip\n' "$xray_sha" | sha256sum --check && \
    python3 -c "import zipfile; z=zipfile.ZipFile('/tmp/xray.zip'); open('/usr/bin/xray','wb').write(z.read('xray'))" && \
    chmod 0755 /usr/bin/xray && rm /tmp/xray.zip
ENTRYPOINT []
