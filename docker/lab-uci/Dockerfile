# The parser is built from exact upstream OpenWrt commits. This test image is
# separate from the router package and installs no code on a physical device.
FROM openrhp-path-lab:local
ARG LIBUBOX_COMMIT=e7608b69283d919d031d13cc8e21692503f5dbea
ARG UCI_COMMIT=74f6277aabffc943d026f406df57c22595134c42
RUN mkdir -p /build/libubox /build/uci && \
    curl --fail --location --proto '=https' "https://codeload.github.com/openwrt/libubox/tar.gz/${LIBUBOX_COMMIT}" | tar -xz --strip-components=1 -C /build/libubox && \
    curl --fail --location --proto '=https' "https://codeload.github.com/openwrt/uci/tar.gz/${UCI_COMMIT}" | tar -xz --strip-components=1 -C /build/uci && \
    touch /build/uci/uci_config.h && \
    gcc -Os -std=gnu99 -DUCI_PREFIX='"/usr/local"' -I/build -I/build/uci \
      /build/uci/cli.c /build/uci/libuci.c /build/uci/file.c /build/uci/util.c \
      /build/uci/delta.c /build/uci/parse.c -o /usr/local/bin/uci
# This links the unchanged upstream CLI/configuration parser directly. Lua and
# blob interoperability are unrelated to stdin parsing and are not linked.
ENV OPENRHP_UCI_TEST_BINARY=/usr/local/bin/uci
WORKDIR /work
ENTRYPOINT []
CMD ["/work/test-results/node-uci.test", "-test.run", "TestUCISecretEncodingRoundTripsThroughRealParser", "-test.v"]
