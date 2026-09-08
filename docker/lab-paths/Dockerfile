FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl gcc make libc6-dev zlib1g-dev libnetfilter-queue-dev libnfnetlink-dev libmnl-dev nftables iproute2 python3 openssl procps && rm -rf /var/lib/apt/lists/*
RUN apt-get update && apt-get install -y --no-install-recommends libcap-dev && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL --retry 3 https://codeload.github.com/bol-van/zapret/tar.gz/f0b0d89f02f44bb047fbfde5d96e9a1fc38e46f0 -o /tmp/zapret.tar.gz && echo 'b5f7815770da2bf559a1c958a34bdea4cb901fc19a8cbb6642ee462773a9dc0a  /tmp/zapret.tar.gz' | sha256sum -c - && mkdir /tmp/zapret && tar -xzf /tmp/zapret.tar.gz -C /tmp/zapret --strip-components=1 && make -C /tmp/zapret/nfq CFLAGS='-DZAPRET_GH_VER=v72.10 -DZAPRET_GH_HASH=f0b0d89' && install -m 0755 /tmp/zapret/nfq/nfqws /usr/bin/nfqws && rm -rf /tmp/zapret /tmp/zapret.tar.gz
COPY run.sh lab.py /lab/
ENTRYPOINT ["/lab/run.sh"]
RUN apt-get update && apt-get install -y --no-install-recommends conntrack && rm -rf /var/lib/apt/lists/*
