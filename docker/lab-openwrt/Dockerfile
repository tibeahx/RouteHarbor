# Supply the independently verified OpenWrt 24.10.7 x86_64 rootfs and a directory
# "dependencies" containing the signed base Packages index/signature and the
# ip-full/libbpf1/libelf1/zlib IPKs named by that index. No build network is needed.
FROM scratch
ADD rootfs.tar.gz /
COPY dependencies/ /tmp/routeharbor-lab-dependencies/
RUN set -eu; \
    cd /tmp/routeharbor-lab-dependencies; \
    usign -V -P /etc/opkg/keys -m Packages -x Packages.sig; \
    awk '/^Filename: / {file=$2} /^SHA256sum: / {hash=$2} /^$/ {if(file != "" && hash != "") print hash "  " file; file=""; hash=""}' Packages > checksums; \
    for file in *.ipk; do \
        line=$(awk -v name="$file" '$2 == name {print}' checksums); \
        [ -n "$line" ]; \
        printf '%s\n' "$line" | sha256sum -c -; \
    done; \
    mkdir -p /var/lock; \
    opkg install ./*.ipk; \
    rm -rf /tmp/routeharbor-lab-dependencies
ENTRYPOINT ["/bin/sh"]
