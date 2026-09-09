FROM scratch
# The caller verifies the official whole-file SHA-256 before this build.
ADD rootfs.tar.gz /
LABEL org.openrhp.lab.rootfs-sha256="862c25809a12356bdc051d144f53a4ebb6494bd0239a19e8c54cd9160db89b21"
ENTRYPOINT ["/bin/sh"]
