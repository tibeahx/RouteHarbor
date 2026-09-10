#!/usr/bin/env python3
"""Fixed official 32-bit OpenWrt profile in its own isolated lab container."""
import sys

import vmctl

vmctl.SHA256 = '394014a15bfb1efd0cd47242897d72493f6a2b3be81b7099a340490384457b82'
vmctl.QEMU_CPU = 'qemu32'
vmctl.CONTAINER = 'routeharbor-openwrt-i386-lab'

if __name__ == '__main__':
    sys.exit(vmctl.main())
