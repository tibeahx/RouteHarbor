#!/usr/bin/env python3
"""Separate selective classifier VM: nonoverlapping WAN and private disk capacity."""
import json
import os
import pathlib
import struct
import sys
import vmctl

vmctl.CONTAINER = 'routeharbor-selective-boot-lab'
vmctl.WAN_PREFIX = '11.0.0'


def capacity():
    """Grow a stopped lab image via regular files; never open a block device."""
    vmctl.require_lab()
    state = vmctl.STATE
    identity = {'project': 'RouteHarbor isolated full-boot lab', 'image_sha256': vmctl.SHA256}
    if json.loads((state/'owner.json').read_text()) != identity:
        raise RuntimeError('Foreign VM disk owner')
    evidence = state/'selective-capacity.json'
    if evidence.exists():
        if json.loads(evidence.read_text()).get('image_sha256') != vmctl.SHA256:
            raise RuntimeError('Foreign selective capacity checkpoint')
        print(evidence.read_text().strip())
        return
    backup = state/'before-selective-capacity.qcow2'
    if backup.exists():
        raise RuntimeError('Incomplete capacity change: preserve backup for explicit recovery')
    vmctl.guest(b'sync\n')
    vmctl.stop_vm()
    if vmctl.running_pid() is not None:
        raise RuntimeError('Never resize a running virtual disk')
    raw, root, expanded = [state/n for n in ['selective-disk.raw','selective-root.ext4','selective-expanded.qcow2']]
    try:
        vmctl.run(['qemu-img','convert','-f','qcow2','-O','raw',str(state/'router.qcow2'),str(raw)],timeout=120)
        with raw.open('r+b') as disk:
            mbr=bytearray(disk.read(512))
            if mbr[510:]!=b'\x55\xaa' or mbr[466]!=0x83:
                raise RuntimeError('Expected official DOS second Linux root partition')
            start,sectors=struct.unpack_from('<II',mbr,470)
            if start<2048 or not 100000<=sectors<=300000:
                raise RuntimeError('Unexpected original root partition extent')
            disk.seek(start*512)
            with root.open('wb') as target:
                target.write(disk.read(sectors*512));target.truncate(512<<20)
            checked=vmctl.run(['e2fsck','-f','-y',str(root)],check=False,timeout=120)
            if checked.returncode not in (0,1):
                raise RuntimeError('Private root filesystem check failed')
            vmctl.run(['resize2fs',str(root)],timeout=120)
            struct.pack_into('<I',mbr,474,1048576)
            disk.seek(0);disk.write(mbr);disk.truncate(start*512+(512<<20));disk.seek(start*512)
            with root.open('rb') as source:
                while data:=source.read(1<<20):disk.write(data)
            disk.flush();os.fsync(disk.fileno())
        vmctl.run(['qemu-img','convert','-f','raw','-O','qcow2',str(raw),str(expanded)],timeout=120)
        (state/'router.qcow2').rename(backup);expanded.rename(state/'router.qcow2')
        evidence.write_text(json.dumps({'image_sha256':vmctl.SHA256,'root_bytes':512<<20,'original_overlay_retained':backup.name,'method':'offline regular-file ext4 expansion; no block devices'})+'\n')
    finally:
        for path in [raw,root,expanded]:path.unlink(missing_ok=True)
        vmctl.start()
    vmctl.wait_ssh()
    print(evidence.read_text().strip())


if __name__ == '__main__':
    if sys.argv[1:]==['capacity']:
        capacity()
    else:
        sys.exit(vmctl.main())
