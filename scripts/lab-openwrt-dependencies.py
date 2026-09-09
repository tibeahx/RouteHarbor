#!/usr/bin/env python3
"""Fetch signed package dependencies for the isolated OpenWrt 24.10.7 x86_64 VM.

The verifier image must already contain independently verified OpenWrt release
keys and usign. This command never downloads or replaces trust keys.
"""

import argparse
import concurrent.futures
import hashlib
import json
import pathlib
import re
import subprocess
import urllib.request

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=pathlib.Path, required=True)
parser.add_argument('--verifier-image', default='openrhp-openwrt-deps:24.10.7')
args = parser.parse_args()
root = args.output.resolve()
root.mkdir(parents=True, exist_ok=True)
repos = {
    'base': 'https://downloads.openwrt.org/releases/24.10.7/packages/x86_64/base/',
    'packages': 'https://downloads.openwrt.org/releases/24.10.7/packages/x86_64/packages/',
    'kmods': 'https://downloads.openwrt.org/releases/24.10.7/targets/x86/64/kmods/6.6.141-1-50daf8372d971124fb3519e8d87e02ae/',
}

def fetch(url, limit=16 << 20):
    with urllib.request.urlopen(url, timeout=60) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError('download too large')
    return data

def index(item):
    name, url = item
    folder = root / name
    folder.mkdir(exist_ok=True)
    for filename in ['Packages', 'Packages.sig']:
        (folder / filename).write_bytes(fetch(url + filename))
    subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                    '--mount', f'type=bind,source={folder},target=/verify,readonly',
                    '--entrypoint', '/usr/bin/usign', args.verifier_image,
                    '-V', '-P', '/etc/opkg/keys', '-m', '/verify/Packages', '-x', '/verify/Packages.sig'], check=True)
    result = {}
    for block in (folder / 'Packages').read_text().split('\n\n'):
        fields = dict(line.split(': ', 1) for line in block.splitlines() if ': ' in line and not line.startswith(' '))
        if 'Package' in fields:
            fields['repository'] = name
            result[fields['Package']] = fields
    return result

all_packages = {}
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
    for packages in pool.map(index, repos.items()):
        all_packages.update(packages)

requested = {'conntrack', 'ip-full', 'tcpdump', 'kmod-nft-tproxy', 'kmod-nft-socket', 'kmod-nft-queue'}
optional = {'kmod-mac80211-hwsim', 'iw', 'wpad-mesh-openssl'}
requested |= optional & all_packages.keys()
selected = {}
remaining = list(requested)
provided = {'kernel', 'libc', 'libgcc1', 'libpthread', 'librt'}
while remaining:
    name = remaining.pop()
    if name in provided or name in selected:
        continue
    fields = all_packages.get(name)
    if not fields:
        providers = [f for f in all_packages.values() if name in [p.strip().split(' ')[0] for p in f.get('Provides', '').split(',')]]
        if len(providers) != 1:
            raise ValueError('unresolved dependency: ' + name)
        fields = providers[0]
    selected[fields['Package']] = fields
    for dependency in fields.get('Depends', '').split(','):
        dependency = dependency.strip().split(' ')[0]
        if dependency:
            remaining.append(dependency)

def artifact(fields):
    filename = fields['Filename']
    if not re.fullmatch(r'[A-Za-z0-9_.+~%-]+\.ipk', filename):
        raise ValueError('unsafe filename')
    url = repos[fields['repository']] + filename
    data = fetch(url)
    if len(data) != int(fields['Size']) or hashlib.sha256(data).hexdigest() != fields['SHA256sum']:
        raise ValueError('package integrity failed')
    (root / filename).write_bytes(data)
    return {'package': fields['Package'], 'version': fields['Version'], 'url': url, 'file': filename, 'sha256': fields['SHA256sum'], 'size': len(data), 'depends': fields.get('Depends', '')}

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    manifest = list(pool.map(artifact, selected.values()))
(root / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
for item in sorted(manifest, key=lambda item: item['package']):
    print('Verified', item['package'], item['version'])
