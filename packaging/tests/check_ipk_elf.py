#!/usr/bin/env python3
"""Inspect real SDK IPK payloads without executing or extracting their paths.

Usage: GO=/absolute/go python3 packaging/tests/check_ipk_elf.py PACKAGE.ipk [...]
Checks ELF sections/segments and authoritative Go build info in the actual package.
"""
import argparse
import hashlib
import io
import json
import os
import pathlib
import re
import struct
import subprocess
import tarfile
import tempfile

EXPECTED = {
    'openrhp': ('usr/bin/openrhp', 'github.com/tibeahx/OpenRHP/cmd/openrhp'),
    'openrhp-guard': ('usr/libexec/openrhp-helper', 'github.com/tibeahx/OpenRHP/cmd/openrhp-helper'),
    'openrhp-node': ('usr/bin/openrhp-node', 'github.com/tibeahx/OpenRHP/cmd/openrhp-node'),
    'openrhp-sing-box': None,
    'openrhp-xray': None,
    'openrhp-conntrack': None,
    'openrhp-continuity': ('usr/libexec/openrhp-continuity', 'github.com/tibeahx/OpenRHP/cmd/openrhp-continuity'),
}
MAX_BYTES = 128 << 20


def read_member(archive, member, limit=MAX_BYTES):
    if not member.isfile() or not 0 <= member.size <= limit:
        raise ValueError('Unexpected archive member type or size')
    source = archive.extractfile(member)
    if source is None:
        raise ValueError('Archive member is missing')
    with source:
        data = source.read(limit + 1)
    if len(data) != member.size or len(data) > limit:
        raise ValueError('Truncated or oversized archive member')
    return data


def members(data, limit):
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        total = 0
        seen = set()
        for index, entry in enumerate(archive):
            name = entry.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and entry.isdir():
                continue
            if index > 16384 or name in seen or any(part in ('', '.', '..') for part in name.split('/')) or '\\' in name:
                raise ValueError('Unexpected archive path or member count')
            seen.add(name)
            total += entry.size
            if total > limit:
                raise ValueError('Expanded archive exceeds validation budget')
            yield name, entry, read_member(archive, entry, limit) if entry.isfile() else None


def elf_info(data):
    if len(data) < 64 or data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError('Unsupported ELF header')
    wide, endian = data[4] == 2, '<' if data[5] == 1 else '>'
    unpack = lambda fmt, offset: struct.unpack_from(endian + fmt, data, offset)
    kind, machine = unpack('HH', 16)
    if kind != 2:
        raise ValueError('Expected a static executable ELF')
    phoff, shoff = unpack('QQ' if wide else 'II', 32 if wide else 28)
    ehsize, phsize, phnum, shsize, shnum, shstr = unpack('HHHHHH', 52 if wide else 40)
    expected_header, expected_program, expected_section = (64, 56, 64) if wide else (52, 32, 40)
    if ehsize != expected_header or phsize != expected_program or shsize != expected_section:
        raise ValueError('Invalid ELF table entry size')
    if not 0 < phnum < 1024 or not 0 < shnum < 16384 or not 0 < shstr < shnum:
        raise ValueError('Missing or unsupported ELF tables')
    if phoff + phsize * phnum > len(data) or shoff + shsize * shnum > len(data):
        raise ValueError('ELF header table extends past EOF')
    for index in range(phnum):
        start = phoff + index * phsize
        program_type = unpack('I', start)[0]
        offset = unpack('Q' if wide else 'I', start + (8 if wide else 4))[0]
        size, memory = unpack('QQ' if wide else 'II', start + (32 if wide else 16))
        if offset + size > len(data) or (program_type == 1 and size > memory):
            raise ValueError('ELF program segment extends past EOF or memory')
        if program_type in (2, 3):
            raise ValueError('Unexpected dynamic loader in a CGO-disabled package')
    sections = []
    for index in range(shnum):
        start = shoff + index * shsize
        name, section_type = unpack('II', start)
        offset, size = unpack('QQ' if wide else 'II', start + (24 if wide else 16))
        if section_type != 8 and offset + size > len(data):
            raise ValueError('ELF section extends past EOF (SDK stripping may have truncated metadata)')
        sections.append((name, section_type, offset, size))
    _, table_type, offset, size = sections[shstr]
    if table_type != 3:
        raise ValueError('ELF section names do not reference a string table')
    names = data[offset:offset + size]
    buildinfo = False
    for name, section_type, offset, size in sections:
        end = names.find(b'\0', name)
        if name >= len(names) or end < 0:
            raise ValueError('Invalid ELF section name offset')
        if names[name:end] == b'.go.buildinfo':
            if section_type != 1 or size < 32 or not data[offset:offset + size].startswith(b'\xff Go buildinf:'):
                raise ValueError('Invalid Go build information section')
            buildinfo = True
    if not buildinfo:
        raise ValueError('Go build information section is missing')
    architecture = {3: '386', 62: 'amd64', 40: 'arm', 183: 'arm64', 243: 'riscv64'}.get(machine)
    if machine == 8:
        architecture = 'mips' + ('64' if wide else '') + ('le' if endian == '<' else '')
    if architecture is None:
        raise ValueError('Unexpected ELF machine')
    if machine != 8 and ((wide != (machine in (62, 183, 243))) or endian != '<'):
        raise ValueError('ELF machine has an incompatible word size or byte order')
    return {'elf_class': 64 if wide else 32, 'byte_order': 'little' if endian == '<' else 'big', 'goarch': architecture}


def package_goarch(architecture):
    for prefix, goarch in [('aarch64', 'arm64'), ('x86_64', 'amd64'), ('i386', '386'),
                          ('mips64el', 'mips64le'), ('mips64', 'mips64'), ('mipsel', 'mipsle'),
                          ('mips', 'mips'), ('arm', 'arm'), ('riscv64', 'riscv64')]:
        if architecture == prefix or architecture.startswith(prefix + '_'):
            return goarch
    raise ValueError('Unsupported OpenWrt package architecture')


def check_package(path, go):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError('Package exceeds validation budget')
    outer = {name: data for name, _, data in members(path.read_bytes(), MAX_BYTES)}
    if set(outer) != {'debian-binary', 'control.tar.gz', 'data.tar.gz'} or outer['debian-binary'] != b'2.0\n':
        raise ValueError('Expected an OpenWrt SDK gzip/tar IPK')
    control = {name: data for name, _, data in members(outer['control.tar.gz'], 1 << 20)}
    fields = {}
    for line in control['control'].decode().splitlines():
        if line and not line[0].isspace():
            key, separator, value = line.partition(':')
            if not separator or key in fields:
                raise ValueError('Invalid package control metadata')
            fields[key] = value.strip()
    name, architecture = fields['Package'], fields['Architecture']
    if name not in EXPECTED:
        raise ValueError('Unexpected package identity')
    expected = EXPECTED[name]
    records = []
    for filename, entry, data in members(outer['data.tar.gz'], 256 << 20):
        if expected and filename == expected[0] and (data is None or data[:4] != b'\x7fELF'):
            raise ValueError('Required package executable is not a regular ELF')
        if data is None or data[:4] != b'\x7fELF':
            continue
        if expected is None or filename != expected[0] or entry.mode != 0o755:
            raise ValueError('Unexpected packaged executable or mode')
        info = elf_info(data)
        if info['goarch'] != package_goarch(architecture):
            raise ValueError('ELF machine disagrees with package architecture')
        with tempfile.TemporaryDirectory(prefix='openrhp-package-elf-') as directory:
            binary = pathlib.Path(directory) / 'binary'
            binary.write_bytes(data)
            binary.chmod(0o600)
            result = subprocess.run([go, 'version', '-m', str(binary)], capture_output=True, text=True, timeout=20)
            lines = result.stdout.splitlines()
            if result.returncode or not lines or lines[0] != str(binary) + ': go1.27.1':
                raise ValueError('Go cannot read the pinned build metadata from the packaged ELF')
            metadata = [line.strip().split('\t') for line in lines[1:]]
            if ['path', expected[1]] not in metadata or not any(row[:2] == ['mod', 'github.com/tibeahx/OpenRHP'] for row in metadata) or ['build', 'GOOS=linux'] not in metadata or ['build', 'CGO_ENABLED=0'] not in metadata or ['build', 'GOARCH=' + info['goarch']] not in metadata:
                raise ValueError('Go build metadata disagrees with the package contract')
            for setting in ['GOMIPS=softfloat'] if info['goarch'] in ('mips', 'mipsle') else ['GOMIPS64=softfloat'] if info['goarch'] in ('mips64', 'mips64le') else []:
                if ['build', setting] not in metadata:
                    raise ValueError('MIPS package must use the declared soft-float Go ABI')
        records.append({'path': filename, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'go_version': 'go1.27.1', **info})
    if len(records) != (1 if expected else 0):
        raise ValueError('Missing or duplicate package executable')
    return {'ipk': path.name, 'package': name, 'version': fields['Version'], 'architecture': architecture, 'binaries': records}


def sdk_packages(sdk, recipe):
    """Select only this build's exact identities; stale SDK output is not evidence."""
    def setting(path, name, operator, quoted=False):
        pattern = r'^' + re.escape(name + operator) + (r'"([^"\n]+)"' if quoted else r'([^\s]+)') + r'$'
        values = re.findall(pattern, path.read_text(), re.MULTILINE)
        if len(values) != 1 or not re.fullmatch(r'[A-Za-z0-9_.+-]+', values[0]):
            raise ValueError('Expected one literal SDK setting: ' + name)
        return values[0]

    version = setting(recipe, 'PKG_VERSION', ':=') + '-r' + setting(recipe, 'PKG_RELEASE', ':=')
    architecture = setting(sdk / '.config', 'CONFIG_TARGET_ARCH_PACKAGES', '=', quoted=True)
    paths = []
    for name in EXPECTED:
        filename = name + '_' + version + '_' + architecture + '.ipk'
        matches = list((sdk / 'bin').rglob(filename))
        if len(matches) != 1 or not matches[0].is_file():
            raise ValueError('Expected exactly one current SDK artifact: ' + filename)
        paths.append(matches[0])
    return paths, version, architecture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('packages', nargs='*', type=pathlib.Path)
    parser.add_argument('--sdk', type=pathlib.Path)
    parser.add_argument('--recipe', type=pathlib.Path)
    args = parser.parse_args()
    version = architecture = None
    if args.sdk or args.recipe:
        if not args.sdk or not args.recipe or args.packages:
            parser.error('Use --sdk and --recipe together, without package arguments')
        try:
            paths, version, architecture = sdk_packages(args.sdk, args.recipe)
        except (ValueError, OSError) as error:
            raise SystemExit(str(error)) from error
    elif args.packages:
        paths = args.packages
    else:
        parser.error('Supply package paths or --sdk and --recipe')
    go = os.environ.get('GO', 'go')
    output = []
    for path in paths:
        try:
            record = check_package(path, go)
            if version is not None and (record['version'] != version or record['architecture'] != architecture or
                                       path.name != record['package'] + '_' + version + '_' + architecture + '.ipk'):
                raise ValueError('Package control identity disagrees with the current SDK build')
            output.append(record)
        except (ValueError, KeyError, OSError, tarfile.TarError, struct.error, subprocess.SubprocessError) as error:
            raise SystemExit(path.name + ': ' + str(error)) from error
    print(json.dumps(output, indent=2))


if __name__ == '__main__':
    main()
