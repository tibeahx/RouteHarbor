#!/usr/bin/env python3
"""SPDX inventory of core builds and linked Go runtime; optional engines are separate."""
import datetime
import hashlib
import json
import os
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
dirty = bool(subprocess.check_output(
    ['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=root, text=True).strip())
source_files = []
for name in ['go.mod', 'api', 'cmd', 'internal']:
    source = root / name
    for path in sorted(source.rglob('*') if source.is_dir() else [source]):
        if path.is_file() and not path.name.endswith('_test.go'):
            source_files.append({'path': str(path.relative_to(root)),
                                 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
source_digest = hashlib.sha256(json.dumps(
    source_files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
source_info = ('Uncommitted working tree based on ' + commit + '; build-input inventory SHA256 ' +
               source_digest + '. These artifacts are not attributed to the base commit alone.'
               if dirty else 'Git source commit ' + commit)
namespace = 'https://github.com/tibeahx/OpenRHP/sbom/' + commit
if dirty:
    namespace += '/working-tree-' + source_digest
go_version = next(line.split()[1] for line in (root / 'go.mod').read_text().splitlines() if line.startswith('go '))
version = '0.1.0-dev'
relationships = [
    {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-OpenRHP'},
    {'spdxElementId': 'SPDXRef-OpenRHP', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-Go'},
]
files = []
artifact_dir = Path(os.environ.get('OUT', str(root / 'dist')))
for artifact in sorted(artifact_dir.glob('openrhp*-linux-*')):
    if not artifact.is_file() or artifact.is_symlink():
        continue
    file_id = 'SPDXRef-Artifact-' + artifact.name
    with artifact.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    files.append({'fileName': './' + artifact.name, 'SPDXID': file_id, 'fileTypes': ['BINARY'],
                  'checksums': [{'algorithm': 'SHA256', 'checksumValue': digest}],
                  'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION'})
    relationships.extend([
        {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': file_id},
        {'spdxElementId': file_id, 'relationshipType': 'GENERATED_FROM', 'relatedSpdxElement': 'SPDXRef-OpenRHP'},
    ])
sbom = {
    'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
    'name': 'OpenRHP core ' + version,
    'documentNamespace': namespace,
    'creationInfo': {'creators': ['Tool: OpenRHP scripts/sbom.py'],
                     'created': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
    'packages': [
        {'name': 'OpenRHP', 'SPDXID': 'SPDXRef-OpenRHP', 'versionInfo': version,
         'downloadLocation': 'NOASSERTION' if dirty else 'git+https://github.com/tibeahx/OpenRHP.git@' + commit,
         'sourceInfo': source_info,
         'filesAnalyzed': False, 'licenseDeclared': 'Apache-2.0', 'licenseConcluded': 'NOASSERTION',
         'copyrightText': 'NOASSERTION',
         'comment': 'Source package reference. Build artifacts are independently described files GENERATED_FROM this source; they are not package contents. Optional sing-box, Xray, nfqws and age are separately installed and not linked or bundled.'},
        {'name': 'Go standard library and runtime', 'SPDXID': 'SPDXRef-Go', 'versionInfo': go_version,
         'downloadLocation': 'https://go.dev/dl/', 'filesAnalyzed': False,
         'licenseDeclared': 'BSD-3-Clause', 'licenseConcluded': 'NOASSERTION', 'copyrightText': 'The Go Authors',
         'comment': 'Pinned toolchain and linked standard library; core go.mod has no third-party module requirements.'},
    ],
    'relationships': relationships,
}
if files:
    sbom['files'] = files
print(json.dumps(sbom, indent=2))
