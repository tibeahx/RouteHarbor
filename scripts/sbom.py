#!/usr/bin/env python3
"""SPDX inventory of core builds and linked Go runtime; optional engines are separate."""
import datetime
import hashlib
import json
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parents[1]
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
go_version = next(line.split()[1] for line in (root / 'go.mod').read_text().splitlines() if line.startswith('go '))
version = '0.1.0-dev'
relationships = [
    {'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': 'SPDXRef-OpenRHP'},
    {'spdxElementId': 'SPDXRef-OpenRHP', 'relationshipType': 'DEPENDS_ON', 'relatedSpdxElement': 'SPDXRef-Go'},
]
files = []
for artifact in sorted((root / 'dist').glob('openrhp*-linux-*')):
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
    'documentNamespace': 'https://github.com/tibeahx/OpenRHP/sbom/' + commit,
    'creationInfo': {'creators': ['Tool: OpenRHP scripts/sbom.py'],
                     'created': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
    'packages': [
        {'name': 'OpenRHP', 'SPDXID': 'SPDXRef-OpenRHP', 'versionInfo': version,
         'downloadLocation': 'git+https://github.com/tibeahx/OpenRHP.git@' + commit,
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
