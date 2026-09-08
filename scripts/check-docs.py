#!/usr/bin/env python3
"""Check Markdown links, JSON examples and unique OpenAPI operation IDs offline.

The Go API contract test verifies bidirectional route coverage.
"""
from pathlib import Path
import json,re,sys
root=Path(__file__).resolve().parents[1]
errors=[]
for doc in [*root.glob('*.md'),*root.glob('docs/*.md')]:
    for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
        target=target.split()[0].strip('<>')
        if re.match(r'^[a-zA-Z]+:',target) or target.startswith('#'):continue
        target=target.split('#')[0]
        if target and not (doc.parent/target).exists():errors.append(f'{doc.relative_to(root)}: missing {target}')
for p in root.glob('examples/*.json'):
    try:json.loads(p.read_text())
    except ValueError as e:errors.append(f'{p.name}: {e}')
contract=json.loads((root/'api/openapi.yaml').read_text())
seen=set()
for route,verbs in contract['paths'].items():
    for verb,op in verbs.items():
        key=op.get('operationId')
        if not key or key in seen:errors.append(f'nonunique operationId: {route} {verb}')
        seen.add(key)
for name in ['README.md','FOR_AGENTS.md','SECURITY.md','CONTRIBUTING.md','LICENSE','docs/quick-setup.md','docs/verification.md']:
    if not (root/name).is_file():errors.append('missing '+name)
if errors:print('\n'.join(errors),file=sys.stderr);sys.exit(1)
print(f'OK: Markdown links, examples and {len(seen)} unique API operations')
