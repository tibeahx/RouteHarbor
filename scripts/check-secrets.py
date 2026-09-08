#!/usr/bin/env python3
"""Small offline fixture check; not a substitute for a real repository secret scan."""
from pathlib import Path
import re,subprocess,sys
root=Path(__file__).resolve().parents[1]
files=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
patterns=[r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'gh[pousr]_[A-Za-z0-9]{30,}',r'AKIA[0-9A-Z]{16}']
errors=[]
for name in files:
 if not name:continue
 p=root/name
 if p.is_file() and p.stat().st_size<2_000_000:
  text=p.read_text(errors='replace')
  if any(re.search(pattern,text) for pattern in patterns):errors.append(name)
if errors:print('Potential secrets: '+', '.join(errors),file=sys.stderr);sys.exit(1)
print('OK: no embedded private-key blocks or common access-token patterns')
