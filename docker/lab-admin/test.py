"""Real Linux privilege-drop, authentication and age-backup lab; no router access."""
import json
import os
import pathlib
import subprocess
import time
import urllib.error
import urllib.request

UID = GID = 37071
state = pathlib.Path('/etc/openrhp')
private = pathlib.Path('/root/test-private')
private.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(private, 0o700)
os.chmod(state, 0o700)

def command(*args, success=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=35)
    if success and result.returncode:
        raise AssertionError('Lab command failed without exposing secret output: ' + args[0])
    if not success and result.returncode == 0:
        raise AssertionError('Expected unsafe or unauthorized operation to fail')
    return result

command('/usr/bin/openrhp', 'bootstrap', '--state', str(state), '--token-file', str(private / 'initial.token'))
config_file = state / 'config.json'
cfg = json.loads(config_file.read_text())
secret = 'PRIVATE-source-password-canary-admin-lab'
cfg['sources'] = [{'id': 'lab-proxy', 'name': 'Lab private proxy', 'type': 'socks5', 'enabled': True, 'auto': True,
                   'settings': {'server': '203.0.113.10', 'server_port': 1080, 'username': 'lab-user', 'password': secret}}]
config_file.write_text(json.dumps(cfg))
for path in [state / '.lock', config_file, state / 'auth/.credentials.lock', state / 'auth/credentials.json', state / 'auth', state]:
    os.chown(path, UID, GID, follow_symlinks=False)

blocked = command('/usr/bin/openrhp', 'token', '--state', str(state), '--out', str(private / 'wrong.token'), success=False)
assert 'as-service token' in blocked.stderr
assert not (private / 'wrong.token').exists()
command('/usr/bin/openrhp', 'as-service', 'serve', success=False)

token_file = state / 'admin/read.token'
issued = command('/usr/bin/openrhp', 'as-service', 'token', '--state', str(state), '--role', 'read', '--out', str(token_file))
token = token_file.read_text().strip()
credential_id = issued.stdout.split()[1]
assert token and token not in issued.stdout + issued.stderr
assert token_file.stat().st_uid == UID and token_file.stat().st_mode & 0o777 == 0o600
assert (state / 'auth/credentials.json').stat().st_uid == UID
command('/usr/bin/openrhp', 'as-service', 'token', '--state', str(state), '--role', 'read', '--out', str(private / 'forbidden.token'), success=False)
assert not (private / 'forbidden.token').exists()

def become_service():
    os.setgroups([])
    os.setgid(GID)
    os.setuid(UID)

server = subprocess.Popen(['/usr/bin/openrhp', 'serve', '--state', str(state), '--runtime', '/tmp/admin-lab-engines', '--listen', '127.0.0.1:18787'],
                          preexec_fn=become_service, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
def api_status():
    request = urllib.request.Request('http://127.0.0.1:18787/api/v1/config', headers={'Authorization': 'Bearer ' + token})
    try:
        with urllib.request.urlopen(request, timeout=1) as response:
            data = response.read()
            assert secret.encode() not in data
            return response.status
    except urllib.error.HTTPError as err:
        return err.code

try:
    for _ in range(50):
        try:
            assert api_status() == 200
            break
        except urllib.error.URLError:
            time.sleep(0.1)
    else:
        raise AssertionError('Real service-user API did not start')
    command('/usr/bin/openrhp', 'as-service', 'token', '--state', str(state), '--revoke', credential_id)
    assert api_status() == 401
finally:
    server.terminate()
    server.wait(timeout=15)

key = private / 'age.key'
command('age-keygen', '-o', str(key))
recipient = command('age-keygen', '-y', str(key)).stdout.strip()
backup = state / 'admin/config.age'
blocked = command('/usr/bin/openrhp', 'backup', '--state', str(state), '--recipient', recipient, '--out', str(private / 'wrong.age'), success=False)
assert 'as-service backup' in blocked.stderr
encrypted = command('/usr/bin/openrhp', 'as-service', 'backup', '--state', str(state), '--recipient', recipient, '--out', str(backup))
assert secret not in encrypted.stdout + encrypted.stderr
assert backup.stat().st_uid == UID and backup.stat().st_mode & 0o777 == 0o600
assert secret.encode() not in backup.read_bytes()
decoded = private / 'decrypted.json'
command('age', '--decrypt', '--identity', str(key), '--output', str(decoded), str(backup))
assert json.loads(decoded.read_text()) == cfg
for path in [config_file, state / 'auth/credentials.json', state / 'auth', state]:
    assert path.stat().st_uid == UID
print('PASS: root drops to the actual service UID; token issue/authenticate/revoke, forbidden root output, and real age secret backup round trip.')
