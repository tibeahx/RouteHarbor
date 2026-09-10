"""Private-disk checkpoint boundary tests; real QEMU boot is a separate lab."""
import hashlib
import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import vmctl


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = pathlib.Path(self.directory.name)
        self.scope = patch.object(vmctl, 'STATE', self.state)
        self.scope.start()
        self.addCleanup(self.scope.stop)
        (self.state / 'owner.json').write_text(json.dumps({
            'project': 'RouteHarbor isolated full-boot lab', 'image_sha256': vmctl.SHA256,
        }))
        for name, value in [('known_hosts', b'pinned-host'), ('identity.pub', b'lab-client'),
                            ('router.qcow2', b'current-disk'), ('pristine.qcow2', b'clean-disk')]:
            (self.state / name).write_bytes(value)
        self.metadata = {
            'image_sha256': vmctl.SHA256,
            'host_identity': self.digest('known_hosts'),
            'client_identity': self.digest('identity.pub'),
            'disk_sha256': self.digest('pristine.qcow2'),
        }
        (self.state / 'pristine.json').write_text(json.dumps(self.metadata))

    def digest(self, name):
        return hashlib.sha256((self.state / name).read_bytes()).hexdigest()

    def test_foreign_owner_is_refused_before_guest_or_disk_access(self):
        (self.state / 'owner.json').write_text('{}')
        with patch.object(vmctl, 'guest') as guest:
            with self.assertRaisesRegex(RuntimeError, 'Foreign'):
                vmctl.snapshot_pristine(True)
            guest.assert_not_called()
        self.assertEqual((self.state / 'router.qcow2').read_bytes(), b'current-disk')

    def test_identity_or_disk_change_is_refused(self):
        for name in ('known_hosts', 'identity.pub', 'pristine.qcow2'):
            with self.subTest(name=name):
                path = self.state / name
                original = path.read_bytes()
                path.write_bytes(b'changed')
                with patch.object(vmctl, 'guest') as guest:
                    with self.assertRaisesRegex(RuntimeError, 'identity|hash'):
                        vmctl.snapshot_pristine(True)
                    guest.assert_not_called()
                path.write_bytes(original)

    def test_active_disk_is_never_copied(self):
        with patch.object(vmctl, 'guest', return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(vmctl, 'stop_vm'), patch.object(vmctl, 'running_pid', return_value=12):
            with self.assertRaisesRegex(RuntimeError, 'active-disk'):
                vmctl.snapshot_pristine(True)
        self.assertEqual((self.state / 'router.qcow2').read_bytes(), b'current-disk')
        self.assertFalse((self.state / 'before-restore.qcow2').exists())

    def test_unreachable_guest_restore_retains_prior_disk_and_pinned_identity(self):
        with patch.object(vmctl, 'guest', side_effect=subprocess.TimeoutExpired('ssh', 5)), \
                patch.object(vmctl, 'stop_vm') as stopped, \
                patch.object(vmctl, 'running_pid', return_value=None), \
                patch.object(vmctl, 'start') as started, \
                patch.object(vmctl, 'wait_ssh', return_value='new-boot'):
            vmctl.snapshot_pristine(True)
            stopped.assert_called_once()
            started.assert_called_once()
        self.assertEqual((self.state / 'router.qcow2').read_bytes(), b'clean-disk')
        self.assertEqual((self.state / 'before-restore.qcow2').read_bytes(), b'current-disk')
        self.assertEqual(self.digest('known_hosts'), self.metadata['host_identity'])
        self.assertEqual(self.digest('identity.pub'), self.metadata['client_identity'])


if __name__ == '__main__':
    unittest.main()
