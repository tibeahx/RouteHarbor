import pathlib
import tempfile
import unittest

from check_ipk_elf import EXPECTED, sdk_packages


class SDKArtifactSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='routeharbor-sdk-selector-')
        self.addCleanup(self.temporary.cleanup)
        self.sdk = pathlib.Path(self.temporary.name)
        (self.sdk / '.config').write_text('CONFIG_TARGET_ARCH_PACKAGES="x86_64"\n')
        self.recipe = self.sdk / 'Makefile'
        self.recipe.write_text('PKG_VERSION:=0.1.0\nPKG_RELEASE:=1\n')
        self.output = self.sdk / 'bin/packages/x86_64/base'
        self.output.mkdir(parents=True)
        for name in EXPECTED:
            (self.output / (name + '_0.1.0-r1_x86_64.ipk')).touch()

    def test_stale_versions_and_other_architectures_are_not_selected(self):
        for suffix in ['_0.0.9-r1_x86_64.ipk', '_0.1.0-r1_mipsel_24kc.ipk']:
            for name in EXPECTED:
                (self.output / (name + suffix)).touch()
        paths, version, architecture = sdk_packages(self.sdk, self.recipe)
        self.assertEqual(len(paths), 7)
        self.assertEqual((version, architecture), ('0.1.0-r1', 'x86_64'))
        self.assertTrue(all(path.name.endswith('_0.1.0-r1_x86_64.ipk') for path in paths))

    def test_missing_current_package_does_not_fall_back_to_stale_output(self):
        (self.output / 'routeharbor_0.1.0-r1_x86_64.ipk').unlink()
        (self.output / 'routeharbor_0.0.9-r1_x86_64.ipk').touch()
        with self.assertRaisesRegex(ValueError, 'exactly one current SDK artifact'):
            sdk_packages(self.sdk, self.recipe)

    def test_duplicate_current_artifact_is_ambiguous(self):
        other = self.sdk / 'bin/targets/x86/64/packages'
        other.mkdir(parents=True)
        (other / 'routeharbor_0.1.0-r1_x86_64.ipk').touch()
        with self.assertRaisesRegex(ValueError, 'exactly one current SDK artifact'):
            sdk_packages(self.sdk, self.recipe)

    def test_computed_recipe_version_is_not_guessed(self):
        self.recipe.write_text('PKG_VERSION:=$(SOME_VERSION)\nPKG_RELEASE:=1\n')
        with self.assertRaisesRegex(ValueError, 'literal SDK setting'):
            sdk_packages(self.sdk, self.recipe)
