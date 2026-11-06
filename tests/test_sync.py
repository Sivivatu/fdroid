import json
import tempfile
import unittest
import os
import io
from contextlib import redirect_stdout
from urllib.request import Request
from pathlib import Path
from unittest.mock import patch

import sync


class RegistryTests(unittest.TestCase):
    def app(self, **overrides):
        return dict(package='org.example.app', name='Example',
                    feed='https://example.github.io/app/repo',
                    repoSha256='a' * 64, apkSha256='b' * 64, **overrides)

    def test_accepts_registry_and_preserves_input(self):
        data = {'repoSha256': 'a' * 64, 'apps': [self.app()]}
        self.assertEqual(sync.validate_registry(data), data)

    def test_rejects_invalid_identity_url_and_duplicate_package(self):
        for key, value in [('package', '../escape'), ('repoSha256', 'abc'),
                           ('apkSha256', 'G' * 64), ('feed', 'http://example.com'),
                           ('feed', 'https://user:pass@example.com/repo'),
                           ('feed', 'https://example.com/repo?x=1')]:
            with self.subTest(key=key, value=value):
                app = {**self.app(), key: value}
                with self.assertRaises(ValueError):
                    sync.validate_registry({'repoSha256': 'a' * 64, 'apps': [app]})
        with self.assertRaises(ValueError):
            sync.validate_registry({'repoSha256': 'a' * 64, 'apps': [self.app(), self.app()]})


class HistoryTests(unittest.TestCase):
    def record(self, package='org.example.one', code=1, sha='a' * 64):
        return dict(package=package, versionCode=code, versionName=str(code),
                    apkName=f'{package}_{code}.apk', sha256=sha, addedAt=1234)

    def test_independent_version_sequences_and_exact_retry(self):
        old = [self.record(code=50)]
        other = self.record(package='org.example.two')
        self.assertEqual(sync.merge_records(old, [other]), [*old, other])
        self.assertEqual(sync.merge_records(old, old), old)
        self.assertEqual(old, [self.record(code=50)])

    def test_rejects_changed_bytes_or_version_name(self):
        old = self.record()
        for changed in [{**old, 'sha256': 'b' * 64}, {**old, 'versionName': 'changed'}]:
            with self.assertRaises(ValueError):
                sync.merge_records([old], [changed])

    def test_retry_preserves_original_date_and_allows_missing_historical_import(self):
        old = self.record(code=5)
        self.assertEqual(sync.merge_records([old], [{**old, 'addedAt': 9999}]), [old])
        self.assertEqual(sync.merge_records([old], [self.record()]), [self.record(), old])

    def test_manifest_rejects_unsafe_duplicate_or_unknown_records(self):
        apps = [{'package': 'org.example.one'}]
        for records in [[self.record(), self.record()],
                        [{**self.record(), 'apkName': '../key.jks'}],
                        [self.record(package='org.unknown.app')],
                        [{**self.record(), 'versionCode': True}],
                        [{**self.record(), 'addedAt': -1}]]:
            with self.assertRaises(ValueError):
                sync.validate_records(records, apps)

    def test_retained_files_reject_missing_modified_extra_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apk = root / self.record()['apkName']
            record = {**self.record(), 'sha256': sync.hash_bytes(b'apk')}
            with self.assertRaises(ValueError):
                sync.verify_retained(root, [record])
            apk.write_bytes(b'apk')
            sync.verify_retained(root, [record])
            apk.write_bytes(b'tampered')
            with self.assertRaises(ValueError):
                sync.verify_retained(root, [record])
            apk.unlink()
            apk.symlink_to('/etc/hosts')
            with self.assertRaises(ValueError):
                sync.verify_retained(root, [record])


class BoundaryTests(unittest.TestCase):
    def test_redirect_is_rejected_before_an_internal_request(self):
        handler = sync.SameOriginRedirect()
        request = Request('https://example.com/repo/entry.jar')
        for url in ['http://169.254.169.254/latest/meta-data', 'https://internal/key',
                    'https://example.com:444/key']:
            with self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, 'Moved', {}, url)
        redirected = handler.redirect_request(request, None, 302, 'Moved', {},
                                              'https://example.com/new/entry.jar')
        self.assertEqual(redirected.full_url, 'https://example.com/new/entry.jar')

    def test_fetch_bounds_download_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('sync.build_opener') as opener:
                response = opener.return_value.open.return_value.__enter__.return_value
                response.read.side_effect = [b'abc', b'']
                sync.fetch('https://example.com/file', Path(tmp) / 'file')
                self.assertEqual((Path(tmp) / 'file').read_bytes(), b'abc')
                response.read.side_effect = [b'abc']
                with self.assertRaises(ValueError):
                    sync.fetch('https://example.com/file', Path(tmp) / 'file', limit=2)

    def test_public_payload_allowlist(self):
        for name in ['repo/index-v1.jar', 'repo/entry.jar', 'repo/index-v2.json',
                     'repo/org.example.app_1.apk', 'repo/icons-160/org.example.app.1.png',
                     'index.html', 'release-manifest.json', '.nojekyll']:
            sync.validate_public_path(Path(name), {'org.example.app'})
        for name in ['config.yml', 'repo/config.yml', 'repo/key.jks', 'repo/.env',
                     '../escape', 'repo/unknown.app_1.apk', 'repo/status/update.json',
                     'repo/icons/private.json']:
            with self.assertRaises(ValueError, msg=name):
                sync.validate_public_path(Path(name), {'org.example.app'})

    def test_apk_checks_package_version_debuggable_and_signer(self):
        app = {'package': 'org.example.app', 'apkSha256': 'b' * 64}
        badging = "package: name='org.example.app' versionCode='1' versionName='1.0'\n"
        signer = 'Signer #1 certificate SHA-256 digest: ' + 'b' * 64
        with patch('sync.run', side_effect=[badging, signer]):
            sync.verify_apk(Path('app.apk'), app, 1, '1.0')
        for bad in [badging.replace('org.example.app', 'other.app'),
                    badging.replace("versionCode='1'", "versionCode='2'"),
                    badging + 'application-debuggable']:
            with patch('sync.run', return_value=bad), self.assertRaises(ValueError):
                sync.verify_apk(Path('app.apk'), app, 1, '1.0')
        with patch('sync.run', side_effect=[badging, signer.replace('b', 'c')]):
            with self.assertRaises(ValueError):
                sync.verify_apk(Path('app.apk'), app, 1, '1.0')

    def test_signed_feed_uses_pinned_signatures_and_v2_hash(self):
        from fdroidserver import index
        app = {'feed': 'https://example.com/repo', 'repoSha256': 'a' * 64}
        with tempfile.TemporaryDirectory() as tmp:
            def fetch(url, target, **kwargs):
                target.write_bytes(b'{"packages": {}}' if url.endswith('index-v2.json') else b'jar')
            with patch('sync.fetch', side_effect=fetch), patch.object(
                index, 'get_index_from_jar', side_effect=[({'packages': {}}, None, None),
                ({'index': {'sha256': sync.hash_bytes(b'{"packages": {}}')}}, None, None)]
            ) as verify:
                self.assertEqual(sync.signed_feed(app, Path(tmp)), {'packages': {}})
                self.assertEqual(verify.call_args_list[0].args[1], 'a' * 64)
            with patch('sync.fetch', side_effect=fetch), patch.object(
                index, 'get_index_from_jar', side_effect=[({}, None, None),
                ({'index': {'sha256': '0' * 64}}, None, None)]
            ), self.assertRaises(ValueError):
                sync.signed_feed(app, Path(tmp))
            with patch('sync.fetch', side_effect=fetch), patch.object(
                index, 'get_index_from_jar', side_effect=ValueError('bad signature')
            ), self.assertRaises(ValueError):
                sync.signed_feed(app, Path(tmp))


class PublisherIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.app = dict(package='org.example.app', name='Example <App>',
                        feed='https://example.com/repo', apkSha256='b' * 64,
                        repoSha256='a' * 64)
        self.registry = dict(repoSha256='a' * 64, apps=[self.app])
        self.version = dict(versionCode=1, versionName='1.0',
                            apkName='org.example.app_1.apk', hash=sync.hash_bytes(b'apk'),
                            hashType='sha256', added=1234000)
        self.index = dict(packages={'org.example.app': [self.version]},
                          apps=[dict(packageName='org.example.app', summary='Example',
                                     description='Example app', license='MIT')])

    def fake_fetch(self, url, path, *args, **kwargs):
        path.write_bytes(b'apk')

    def test_publish_complete_snapshot_retry_and_read_only_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def fdroid(command, cwd=None):
                repo = cwd / 'repo'
                (repo / 'index-v1.jar').write_bytes(b'signed')
                (repo / 'status').mkdir()
                return ''
            with patch('sync.signed_feed', return_value=self.index), patch('sync.fetch', self.fake_fetch), \
                 patch('sync.verify_apk'), patch('sync.restore_key', return_value=root / 'key.jks'), \
                 patch.dict(os.environ, {'FDROID_KEY_ALIAS': 'test'}), \
                 patch('sync.run', side_effect=fdroid), patch('sync.verify_indexes'):
                records = sync.publish(self.registry, root / 'empty', root / 'first')
                self.assertFalse((root / 'empty').exists())
                before = (root / 'first/release-manifest.json').read_bytes()
                retried = sync.publish(self.registry, root / 'first', root / 'second')
                self.assertEqual(records, retried)
                self.assertEqual(before, (root / 'first/release-manifest.json').read_bytes())
                self.assertEqual(before, (root / 'second/release-manifest.json').read_bytes())
                self.assertFalse((root / 'second/repo/status').exists())
                self.assertIn('Example &lt;App&gt;', (root / 'second/index.html').read_text())
                with self.assertRaises(ValueError):
                    sync.publish(self.registry, root / 'first', root / 'first/subdirectory')
                with self.assertRaises(ValueError):
                    sync.publish(self.registry, root / 'empty', root / 'first')

    def test_import_rejects_hash_failure_and_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record = sync.upstream_records(self.app, self.index)[0]
            with patch('sync.signed_feed', return_value=self.index), \
                 patch('sync.fetch', side_effect=lambda url, path, limit: path.write_bytes(b'bad')):
                with self.assertRaises(ValueError):
                    sync.import_app(self.app, [], root, root, root)
                with self.assertRaises(ValueError):
                    sync.import_app(self.app, [{**record, 'versionCode': 2}], root, root, root)
            with self.assertRaises(ValueError):
                sync.upstream_records(self.app, {**self.index, 'packages': {'org.example.app': []}})

    def test_repository_key_pin_and_required_inputs(self):
        secrets = dict(FDROID_KEYSTORE_BASE64='a2V5', FDROID_KEYSTORE_PASSWORD='test',
                       FDROID_KEY_ALIAS='test', FDROID_KEY_PASSWORD='test')
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
                sync.restore_key(root, 'a' * 64)
            def keytool(command):
                (root / 'certificate.der').write_bytes(b'certificate')
                return ''
            with patch.dict(os.environ, secrets), patch('sync.run', side_effect=keytool):
                sync.restore_key(root, sync.hash_bytes(b'certificate'))
                self.assertEqual((root / 'repository.jks').stat().st_mode & 0o777, 0o600)
                with self.assertRaises(ValueError):
                    sync.restore_key(root, 'a' * 64)

    def test_local_index_inventory_and_live_download_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            record = sync.upstream_records(self.app, self.index)[0]
            with patch('sync.authenticate_indexes', return_value=self.index):
                sync.verify_indexes(Path(tmp), self.registry, [record])
                with self.assertRaises(ValueError):
                    sync.verify_indexes(Path(tmp), self.registry, [])
            with patch('sync.signed_feed', return_value=self.index), \
                 patch('sync.fetch', self.fake_fetch), patch('sync.verify_apk'), redirect_stdout(io.StringIO()):
                sync.verify_live(self.registry, 'https://example.com')
                sync.verify_live(self.registry, 'https://example.com', [record])
                with self.assertRaises(ValueError):
                    sync.verify_live(self.registry, 'https://example.com', [{**record, 'versionCode': 2,
                                      'apkName': 'org.example.app_2.apk'}])
                with self.assertRaises(ValueError):
                    sync.verify_live({**self.registry, 'apps': []}, 'https://example.com')

    def test_payload_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'index.html').symlink_to('/etc/hosts')
            with self.assertRaises(ValueError):
                sync.validate_payload(Path(tmp), self.registry)

    def test_command_line_routes_verify_and_publish(self):
        with patch('sys.argv', ['sync.py', '--verify', 'https://example.com']), \
             patch('sync.verify_live') as verify:
            sync.main()
            verify.assert_called_once()
        with patch('sys.argv', ['sync.py', '--state', 'state', '--output', 'public']), \
             patch('sync.publish', return_value=[]) as publish, redirect_stdout(io.StringIO()):
            sync.main()
            publish.assert_called_once()


if __name__ == '__main__':
    unittest.main()
