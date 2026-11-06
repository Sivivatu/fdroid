#!/usr/bin/env python3
"""Import authenticated upstream APKs and publish a signed shared F-Droid feed."""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

REPO_URL = 'https://sivivatu.github.io/fdroid/repo'
ROOT = Path(__file__).resolve().parent
FINGERPRINT = re.compile(r'[a-f0-9]{64}')
PACKAGE = re.compile(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+')
BUILD_TOOLS = Path(os.environ.get('ANDROID_HOME', '/home/ubuntu/Android/Sdk')) / 'build-tools/36.1.0'
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_APK_BYTES = 512 * 1024 * 1024


def hash_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate_url(value: str) -> None:
    parsed = urlsplit(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment):
        raise ValueError('Feeds require a public HTTPS URL without credentials or query')


def validate_registry(data: dict) -> dict:
    if not FINGERPRINT.fullmatch(data['repoSha256']) or not data['apps']:
        raise ValueError('Missing central fingerprint or applications')
    packages = [app['package'] for app in data['apps']]
    if len(set(packages)) != len(packages):
        raise ValueError('Duplicate application package')
    for app in data['apps']:
        if not PACKAGE.fullmatch(app['package']) or not app['name']:
            raise ValueError('Invalid application identity')
        validate_url(app['feed'])
        for field in ['repoSha256', 'apkSha256']:
            if not FINGERPRINT.fullmatch(app[field]):
                raise ValueError('Invalid certificate fingerprint')
    return data


def run(command: list[str], cwd: Path | None = None) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'{Path(command[0]).name} failed; private output suppressed')
    return result.stdout


class SameOriginRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        old, new = urlsplit(request.full_url), urlsplit(new_url)
        if (new.scheme, new.hostname, new.port) != (old.scheme, old.hostname, old.port):
            raise ValueError('Cross-origin download redirect rejected before request')
        return super().redirect_request(request, fp, code, message, headers, new_url)


def fetch(url: str, target: Path, limit: int = MAX_INDEX_BYTES) -> None:
    validate_url(url)
    with build_opener(SameOriginRedirect()).open(url, timeout=60) as response, target.open('wb') as stream:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > limit:
                raise ValueError('Download exceeds publication size limit')
            stream.write(chunk)


def signed_feed(app: dict, work: Path) -> dict:
    for name in ['index-v1.jar', 'entry.jar', 'index-v2.json']:
        fetch(app['feed'].rstrip('/') + '/' + name, work / name)
    return authenticate_indexes(work, app['repoSha256'])


def authenticate_indexes(work: Path, fingerprint: str) -> dict:
    from fdroidserver import common, index
    common.config = {}
    common.fill_config_defaults(common.config)
    v1, _, _ = index.get_index_from_jar(
        str(work / 'index-v1.jar'), fingerprint, allow_deprecated=True)
    entry, _, _ = index.get_index_from_jar(str(work / 'entry.jar'), fingerprint)
    if entry['index']['sha256'] != digest(work / 'index-v2.json'):
        raise ValueError('Signed entry does not authenticate v2 index')
    v2 = json.loads((work / 'index-v2.json').read_text())
    v2_records = {(package, item['manifest']['versionCode'], item['file']['name'].lstrip('/'),
                   item['file']['sha256']) for package, app in v2['packages'].items()
                  for item in app['versions'].values()}
    if index_records(v1) != v2_records:
        raise ValueError('Authenticated v1 and v2 release inventories disagree')
    return v1


def validate_records(records: list[dict], apps: list[dict]) -> None:
    allowed = {app['package'] for app in apps}
    seen = set()
    for item in records:
        package, code = item['package'], item['versionCode']
        if (package not in allowed or type(code) is not int or code < 1
                or item['apkName'] != f'{package}_{code}.apk'
                or not FINGERPRINT.fullmatch(item['sha256'])
                or not isinstance(item['versionName'], str)
                or type(item['addedAt']) is not int or item['addedAt'] <= 0
                or (package, code) in seen):
            raise ValueError('Invalid or duplicate release manifest record')
        seen.add((package, code))


def merge_records(previous: list[dict], incoming: list[dict]) -> list[dict]:
    merged = {(item['package'], item['versionCode']): item for item in previous}
    for item in incoming:
        identity = item['package'], item['versionCode']
        old = merged.get(identity)
        if old and any(old[key] != item[key] for key in ['sha256', 'apkName', 'versionName']):
            raise ValueError('Published package/version cannot change')
        merged = {**merged, identity: old or item}
    return [merged[key] for key in sorted(merged)]


def verify_retained(repo: Path, records: list[dict]) -> None:
    names = {record['apkName'] for record in records}
    actual = {path.name for path in repo.glob('*.apk')}
    if actual != names:
        raise ValueError('Missing or untracked retained APK')
    for item in records:
        path = repo / item['apkName']
        if path.is_symlink() or not path.is_file() or digest(path) != item['sha256']:
            raise ValueError('Missing or altered retained APK')


def verify_apk(path: Path, app: dict, code: int, version: str) -> None:
    badging = run([str(BUILD_TOOLS / 'aapt2'), 'dump', 'badging', str(path)])
    match = re.search(r"^package: name='([^']+)' versionCode='(\d+)' versionName='([^']+)'", badging, re.M)
    if (not match or (match[1], int(match[2]), match[3]) != (app['package'], code, version)
            or 'application-debuggable' in badging):
        raise ValueError('Unexpected APK package/version or debuggable release')
    certificates = run([str(BUILD_TOOLS / 'apksigner'), 'verify', '--print-certs', str(path)])
    signers = re.findall(r'^Signer #\d+ certificate SHA-256 digest: ([a-fA-F0-9]+)$', certificates, re.M)
    if [signer.lower() for signer in signers] != [app['apkSha256']]:
        raise ValueError('APK signer does not match permanent certificate pin')


def upstream_records(app: dict, index: dict) -> list[dict]:
    versions = index['packages'][app['package']]
    records = [dict(package=app['package'], versionCode=item['versionCode'],
                    versionName=item['versionName'], apkName=item['apkName'],
                    sha256=item['hash'], addedAt=item['added'] // 1000)
               for item in versions if item.get('hashType') == 'sha256']
    if len(records) != len(versions) or not records:
        raise ValueError('Upstream requires SHA-256 releases')
    validate_records(records, [app])
    return records


def write_metadata(app: dict, index: dict, metadata: Path, records: list[dict]) -> None:
    info = next(item for item in index['apps'] if item['packageName'] == app['package'])
    fields = {'authorName': 'AuthorName', 'license': 'License', 'summary': 'Summary',
              'description': 'Description', 'categories': 'Categories',
              'sourceCode': 'SourceCode', 'webSite': 'WebSite', 'issueTracker': 'IssueTracker'}
    document = {target: info[source] for source, target in fields.items() if source in info}
    latest = max(records, key=lambda item: item['versionCode'])
    document = {**document, 'Name': app['name'], 'AutoUpdateMode': 'None',
                'UpdateCheckMode': 'None', 'CurrentVersion': latest['versionName'],
                'CurrentVersionCode': latest['versionCode']}
    # JSON is a YAML subset; no upstream executable build/config fields are accepted.
    (metadata / (app['package'] + '.yml')).write_text(json.dumps(document, indent=2) + '\n')


def import_app(app: dict, previous: list[dict], repo: Path, metadata: Path, work: Path) -> list[dict]:
    index = signed_feed(app, work)
    incoming = upstream_records(app, index)
    old = [item for item in previous if item['package'] == app['package']]
    if old and max(r['versionCode'] for r in incoming) < max(r['versionCode'] for r in old):
        raise ValueError('Upstream version rollback rejected')
    records = merge_records(previous, incoming)
    for record in incoming:
        target = repo / record['apkName']
        if not target.exists():
            fetch(app['feed'].rstrip('/') + '/' + record['apkName'], target, MAX_APK_BYTES)
        if digest(target) != record['sha256']:
            raise ValueError('Downloaded APK differs from signed upstream index')
        verify_apk(target, app, record['versionCode'], record['versionName'])
    write_metadata(app, index, metadata, [r for r in records if r['package'] == app['package']])
    return records


def restore_key(private: Path, fingerprint: str) -> Path:
    for suffix in ['KEYSTORE_BASE64', 'KEYSTORE_PASSWORD', 'KEY_ALIAS', 'KEY_PASSWORD']:
        if not os.environ.get('FDROID_' + suffix):
            raise ValueError('Missing repository signing input: FDROID_' + suffix)
    key = private / 'repository.jks'
    key.write_bytes(base64.b64decode(os.environ['FDROID_KEYSTORE_BASE64'], validate=True))
    key.chmod(0o600)
    cert = private / 'certificate.der'
    run(['keytool', '-exportcert', '-keystore', str(key), '-alias', os.environ['FDROID_KEY_ALIAS'],
         '-storepass:env', 'FDROID_KEYSTORE_PASSWORD', '-file', str(cert)])
    if digest(cert) != fingerprint:
        raise ValueError('Repository key differs from permanent certificate pin')
    return key


def write_config(work: Path, key: Path) -> None:
    config = dict(repo_url=REPO_URL, repo_name='Sivivatu Apps',
                  repo_description='Developer-operated Android apps and public betas.',
                  repo_icon='icon.png', archive_older=0, make_current_version_link=False,
                  keystore=str(key), repo_keyalias=os.environ['FDROID_KEY_ALIAS'],
                  keystorepass={'env': 'FDROID_KEYSTORE_PASSWORD'},
                  keypass={'env': 'FDROID_KEY_PASSWORD'},
                  sdk_path=str(BUILD_TOOLS.parents[1]))
    path = work / 'config.yml'
    path.write_text(json.dumps(config))
    path.chmod(0o600)


def create_icon(repo: Path) -> None:
    from PIL import Image, ImageDraw
    (repo / 'icons').mkdir(exist_ok=True)
    icon = Image.new('RGB', (192, 192), '#163c2c')
    draw = ImageDraw.Draw(icon)
    for x, y in [(40, 40), (108, 40), (40, 108), (108, 108)]:
        draw.rounded_rectangle((x, y, x + 44, y + 44), radius=10, fill='#a0ebbd')
    icon.save(repo / 'icons/icon.png')


def index_records(index: dict) -> set[tuple]:
    return {(package, item['versionCode'], item['apkName'], item['hash'])
            for package, versions in index['packages'].items() for item in versions}


def verify_indexes(work: Path, registry: dict, records: list[dict]) -> None:
    verified = authenticate_indexes(work / 'repo', registry['repoSha256'])
    expected = {(r['package'], r['versionCode'], r['apkName'], r['sha256']) for r in records}
    if index_records(verified) != expected:
        raise ValueError('Generated signed index differs from retained manifest')


def validate_public_path(path: Path, packages: set[str]) -> None:
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Unsafe public path')
    if len(path.parts) == 1 and path.name in {'index.html', '.nojekyll', 'release-manifest.json'}:
        return
    if path.parts[0] != 'repo' or len(path.parts) < 2:
        raise ValueError('Unexpected public payload')
    rest = path.parts[1:]
    indexes = {'index.jar', 'index.xml', 'index-v1.jar', 'index-v1.json', 'entry.jar',
               'entry.json', 'index-v2.json', 'index.html', 'index.css', 'index.png'}
    if len(rest) == 1 and rest[0] in indexes:
        return
    if len(rest) == 1 and any(re.fullmatch(re.escape(p) + r'_\d+\.apk', rest[0]) for p in packages):
        return
    if rest[0] == 'diff' and len(rest) == 2 and re.fullmatch(r'\d+\.json', rest[1]):
        return
    if (re.fullmatch(r'icons(?:-\d+)?', rest[0]) or rest[0] in packages) and 2 <= len(rest) <= 4:
        if re.fullmatch(r'[A-Za-z0-9_.+-]+\.(png|webp|jpg|jpeg)', rest[-1]):
            return
    raise ValueError('Unexpected public file: ' + str(path))


def validate_payload(root: Path, registry: dict) -> None:
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Symlink in public payload')
        if path.is_file():
            validate_public_path(path.relative_to(root), {app['package'] for app in registry['apps']})


def landing(registry: dict) -> str:
    url = REPO_URL + '?fingerprint=' + registry['repoSha256'].upper()
    apps = ''.join('<li>' + html.escape(app['name']) + '</li>' for app in registry['apps'])
    return f'''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Sivivatu Apps</title>
<style>body{{font:18px system-ui;max-width:780px;margin:3rem auto;padding:1rem;line-height:1.6}}code{{overflow-wrap:anywhere}}a{{color:#17663a}}</style>
<h1>Sivivatu Apps</h1><p>One F-Droid subscription for our Android apps and public betas.</p>
<ul>{apps}</ul><p><a href="fdroidrepos://{html.escape(url.removeprefix('https://'))}">Add to F-Droid</a></p>
<p>Or paste this into F-Droid → Settings → Repositories → Add:</p><p><code>{url}</code></p>
<p><img src="repo/index.png" width="192" height="192" alt="F-Droid repository QR code"></p>
<p>Repository SHA-256 fingerprint: <code>{registry['repoSha256'].upper()}</code></p>
<p>This is a developer-operated repository, separate from the default f-droid.org catalogue.
Existing installations can update because the original APK signing certificates are preserved.
Add this URL explicitly; subscriptions to the older feeds do not migrate automatically.</p>
<p><a href="https://github.com/Sivivatu/fdroid">Publication source and documentation</a></p></html>'''


def publish(registry: dict, state: Path, output: Path) -> list[dict]:
    state, output = state.resolve(), output.resolve()
    if state == output or state in output.parents or output in state.parents:
        raise ValueError('State and output must be separate directories')
    if output.exists() and any(output.iterdir()):
        raise ValueError('Public output must be empty')
    manifest = state / 'release-manifest.json'
    if manifest.is_symlink() or (state / 'repo').is_symlink():
        raise ValueError('Retained state cannot contain symlinks')
    previous = json.loads(manifest.read_text()) if manifest.exists() else []
    validate_records(previous, registry['apps'])
    verify_retained(state / 'repo', previous)
    with tempfile.TemporaryDirectory(prefix='fdroid-private-') as tmp:
        private = Path(tmp)
        private.chmod(0o700)
        work, repo = private / 'work', private / 'work/repo'
        repo.mkdir(parents=True)
        metadata = work / 'metadata'
        metadata.mkdir()
        for item in previous:
            shutil.copy2(state / 'repo' / item['apkName'], repo / item['apkName'])
        records = list(previous)
        for app in registry['apps']:
            upstream = private / app['package']
            upstream.mkdir()
            records = import_app(app, records, repo, metadata, upstream)
        for record in records:
            app = next(a for a in registry['apps'] if a['package'] == record['package'])
            verify_apk(repo / record['apkName'], app, record['versionCode'], record['versionName'])
            os.utime(repo / record['apkName'], (record['addedAt'], record['addedAt']))
        write_config(work, restore_key(private, registry['repoSha256']))
        create_icon(repo)
        run(['fdroid', 'update', '--pretty', '--use-date-from-apk'], cwd=work)
        verify_indexes(work, registry, records)
        if (repo / 'status').exists():
            shutil.rmtree(repo / 'status')
        verify_retained(repo, records)
        public = private / 'public'
        shutil.copytree(repo, public / 'repo')
        (public / 'index.html').write_text(landing(registry))
        (public / '.nojekyll').touch()
        (public / 'release-manifest.json').write_text(json.dumps(records, indent=2) + '\n')
        validate_payload(public, registry)
        shutil.copytree(public, output, dirs_exist_ok=True)
        # State is a read-only snapshot. Only the caller commits the complete,
        # validated output to its persistent Git branch, never a partial import.
    return records


def verify_live(registry: dict, base: str, expected: list[dict] | None = None) -> None:
    validate_url(base)
    with tempfile.TemporaryDirectory(prefix='fdroid-live-') as tmp:
        root = Path(tmp)
        verified = signed_feed({'feed': base.rstrip('/') + '/repo',
                                'repoSha256': registry['repoSha256']}, root)
        packages = {app['package'] for app in registry['apps']}
        if set(verified['packages']) != packages:
            raise ValueError('Live feed does not contain exactly the registered applications')
        if expected is not None:
            validate_records(expected, registry['apps'])
            wanted = {(r['package'], r['versionCode'], r['apkName'], r['sha256']) for r in expected}
            if index_records(verified) != wanted:
                raise ValueError('Live feed has not reached the deployed release manifest')
        for app in registry['apps']:
            for item in upstream_records(app, verified):
                path = root / item['apkName']
                fetch(base.rstrip('/') + '/repo/' + item['apkName'], path, MAX_APK_BYTES)
                if digest(path) != item['sha256']:
                    raise ValueError('Live APK differs from authenticated index')
                verify_apk(path, app, item['versionCode'], item['versionName'])
    print('Live signatures, package identities and all APK hashes/certificates verified.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--registry', type=Path, default=ROOT / 'apps.json')
    parser.add_argument('--state', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--verify', metavar='PAGES_BASE_URL')
    parser.add_argument('--expected-manifest', type=Path)
    args = parser.parse_args()
    registry = validate_registry(json.loads(args.registry.read_text()))
    if args.verify:
        expected = json.loads(args.expected_manifest.read_text()) if args.expected_manifest else None
        verify_live(registry, args.verify, expected)
    elif args.state and args.output:
        records = publish(registry, args.state, args.output)
        print(f'Authenticated {len(records)} releases across {len(registry["apps"])} apps.')
    else:
        parser.error('Provide --state and --output, or --verify')


if __name__ == '__main__':
    main()
