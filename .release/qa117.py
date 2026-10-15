#!/usr/bin/env python3
"""Publish the owner-authorized 1.1.7 QA binaries; no private app source or key."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import zipfile
import xml.etree.ElementTree as ET
from urllib.request import Request, urlopen
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO = 'AndSuch-Mods/General-AI-Test-Space-9'
INITIAL = '5d4159b9a1397c555a0cdf27800b2a82fbaff8e2'
TAG = 'csi-maklock-qa-1.1.7-build116'
PREVIOUS_TAG = 'csi-maklock-qa-1.1.6-build115'
CHANNEL = 'csi-maklock-qa-automatic-update-r6'
BRANCH = 'csi/release-1.1.7'
RECEIVER = 'csi-staging/117-receiver'
PAYLOAD = 'csi-staging/117-encrypted'
REPORT = 'csi-staging/117-status'
SOURCE = '21acd59b6cc8ef66afef8a1e66131b73d04e051f'
PACKAGE = 'CSI-MakLock-1.1.7-QA.pkg'
LEGACY = 'CSI-MakLock-1.1.5-QA.pkg'
KEY = 'GkAuP9JPTXXLJ/lYnKHfueGYs3gsp7FvSzOt+KMk6nY='
PACKAGE_HASH = 'e52d62eb6df921a4782fbd9a4775b03a50092eb3c6df4d0de579117560322cc4'
FEED_HASH = '6878faac6fcdbf1721cd09c76cb7ea96819e1254d9796d9daf030b740116923c'
OLD_PACKAGE_HASH = '7c1d61e2a7e823a931f5e71559ec595ae8e9637cf377721d593ca28f298429b6'
OLD_FEED_HASH = '71f23b9cfe7850bf3a30ae2e61625b3fbdb0d7383a19ec22aca35f81b7eaa369'
ALLOW = {PACKAGE, 'appcast.xml', 'update-manifest.json', 'public-key.txt', 'SHA256SUMS'}
PREFIX = f'https://github.com/{REPO}/releases/download/{CHANNEL}/'
TITLE = 'CSI MakLock 1.1.7 QA, build 116'
NOTES = 'Test-only 1.1.7 for icon review. Uses the owner-selected 3D yellow padlock and green CSI badge with a black interior, with exact 1x/2x menu and window artwork. The flatter alternative is not included.\n\nAutomatic startup update checks now wait two minutes for Wi-Fi. Check for Updates remains immediate; routine checking continues about 24 hours after the previous check finishes. Existing CSI MakLock password, Keychain identity, settings, protected apps and Watch selection are preserved. This is not the future 1.0.0 release.\n\nDownload CSI-MakLock-1.1.7-QA.pkg and install over the existing application. No password reset or preferences deletion is needed. This is an unsigned QA installer with an ad-hoc signed app, not Apple-notarized software. Use the supported macOS Privacy & Security approval if required. The Sparkle feed and package use the existing trusted Ed25519 key. In-app installation still requires the independent CSI MakLock password and allows protected apps to save work before closing. Protection is unavailable while the MakLock process is stopped for replacement.\n\nBuilt and packaged on the private self-hosted Apple silicon Mac with universal arm64/x86_64 slices. Model, SDK, signature, package and compiled-artwork checks are automated; external-monitor appearance, Intel/macOS 15 runtime behavior and human Gatekeeper/administrator prompts still need owner testing. No new hosted Mac runner is used for this release.\n\nOlder canonical releases remain unchanged. The r6 channel keeps its legacy package URL for compatibility and preserves the preceding package/metadata before activating the signed feed. Only binaries and release metadata are public. No private application source is published.'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root):
    files = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
    assert set(files) == ALLOW and len(list(root.iterdir())) == len(ALLOW), 'Unexpected distribution files'
    m = json.loads(files['update-manifest.json'])
    assert m['sourceCommit'] == SOURCE and m['version'] == '1.1.7' and m['build'] == 116
    assert m['startingVersion'] == '1.1.6' and m['startingBuild'] == 115 and m['testOnly'] is True
    assert m['repository'] == REPO and m['releaseTag'] == TAG and m['channelTag'] == CHANNEL
    assert m['feedURL'] == PREFIX + 'appcast.xml' and m['packageURL'] == PREFIX + LEGACY
    assert m['canonicalPackageURL'] == f'https://github.com/{REPO}/releases/download/{TAG}/{PACKAGE}'
    assert m['startingPackageSHA256'] == OLD_PACKAGE_HASH and m['previousAppcastSHA256'] == OLD_FEED_HASH
    assert m['packageSHA256'] == digest(files[PACKAGE]) == PACKAGE_HASH and len(files[PACKAGE]) == m['length']
    assert m['appcastSHA256'] == digest(files['appcast.xml']) == FEED_HASH
    assert m['publicKey'] == files['public-key.txt'].decode().strip() == KEY
    assert files['SHA256SUMS'].decode() == PACKAGE_HASH + '  ' + PACKAGE + '\n'
    key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(KEY, validate=True))
    key.verify(base64.b64decode(m['edSignature'], validate=True), files[PACKAGE])
    feed = files['appcast.xml']
    match = re.search(rb'<!-- sparkle-signatures:\nedSignature: ([A-Za-z0-9+/=]+)\nlength: ([0-9]+)\n-->\s*\Z', feed)
    assert match and int(match[2]) == match.start(), 'Invalid signed feed trailer'
    key.verify(base64.b64decode(match[1], validate=True), feed[:match.start()])
    items = ET.fromstring(feed).findall('./channel/item')
    assert len(items) == 1
    attrs = items[0].find('enclosure').attrib
    namespace = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'
    expected = {'url': m['packageURL'], 'length': str(m['length']), namespace+'version': '116',
                namespace+'shortVersionString': '1.1.7', namespace+'installationType': 'package',
                namespace+'edSignature': m['edSignature']}
    assert all(attrs.get(k) == v for k, v in expected.items())
    return files


class GitHub:
    def api(self, path, method='GET', body=None, binary=False):
        command = ['gh', 'api', '--method', method, 'repos/' + REPO + '/' + path]
        if binary:
            command += ['-H', 'Accept: application/octet-stream']
        if body is not None:
            command += ['--input', '-']
        result = subprocess.check_output(command, input=json.dumps(body).encode() if body is not None else None)
        return result if binary else json.loads(result)

    def releases(self):
        return self.api('releases?per_page=100')

    def read(self, release_id):
        return self.api('releases/' + str(release_id))

    def download(self, asset):
        data = self.api('releases/assets/' + str(asset['id']), binary=True)
        assert asset['size'] == len(data) and asset.get('digest') == 'sha256:' + digest(data)
        return data

    def upload(self, release_id, name, data):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / name
            path.write_bytes(data)
            subprocess.run(['gh', 'api', '--method', 'POST', '-H', 'Content-Type: application/octet-stream',
                            f'https://uploads.github.com/repos/{REPO}/releases/{release_id}/assets?name={name}',
                            '--input', str(path)], stdout=subprocess.DEVNULL, check=True)

    def rename(self, asset, name):
        return self.api('releases/assets/' + str(asset['id']), 'PATCH', {'name': name})

    def publish(self, release_id):
        return self.api('releases/' + str(release_id), 'PATCH', {'draft': False, 'make_latest': 'false'})


def release_for(github, tag):
    matches = [r for r in github.releases() if r['tag_name'] == tag]
    assert len(matches) == 1, 'Expected exactly one release for ' + tag
    release = github.read(matches[0]['id'])
    assert release['prerelease']
    if tag == CHANNEL:
        assert release['target_commitish'] == INITIAL
    else:
        assert re.fullmatch(r'[0-9a-f]{40}', release['target_commitish'])
    return release


def assets(release):
    result = {a['name']: a for a in release['assets']}
    assert len(result) == len(release['assets']), 'Duplicate assets'
    return result


def ensure_asset(github, release_id, name, data):
    present = assets(github.read(release_id)).get(name)
    if present:
        assert github.download(present) == data, 'Existing asset differs: ' + name
    else:
        github.upload(release_id, name, data)
        assert github.download(assets(github.read(release_id))[name]) == data


def promote(github, candidate, files):
    """Archive the original bytes; change the compatibility package, then feed LAST.

    Each operation is idempotent. A partial replacement can only cause signature
    rejection, never acceptance of a mismatched package. A retry completes it.
    """
    assert set(assets(candidate)) == ALLOW
    assert candidate['tag_name'] == TAG and re.fullmatch(r'[0-9a-f]{40}', candidate['target_commitish'])
    assert all(github.download(asset) == files[name] for name, asset in assets(candidate).items())
    previous = release_for(github, PREVIOUS_TAG)
    assert not previous['draft']
    previous_files = {name: github.download(asset) for name, asset in assets(previous).items()}
    assert digest(previous_files['CSI-MakLock-1.1.6-QA.pkg']) == OLD_PACKAGE_HASH
    assert digest(previous_files['appcast.xml']) == OLD_FEED_HASH
    channel = release_for(github, CHANNEL)
    assert not channel['draft']
    channel_id = channel['id']
    names = assets(channel)
    archive_names = {LEGACY: 'CSI-MakLock-1.1.6-build115-QA.pkg', 'appcast.xml': 'appcast-build115.xml',
                     'update-manifest.json': 'update-manifest-build115.json', 'SHA256SUMS': 'SHA256SUMS-build115'}
    # Recover original bytes either from the unchanged live assets or their archives.
    originals = {}
    for name, archived in archive_names.items():
        item = names.get(archived) or names.get(name)
        assert item is not None, 'Missing original ' + name
        originals[name] = github.download(item)
    assert digest(originals[LEGACY]) == OLD_PACKAGE_HASH
    assert digest(originals['appcast.xml']) == OLD_FEED_HASH
    old_manifest = json.loads(originals['update-manifest.json'])
    assert old_manifest['packageSHA256'] == OLD_PACKAGE_HASH and old_manifest['appcastSHA256'] == OLD_FEED_HASH
    assert old_manifest['version'] == '1.1.6' and old_manifest['build'] == 115 and old_manifest['publicKey'] == KEY
    assert originals['SHA256SUMS'].decode() == OLD_PACKAGE_HASH + '  ' + LEGACY + '\n'
    assert github.download(names['public-key.txt']).decode().strip() == KEY
    replacements = {LEGACY: files[PACKAGE], 'update-manifest.json': files['update-manifest.json'],
                    'SHA256SUMS': (PACKAGE_HASH + '  ' + LEGACY + '\n').encode(), 'appcast.xml': files['appcast.xml']}
    for name, replacement in replacements.items():
        if name in names:
            assert github.download(names[name]) in (originals[name], replacement), 'Unexpected live channel bytes: ' + name
    # Publish only after all preflight validation; the user already approved this job.
    if candidate['draft']:
        github.publish(candidate['id'])
    # Save immutable copies of all original metadata before modifying any live address.
    for name, archived in archive_names.items():
        ensure_asset(github, channel_id, archived, originals[name])
    for name, replacement in replacements.items():
        current = assets(github.read(channel_id)).get(name)
        if current and github.download(current) == replacement:
            continue
        if current:
            # Preserve the original asset ID and bytes as an additional legacy backup.
            backup = archive_names[name] + '.original'
            assert backup not in assets(github.read(channel_id)), 'Unexpected existing backup'
            github.rename(current, backup)
        ensure_asset(github, channel_id, name, replacement)
    final = assets(github.read(channel_id))
    assert all(github.download(final[name]) == data for name, data in replacements.items())
    assert all(github.download(final[archive_names[name]]) == data for name, data in originals.items())
    assert not github.read(candidate['id'])['draft']
    assert {name: github.download(asset) for name, asset in assets(github.read(previous['id'])).items()} == previous_files
    return {'published': True, 'releaseURL': candidate['html_url'], 'publicFeedSHA256': FEED_HASH,
            'packageSHA256': PACKAGE_HASH, 'previous116Preserved': True, 'sourceCommit': SOURCE, 'version': '1.1.7', 'build': 116, 'feedChangedLast': True}


def write_branch(branch, files, message):
    """Append status/transport metadata without rewriting any existing history."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        subprocess.run(['git', 'init', '-q', str(root)], check=True)
        def git(*args):
            return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()
        origin = subprocess.check_output(['git', 'remote', 'get-url', 'origin'], text=True).strip()
        git('remote', 'add', 'origin', origin)
        git('config', 'user.name', 'github-actions[bot]')
        git('config', 'user.email', '41898282+github-actions[bot]@users.noreply.github.com')
        # Reuse checkout's authenticated extraheader without printing its value.
        config = subprocess.run(['git', 'config', '--get-regexp', r'http\..*\.extraheader'], capture_output=True, text=True)
        for line in config.stdout.splitlines():
            name, value = line.split(' ', 1)
            git('config', name, value)
        if git('ls-remote', '--heads', 'origin', 'refs/heads/' + branch):
            git('fetch', '--depth=1', 'origin', branch)
            git('checkout', '-b', branch, 'FETCH_HEAD')
        else:
            git('checkout', '--orphan', branch)
        for name, data in files.items():
            (root / name).write_bytes(data)
        git('add', *files)
        if git('status', '--porcelain'):
            git('commit', '-m', message)
            git('push', 'origin', 'HEAD:refs/heads/' + branch)


def receive(root):
    run = os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT']
    assert re.fullmatch(r'[0-9]+-[0-9]+', run)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    handshake = {'run': run, 'tag': TAG, 'publicKeySHA256': digest(public), 'packageSHA256': PACKAGE_HASH}
    write_branch(RECEIVER, {'receiver.json': json.dumps(handshake).encode(), 'receiver.pem': public}, 'Prepare ephemeral encrypted QA receiver')
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        found = subprocess.check_output(['git', 'ls-remote', '--heads', 'origin', 'refs/heads/' + PAYLOAD], text=True)
        if found:
            subprocess.run(['git', 'fetch', '-q', 'origin', PAYLOAD], check=True)
            def read(name): return subprocess.check_output(['git', 'show', 'FETCH_HEAD:' + name])
            metadata = json.loads(read('transport.json'))
            if metadata['run'] == run:
                assert metadata['publicKeySHA256'] == digest(public) and metadata['tag'] == TAG
                symmetric = key.decrypt(read('wrapped-key.bin'), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=run.encode()))
                archive = AESGCM(symmetric).decrypt(base64.b64decode(metadata['nonce'], validate=True), read('candidate.enc'), run.encode())
                root.mkdir(parents=True, exist_ok=False)
                with zipfile.ZipFile(io.BytesIO(archive)) as contents:
                    assert len(contents.infolist()) == len(ALLOW) and set(contents.namelist()) == ALLOW
                    for name in ALLOW:
                        assert contents.getinfo(name).file_size < 20_000_000
                        (root / name).write_bytes(contents.read(name))
                verify(root)
                return
        time.sleep(5)
    raise RuntimeError('Encrypted candidate was not delivered before timeout; no release changed.')


def ensure_release_tag():
    reference = 'refs/tags/' + TAG
    expected = os.environ['GITHUB_SHA']
    existing = subprocess.check_output(['git', 'ls-remote', '--refs', 'origin', reference], text=True).strip()
    if not existing:
        subprocess.run(['git', 'push', 'origin', expected + ':' + reference], check=True)
        existing = subprocess.check_output(['git', 'ls-remote', '--refs', 'origin', reference], text=True).strip()
    assert existing.split() == [expected, reference], 'Never overwrite an existing tag'


def stage(github, root):
    files = verify(root)
    # Verify current channel and the immutable prior release before creating anything.
    channel = release_for(github, CHANNEL)
    assert not channel['draft']
    names = assets(channel)
    # A failed upload may leave the live name absent after the old asset was
    # archived. Resume using the verified archive; never invent predecessor data.
    feed = names.get('appcast.xml') or names.get('appcast-build115.xml')
    package = names.get(LEGACY) or names.get('CSI-MakLock-1.1.6-build115-QA.pkg')
    assert feed and package
    assert digest(github.download(feed)) in {OLD_FEED_HASH, FEED_HASH}
    assert digest(github.download(package)) in {OLD_PACKAGE_HASH, PACKAGE_HASH}
    previous = release_for(github, PREVIOUS_TAG)
    assert not previous['draft']
    assert digest(github.download(assets(previous)['CSI-MakLock-1.1.6-QA.pkg'])) == OLD_PACKAGE_HASH
    assert digest(github.download(assets(previous)['appcast.xml'])) == OLD_FEED_HASH
    ensure_release_tag()
    existing = [r for r in github.releases() if r['tag_name'] == TAG]
    assert len(existing) <= 1
    if existing:
        candidate = github.read(existing[0]['id'])
    else:
        candidate = github.api('releases', 'POST', {
            'tag_name': TAG, 'target_commitish': os.environ['GITHUB_SHA'],
            'name': TITLE, 'body': NOTES, 'draft': True, 'prerelease': True,
            'make_latest': 'false'})
    assert candidate['prerelease'] and candidate['tag_name'] == TAG
    assert candidate['target_commitish'] == os.environ['GITHUB_SHA']
    assert candidate['name'] == TITLE and candidate['body'] == NOTES
    assert set(assets(candidate)) <= ALLOW
    for name, asset in assets(candidate).items():
        assert github.download(asset) == files[name], 'Refusing to overwrite different candidate bytes'
    if not candidate['draft']:
        assert set(assets(candidate)) == ALLOW
    for name, data in sorted(files.items()):
        ensure_asset(github, candidate['id'], name, data)
    return github.read(candidate['id']), files


def verify_public_urls(files):
    """Read the same unauthenticated HTTPS addresses used by employee Macs."""
    def download(url):
        request = Request(url, headers={'User-Agent': 'CSI-MakLock-QA-Verification', 'Cache-Control': 'no-cache'})
        with urlopen(request, timeout=90) as response:
            assert response.status == 200 and response.geturl().startswith('https://')
            return response.read()
    canonical = f'https://github.com/{REPO}/releases/download/{TAG}/'
    assert download(canonical + PACKAGE) == files[PACKAGE], 'Canonical public download differs'
    assert download(PREFIX + LEGACY) == files[PACKAGE], 'Public compatibility download differs'
    assert download(PREFIX + 'appcast.xml') == files['appcast.xml'], 'Public feed differs'
    assert download(PREFIX + 'update-manifest.json') == files['update-manifest.json']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['receive-and-publish', 'verify'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.mode == 'verify':
        verify(args.directory)
        print('Verified 1.1.7 package, feed, signature, source and compatibility.')
        return
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ['GITHUB_REPOSITORY'] == REPO
    assert os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'] == 'refs/heads/' + BRANCH
    assert json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPO]))['private'] is False
    tracked = set(subprocess.check_output(['git', 'ls-files'], text=True).splitlines())
    assert tracked == {'README.md', '.release/qa117.py', '.github/workflows/release-117.yml'}, 'Unexpected public files'
    github = GitHub()
    existing = [r for r in github.releases() if r['tag_name'] == TAG]
    if len(existing) == 1 and set(assets(github.read(existing[0]['id']))) == ALLOW:
        args.directory.mkdir(parents=True, exist_ok=False)
        for name, asset in assets(github.read(existing[0]['id'])).items():
            (args.directory / name).write_bytes(github.download(asset))
        verify(args.directory)
    else:
        receive(args.directory)
    candidate, files = stage(github, args.directory)
    # This release is explicitly owner-authorized. Promote in this same job:
    # publishing with GITHUB_TOKEN does not trigger another release workflow.
    report = promote(github, candidate, files)
    verify_public_urls(files)
    report['unauthenticatedPublicDownloadsVerified'] = True
    report['runURL'] = f'https://github.com/{REPO}/actions/runs/' + os.environ['GITHUB_RUN_ID']
    report['releaseAutomationCommit'] = os.environ['GITHUB_SHA']
    write_branch(REPORT, {'publication-report.json': (json.dumps(report, indent=2)+'\n').encode()},
                 'Record verified owner-authorized 1.1.7 publication')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            import traceback
            print('::error::' + str(error).replace('%', '%25').replace('\n', '%0A'))
            write_branch(REPORT, {'publication-error.txt': traceback.format_exc().encode()},
                         'Record 1.1.7 publication failure for diagnosis')
        raise


