#!/usr/bin/env python3
"""Binary-only QA release staging and explicit, user-triggered channel promotion.

No application source or private Sparkle key is used by this automation.
Staging never changes the live feed. Promotion runs only after the user publishes
this draft release (or explicitly re-runs that approved publication workflow).
"""
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

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

REPO = 'AndSuch-Mods/General-AI-Test-Space-9'
INITIAL = '5d4159b9a1397c555a0cdf27800b2a82fbaff8e2'
TAG = 'csi-maklock-qa-1.1.6-build113'
CHANNEL = 'csi-maklock-qa-automatic-update-r6'
BRANCH = 'csi/stage-1.1.6'
RECEIVER = 'csi-staging/116-receiver'
PAYLOAD = 'csi-staging/116-encrypted'
REPORT = 'csi-staging/116-status'
SOURCE = '7ec987c3dab9463b45b72a60ccdf58ed8cfafcd7'
PACKAGE = 'CSI-MakLock-1.1.6-QA.pkg'
LEGACY = 'CSI-MakLock-1.1.5-QA.pkg'
KEY = 'GkAuP9JPTXXLJ/lYnKHfueGYs3gsp7FvSzOt+KMk6nY='
PACKAGE_HASH = '48a0cf1a5135e81f3df98b60f54325df806e444f58ac754e439136de7fb5a1bb'
FEED_HASH = '042d216f4082844f24d8178c9c4fb8411f220672af6ef6ddf4cca1919f5fbf17'
OLD_PACKAGE_HASH = '10bd9c1ee44f51884b34a7ef4ce367295b9636f232b598c50a73bc32cae4b7a9'
OLD_FEED_HASH = '3c041e89502142a78d1931d79e2cedf0d4d1cb19bf80a897250fe44d60f4b824'
ALLOW = {PACKAGE, 'appcast.xml', 'update-manifest.json', 'public-key.txt', 'SHA256SUMS'}
PREFIX = f'https://github.com/{REPO}/releases/download/{CHANNEL}/'
TITLE = 'CSI MakLock 1.1.6 QA, build 113'
NOTES = '''READY FOR OWNER RELEASE: leave this draft unpublished until both test Macs are ready. Clicking Publish release starts the prepared update-channel activation; wait for the green Release approved CSI MakLock 1.1.6 workflow before checking for updates. No manual file upload or feed editing is needed.

Test-only 1.1.6 update for existing 1.1.5 build 112 installations. Fixes About-window closing, repeated Keychain access, selected-Watch unlocking of protected System Settings and Activity Monitor, and cached application artwork. Existing CSI credentials, preferences, protected apps and Watch selection are preserved. CSI administration still requires the independent CSI password.

Unsigned installer and ad-hoc signed application; no Apple notarization. Sparkle feed and package use the existing Ed25519 key. Approve the update with the independent CSI password and save work if protected apps request it. Protection is unavailable while the MakLock process is stopped for replacement. Native macOS 15 and 26 validation is linked in the private release handoff. Human Gatekeeper, administrator prompts and physical Watch/Touch ID acceptance remain Mac tests.

The canonical installer here is named 1.1.6. The existing r6 update channel also serves it under its legacy package address because installed 1.1.5 trusts that exact address. The original 1.1.5 build 112 installer and metadata are retained separately on r6. This is a QA release, not a production release.'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root):
    files = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
    assert set(files) == ALLOW and len(list(root.iterdir())) == len(ALLOW), 'Unexpected distribution files'
    m = json.loads(files['update-manifest.json'])
    assert m['sourceCommit'] == SOURCE and m['version'] == '1.1.6' and m['build'] == 113
    assert m['startingVersion'] == '1.1.5' and m['startingBuild'] == 112 and m['testOnly'] is True
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
    expected = {'url': m['packageURL'], 'length': str(m['length']), namespace+'version': '113',
                namespace+'shortVersionString': '1.1.6', namespace+'installationType': 'package',
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
    channel = release_for(github, CHANNEL)
    assert not channel['draft']
    channel_id = channel['id']
    names = assets(channel)
    archive_names = {LEGACY: 'CSI-MakLock-1.1.5-build112-QA.pkg', 'appcast.xml': 'appcast-build112.xml',
                     'update-manifest.json': 'update-manifest-build112.json', 'SHA256SUMS': 'SHA256SUMS-build112'}
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
    assert old_manifest['version'] == '1.1.5' and old_manifest['build'] == 112 and old_manifest['publicKey'] == KEY
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
    return {'published': True, 'releaseURL': candidate['html_url'], 'publicFeedSHA256': FEED_HASH,
            'packageSHA256': PACKAGE_HASH, 'original115Preserved': True, 'feedChangedLast': True}


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


def stage(github, root):
    files = verify(root)
    # Prove staging did not follow an already modified channel.
    current = release_for(github, CHANNEL)
    assert digest(github.download(assets(current)['appcast.xml'])) == OLD_FEED_HASH
    assert digest(github.download(assets(current)[LEGACY])) == OLD_PACKAGE_HASH
    matches = [r for r in github.releases() if r['tag_name'] == TAG]
    assert len(matches) <= 1
    if not matches:
        github.api('releases', 'POST', {'tag_name': TAG, 'target_commitish': os.environ['GITHUB_SHA'], 'name': TITLE,
                                      'body': NOTES, 'prerelease': True, 'draft': True, 'make_latest': 'false'})
    candidate = release_for(github, TAG)
    assert candidate['draft'], 'Refusing to stage over a published release'
    github.api('releases/' + str(candidate['id']), 'PATCH',
               {'target_commitish': os.environ['GITHUB_SHA'], 'name': TITLE, 'body': NOTES})
    candidate = github.read(candidate['id'])
    assert candidate['target_commitish'] == os.environ['GITHUB_SHA']
    assert candidate['name'] == TITLE and candidate['body'] == NOTES
    assert set(assets(candidate)) <= ALLOW
    for name, data in sorted(files.items()):
        ensure_asset(github, candidate['id'], name, data)
    candidate = github.read(candidate['id'])
    assert candidate['draft'] and set(assets(candidate)) == ALLOW
    report = {'staged': True, 'published': False, 'draftReleaseID': candidate['id'],
              'draftReleaseURL': candidate['html_url'],
              'approvalAction': 'Publish release', 'releaseAutomationCommit': os.environ['GITHUB_SHA'], 'packageSHA256': PACKAGE_HASH,
              'publicFeedSHA256': OLD_FEED_HASH, 'public115SHA256': OLD_PACKAGE_HASH,
              'runURL': f'https://github.com/{REPO}/actions/runs/' + os.environ['GITHUB_RUN_ID']}
    write_branch(REPORT, {'staging-report.json': (json.dumps(report, indent=2)+'\n').encode()}, 'Record staged candidate; public feed unchanged')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['receive-and-stage', 'publish', 'verify'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.mode == 'verify':
        verify(args.directory)
        print('Candidate signature, hashes, identity and trusted URLs verified.')
        return
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ['GITHUB_REPOSITORY'] == REPO
    assert json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPO]))['private'] is False
    tracked = set(subprocess.check_output(['git', 'ls-files'], text=True).splitlines())
    assert tracked == {'README.md', '.release/qa116.py', '.github/workflows/stage-116.yml', '.github/workflows/release-116.yml'}, 'Unexpected public repository files'
    github = GitHub()
    if args.mode == 'receive-and-stage':
        assert os.environ['GITHUB_REF'] == 'refs/heads/' + BRANCH
        existing = [r for r in github.releases() if r['tag_name'] == TAG]
        if len(existing) == 1:
            existing = [github.read(existing[0]['id'])]
        if len(existing) == 1 and existing[0]['draft'] and set(assets(existing[0])) == ALLOW:
            args.directory.mkdir(parents=True, exist_ok=False)
            for name, asset in assets(existing[0]).items():
                (args.directory / name).write_bytes(github.download(asset))
            verify(args.directory)
        else:
            receive(args.directory)
        stage(github, args.directory)
    else:
        assert os.environ['GITHUB_EVENT_NAME'] == 'release' and os.environ['GITHUB_REF'] == 'refs/tags/' + TAG
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        assert event['action'] == 'published' and event['release']['tag_name'] == TAG
        candidate = release_for(github, TAG)
        assert not candidate['draft'] and event['release']['id'] == candidate['id']
        assert candidate['target_commitish'] == os.environ['GITHUB_SHA'], 'Release must use the reviewed staging commit'
        args.directory.mkdir(parents=True, exist_ok=False)
        assert set(assets(candidate)) == ALLOW
        for name, asset in assets(candidate).items():
            (args.directory / name).write_bytes(github.download(asset))
        report = promote(github, candidate, verify(args.directory))
        write_branch(REPORT, {'publication-report.json': (json.dumps(report, indent=2)+'\n').encode()}, 'Record user-approved 1.1.6 publication')
        print(json.dumps(report, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            import traceback
            summary = traceback.format_exc()
            print('::error::' + str(error).replace('%', '%25').replace('\n', '%0A'))
            write_branch(REPORT, {'staging-error.txt': summary.encode()}, 'Record release staging error without altering public feed')
        raise
