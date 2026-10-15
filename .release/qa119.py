#!/usr/bin/env python3
"""Stage build 119; activate its feed only after the owner publishes its draft."""
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
TAG = 'csi-maklock-qa-1.1.7-build119'
PREVIOUS_TAG = 'csi-maklock-qa-1.1.7-build117'
CHANNEL = 'csi-maklock-qa-automatic-update-r6'
BRANCH = 'csi/stage-1.1.7-build119'
RECEIVER = 'csi-staging/117b119-receiver'
PAYLOAD = 'csi-staging/117b119-encrypted'
REPORT = 'csi-staging/117b119-status'
SOURCE = '9f80e3fa1b4058d7e25125955768ebd0962778f2'
PACKAGE = 'CSI-MakLock-1.1.7-QA.pkg'
LEGACY = 'CSI-MakLock-1.1.5-QA.pkg'
KEY = 'GkAuP9JPTXXLJ/lYnKHfueGYs3gsp7FvSzOt+KMk6nY='
PACKAGE_HASH = 'ec675aaa10df5a090a7115463cdc80a4112ac593016ca06ece6c6fc151049094'
FEED_HASH = 'ff69dcc80eba83fffaf0edbbf581ca20461855d3629abf1b9f780624c945bb86'
OLD_PACKAGE_HASH = '806834d6f7f9bb45e9fd4d241d630980c40c100ce64b5561eee53437db18b5ee'
OLD_FEED_HASH = 'c480e459e79b130b8a89e650ef2f0107554363df17fb38a3e67115ded6370b7f'
ALLOW = {PACKAGE, 'appcast.xml', 'update-manifest.json', 'public-key.txt', 'SHA256SUMS'}
PREFIX = f'https://github.com/{REPO}/releases/download/{CHANNEL}/'
TITLE = 'CSI MakLock 1.1.7 QA, build 119: combined protection update'
NOTES = 'READY FOR OWNER TEST: one combined update, version 1.1.7 internal build 119. Leave this draft unpublished until ready. In the GitHub website choose Edit, then Publish release. Wait for Release approved CSI MakLock build 119 to finish before checking for updates. Installed build 117 goes directly to 119; the private-only build 118 is not a separate public update.\n\nEvery protected app hides and relocks when its access timer expires, including default and employee-added apps. Desktop clicks leave hidden apps alone; reopening a locked app requests authentication. Sleep, inactivity and Watch departure retain quiet hiding. If macOS actually refuses to hide content, the protective fallback remains.\n\nAdds a password-gated Use Touch ID switch in Security. Disabling it stops biometric requests while retaining password and enabled selected-Watch unlock. Passwords is now a default protected app alongside System Settings and Activity Monitor. Existing Passwords entries move to the default section without duplicates, retaining their enabled state, identity and saved date. Apple Passwords may still require its own authentication. Requires macOS 15 or newer.\n\nThe independent password, Keychain identity, other protected apps, preferences, Watch selection, approved icons and startup update delay are preserved. Phone support and the future 1.0 release remain deferred. Install over the existing app without deleting preferences or Keychain entries.\n\nNative Universal 2 build and automated regression checks passed on the private Mac runner. In-process application, preference and Watch tests do not manipulate the employee desktop. Real AppKit GUI fixtures compiled only. Physical multi-display behavior, Touch ID and Watch hardware, macOS 15 runtime behavior and human Gatekeeper/administrator prompts still need owner testing.\n\nUnsigned QA installer containing an ad-hoc signed app; no Apple notarization. Use normal macOS Privacy & Security approval if required. Update installation still requires the independent CSI MakLock password and allows protected apps to save before closing. Protection cannot persist while MakLock stops for replacement.\n\nOnly the installer and signed release metadata are distributed. The previous canonical build 117 and older releases are preserved. The live compatibility feed changes last, only after the owner publishes this draft.'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(root):
    files = {p.name: p.read_bytes() for p in root.iterdir() if p.is_file()}
    assert set(files) == ALLOW and len(list(root.iterdir())) == len(ALLOW), 'Unexpected distribution files'
    m = json.loads(files['update-manifest.json'])
    assert m['sourceCommit'] == SOURCE and m['version'] == '1.1.7' and m['build'] == 119
    assert m['startingVersion'] == '1.1.7' and m['startingBuild'] == 117 and m['testOnly'] is True
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
    assert m['minimumSystemVersion'] == '15.0'
    assert items[0].findtext('{http://www.andymatuschak.org/xml-namespaces/sparkle}minimumSystemVersion') == '15.0'
    attrs = items[0].find('enclosure').attrib
    namespace = '{http://www.andymatuschak.org/xml-namespaces/sparkle}'
    expected = {'url': m['packageURL'], 'length': str(m['length']), namespace+'version': '119',
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
    assert not candidate['draft'], 'Owner must publish the draft first'
    assert set(assets(candidate)) == ALLOW
    assert candidate['tag_name'] == TAG and re.fullmatch(r'[0-9a-f]{40}', candidate['target_commitish'])
    assert all(github.download(asset) == files[name] for name, asset in assets(candidate).items())
    previous = release_for(github, PREVIOUS_TAG)
    assert not previous['draft']
    previous_files = {name: github.download(asset) for name, asset in assets(previous).items()}
    assert digest(previous_files['CSI-MakLock-1.1.7-QA.pkg']) == OLD_PACKAGE_HASH
    assert digest(previous_files['appcast.xml']) == OLD_FEED_HASH
    channel = release_for(github, CHANNEL)
    assert not channel['draft']
    channel_id = channel['id']
    names = assets(channel)
    archive_names = {LEGACY: 'CSI-MakLock-1.1.7-build117-QA.pkg', 'appcast.xml': 'appcast-build117.xml',
                     'update-manifest.json': 'update-manifest-build117.json', 'SHA256SUMS': 'SHA256SUMS-build117'}
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
    assert old_manifest['version'] == '1.1.7' and old_manifest['build'] == 117 and old_manifest['publicKey'] == KEY
    assert originals['SHA256SUMS'].decode() == OLD_PACKAGE_HASH + '  ' + LEGACY + '\n'
    assert github.download(names['public-key.txt']).decode().strip() == KEY
    replacements = {LEGACY: files[PACKAGE], 'update-manifest.json': files['update-manifest.json'],
                    'SHA256SUMS': (PACKAGE_HASH + '  ' + LEGACY + '\n').encode(), 'appcast.xml': files['appcast.xml']}
    for name, replacement in replacements.items():
        if name in names:
            assert github.download(names[name]) in (originals[name], replacement), 'Unexpected live channel bytes: ' + name
    # The release event proves owner publication; staging cannot activate this feed.
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
    # A draft's html_url may retain GitHub's temporary untagged address after
    # publication. Use the immutable tag that public downloads just validated.
    return {'published': True, 'releaseURL': f'https://github.com/{REPO}/releases/tag/{TAG}', 'publicFeedSHA256': FEED_HASH,
            'packageSHA256': PACKAGE_HASH, 'previous117Build117Preserved': True, 'sourceCommit': SOURCE, 'version': '1.1.7', 'build': 119, 'feedChangedLast': True}


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
    # Staging only accepts the known preceding channel bytes.
    feed = names.get('appcast.xml') or names.get('appcast-build117.xml')
    package = names.get(LEGACY) or names.get('CSI-MakLock-1.1.7-build117-QA.pkg')
    assert feed and package
    assert digest(github.download(feed)) == OLD_FEED_HASH
    assert digest(github.download(package)) == OLD_PACKAGE_HASH
    previous = release_for(github, PREVIOUS_TAG)
    assert not previous['draft']
    assert digest(github.download(assets(previous)['CSI-MakLock-1.1.7-QA.pkg'])) == OLD_PACKAGE_HASH
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
    assert candidate['draft'] and candidate['prerelease'] and candidate['tag_name'] == TAG
    assert candidate['target_commitish'] == os.environ['GITHUB_SHA']
    assert candidate['name'] == TITLE and candidate['body'] == NOTES
    assert set(assets(candidate)) <= ALLOW
    for name, asset in assets(candidate).items():
        assert github.download(asset) == files[name], 'Refusing to overwrite different candidate bytes'
    for name, data in sorted(files.items()):
        ensure_asset(github, candidate['id'], name, data)
    candidate = github.read(candidate['id'])
    assert candidate['draft'] and set(assets(candidate)) == ALLOW
    current = assets(github.read(channel['id']))
    assert digest(github.download(current['appcast.xml'])) == OLD_FEED_HASH
    assert digest(github.download(current[LEGACY])) == OLD_PACKAGE_HASH
    return candidate, files


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
    parser.add_argument('mode', choices=['receive-and-stage', 'publish', 'verify'])
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    if args.mode == 'verify':
        verify(args.directory)
        print('Verified build 119 package, feed, signature, source and compatibility.')
        return
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ['GITHUB_REPOSITORY'] == REPO
    if args.mode == 'receive-and-stage':
        assert os.environ['GITHUB_EVENT_NAME'] == 'push' and os.environ['GITHUB_REF'] == 'refs/heads/' + BRANCH
    else:
        assert os.environ['GITHUB_EVENT_NAME'] == 'release' and os.environ['GITHUB_REF'] == 'refs/tags/' + TAG
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        assert event['action'] == 'published' and event['release']['tag_name'] == TAG
        assert not event['release']['draft'] and event['release']['prerelease']
    assert json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPO]))['private'] is False
    tracked = set(subprocess.check_output(['git', 'ls-files'], text=True).splitlines())
    assert tracked == {'README.md', '.release/qa119.py', '.github/workflows/stage-119.yml', '.github/workflows/release-119.yml'}, 'Unexpected public files'
    github = GitHub()
    existing = [r for r in github.releases() if r['tag_name'] == TAG]
    assert len(existing) <= 1
    if args.mode == 'receive-and-stage':
        if existing:
            assert github.read(existing[0]['id'])['draft'], 'Never change a published candidate'
        if len(existing) == 1 and set(assets(github.read(existing[0]['id']))) == ALLOW:
            args.directory.mkdir(parents=True, exist_ok=False)
            for name, asset in assets(github.read(existing[0]['id'])).items():
                (args.directory / name).write_bytes(github.download(asset))
            verify(args.directory)
        else:
            receive(args.directory)
        candidate, files = stage(github, args.directory)
        report = {'staged': True, 'published': False, 'draftReleaseID': candidate['id'],
                  'draftReleaseURL': candidate['html_url'], 'approvalAction': 'Publish release',
                  'sourceCommit': SOURCE, 'version': '1.1.7', 'build': 119,
                  'packageSHA256': PACKAGE_HASH, 'publicFeedSHA256': OLD_FEED_HASH}
        report_name = 'staging-report.json'
    else:
        candidate = release_for(github, TAG)
        assert not candidate['draft'] and event['release']['id'] == candidate['id']
        assert candidate['target_commitish'] == os.environ['GITHUB_SHA']
        assert set(assets(candidate)) == ALLOW
        args.directory.mkdir(parents=True, exist_ok=False)
        for name, asset in assets(candidate).items():
            (args.directory / name).write_bytes(github.download(asset))
        files = verify(args.directory)
        report = promote(github, candidate, files)
        verify_public_urls(files)
        report['unauthenticatedPublicDownloadsVerified'] = True
        report_name = 'publication-report.json'
    report['runURL'] = f'https://github.com/{REPO}/actions/runs/' + os.environ['GITHUB_RUN_ID']
    report['releaseAutomationCommit'] = os.environ['GITHUB_SHA']
    write_branch(REPORT, {report_name: (json.dumps(report, indent=2)+'\n').encode()},
                 'Record build 119 staging or owner-approved publication')
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
