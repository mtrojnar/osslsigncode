#!/usr/bin/env python3
"""Validate release inputs and upload attested assets to a new draft only."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


class ReleaseError(RuntimeError):
    """A release safety check failed."""


def validate_version(version):
    """Accept the version tags supported by release.yml, not arbitrary refs."""
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[A-Za-z0-9][A-Za-z0-9._-]*)?", version):
        raise ReleaseError("Expected a version tag such as 2.15 or 2.15-rc1")
    return version


def validate_sha(sha):
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ReleaseError("Expected a full commit SHA")
    return sha


class GitHub:
    """Small REST client; intentionally has no update/delete release methods."""

    def __init__(self, repository, token):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ReleaseError("Invalid GitHub repository")
        self.repository = repository
        self.token = token

    def request(self, method, path, data=None, asset=None):
        base = "https://uploads.github.com" if asset else "https://api.github.com"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "osslsigncode-release",
        }
        if asset:
            body = asset.read_bytes()
            headers["Content-Type"] = "application/octet-stream"
        elif data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        else:
            body = None
        request = Request(base + path, data=body, headers=headers, method=method)
        try:
            with urlopen(request, timeout=120) as response:
                return json.load(response)
        except HTTPError as error:
            raise ReleaseError(f"GitHub {method} {path} failed: HTTP {error.code}") from error

    def api(self, method, path, **kwargs):
        return self.request(method, f"/repos/{self.repository}/{path}", **kwargs)


def resolve_tag(api, version):
    """Resolve lightweight and annotated tags, never a same-named branch."""
    obj = api.api("GET", f"git/ref/tags/{version}")["object"]
    for _ in range(10):
        if obj["type"] == "commit":
            return validate_sha(obj["sha"])
        if obj["type"] != "tag":
            break
        obj = api.api("GET", f"git/tags/{validate_sha(obj['sha'])}")["object"]
    raise ReleaseError("Release tag does not resolve to a commit")


def require_protected_environment(api):
    environment = api.api("GET", "environments/release")
    for rule in environment.get("protection_rules", []):
        if (rule.get("type") == "required_reviewers" and rule.get("reviewers")
                and rule.get("prevent_self_review") is True):
            return
    raise ReleaseError("Configure the release environment with required reviewers and prevent self-review")


def matching_releases(api, version):
    # The by-tag endpoint hides drafts. Paginate through all releases.
    page = 1
    while True:
        releases = api.api("GET", f"releases?per_page=100&page={page}")
        yield from (item for item in releases if item["tag_name"] == version)
        if len(releases) < 100:
            return
        page += 1


def require_new_release(api, version):
    if next(matching_releases(api, version), None) is not None:
        raise ReleaseError(f"A release already exists for {version}; refusing to modify it")


def prepare_release(api, version, refresh_draft=False, source_archive_sha256=None):
    if not refresh_draft:
        return {"version": version, "sha": check_release(api, version)}
    # A read-only workflow token cannot see draft metadata. The maintainer
    # supplies the original source digest from an authenticated draft lookup
    # and checks draft state before manually writing or publishing anything.
    if not re.fullmatch(r"[0-9a-f]{64}", source_archive_sha256 or ""):
        raise ReleaseError("Manual refresh requires the preserved source archive's SHA-256 digest")
    return {"version": version, "sha": resolve_tag(api, version),
            "source_archive_sha256": source_archive_sha256}


def check_release(api, version, expected_sha=None):
    sha = resolve_tag(api, version)
    if expected_sha is not None and sha != validate_sha(expected_sha):
        raise ReleaseError("Release tag moved after the build was prepared")
    require_protected_environment(api)
    require_new_release(api, version)
    return sha


def archive_names(version):
    return sorted(f"osslsigncode-{version}-{platform}-{arch}.{extension}"
                  for platform, extension in (("linux", "tar.gz"), ("macos", "zip"), ("windows", "zip"))
                  for arch in ("amd64", "arm64"))


def check_files(directory, names):
    if {path.name for path in directory.iterdir()} != set(names):
        raise ReleaseError("Expected exactly the six release archives and their release metadata")
    for name in names:
        path = directory / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
            raise ReleaseError(f"Not a non-empty regular release asset: {name}")


def metadata(repository, version, source_sha, workflow_sha, source_archive_sha256=None):
    data = {"repository": repository, "tag": version,
            "source_sha": validate_sha(source_sha), "workflow_sha": validate_sha(workflow_sha)}
    if source_archive_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", source_archive_sha256):
            raise ReleaseError("Invalid source archive SHA-256 digest")
        data["source_archive"] = {"name": f"osslsigncode-{version}.tar.gz",
                                  "sha256": source_archive_sha256}
    return json.dumps(data, indent=2, sort_keys=True) + "\n"


def checksums(directory, names):
    return "".join(f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
                   for name in sorted(names))


def prepare_assets(directory, repository, version, source_sha, workflow_sha, source_archive_sha256=None):
    names = archive_names(version)
    check_files(directory, names)
    info = metadata(repository, version, source_sha, workflow_sha, source_archive_sha256)
    (directory / "BUILDINFO.json").write_text(info, encoding="utf-8")
    manifest = checksums(directory, names + ["BUILDINFO.json"])
    if source_archive_sha256 is not None:
        manifest += f"{source_archive_sha256}  osslsigncode-{version}.tar.gz\n"
    (directory / "SHA256SUMS.txt").write_text(manifest, encoding="utf-8")


def publish(api, directory, version, source_sha, workflow_sha):
    names = archive_names(version) + ["BUILDINFO.json", "SHA256SUMS.txt"]
    check_files(directory, names)
    # Do not regenerate files after attestation: verify the exact manifest and
    # digests which were signed before giving them to the release API.
    if (directory / "BUILDINFO.json").read_text(encoding="utf-8") != metadata(api.repository, version, source_sha, workflow_sha):
        raise ReleaseError("Release build metadata changed after preparation")
    if (directory / "SHA256SUMS.txt").read_text(encoding="utf-8") != checksums(directory, names[:-1]):
        raise ReleaseError("Release assets changed after checksum generation")
    check_release(api, version, source_sha)
    release = api.api("POST", "releases", data={
        "tag_name": version, "target_commitish": source_sha, "name": version,
        "draft": True, "prerelease": "-" in version, "generate_release_notes": True,
    })
    release_id = int(release["id"])
    for name in names:
        # Address the newly created draft by ID, not by tag. Never update an
        # existing release, delete assets, or overwrite matching filenames.
        current = api.api("GET", f"releases/{release_id}")
        if current.get("draft") is not True or current.get("tag_name") != version:
            raise ReleaseError("Release is no longer the expected draft; stopping uploads")
        path = f"/repos/{api.repository}/releases/{release_id}/assets?" + urlencode({"name": name})
        api.request("POST", path, asset=directory / name)
    print(f"Created draft release {release_id}; review it and publish manually after this run succeeds")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "assets", "publish"))
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        version = validate_version(os.environ["VERSION"])
        repository = os.environ["GITHUB_REPOSITORY"]
        if args.command == "assets":
            prepare_assets(args.dist, repository, version, os.environ["SOURCE_SHA"],
                           os.environ["WORKFLOW_SHA"], os.environ.get("SOURCE_ARCHIVE_SHA256") or None)
        else:
            api = GitHub(repository, os.environ["GH_TOKEN"])
            if args.command == "prepare":
                values = prepare_release(api, version, os.environ.get("REFRESH_DRAFT") == "true",
                                         os.environ.get("SOURCE_ARCHIVE_SHA256"))
                with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                    for name, value in values.items():
                        output.write(f"{name}={value}\n")
            else:
                publish(api, args.dist, version, os.environ["SOURCE_SHA"], os.environ["WORKFLOW_SHA"])
    except (ReleaseError, KeyError, OSError, ValueError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
