#!/usr/bin/env python3
"""Offline regression tests for release safety checks (no GitHub writes)."""

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release", ROOT / ".github/scripts/release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)
SHA = "a" * 40
WORKFLOW_SHA = "b" * 40
VERSION = "2.16-rc1"
REPOSITORY = "example/osslsigncode"


class FakeGitHub:
    repository = REPOSITORY

    def __init__(self):
        self.calls = []
        self.responses = {
            ("GET", f"git/ref/tags/{VERSION}"): {"object": {"type": "commit", "sha": SHA}},
            ("GET", "releases?per_page=100&page=1"): [],
            ("POST", "releases"): {"id": 42},
            ("GET", "releases/42"): {"draft": True, "tag_name": VERSION},
        }

    def api(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return self.responses[(method, path)]

    def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return {}


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeGitHub()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        for name in release.archive_names(VERSION):
            (self.directory / name).write_bytes(b"test archive")

    def prepare_assets(self):
        release.prepare_assets(self.directory, REPOSITORY, VERSION, SHA, WORKFLOW_SHA)

    def publish(self):
        release.publish(self.api, self.directory, VERSION, SHA, WORKFLOW_SHA)

    def test_versions(self):
        for version in ("2.15", "2.15.1", "2.16-rc1", "2.16.1-beta.2"):
            self.assertEqual(release.validate_version(version), version)
        for version in ("", "master", SHA, "v2.15", "2.15\n", "2.15\nVERSION=evil",
                        "2.15-$(touch${IFS}INJECTION_MARKER)", '2.15-";id;#', "../2.15"):
            with self.subTest(version=version), self.assertRaises(release.ReleaseError):
                release.validate_version(version)

    def test_lightweight_tag(self):
        self.assertEqual(release.check_release(self.api, VERSION), SHA)

    def test_annotated_tag(self):
        tag_sha = "c" * 40
        self.api.responses[("GET", f"git/ref/tags/{VERSION}")]["object"] = {"type": "tag", "sha": tag_sha}
        self.api.responses[("GET", f"git/tags/{tag_sha}")] = {"object": {"type": "commit", "sha": SHA}}
        self.assertEqual(release.resolve_tag(self.api, VERSION), SHA)

    def test_non_commit_tag(self):
        self.api.responses[("GET", f"git/ref/tags/{VERSION}")]["object"]["type"] = "tree"
        with self.assertRaisesRegex(release.ReleaseError, "does not resolve"):
            release.resolve_tag(self.api, VERSION)

    def test_moved_tag(self):
        with self.assertRaisesRegex(release.ReleaseError, "tag moved"):
            release.check_release(self.api, VERSION, "c" * 40)

    def test_new_release_needs_no_environment(self):
        values = release.prepare_release(self.api, VERSION)
        self.assertEqual(values, {"version": VERSION, "sha": SHA})
        self.assertEqual([(method, path) for method, path, _ in self.api.calls],
                         [("GET", f"git/ref/tags/{VERSION}"),
                          ("GET", "releases?per_page=100&page=1")])

    def test_workflow_needs_no_environment(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertNotRegex(workflow, r"(?m)^\s*environment:")

    def test_existing_draft_or_published_release_is_never_modified(self):
        self.prepare_assets()
        for draft in (False, True):
            self.api.responses[("GET", "releases?per_page=100&page=1")] = [{"tag_name": VERSION, "draft": draft}]
            with self.subTest(draft=draft), self.assertRaisesRegex(release.ReleaseError, "already exists"):
                self.publish()
        self.assertFalse(any(method != "GET" for method, _, _ in self.api.calls))

    def test_old_release_on_later_page(self):
        self.api.responses[("GET", "releases?per_page=100&page=1")] = [{"tag_name": "other"}] * 100
        self.api.responses[("GET", "releases?per_page=100&page=2")] = [{"tag_name": VERSION}]
        with self.assertRaisesRegex(release.ReleaseError, "already exists"):
            release.check_release(self.api, VERSION)

    def test_manual_refresh_needs_no_access_to_draft(self):
        del self.api.responses[("GET", "releases?per_page=100&page=1")]
        values = release.prepare_release(self.api, VERSION, refresh_draft=True,
                                         source_archive_sha256="d" * 64)
        self.assertEqual(values, {"version": VERSION, "sha": SHA,
                                  "source_archive_sha256": "d" * 64})
        self.assertEqual([(method, path) for method, path, _ in self.api.calls],
                         [("GET", f"git/ref/tags/{VERSION}")])

    def test_manual_refresh_requires_valid_source_digest(self):
        for digest in (None, "", "d" * 63, "D" * 64, "sha256:" + "d" * 64):
            with self.subTest(digest=digest), self.assertRaisesRegex(release.ReleaseError, "SHA-256 digest"):
                release.prepare_release(self.api, VERSION, refresh_draft=True,
                                        source_archive_sha256=digest)

    def test_manual_refresh_checksums_include_preserved_source(self):
        release.prepare_assets(self.directory, REPOSITORY, VERSION, SHA, WORKFLOW_SHA,
                               source_archive_sha256="d" * 64)
        manifest = (self.directory / "SHA256SUMS.txt").read_text()
        self.assertIn(f'{"d" * 64}  osslsigncode-{VERSION}.tar.gz\n', manifest)
        info = json.loads((self.directory / "BUILDINFO.json").read_text())
        self.assertEqual(info["source_archive"]["sha256"], "d" * 64)
        # The automatic publisher still rejects manual-refresh metadata.
        with self.assertRaises(release.ReleaseError):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_exact_archive_set(self):
        (self.directory / "untrusted.zip").write_bytes(b"unexpected")
        with self.assertRaises(release.ReleaseError):
            self.prepare_assets()

    def test_missing_archive(self):
        (self.directory / release.archive_names(VERSION)[0]).unlink()
        with self.assertRaises(release.ReleaseError):
            self.prepare_assets()

    def test_symlink_archive(self):
        path = self.directory / release.archive_names(VERSION)[0]
        path.unlink()
        path.symlink_to(ROOT / "README.md")
        with self.assertRaisesRegex(release.ReleaseError, "regular release asset"):
            self.prepare_assets()

    def test_changed_asset_is_rejected_before_any_api_call(self):
        self.prepare_assets()
        (self.directory / release.archive_names(VERSION)[0]).write_bytes(b"changed after attestation")
        with self.assertRaisesRegex(release.ReleaseError, "assets changed"):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_changed_metadata_is_rejected(self):
        self.prepare_assets()
        metadata = self.directory / "BUILDINFO.json"
        data = json.loads(metadata.read_text())
        data["source_sha"] = "c" * 40
        metadata.write_text(json.dumps(data))
        with self.assertRaisesRegex(release.ReleaseError, "metadata changed"):
            self.publish()
        self.assertEqual(self.api.calls, [])

    def test_only_new_draft_is_created_and_uploaded_by_id(self):
        self.prepare_assets()
        self.publish()
        writes = [(method, path, kwargs) for method, path, kwargs in self.api.calls if method != "GET"]
        self.assertEqual(len(writes), 9)
        method, path, kwargs = writes[0]
        self.assertEqual((method, path), ("POST", "releases"))
        self.assertIs(kwargs["data"]["draft"], True)
        self.assertEqual(kwargs["data"]["target_commitish"], SHA)
        self.assertIs(kwargs["data"]["prerelease"], True)
        for method, path, kwargs in writes[1:]:
            self.assertEqual(method, "POST")
            self.assertTrue(path.startswith(f"/repos/{REPOSITORY}/releases/42/assets?name="))
            self.assertIn("asset", kwargs)

    def test_concurrent_publication_stops_uploads(self):
        self.prepare_assets()
        self.api.responses[("GET", "releases/42")]["draft"] = False
        with self.assertRaisesRegex(release.ReleaseError, "expected draft"):
            self.publish()
        self.assertFalse(any("/assets?" in path for _, path, _ in self.api.calls))

    def test_all_release_actions_and_container_are_pinned(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            actions = re.findall(r"uses:\s+([^\s#]+)", path.read_text())
            self.assertTrue(actions)
            for action in actions:
                with self.subTest(workflow=path.name, action=action):
                    self.assertRegex(action, r"^[\w./-]+@[0-9a-f]{40}$")
        self.assertRegex(workflow, r"alpine:3\.24@sha256:[0-9a-f]{64}")
        self.assertNotIn("laverdet/", workflow)
        self.assertNotIn("softprops/", workflow)


if __name__ == "__main__":
    unittest.main()
