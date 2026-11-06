# Binary releases

The release workflow builds an **existing version tag**, tests all six binaries,
then waits for approval before attesting the assets and creating a new draft.
It never updates an existing draft or published release. Review and publish the
new draft manually only after the workflow has completed successfully.

## Repository settings required before the first run

1. Create an environment named **release** in Settings → Environments.
2. Add trusted **required reviewers** and enable **Prevent self-review**. Disable
   administrator bypass where available. The workflow checks the reviewer rules
   before building and again before creating the draft; missing rules fail closed.
3. Protect version tags with a repository ruleset: restrict creation to release
   maintainers and disallow tag updates and deletion. Protect the default branch
   and review changes to workflows and release helpers.
4. Enable **immutable releases** in the repository settings before publishing.
   This prevents subsequent asset or tag replacement outside this workflow too.

These settings are not configured by repository files. The workflow token needs
Contents read access and Actions read access for preflight. Only the approved
release job receives Contents write. The attestation jobs receive attestations
write and OIDC permissions. No long-lived publishing or signing secret is needed.

Dispatch the workflow with a tag such as `2.16` or `2.16-rc1`, or push that tag.
Arbitrary branch names and commit IDs are not accepted. The tag is resolved once
to a commit SHA for all builders and checked again immediately before release
creation. Release helpers always come from the workflow's immutable commit, not
from the historical source tag.

If uploading fails after draft creation, inspect the partial draft. Remove it
manually before starting a fresh run; reruns intentionally cannot overwrite it.
Do not publish a partial draft while the upload job is running.

## Manually refreshing an existing draft

Dispatch with `refresh_draft: true` to rebuild and attest files for an existing
draft without granting any job permission to modify releases. Read-only workflow
tokens cannot see draft metadata: supply `source_archive_sha256` from the draft's
authenticated GitHub asset metadata. That digest is included in the authenticated
build metadata, checksums and attestations without downloading the draft's source
archive in CI. This mode does not need the publishing environment because it
cannot publish or update releases; draft-state checks remain the maintainer's
responsibility.

After all jobs succeed, download the `verified-release-<version>` workflow
artifact, and copy the preserved source archive beside those files. Verify all
attestations against the exact workflow commit and check all checksums and build
metadata. An authorized maintainer may then replace the
draft's files manually, checking immediately before each write that the release
is still a draft and the tag is unchanged. Keep the original source archive.
Publish only after verifying the uploaded assets against the local digests.

This is an explicit manual approval path, not an automatic overwrite exception.
The default publisher continues to reject all existing releases.

## Build inputs

All workflow Actions are pinned to full commit SHAs. Linux runs in a digest-pinned,
native Alpine container on the Ubuntu host, without third-party loader binaries
or GitHub tokens inside the container. Linux binaries must be static PIE with no
interpreter or shared-library dependencies, RELRO, and a non-executable stack.
Older source tags receive the narrowly scoped static-PIE linker adjustment.

OpenSSL, zlib and NASM source downloads retain their pinned SHA-256 checks, which
must pass before extraction. Native dependency caches use a new release-only
namespace keyed by the source archive's digest, so older unverified caches are
not reused. When updating a dependency or Action, review its
source and obtain the new digest from a trusted upstream source. Rebuild releases
when bundled OpenSSL or zlib needs a security update: static libraries are not
updated by the user's operating-system package manager.

## Verifying downloaded releases

Download the archives, `BUILDINFO.json`, and `SHA256SUMS.txt` from the same release.
Authenticate the checksum manifest using a recent GitHub CLI, then check the
files locally:

```sh
gh attestation verify SHA256SUMS.txt --repo mtrojnar/osslsigncode \
  --signer-workflow mtrojnar/osslsigncode/.github/workflows/release.yml \
  --deny-self-hosted-runners
sha256sum -c SHA256SUMS.txt
```

Individual archives and `BUILDINFO.json` also have GitHub attestations and can be
verified with the same command. The build-provenance attestation identifies the
workflow execution. For a historical tag built using manual dispatch, the actual
source commit differs from the workflow commit; both are recorded separately in
the authenticated `BUILDINFO.json`. Compare its `source_sha` with the expected
release tag. Neither an unsigned checksum nor an attestation alone proves that
the source or its dependencies are free from vulnerabilities.

## Local checks

```sh
python3 -B -m unittest discover -s tests -p test_release_workflow.py
sh -n .github/scripts/build-linux-release.sh
```

The regression tests use a fake GitHub API and never publish, delete, or update
GitHub releases.
