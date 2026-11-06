# Shared F-Droid publication design

## Product requirements

One subscription at https://sivivatu.github.io/fdroid/repo serves Battery Monitor
and Wilderguard. App source, builds, release gates and APK signing stay in their
existing repositories. Existing feed URLs remain operational. New apps require
only a reviewed registry entry and an independently signed upstream feed.

## Architecture and system design

A scheduled/manual trusted-main workflow imports signed upstream v1/v2 indexes,
checks pinned repository certificates, APK hashes, embedded package/version and
per-app signing certificates. It retains byte-identical APK history in a public
`publication` branch, signs a combined index with fdroidserver 2.4.5, and deploys
an explicit public payload through GitHub Pages. No source repository executes
code in the central signing job. No cross-repository credential is required.

## Technical decisions

Use the existing Battery Monitor repository signing identity, whose authoritative
backup is in Infisical EU. Only its four FDROID_* values are replicated to the
central `fdroid-release` environment; APK private keys stay upstream. This shares
repository-key custody with Battery Monitor and must be considered during recovery.
The new URL still requires explicit subscription. Do not change either old feed.

Prefer the existing hash-locked fdroidserver dependency tree and vendor signature
verification over implementing cryptography. Reconstruct metadata from verified
upstream app fields; never execute upstream configuration or scripts. Keep the
registry as an allowlist. Reject package/version collisions, certificate changes,
hash mismatches, upstream rollback, symlinks, unsafe paths and private payloads.

## Task list and validation

1. RED: test registry, signature/hash failures, package identity, immutable history,
   independent version sequences and public-output boundaries.
2. GREEN: implement importer, central index signing, repeatable state and verifier.
3. Exercise all retained releases from both real feeds; run a second sync and
   confirm APK/manifest immutability. Require >=80% publisher coverage.
4. Review code/security, configure protected-main signing and Pages, publish.
5. Verify served v1/v2 signatures and every APK; publish operations/onboarding in
   TeamAI, recording the evidence and any client-installation limitation.

## Risks and limits

GitHub Pages and Git history have storage limits; APK history grows monotonically.
Fail closed if any upstream fails. Daily polling adds up to a day of release lag;
manual dispatch is available. Retain upstream endpoints for existing subscribers.
An F-Droid client installation/upgrade is a separate check from cryptographic
verification. Preserve license/source metadata as supplied; hosting is not
acceptance into f-droid.org and does not establish an app's license compliance.
