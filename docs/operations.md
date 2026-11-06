# Shared publication operations

## Sources and trust

| Application | Package | Existing feed |
| --- | --- | --- |
| Battery Monitor Beta | `io.github.sivivatu.batterymonitor` | https://sivivatu.github.io/battery-monitor/fdroid/beta/repo |
| Wilderguard Beta | `com.wilderguard.game.beta` | https://sivivatu.github.io/wilderguard-beta/fdroid/repo |

App source repositories and release tooling remain independent. The public
`wilderguard-beta` repository contains publication output; its presence is not
evidence of where Wilderguard source is maintained. Central metadata is derived
from authenticated upstream fields. The publisher does not invent license or
source availability claims; Wilderguard currently reports `Unknown` as its license.

The registry `apps.json` is the trust allowlist. Review changes like a signing
policy change: a wrong pin or package can publish an unintended application.
The central feed's permanent repository certificate SHA-256 is:

```text
133465e78e767c9691c06786f8c286144ef43cbf5a2565d0285ab4cbfb072a1b
```

This deliberately reuses Battery Monitor's repository identity. The URL is new,
so users still add a subscription explicitly. Never resign APKs in this repository.

## Key custody

Authoritative backup: Infisical EU Cloud, organization Databard Analytics, project
`battery-monitor` (`7ec1693b-18a8-4da7-bdc3-ca535cff5f75`), `prod`,
`/android-signing`. Existing trusted-machine originals are kept outside Git with
owner-only permissions. The central `Sivivatu/fdroid` GitHub environment
`fdroid-release` receives only these encrypted replicas:

- `FDROID_KEYSTORE_BASE64`
- `FDROID_KEYSTORE_PASSWORD`
- `FDROID_KEY_ALIAS`
- `FDROID_KEY_PASSWORD`

Restrict that environment to branch `main`. Only the signing step receives the
four values. No Infisical login credential, APK key or personal token is stored
in the central repository. Infisical changes do not automatically refresh GitHub
replicas. GitHub secrets cannot be read back for recovery. Maintain an
owner-controlled encrypted offline backup; its existence is not established by
this setup. Reusing this key links central and Battery Monitor recovery/security.

## Local publication and recovery

On a trusted machine, restore the original repository key from custody and
verify its certificate against the public pin. Supply the four variables without
printing values, passing passwords as arguments, or writing them into Git.
The publisher decodes the key into a private temporary directory and deletes it
before returning. Never upload that directory, config or a secret export.

```sh
# state is a checkout/snapshot of the public publication branch; it is read-only.
# output must be empty and outside state. The four FDROID_* variables are required.
umask 077
python sync.py --state /trusted/public-state --output /trusted/new-public-output
```

The workflow tests first, loads `publication`, builds and validates the complete
new payload, commits that payload without force-pushing, then deploys Pages and
verifies the served signed indexes and all APKs. Failed imports do not modify the
input snapshot. The remote publication branch only advances through a complete
Git commit. Runner checkout files are disposable if copying/committing fails.

If Pages fails after the branch advances, rerun the workflow to deploy retained
history. If public verification fails, inspect propagation and the served data;
rerun after establishing the cause. Never roll back the public branch over newer
versions, regenerate lost keys, force-push, or replace an existing APK version.
Fix bad source releases with a higher per-app versionCode and the same APK key.
Keep old feeds active during migration. Archive/storage moves need a separate
plan before GitHub's repository and Pages limits become a problem.

## Verification limits

A successful sync checks signed v1 and v2 inventory agreement, immutable APK
hashes, embedded package/version, non-debuggable release and APK certificates.
The workflow's final command repeats these checks against public HTTPS URLs.
It does not establish installation, feature behavior, permissions or a two-version
upgrade in the F-Droid Android client. Record those checks separately when run.
