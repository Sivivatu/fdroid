# Sivivatu Apps — shared F-Droid repository

**Add both apps with one subscription:** https://sivivatu.github.io/fdroid/

In F-Droid → Settings → Repositories → Add, paste:

```text
https://sivivatu.github.io/fdroid/repo?fingerprint=133465E78E767C9691C06786F8C286144EF43CBF5A2565D0285AB4CBFB072A1B
```

This developer-operated feed contains **Battery Monitor Beta** and
**Wilderguard Beta**. It is separate from the default f-droid.org catalogue.
Original app signing certificates and APK bytes are preserved, allowing updates
to existing installations. Users must add this new URL explicitly. Existing
single-app feed URLs remain available and do not migrate subscriptions automatically.

## How publication works

The app projects build and sign releases independently. Their existing public
F-Droid feeds are authenticated inputs to this repository. `apps.json` pins each
package ID, upstream feed URL, upstream repository certificate and APK certificate.
The shared publisher downloads and verifies both upstream signed v1/v2 indexes,
checks their inventories agree, then verifies every APK hash, embedded identity
and signing certificate. It rejects rollback or changed bytes for a published
package/version. Versions are independent between apps; historical APKs are retained.

The workflow runs daily at approximately **05:27 UTC**, on updates to `main`,
and on manual dispatch. GitHub may delay or disable schedules on inactive repos;
manual dispatch remains available. A failed upstream aborts the whole sync and
leaves the last published feed available. Generated public state lives on the
`publication` branch; trusted publisher code and registry live on `main`.

The central signer receives only four repository-key values in the protected
`fdroid-release` environment. It never receives either app's private APK key or
runs source-project scripts. No cross-repository PAT is required. Only a validated
public payload is committed and deployed. APK history is not deleted or rebuilt.

## Operations

After publishing a release through its existing app process, wait for the daily
sync or run:

```sh
gh workflow run sync.yml --repo Sivivatu/fdroid --ref main
gh run list --repo Sivivatu/fdroid --workflow sync.yml --limit 5
```

Check the run's validation, publication and live verification stages. A green
validation job alone is not proof of deployment. See [operations](docs/operations.md)
for custody, local validation and failure recovery; see
[adding a project](docs/adding-projects.md) for the onboarding process.

## Development

Use Python 3.12 and JDK 21. Publication and live verification also require
Android SDK build-tools 36.1.0 via `ANDROID_HOME`.

```sh
python -m pip install --require-hashes -r requirements.txt
python -m pip install coverage==7.13.4
python -m coverage run --source=sync -m unittest discover -s tests -v
python -m coverage report --fail-under=80
python sync.py --verify https://sivivatu.github.io/fdroid
```

The tests cover signature/hash rejection, certificate/package boundaries,
independent versions, immutable history, safe redirects and complete-snapshot
publication. [Design and acceptance criteria](docs/design.md) describe the scope.
Cryptographic verification does not establish a real F-Droid client upgrade test.

## Upstream documentation

- [F-Droid repository setup](https://f-droid.org/en/docs/Setup_an_F-Droid_App_Repo/)
- [F-Droid signing](https://f-droid.org/en/docs/Signing_Process/)
- [GitHub Pages deployment workflow](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [Android app signing](https://developer.android.com/studio/publish/app-signing)
