# Add another app to the shared F-Droid repository

1. **Keep the app in its own source repository.** Establish its reviewed release
   process, increasing Android `versionCode`, permanent APK signing key, public
   release/source links and F-Droid metadata. A new beta package installs separately
   from an existing stable/debug package; changing package identity is not an upgrade.

2. **Publish an independent signed upstream F-Droid feed.** It must expose
   `index-v1.jar`, `entry.jar`, `index-v2.json` and the referenced release APKs at
   a public HTTPS URL. Both index formats must describe the same releases. The
   central publisher imports canonical filenames `<package>_<versionCode>.apk`.
   Maintain the upstream release process after onboarding; central sync polls it.
   Keep metadata/license/source claims accurate. The upstream may contain other
   apps, but only this explicitly registered package is imported.

3. **Establish public certificate pins independently.** Export the upstream
   repository certificate from trusted key custody, calculate its SHA-256, and
   verify its signed indexes. Verify a released APK with Android `apksigner verify
   --print-certs`; confirm package/version using `aapt2 dump badging`. Compare the
   APK certificate with the project's permanent release-key record. Merely copying
   unsigned fingerprints from a website does not authenticate initial trust.
   Record the public pins, provenance and expected source/publication URLs.

4. **Add one entry to `apps.json` in this repository.** Example:

   ```json
   {
     "package": "org.example.newapp",
     "name": "New App Beta",
     "feed": "https://owner.github.io/newapp/fdroid/repo",
     "repoSha256": "<64 lowercase hexadecimal characters>",
     "apkSha256": "<64 lowercase hexadecimal characters>"
   }
   ```

   Do not change the top-level central `repoSha256`. Do not upload the app's
   signing key or introduce a cross-repository personal token. Only the upstream
   app release process needs its APK private key. A separate app can reuse numeric
   version codes already used by another package.

5. **Validate and review.** Run the README's tests/coverage checks. On a trusted
   signing environment, import with retained public state and an empty separate
   output directory. Confirm all previous package/version/hash records remain,
   new records have expected identities, both index formats agree and no private
   files enter the output. Retry using the first output as input and check the
   manifest/APK bytes are unchanged. Review the registry and publisher diff before
   merging to `main`; PR jobs never receive signing secrets.

6. **Publish and verify.** Merging the entry to `main` triggers a full sync. Check
   both workflow jobs and the final public signature/APK verification. Existing
   shared-feed subscribers then see the new app after refreshing. Test installing
   the app and upgrading an existing installation in a real F-Droid client when
   that evidence is needed; do not infer it from an index-only check.

7. **Update shared knowledge.** Add the package, upstream endpoint, public pins,
   source/publication ownership and dated verification evidence to TeamAI's
   `docs/fdroid-publication.md`. Keep secrets and machine-local exports out of the
   team repository. Preserve the new app's old feed URL for any existing subscribers.

Later releases require no central registry change: publish upstream with a higher
versionCode, then wait for daily sync or manually dispatch `sync.yml`. Certificate
rotation, app removal, unstable source hosting or storage migration requires an
explicit migration design; do not bypass the pins or delete retained history.
