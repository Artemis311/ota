# Synchronized blazer releases

`.github/workflows/blazer-v31.yaml` owns the public release schedule for both pixincreate/Magisk and APatch. It runs daily at **04:23 UTC** and can also be started manually. Manual runs default to a test build with publishing disabled.

Each run resolves the GrapheneOS `stable-security-preview` version once. Both builders receive that exact version. pixincreate still selects the newest downloadable release/prerelease or trusted successful developer build, verifying the APK/artifact checksum. APatch resolves the newest official stable manager release; the GrapheneOS KernelPatch fixes and SELinux filter remain pinned to reviewed commits.

Both packages are staged and verified before either new release is made public. The two GitHub publication requests happen consecutively; GitHub has no atomic two-release transaction. If the second publication fails, the coordinator attempts to return newly published releases to draft. Releases that were already public are never rolled back or overwritten. The existing Magisk/rootless Custota feed and Pages deployment run only after the pair succeeds. The APatch Custota server is https://artemis311.github.io/ota/apatch/ (Custota appends blazer.json). Its signed sidecar and update JSON are hosted on Pages, so the public release still exposes only the OTA ZIP. APatch now includes the official signed Custota 6.7 system app, privilege XML and offline patches to both SELinux policy copies. The partition verifier reproduces exactly those changes and rejects unrelated modifications. Existing older APatch ZIPs did not include Custota; install the new Custota-enabled OTA first.

APatch exposes exactly one attachment: `blazer-<version>-apatch.zip`. The checksum, manager download link and pinned source credits are in the release description. A hidden JSON block binds the complete input fingerprint to the uploaded ZIP's SHA-256 and size, allowing verified reuse without public metadata attachments. New builds remain public prereleases until device validation is separately established.

Complete matching releases are reused. A matching incomplete draft can be rebuilt and its partial upload repaired; an inconsistent public release stops the run. The manually verified APatch release for 2026102101 is recognized by its exact release ID, commit, ZIP digest, manager digest and the initial payload-source identities. Payload-source changes invalidate that reuse.

The automatic BBR profile supports identifiable clean 6.6 Android kernels. It checks the actual extracted OTA kernel, requires built-in BBR and fq, resolves the exact common-kernel commit and accepts only the reviewed BBRv1 source digest. A different kernel family, changed TCP implementation or missing required feature stops publication for review. It never silently substitutes Cubic or a newer BBR generation.

Validation: `.github/workflows/ota-validation.yaml` checks the YAML, Python and generated shell scripts; exercises publication ordering, OS/digest binding, rollback and draft recovery; and performs read-only upstream resolution and existing-release verification. It does not receive firmware signing keys or publish releases.

The separate `private-apatch.yaml` workflow remains available for the earlier private test procedure. It does not participate in public scheduled publishing.
