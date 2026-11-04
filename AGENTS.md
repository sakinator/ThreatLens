# ThreatLens Autonomous Agent Operational Policy

## Mandatory Pre-Flight & Release Checklist
Whenever implementing features, fixes, or modifications in ThreatLens:

1. **Synchronize Documentation**:
   - `CHANGELOG.md` MUST contain a release entry `## [vX.Y.Z] - YYYY-MM-DD` for the current or new version.
   - Any relevant `.md` files (`README.md`, specs) must be updated in the same changeset.

2. **Version Bump**:
   - Always increment `versionCode` and `versionName` in `app/build.gradle.kts`.

3. **Run Regression Suites**:
   - `python tools/codebase_auditor.py`
   - `python tools/run_regression_suite.py`

4. **Tagging & Publishing**:
   - Pushing to `main` is NOT sufficient to create a public release.
   - You MUST run `git tag vX.Y.Z` and `git push origin vX.Y.Z` so GitHub Actions publishes the signed APK to the public Releases page.
