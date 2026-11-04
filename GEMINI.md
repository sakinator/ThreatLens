# ThreatLens Agent Development & Release Guidelines

As an AI agent pair programming on ThreatLens, you MUST adhere to the following strict operational rules on every turn.

## 1. The "Ship-Ready" Release Protocol (MANDATORY)

Never declare a build or task complete merely because code is pushed to `main`. Pushing to `main` ONLY creates an internal Actions artifact; it DOES NOT publish to the user-facing GitHub Releases page.

Every deliverable, feature addition, or user-requested change MUST complete this 5-step checklist before finishing:

1. **Version Bump**:
   - Check `app/build.gradle.kts`.
   - Increment `versionCode` (integer, e.g. 26 -> 27).
   - Increment `versionName` (semver string, e.g. "1.7.1" -> "1.7.2").

2. **Documentation & Changelog Synchronization**:
   - Update `CHANGELOG.md` with a new top-level section:
     ```markdown
     ## [vX.Y.Z] - YYYY-MM-DD
     ### 🚀 <Feature Title>
     * Bullet points describing all new behaviors, files, and architectural additions.
     ```
   - If UI components, architecture, or documentation files (`README.md`, diagrams) changed, update them in the same commit.

3. **Verification & Regression Gate**:
   - Run `python tools/codebase_auditor.py` (Must report: `ZERO SYMBOL OR COMPILER ISSUES FOUND`).
   - Run `python tools/run_regression_suite.py` (Must report: `0 failed`).
   - The regression suite verifies that `CHANGELOG.md` contains the active `versionName`.

4. **Atomic Git Commit & Tag**:
   - Stage all source code, resources, tests, and markdown files:
     `git add app/ tools/ CHANGELOG.md README.md`
   - Commit with descriptive conventional message:
     `git commit -m "feat(<scope>): <description>"`
   - Create the matching version tag:
     `git tag vX.Y.Z`

5. **Dual Push (Branch + Tag)**:
   - Push the branch: `git push origin main`
   - Push the tag: `git push origin vX.Y.Z`
   - Monitor the tag's GitHub Actions run (`gh run watch <run_id>`) until `Create or Update GitHub Release with APK` completes and the release is live on GitHub Releases (`gh release view vX.Y.Z`).

## 2. Code Quality & Design Constraints
- Never delete or bypass unit tests; extend test suites for all new capabilities.
- Preserve all existing comments and docstrings.
- Small notification icons must be clean, monochrome white vectors (`#FFFFFFFF`).
- Never alter `keystore/release.jks`.
