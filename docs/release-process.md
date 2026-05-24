# AIsbom CLI Release Process

This document outlines the standard operating procedure for cutting a new release of `aisbom-cli` and publishing it to PyPI and the `aisbom.io` changelog.

## 1. Bump the Version
Update the `version` field in `pyproject.toml` to the new version number (e.g., `0.10.0`).

```bash
poetry version minor  # or patch, major
git add pyproject.toml
git commit -m "chore: bump version to 0.10.0"
git push origin main
```

## 2. Draft the Release Notes
**Do NOT use GitHub's default `--generate-notes` flag if features were pushed directly to `main` without a Pull Request.** The default generator ignores direct commits.

Instead, manually draft the release notes in a temporary text file (`release_notes.txt`) using the standard Markdown template. Ensure you use proper markdown headings (`###`) so the changelog page renders correctly.

**Template (`release_notes.txt`):**
```markdown
### What's new
[Feature Name] — [Brief description of the feature].
* **Sub-feature**: Details...
* **Sub-feature**: Details...

### What's not changing
Scanner behavior, exit codes, output formats — all identical to v0.X.Y.
```

## 3. Create the GitHub Release
Use the GitHub CLI (`gh`) to create the release, passing the manually drafted notes file. This automatically kicks off the `publish.yml` GitHub Actions workflow.

```bash
gh release create v0.10.0 --title "v0.10.0 — [Feature Name]" --notes-file release_notes.txt
```

## 4. Pipeline Verification
Once the GitHub release is created, the following automated sequence occurs:
1. **`aisbom-cli` publish pipeline**: Builds the PyPI package, builds the standalone binaries, and attaches them to the GitHub release.
2. **Webhook Dispatch**: The final step of `publish.yml` sends a `repository_dispatch` webhook to the `ai-sbom-platform` (landing page) repository. *(Note: This requires a valid PAT in the `LANDING_DISPATCH_TOKEN` secret).*
3. **Changelog Regeneration**: The `regenerate-changelog.yml` workflow in the landing page repository catches the webhook, pulls the new release notes via the GitHub API, and updates `changelog.html`. It then pushes the commit to `main` using the `PAT_TOKEN` secret.
4. **Cloudflare Deployment**: The push to `main` naturally triggers the `deploy.yml` workflow, pushing the new changelog live to `https://aisbom.io/changelog`.
