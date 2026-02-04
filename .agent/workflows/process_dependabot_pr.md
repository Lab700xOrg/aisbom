---
description: Process and merge a Dependabot PR after verification. Usage: Replace [PR_ID] with the actual PR number.
---

1. Fetch the PR branch
   ```bash
   git fetch origin pull/[PR_ID]/head:pr-[PR_ID]
   ```

2. Checkout the PR branch
   ```bash
   git checkout pr-[PR_ID]
   ```

3. Install dependencies
   ```bash
   poetry install
   ```

4. Generate test artifacts (Smoke Test #1)
   ```bash
   poetry run aisbom generate-test-artifacts
   ```

5. Run Automated Tests
   ```bash
   poetry run pytest
   ```

6. Smoke Test #2: Check Coverage
   ```bash
   poetry run pytest --cov=aisbom --cov-fail-under=85
   ```

7. Smoke Test #3: Info
   ```bash
   poetry run aisbom info
   ```

8. Smoke Test #4: Standard Scan
   ```bash
   poetry run aisbom scan demo_data --no-fail-on-risk --format markdown
   ```

9. Smoke Test #5: Strict Mode Scan
   ```bash
   poetry run aisbom scan demo_data --strict --no-fail-on-risk --format markdown
   ```

10. Smoke Test #6: Remote Scan (HuggingFace)
   ```bash
   poetry run aisbom scan hf://google-bert/bert-base-uncased --no-fail-on-risk --format markdown
   ```

11. Smoke Test #7: Scan Current Directory (Artifacts)
    ```bash
    poetry run aisbom scan . --no-fail-on-risk --format markdown
    ```

12. Smoke Test #8: Drift Detection (Diff)
    ```bash
    poetry run aisbom diff demo_data/sbom_baseline.json demo_data/sbom_drifted.json --no-fail-on-risk-increase
    ```

13. Smoke Test #9: Migration Linting
    ```bash
    poetry run aisbom scan mock_broken.pt --lint --no-fail-on-risk
    ```

14. Smoke Test #10: Compliance Export (SPDX & CycloneDX)
    ```bash
    poetry run aisbom scan . --format spdx --output sbom.spdx.json
    poetry run aisbom scan . --format json --output sbom.json
    ```

15. Checkout Main
    ```bash
    git checkout main
    ```

16. Merge PR
    ```bash
    git merge pr-[PR_ID]
    ```

17. Push Changes (Requires Auth)
    ```bash
    git push origin main
    ```

18. Verify Remote CI
    ```bash
    python3 .agent/scripts/check_latest_ci.py
    ```

19. Cleanup Artifacts
    ```bash
    rm -f mock_malware.pt mock_restricted.safetensors mock_restricted.gguf mock_broken.pt sbom.spdx.json sbom.json demo_data/sbom_baseline.json demo_data/sbom_drifted.json
    ```
