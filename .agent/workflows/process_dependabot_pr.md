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

12. Checkout Main
    ```bash
    git checkout main
    ```

13. Merge PR
    ```bash
    git merge pr-[PR_ID]
    ```

14. Push Changes (Requires Auth)
    ```bash
    git push origin main
    ```

15. Verify Remote CI
    ```bash
    python3 .agent/scripts/check_latest_ci.py
    ```

16. Cleanup Artifacts
    ```bash
    rm -f mock_malware.pt mock_restricted.safetensors mock_restricted.gguf mock_broken.pt
    ```
