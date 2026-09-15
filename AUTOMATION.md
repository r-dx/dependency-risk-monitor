# Automation disclosure

The monitor runs Wednesday and Saturday at 02:17 UTC and supports manual dispatch. It uses a GitHub-hosted runner and the public OSV API, then commits `reports/latest.json` only when normalized advisory meaning changes. Retrieval timestamps alone never produce commits. If OSV is unavailable, the last valid report remains intact and the workflow exits without a data commit. The workflow uses only `contents: write`, no secrets, and no target scanning. Routine collection is automated, not manual analysis.
