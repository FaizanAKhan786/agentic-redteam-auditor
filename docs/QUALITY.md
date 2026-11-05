# Agentic Red-Team Auditor | Quality & reproducibility

> **Status rule:** Check the [live GitHub Actions history](https://github.com/FaizanAKhan786/agentic-redteam-auditor/actions) for real workflow conclusions. This document does not invent benchmark scores or imply every feature was tested.

## Automated verification

Pytest isolated mock target and orchestration tests; simulated audit CLI smoke check with a report artifact.

- [View the CI workflow](https://github.com/FaizanAKhan786/agentic-redteam-auditor/actions/workflows/ci.yml)
- Any failing run is an unresolved result until corrected; a green syntax/unit-check workflow is not proof of deployment readiness.

## Reproduce the checks

Run these commands from the **repository root**, unless the commands change directories:

```bash
pip install -r requirements.txt
python -m pytest tests/ -q
python -m auditor.orchestrator --demo --output ci-audit-reports
```

## How to interpret the results

**Relevant metrics:** Per-test finding reports, severity assignments and reproducer transcripts against deliberately seeded vulnerabilities.

**Requirements and limitations:** Test output from simulated vulnerable agents does not establish attack success rates on arbitrary real systems. For external systems, obtain explicit authorization and maintain a separate benchmark set.

Before comparing results, save the commit SHA, command, dataset and split (including seed), model revision, dependency environment, hardware/CPU/GPU, and the raw result file. Use the same evaluation set for all compared runs and distinguish **synthetic tests** from **real-world measurements**.

## Publication policy

Only publish numeric scores alongside the run configuration and raw evidence. A threshold, code assertion or example report must **not** be presented as a measured production result.

[Project README](../README.md) · [GitHub Actions](https://github.com/FaizanAKhan786/agentic-redteam-auditor/actions)
